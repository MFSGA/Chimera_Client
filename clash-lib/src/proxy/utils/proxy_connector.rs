use async_trait::async_trait;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use std::{
    collections::VecDeque,
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock},
    time::Duration,
};
use tracing::trace;

use super::new_protected_tcp_stream;
use crate::{
    app::{
        dispatcher::{
            ChainedDatagram, ChainedDatagramWrapper, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        net::OutboundInterface,
    },
    common::errors::new_io_error,
    proxy::{
        AnyOutboundDatagram, AnyOutboundHandler, AnyStream,
        direct::datagram::OutboundDatagramImpl, utils::new_protected_udp_socket,
    },
    session::{Network, Session, SocksAddr, Type},
};

/// allows a proxy to get a connection to a remote server
#[async_trait]
pub trait RemoteConnector: Send + Sync + Debug {
    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyStream>;

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram>;
}

#[derive(Debug)]
pub struct DirectConnector;

impl DirectConnector {
    pub fn new() -> Self {
        Self
    }
}

pub static GLOBAL_DIRECT_CONNECTOR: LazyLock<Arc<dyn RemoteConnector>> =
    LazyLock::new(global_direct_connector);

fn global_direct_connector() -> Arc<dyn RemoteConnector> {
    Arc::new(DirectConnector::new())
}

fn interleave_ip_families(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    let prefer_ipv6 = addresses.first().is_some_and(IpAddr::is_ipv6);
    let (mut ipv4, mut ipv6): (VecDeque<_>, VecDeque<_>) =
        addresses.into_iter().partition(IpAddr::is_ipv4);
    let mut ordered = Vec::with_capacity(ipv4.len() + ipv6.len());

    while !ipv4.is_empty() || !ipv6.is_empty() {
        let (primary, secondary) = if prefer_ipv6 {
            (&mut ipv6, &mut ipv4)
        } else {
            (&mut ipv4, &mut ipv6)
        };
        if let Some(address) = primary.pop_front() {
            ordered.push(address);
        }
        if let Some(address) = secondary.pop_front() {
            ordered.push(address);
        }
    }
    ordered
}

#[async_trait]
impl RemoteConnector for DirectConnector {
    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        let addresses = if let Ok(ip) = address.parse() {
            vec![ip]
        } else {
            resolver
                .resolve_all(address, false)
                .await
                .map_err(|error| {
                    new_io_error(format!("can't resolve dns: {error}"))
                })?
        };
        if addresses.is_empty() {
            return Err(new_io_error("no dns result"));
        }

        let mut attempts = FuturesUnordered::new();
        for (attempt, dial_addr) in
            interleave_ip_families(addresses).into_iter().enumerate()
        {
            let iface = iface.cloned();
            attempts.push(
                async move {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_millis(
                            300 * attempt as u64,
                        ))
                        .await;
                    }
                    let result = new_protected_tcp_stream(
                        (dial_addr, port).into(),
                        iface.as_ref(),
                        #[cfg(target_os = "linux")]
                        so_mark,
                    )
                    .await;
                    (dial_addr, result)
                }
                .boxed(),
            );
        }

        let mut errors = Vec::new();
        while let Some((dial_addr, result)) = attempts.next().await {
            match result {
                Ok(stream) => return Ok(Box::new(stream) as _),
                Err(error) => {
                    errors.push(format!("{dial_addr}: {error}"));
                }
            }
        }
        Err(new_io_error(format!(
            "all resolved addresses failed: {}",
            errors.join("; ")
        )))
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let dgram = new_protected_udp_socket(
            src,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            destination
                .ip()
                .map(|ip| SocketAddr::new(ip, destination.port())),
        )
        .await
        .map(|x| OutboundDatagramImpl::new(x, resolver))?;

        let dgram = ChainedDatagramWrapper::new(dgram);
        Ok(Box::new(dgram))
    }
}

pub struct ProxyConnector {
    proxy: AnyOutboundHandler,
    connector: Box<dyn RemoteConnector>,
}

impl ProxyConnector {
    pub fn new(
        proxy: AnyOutboundHandler,
        // TODO: make this Arc
        connector: Box<dyn RemoteConnector>,
    ) -> Self {
        Self { proxy, connector }
    }
}

impl Debug for ProxyConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConnector")
            .field("proxy", &self.proxy.name())
            .finish()
    }
}

#[async_trait]
impl RemoteConnector for ProxyConnector {
    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        let sess = Session {
            network: Network::Tcp,
            typ: Type::Ignore,
            destination: SocksAddr::Domain(address.to_owned(), port),
            iface: iface.cloned(),
            #[cfg(target_os = "linux")]
            so_mark,
            ..Default::default()
        };

        trace!(
            "proxy connector `{}` connecting to {}:{}",
            self.proxy.name(),
            address,
            port
        );

        let s = self
            .proxy
            .connect_stream_with_connector(&sess, resolver, self.connector.as_ref())
            .await?;

        let stream = ChainedStreamWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        _src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            iface: iface.cloned(),
            destination: destination.clone(),
            #[cfg(target_os = "linux")]
            so_mark,
            ..Default::default()
        };
        let s = self
            .proxy
            .connect_datagram_with_connector(
                &sess,
                resolver,
                self.connector.as_ref(),
            )
            .await?;

        let stream = ChainedDatagramWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc};

    use tokio::net::TcpListener;

    use super::{DirectConnector, RemoteConnector};
    use crate::app::dns::MockClashResolver;

    #[tokio::test]
    async fn direct_connector_tries_the_next_resolved_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_all()
            .withf(|host, enhanced| host == "proxy.test" && !enhanced)
            .once()
            .returning(|_, _| {
                Ok(vec![
                    "127.0.0.2".parse::<IpAddr>().unwrap(),
                    "127.0.0.1".parse::<IpAddr>().unwrap(),
                ])
            });

        let stream = DirectConnector::new()
            .connect_stream(
                Arc::new(resolver),
                "proxy.test",
                port,
                None,
                #[cfg(target_os = "linux")]
                None,
            )
            .await
            .expect("second resolved address should connect");

        drop(stream);
        drop(listener);
    }

    #[test]
    fn happy_eyeballs_interleaves_address_families() {
        let addresses = ["192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"]
            .map(|address| address.parse().unwrap())
            .to_vec();

        assert_eq!(
            super::interleave_ip_families(addresses),
            ["192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2",]
                .map(|address| address.parse::<IpAddr>().unwrap())
        );
    }
}
