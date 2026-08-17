use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use ipnet::IpNet;
use rand::seq::IndexedRandom;
use tokio::sync::OnceCell;

use self::{keys::KeyBytes, wireguard::Config};
use super::{
    ConnectorType, DialWithConnector, HandlerCommonOptions, OutboundHandler,
    OutboundType, PlainProxyAPIResponse, utils::RemoteConnector,
};
use crate::{
    Error,
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::{map_io_error, new_io_error},
    impl_default_connector,
    session::Session,
};

mod device;
mod events;
mod keys;
mod ports;
mod stack;
mod wireguard;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub ip: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub remote_dns_resolve: bool,
    pub dns: Option<Vec<String>>,
    pub mtu: Option<u16>,
    pub udp: bool,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}

struct Inner {
    device_manager: Arc<device::DeviceManager>,
    #[allow(unused)]
    wg_handle: tokio::task::JoinHandle<()>,
    #[allow(unused)]
    device_manager_handle: tokio::task::JoinHandle<()>,
}

pub struct Handler {
    opts: HandlerOptions,
    inner: OnceCell<Inner>,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuard")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            inner: OnceCell::new(),
            connector: Default::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn options(&self) -> &HandlerOptions {
        &self.opts
    }

    async fn initialize_inner(
        &self,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<&Inner, Error> {
        self.inner
            .get_or_try_init(|| async {
                let recv_pair = tokio::sync::mpsc::channel(1024);
                let send_pair = tokio::sync::mpsc::channel(1024);
                let server_ip = resolver
                    .resolve(&self.opts.server, false)
                    .await
                    .map_err(map_io_error)?
                    .ok_or_else(|| {
                        new_io_error(format!(
                            "invalid remote server: {}",
                            self.opts.server
                        ))
                    })?;
                let allowed_ips = self
                    .opts
                    .allowed_ips
                    .as_ref()
                    .map(|ips| {
                        ips.iter()
                            .map(|ip| {
                                ip.parse::<IpNet>().map_err(|error| {
                                    new_io_error(format!(
                                        "invalid allowed ip: {error}"
                                    ))
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default();

                let private_key = self
                    .opts
                    .private_key
                    .parse::<KeyBytes>()
                    .map_err(new_io_error)?;
                let public_key = self
                    .opts
                    .public_key
                    .parse::<KeyBytes>()
                    .map_err(new_io_error)?;
                let pre_shared_key = self
                    .opts
                    .pre_shared_key
                    .as_ref()
                    .map(|value| value.parse::<KeyBytes>().map(|key| key.0.into()))
                    .transpose()
                    .map_err(new_io_error)?;

                let wg = wireguard::WireguardTunnel::new(
                    Config {
                        private_key: private_key.0.into(),
                        endpoint_public_key: public_key.0.into(),
                        pre_shared_key,
                        remote_endpoint: (server_ip, self.opts.port).into(),
                        source_peer_ip: self.opts.ip,
                        source_peer_ipv6: self.opts.ipv6,
                        keepalive_seconds: Some(10),
                        allowed_ips,
                        reserved_bits: match &self.opts.reserved_bits {
                            Some(bits) if bits.len() >= 3 => {
                                [bits[0], bits[1], bits[2]]
                            }
                            _ => [0, 0, 0],
                        },
                    },
                    recv_pair.0,
                    send_pair.1,
                    resolver.clone(),
                    self.connector.read().await.as_ref().cloned(),
                    sess,
                )
                .await
                .map_err(map_io_error)?;

                let wg_handle = tokio::spawn(async move {
                    wg.start_polling().await;
                });

                let packet_notifier = tokio::sync::mpsc::channel(1024);
                let device = device::VirtualIpDevice::new(
                    send_pair.0,
                    recv_pair.1,
                    packet_notifier.0,
                    self.opts.mtu.unwrap_or(1420) as usize,
                );
                let device_manager = Arc::new(device::DeviceManager::new(
                    self.opts.ip,
                    self.opts.ipv6,
                    resolver,
                    if self.opts.remote_dns_resolve {
                        self.opts
                            .dns
                            .as_ref()
                            .map(|servers| {
                                servers
                                    .iter()
                                    .filter_map(|server| {
                                        server
                                            .parse::<IpAddr>()
                                            .ok()
                                            .map(|ip| (ip, 53).into())
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    } else {
                        vec![]
                    },
                    packet_notifier.1,
                ));
                let device_manager_clone = device_manager.clone();
                let device_manager_handle = tokio::spawn(async move {
                    device_manager_clone.poll_sockets(device).await;
                });

                Ok(Inner {
                    device_manager,
                    wg_handle,
                    device_manager_handle,
                })
            })
            .await
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::WireGuard
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let inner = self
            .initialize_inner(resolver.clone(), sess)
            .await
            .map_err(map_io_error)?;

        let ip = if self.opts.remote_dns_resolve
            && sess.destination.is_domain()
            && self
                .opts
                .dns
                .as_ref()
                .is_some_and(|servers| !servers.is_empty())
        {
            let server = {
                let mut rng = rand::rng();
                self.opts
                    .dns
                    .as_ref()
                    .and_then(|servers| servers.choose(&mut rng))
                    .cloned()
            }
            .ok_or_else(|| new_io_error("invalid wireguard dns server"))?;
            inner
                .device_manager
                .look_up_dns(
                    &sess.destination.host(),
                    (server.parse::<IpAddr>().map_err(map_io_error)?, 53).into(),
                )
                .await
                .ok_or_else(|| new_io_error("invalid remote address"))?
        } else {
            resolver
                .resolve(&sess.destination.host(), false)
                .await
                .map_err(map_io_error)?
                .ok_or_else(|| new_io_error("invalid remote address"))?
        };

        let socket = inner
            .device_manager
            .new_tcp_socket((ip, sess.destination.port()).into())
            .await;
        let chained = ChainedStreamWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let inner = self
            .initialize_inner(resolver, sess)
            .await
            .map_err(map_io_error)?;
        let socket = inner.device_manager.new_udp_socket().await;
        let chained = ChainedDatagramWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut map = HashMap::new();
        map.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        map.insert("port".to_owned(), Box::new(self.opts.port) as _);
        map.insert(
            "public-key".to_owned(),
            Box::new(self.opts.public_key.clone()) as _,
        );
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> HandlerOptions {
        HandlerOptions {
            name: "wg-test".to_string(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.invalid".to_string(),
            port: 51820,
            ip: Ipv4Addr::new(10, 0, 0, 2),
            ipv6: None,
            private_key: "short".to_string(),
            public_key: "short".to_string(),
            pre_shared_key: None,
            remote_dns_resolve: false,
            dns: None,
            mtu: Some(1380),
            udp: true,
            allowed_ips: Some(vec!["0.0.0.0/0".to_string()]),
            reserved_bits: None,
        }
    }

    #[tokio::test]
    async fn wireguard_handler_metadata_is_lazy_and_matches_reference() {
        let handler = Handler::new(options());
        assert_eq!(handler.name(), "wg-test");
        assert!(matches!(handler.proto(), OutboundType::WireGuard));
        assert!(handler.support_udp().await);
        assert!(matches!(
            handler.support_connector().await,
            ConnectorType::None
        ));
        assert!(handler.inner.get().is_none());

        let map = handler.as_map().await;
        assert!(map.contains_key("server"));
        assert!(map.contains_key("port"));
        assert!(map.contains_key("public-key"));
        assert!(handler.inner.get().is_none());
    }
}
