use std::fmt::Debug;

use async_trait::async_trait;
use futures::TryFutureExt;

use crate::app::dispatcher::ChainedDatagram;
use crate::{
    Session,
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagramWrapper,
            ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::map_io_error,
    config::internal::proxy::PROXY_DIRECT,
    proxy::{
        ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
        datagram::OutboundDatagramImpl,
        utils::{RemoteConnector, new_dual_stack_udp_socket, new_tcp_stream},
    },
};

#[derive(Clone)]
pub struct Handler {
    pub name: String,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Direct").field("name", &self.name).finish()
    }
}

impl Handler {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_DIRECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let remote_ip = resolver
            .resolve(sess.destination.host().as_str(), false)
            .map_err(map_io_error)
            .await?
            .ok_or_else(|| std::io::Error::other("no dns result"))?;

        let s = new_tcp_stream(
            (remote_ip, sess.destination.port()).into(),
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
        )
        .await?;

        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        // The outbound socket is shared across all destinations from the same
        // client. Use a dual-stack socket so one socket can send to both IPv4
        // and IPv6 destinations without EAFNOSUPPORT.
        let udp = new_dual_stack_udp_socket(
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
        )?;

        let d =
            ChainedDatagramWrapper::new(OutboundDatagramImpl::new(udp, resolver));
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedStream> {
        let s = connector
            .connect_stream(
                resolver,
                sess.destination.host().as_str(),
                sess.destination.port(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let d = connector
            .connect_datagram(
                resolver,
                None,
                sess.destination.clone(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use futures::{SinkExt, StreamExt};
    use tokio::net::UdpSocket;

    use super::*;
    use crate::{
        app::dns::MockClashResolver,
        proxy::datagram::UdpPacket,
        session::{Network, SocksAddr, Type},
    };

    async fn spawn_udp_echo(bind: &str) -> SocketAddr {
        let socket = UdpSocket::bind(bind).await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        });
        addr
    }

    fn make_resolver() -> ThreadSafeDNSResolver {
        Arc::new(MockClashResolver::new())
    }

    #[tokio::test]
    async fn test_connect_datagram_ipv4_roundtrip() {
        let echo = spawn_udp_echo("127.0.0.1:0").await;
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            destination: SocksAddr::Ip(echo),
            ..Default::default()
        };

        let mut datagram = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        datagram
            .send(UdpPacket {
                data: b"hello-v4".to_vec(),
                dst_addr: SocksAddr::Ip(echo),
                ..Default::default()
            })
            .await
            .expect("send failed");

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(pkt.data, b"hello-v4");
    }

    #[tokio::test]
    async fn test_connect_datagram_ipv6_roundtrip() {
        if UdpSocket::bind("[::1]:0").await.is_err() {
            eprintln!("skipping: no IPv6 loopback");
            return;
        }

        let echo = spawn_udp_echo("[::1]:0").await;
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            destination: SocksAddr::Ip(echo),
            source: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            ..Default::default()
        };

        let mut datagram = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        datagram
            .send(UdpPacket {
                data: b"hello-v6".to_vec(),
                dst_addr: SocksAddr::Ip(echo),
                ..Default::default()
            })
            .await
            .expect("send failed");

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(pkt.data, b"hello-v6");
    }
}
