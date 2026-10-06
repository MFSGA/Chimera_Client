use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr, SocketAddrV6},
};

use async_trait::async_trait;

pub(crate) mod datagram;

use crate::app::dispatcher::ChainedDatagram;
use crate::{
    Session,
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagramWrapper,
            ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        flow::NetworkPath,
        net::OutboundInterface,
    },
    config::internal::proxy::PROXY_DIRECT,
    proxy::{
        ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
        utils::{
            DirectConnector, GLOBAL_DIRECT_CONNECTOR, RemoteConnector,
            new_protected_dual_stack_udp_socket, new_protected_udp_socket,
        },
    },
};

use datagram::OutboundDatagramImpl;

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
        let s = GLOBAL_DIRECT_CONNECTOR
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

    async fn connect_stream_with_path_selection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        selection: &crate::app::flow::DirectPathSelection,
    ) -> std::io::Result<BoxedChainedStream> {
        self.connect_stream_with_path_selection_result(sess, resolver, selection)
            .await
            .map(|(stream, _)| stream)
    }

    async fn connect_stream_with_path_selection_result(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        selection: &crate::app::flow::DirectPathSelection,
    ) -> std::io::Result<(BoxedChainedStream, Option<crate::app::flow::NetworkPathId>)>
    {
        let (stream, path_id) = DirectConnector::new()
            .connect_stream_with_path_selection_result(
                resolver,
                sess.destination.host().as_str(),
                sess.destination.port(),
                sess.iface.as_ref(),
                selection,
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let stream = ChainedStreamWrapper::new(stream);
        stream.append_to_chain(self.name()).await;
        Ok((Box::new(stream), path_id))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let udp = if sess.typ == crate::session::Type::Dns {
            let destination = sess.destination.ip().ok_or_else(|| {
                std::io::Error::other(
                    "DNS UDP destination must be resolved before dialing",
                )
            })?;
            new_protected_udp_socket(
                None,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                Some((destination, sess.destination.port()).into()),
            )
            .await?
        } else {
            // General direct UDP sockets may serve multiple destinations, so
            // they must not be pinned to the first packet's route.
            new_protected_dual_stack_udp_socket(
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?
        };

        let datagram = OutboundDatagramImpl::new(udp, resolver);
        #[cfg(all(feature = "tun", target_os = "macos"))]
        let datagram = {
            let v4 = crate::app::net::DEFAULT_OUTBOUND_INTERFACE
                .read()
                .await
                .clone();
            let v6 = crate::app::net::DEFAULT_OUTBOUND_INTERFACE_V6
                .read()
                .await
                .clone();
            if sess.iface.is_none()
                && sess.typ != crate::session::Type::Dns
                && v6.as_ref().is_some_and(|v6| {
                    v4.as_ref().is_none_or(|v4| v4.name != v6.name)
                })
            {
                let socket = new_protected_udp_socket(
                    Some("[::]:0".parse().map_err(std::io::Error::other)?),
                    None,
                    Some("[::]:0".parse().map_err(std::io::Error::other)?),
                )
                .await?;
                datagram.with_ipv6_socket(socket)
            } else {
                datagram
            }
        };
        let d = ChainedDatagramWrapper::new(datagram);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }

    async fn connect_datagram_with_path_selection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        selection: &crate::app::flow::DirectPathSelection,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let Some(destination) = sess.destination.ip() else {
            if selection.required {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NetworkUnreachable,
                    "required UDP path cannot be selected without a resolved destination family",
                ));
            }
            return self.connect_datagram(sess, resolver).await;
        };
        let family = crate::app::flow::AddressFamily::from(destination);
        let Some(path) = selection.for_family(family) else {
            if selection.required {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NetworkUnreachable,
                    format!("required UDP network path unavailable for {family:?}"),
                ));
            }
            return self.connect_datagram(sess, resolver).await;
        };

        let iface = outbound_interface_for_path(path, sess.iface.as_ref())?;
        let source = source_socket_addr(path)?;
        let endpoint = SocketAddr::new(destination, sess.destination.port());
        let socket = new_protected_udp_socket(
            Some(source),
            Some(&iface),
            #[cfg(target_os = "linux")]
            sess.so_mark,
            Some(endpoint),
        )
        .await?;
        let local = socket.local_addr()?;
        if local.ip() != source.ip() {
            return Err(std::io::Error::other(format!(
                "UDP socket selected unexpected local address {} (requested {})",
                local.ip(),
                source.ip()
            )));
        }

        let datagram = OutboundDatagramImpl::new(socket, resolver);
        let datagram = ChainedDatagramWrapper::new(datagram);
        datagram.append_to_chain(self.name()).await;
        Ok(Box::new(datagram))
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

pub(crate) fn outbound_interface_for_path(
    path: &NetworkPath,
    configured: Option<&OutboundInterface>,
) -> std::io::Result<OutboundInterface> {
    let interface_id = &path.id.interface;
    if path.id.source_address != path.source_address {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "selected path identity does not match its source address",
        ));
    }
    if configured.is_some_and(|iface| {
        iface.name != interface_id.name || iface.index != interface_id.index
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "selected path violates the configured outbound interface",
        ));
    }

    let mut interface = configured.cloned().unwrap_or(OutboundInterface {
        name: interface_id.name.clone(),
        addr_v4: None,
        netmask_v4: None,
        broadcast_v4: None,
        addr_v6: None,
        netmask_v6: None,
        broadcast_v6: None,
        index: interface_id.index,
        mac_addr: None,
    });
    interface.name.clone_from(&interface_id.name);
    interface.index = interface_id.index;
    match path.source_address {
        Some(IpAddr::V4(address)) => interface.addr_v4 = Some(address),
        Some(IpAddr::V6(address)) => interface.addr_v6 = Some(address),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "selected network path has no source address",
            ));
        }
    }
    Ok(interface)
}

pub(crate) fn source_socket_addr(path: &NetworkPath) -> std::io::Result<SocketAddr> {
    match path.source_address {
        Some(IpAddr::V4(address)) => Ok(SocketAddr::from((address, 0))),
        Some(IpAddr::V6(address)) => Ok(SocketAddr::V6(SocketAddrV6::new(
            address,
            0,
            0,
            path.scope_id.unwrap_or_else(|| {
                if address.is_unicast_link_local() {
                    path.id.interface.index
                } else {
                    0
                }
            }),
        ))),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "selected network path has no source address",
        )),
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
        app::flow::{
            AddressFamily, DirectPathSelection, InterfaceId, InterfaceKind,
            NetworkPath, NetworkPathId,
        },
        proxy::datagram::UdpPacket,
        session::{Network, SocksAddr, Type},
    };

    async fn spawn_udp_echo(bind: &str) -> SocketAddr {
        let sock = UdpSocket::bind(bind).await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        addr
    }

    fn make_resolver() -> ThreadSafeDNSResolver {
        // IP destinations never touch the resolver; an empty mock is enough.
        Arc::new(MockClashResolver::new())
    }

    fn loopback_path(source: Ipv4Addr) -> NetworkPath {
        NetworkPath {
            id: NetworkPathId {
                interface: InterfaceId {
                    name: "loopback-test".to_string(),
                    index: 0,
                },
                family: AddressFamily::Ipv4,
                source_address: Some(source.into()),
                network_generation: 1,
            },
            interface_kind: InterfaceKind::Loopback,
            source_address: Some(source.into()),
            scope_id: None,
            gateway: None,
        }
    }

    #[test]
    fn selected_path_must_match_explicit_interface_constraint() {
        let path = loopback_path(Ipv4Addr::LOCALHOST);
        let configured = OutboundInterface {
            name: "en0".to_string(),
            addr_v4: Some(Ipv4Addr::LOCALHOST),
            netmask_v4: None,
            broadcast_v4: None,
            addr_v6: None,
            netmask_v6: None,
            broadcast_v6: None,
            index: 4,
            mac_addr: None,
        };

        let error =
            outbound_interface_for_path(&path, Some(&configured)).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(not(feature = "tun"))]
    #[tokio::test]
    async fn direct_tcp_selected_path_binds_its_source_address() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_all()
            .withf(|host, enhanced| host == "path.test" && !enhanced)
            .once()
            .returning(|_, _| {
                Ok(vec![
                    "2001:db8::10".parse().unwrap(),
                    Ipv4Addr::LOCALHOST.into(),
                ])
            });
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Tcp,
            typ: Type::Socks5,
            destination: SocksAddr::Domain("path.test".to_string(), endpoint.port()),
            ..Default::default()
        };

        let selection = DirectPathSelection {
            network_generation: 1,
            ipv4: Some(loopback_path(Ipv4Addr::LOCALHOST)),
            required: true,
            ..Default::default()
        };
        let stream = handler
            .connect_stream_with_path_selection(
                &sess,
                Arc::new(resolver),
                &selection,
            )
            .await
            .expect("path-bound direct connection should succeed");
        let (accepted, peer) = listener.accept().await.unwrap();

        assert_eq!(peer.ip(), Ipv4Addr::LOCALHOST);
        drop(accepted);
        drop(stream);
    }

    #[cfg(not(feature = "tun"))]
    #[tokio::test]
    async fn direct_tcp_advances_to_an_alternate_eligible_path_after_bind_failure() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_all()
            .withf(|host, enhanced| host == "path.test" && !enhanced)
            .once()
            .returning(|_, _| Ok(vec![Ipv4Addr::LOCALHOST.into()]));
        let unusable = loopback_path("192.0.2.77".parse().unwrap());
        let usable = loopback_path(Ipv4Addr::LOCALHOST);
        let selection = DirectPathSelection {
            network_generation: 1,
            ipv4_candidates: vec![unusable, usable],
            required: true,
            ..Default::default()
        };
        let sess = Session {
            network: Network::Tcp,
            typ: Type::Socks5,
            destination: SocksAddr::Domain("path.test".to_string(), endpoint.port()),
            ..Default::default()
        };

        let stream = Handler::new("DIRECT")
            .connect_stream_with_path_selection(
                &sess,
                Arc::new(resolver),
                &selection,
            )
            .await
            .expect(
                "the eligible loopback path should win after the first bind fails",
            );
        let (accepted, peer) =
            tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("alternate-path dial was not started promptly")
                .unwrap();

        assert_eq!(peer.ip(), Ipv4Addr::LOCALHOST);
        drop(accepted);
        drop(stream);
    }

    #[tokio::test]
    async fn direct_tcp_hard_path_requirement_does_not_fall_back() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_all()
            .withf(|host, enhanced| host == "path.test" && !enhanced)
            .once()
            .returning(|_, _| Ok(vec![Ipv4Addr::LOCALHOST.into()]));
        let sess = Session {
            network: Network::Tcp,
            typ: Type::Socks5,
            destination: SocksAddr::Domain("path.test".to_string(), endpoint.port()),
            ..Default::default()
        };
        let ipv6_path = NetworkPath {
            id: NetworkPathId {
                interface: InterfaceId {
                    name: "loopback-test".to_string(),
                    index: 0,
                },
                family: AddressFamily::Ipv6,
                source_address: Some("::1".parse().unwrap()),
                network_generation: 1,
            },
            interface_kind: InterfaceKind::Loopback,
            source_address: Some("::1".parse().unwrap()),
            scope_id: None,
            gateway: None,
        };
        let selection = DirectPathSelection {
            network_generation: 1,
            ipv6: Some(ipv6_path),
            required: true,
            ..Default::default()
        };

        let result = Handler::new("DIRECT")
            .connect_stream_with_path_selection(
                &sess,
                Arc::new(resolver),
                &selection,
            )
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("hard path requirement unexpectedly fell back"),
        };

        assert!(
            error
                .to_string()
                .contains("required network path unavailable")
        );
    }

    /// Full round-trip through Handler::connect_datagram ->
    /// new_dual_stack_udp_socket -> IPv4 echo server. This exercises the real
    /// socket-creation path, including the Windows WSAEINVAL regression.
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

        let mut d = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        d.send(UdpPacket {
            data: b"hello-v4".to_vec(),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        })
        .await
        .expect("send failed");

        let pkt = tokio::time::timeout(Duration::from_secs(2), d.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(pkt.data, b"hello-v4");
    }

    #[cfg(not(feature = "tun"))]
    #[tokio::test]
    async fn direct_udp_selected_path_binds_its_source_address() {
        let echo = spawn_udp_echo("127.0.0.1:0").await;
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            destination: SocksAddr::Ip(echo),
            ..Default::default()
        };
        let source = Ipv4Addr::LOCALHOST;
        let selection = DirectPathSelection {
            network_generation: 1,
            ipv4: Some(loopback_path(source)),
            required: true,
            ..Default::default()
        };

        let mut datagram = handler
            .connect_datagram_with_path_selection(&sess, make_resolver(), &selection)
            .await
            .expect("path-bound direct UDP socket should succeed");
        datagram
            .send(UdpPacket {
                data: b"path-bound-v4".to_vec(),
                dst_addr: SocksAddr::Ip(echo),
                ..Default::default()
            })
            .await
            .expect("send failed");

        let packet = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("path-bound UDP response timed out")
            .expect("path-bound UDP stream ended");
        assert_eq!(packet.data, b"path-bound-v4");
    }

    #[tokio::test]
    async fn test_connect_datagram_dns_uses_resolved_upstream() {
        let echo = spawn_udp_echo("127.0.0.1:0").await;
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Udp,
            typ: Type::Dns,
            destination: SocksAddr::Ip(echo),
            ..Default::default()
        };

        let mut datagram = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("DNS connect_datagram failed");
        datagram
            .send(UdpPacket {
                data: b"dns-query".to_vec(),
                dst_addr: SocksAddr::Ip(echo),
                ..Default::default()
            })
            .await
            .expect("DNS send failed");

        let packet = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("DNS response timed out")
            .expect("DNS stream ended");
        assert_eq!(packet.data, b"dns-query");
    }

    /// Same direct UDP socket, two different IPv4 destinations. This validates
    /// the 1-to-N multiplexing that requires a dual-stack socket.
    #[tokio::test]
    async fn test_connect_datagram_ipv4_multi_dest() {
        let echo_a = spawn_udp_echo("127.0.0.1:0").await;
        let echo_b = spawn_udp_echo("127.0.0.1:0").await;
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            destination: SocksAddr::Ip(echo_a),
            ..Default::default()
        };

        let mut d = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        for (dst, payload) in [(echo_a, b"to-a" as &[u8]), (echo_b, b"to-b")] {
            d.send(UdpPacket {
                data: payload.to_vec(),
                dst_addr: SocksAddr::Ip(dst),
                ..Default::default()
            })
            .await
            .expect("send failed");
        }

        let mut received = std::collections::HashSet::new();
        for _ in 0..2 {
            let pkt = tokio::time::timeout(Duration::from_secs(2), d.next())
                .await
                .expect("timed out")
                .expect("stream ended");
            received.insert(pkt.data);
        }
        assert!(received.contains(b"to-a".as_ref()));
        assert!(received.contains(b"to-b".as_ref()));
    }

    /// IPv6 round-trip. Skipped when the host has no IPv6 loopback.
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

        let mut d = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        d.send(UdpPacket {
            data: b"hello-v6".to_vec(),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        })
        .await
        .expect("send failed");

        let pkt = tokio::time::timeout(Duration::from_secs(2), d.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(pkt.data, b"hello-v6");
    }
}
