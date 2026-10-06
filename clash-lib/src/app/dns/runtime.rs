use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::{RuleDispatch, ThreadSafeDNSResolver},
        flow::{
            AddressFamily, DirectPathSelection, IntentStrength, InterfaceId,
            NetworkIntentSnapshot, NetworkPathId, PathIntent, PathTarget,
            RouteDecision,
        },
        net::OutboundInterface,
        path_policy::compile_path_plan,
    },
    common::errors::new_io_error,
    proxy::{
        AnyOutboundHandler,
        datagram::UdpPacket,
        utils::{NetworkPathSource, SharedNetworkStatus},
    },
    session::{Network, Session, SocksAddr, Type},
};
use futures::{SinkExt, StreamExt};
use hickory_net::runtime::{
    DnsUdpSocket, RuntimeProvider, TokioHandle, TokioTime,
    iocompat::AsyncIoTokioAsStd,
};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Default)]
pub(super) struct DnsPathUse {
    pub path_id: Option<NetworkPathId>,
    pub endpoint: Option<SocketAddr>,
}

pub(super) type SharedDnsPathUse = Arc<Mutex<DnsPathUse>>;

#[derive(Clone)]
pub struct DnsRuntimeProvider {
    handle: TokioHandle,
    outbound: AnyOutboundHandler,
    dns_resolver: ThreadSafeDNSResolver,
    iface: Option<OutboundInterface>,
    so_mark: Option<u32>,
    rule_dispatch: Option<Arc<RuleDispatch>>,
    network_path_source: Option<NetworkPathSource>,
    selected_path: SharedDnsPathUse,
}

impl DnsRuntimeProvider {
    pub fn new(
        outbound: AnyOutboundHandler,
        dns_resolver: ThreadSafeDNSResolver,
        iface: Option<OutboundInterface>,
        so_mark: Option<u32>,
        rule_dispatch: Option<Arc<RuleDispatch>>,
        network_path_source: Option<NetworkPathSource>,
        selected_path: SharedDnsPathUse,
    ) -> Self {
        Self {
            handle: TokioHandle::default(),
            outbound,
            dns_resolver,
            iface,
            so_mark,
            rule_dispatch,
            network_path_source,
            selected_path,
        }
    }

    #[cfg(test)]
    pub fn new_direct(
        iface: Option<OutboundInterface>,
        so_mark: Option<u32>,
    ) -> Self {
        use crate::{
            app::dns, config::internal::proxy::PROXY_DIRECT, proxy::direct,
        };
        use std::sync::Arc;

        let proxy = Arc::new(direct::Handler::new(PROXY_DIRECT));
        // SystemResolver::new us trivial,it always return Ok
        let dns_resolver = Arc::new(dns::SystemResolver::new(false).unwrap());
        Self::new(
            proxy,
            dns_resolver,
            iface,
            so_mark,
            None,
            None,
            Arc::new(Mutex::new(DnsPathUse::default())),
        )
    }

    /// Pick the outbound handler for an upstream DNS dial. Rule-respecting
    /// DNS fails closed if the router or selected outbound is unavailable.
    async fn pick_outbound(&self, sess: &Session) -> io::Result<AnyOutboundHandler> {
        let Some(rd) = &self.rule_dispatch else {
            return Ok(self.outbound.clone());
        };
        let router = rd
            .router
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| io::Error::other("DNS rule router is not ready"))?;
        let mgr = rd
            .outbound_manager
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| {
                io::Error::other("DNS rule outbound manager is not ready")
            })?;
        let mut sess = sess.clone();
        let (name, _) = router.match_route(&mut sess).await;
        mgr.get_outbound_for_new_flow(name).await?.ok_or_else(|| {
            io::Error::other("DNS rule selected an unavailable outbound")
        })
    }

    fn session_for(&self, server_addr: SocketAddr, network: Network) -> Session {
        let source = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        Session {
            source,
            network,
            typ: Type::Dns,
            destination: server_addr.into(),
            so_mark: self.so_mark,
            iface: self.iface.clone(),
            ..Default::default()
        }
    }

    async fn direct_path_selection(
        &self,
        outbound: &AnyOutboundHandler,
        server_addr: SocketAddr,
    ) -> io::Result<Option<(DirectPathSelection, u64, SharedNetworkStatus)>> {
        if outbound.name() != crate::config::internal::proxy::PROXY_DIRECT {
            return Ok(None);
        }
        if self.iface.is_none()
            && (server_addr.ip().is_loopback()
                || server_addr.ip().is_unspecified()
                || server_addr.ip().is_multicast())
        {
            // Local DNS forwarders and multicast resolvers remain governed by
            // the system socket path unless the user explicitly binds an
            // interface.
            return Ok(None);
        }
        let Some(source) = self.network_path_source.as_ref() else {
            return Ok(None);
        };
        let Some((
            network_generation,
            observations,
            tun_enabled,
            status,
            _network_intent,
        )) = source.snapshot().await
        else {
            return Ok(None);
        };
        if tun_enabled {
            return Ok(None);
        }

        let explicit_interface = self.iface.as_ref().map(|iface| PathIntent {
            strength: IntentStrength::Require,
            target: PathTarget::Interface(InterfaceId {
                name: iface.name.clone(),
                index: iface.index,
            }),
        });
        let intent = NetworkIntentSnapshot {
            policy_generation: 0,
            intents: explicit_interface.into_iter().collect(),
        };
        let family = AddressFamily::from(server_addr.ip());
        let compiled = compile_path_plan(
            &observations,
            &intent,
            network_generation,
            RouteDecision {
                outbound: "DNS".to_owned(),
                rule: None,
            },
            Some(family),
        );
        let path = compiled.decision.selected.as_ref().and_then(|selected| {
            compiled
                .plan
                .candidates
                .iter()
                .find(|path| &path.id == selected)
        });
        if !intent.intents.is_empty() && path.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                format!("required DNS network path unavailable for {family:?}"),
            ));
        }
        let Some(path) = path else {
            return Ok(None);
        };
        let mut selection = DirectPathSelection {
            policy_generation: intent.policy_generation,
            network_generation,
            required: !intent.intents.is_empty(),
            ..Default::default()
        };
        match family {
            AddressFamily::Ipv4 => selection.ipv4 = Some(path.clone()),
            AddressFamily::Ipv6 => selection.ipv6 = Some(path.clone()),
        }
        Ok(Some((selection, network_generation, status)))
    }

    async fn selected_path_is_current(
        status: &SharedNetworkStatus,
        network_generation: u64,
    ) -> bool {
        status
            .read()
            .await
            .shadow_path_snapshot()
            .is_some_and(|(current, _, _)| current == network_generation)
    }

    async fn report_path_failure(
        &self,
        path_id: NetworkPathId,
        server_addr: SocketAddr,
        error_kind: io::ErrorKind,
    ) {
        let Some(source) = self.network_path_source.as_ref() else {
            return;
        };
        let Some(reporter) = source.traffic_reporter().await else {
            return;
        };
        reporter
            .capture_scoped(
                crate::app::runtime_state::TrafficKind::Dns,
                Some(path_id),
                Some(SocksAddr::Ip(server_addr)),
            )
            .failed(error_kind);
    }
}

impl RuntimeProvider for DnsRuntimeProvider {
    type Handle = TokioHandle;
    type Tcp = AsyncIoTokioAsStd<BoxedChainedStream>;
    type Timer = TokioTime;
    type Udp = DnsProxyUdpSocket;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        // ignored: self.iface is used
        _bind_addr: Option<SocketAddr>,
        _timeout: Option<Duration>,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>>
    {
        let provider = self.clone();
        let dns = self.dns_resolver.clone();
        let sess = self.session_for(server_addr, Network::Tcp);
        Box::pin(async move {
            *provider.selected_path.lock().await = DnsPathUse::default();
            let outbound = provider.pick_outbound(&sess).await?;
            if let Some((selection, generation, status)) = provider
                .direct_path_selection(&outbound, server_addr)
                .await?
            {
                let selected_path = match AddressFamily::from(server_addr.ip()) {
                    AddressFamily::Ipv4 => selection.ipv4.as_ref(),
                    AddressFamily::Ipv6 => selection.ipv6.as_ref(),
                }
                .map(|path| path.id.clone());
                let stream = match outbound
                    .connect_stream_with_path_selection(&sess, dns, &selection)
                    .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        if let Some(path_id) = selected_path {
                            provider
                                .report_path_failure(
                                    path_id,
                                    server_addr,
                                    error.kind(),
                                )
                                .await;
                        }
                        return Err(error);
                    }
                };
                if !Self::selected_path_is_current(&status, generation).await {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "DNS transport dial completed on a stale network path",
                    ));
                }
                *provider.selected_path.lock().await = DnsPathUse {
                    path_id: selected_path,
                    endpoint: Some(server_addr),
                };
                Ok(AsyncIoTokioAsStd(stream))
            } else {
                outbound
                    .connect_stream(&sess, dns)
                    .await
                    .map(AsyncIoTokioAsStd)
            }
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>>
    {
        let provider = self.clone();
        let dns = self.dns_resolver.clone();
        let sess = self.session_for(server_addr, Network::Udp);

        Box::pin(async move {
            *provider.selected_path.lock().await = DnsPathUse::default();
            let outbound = provider.pick_outbound(&sess).await?;
            let datagram = if let Some((selection, generation, status)) = provider
                .direct_path_selection(&outbound, server_addr)
                .await?
            {
                let selected_path = match AddressFamily::from(server_addr.ip()) {
                    AddressFamily::Ipv4 => selection.ipv4.as_ref(),
                    AddressFamily::Ipv6 => selection.ipv6.as_ref(),
                }
                .map(|path| path.id.clone());
                let datagram = match outbound
                    .connect_datagram_with_path_selection(&sess, dns, &selection)
                    .await
                {
                    Ok(datagram) => datagram,
                    Err(error) => {
                        if let Some(path_id) = selected_path {
                            provider
                                .report_path_failure(
                                    path_id,
                                    server_addr,
                                    error.kind(),
                                )
                                .await;
                        }
                        return Err(error);
                    }
                };
                if !Self::selected_path_is_current(&status, generation).await {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "DNS UDP transport dial completed on a stale network path",
                    ));
                }
                *provider.selected_path.lock().await = DnsPathUse {
                    path_id: selected_path,
                    endpoint: Some(server_addr),
                };
                datagram
            } else {
                outbound.connect_datagram(&sess, dns).await?
            };
            Ok(DnsProxyUdpSocket(Mutex::new(datagram)))
        })
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::DnsRuntimeProvider;
    use crate::{
        app::{
            flow::{AddressFamily, InterfaceId, InterfaceKind},
            net::OutboundInterface,
            network::{
                BindingStatus, DefaultRouteEvidence, NetworkSnapshot, NetworkStatus,
                PathCandidateObservation,
            },
        },
        proxy::utils::NetworkPathSource,
        session::{Network, SocksAddr, Type},
    };
    use std::{net::IpAddr, sync::Arc};

    fn path_candidate(
        name: &str,
        index: u32,
        source: &str,
        default_route: DefaultRouteEvidence,
    ) -> PathCandidateObservation {
        let source_address: IpAddr = source.parse().unwrap();
        PathCandidateObservation {
            interface: InterfaceId {
                name: name.to_owned(),
                index,
            },
            interface_kind: InterfaceKind::Unknown,
            family: AddressFamily::from(source_address),
            source_address,
            scope_id: None,
            gateway: None,
            default_route,
            binding: BindingStatus::Verified,
            binding_error: None,
        }
    }

    fn interface(name: &str, index: u32) -> OutboundInterface {
        OutboundInterface {
            name: name.to_owned(),
            addr_v4: None,
            netmask_v4: None,
            broadcast_v4: None,
            addr_v6: None,
            netmask_v6: None,
            broadcast_v6: None,
            index,
            mac_addr: None,
        }
    }

    async fn provider_with_paths(
        iface: Option<OutboundInterface>,
        candidates: Vec<PathCandidateObservation>,
    ) -> DnsRuntimeProvider {
        let source = NetworkPathSource::default();
        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        let snapshot = NetworkSnapshot {
            path_candidates: candidates,
            ..Default::default()
        };
        status.observed(&snapshot);
        source
            .attach(Arc::new(tokio::sync::RwLock::new(status)))
            .await;

        let mut provider = DnsRuntimeProvider::new_direct(iface, None);
        provider.network_path_source = Some(source);
        provider
    }

    #[test]
    fn ipv6_dns_sessions_preserve_target_family_and_socket_mark() {
        let provider = DnsRuntimeProvider::new_direct(None, Some(7777));
        let target = "[2606:4700:4700::1111]:853".parse().unwrap();

        for network in [Network::Tcp, Network::Udp] {
            let session = provider.session_for(target, network);

            assert_eq!(session.network, network);
            assert_eq!(session.typ, Type::Dns);
            assert!(session.source.is_ipv6());
            assert_eq!(session.destination, SocksAddr::Ip(target));
            assert_eq!(session.so_mark, Some(7777));
        }
    }

    #[tokio::test]
    async fn respect_rules_fails_closed_before_router_is_ready() {
        let mut provider = DnsRuntimeProvider::new_direct(None, None);
        provider.rule_dispatch = Some(crate::app::dns::RuleDispatch::new());
        let session =
            provider.session_for("192.0.2.53:53".parse().unwrap(), Network::Udp);

        let error = provider
            .pick_outbound(&session)
            .await
            .expect_err("rule-based DNS must not silently use the static outbound");

        assert!(error.to_string().contains("router is not ready"));
    }

    #[tokio::test]
    async fn direct_dns_uses_default_or_required_interface_path() {
        let paths = vec![
            path_candidate(
                "wifi0",
                4,
                "192.0.2.10",
                DefaultRouteEvidence::PrimaryDefaultRoute,
            ),
            path_candidate(
                "eth0",
                5,
                "198.51.100.10",
                DefaultRouteEvidence::OtherInterface,
            ),
        ];
        let server = "192.0.2.53:53".parse().unwrap();

        let default_provider = provider_with_paths(None, paths.clone()).await;
        let default = default_provider
            .direct_path_selection(&default_provider.outbound, server)
            .await
            .unwrap()
            .expect("the unique default route should be selected");
        assert_eq!(default.0.ipv4.unwrap().id.interface.name, "wifi0");

        let explicit_provider =
            provider_with_paths(Some(interface("eth0", 5)), paths).await;
        let explicit = explicit_provider
            .direct_path_selection(&explicit_provider.outbound, server)
            .await
            .unwrap()
            .expect("an explicit DNS interface is a hard requirement");
        assert_eq!(explicit.0.ipv4.unwrap().id.interface.name, "eth0");
    }

    #[tokio::test]
    async fn direct_dns_fails_closed_when_required_interface_is_missing() {
        let provider = provider_with_paths(
            Some(interface("gone0", 9)),
            vec![path_candidate(
                "wifi0",
                4,
                "192.0.2.10",
                DefaultRouteEvidence::PrimaryDefaultRoute,
            )],
        )
        .await;
        let error = provider
            .direct_path_selection(
                &provider.outbound,
                "192.0.2.53:53".parse().unwrap(),
            )
            .await
            .expect_err("a missing required interface must not silently fall back");

        assert_eq!(error.kind(), std::io::ErrorKind::NetworkUnreachable);
    }

    #[tokio::test]
    async fn direct_dns_keeps_local_forwarders_system_managed() {
        let provider = provider_with_paths(
            None,
            vec![path_candidate(
                "wifi0",
                4,
                "192.0.2.10",
                DefaultRouteEvidence::PrimaryDefaultRoute,
            )],
        )
        .await;
        let selection = provider
            .direct_path_selection(
                &provider.outbound,
                "127.0.0.1:53".parse().unwrap(),
            )
            .await
            .unwrap();

        assert!(selection.is_none());
    }
}

// Mutex could be inefficient
// But this is for DNS, it doesn't require high perf
// SocketAddr indicates the source address of the UDP socket
pub struct DnsProxyUdpSocket(Mutex<BoxedChainedDatagram>);

impl DnsUdpSocket for DnsProxyUdpSocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let inner = Box::pin(self.0.lock()).as_mut().poll(cx);
        let mut inner = ready!(inner);
        let out = ready!(inner.poll_next_unpin(cx))
            .ok_or(new_io_error("dns proxy outbound is closed"));

        let ret = out.map(|x: crate::proxy::datagram::UdpPacket| {
            let len = x.data.len().min(buf.len());
            buf[..len].copy_from_slice(&x.data[0..len]);
            (
                len,
                x.src_addr
                    .try_into_socket_addr()
                    .expect("packet source addr can't be a domain for dns proxy"),
            )
        });
        Poll::Ready(ret)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let inner = Box::pin(self.0.lock()).as_mut().poll(cx);
        let mut inner = ready!(inner);
        match inner.poll_ready_unpin(cx) {
            Poll::Ready(Ok(_)) => (),
            Poll::Pending => match ready!(inner.poll_flush_unpin(cx)) {
                Ok(_) => (),
                Err(e) => return Poll::Ready(Err(e)),
            },
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        };
        let src = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let packet = UdpPacket {
            data: buf.to_vec(),
            src_addr: src,
            dst_addr: target.into(),
            inbound_user: None,
        };
        match inner.start_send_unpin(packet) {
            Ok(_) => (),
            Err(e) => return Poll::Ready(Err(e)),
        }

        let ret = match ready!(inner.poll_flush_unpin(cx)) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(e),
        };
        Poll::Ready(ret)
    }
}
