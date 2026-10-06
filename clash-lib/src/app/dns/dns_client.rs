use super::{
    ClashResolver, Client, EdnsClientSubnet, RuleDispatch,
    runtime::{DnsPathUse, DnsRuntimeProvider, SharedDnsPathUse},
};
use std::{
    fmt::{Debug, Display, Formatter},
    net::{self, IpAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;

use hickory_net::{
    DnsHandle, client, tcp::TcpClientStream, udp::UdpClientStream, xfer::FirstAnswer,
};
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
use hickory_net::{h2::HttpsClientStream, tls::tls_client_connect};
use hickory_proto::{
    op::{self, DnsRequest, DnsRequestOptions, Message},
    rr::{
        RecordType,
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
    },
};
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use tracing::{debug, info, instrument, trace, warn};

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
use crate::common::tls::{self, GLOBAL_ROOT_STORE};
use crate::{
    Error,
    app::{
        dns::{self},
        net::OutboundInterface,
    },
    dns::{ThreadSafeDNSClient, dhcp::DhcpClient},
    proxy::{OutboundHandler, utils::NetworkPathSource},
};
use anyhow::anyhow;

#[derive(Clone, Debug, PartialEq)]
pub enum DNSNetMode {
    Udp,
    Tcp,
    DoT,
    DoH,
    Dhcp,
}

impl Display for DNSNetMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::DoT => write!(f, "DoT"),
            Self::DoH => write!(f, "DoH"),
            Self::Dhcp => write!(f, "DHCP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::{
            dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
            dns::MockClashResolver,
        },
        proxy::{self, DialWithConnector, OutboundHandler, OutboundType},
        session::Session,
    };
    use hickory_proto::{
        op,
        rr::{self, Name, rdata::opt::EdnsOption},
    };
    use std::{net::Ipv4Addr, str::FromStr};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    #[derive(Debug)]
    struct ResolverProbeOutbound;

    #[async_trait]
    impl DialWithConnector for ResolverProbeOutbound {}

    #[async_trait]
    impl OutboundHandler for ResolverProbeOutbound {
        fn name(&self) -> &str {
            "resolver-probe"
        }

        fn proto(&self) -> OutboundType {
            OutboundType::Direct
        }

        async fn connect_stream(
            &self,
            _sess: &Session,
            resolver: Arc<dyn ClashResolver>,
        ) -> std::io::Result<BoxedChainedStream> {
            resolver
                .resolve("proxy.example", false)
                .await
                .map_err(std::io::Error::other)?;
            Err(std::io::Error::other("resolver probe complete"))
        }

        async fn connect_datagram(
            &self,
            _sess: &Session,
            _resolver: Arc<dyn ClashResolver>,
        ) -> std::io::Result<BoxedChainedDatagram> {
            Err(std::io::Error::other("not used by resolver probe"))
        }
    }

    #[tokio::test]
    async fn dns_transport_uses_explicit_outbound_resolver() {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve()
            .with(
                mockall::predicate::eq("proxy.example"),
                mockall::predicate::eq(false),
            )
            .once()
            .returning(|_, _| Ok(Some(net::IpAddr::from([203, 0, 113, 7]))));

        let cfg = DnsConfig::Tcp(
            "203.0.113.53:53".parse().unwrap(),
            None,
            Arc::new(ResolverProbeOutbound),
            None,
        );

        let result = dns_stream_builder(
            &cfg,
            Some(Arc::new(resolver)),
            None,
            None,
            Arc::new(Mutex::new(DnsPathUse::default())),
        )
        .await;
        assert!(result.is_err());
    }

    fn client_with_ecs(ecs: Option<EdnsClientSubnet>) -> DnsClient {
        let proxy = Arc::new(proxy::direct::Handler::new("test-proxy"));
        let addr = net::SocketAddr::new(net::IpAddr::from([127, 0, 0, 1]), 53);
        DnsClient {
            inner: Arc::new(RwLock::new(Inner {
                c: None,
                bg_handle: None,
                selected_path: None,
            })),
            cfg: RwLock::new(DnsConfig::Udp(addr, None, proxy.clone(), None)),
            proxy,
            bootstrap_resolver: None,
            outbound_resolver: None,
            refresh_address_on_rebuild: AtomicBool::new(false),
            host: url::Host::Domain("example.org".to_string()),
            port: 53,
            net: DNSNetMode::Udp,
            iface: None,
            ecs,
            rule_dispatch: None,
            network_path_source: None,
        }
    }

    #[tokio::test]
    async fn truncated_udp_response_retries_over_tcp() -> anyhow::Result<()> {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = tcp_listener.local_addr()?;
        let udp_socket = UdpSocket::bind(addr).await?;

        let udp_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            let (length, peer) = udp_socket.recv_from(&mut buffer).await?;
            let request = Message::from_vec(&buffer[..length])?;
            let mut response =
                Message::response(request.metadata.id, request.metadata.op_code);
            response.metadata.truncation = true;
            response.add_query(request.queries[0].clone());
            udp_socket.send_to(&response.to_vec()?, peer).await?;
            anyhow::Ok(())
        });

        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await?;
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).await?;
            let mut buffer = vec![0_u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut buffer).await?;
            let request = Message::from_vec(&buffer)?;
            let query = request.queries[0].clone();
            let mut response =
                Message::response(request.metadata.id, request.metadata.op_code);
            response.add_query(query.clone());
            response.add_answer(rr::Record::from_rdata(
                query.name().clone(),
                60,
                rr::RData::A(rr::rdata::A(Ipv4Addr::new(192, 0, 2, 53))),
            ));
            let response = response.to_vec()?;
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(&response).await?;
            anyhow::Ok(())
        });

        let mut client = client_with_ecs(None);
        client.host = url::Host::Ipv4(Ipv4Addr::LOCALHOST);
        client.port = addr.port();
        client.cfg =
            RwLock::new(DnsConfig::Udp(addr, None, client.proxy.clone(), None));

        let response = client.exchange(&build_message(RecordType::A)).await?;

        assert!(!response.metadata.truncation);
        assert_eq!(
            response.answers[0].data,
            rr::RData::A(rr::rdata::A(Ipv4Addr::new(192, 0, 2, 53)))
        );
        udp_task.await??;
        tcp_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn dns_response_reports_the_selected_network_path() {
        use crate::app::{
            flow::{AddressFamily, InterfaceId, InterfaceKind, NetworkPathId},
            network::{
                BindingStatus, DefaultRouteEvidence, NetworkSnapshot, NetworkStatus,
                PathCandidateObservation,
            },
        };

        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        let snapshot = NetworkSnapshot {
            path_candidates: vec![PathCandidateObservation {
                interface: InterfaceId {
                    name: "wifi0".to_owned(),
                    index: 4,
                },
                interface_kind: InterfaceKind::Wifi,
                family: AddressFamily::Ipv4,
                source_address: "192.0.2.10".parse().unwrap(),
                scope_id: None,
                gateway: Some("192.0.2.1".parse().unwrap()),
                default_route: DefaultRouteEvidence::PrimaryDefaultRoute,
                binding: BindingStatus::Verified,
                binding_error: None,
            }],
            ..Default::default()
        };
        status.observed(&snapshot);
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let reporter = status.traffic_reporter(tx);
        let source = NetworkPathSource::default();
        source.attach(Arc::new(RwLock::new(status))).await;
        source.attach_traffic_reporter(reporter).await;

        let mut client = client_with_ecs(None);
        client.network_path_source = Some(source);
        let selected_path = Arc::new(Mutex::new(DnsPathUse {
            path_id: Some(NetworkPathId {
                interface: InterfaceId {
                    name: "wifi0".to_owned(),
                    index: 4,
                },
                family: AddressFamily::Ipv4,
                source_address: Some("192.0.2.10".parse().unwrap()),
                network_generation: 1,
            }),
            endpoint: Some("1.1.1.1:53".parse().unwrap()),
        }));
        client.inner.write().await.selected_path = Some(selected_path.clone());

        client
            .report_path_response(&Message::query(), &selected_path)
            .await;
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn refresh_upstream_address_uses_bootstrap_resolver() {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve()
            .with(
                mockall::predicate::eq("example.org"),
                mockall::predicate::eq(false),
            )
            .once()
            .returning(|_, _| Ok(Some(net::IpAddr::from([203, 0, 113, 10]))));

        let mut client = client_with_ecs(None);
        client.bootstrap_resolver = Some(Arc::new(resolver));

        assert!(client.refresh_upstream_address().await.unwrap());
        assert_eq!(
            client.cfg.read().await.addr(),
            net::SocketAddr::from(([203, 0, 113, 10], 53))
        );
    }

    #[tokio::test]
    async fn reset_transport_aborts_background_and_marks_address_refresh() {
        let client = client_with_ecs(None);
        client.inner.write().await.bg_handle =
            Some(tokio::spawn(std::future::pending::<()>()));

        let reset = client.reset_transport().await.unwrap();

        assert_eq!(reset, 1);
        let inner = client.inner.read().await;
        assert!(inner.c.is_none());
        assert!(inner.bg_handle.is_none());
        assert!(client.refresh_address_on_rebuild.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn reset_transport_includes_bootstrap_resolver() {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_reset_transports()
            .once()
            .returning(|| Ok(3));
        let mut client = client_with_ecs(None);
        client.bootstrap_resolver = Some(Arc::new(resolver));

        assert_eq!(client.reset_transport().await.unwrap(), 4);
        assert!(client.refresh_address_on_rebuild.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn reset_transport_releases_own_state_when_bootstrap_reset_fails() {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_reset_transports()
            .once()
            .returning(|| Err(anyhow::anyhow!("bootstrap reset failed")));
        let mut client = client_with_ecs(None);
        client.bootstrap_resolver = Some(Arc::new(resolver));
        client.inner.write().await.bg_handle =
            Some(tokio::spawn(std::future::pending::<()>()));
        assert!(client.reset_transport().await.is_err());
        assert!(client.inner.read().await.bg_handle.is_none());
        assert!(client.refresh_address_on_rebuild.load(Ordering::Acquire));
    }

    fn build_message(record_type: RecordType) -> Message {
        let mut msg = Message::new(
            0,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        let mut query = op::Query::new();
        query.set_name(Name::from_ascii("example.org").expect("valid name"));
        query.set_query_type(record_type);
        msg.add_query(query);
        msg
    }

    #[test]
    fn apply_edns_client_subnet_adds_ipv4_option() {
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: None,
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::A);

        client.apply_edns_client_subnet(&mut msg);

        let edns = msg.edns.as_ref().expect("edns should exist");
        let option = edns
            .option(EdnsCode::Subnet)
            .expect("subnet option missing");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(subnet.addr(), net::IpAddr::from([1, 2, 3, 0]));
                assert_eq!(subnet.source_prefix(), 24);
                assert_eq!(subnet.scope_prefix(), 0);
            }
            _ => panic!("unexpected edns option"),
        }
    }

    #[test]
    fn apply_edns_client_subnet_prefers_ipv6_for_aaaa() {
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: Some("2001:db8::/48".parse().unwrap()),
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::AAAA);

        client.apply_edns_client_subnet(&mut msg);

        let edns = msg.edns.as_ref().expect("edns should exist");
        let option = edns
            .option(EdnsCode::Subnet)
            .expect("subnet option missing");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(
                    subnet.addr(),
                    net::IpAddr::from_str("2001:db8::").unwrap()
                );
                assert_eq!(subnet.source_prefix(), 48);
                assert_eq!(subnet.scope_prefix(), 0);
            }
            _ => panic!("unexpected edns option"),
        }
    }

    #[test]
    fn apply_edns_client_subnet_respects_existing_option() {
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: None,
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::A);

        let mut edns = hickory_proto::op::Edns::new();
        {
            let opts = edns.options_mut();
            opts.insert(EdnsOption::Subnet(ClientSubnet::new(
                net::IpAddr::from([9, 8, 7, 0]),
                24,
                24,
            )));
        }
        msg.set_edns(edns);

        client.apply_edns_client_subnet(&mut msg);

        let edns = msg.edns.as_ref().expect("edns should remain");
        let option = edns
            .option(EdnsCode::Subnet)
            .expect("subnet option missing");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(subnet.addr(), net::IpAddr::from([9, 8, 7, 0]));
                assert_eq!(subnet.source_prefix(), 24);
                assert_eq!(subnet.scope_prefix(), 0);
            }
            _ => panic!("unexpected edns option"),
        }
    }

    #[test]
    fn apply_edns_client_subnet_normalizes_existing_option_without_config() {
        let client = client_with_ecs(None);
        let mut msg = build_message(RecordType::A);

        let mut edns = hickory_proto::op::Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                net::IpAddr::from([9, 8, 7, 0]),
                24,
                24,
            )));
        msg.set_edns(edns);

        client.apply_edns_client_subnet(&mut msg);

        let option = msg
            .edns
            .as_ref()
            .and_then(|edns| edns.option(EdnsCode::Subnet))
            .expect("subnet option should remain");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(subnet.addr(), net::IpAddr::from([9, 8, 7, 0]));
                assert_eq!(subnet.source_prefix(), 24);
                assert_eq!(subnet.scope_prefix(), 0);
            }
            _ => panic!("unexpected edns option"),
        }
    }
}

impl FromStr for DNSNetMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDP" => Ok(Self::Udp),
            "TCP" => Ok(Self::Tcp),
            "DoH" => Ok(Self::DoH),
            "DoT" => Ok(Self::DoT),
            "DHCP" => Ok(Self::Dhcp),
            _ => Err(Error::DNSError("unsupported protocol".into())),
        }
    }
}

#[derive(Clone)]
pub struct Opts {
    pub father: Option<Arc<dyn ClashResolver>>,
    pub outbound_resolver: Option<Arc<dyn ClashResolver>>,
    pub host: url::Host<String>,
    pub port: u16,
    pub net: DNSNetMode,
    pub iface: Option<OutboundInterface>,
    pub proxy: Arc<dyn OutboundHandler>,
    pub ecs: Option<EdnsClientSubnet>,
    pub doh_path: Option<String>,
    pub fw_mark: Option<u32>,
    /// When set, upstream dials consult the rule engine. Only populated for
    /// `nameserver`, `fallback`, and `nameserver-policy` clients when
    /// `dns.respect-rules` is true; bootstrap clients (`default-nameserver`,
    /// `proxy-server-nameserver`) leave this `None`.
    pub rule_dispatch: Option<Arc<RuleDispatch>>,
    /// Shared live network status used for DIRECT DNS socket path selection.
    pub network_path_source: Option<NetworkPathSource>,
}

type FwMark = Option<u32>;

#[derive(Clone)]
enum DnsConfig {
    Udp(
        net::SocketAddr,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Tcp(
        net::SocketAddr,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Tls(
        net::SocketAddr,
        url::Host<String>,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Https(
        net::SocketAddr,
        url::Host<String>,
        String,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
}

impl DnsConfig {
    fn addr(&self) -> net::SocketAddr {
        match self {
            Self::Udp(addr, ..)
            | Self::Tcp(addr, ..)
            | Self::Tls(addr, ..)
            | Self::Https(addr, ..) => *addr,
        }
    }

    fn set_ip(&mut self, ip: IpAddr) {
        match self {
            Self::Udp(addr, ..)
            | Self::Tcp(addr, ..)
            | Self::Tls(addr, ..)
            | Self::Https(addr, ..) => addr.set_ip(ip),
        }
    }
}

impl Display for DnsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            DnsConfig::Udp(addr, iface, proxy, _) => {
                write!(f, "UDP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "via proxy: {}", proxy.name())?;
                Ok(())
            }
            DnsConfig::Tcp(addr, iface, proxy, _) => {
                write!(f, "TCP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "via proxy: {}", proxy.name())?;
                Ok(())
            }
            DnsConfig::Tls(addr, host, iface, proxy, _) => {
                write!(f, "TLS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "host: {host}")?;
                write!(f, "via proxy: {}", proxy.name())
            }
            DnsConfig::Https(addr, host, _, iface, proxy, _) => {
                write!(f, "HTTPS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "host: {host}")?;
                write!(f, "via proxy: {}", proxy.name())
            }
        }
    }
}

struct Inner {
    c: Option<client::Client<DnsRuntimeProvider>>,
    bg_handle: Option<JoinHandle<()>>,
    selected_path: Option<SharedDnsPathUse>,
}

/// DnsClient
pub struct DnsClient {
    inner: Arc<RwLock<Inner>>,

    cfg: RwLock<DnsConfig>,
    proxy: Arc<dyn OutboundHandler>,
    bootstrap_resolver: Option<Arc<dyn ClashResolver>>,
    outbound_resolver: Option<Arc<dyn ClashResolver>>,
    refresh_address_on_rebuild: AtomicBool,

    // debug purpose
    host: url::Host<String>,
    port: u16,
    net: DNSNetMode,
    iface: Option<OutboundInterface>,
    ecs: Option<EdnsClientSubnet>,
    rule_dispatch: Option<Arc<RuleDispatch>>,
    network_path_source: Option<NetworkPathSource>,
}

impl DnsClient {
    async fn build_stream(
        &self,
    ) -> Result<
        (
            client::Client<DnsRuntimeProvider>,
            JoinHandle<()>,
            SharedDnsPathUse,
        ),
        Error,
    > {
        let cfg = self.cfg.read().await.clone();
        #[cfg(feature = "tun")]
        let cfg = {
            let mut cfg = cfg;
            let iface = match &mut cfg {
                DnsConfig::Udp(_, iface, ..)
                | DnsConfig::Tcp(_, iface, ..)
                | DnsConfig::Tls(_, _, iface, ..)
                | DnsConfig::Https(_, _, _, iface, ..) => iface,
            };
            if let Some(saved) = iface {
                *iface = crate::app::net::resolve_outbound_interface(Some(
                    &crate::app::net::Interface::Name(saved.name.clone()),
                ))
                .await?;
            }
            cfg
        };
        let selected_path = Arc::new(Mutex::new(DnsPathUse::default()));
        let (client, background) = dns_stream_builder(
            &cfg,
            self.outbound_resolver.clone(),
            self.rule_dispatch.clone(),
            self.network_path_source.clone(),
            selected_path.clone(),
        )
        .await?;
        Ok((client, background, selected_path))
    }

    async fn report_path_response(
        &self,
        response: &Message,
        selected_path: &SharedDnsPathUse,
    ) {
        let DnsPathUse { path_id, endpoint } = selected_path.lock().await.clone();
        let Some(path_id) = path_id else {
            return;
        };
        let Some(destination) = endpoint else {
            return;
        };
        let Some(source) = self.network_path_source.as_ref() else {
            return;
        };
        let Some(reporter) = source.traffic_reporter().await else {
            return;
        };
        let bytes = response.to_vec().map_or(1, |message| message.len());
        reporter
            .capture_scoped(
                crate::app::runtime_state::TrafficKind::Dns,
                Some(path_id),
                Some(destination.into()),
            )
            .received(bytes);
    }

    async fn refresh_upstream_address(&self) -> anyhow::Result<bool> {
        let url::Host::Domain(domain) = &self.host else {
            return Ok(false);
        };
        let Some(resolver) = &self.bootstrap_resolver else {
            return Ok(false);
        };
        let Some(ip) = resolver.resolve(domain, false).await? else {
            return Err(Error::DNSError(format!(
                "unable to refresh DNS upstream address for {domain}"
            ))
            .into());
        };

        let mut cfg = self.cfg.write().await;
        let old_addr = cfg.addr();
        if old_addr.ip() == ip {
            debug!(
                upstream = %self.id(),
                address = %old_addr,
                "DNS upstream address refresh returned the current address"
            );
            return Ok(false);
        }

        cfg.set_ip(ip);
        info!(
            upstream = %self.id(),
            old_address = %old_addr,
            new_address = %cfg.addr(),
            "refreshed DNS upstream address after connection failures"
        );
        Ok(true)
    }

    async fn rebuild_current_address(
        &self,
        address_refreshed: bool,
    ) -> Result<
        (
            client::Client<DnsRuntimeProvider>,
            JoinHandle<()>,
            SharedDnsPathUse,
        ),
        Error,
    > {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(200);

        for attempt in 0..=MAX_RETRIES {
            match self.build_stream().await {
                Ok(result) => {
                    if attempt > 0 {
                        info!(
                            upstream = %self.id(),
                            address_refreshed,
                            attempt = attempt + 1,
                            max_attempts = MAX_RETRIES + 1,
                            "dns client rebuild succeeded"
                        );
                    }
                    return Ok(result);
                }
                Err(err) if attempt < MAX_RETRIES => {
                    warn!(
                        upstream = %self.id(),
                        address_refreshed,
                        attempt = attempt + 1,
                        max_attempts = MAX_RETRIES + 1,
                        retry_delay_ms = RETRY_DELAY.as_millis(),
                        error = %err,
                        "dns client rebuild failed, retrying"
                    );
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(err) => return Err(err),
            }
        }

        unreachable!()
    }

    /// Rebuild the DNS stream with retries, waiting between attempts.
    /// Network transitions can briefly make outbound sockets unavailable; a
    /// short retry loop avoids permanently failing the resolver on a transient
    /// rebuild error.
    async fn rebuild_with_retries(
        &self,
    ) -> anyhow::Result<(
        client::Client<DnsRuntimeProvider>,
        JoinHandle<()>,
        SharedDnsPathUse,
    )> {
        if self
            .refresh_address_on_rebuild
            .swap(false, Ordering::AcqRel)
            && let Err(error) = self.refresh_upstream_address().await
        {
            self.refresh_address_on_rebuild
                .store(true, Ordering::Release);
            return Err(error);
        }

        let err = match self.rebuild_current_address(false).await {
            Ok(result) => return Ok(result),
            Err(err) => err,
        };
        warn!(
            upstream = %self.id(),
            error = %err,
            "dns client rebuild attempts exhausted, refreshing upstream address"
        );
        if !self.refresh_upstream_address().await? {
            return Err(err.into());
        }

        self.rebuild_current_address(true).await.map_err(Into::into)
    }

    pub async fn new_client(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        // TODO: use proxy to connect?

        if matches!(opts.net, DNSNetMode::Dhcp) {
            let host = opts.host.to_string();
            return Ok(Arc::new(
                DhcpClient::new(
                    &host,
                    opts.fw_mark,
                    opts.network_path_source.clone(),
                )
                .await?,
            ));
        }

        let mut ip: Option<IpAddr> = None;
        let need_resolve = match &opts.host {
            url::Host::Domain(v) => Some(v),
            url::Host::Ipv4(v) => {
                ip = Some(net::IpAddr::V4(*v));
                None
            }
            url::Host::Ipv6(v) => {
                ip = Some(net::IpAddr::V6(*v));
                None
            }
        };

        let resolved_ip = match need_resolve {
            Some(domain) => match opts.father.as_ref() {
                Some(father) => match father.resolve(domain, false).await? {
                    Some(ip) => Some(ip),
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "can't resolve default DNS: {}",
                            domain
                        ))
                        .into());
                    }
                },
                _ => {
                    return Err(Error::DNSError(format!(
                        "unable to resolve DNS hostname {} without a default \
                         resolver",
                        domain
                    ))
                    .into());
                }
            },
            None => None,
        };
        let ip = ip.or(resolved_ip).ok_or_else(|| {
            anyhow!(
                "invalid DNS host: {}, unable to parse as IP and no default \
                 resolver",
                opts.host
            )
        })?;
        match opts.net {
            DNSNetMode::Udp => {
                let cfg = DnsConfig::Udp(
                    net::SocketAddr::new(ip, opts.port),
                    opts.iface.clone(),
                    opts.proxy.clone(),
                    opts.fw_mark,
                );
                Ok(Arc::new(Self {
                    inner: Arc::new(RwLock::new(Inner {
                        c: None,
                        bg_handle: None,
                        selected_path: None,
                    })),
                    cfg: RwLock::new(cfg),
                    proxy: opts.proxy,
                    bootstrap_resolver: opts.father,
                    outbound_resolver: opts.outbound_resolver,
                    refresh_address_on_rebuild: AtomicBool::new(false),
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                    network_path_source: opts.network_path_source.clone(),
                }))
            }
            DNSNetMode::Tcp => {
                let cfg = DnsConfig::Tcp(
                    net::SocketAddr::new(ip, opts.port),
                    opts.iface.clone(),
                    opts.proxy.clone(),
                    opts.fw_mark,
                );
                Ok(Arc::new(Self {
                    inner: Arc::new(RwLock::new(Inner {
                        c: None,
                        bg_handle: None,
                        selected_path: None,
                    })),

                    cfg: RwLock::new(cfg),
                    proxy: opts.proxy,
                    bootstrap_resolver: opts.father,
                    outbound_resolver: opts.outbound_resolver,
                    refresh_address_on_rebuild: AtomicBool::new(false),
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                    network_path_source: opts.network_path_source.clone(),
                }))
            }
            DNSNetMode::DoT => {
                let cfg = DnsConfig::Tls(
                    net::SocketAddr::new(ip, opts.port),
                    opts.host.clone(),
                    opts.iface.clone(),
                    opts.proxy.clone(),
                    opts.fw_mark,
                );
                Ok(Arc::new(Self {
                    inner: Arc::new(RwLock::new(Inner {
                        c: None,
                        bg_handle: None,
                        selected_path: None,
                    })),
                    cfg: RwLock::new(cfg),
                    proxy: opts.proxy,
                    bootstrap_resolver: opts.father,
                    outbound_resolver: opts.outbound_resolver,
                    refresh_address_on_rebuild: AtomicBool::new(false),
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                    network_path_source: opts.network_path_source.clone(),
                }))
            }
            DNSNetMode::DoH => {
                let cfg = DnsConfig::Https(
                    net::SocketAddr::new(ip, opts.port),
                    opts.host.clone(),
                    opts.doh_path.unwrap_or_else(|| "/dns-query".to_owned()),
                    opts.iface.clone(),
                    opts.proxy.clone(),
                    opts.fw_mark,
                );
                Ok(Arc::new(Self {
                    inner: Arc::new(RwLock::new(Inner {
                        c: None,
                        bg_handle: None,
                        selected_path: None,
                    })),

                    cfg: RwLock::new(cfg),
                    proxy: opts.proxy,
                    bootstrap_resolver: opts.father,
                    outbound_resolver: opts.outbound_resolver,
                    refresh_address_on_rebuild: AtomicBool::new(false),
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                    network_path_source: opts.network_path_source.clone(),
                }))
            }
            DNSNetMode::Dhcp => unreachable!("."),
        }
    }

    fn apply_edns_client_subnet(&self, message: &mut Message) {
        if let Some(EdnsOption::Subnet(existing)) = message
            .edns
            .as_ref()
            .and_then(|edns| edns.option(EdnsCode::Subnet))
        {
            let corrected =
                ClientSubnet::new(existing.addr(), existing.source_prefix(), 0);
            if let Some(edns) = message.edns.as_mut() {
                edns.options_mut().remove(EdnsCode::Subnet);
                edns.options_mut().insert(EdnsOption::Subnet(corrected));
            }
            return;
        }

        let Some(ecs) = &self.ecs else {
            return;
        };

        if ecs.ipv4.is_none() && ecs.ipv6.is_none() {
            return;
        }

        let prefer_ipv6 = matches!(
            message.queries.first().map(|q| q.query_type()),
            Some(RecordType::AAAA)
        );

        let candidate = if prefer_ipv6 {
            ecs.ipv6
                .map(|ipv6| (net::IpAddr::from(ipv6.network()), ipv6.prefix_len()))
                .or_else(|| {
                    ecs.ipv4.map(|ipv4| {
                        (net::IpAddr::from(ipv4.network()), ipv4.prefix_len())
                    })
                })
        } else {
            ecs.ipv4
                .map(|ipv4| (net::IpAddr::from(ipv4.network()), ipv4.prefix_len()))
                .or_else(|| {
                    ecs.ipv6.map(|ipv6| {
                        (net::IpAddr::from(ipv6.network()), ipv6.prefix_len())
                    })
                })
        };

        let Some((addr, prefix)) = candidate else {
            return;
        };

        let edns = message
            .edns
            .get_or_insert_with(hickory_proto::op::Edns::new);

        let options = edns.options_mut();
        options.remove(EdnsCode::Subnet);
        options.insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix, 0)));
    }
}

impl Debug for DnsClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("net", &self.net)
            .field("iface", &self.iface)
            .field("proxy", &self.proxy.name())
            .finish()
    }
}

#[async_trait]
impl Client for DnsClient {
    fn id(&self) -> String {
        format!("{}#{}:{}", self.net, self.host, self.port)
    }

    async fn reset_transport(&self) -> anyhow::Result<u32> {
        self.refresh_address_on_rebuild
            .store(true, Ordering::Release);

        let mut inner = self.inner.write().await;
        inner.c.take();
        inner.selected_path.take();
        if let Some(background) = inner.bg_handle.take() {
            background.abort();
        }
        drop(inner);
        let reset = if let Some(resolver) = &self.bootstrap_resolver {
            resolver.reset_transports().await?
        } else {
            0
        };
        Ok(reset.saturating_add(1))
    }

    #[instrument(skip(msg), level = "trace")]
    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let need_initialize = {
            let inner = self.inner.read().await;
            inner.c.is_none()
                || inner.bg_handle.as_ref().is_none_or(|bg| bg.is_finished())
        };
        if need_initialize {
            let mut inner = self.inner.write().await;

            match &inner.bg_handle {
                Some(bg) => {
                    if bg.is_finished() {
                        warn!(
                            "dns client background task is finished, likely \
                             connection closed, restarting a new one"
                        );
                        let (client, bg, selected_path) =
                            self.rebuild_with_retries().await?;
                        inner.c.replace(client);
                        inner.bg_handle.replace(bg);
                        inner.selected_path.replace(selected_path);
                    } else {
                        trace!(
                            "dns client background task is still running, reusing \
                             existing connection"
                        );
                    }
                }
                _ => {
                    // initializing client
                    info!("initializing dns client: {}", self.cfg.read().await);
                    let (client, bg, selected_path) =
                        self.rebuild_with_retries().await?;
                    inner.c.replace(client);
                    inner.bg_handle.replace(bg);
                    inner.selected_path.replace(selected_path);
                }
            }
        }

        let mut outbound = msg.clone();
        self.apply_edns_client_subnet(&mut outbound);

        if outbound.metadata.id == 0 {
            outbound.metadata.id = rand::random::<u16>();
        }

        let (client, selected_path) = {
            let inner = self.inner.read().await;
            let client = inner.c.as_ref().ok_or_else(|| {
                Error::DNSError(
                    "DNS transport reset during query initialization; retry query"
                        .to_owned(),
                )
            })?;
            let selected_path = inner.selected_path.as_ref().ok_or_else(|| {
                Error::DNSError(
                    "DNS path state reset during query initialization; retry query"
                        .to_owned(),
                )
            })?;
            (client.clone(), selected_path.clone())
        };
        let response = client
            .send(DnsRequest::new(
                outbound.clone(),
                DnsRequestOptions::default(),
            ))
            .first_answer()
            .await
            .map_err(|x| Error::DNSError(x.to_string()))
            .map(|x: op::DnsResponse| x.into_message())?;

        if !response.metadata.truncation {
            self.report_path_response(&response, &selected_path).await;
            return Ok(response);
        }

        self.report_path_response(&response, &selected_path).await;

        let cfg = self.cfg.read().await.clone();
        let DnsConfig::Udp(addr, iface, proxy, fw_mark) = cfg else {
            return Ok(response);
        };
        warn!(
            upstream = %self.id(),
            "UDP DNS response was truncated; retrying over TCP"
        );

        let tcp_cfg = DnsConfig::Tcp(addr, iface, proxy, fw_mark);
        let tcp_selected_path = Arc::new(Mutex::new(DnsPathUse::default()));
        let (tcp_client, tcp_background) = dns_stream_builder(
            &tcp_cfg,
            self.outbound_resolver.clone(),
            self.rule_dispatch.clone(),
            self.network_path_source.clone(),
            tcp_selected_path.clone(),
        )
        .await
        .map_err(|error| Error::DNSError(error.to_string()))?;
        let tcp_result = tcp_client
            .send(DnsRequest::new(outbound, DnsRequestOptions::default()))
            .first_answer()
            .await;
        tcp_background.abort();
        let tcp_response: op::DnsResponse =
            tcp_result.map_err(|error| Error::DNSError(error.to_string()))?;
        let tcp_response = tcp_response.into_message();
        self.report_path_response(&tcp_response, &tcp_selected_path)
            .await;
        if tcp_response.metadata.truncation {
            return Err(anyhow!(
                "DNS upstream returned a truncated response over TCP"
            ));
        }
        Ok(tcp_response)
    }
}

async fn dns_stream_builder(
    cfg: &DnsConfig,
    outbound_resolver: Option<Arc<dyn ClashResolver>>,
    rule_dispatch: Option<Arc<RuleDispatch>>,
    network_path_source: Option<NetworkPathSource>,
    selected_path: SharedDnsPathUse,
) -> Result<(client::Client<DnsRuntimeProvider>, JoinHandle<()>), Error> {
    let dns_resolver: Arc<dyn ClashResolver> = match outbound_resolver {
        Some(resolver) => resolver,
        None => Arc::new(dns::SystemResolver::new(false)?),
    };
    match cfg {
        DnsConfig::Udp(addr, iface, proxy, fw_mark) => {
            let stream = UdpClientStream::builder(
                *addr,
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *fw_mark,
                    rule_dispatch.clone(),
                    network_path_source.clone(),
                    selected_path.clone(),
                ),
            )
            .with_timeout(Some(Duration::from_secs(5)))
            .build();

            let (x, y) = client::Client::<DnsRuntimeProvider>::from_sender(stream);
            Ok((x, tokio::spawn(y)))
        }
        DnsConfig::Tcp(addr, iface, proxy, fw_mark) => {
            let (stream_future, sender) = TcpClientStream::new(
                *addr,
                None,
                Some(Duration::from_secs(5)),
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *fw_mark,
                    rule_dispatch.clone(),
                    network_path_source.clone(),
                    selected_path.clone(),
                ),
            );

            let stream = stream_future
                .await
                .map_err(|x| Error::DNSError(x.to_string()))?;
            let (x, y) = client::Client::<DnsRuntimeProvider>::new(stream, sender);
            Ok((x, tokio::spawn(y)))
        }
        #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
        DnsConfig::Tls(addr, host, iface, proxy, fw_mark) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["dot".into(), "h2".into()];

            let addr = *addr;
            let host = host.clone();
            let iface = iface.clone();
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| Error::DNSError(e.to_string()))?;
            let (stream_future, sender) = tls_client_connect(
                addr,
                server_name,
                Arc::new(tls_config),
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *fw_mark,
                    rule_dispatch.clone(),
                    network_path_source.clone(),
                    selected_path.clone(),
                ),
            );

            let stream = stream_future
                .await
                .map_err(|x| Error::DNSError(x.to_string()))?;
            let (x, y) = client::Client::<DnsRuntimeProvider>::with_timeout(
                stream,
                sender,
                Duration::from_secs(5),
            );
            Ok((x, tokio::spawn(y)))
        }
        #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
        DnsConfig::Https(addr, host, path, iface, proxy, fw_mark) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["h2".into()];

            let host_ip = match host {
                url::Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
                url::Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
                _ => None,
            };
            if host_ip == Some(addr.ip()) {
                tls_config.dangerous().set_certificate_verifier(Arc::new(
                    tls::NoHostnameTlsVerifier::new(),
                ));
            }
            let stream = HttpsClientStream::builder(
                Arc::new(tls_config),
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *fw_mark,
                    rule_dispatch.clone(),
                    network_path_source.clone(),
                    selected_path.clone(),
                ),
            )
            .build(*addr, host.to_string().into(), path.clone().into())
            .await
            .map_err(|x| Error::DNSError(x.to_string()))?;

            let (x, y) = client::Client::<DnsRuntimeProvider>::from_sender(stream);
            Ok((x, tokio::spawn(y)))
        }
        #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
        DnsConfig::Tls(..) | DnsConfig::Https(..) => Err(Error::InvalidConfig(
            "encrypted DNS requires the `aws-lc-rs` or `ring` feature".to_owned(),
        )),
    }
}
