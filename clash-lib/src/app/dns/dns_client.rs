use super::{
    ClashResolver, Client, EdnsClientSubnet, RuleDispatch,
    runtime::DnsRuntimeProvider,
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
    DnsHandle, client, h2::HttpsClientStream, tcp::TcpClientStream,
    tls::tls_client_connect, udp::UdpClientStream, xfer::FirstAnswer,
};
use hickory_proto::{
    op::{self, DnsRequest, DnsRequestOptions, Message},
    rr::{
        RecordType,
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
    },
};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{debug, info, instrument, trace, warn};

use crate::{
    Error,
    app::{
        dns::{self},
        net::OutboundInterface,
    },
    common::tls::{self, GLOBAL_ROOT_STORE},
    dns::{ThreadSafeDNSClient, dhcp::DhcpClient},
    proxy::OutboundHandler,
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
    use crate::{app::dns::MockClashResolver, proxy};
    use hickory_proto::{
        op,
        rr::{Name, rdata::opt::EdnsOption},
    };
    use std::str::FromStr;

    fn client_with_ecs(ecs: Option<EdnsClientSubnet>) -> DnsClient {
        let proxy = Arc::new(proxy::direct::Handler::new("test-proxy"));
        let addr = net::SocketAddr::new(net::IpAddr::from([127, 0, 0, 1]), 53);
        DnsClient {
            inner: Arc::new(RwLock::new(Inner {
                c: None,
                bg_handle: None,
            })),
            cfg: RwLock::new(DnsConfig::Udp(addr, None, proxy.clone(), None)),
            proxy,
            bootstrap_resolver: None,
            refresh_address_on_rebuild: AtomicBool::new(false),
            host: url::Host::Domain("example.org".to_string()),
            port: 53,
            net: DNSNetMode::Udp,
            iface: None,
            ecs,
            rule_dispatch: None,
        }
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
    async fn reset_transport_resets_bootstrap_resolver_first() {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_reset_transports()
            .once()
            .returning(|| Ok(3));
        let mut client = client_with_ecs(None);
        client.bootstrap_resolver = Some(Arc::new(resolver));

        assert_eq!(client.reset_transport().await.unwrap(), 3);
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
                assert_eq!(subnet.scope_prefix(), 24);
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
                assert_eq!(subnet.scope_prefix(), 48);
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
                assert_eq!(subnet.scope_prefix(), 24);
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
    pub host: url::Host<String>,
    pub port: u16,
    pub net: DNSNetMode,
    pub iface: Option<OutboundInterface>,
    pub proxy: Arc<dyn OutboundHandler>,
    pub ecs: Option<EdnsClientSubnet>,
    pub fw_mark: Option<u32>,
    /// When set, upstream dials consult the rule engine. Only populated for
    /// `nameserver`, `fallback`, and `nameserver-policy` clients when
    /// `dns.respect-rules` is true; bootstrap clients (`default-nameserver`,
    /// `proxy-server-nameserver`) leave this `None`.
    pub rule_dispatch: Option<Arc<RuleDispatch>>,
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
            DnsConfig::Https(addr, host, iface, proxy, _) => {
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
}

/// DnsClient
pub struct DnsClient {
    inner: Arc<RwLock<Inner>>,

    cfg: RwLock<DnsConfig>,
    proxy: Arc<dyn OutboundHandler>,
    bootstrap_resolver: Option<Arc<dyn ClashResolver>>,
    refresh_address_on_rebuild: AtomicBool,

    // debug purpose
    host: url::Host<String>,
    port: u16,
    net: DNSNetMode,
    iface: Option<OutboundInterface>,
    ecs: Option<EdnsClientSubnet>,
    rule_dispatch: Option<Arc<RuleDispatch>>,
}

impl DnsClient {
    async fn build_stream(
        &self,
    ) -> Result<(client::Client<DnsRuntimeProvider>, JoinHandle<()>), Error> {
        let cfg = self.cfg.read().await.clone();
        dns_stream_builder(&cfg, self.rule_dispatch.clone()).await
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
    ) -> Result<(client::Client<DnsRuntimeProvider>, JoinHandle<()>), Error> {
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
    ) -> anyhow::Result<(client::Client<DnsRuntimeProvider>, JoinHandle<()>)> {
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
            return Ok(Arc::new(DhcpClient::new(&host, opts.fw_mark).await));
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
                    })),
                    cfg: RwLock::new(cfg),
                    proxy: opts.proxy,
                    bootstrap_resolver: opts.father,
                    refresh_address_on_rebuild: AtomicBool::new(false),
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
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
                    })),

                    cfg: RwLock::new(cfg),
                    proxy: opts.proxy,
                    bootstrap_resolver: opts.father,
                    refresh_address_on_rebuild: AtomicBool::new(false),
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
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
                    })),
                    cfg: RwLock::new(cfg),
                    proxy: opts.proxy,
                    bootstrap_resolver: opts.father,
                    refresh_address_on_rebuild: AtomicBool::new(false),
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                }))
            }
            DNSNetMode::DoH => {
                let cfg = DnsConfig::Https(
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
                    })),

                    cfg: RwLock::new(cfg),
                    proxy: opts.proxy,
                    bootstrap_resolver: opts.father,
                    refresh_address_on_rebuild: AtomicBool::new(false),
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                }))
            }
            DNSNetMode::Dhcp => unreachable!("."),
        }
    }

    fn apply_edns_client_subnet(&self, message: &mut Message) {
        let Some(ecs) = &self.ecs else {
            return;
        };

        if ecs.ipv4.is_none() && ecs.ipv6.is_none() {
            return;
        }

        if message
            .edns
            .as_ref()
            .is_some_and(|edns| edns.option(EdnsCode::Subnet).is_some())
        {
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
        options.insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix, prefix)));
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
        let mut reset = if let Some(resolver) = &self.bootstrap_resolver {
            resolver.reset_transports().await?
        } else {
            0
        };
        self.refresh_address_on_rebuild
            .store(true, Ordering::Release);

        let mut inner = self.inner.write().await;
        let had_client = inner.c.take().is_some();
        let background = inner.bg_handle.take();
        let had_background = background.is_some();
        if let Some(background) = background {
            background.abort();
        }
        if had_client || had_background {
            reset = reset.saturating_add(1);
        }
        Ok(reset)
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
                        let (client, bg) = self.rebuild_with_retries().await?;
                        inner.c.replace(client);
                        inner.bg_handle.replace(bg);
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
                    let (client, bg) = self.rebuild_with_retries().await?;
                    inner.c.replace(client);
                    inner.bg_handle.replace(bg);
                }
            }
        }

        let mut outbound = msg.clone();
        self.apply_edns_client_subnet(&mut outbound);

        let mut req = DnsRequest::new(outbound, DnsRequestOptions::default());
        if req.metadata.id == 0 {
            req.metadata.id = rand::random::<u16>();
        }
        self.inner
            .read()
            .await
            .c
            .as_ref()
            .unwrap()
            .send(req)
            .first_answer()
            .await
            .map_err(|x| Error::DNSError(x.to_string()).into())
            .map(|x: op::DnsResponse| x.into_message())
    }
}

async fn dns_stream_builder(
    cfg: &DnsConfig,
    rule_dispatch: Option<Arc<RuleDispatch>>,
) -> Result<(client::Client<DnsRuntimeProvider>, JoinHandle<()>), Error> {
    let dns_resolver = Arc::new(dns::SystemResolver::new(false)?);
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
                ),
            );

            let stream = stream_future
                .await
                .map_err(|x| Error::DNSError(x.to_string()))?;
            let (x, y) = client::Client::<DnsRuntimeProvider>::new(stream, sender);
            Ok((x, tokio::spawn(y)))
        }
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
        DnsConfig::Https(addr, host, iface, proxy, fw_mark) => {
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
                ),
            )
            .build(*addr, host.to_string().into(), "/dns-query".into())
            .await
            .map_err(|x| Error::DNSError(x.to_string()))?;

            let (x, y) = client::Client::<DnsRuntimeProvider>::from_sender(stream);
            Ok((x, tokio::spawn(y)))
        }
    }
}
