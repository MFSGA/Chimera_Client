use std::{
    fmt::{Debug, Display, Formatter},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use hickory_proto::{op::Message, op::ResponseCode, xfer::Protocol};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use tokio::sync::RwLock;

use crate::{
    Error,
    app::dns::{ClashResolver, helper::build_dns_response_message},
    proxy::OutboundHandler,
};

use super::{Client, ThreadSafeDNSClient};

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone)]
pub struct Opts {
    pub father: Option<Arc<dyn ClashResolver>>,
    pub host: url::Host<String>,
    pub port: u16,
    pub net: DNSNetMode,
    pub iface: Option<String>,
    pub proxy: Arc<dyn OutboundHandler>,
    pub ecs: Option<()>,
    pub fw_mark: Option<u32>,
    pub ipv6: bool,
}

enum DnsConfig {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls(SocketAddr, url::Host<String>),
    Https(SocketAddr, url::Host<String>),
}

impl Display for DnsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsConfig::Udp(addr) => write!(f, "UDP: {}:{}", addr.ip(), addr.port()),
            DnsConfig::Tcp(addr) => write!(f, "TCP: {}:{}", addr.ip(), addr.port()),
            DnsConfig::Tls(addr, host) => {
                write!(f, "TLS: {}:{} host: {}", addr.ip(), addr.port(), host)
            }
            DnsConfig::Https(addr, host) => {
                write!(f, "HTTPS: {}:{} host: {}", addr.ip(), addr.port(), host)
            }
        }
    }
}

struct Inner {
    resolver: Option<TokioResolver>,
}

pub struct DnsClient {
    inner: Arc<RwLock<Inner>>,
    cfg: DnsConfig,
    proxy: Arc<dyn OutboundHandler>,
    host: url::Host<String>,
    port: u16,
    net: DNSNetMode,
    iface: Option<String>,
    ecs: Option<()>,
    ipv6: bool,
}

impl DnsClient {
    pub async fn new_client(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        let resolved_ip = match &opts.host {
            url::Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            url::Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            url::Host::Domain(domain) => match &opts.father {
                Some(father) => father.resolve(domain, false).await?,
                None => tokio::net::lookup_host((domain.as_str(), opts.port))
                    .await?
                    .next()
                    .map(|addr| addr.ip()),
            },
        };
        let ip = resolved_ip.ok_or_else(|| {
            anyhow::anyhow!("no ip resolved for dns server {}", opts.host)
        })?;
        let socket_addr = SocketAddr::new(ip, opts.port);

        let cfg = match opts.net {
            DNSNetMode::Udp => DnsConfig::Udp(socket_addr),
            DNSNetMode::Tcp => DnsConfig::Tcp(socket_addr),
            DNSNetMode::DoT => DnsConfig::Tls(socket_addr, opts.host.clone()),
            DNSNetMode::DoH => DnsConfig::Https(socket_addr, opts.host.clone()),
            DNSNetMode::Dhcp => {
                return Err(Error::DNSError("unsupported dns protocol".into()).into());
            }
        };

        Ok(Arc::new(Self {
            inner: Arc::new(RwLock::new(Inner { resolver: None })),
            cfg,
            proxy: opts.proxy,
            host: opts.host,
            port: opts.port,
            net: opts.net,
            iface: opts.iface,
            ecs: opts.ecs,
            ipv6: opts.ipv6,
        }))
    }

    fn apply_edns_client_subnet(&self, _message: &mut Message) {}

    async fn ensure_resolver(&self) -> anyhow::Result<TokioResolver> {
        if let Some(resolver) = self.inner.read().await.resolver.clone() {
            return Ok(resolver);
        }

        let protocol = match self.net {
            DNSNetMode::Udp => Protocol::Udp,
            DNSNetMode::Tcp => Protocol::Tcp,
            DNSNetMode::DoT | DNSNetMode::DoH | DNSNetMode::Dhcp => {
                return Err(Error::DNSError("unsupported dns protocol".into()).into());
            }
        };

        let socket_addr = match &self.cfg {
            DnsConfig::Udp(addr) | DnsConfig::Tcp(addr) => *addr,
            DnsConfig::Tls(addr, _) | DnsConfig::Https(addr, _) => *addr,
        };

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(socket_addr, protocol));

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.ip_strategy = if self.ipv6 {
            hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6
        } else {
            hickory_resolver::config::LookupIpStrategy::Ipv4Only
        };

        let resolver = TokioResolver::builder_with_config(
            config,
            TokioConnectionProvider::default(),
        )
        .with_options(resolver_opts)
        .build();

        self.inner.write().await.resolver = Some(resolver.clone());
        Ok(resolver)
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
        format!("{}#{}:{}", &self.net, &self.host, &self.port)
    }

    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let query = msg
            .query()
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;

        let mut outbound = msg.clone();
        self.apply_edns_client_subnet(&mut outbound);

        let lookup = self
            .ensure_resolver()
            .await?
            .lookup(query.name().clone(), query.query_type())
            .await?;

        let records: Vec<_> = lookup.record_iter().cloned().collect();
        let mut response = build_dns_response_message(msg, true, false);

        if records.is_empty() {
            response.set_response_code(ResponseCode::NXDomain);
            return Ok(response);
        }

        response.set_response_code(ResponseCode::NoError);
        response.set_answer_count(records.len() as u16);
        response.add_answers(records);
        Ok(response)
    }
}
