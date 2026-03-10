use std::{
    fmt::{Debug, Display, Formatter},
    net::{self, IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use hickory_proto::{op::Message, op::ResponseCode, xfer::Protocol};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};

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

#[derive(Debug)]
pub struct DnsClient {
    id: String,
    resolver: TokioResolver,
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

        let protocol = match opts.net {
            DNSNetMode::Udp => Protocol::Udp,
            DNSNetMode::Tcp => Protocol::Tcp,
            DNSNetMode::DoT | DNSNetMode::DoH | DNSNetMode::Dhcp => {
                return Err(
                    Error::DNSError("unsupported dns protocol".into()).into()
                );
            }
        };

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(socket_addr, protocol));

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.ip_strategy = if opts.ipv6 {
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

        Ok(Arc::new(Self {
            id: format!("{}://{}:{}", opts.net, opts.host, opts.port),
            resolver,
        }))
    }
}

#[async_trait]
impl Client for DnsClient {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let query = msg
            .query()
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;
        let lookup = self
            .resolver
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
