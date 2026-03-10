use std::{
    fmt::{Debug, Display, Formatter},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use hickory_proto::{op::Message, op::ResponseCode, xfer::Protocol};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};

use crate::{Error, app::dns::helper::build_dns_response_message};

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

#[derive(Clone, Debug)]
pub struct Opts {
    pub host: String,
    pub port: u16,
    pub net: DNSNetMode,
    pub ipv6: bool,
}

#[derive(Debug)]
pub struct DnsClient {
    id: String,
    resolver: TokioResolver,
}

impl DnsClient {
    pub async fn new_client(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        let socket_addr = if let Ok(ip) = opts.host.parse() {
            SocketAddr::new(ip, opts.port)
        } else {
            tokio::net::lookup_host((opts.host.as_str(), opts.port))
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("no ip resolved for dns server {}", opts.host))?
        };

        let protocol = match opts.net {
            DNSNetMode::Udp => Protocol::Udp,
            DNSNetMode::Tcp => Protocol::Tcp,
            DNSNetMode::DoT | DNSNetMode::DoH | DNSNetMode::Dhcp => {
                return Err(Error::DNSError("unsupported dns protocol".into()).into());
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
