use std::{net::SocketAddr, path::Path};

use async_trait::async_trait;
use hickory_proto::op::Message;
use serde::Deserialize;

mod handler;

mod utils;

pub use handler::{DNSError, get_dns_listener};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoHConfig {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoH3Config {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoTConfig {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
}

pub type DnsServerKey = Option<String>;
pub type DnsServerCert = Option<String>;

#[derive(Debug, Default, Clone)]
pub struct DNSListenAddr {
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    pub doh: Option<DoHConfig>,
    pub dot: Option<DoTConfig>,
    pub doh3: Option<DoH3Config>,
}

#[async_trait]
pub trait DnsMessageExchanger: Send + Sync {
    fn ipv6(&self) -> bool;
    async fn exchange(&self, message: &Message) -> Result<Message, DNSError>;
}
