use std::{net::SocketAddr, path::Path};

mod handler;

mod utils;

pub use handler::{DNSError, get_dns_listener};

// #[derive(Debug, Deserialize, Clone)]
// #[serde(rename_all = "kebab-case")]
#[derive(Debug, Clone)]
pub struct DoHConfig {}

#[derive(Debug, Clone)]
pub struct DoH3Config {}

#[derive(Debug, Clone)]
pub struct DoTConfig {}

#[derive(Debug, Default, Clone)]
pub struct DNSListenAddr {
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    pub doh: Option<DoHConfig>,
    pub dot: Option<DoTConfig>,
    pub doh3: Option<DoH3Config>,
}

pub trait DnsMessageExchanger: Send + Sync {
    fn ipv6(&self) -> bool;
    // async fn exchange(&self, message: &Message) -> Result<Message, DNSError>;
}
