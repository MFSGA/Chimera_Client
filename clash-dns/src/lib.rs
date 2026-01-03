use std::net::SocketAddr;

#[derive(Debug, Default, Clone)]
pub struct DNSListenAddr {
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    // pub doh: Option<DoHConfig>,
    // pub dot: Option<DoTConfig>,
    // pub doh3: Option<DoH3Config>,
}
