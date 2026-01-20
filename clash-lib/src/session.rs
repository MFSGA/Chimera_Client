use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksAddr {
    pub fn any_ipv4() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Type {
    Http,
    HttpConnect,
    Socks5,
    #[cfg(feature = "tun")]
    Tun,
    #[cfg(all(target_os = "linux", feature = "tproxy"))]
    Tproxy,
    #[cfg(all(target_os = "linux", feature = "redir"))]
    Redir,
    Tunnel,
    Shadowsocks,
    Ignore,
}

#[derive(Serialize)]
pub struct Session {
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The type of the inbound connection.
    pub typ: Type,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The packet mark SO_MARK
    pub so_mark: Option<u32>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            typ: Type::Http,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            destination: SocksAddr::any_ipv4(),
            so_mark: None,
        }
    }
}
