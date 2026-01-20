use std::{
    fmt::{Display, Formatter},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use bytes::BufMut;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};

pub struct SocksAddrType;

impl SocksAddrType {
    pub const DOMAIN: u8 = 0x3;
    pub const V4: u8 = 0x1;
    pub const V6: u8 = 0x4;
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksAddr {
    pub fn any_ipv4() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }

    pub async fn read_from<T: AsyncRead + Unpin>(r: &mut T) -> io::Result<Self> {
        match r.read_u8().await? {
            SocksAddrType::V4 => {
                let ip = Ipv4Addr::from(r.read_u32().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::V6 => {
                let ip = Ipv6Addr::from(r.read_u128().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::DOMAIN => {
                let domain_len = r.read_u8().await? as usize;
                let mut buf = vec![0u8; domain_len];
                let n = r.read_exact(&mut buf).await?;
                if n != domain_len {
                    return Err(io::Error::other("invalid domain length"));
                }
                let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                let port = r.read_u16().await?;
                Ok(Self::Domain(domain, port))
            }
            _ => Err(invalid_atyp()),
        }
    }

    pub fn write_buf<T: BufMut>(&self, buf: &mut T) {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => {
                    buf.put_u8(SocksAddrType::V4);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
                SocketAddr::V6(addr) => {
                    buf.put_u8(SocksAddrType::V6);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
            },
            Self::Domain(domain, port) => {
                buf.put_u8(SocksAddrType::DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(ip) => ip.ip().to_string(),
            SocksAddr::Domain(domain, _) => domain.to_string(),
        }
    }
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::Ip(a) => Self::from(a.to_owned()),
            SocksAddr::Domain(domain, port) => Self::try_from((domain.clone(), *port)).unwrap(),
        }
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl TryFrom<(String, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from(value: (String, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = value.0.parse::<IpAddr>() {
            todo!()
            // return Ok(Self::from((ip, value.1)));
        }
        if value.0.len() > 0xff {
            return Err(io::Error::other("domain too long"));
        }
        Ok(Self::Domain(value.0, value.1))
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

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[todo] {} -> []",
            // self.network,
            self.source,
            // self.destination,
            //self.resolved_ip.unwrap_or(IpAddr::V4(Ipv4Addr::from(0)))
        )
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            network: self.network,
            typ: self.typ,
            source: self.source,
            destination: self.destination.clone(),
            // resolved_ip: self.resolved_ip,
            so_mark: self.so_mark,
            /* iface: self.iface.as_ref().cloned(),
            asn: self.asn.clone(),
            traffic_stats: self.traffic_stats.clone(), */
        }
    }
}

fn invalid_domain() -> io::Error {
    io::Error::other("invalid domain")
}

fn invalid_atyp() -> io::Error {
    io::Error::other("invalid address type")
}
