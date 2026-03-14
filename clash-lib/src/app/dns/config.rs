use std::net::SocketAddr;

use crate::{Error, config::def::DNSListen};

pub use chimera_dns::{DNSListenAddr, DoH3Config, DoHConfig, DoTConfig};

#[derive(Default)]
pub struct DNSConfig {
    pub listen: DNSListenAddr,
    /// 2
    pub ipv6: bool,
    /// 3
    pub enable: bool,
}

impl TryFrom<crate::config::def::Config> for DNSConfig {
    type Error = Error;

    fn try_from(value: crate::def::Config) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&crate::config::def::Config> for DNSConfig {
    type Error = Error;

    fn try_from(c: &crate::config::def::Config) -> Result<Self, Self::Error> {
        let dc = &c.dns;

        Ok(Self {
            listen: dc
                .listen
                .clone()
                .map(|l| match l {
                    DNSListen::Udp(u) => {
                        let addr = parse_listen_addr(&u)?;
                        Ok::<DNSListenAddr, Error>(DNSListenAddr {
                            udp: Some(addr),
                            ..Default::default()
                        })
                        /* Ok(DNSListenAddr {
                            udp: Some(addr),
                            ..Default::default()
                        }) */
                    }
                })
                .transpose()?
                .unwrap_or_default(),
            ipv6: dc.ipv6,
            enable: dc.enable,
        })
    }
}

fn parse_listen_addr(addr: &str) -> Result<SocketAddr, Error> {
    if addr.starts_with(':') {
        format!("0.0.0.0{addr}").parse().map_err(|_| {
            Error::InvalidConfig(format!("invalid dns listen address: {addr}"))
        })
    } else {
        addr.parse().map_err(|_| {
            Error::InvalidConfig(format!("invalid dns listen address: {addr}"))
        })
    }
}
