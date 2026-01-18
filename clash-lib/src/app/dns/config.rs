use std::net::SocketAddr;

use chimera_dns::DNSListenAddr;

use crate::{Error, config::def::DNSListen};

#[derive(Default)]
pub struct DNSConfig {
    pub listen: DNSListenAddr,
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
                        let addr = u.parse::<SocketAddr>().map_err(|_| {
                            Error::InvalidConfig(format!("invalid dns udp listen address: {u}"))
                        })?;
                        // future: will delete
                        Ok::<DNSListenAddr, Error>(DNSListenAddr {
                            udp: Some(addr),
                            ..Default::default()
                        })
                    }
                })
                .transpose()?
                .unwrap_or_default(),
        })
    }
}
