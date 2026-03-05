use std::{
    net::{IpAddr, SocketAddr},
    num::{NonZeroU16, ParseIntError},
    ops::RangeInclusive,
};

use rand::RngExt;

use crate::{
    config::internal::proxy::{Hysteria2Obfs, OutboundHysteria2},
    proxy::hysteria2::{Handler, HystOption, Obfs, SalamanderObfs},
    session::SocksAddr,
};

#[derive(Clone)]
pub struct PortGenerator {
    pub default: u16,
    ports: Vec<u16>,
    ranges: Vec<RangeInclusive<u16>>,
}

impl PortGenerator {
    pub fn new(port: u16) -> Self {
        Self {
            default: port,
            ports: vec![],
            ranges: vec![],
        }
    }

    pub fn add_single(&mut self, port: u16) {
        self.ports.push(port);
    }

    fn add_range(&mut self, start: u16, end: u16) {
        self.ranges.push(start..=end);
    }

    pub fn get(&self) -> u16 {
        let mut rng = rand::rng();
        let len = 1
            + self.ports.len()
            + self.ranges.iter().map(|range| range.len()).sum::<usize>();
        let idx = rng.random_range(0..len);
        match idx {
            0 => self.default,
            idx if idx <= self.ports.len() => self.ports[idx - 1],
            idx => {
                let mut range_values = self.ranges.iter().cloned().flatten();
                range_values
                    .nth(idx - 1 - self.ports.len())
                    .expect("port range index is valid")
            }
        }
    }

    pub fn parse_ports_str(self, ports: &str) -> Result<Self, ParseIntError> {
        if ports.is_empty() {
            return Ok(self);
        }
        ports
            .split(',')
            .map(str::trim)
            .try_fold(self, |mut acc, token| {
                let parsed: Result<_, ParseIntError> = token
                    .parse::<u16>()
                    .map(|port| acc.add_single(port))
                    .or_else(|e| {
                        let mut parts = token.split('-');
                        let start = parts.next().ok_or(e.clone())?;
                        let end = parts.next().ok_or(e)?;
                        let start = start.parse::<NonZeroU16>()?;
                        let end = end.parse::<NonZeroU16>()?;
                        acc.add_range(start.get(), end.get());
                        Ok(())
                    })
                    .map(|_| acc);
                parsed
            })
    }
}

impl TryFrom<OutboundHysteria2> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundHysteria2) -> Result<Self, Self::Error> {
        let addr = if let Ok(ip) = value.server.parse::<IpAddr>() {
            SocksAddr::Ip(SocketAddr::new(ip, value.port))
        } else {
            SocksAddr::Domain(value.server.clone(), value.port)
        };

        let obfs = match (value.obfs, value.obfs_password.as_ref()) {
            (Some(obfs), Some(password)) => match obfs {
                Hysteria2Obfs::Salamander => {
                    Some(Obfs::Salamander(SalamanderObfs {
                        key: password.to_owned().into_bytes(),
                    }))
                }
            },
            (Some(_), None) => {
                return Err(crate::Error::InvalidConfig(
                    "hysteria2 `obfs-password` is required when `obfs` is set"
                        .to_owned(),
                ));
            }
            _ => None,
        };

        let ports = if let Some(port_rules) = value.ports {
            Some(
                PortGenerator::new(value.port)
                    .parse_ports_str(&port_rules)
                    .map_err(|e| {
                        crate::Error::InvalidConfig(format!(
                            "hysteria2 parse `ports` failed: {e:?}, input: {port_rules:?}"
                        ))
                    })?,
            )
        } else {
            None
        };

        let sni = value.sni.or(match &addr {
            SocksAddr::Domain(domain, _) => Some(domain.clone()),
            SocksAddr::Ip(_) => None,
        });

        Ok(Handler::new(HystOption {
            name: value.name,
            addr,
            ports,
            sni,
            password: value.password,
            obfs,
            skip_cert_verify: value.skip_cert_verify,
            alpn: value.alpn.unwrap_or_default(),
            fingerprint: value.fingerprint,
            disable_mtu_discovery: value.disable_mtu_discovery.unwrap_or(false),
            ca: value.ca,
            ca_str: value.ca_str,
            up_down: value.up.zip(value.down),
            cwnd: value.cwnd,
            udp_mtu: value.udp_mtu,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proxy::OutboundHandler;

    #[test]
    fn parse_ports_ranges() {
        let generator = PortGenerator::new(1000)
            .parse_ports_str("1001,1002,3000-3002")
            .expect("ports should parse");

        for _ in 0..10 {
            let port = generator.get();
            assert!(
                matches!(port, 1000 | 1001 | 1002 | 3000..=3002),
                "unexpected port generated: {port}"
            );
        }
    }

    #[test]
    fn convert_hysteria2_config() {
        crate::setup_default_crypto_provider();

        let config = OutboundHysteria2 {
            name: "hy2".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            password: "secret".to_owned(),
            skip_cert_verify: true,
            ..Default::default()
        };

        let handler: Handler = config.try_into().expect("converter should succeed");
        assert_eq!(handler.name(), "hy2");
    }
}
