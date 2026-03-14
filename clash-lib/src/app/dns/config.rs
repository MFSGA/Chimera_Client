use std::collections::HashMap;
use std::net::SocketAddr;

use crate::{Error, config::def::DNSListen};

pub use chimera_dns::{DNSListenAddr, DoH3Config, DoHConfig, DoTConfig};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DNSNetMode {
    Udp,
    Tcp,
    DoT,
    DoH,
    Dhcp,
}

#[derive(Clone, Debug)]
pub struct NameServer {
    pub net: DNSNetMode,
    pub host: String,
    pub port: u16,
}

impl NameServer {
    pub async fn to_socket_addr(&self) -> anyhow::Result<SocketAddr> {
        if let Ok(addr) = self.host.parse() {
            return Ok(SocketAddr::new(addr, self.port));
        }

        tokio::net::lookup_host((self.host.as_str(), self.port))
            .await?
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("no ip resolved for dns server {}", self.host)
            })
    }
}

#[derive(Default)]
pub struct DNSConfig {
    pub listen: DNSListenAddr,
    pub nameserver: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub default_nameserver: Vec<NameServer>,
    pub nameserver_policy: HashMap<String, NameServer>,
    pub ipv6: bool,
    pub enable: bool,
}

impl DNSConfig {
    fn parse_nameserver(servers: &[String]) -> Result<Vec<NameServer>, Error> {
        let mut nameservers = Vec::new();

        for server in servers {
            let (scheme, rest) = match server.split_once("://") {
                Some((scheme, rest)) => (scheme, rest),
                None => ("udp", server.as_str()),
            };

            let net = match scheme {
                "udp" => DNSNetMode::Udp,
                "tcp" => DNSNetMode::Tcp,
                "tls" => DNSNetMode::DoT,
                "https" => DNSNetMode::DoH,
                "dhcp" => DNSNetMode::Dhcp,
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "unsupported dns server scheme: {scheme}"
                    )));
                }
            };

            let host_port = rest.split('#').next().unwrap_or(rest).trim_matches('/');
            let (host, port) = match net {
                DNSNetMode::Udp => parse_host_port(host_port, 53)?,
                DNSNetMode::Tcp => parse_host_port(host_port, 53)?,
                DNSNetMode::DoT => parse_host_port(host_port, 853)?,
                DNSNetMode::DoH => parse_host_port(host_port, 443)?,
                DNSNetMode::Dhcp => parse_host_port(host_port, 0)?,
            };

            nameservers.push(NameServer { net, host, port });
        }

        Ok(nameservers)
    }

    fn parse_nameserver_policy(
        policy: &HashMap<String, String>,
    ) -> Result<HashMap<String, NameServer>, Error> {
        let mut out = HashMap::new();

        for (domain, server) in policy {
            let parsed = DNSConfig::parse_nameserver(std::slice::from_ref(server))?;
            let ns = parsed.into_iter().next().ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "invalid dns nameserver policy for domain {domain}"
                ))
            })?;
            out.insert(domain.to_ascii_lowercase(), ns);
        }

        Ok(out)
    }
}

fn parse_host_port(input: &str, default_port: u16) -> Result<(String, u16), Error> {
    if input.is_empty() {
        return Err(Error::InvalidConfig("dns server host is empty".to_string()));
    }

    if let Some(host) = input.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        return Ok((host.to_string(), default_port));
    }

    if let Ok(addr) = input.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }

    if let Some((host, port)) = input.rsplit_once(':')
        && !host.contains(':')
    {
        let port = port.parse::<u16>().map_err(|_| {
            Error::InvalidConfig(format!("invalid dns server port in {input}"))
        })?;
        return Ok((host.to_string(), port));
    }

    Ok((input.to_string(), default_port))
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
                            Error::InvalidConfig(format!(
                                "invalid dns udp listen address: {u}"
                            ))
                        })?;
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
            nameserver: DNSConfig::parse_nameserver(&dc.nameserver)?,
            fallback: DNSConfig::parse_nameserver(&dc.fallback)?,
            default_nameserver: DNSConfig::parse_nameserver(&dc.default_nameserver)?,
            nameserver_policy: DNSConfig::parse_nameserver_policy(
                &dc.nameserver_policy,
            )?,
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
