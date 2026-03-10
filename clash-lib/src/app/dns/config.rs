pub use super::dns_client::DNSNetMode;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use chimera_dns::DNSListenAddr;
use ipnet::IpNet;
use std::fmt::Display;
use url::Url;

use crate::{
    Error,
    config::def::{DNSListen, DNSMode, FallbackFilter as DefFallbackFilter},
};

#[derive(Clone, Debug)]
pub struct NameServer {
    pub net: DNSNetMode,
    pub host: url::Host<String>,
    pub port: u16,
    pub interface: Option<String>,
    pub proxy: Option<String>,
}

impl Display for NameServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}:{}#{:?}",
            self.net, self.host, self.port, self.interface,
        )
    }
}

impl NameServer {
    pub async fn to_socket_addr(&self) -> anyhow::Result<SocketAddr> {
        match &self.host {
            url::Host::Ipv4(ip) => return Ok(SocketAddr::new((*ip).into(), self.port)),
            url::Host::Ipv6(ip) => return Ok(SocketAddr::new((*ip).into(), self.port)),
            url::Host::Domain(host) => {
                return tokio::net::lookup_host((host.as_str(), self.port))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("no ip resolved for dns server {}", host));
            }
        }
    }
}

#[derive(Default)]
pub struct FallbackFilter {
    pub geo_ip: bool,
    pub geo_ip_code: String,
    pub ip_cidr: Vec<IpNet>,
    pub domain: Vec<String>,
}

#[derive(Default)]
pub struct DNSConfig {
    pub listen: DNSListenAddr,
    pub nameserver: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub fallback_filter: FallbackFilter,
    pub default_nameserver: Vec<NameServer>,
    pub nameserver_policy: HashMap<String, NameServer>,
    pub hosts: HashMap<String, IpAddr>,
    pub enhance_mode: DNSMode,
    pub fake_ip_range: IpNet,
    pub fake_ip_filter: Vec<String>,
    pub store_fake_ip: bool,
    pub ipv6: bool,
    pub enable: bool,
    pub edns_client_subnet: Option<()>,
    pub fw_mark: Option<u32>,
}

impl DNSConfig {
    fn parse_nameserver(servers: &[String]) -> Result<Vec<NameServer>, Error> {
        let mut nameservers = Vec::new();

        for server in servers {
            let mut server = server.clone();

            if !server.contains("://") {
                if server.contains(':') && !server.starts_with('[') {
                    server = format!("udp://[{server}]");
                } else {
                    server = format!("udp://{server}");
                }
            }

            let url = Url::parse(&server).map_err(|_| {
                Error::InvalidConfig(format!("invalid dns server: {}", server))
            })?;

            let host = url.host().ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "invalid dns server: no host found in {}",
                    server
                ))
            })?;

            let host = match host {
                url::Host::Domain(value) => match value.parse::<std::net::Ipv4Addr>() {
                    Ok(ipv4) => url::Host::Ipv4(ipv4),
                    Err(_) => url::Host::Domain(value.to_string()),
                },
                value => value.to_owned(),
            };

            let (net, port) = match url.scheme() {
                "udp" => (DNSNetMode::Udp, url.port().unwrap_or(53)),
                "tcp" => (DNSNetMode::Tcp, url.port().unwrap_or(53)),
                "tls" => (DNSNetMode::DoT, url.port().unwrap_or(853)),
                "https" => (DNSNetMode::DoH, url.port().unwrap_or(443)),
                "dhcp" => (DNSNetMode::Dhcp, url.port().unwrap_or(0)),
                scheme => {
                    return Err(Error::InvalidConfig(format!(
                        "unsupported dns server scheme: {scheme}"
                    )));
                }
            };

            nameservers.push(NameServer {
                net,
                host,
                port,
                interface: None,
                proxy: None,
            });
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

    fn parse_hosts(hosts: &HashMap<String, String>) -> Result<HashMap<String, IpAddr>, Error> {
        let mut out = HashMap::from([(
            "localhost".to_string(),
            "127.0.0.1".parse::<IpAddr>().expect("localhost ip should be valid"),
        )]);

        for (host, ip) in hosts {
            let ip = ip.parse::<IpAddr>().map_err(|e| {
                Error::InvalidConfig(format!("invalid hosts entry {host}: {e}"))
            })?;
            out.insert(host.trim_end_matches('.').to_ascii_lowercase(), ip);
        }

        Ok(out)
    }

    fn parse_fallback_filter(filter: &DefFallbackFilter) -> Result<FallbackFilter, Error> {
        let mut ip_cidr = Vec::with_capacity(filter.ip_cidr.len());
        for cidr in &filter.ip_cidr {
            ip_cidr.push(cidr.parse::<IpNet>().map_err(|e| {
                Error::InvalidConfig(format!("invalid fallback ipcidr {cidr}: {e}"))
            })?);
        }

        Ok(FallbackFilter {
            geo_ip: filter.geo_ip,
            geo_ip_code: filter.geo_ip_code.clone(),
            ip_cidr,
            domain: filter.domain.clone(),
        })
    }
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
                    }
                })
                .transpose()?
                .unwrap_or_default(),
            nameserver: DNSConfig::parse_nameserver(&dc.nameserver)?,
            fallback: DNSConfig::parse_nameserver(&dc.fallback)?,
            fallback_filter: DNSConfig::parse_fallback_filter(&dc.fallback_filter)?,
            default_nameserver: DNSConfig::parse_nameserver(&dc.default_nameserver)?,
            nameserver_policy: DNSConfig::parse_nameserver_policy(
                &dc.nameserver_policy,
            )?,
            hosts: DNSConfig::parse_hosts(&c.hosts)?,
            enhance_mode: dc.enhanced_mode.clone(),
            fake_ip_range: dc
                .fake_ip_range
                .parse::<IpNet>()
                .map_err(|e| Error::InvalidConfig(format!("invalid fake-ip-range: {e}")))?,
            fake_ip_filter: dc.fake_ip_filter.clone(),
            store_fake_ip: c.profile.store_fake_ip,
            ipv6: dc.ipv6,
            enable: dc.enable,
            edns_client_subnet: None,
            fw_mark: None,
        })
    }
}
