pub use super::dns_client::DNSNetMode;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ipnet::{AddrParseError, IpNet, Ipv4Net, Ipv6Net};
use serde::Deserialize;
use std::fmt::Display;
use tracing::warn;
use url::Url;

use crate::{
    Error,
    app::net::OutboundInterface,
    common::trie,
    config::def::{
        DNSListen, DNSMode, EdnsClientSubnet as DefEdnsClientSubnet,
        FallbackFilter as DefFallbackFilter,
    },
};

pub use chimera_dns::{DNSListenAddr, DoH3Config, DoHConfig, DoTConfig};

#[derive(Clone, Debug)]
pub struct NameServer {
    pub net: DNSNetMode,
    pub host: url::Host<String>,
    pub port: u16,
    pub interface: Option<OutboundInterface>,
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

#[derive(Clone, Debug, Default)]
pub struct FallbackFilter {
    pub geo_ip: bool,
    pub geo_ip_code: String,
    pub ip_cidr: Option<Vec<IpNet>>,
    pub domain: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EdnsClientSubnet {
    pub ipv4: Option<Ipv4Net>,
    pub ipv6: Option<Ipv6Net>,
}

#[derive(Default)]
pub struct DNSConfig {
    pub listen: DNSListenAddr,
    pub nameserver: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub fallback_filter: FallbackFilter,
    pub default_nameserver: Vec<NameServer>,
    pub nameserver_policy: HashMap<String, NameServer>,
    pub hosts: Option<trie::StringTrie<IpAddr>>,
    pub enhance_mode: DNSMode,
    pub fake_ip_range: IpNet,
    pub fake_ip_filter: Vec<String>,
    pub store_fake_ip: bool,
    pub store_smart_stats: bool,
    pub ipv6: bool,
    pub enable: bool,
    pub edns_client_subnet: Option<EdnsClientSubnet>,
    pub fw_mark: Option<u32>,
}

impl DNSConfig {
    pub fn parse_nameserver(servers: &[String]) -> Result<Vec<NameServer>, Error> {
        let mut nameservers = Vec::new();

        for (index, server) in servers.iter().enumerate() {
            let mut server = server.clone();

            if server == "system" {
                warn!("'system' is not supported as dns nameserver, skipping");
                continue;
            }

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

            let host = match url.host() {
                Some(host) => host,
                None if url.scheme() == "dhcp" => url::Host::Domain("system"),
                None => {
                    return Err(Error::InvalidConfig(format!(
                        "invalid dns server: no host found in {}",
                        server
                    )));
                }
            };

            let host = match host {
                url::Host::Domain(value) => {
                    match value.parse::<std::net::Ipv4Addr>() {
                        Ok(ipv4) => url::Host::Ipv4(ipv4),
                        Err(_) => url::Host::Domain(value.to_string()),
                    }
                }
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
                        "DNS nameserver [{index}] unsupported scheme: {scheme}"
                    )));
                }
            };

            nameservers.push(NameServer {
                net,
                host,
                port,
                interface: DNSConfig::parse_outbound_interface(&url, index)?,
                proxy: DNSConfig::parse_outbound_proxy(&url),
            });
        }

        Ok(nameservers)
    }

    fn parse_outbound_proxy(url: &Url) -> Option<String> {
        let fragment = url.fragment()?;
        for pair in fragment.split('&') {
            if pair.is_empty() {
                continue;
            }
            if let Some(value) = pair.strip_prefix("proxy=") {
                if !value.is_empty() {
                    return Some(value.to_string());
                }
                continue;
            }
            if !pair.contains('=') {
                return Some(pair.to_string());
            }
        }
        None
    }

    fn parse_outbound_interface(
        url: &Url,
        index: usize,
    ) -> Result<Option<OutboundInterface>, Error> {
        let Some(fragment) = url.fragment() else {
            return Ok(None);
        };
        for pair in fragment.split('&') {
            if let Some(value) = pair.strip_prefix("interface=") {
                if !value.is_empty() {
                    return Ok(Some(resolve_outbound_interface(value, index)?));
                }
            }
        }
        Ok(None)
    }

    pub fn parse_nameserver_policy(
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

            let (_, valid) = trie::valid_and_split_domain(domain);
            if !valid {
                return Err(Error::InvalidConfig(format!(
                    "DNS ResolverRule invalid domain: {domain}"
                )));
            }

            out.insert(domain.to_ascii_lowercase(), ns);
        }

        Ok(out)
    }

    pub fn parse_hosts(
        hosts: &HashMap<String, String>,
    ) -> Result<trie::StringTrie<IpAddr>, Error> {
        let mut out = trie::StringTrie::new();
        out.insert("localhost", Arc::new("127.0.0.1".parse::<IpAddr>().unwrap()));

        for (host, ip) in hosts {
            let ip = ip.parse::<IpAddr>().map_err(|e| {
                Error::InvalidConfig(format!("invalid hosts entry {host}: {e}"))
            })?;
            out.insert(
                &host.trim_end_matches('.').to_ascii_lowercase(),
                Arc::new(ip),
            );
        }

        Ok(out)
    }

    pub fn parse_fallback_ip_cidr(ipcidr: &[String]) -> anyhow::Result<Vec<IpNet>> {
        let mut output = vec![];

        for ip in ipcidr {
            let net: IpNet = ip
                .parse()
                .map_err(|x: AddrParseError| Error::InvalidConfig(x.to_string()))?;
            output.push(net);
        }

        Ok(output)
    }

    fn parse_edns_client_subnet(
        ecs: &DefEdnsClientSubnet,
    ) -> Result<EdnsClientSubnet, Error> {
        let ipv4 = ecs
            .ipv4
            .as_ref()
            .map(|value| {
                value.parse::<Ipv4Net>().map_err(|_| {
                    Error::InvalidConfig(format!(
                        "invalid edns-client-subnet ipv4 network: {value}"
                    ))
                })
            })
            .transpose()?;

        let ipv6 = ecs
            .ipv6
            .as_ref()
            .map(|value| {
                value.parse::<Ipv6Net>().map_err(|_| {
                    Error::InvalidConfig(format!(
                        "invalid edns-client-subnet ipv6 network: {value}"
                    ))
                })
            })
            .transpose()?;

        if ipv4.is_none() && ipv6.is_none() {
            return Err(Error::InvalidConfig(
                "edns-client-subnet requires at least one of ipv4/ipv6"
                    .to_string(),
            ));
        }

        Ok(EdnsClientSubnet { ipv4, ipv6 })
    }
}

#[cfg(feature = "tun")]
fn resolve_outbound_interface(
    iface_name: &str,
    index: usize,
) -> Result<OutboundInterface, Error> {
    match iface_name {
        "auto" => crate::app::net::get_outbound_interface().ok_or_else(|| {
            Error::InvalidConfig(
                "DNS nameserver [auto] no outbound interface found".into(),
            )
        }),
        name => crate::app::net::get_interface_by_name(name).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "DNS nameserver [{index}] invalid interface: {name}"
            ))
        }),
    }
}

#[cfg(not(feature = "tun"))]
fn resolve_outbound_interface(
    iface_name: &str,
    index: usize,
) -> Result<OutboundInterface, Error> {
    let _ = index;
    Err(Error::InvalidConfig(format!(
        "DNS nameserver interface requires the `tun` feature: {iface_name}"
    )))
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

        if dc.enable && dc.nameserver.is_empty() {
            return Err(Error::InvalidConfig(
                "dns enabled, no nameserver specified".to_string(),
            ));
        }

        if dc.default_nameserver.is_empty() {
            return Err(Error::InvalidConfig(
                "default nameserver empty".to_string(),
            ));
        }

        let nameserver = DNSConfig::parse_nameserver(&dc.nameserver)?;
        let fallback = DNSConfig::parse_nameserver(&dc.fallback)?;
        let default_nameserver =
            DNSConfig::parse_nameserver(&dc.default_nameserver)?;

        for ns in &default_nameserver {
            if matches!(ns.host, url::Host::Domain(_)) {
                return Err(Error::InvalidConfig(
                    "default dns must be ip address".to_string(),
                ));
            }
        }

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
                    DNSListen::Multiple(map) => {
                        let mut udp = None;
                        let mut tcp = None;
                        let mut doh = None;
                        let mut dot = None;
                        let mut doh3 = None;

                        for (key, value) in map {
                            match key.as_str() {
                                "udp" => {
                                    let raw = value.as_str().ok_or_else(|| {
                                        Error::InvalidConfig(format!(
                                            "invalid udp dns listen address: {value:?}"
                                        ))
                                    })?;
                                    let addr = parse_listen_addr(raw)?;
                                    udp = Some(addr);
                                }
                                "tcp" => {
                                    let raw = value.as_str().ok_or_else(|| {
                                        Error::InvalidConfig(format!(
                                            "invalid tcp dns listen address: {value:?}"
                                        ))
                                    })?;
                                    let addr = parse_listen_addr(raw)?;
                                    tcp = Some(addr);
                                }
                                "doh" => {
                                    doh = Some(DoHConfig::deserialize(value).map_err(
                                        |err| {
                                            Error::InvalidConfig(format!(
                                                "invalid doh dns listen config: {err:?}"
                                            ))
                                        },
                                    )?);
                                }
                                "dot" => {
                                    dot = Some(DoTConfig::deserialize(value).map_err(
                                        |err| {
                                            Error::InvalidConfig(format!(
                                                "invalid dot dns listen config: {err:?}"
                                            ))
                                        },
                                    )?);
                                }
                                "doh3" => {
                                    doh3 = Some(DoH3Config::deserialize(value).map_err(
                                        |err| {
                                            Error::InvalidConfig(format!(
                                                "invalid doh3 dns listen config: {err:?}"
                                            ))
                                        },
                                    )?);
                                }
                                _ => {
                                    return Err(Error::InvalidConfig(format!(
                                        "invalid dns listen address: {key}"
                                    )));
                                }
                            }
                        }

                        Ok::<DNSListenAddr, Error>(DNSListenAddr {
                            udp,
                            tcp,
                            doh,
                            dot,
                            doh3,
                        })
                    }
                })
                .transpose()?
                .unwrap_or_default(),
            nameserver,
            fallback,
            fallback_filter: dc.fallback_filter.clone().into(),
            default_nameserver,
            nameserver_policy: DNSConfig::parse_nameserver_policy(
                &dc.nameserver_policy,
            )?,
            hosts: Some(DNSConfig::parse_hosts(&c.hosts)?),
            enhance_mode: dc.enhanced_mode.clone(),
            fake_ip_range: dc.fake_ip_range.parse::<IpNet>().map_err(|e| {
                Error::InvalidConfig(format!("invalid fake-ip-range: {e}"))
            })?,
            fake_ip_filter: dc.fake_ip_filter.clone(),
            store_fake_ip: c.profile.store_fake_ip,
            store_smart_stats: c.profile.store_smart_stats,
            ipv6: c.ipv6 && dc.ipv6,
            enable: dc.enable,
            edns_client_subnet: dc
                .edns_client_subnet
                .as_ref()
                .map(DNSConfig::parse_edns_client_subnet)
                .transpose()?,
            fw_mark: c.routing_mark,
        })
    }
}

impl From<DefFallbackFilter> for FallbackFilter {
    fn from(filter: DefFallbackFilter) -> Self {
        let ip_cidr = DNSConfig::parse_fallback_ip_cidr(&filter.ip_cidr);
        Self {
            geo_ip: filter.geo_ip,
            geo_ip_code: filter.geo_ip_code.to_uppercase(),
            ip_cidr: ip_cidr.ok(),
            domain: filter.domain,
        }
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
