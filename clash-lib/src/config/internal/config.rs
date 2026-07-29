use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use anyhow::anyhow;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::{
    Error,
    app::remote_content_manager::providers::rule_provider::{
        RuleSetBehavior, RuleSetFormat,
    },
    app::{dns, net::Interface},
    common::auth,
    config::{
        def::{self, LogLevel, RunMode},
        internal::{
            listener::InboundOpts,
            proxy::{OutboundProxy, OutboundProxyProviderDef},
            rule::RuleType,
        },
    },
};

pub struct Config {
    /// 1
    pub rules: Vec<RuleType>,
    /// 2
    pub proxies: HashMap<String, OutboundProxy>,
    /// 3
    pub proxy_groups: HashMap<String, OutboundProxy>,
    /// 3.1
    pub proxy_providers: HashMap<String, OutboundProxyProviderDef>,
    pub rule_providers: HashMap<String, RuleProviderDef>,
    /// 3.2
    pub proxy_names: Vec<String>,
    /// 3.3
    pub users: Vec<auth::User>,
    /// 3.4
    pub listeners: HashSet<InboundOpts>,
    /// 4
    pub general: General,
    /// 5
    pub dns: dns::Config,
    /// 6
    pub tun: TunConfig,
    /// 7
    pub experimental: Option<def::Experimental>,
    /// 8
    pub profile: Profile,
}

impl Config {
    pub fn validate(self) -> Result<Self, crate::Error> {
        for r in self.rules.iter() {
            if !self.proxies.contains_key(r.target())
                && !self.proxy_groups.contains_key(r.target())
            {
                return Err(Error::InvalidConfig(format!(
                    "proxy `{}` referenced in a rule was not found",
                    r.target()
                )));
            }
        }
        #[cfg(feature = "anytls")]
        for opts in &self.listeners {
            if let InboundOpts::Anytls {
                common_opts, users, ..
            } = opts
            {
                let mut seen = std::collections::HashSet::new();
                for user in users {
                    if !seen.insert(user.password.as_str()) {
                        return Err(Error::InvalidConfig(format!(
                            "anytls inbound '{}': duplicate user password",
                            common_opts.name
                        )));
                    }
                }
            }
        }
        Ok(self)
    }
}

pub struct General {
    pub authentication: Vec<String>,
    pub bind_address: BindAddress,
    pub controller: Controller,
    pub mode: RunMode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub interface: Option<Interface>,
    pub routing_mask: Option<u32>,
    pub mmdb: Option<String>,
    pub mmdb_download_url: Option<String>,
    pub asn_mmdb: Option<String>,
    pub asn_mmdb_download_url: Option<String>,
    pub geosite: Option<String>,
    pub geosite_download_url: Option<String>,
}

#[derive(Serialize, Clone, Debug, Copy, PartialEq, Hash, Eq)]
#[serde(transparent)]
pub struct BindAddress(pub IpAddr);
impl BindAddress {
    pub fn all_v4() -> Self {
        Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    pub fn dual_stack() -> Self {
        Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }

    pub fn local() -> Self {
        Self(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    pub fn is_localhost(&self) -> bool {
        match self.0 {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        }
    }
}

impl Default for BindAddress {
    fn default() -> Self {
        Self::all_v4()
    }
}

impl<'de> Deserialize<'de> for BindAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        match str.as_str() {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            "[::]" | "::" => Ok(Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Invalid BindAddress value {str}"
                    )))
                }
            }
        }
    }
}

impl FromStr for BindAddress {
    type Err = anyhow::Error;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            "[::]" | "::" => Ok(Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(anyhow!("Invalid BindAddress value {str}"))
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Controller {
    pub external_controller: Option<String>,
    pub external_controller_ipc: Option<String>,
    pub external_ui: Option<String>,
    pub external_ui_download_url: Option<String>,
    pub secret: Option<String>,
    pub cors_allow_origins: Option<Vec<String>>,
}

pub struct Profile {
    pub store_selected: bool,
    pub store_smart_stats: bool,
    // this is read to dns config directly
    // store_fake_ip: bool,
}

#[derive(Default, Clone)]
pub struct TunConfig {
    pub enable: bool,
    pub device_id: String,
    pub route_all: bool,
    pub routes: Vec<IpNet>,
    pub route_exclude_address: Vec<IpNet>,
    pub gateway: Ipv4Net,
    pub gateway_v6: Option<Ipv6Net>,
    pub mtu: Option<u16>,
    pub so_mark: Option<u32>,
    pub route_table: u32,
    pub dns_hijack: bool,
    pub dns_hijack_rules: Vec<DnsHijackRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsHijackProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsHijackAddress {
    Any,
    Ip(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsHijackRule {
    pub protocol: DnsHijackProtocol,
    pub address: DnsHijackAddress,
    pub port: u16,
}

impl DnsHijackRule {
    pub fn matches_udp(&self, destination: SocketAddr) -> bool {
        self.protocol == DnsHijackProtocol::Udp
            && self.port == destination.port()
            && match self.address {
                DnsHijackAddress::Any => true,
                DnsHijackAddress::Ip(address) => address == destination.ip(),
            }
    }
}

impl TunConfig {
    pub fn dns_hijack_udp_ports(&self) -> Vec<u16> {
        if !self.dns_hijack {
            return Vec::new();
        }
        if self.dns_hijack_rules.is_empty() {
            return vec![53];
        }

        let mut ports = Vec::new();
        for rule in &self.dns_hijack_rules {
            if rule.protocol == DnsHijackProtocol::Udp && !ports.contains(&rule.port)
            {
                ports.push(rule.port);
            }
        }
        ports
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub enum RuleProviderDef {
    Http(HttpRuleProvider),
    File(FileRuleProvider),
    Inline(InlineRuleProvider),
}

#[derive(Serialize, Deserialize)]
pub struct HttpRuleProvider {
    pub url: String,
    pub interval: u64,
    pub behavior: RuleSetBehavior,
    pub path: String,
    pub format: Option<RuleSetFormat>,
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FileRuleProvider {
    pub path: String,
    pub interval: Option<u64>,
    pub behavior: RuleSetBehavior,
    pub format: Option<RuleSetFormat>,
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct InlineRuleProvider {
    pub path: String,
    pub behavior: RuleSetBehavior,
    #[serde(alias = "payload")]
    pub inline_rules: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::{DnsHijackAddress, DnsHijackProtocol, DnsHijackRule, TunConfig};

    #[test]
    fn dns_hijack_rule_matches_udp_destination() {
        let any = DnsHijackRule {
            protocol: DnsHijackProtocol::Udp,
            address: DnsHijackAddress::Any,
            port: 53,
        };
        let specific = DnsHijackRule {
            protocol: DnsHijackProtocol::Udp,
            address: DnsHijackAddress::Ip("1.1.1.1".parse().unwrap()),
            port: 53,
        };
        let tcp = DnsHijackRule {
            protocol: DnsHijackProtocol::Tcp,
            ..any
        };

        assert!(any.matches_udp("8.8.8.8:53".parse().unwrap()));
        assert!(!any.matches_udp("8.8.8.8:5353".parse().unwrap()));
        assert!(specific.matches_udp("1.1.1.1:53".parse().unwrap()));
        assert!(!specific.matches_udp("8.8.8.8:53".parse().unwrap()));
        assert!(!tcp.matches_udp("1.1.1.1:53".parse().unwrap()));

        let ipv6 = DnsHijackRule {
            address: DnsHijackAddress::Ip(IpAddr::V6(
                "2001:4860:4860::8888".parse().unwrap(),
            )),
            ..any
        };
        assert!(ipv6.matches_udp(SocketAddr::new(
            "2001:4860:4860::8888".parse().unwrap(),
            53
        )));
    }

    #[test]
    fn dns_hijack_udp_ports_follow_protocol_rules() {
        let tun = TunConfig {
            dns_hijack: true,
            dns_hijack_rules: vec![
                DnsHijackRule {
                    protocol: DnsHijackProtocol::Tcp,
                    address: DnsHijackAddress::Any,
                    port: 53,
                },
                DnsHijackRule {
                    protocol: DnsHijackProtocol::Udp,
                    address: DnsHijackAddress::Any,
                    port: 5353,
                },
                DnsHijackRule {
                    protocol: DnsHijackProtocol::Udp,
                    address: DnsHijackAddress::Any,
                    port: 5353,
                },
            ],
            ..Default::default()
        };
        assert_eq!(tun.dns_hijack_udp_ports(), vec![5353]);

        let legacy = TunConfig {
            dns_hijack: true,
            ..Default::default()
        };
        assert_eq!(legacy.dns_hijack_udp_ports(), vec![53]);
        assert!(TunConfig::default().dns_hijack_udp_ports().is_empty());
    }
}
