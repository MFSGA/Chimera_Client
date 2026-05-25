use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use anyhow::anyhow;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::{
    Error,
    app::{dns, net::Interface},
    common::auth,
    config::{
        def::{LogLevel, RunMode},
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
}

impl TunConfig {
    pub fn dedicated_dns_ipv4(&self) -> Option<Ipv4Addr> {
        let network = u32::from(self.gateway.network());
        let broadcast = u32::from(self.gateway.broadcast());
        let candidate = network.checked_add(2)?;

        if candidate >= broadcast {
            return None;
        }

        Some(Ipv4Addr::from(candidate))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub enum RuleProviderDef {
    // Http(HttpRuleProvider),
    File(FileRuleProvider),
    // Inline(InlineRuleProvider),
}

#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FileRuleProvider {
    pub path: String,
    // todo
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::TunConfig;

    #[test]
    fn dedicated_dns_is_gateway_plus_one_in_24() {
        let tun = TunConfig {
            gateway: "198.18.0.1/24".parse().unwrap(),
            ..Default::default()
        };
        assert_eq!(tun.dedicated_dns_ipv4(), Some(Ipv4Addr::new(198, 18, 0, 2)));
    }

    #[test]
    fn dedicated_dns_in_16_subnet() {
        let tun = TunConfig {
            gateway: "10.0.0.1/16".parse().unwrap(),
            ..Default::default()
        };
        assert_eq!(tun.dedicated_dns_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn dedicated_dns_gateway_is_network_plus_one() {
        let tun = TunConfig {
            gateway: "172.16.0.5/24".parse().unwrap(),
            ..Default::default()
        };
        // gateway addr (172.16.0.5) != network+1 (172.16.0.1), but
        // dedicated_dns_ipv4 computes from network address: network+2 = 172.16.0.2
        assert_eq!(tun.dedicated_dns_ipv4(), Some(Ipv4Addr::new(172, 16, 0, 2)));
    }

    #[test]
    fn dedicated_dns_in_30_subnet_room_for_dns() {
        let tun = TunConfig {
            gateway: "10.0.0.1/30".parse().unwrap(),
            ..Default::default()
        };
        // /30 subnet: network=10.0.0.0, broadcast=10.0.0.3
        // network+2 = 10.0.0.2 < 10.0.0.3, so Some(10.0.0.2)
        assert_eq!(tun.dedicated_dns_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn dedicated_dns_in_31_subnet_too_small() {
        let tun = TunConfig {
            gateway: "10.0.0.1/31".parse().unwrap(),
            ..Default::default()
        };
        // /31 subnet: network=10.0.0.0, broadcast=10.0.0.1
        // candidate overflow would clamp, so None
        assert_eq!(tun.dedicated_dns_ipv4(), None);
    }

    #[test]
    fn dedicated_dns_in_32_subnet_too_small() {
        let tun = TunConfig {
            gateway: "10.0.0.1/32".parse().unwrap(),
            ..Default::default()
        };
        // /32 subnet: network=10.0.0.1, broadcast=10.0.0.1
        // network+2 = 10.0.0.3 > 10.0.0.1, so None
        assert_eq!(tun.dedicated_dns_ipv4(), None);
    }

    #[test]
    fn dedicated_dns_overflow_protection() {
        // Use network address near u32::MAX to test checked_add safety
        let tun = TunConfig {
            gateway: "255.255.255.0/24".parse().unwrap(),
            ..Default::default()
        };
        // network = 255.255.255.0, broadcast = 255.255.255.255
        // network+2 = 255.255.255.2 <= broadcast = 255.255.255.255, ok
        assert_eq!(
            tun.dedicated_dns_ipv4(),
            Some(Ipv4Addr::new(255, 255, 255, 2))
        );
    }

    #[test]
    fn dedicated_dns_default_gateway() {
        let tun = TunConfig {
            gateway: "198.18.0.1/24".parse().unwrap(),
            ..Default::default()
        };
        let dns = tun.dedicated_dns_ipv4().unwrap();
        // DNS must not be the gateway IP itself
        assert_ne!(dns, Ipv4Addr::new(198, 18, 0, 1));
        // DNS must not be a public IP
        assert!(!dns.is_global());
    }
}
