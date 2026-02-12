use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::{
    Error,
    app::dns,
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
    pub dns: dns::DNSConfig,
    /// 6
    pub tun: TunConfig,
    /// 7
    pub profile: Profile,
}

impl Config {
    pub fn validate(self) -> Result<Self, crate::Error> {
        for r in self.rules.iter() {
            if !self.proxies.contains_key(r.target()) && !self.proxy_groups.contains_key(r.target())
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
    /// 1
    pub log_level: LogLevel,
    /// 2
    pub(crate) controller: Controller,
    /// 3
    pub mmdb: Option<String>,
    /// 4
    pub mmdb_download_url: Option<String>,
    /// 5
    pub mode: RunMode,
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

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Controller {
    pub external_controller: Option<String>,
    pub external_controller_ipc: Option<String>,
    pub external_ui: Option<String>,
    pub secret: Option<String>,
    pub cors_allow_origins: Option<Vec<String>>,
}

pub struct Profile {
    pub store_selected: bool,
    pub store_smart_stats: bool,
    // this is read to dns config directly
    // store_fake_ip: bool,
}

#[derive(Default)]
pub struct TunConfig {
    pub enable: bool,
    pub device_id: String,
    pub route_all: bool,
    pub routes: Vec<IpNet>,
    pub gateway: Ipv4Net,
    pub gateway_v6: Option<Ipv6Net>,
    pub mtu: Option<u16>,
    pub so_mark: Option<u32>,
    pub route_table: u32,
    pub dns_hijack: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum RuleProviderDef {
    // Http(HttpRuleProvider),
    File(FileRuleProvider),
    // Inline(InlineRuleProvider),
}

#[derive(Serialize, Deserialize)]
pub struct FileRuleProvider {
    pub path: String,
    // todo
}
