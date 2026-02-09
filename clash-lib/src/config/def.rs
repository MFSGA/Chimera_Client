use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::Value;

use std::{collections::HashMap, fmt::Display, path::PathBuf, str::FromStr};

use crate::{Error, config::internal::config::BindAddress};

const DEFAULT_ROUTE_TABLE: u32 = 2468;

fn default_tun_device_id() -> String {
    "utun1989".to_string()
}

fn default_tun_address() -> String {
    "198.18.0.1/24".to_string()
}

fn default_route_table() -> u32 {
    DEFAULT_ROUTE_TABLE
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum DnsHijack {
    Switch(bool),
    List(Vec<String>),
}

impl Default for DnsHijack {
    fn default() -> Self {
        Self::Switch(false)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TunConfig {
    pub enable: bool,
    #[serde(alias = "device_id", alias = "device-url", alias = "device")]
    #[serde(default = "default_tun_device_id")]
    pub device_id: String,
    #[serde(default = "default_tun_address")]
    pub gateway: String,
    #[serde(alias = "gateway_v6", alias = "gateway-v6")]
    pub gateway_v6: Option<String>,
    pub routes: Option<Vec<String>>,
    #[serde(default, alias = "route_all")]
    pub route_all: bool,
    pub mtu: Option<u16>,
    #[serde(alias = "so_mark")]
    pub so_mark: Option<u32>,
    #[serde(default = "default_route_table", alias = "route_table")]
    pub route_table: u32,
    #[serde(default, alias = "dns_hijack")]
    pub dns_hijack: DnsHijack,
}

// todo: rename to DefConfig
#[derive(Deserialize)]
pub struct Config {
    /// 1. Allow connections from IP addresses other than local listening address
    pub allow_lan: Option<bool>,
    /// The address that the inbound listens on
    /// 2. # Note
    /// - setting this to `*` will listen on all interfaces, which is
    ///   essentially the same as setting it to `0.0.0.0`
    /// - setting this to non local IP will enable `allow_lan` automatically
    /// - and if you don't want `allow_lan` to be enabled, you should set this
    ///   to `localhost` or `127.1`
    pub bind_address: BindAddress,
    /// 3. Proxy settings
    #[serde(rename = "proxies")]
    pub proxy: Option<Vec<HashMap<String, Value>>>,
    /// 11. HTTP and SOCKS5 proxy authentication
    #[serde(default)]
    pub authentication: Vec<String>,
    /// 4. Proxy group settings
    pub proxy_group: Option<Vec<HashMap<String, Value>>>,
    #[serde(rename = "rules")]
    /// 5. Rule settings
    pub rule: Option<Vec<String>>,

    /// 6. Log level
    /// Either `debug`, `info`, `warning`, `error` or `off`
    pub log_level: LogLevel,
    /// external controller address
    pub external_controller: Option<String>,
    /// dashboard folder path relative to the $CWD
    pub external_ui: Option<String>,
    /// external controller secret
    pub secret: Option<String>,
    /// CORS allowed origins
    /// # examples
    /// ```yaml
    /// cors-allow-origins:
    ///   - "https://example.com"
    #[serde(rename = "cors-allow-origins")]
    pub cors_allow_origins: Option<Vec<String>>,
    #[cfg_attr(not(unix), serde(alias = "external-controller-pipe"))]
    #[cfg_attr(unix, serde(alias = "external-controller-unix"))]
    pub external_controller_ipc: Option<String>,
    /// 8. DNS client/server settings
    pub dns: DNS,
    /// 9 Profile settings
    pub profile: Profile,
    /// 10.1 Path to country mmdb file (GeoIP)
    pub mmdb: Option<String>,
    /// 10.2 Download URL for country mmdb file
    #[serde(rename = "mmdb-download-url")]
    pub mmdb_download_url: Option<String>,
    /// 11.1 The HTTP proxy port
    #[serde(alias = "http_port")]
    pub port: Option<Port>,
    /// The SOCKS5 proxy port
    pub socks_port: Option<Port>,
    /// The redir port
    #[doc(hidden)]
    pub redir_port: Option<Port>,
    pub tproxy_port: Option<Port>,
    /// The HTTP/SOCKS5 mixed proxy port
    /// # Example
    /// ```yaml
    /// mixed-port: 7892
    /// ```
    pub mixed_port: Option<Port>,
    /// TUN settings
    pub tun: Option<TunConfig>,
    /// 12
    pub listeners: Option<Vec<HashMap<String, Value>>>,
    // 13. these options has default vals,
    // and needs extra processing
    /// whether your network environment supports IPv6
    /// this will affect the DNS server response to AAAA questions
    /// default is `false`
    pub ipv6: bool,
    /// 14. fwmark on Linux only
    /// # Note
    /// - traffics originated from clash will be marked with this value
    /// - so you can use this value to match the traffic in iptables to avoid
    ///   traffic loops
    pub routing_mark: Option<u32>,
    /// 15. Clash router working mode
    /// Either `rule`, `global` or `direct`
    #[serde(default)]
    pub mode: RunMode,
}

impl TryFrom<PathBuf> for Config {
    type Error = Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        let content = std::fs::read_to_string(value)?;
        let config = content.parse::<Config>()?;
        Ok(config)
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut val: Value = serde_yaml::from_str(s).map_err(|e| {
            Error::InvalidConfig(format!("couldn't not parse config content {s}: {e}"))
        })?;

        val.apply_merge().map_err(|e| {
            Error::InvalidConfig(format!(
                "failed to process anchors in config content {s}: {e}"
            ))
        })?;

        serde_yaml::from_value(val)
            .map_err(|e| Error::InvalidConfig(format!("could not parse config content: {e}")))
    }
}

#[derive(PartialEq, Serialize, Deserialize, Default, Copy, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Error,
    #[serde(alias = "warn")]
    Warning,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Error => write!(f, "error"),
            LogLevel::Warning => write!(f, "warn"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum DNSListen {
    Udp(String),
    // todo
    // Multiple(HashMap<String, Value>),
}

/// DNS client/server settings
/// This section is optional. When not present, the DNS server will be disabled
/// and system DNS config will be used # Example
/// ```yaml
/// dns:
///   enable: true
///   ipv6: false # when the false, response to AAAA questions will be empty
///   listen:
///     udp: 127.0.0.1:53553
///     tcp: 127.0.0.1:53553
///     dot:
///       addr: 127.0.0.1:53554
///       hostname: dns.clash
///       ca-cert: dns.crt
///       ca-key: dns.key
///     doh:
///       addr: 127.0.0.1:53555
///       ca-cert: dns.crt
///       ca-key: dns.key
///   # edns-client-subnet:
///   #   ipv4: 1.2.3.0/24
///   #   ipv6: 2001:db8::/56
/// ```

#[derive(Serialize, Deserialize, Educe)]
#[serde(rename_all = "kebab-case", default)]
#[educe(Default)]
pub struct DNS {
    /// Enable IPv6 DNS responses (AAAA)
    pub ipv6: bool,
    /// DNS server listening address. If not present, the DNS server will be
    /// disabled.
    pub listen: Option<DNSListen>,
    /// 3. When disabled, system DNS config will be used
    /// All other DNS related options will only be used when this is enabled
    pub enable: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
pub struct Profile {
    /// Store the `select` results in $CWD/cache.db
    pub store_selected: bool,
    /// persistence fakeip
    #[serde(rename = "store-fake-ip")]
    pub store_fake_ip: bool,
    /// Store smart proxy group statistics and preferences
    #[serde(rename = "store-smart-stats")]
    pub store_smart_stats: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            store_selected: true,
            store_fake_ip: false,
            store_smart_stats: true,
        }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Copy)]
pub struct Port(pub u16);

impl From<Port> for u16 {
    fn from(val: Port) -> Self {
        val.0
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StrOrNum {
            Str(String),
            Num(u64),
            Other,
        }

        let value = StrOrNum::deserialize(deserializer)?;

        match value {
            StrOrNum::Num(num) => u16::try_from(num)
                .map(Port)
                .map_err(|_| serde::de::Error::custom("Port number out of range")),

            StrOrNum::Str(s) => s.parse::<u16>().map(Port).map_err(serde::de::Error::custom),

            StrOrNum::Other => Err(serde::de::Error::custom("Invalid type for port")),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[serde(alias = "Global")]
    Global,
    #[default]
    #[serde(alias = "Rule")]
    Rule,
    #[serde(alias = "Direct")]
    Direct,
}

impl Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::Global => write!(f, "global"),
            RunMode::Rule => write!(f, "rule"),
            RunMode::Direct => write!(f, "direct"),
        }
    }
}
