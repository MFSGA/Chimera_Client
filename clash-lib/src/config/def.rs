use educe::Educe;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use std::{collections::HashMap, fmt::Display, path::PathBuf, str::FromStr};

use crate::{Error, config::internal::config::BindAddress};

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
    #[default]
    Info,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Info => write!(f, "info"),
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
    /// DNS server listening address. If not present, the DNS server will be
    /// disabled.
    pub listen: Option<DNSListen>,
}
