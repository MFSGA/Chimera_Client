use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::Value;

use std::{collections::HashMap, fmt::Display, path::PathBuf, str::FromStr};

use crate::{
    Error,
    app::remote_content_manager::providers::rule_provider::{
        RuleSetBehavior, RuleSetFormat,
    },
    config::internal::{
        config::BindAddress,
        listener::InboundOpts,
        proxy::{
            OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
        },
    },
};

const DEFAULT_ROUTE_TABLE: u32 = 2468;
const DEFAULT_ROUTE_TABLE_V6: u32 = 2469;

fn default_tun_device_id() -> String {
    "utun1989".to_string()
}

fn default_tun_address() -> String {
    // Keep the TUN link subnet separate from the default 198.19.0.0/16
    // fake-IP pool. Fake-IP traffic is routed to TUN explicitly.
    "198.18.0.1/30".to_string()
}

pub(crate) fn default_tun_address_v6() -> String {
    "fd00:198:18::1/126".to_string()
}

fn default_route_table() -> u32 {
    DEFAULT_ROUTE_TABLE
}

fn default_route_table_v6() -> u32 {
    DEFAULT_ROUTE_TABLE_V6
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
    pub ipv6: Option<bool>,
    #[serde(alias = "gateway_v6", alias = "gateway-v6")]
    pub gateway_v6: Option<String>,
    pub routes: Option<Vec<String>>,
    #[serde(default, alias = "route_exclude_address")]
    pub route_exclude_address: Option<Vec<String>>,
    #[serde(default, alias = "inet4_route_exclude_address")]
    pub inet4_route_exclude_address: Option<Vec<String>>,
    #[serde(default, alias = "inet6_route_exclude_address")]
    pub inet6_route_exclude_address: Option<Vec<String>>,
    #[serde(default, alias = "route_all", alias = "auto-route")]
    pub route_all: bool,
    /// Mihomo's strict-route is not implemented by Chimera's platform routing.
    /// Keep the field explicit so a privacy-sensitive setting cannot be ignored.
    #[serde(default)]
    pub strict_route: bool,
    pub mtu: Option<u16>,
    #[serde(alias = "so_mark")]
    pub so_mark: Option<u32>,
    #[serde(default = "default_route_table", alias = "route_table")]
    pub route_table: u32,
    #[serde(default = "default_route_table_v6", alias = "route_table_v6")]
    pub route_table_v6: u32,
    #[serde(default, alias = "dns_hijack")]
    pub dns_hijack: DnsHijack,
}

#[derive(Deserialize, Educe)]
#[serde(rename_all = "kebab-case", default)]
#[educe(Default)]
pub struct Config {
    /// 1. Allow connections from IP addresses other than local listening address
    pub allow_lan: Option<bool>,
    /// The address that the inbound listens on
    /// 2. # Note
    /// - setting this to `*` will listen on all interfaces, which is
    ///   essentially the same as setting it to `0.0.0.0`
    /// - binding to a wildcard or non-loopback address does not enable LAN
    ///   access by itself; `allow-lan: true` must still be set explicitly
    /// - to keep the proxy local-only, use a loopback address such as
    ///   `localhost` or `127.0.0.1`
    pub bind_address: BindAddress,
    /// 3. Proxy settings
    #[serde(rename = "proxies")]
    pub proxy: Option<Vec<OutboundProxyProtocol>>,
    /// 11. HTTP and SOCKS5 proxy authentication
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(rename = "proxy-groups")]
    /// 4. Proxy group settings
    pub proxy_group: Option<Vec<OutboundGroupProtocol>>,
    #[serde(rename = "rules")]
    /// 5. Rule settings
    pub rule: Option<Vec<String>>,

    /// 6. Log level
    ///
    /// Either `debug`, `info`, `warning`, `error` or `off`
    pub log_level: LogLevel,
    /// external controller address
    pub external_controller: Option<String>,
    /// dashboard folder path relative to the $CWD
    pub external_ui: Option<String>,
    /// dashboard download URL for bootstrapping external UI assets
    pub external_ui_url: Option<String>,
    /// external controller secret
    pub secret: Option<String>,
    /// CORS allowed origins
    /// # examples
    /// ```yaml
    /// cors-allow-origins:
    ///   - "https://example.com"
    #[serde(rename = "cors-allow-origins")]
    pub cors_allow_origins: Option<Vec<String>>,
    #[serde(default)]
    pub hosts: HashMap<String, String>,
    #[cfg_attr(not(unix), serde(alias = "external-controller-pipe"))]
    #[cfg_attr(unix, serde(alias = "external-controller-unix"))]
    pub external_controller_ipc: Option<String>,
    /// 8. DNS client/server settings
    pub dns: DNS,
    /// 9 Profile settings
    pub profile: Profile,
    /// 10.1 Path to country mmdb file (GeoIP)
    #[serde(default)]
    pub mmdb: Option<String>,
    /// 10.2 Download URL for country mmdb file
    #[serde(rename = "mmdb-download-url")]
    pub mmdb_download_url: Option<String>,
    /// Optional ASN database path relative to the working dir
    pub asn_mmdb: Option<String>,
    /// Optional ASN database download url
    #[serde(rename = "asn-mmdb-download-url")]
    pub asn_mmdb_download_url: Option<String>,
    /// Geosite database path relative to the working dir
    pub geosite: Option<String>,
    /// Geosite database download url
    #[serde(rename = "geosite-download-url")]
    pub geosite_download_url: Option<String>,
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
    #[serde(rename = "proxy-providers")]
    pub proxy_provider: Option<HashMap<String, OutboundProxyProviderDef>>,
    #[serde(rename = "rule-providers")]
    pub rule_provider: Option<HashMap<String, RuleProviderDef>>,
    /// TUN settings
    pub tun: Option<TunConfig>,
    /// 12
    pub listeners: Option<Vec<InboundOpts>>,
    // 13. these options has default vals,
    // and needs extra processing
    /// Globally enable IPv6 for proxy traffic and DNS responses.
    /// When false, IPv6 endpoints and listeners are rejected, domain lookups
    /// use IPv4 results only, and IPv6 TUN/DNS settings are unavailable.
    /// The default is `false`.
    pub ipv6: bool,
    /// outbound interface name
    #[serde(rename = "interface-name")]
    pub interface: Option<String>,
    /// 14. fwmark on Linux only
    /// # Note
    /// - traffics originated from clash will be marked with this value
    /// - so you can use this value to match the traffic in iptables to avoid
    ///   traffic loops
    pub routing_mark: Option<u32>,
    /// experimental settings, if any
    pub experimental: Option<Experimental>,
    /// 15. Clash router working mode
    ///
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

/// Detect one-character misspellings and adjacent transpositions in
/// listener keys without inspecting or echoing secret configuration values.
fn near_sensitive_key(expected: &str, actual: &str) -> bool {
    let a = expected.as_bytes();
    let b = actual.as_bytes();
    if a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    if a.len() == b.len() {
        let differing: Vec<_> = a
            .iter()
            .zip(b)
            .enumerate()
            .filter_map(|(i, (left, right))| (left != right).then_some(i))
            .collect();
        return match differing.as_slice() {
            [_] => true,
            [first, second]
                if *second == *first + 1
                    && a[*first] == b[*second]
                    && a[*second] == b[*first] =>
            {
                true
            }
            _ => false,
        };
    }
    let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
    let (mut i, mut j, mut skipped) = (0, 0, false);
    while i < short.len() {
        if short[i] == long[j] {
            i += 1;
            j += 1;
        } else if skipped {
            return false;
        } else {
            skipped = true;
            j += 1;
        }
    }
    true
}

fn unknown_sensitive_dns_field(field: &str) -> bool {
    // DNS remains permissive for unrelated legacy/vendor keys. Only these
    // recognized controls and their privacy-shaped misspellings are guarded.
    const KNOWN: &[&str] = &[
        "enable",
        "ipv6",
        "listen",
        "enhanced-mode",
        "nameserver",
        "nameserver-policy",
        "default-nameserver",
        "proxy-server-nameserver",
        "proxy-server-nameserver-policy",
        "direct-nameserver",
        "direct-nameserver-follow-policy",
        "fallback",
        "fallback-filter",
        "fake-ip-range",
        "fake-ip-range6",
        "fake-ip-filter",
        "fake-ip-filter-mode",
        "fake-ip-ttl",
        "edns-client-subnet",
        "respect-rules",
        "use-hosts",
        "service-discovery-mode",
        "resolver-profiles",
        "policy-rules",
    ];
    if KNOWN.contains(&field) {
        return false;
    }
    let lower = field.to_ascii_lowercase();
    const SENSITIVE_PREFIXES: &[&str] = &[
        "ipv6",
        "listen",
        "enable-",
        "enable_",
        "name",
        "proxy-server",
        "proxy_server",
        "direct-name",
        "direct_name",
        "default-name",
        "default_name",
        "fake-ip",
        "fake_ip",
        "fakeip",
        "fallback",
        "respect",
        "edns",
        "enhanc",
        "resolver-profile",
        "policy-rule",
        "dns-hijack",
        "use-system-host",
        "use_system_host",
        "use-host",
        "use_host",
    ];
    SENSITIVE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        || KNOWN
            .iter()
            .any(|known| lower == *known || near_sensitive_key(known, &lower))
}

/// Keep existing TUN aliases and unrelated vendor extensions while refusing
/// near-misses that would otherwise disable DNS hijacking or strict routing.
fn unknown_sensitive_tun_field(field: &str) -> bool {
    const KNOWN: &[&str] = &[
        "enable",
        "device-id",
        "device_id",
        "device-url",
        "device",
        "gateway",
        "ipv6",
        "gateway-v6",
        "gateway_v6",
        "routes",
        "route-exclude-address",
        "route_exclude_address",
        "inet4-route-exclude-address",
        "inet4_route_exclude_address",
        "inet6-route-exclude-address",
        "inet6_route_exclude_address",
        "route-all",
        "route_all",
        "auto-route",
        "strict-route",
        "mtu",
        "so-mark",
        "so_mark",
        "route-table",
        "route_table",
        "route-table-v6",
        "route_table_v6",
        "dns-hijack",
        "dns_hijack",
    ];
    if KNOWN.contains(&field) {
        return false;
    }
    let lower = field.to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "dns", "strict", "auto", "route", "include", "exclude", "inet4", "inet6",
        "gateway", "device", "so-mark", "stack",
    ];
    PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
        || KNOWN
            .iter()
            .any(|known| lower == *known || near_sensitive_key(known, &lower))
}

/// DNS listeners are security boundaries: a typo in `tcp`, `doh`, or
/// `ca-key` must not silently disable a listener or its TLS identity.
fn unknown_sensitive_dns_listener_field(field: &str) -> bool {
    const KNOWN: &[&str] = &["udp", "tcp", "doh", "dot", "doh3"];
    if KNOWN.contains(&field) {
        return false;
    }
    let lower = field.to_ascii_lowercase();
    const PREFIXES: &[&str] =
        &["udp", "tcp", "doh", "dot", "dns", "http", "tls", "listen"];
    PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
        || KNOWN.iter().any(|known| near_sensitive_key(known, &lower))
}

fn unknown_sensitive_dns_tls_listen_field(transport: &str, field: &str) -> bool {
    const COMMON: &[&str] = &["addr", "ca-cert", "ca-key"];
    if COMMON.contains(&field) || (transport != "dot" && field == "hostname") {
        return false;
    }
    let lower = field.to_ascii_lowercase();
    const PREFIXES: &[&str] = &["addr", "ca-", "cert", "key", "host", "tls"];
    PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
        || COMMON
            .iter()
            .chain(std::iter::once(&"hostname"))
            .any(|known| near_sensitive_key(known, &lower) || lower == *known)
}

fn unknown_sensitive_fallback_filter_field(field: &str) -> bool {
    const KNOWN: &[&str] = &["geoip", "geoip-code", "ipcidr", "domain", "geosite"];
    if KNOWN.contains(&field) {
        // `geosite` has its own existing unsupported-field diagnostic.
        return false;
    }
    let lower = field.to_ascii_lowercase();
    lower.starts_with("geo")
        || lower.starts_with("ipci")
        || lower.starts_with("ip-cidr")
        || lower.starts_with("ip_cidr")
        || lower.starts_with("domain")
        || KNOWN
            .iter()
            .any(|known| lower == *known || near_sensitive_key(known, &lower))
}

fn suspicious_dns_listener_key(field: &str) -> bool {
    const KNOWN: &[&str] = &["udp", "tcp", "doh", "dot", "doh3"];
    if KNOWN.contains(&field) {
        return false;
    }
    let field = field.to_ascii_lowercase();
    ["udp", "tcp", "doh", "dot", "dns", "http", "tls", "listen"]
        .iter()
        .any(|prefix| field.starts_with(prefix))
        || KNOWN.iter().any(|known| near_sensitive_key(known, &field))
}

fn suspicious_dns_listener_tls_key(transport: &str, field: &str) -> bool {
    const COMMON: &[&str] = &["addr", "ca-cert", "ca-key"];
    if COMMON.contains(&field) || (transport != "dot" && field == "hostname") {
        return false;
    }
    let lower = field.to_ascii_lowercase();
    ["addr", "ca-", "cert", "key", "host", "tls"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        || COMMON
            .iter()
            .chain(std::iter::once(&"hostname"))
            .any(|known| near_sensitive_key(known, &lower))
}

/// Some Mihomo options express strong DNS or TUN privacy guarantees.
/// Until their runtime semantics exist here, accepting them as no-op YAML
/// entries is more dangerous than rejecting the configuration.
///
/// Keep this targeted: legacy vendor keys unrelated to security remain
/// accepted for backward compatibility.
fn reject_unsupported_mihomo_privacy_fields(value: &Value) -> Result<(), Error> {
    const UNSUPPORTED: &[(&str, &[&str])] = &[
        (
            "tun",
            &[
                "dns-mode",
                "auto-detect-interface",
                "include-interface",
                "exclude-interface",
                "stack",
                "route-address",
            ],
        ),
        ("dns", &["use-system-hosts", "fallback-lazy-query"]),
    ];

    for &(section, fields) in UNSUPPORTED {
        let Some(mapping) = value.get(section).and_then(Value::as_mapping) else {
            continue;
        };

        for &field in fields {
            if mapping.keys().any(|key| key.as_str() == Some(field)) {
                return Err(Error::InvalidConfig(format!(
                    "{section}.{field} is not implemented; refusing to silently ignore a Mihomo privacy-sensitive setting"
                )));
            }
        }
    }

    if let Some(tun_fields) = value.get("tun").and_then(Value::as_mapping) {
        for field in tun_fields.keys().filter_map(Value::as_str) {
            if unknown_sensitive_tun_field(field) {
                return Err(Error::InvalidConfig(format!(
                    "tun.{field} is an unknown privacy-sensitive TUN field; refusing to silently ignore it"
                )));
            }
        }
    }

    if let Some(dns_fields) = value.get("dns").and_then(Value::as_mapping) {
        for field in dns_fields.keys().filter_map(Value::as_str) {
            if unknown_sensitive_dns_field(field) {
                return Err(Error::InvalidConfig(format!(
                    "dns.{field} is an unknown privacy-sensitive DNS field; refusing to silently ignore it"
                )));
            }
        }
    }

    // A partial/typo listener block can deserialize as an empty listener
    // set. Validate protocol and TLS identity keys before serde drops them.
    if let Some(listeners) = value
        .get("dns")
        .and_then(|dns| dns.get("listen"))
        .and_then(Value::as_mapping)
    {
        for (key, definition) in listeners {
            let Some(protocol) = key.as_str() else {
                continue;
            };
            if unknown_sensitive_dns_listener_field(protocol) {
                return Err(Error::InvalidConfig(format!(
                    "dns.listen.{protocol} is an unknown privacy-sensitive DNS listener field; refusing to silently ignore it"
                )));
            }
            if matches!(protocol, "doh" | "dot" | "doh3")
                && let Some(fields) = definition.as_mapping()
            {
                for field in fields.keys().filter_map(Value::as_str) {
                    if unknown_sensitive_dns_tls_listen_field(protocol, field) {
                        return Err(Error::InvalidConfig(format!(
                            "dns.listen.{protocol}.{field} is an unknown privacy-sensitive DNS TLS listener field; refusing to silently ignore it"
                        )));
                    }
                }
            }
        }
    }

    if let Some(fallback_fields) = value
        .get("dns")
        .and_then(|dns| dns.get("fallback-filter"))
        .and_then(Value::as_mapping)
    {
        for field in fallback_fields.keys().filter_map(Value::as_str) {
            if unknown_sensitive_fallback_filter_field(field) {
                return Err(Error::InvalidConfig(format!(
                    "dns.fallback-filter.{field} is an unknown privacy-sensitive fallback filter; refusing to silently ignore it"
                )));
            }
        }
    }

    // A GeoSite fallback selector affects which DNS upstream sees a query.
    // Ignoring it can expose QNAMEs to an unintended resolver.
    if value
        .get("dns")
        .and_then(|dns| dns.get("fallback-filter"))
        .and_then(|fallback| fallback.get("geosite"))
        .is_some()
    {
        return Err(Error::InvalidConfig(
            "dns.fallback-filter.geosite is not implemented; refusing to silently ignore a Mihomo privacy-sensitive setting"
                .to_owned(),
        ));
    }

    Ok(())
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut val: Value = serde_yaml::from_str(s).map_err(|e| {
            // Neither the raw YAML nor the parser's free-form message is safe
            // to log: either may include proxy credentials or private QNAMEs.
            // Line and column identify the failure without exposing values.
            let location = e
                .location()
                .map(|location| {
                    format!(
                        " at line {}, column {}",
                        location.line(),
                        location.column()
                    )
                })
                .unwrap_or_default();
            Error::InvalidConfig(format!(
                "could not parse config YAML syntax{location}"
            ))
        })?;

        val.apply_merge().map_err(|_error| {
            // A merge diagnostic can include a rejected scalar. Do not echo it.
            Error::InvalidConfig(
                "failed to process config YAML anchors: invalid merge value (details omitted for privacy)"
                    .to_owned(),
            )
        })?;

        reject_unsupported_mihomo_privacy_fields(&val)?;

        if let Some(tun_fields) = val.get("tun").and_then(Value::as_mapping) {
            for field in tun_fields.keys().filter_map(Value::as_str) {
                if unknown_sensitive_tun_field(field) {
                    return Err(Error::InvalidConfig(format!(
                        "tun.{field} is an unknown privacy-sensitive TUN field; refusing to silently ignore it"
                    )));
                }
            }
        }

        if let Some(dns_fields) = val.get("dns").and_then(Value::as_mapping) {
            for field in dns_fields.keys().filter_map(Value::as_str) {
                if unknown_sensitive_dns_field(field) {
                    return Err(Error::InvalidConfig(format!(
                        "dns.{field} is an unknown privacy-sensitive DNS field; refusing to silently ignore it"
                    )));
                }
            }
        }

        if let Some(fallback_fields) = val
            .get("dns")
            .and_then(|dns| dns.get("fallback-filter"))
            .and_then(Value::as_mapping)
        {
            for field in fallback_fields.keys().filter_map(Value::as_str) {
                if field.eq_ignore_ascii_case("geosite")
                    || unknown_sensitive_fallback_filter_field(field)
                {
                    return Err(Error::InvalidConfig(format!(
                        "dns.fallback-filter.{field} is an unknown privacy-sensitive fallback filter; refusing to silently ignore it"
                    )));
                }
            }
        }

        // Serde accepts unknown mapping keys. A mistyped DNS listener or
        // TLS certificate key would silently disable the intended endpoint.
        // Validate after YAML merges, but before deserialization.
        if let Some(listeners) = val
            .get("dns")
            .and_then(|dns| dns.get("listen"))
            .and_then(Value::as_mapping)
        {
            for (key, definition) in listeners {
                let Some(protocol) = key.as_str() else {
                    continue;
                };
                if suspicious_dns_listener_key(protocol) {
                    return Err(Error::InvalidConfig(format!(
                        "dns.listen.{protocol} is an unknown privacy-sensitive DNS listener field"
                    )));
                }
                if matches!(protocol, "doh" | "dot" | "doh3")
                    && let Some(fields) = definition.as_mapping()
                {
                    for field in fields.keys().filter_map(Value::as_str) {
                        if suspicious_dns_listener_tls_key(protocol, field) {
                            return Err(Error::InvalidConfig(format!(
                                "dns.listen.{protocol}.{field} is an unknown privacy-sensitive TLS listener field"
                            )));
                        }
                    }
                }
            }
        }

        serde_path_to_error::deserialize(val).map_err(|error| {
            // Serde's default "invalid type" diagnostics may print the
            // rejected scalar verbatim. Report a safe top-level section but
            // never expose arbitrary map keys, hostnames, tokens or values.
            let path = error.path().to_string();
            let section = path.split(['.', '[']).next().unwrap_or("");
            let context = match section {
                "dns" => " in dns",
                "tun" => " in tun",
                "profile" => " in profile",
                "proxies" => " in proxies",
                "proxy-groups" => " in proxy-groups",
                "proxy-providers" => " in proxy-providers",
                "rule-providers" => " in rule-providers",
                "listeners" => " in listeners",
                _ => "",
            };
            // Preserve safe schema diagnostics for typo recovery while
            // redacting the unknown field name and rejected scalar itself.
            let kind = if error.inner().to_string().contains("unknown field") {
                "unknown field"
            } else {
                "invalid type or value"
            };
            Error::InvalidConfig(format!(
                "could not parse config content{context}: {kind} (details omitted for privacy)"
            ))
        })
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
#[serde(rename_all = "kebab-case")]
pub struct DohListenDef {
    pub addr: String,
    /// Server certificate chain path; required for DoH and DoH3 listeners.
    pub ca_cert: Option<String>,
    /// Server private key path; required for DoH and DoH3 listeners.
    pub ca_key: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct DotListenDef {
    pub addr: String,
    /// Server certificate chain path; required for DoT listeners.
    pub ca_cert: Option<String>,
    /// Server private key path; required for DoT listeners.
    pub ca_key: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum RuleProviderDef {
    Http(HttpRuleProviderDef),
    File(FileRuleProviderDef),
    Inline(InlineRuleProviderDef),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct HttpRuleProviderDef {
    pub url: String,
    #[serde(default)]
    pub interval: u64,
    pub behavior: RuleSetBehavior,
    pub path: Option<String>,
    pub format: Option<RuleSetFormat>,
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct FileRuleProviderDef {
    pub path: String,
    pub interval: Option<u64>,
    pub behavior: RuleSetBehavior,
    pub format: Option<RuleSetFormat>,
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InlineRuleProviderDef {
    pub path: Option<String>,
    pub behavior: RuleSetBehavior,
    #[serde(alias = "payload")]
    pub inline_rules: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DnsMultipleListenDef {
    pub udp: Option<String>,
    pub tcp: Option<String>,
    pub doh: Option<DohListenDef>,
    pub dot: Option<DotListenDef>,
    pub doh3: Option<DohListenDef>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum DNSListen {
    Udp(String),
    Multiple(Box<DnsMultipleListenDef>),
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DNSMode {
    #[default]
    Normal,
    FakeIp,
    RedirHost,
}

#[derive(Serialize, Deserialize, Clone, Educe)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
#[educe(Default)]
pub struct FallbackFilter {
    #[serde(rename = "geoip")]
    #[educe(Default = true)]
    pub geo_ip: bool,
    #[serde(rename = "geoip-code")]
    #[educe(Default = "CN")]
    pub geo_ip_code: String,
    #[serde(rename = "ipcidr")]
    pub ip_cidr: Vec<String>,
    pub domain: Vec<String>,
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
    /// Whether to use fake IP addresses
    pub enhanced_mode: DNSMode,
    /// DNS upstream servers
    pub nameserver: Vec<String>,
    /// DNS upstreams dedicated to resolving proxy node hostnames
    pub proxy_server_nameserver: Vec<String>,
    /// Ordered Mihomo per-node DNS policy. Mapping order is significant.
    pub proxy_server_nameserver_policy: serde_yaml::Mapping,
    /// DNS upstreams used when the final outbound is DIRECT.
    pub direct_nameserver: Vec<String>,
    /// Match the main nameserver-policy when using direct-nameserver.
    /// Mihomo defaults this to false; no direct-nameserver means no effect.
    pub direct_nameserver_follow_policy: bool,
    /// Fallback DNS upstream servers
    pub fallback: Vec<String>,
    /// Fallback DNS filter
    pub fallback_filter: FallbackFilter,
    /// Default nameservers used for resolving DNS upstream hostnames later
    #[educe(Default = vec![
      String::from("114.114.114.114"),
      String::from("8.8.8.8")]
    )]
    pub default_nameserver: Vec<String>,
    pub edns_client_subnet: Option<EdnsClientSubnet>,
    /// Lookup domains via specific nameservers
    pub nameserver_policy: HashMap<String, String>,
    /// Fake IP addresses pool CIDR
    #[educe(Default = "198.19.0.1/16")]
    pub fake_ip_range: String,
    /// Optional IPv6 fake IP address pool CIDR
    pub fake_ip_range6: Option<String>,
    /// Fake IP addresses filter
    pub fake_ip_filter: Vec<String>,
    /// Mihomo synthetic Fake-IP response TTL; values below 1 clamp to 1.
    #[educe(Default = 1)]
    pub fake_ip_ttl: i64,
    /// Only Mihomo's default blacklist semantics are currently implemented.
    /// Unsupported modes must fail parsing rather than silently fall back.
    pub fake_ip_filter_mode: FakeIpFilterMode,
    /// Opt-in safe forwarding for SRV service-discovery queries in Fake-IP mode.
    /// The default preserves the legacy empty-answer behavior.
    pub service_discovery_mode: DnsServiceDiscoveryMode,
    /// Enable IPv6 DNS responses (AAAA)
    pub ipv6: bool,
    /// DNS server listening address. If not present, the DNS server will be
    /// disabled.
    pub listen: Option<DNSListen>,
    /// 3. When disabled, system DNS config will be used
    ///
    /// All other DNS related options will only be used when this is enabled
    pub enable: bool,
    /// Whether to use `Config::hosts` when resolving hostnames
    #[educe(Default = true)]
    pub use_hosts: bool,
    /// Route upstream DNS queries from nameserver/fallback/policy through rules.
    pub respect_rules: bool,
    /// S01: optional compile-only DNS resolver profiles; not used for DNS
    /// transport until the S02/S03 query-plan implementation is enabled.
    pub resolver_profiles: HashMap<String, DnsResolverProfileDef>,
    /// S01: ordered query policy rules; never changes Business Rules.
    pub policy_rules: Vec<DnsPolicyRuleDef>,
}

#[derive(Serialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FakeIpFilterMode {
    #[default]
    Blacklist,
    Whitelist,
}

impl<'de> Deserialize<'de> for FakeIpFilterMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Mihomo's FilterMode.UnmarshalText first lowercases the mode name.
        let mode = String::deserialize(deserializer)?;
        match mode.to_ascii_lowercase().as_str() {
            "blacklist" => Ok(Self::Blacklist),
            "whitelist" => Ok(Self::Whitelist),
            _ => Err(serde::de::Error::unknown_variant(
                &mode,
                &["blacklist", "whitelist"],
            )),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsServiceDiscoveryMode {
    #[default]
    Legacy,
    Safe,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsResolverProfileDef {
    pub servers: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsPolicyRuleDef {
    pub r#match: DnsPolicyMatchDef,
    pub action: DnsPolicyActionDef,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsPolicyMatchDef {
    pub domain: Option<String>,
    pub domain_suffix: Option<String>,
    /// One record type or a list. Both scalar SRV and [A, AAAA] are accepted.
    pub qtype: Option<DnsQtypeDef>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum DnsQtypeDef {
    One(String),
    Many(Vec<String>),
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsPolicyActionDef {
    pub resolver: Option<String>,
    pub egress: Option<String>,
    pub on_failure: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct EdnsClientSubnet {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Experimental {
    /// buffer size for tcp stream bidirectional copy
    pub tcp_buffer_size: Option<usize>,
    /// max entries in the closed-flows ring buffer (default 50)
    pub closed_flows_cap: Option<usize>,
    /// Resolve proxy destination domains locally before opening the remote flow.
    ///
    /// This preserves the original domain for routing and flow metadata, but
    /// sends the resolved IP to the selected proxy. It is useful when the
    /// proxy server's own DNS cannot reliably resolve destination domains.
    #[serde(default)]
    pub proxy_resolve_local: bool,
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

            StrOrNum::Str(s) => {
                s.parse::<u16>().map(Port).map_err(serde::de::Error::custom)
            }

            StrOrNum::Other => {
                Err(serde::de::Error::custom("Invalid type for port"))
            }
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

#[cfg(test)]
mod tests {
    use super::Config;
    #[cfg(feature = "wireguard")]
    use crate::config::internal::proxy::OutboundProxyProtocol;

    #[test]
    fn dns_listener_typo_must_not_silently_disable_listener() {
        for typo in ["tpc", "udpp", "dho", "dottt", "doh4"] {
            let yaml = format!(
                "dns:\n  enable: false\n  listen:\n    {typo}: 127.0.0.1:5353\n"
            );
            let error = match yaml.parse::<Config>() {
                Ok(_) => panic!("DNS listener typo {typo} silently accepted"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&format!("dns.listen.{typo}"))
                    && error.contains("unknown"),
                "wrong listener key needs a precise, safe diagnostic: {error}"
            );
        }
        assert!(
            "dns:\n  enable: false\n  listen:\n    udp: 127.0.0.1:5353\n    vendor-extension: true\n"
                .parse::<Config>()
                .is_ok()
        );
    }

    #[test]
    fn dns_tls_certificate_typo_must_not_silently_disable_identity() {
        for (transport, typo) in [
            ("doh", "ca-kye"),
            ("dot", "ca-cret"),
            ("doh3", "hostnamee"),
            ("doh", "adrd"),
        ] {
            let yaml = format!(
                "dns:\n  enable: false\n  listen:\n    {transport}:\n      addr: 127.0.0.1:5353\n      {typo}: secret.example\n"
            );
            let error = match yaml.parse::<Config>() {
                Ok(_) => panic!("DNS TLS typo {transport}.{typo} silently accepted"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&format!("dns.listen.{transport}.{typo}"))
                    && error.contains("unknown"),
                "TLS typo needs a precise diagnostic: {error}"
            );
            assert!(
                !error.contains("secret.example"),
                "diagnostic leaked config value"
            );
        }
        assert!(
            "dns:\n  listen:\n    doh:\n      addr: 127.0.0.1:5353\n      vendor-extension: true\n"
                .parse::<Config>()
                .is_ok()
        );
    }

    #[test]
    fn unsupported_tun_typo_and_dns_fallback_geosite_fail_closed() {
        for (yaml, field) in [
            (
                "tun:\n  enable: false\n  strcit-route: true\n",
                "tun.strcit-route",
            ),
            (
                "dns:\n  enable: false\n  fallback-filter:\n    geosite: private\n",
                "dns.fallback-filter.geosite",
            ),
        ] {
            let error = match yaml.parse::<Config>() {
                Ok(_) => panic!(
                    "unimplemented security behavior was silently accepted: {field}"
                ),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(field),
                "missing fail-closed diagnostic: {error}"
            );
        }
    }

    #[test]
    fn yaml_compat_merges_aliases_without_overwriting_explicit_values() {
        let yaml = r#"
shared: &shared
  type: direct
  name: inherited
proxy:
  <<: *shared
  name: override
"#;
        let mut value: serde_yaml::Value =
            serde_yaml::from_str(yaml).expect("YAML aliases should parse");
        value.apply_merge().expect("YAML merge keys should apply");
        assert_eq!(value["proxy"]["name"].as_str(), Some("override"));
        assert_eq!(value["proxy"]["type"].as_str(), Some("direct"));
    }

    #[test]
    fn yaml_compat_preserves_leading_zero_strings() {
        let value: serde_yaml::Value =
            serde_yaml::from_str("id: 0123\nquoted: 'true'\n")
                .expect("YAML scalars should parse");
        assert_eq!(value["id"].as_str(), Some("0123"));
        assert_eq!(value["quoted"].as_str(), Some("true"));
    }

    #[test]
    fn unknown_dns_object_field_never_echoes_private_key() {
        let yaml = "dns:\n  resolver-profiles:\n    secure:\n      servers: [1.1.1.1]\n      private-unknown-key-4839: true\n";
        let error = match yaml.parse::<Config>() {
            Ok(_) => panic!("unknown strict resolver field unexpectedly accepted"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("unknown field") && error.contains("dns"),
            "{error}"
        );
        assert!(!error.contains("private-unknown-key-4839"));
    }

    #[test]
    fn invalid_dns_value_diagnostic_never_echoes_private_scalar() {
        let yaml = "dns:\n  enable: fixture-sensitive-enable-token-4839\n";
        let error = match yaml.parse::<Config>() {
            Ok(_) => panic!("invalid bool unexpectedly parsed"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("parse config"),
            "missing config diagnostic: {error}"
        );
        assert!(!error.contains("fixture-sensitive-enable-token-4839"));
    }

    #[test]
    fn invalid_yaml_merge_scalar_never_echoes_private_value() {
        let yaml = "dns:\n  <<: private-merge-secret-4839\n";
        let error = match yaml.parse::<Config>() {
            Ok(_) => panic!("invalid YAML merge scalar unexpectedly parsed"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("anchors"),
            "missing merge diagnostic: {error}"
        );
        assert!(!error.contains("private-merge-secret-4839"));
    }

    #[test]
    fn invalid_yaml_merge_diagnostic_never_echoes_config_values() {
        let yaml = "secret: fixture-merge-token-4839\ndns:\n  <<: [false, true]\n  nameserver: [private.internal.example]\n";
        let error = match yaml.parse::<Config>() {
            Ok(_) => panic!("invalid YAML merge unexpectedly parsed"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("anchors"),
            "missing anchor diagnostic: {error}"
        );
        assert!(!error.contains("fixture-merge-token-4839"));
        assert!(!error.contains("private.internal.example"));
    }

    #[test]
    fn malformed_dns_yaml_diagnostic_never_echoes_config_values() {
        // Parsing failures may be surfaced in startup logs. A malformed DNS
        // section must not dump unrelated proxy credentials or private names.
        let yaml = "secret: fixture-sensitive-token-4839\ndns:\n  nameserver: ['private.internal.example'\n";
        let error = match yaml.parse::<Config>() {
            Ok(_) => panic!("malformed YAML unexpectedly parsed"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("parse config"),
            "missing actionable diagnostic: {error}"
        );
        assert!(!error.contains("fixture-sensitive-token-4839"));
        assert!(!error.contains("private.internal.example"));
    }

    #[test]
    fn missing_mmdb_stays_disabled() {
        let cfg: Config = "port: 7890".parse().expect("config should parse");

        assert_eq!(cfg.mmdb, None);
    }

    #[test]
    fn explicit_null_mmdb_stays_disabled() {
        let cfg: Config = "port: 7890\nmmdb: null"
            .parse()
            .expect("config should parse");

        assert_eq!(cfg.mmdb, None);
    }

    #[test]
    fn experimental_closed_flows_cap_parses() {
        let cfg: Config = "experimental:\n  closed-flows-cap: 64"
            .parse()
            .expect("config should parse");

        assert_eq!(
            cfg.experimental
                .as_ref()
                .and_then(|exp| exp.closed_flows_cap),
            Some(64)
        );
        assert!(
            !cfg.experimental
                .as_ref()
                .is_some_and(|exp| exp.proxy_resolve_local)
        );
    }

    #[test]
    fn mihomo_fake_ip_filter_blacklist_is_accepted() {
        let cfg: Config = "dns:\n  fake-ip-filter-mode: blacklist"
            .parse()
            .expect("Mihomo default filter mode must work");
        assert_eq!(
            cfg.dns.fake_ip_filter_mode,
            super::FakeIpFilterMode::Blacklist
        );
    }

    #[test]
    fn mihomo_unsupported_fake_ip_filter_modes_are_not_silently_ignored() {
        for mode in ["rule", "RULE"] {
            let yaml = format!("dns:\n  fake-ip-filter-mode: {mode}");
            assert!(
                yaml.parse::<Config>().is_err(),
                "unsupported {mode} mode must be rejected rather than treated as blacklist"
            );
        }
    }

    #[test]
    fn mihomo_fake_ip_whitelist_mode_parses_explicitly() {
        for mode in ["whitelist", "WhiteList", "WHITELIST"] {
            let yaml = format!(
                "dns:\n  fake-ip-filter-mode: {mode}\n  fake-ip-filter:\n    - '*.example.com'"
            );
            let cfg: Config = yaml
                .parse()
                .expect("Mihomo whitelist mode should be recognized");
            assert_eq!(
                cfg.dns.fake_ip_filter_mode,
                super::FakeIpFilterMode::Whitelist
            );
        }
    }

    #[test]
    fn unknown_privacy_shaped_dns_field_names_fail_closed() {
        // A typo in a DNS egress control silently becomes a no-op with the
        // legacy permissive deserializer. Unrelated vendor keys remain legal.
        for field in [
            "nameserver-polcy",
            "namserver-policy",
            "proxy-server-nameserver-policiy",
            "fake-ip-filtre-mode",
            "fake_ip_filter_mode",
            "fake_ip_range",
            "drect-nameserver-follow-policy",
            "respec-rules",
            "enhance-mode",
            "edns-clinet-subnet",
            "use_system_hosts",
            "use-system-host",
            "use-hosts-enabled",
            "proxy_server_nameserver_policy",
            "direct_nameserver_follow_policy",
            "ipv6-enabled",
            "listen-udp",
            "enable-dns",
        ] {
            let yaml = format!("dns:\n  enable: false\n  {field}: secret.example\n");
            let error = match yaml.parse::<Config>() {
                Ok(_) => panic!("unknown sensitive DNS field {field} was ignored"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&format!("dns.{field}")) && error.contains("unknown"),
                "missing precise unknown-field diagnostic: {error}"
            );
            assert!(
                !error.contains("secret.example"),
                "unknown-field error must not disclose private DNS data"
            );
        }
        let vendor_extension = "dns:\n  enable: false\n  vendor-extension: true\n";
        assert!(
            vendor_extension.parse::<Config>().is_ok(),
            "unrelated legacy/vendor DNS keys must remain accepted"
        );
    }

    #[test]
    fn unknown_dns_privacy_typo_in_yaml_merge_fails_closed() {
        let yaml = "template: &privacy\n  nameserver-polcy: secret.example\ndns:\n  <<: *privacy\n  enable: false\n";
        let error = match yaml.parse::<Config>() {
            Ok(_) => panic!("YAML anchor merged unknown DNS privacy key"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("dns.nameserver-polcy"), "{error}");
        assert!(!error.contains("secret.example"), "{error}");
    }

    #[test]
    fn unknown_privacy_shaped_tun_field_names_fail_closed() {
        for field in [
            "dns-hijak",
            "strict-rout",
            "auto-rout",
            "route-al",
            "route-exclude-addres",
            "include-interfac",
            "exclude-interfac",
            "strcit-route",
        ] {
            let yaml = format!("tun:\n  enable: false\n  {field}: true\n");
            let error = match yaml.parse::<Config>() {
                Ok(_) => panic!("unknown sensitive TUN field {field} was ignored"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&format!("tun.{field}")) && error.contains("unknown"),
                "missing precise privacy-field diagnostic: {error}"
            );
        }
        let vendor_extension = "tun:\n  enable: false\n  vendor-extension: true\n";
        assert!(
            vendor_extension.parse::<Config>().is_ok(),
            "unrelated legacy/vendor TUN keys must remain accepted"
        );
    }

    #[test]
    fn dns_listener_privacy_typos_cannot_silently_disable_listener() {
        for field in ["tpc", "udpp", "dho", "dottt", "doh4"] {
            let yaml = format!(
                "dns:\n  enable: false\n  listen:\n    {field}: 127.0.0.1:5353\n"
            );
            let error = match yaml.parse::<Config>() {
                Ok(_) => {
                    panic!("unknown DNS listener {field} was silently accepted")
                }
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&format!("dns.listen.{field}"))
                    && error.contains("unknown"),
                "listener typo needs precise fail-closed diagnostics: {error}"
            );
        }
        // Keep unrelated legacy/vendor listener extensions accepted.
        let yaml = "dns:\n  enable: false\n  listen:\n    udp: 127.0.0.1:5353\n    vendor-extension: true\n";
        assert!(yaml.parse::<Config>().is_ok());
    }

    #[test]
    fn dns_tls_listener_certificate_typos_fail_closed() {
        for (transport, field) in [
            ("doh", "ca-kye"),
            ("dot", "ca-cret"),
            ("doh3", "hostnamee"),
            ("doh", "adrd"),
        ] {
            let yaml = format!(
                "dns:\n  enable: false\n  listen:\n    {transport}:\n      addr: 127.0.0.1:5353\n      {field}: secret.example\n"
            );
            let error = match yaml.parse::<Config>() {
                Ok(_) => {
                    panic!("unknown DNS TLS listener {transport}.{field} accepted")
                }
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&format!("dns.listen.{transport}.{field}"))
                    && error.contains("unknown"),
                "TLS listener typo needs precise diagnostic: {error}"
            );
            assert!(
                !error.contains("secret.example"),
                "DNS secret leaked: {error}"
            );
        }
        let legacy = "dns:\n  listen:\n    doh:\n      addr: 127.0.0.1:5353\n      vendor-extension: true\n";
        assert!(legacy.parse::<Config>().is_ok());
    }

    #[test]
    fn fallback_filter_unknown_privacy_fields_fail_closed() {
        for field in [
            "geoiip",
            "geoip-cod",
            "ipcid",
            "domai",
            "geosit",
            "ip-cidr",
            "ip_cidr",
            "geo-ip",
            "geo_ip",
            "ip-cidr-list",
            "ip_cidr_list",
        ] {
            let yaml = format!(
                "dns:\n  enable: false\n  fallback-filter:\n    {field}: secret.example\n"
            );
            let error = match yaml.parse::<Config>() {
                Ok(_) => {
                    panic!("invalid fallback-filter field {field} silently ignored")
                }
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&format!("dns.fallback-filter.{field}"))
                    && error.contains("unknown"),
                "missing explicit fallback privacy diagnostic: {error}"
            );
            assert!(
                !error.contains("secret.example"),
                "fallback privacy diagnostic must not expose values"
            );
        }
        let vendor = "dns:\n  fallback-filter:\n    vendor-extension: true\n";
        assert!(vendor.parse::<Config>().is_ok());
    }

    #[test]
    fn mihomo_privacy_fields_fail_closed_instead_of_being_ignored() {
        // The fixed Mihomo reference uses these to control DNS egress,
        // Fake-IP and TUN routing. An accepted no-op is unsafe.
        for (section, key, value) in [
            ("tun", "dns-mode", "hijack"),
            ("tun", "auto-detect-interface", "true"),
            ("tun", "include-interface", "[en0]"),
            ("tun", "exclude-interface", "[en1]"),
            ("tun", "stack", "system"),
            ("tun", "route-address", "[0.0.0.0/0]"),
            ("dns", "use-system-hosts", "false"),
            ("dns", "fallback-lazy-query", "true"),
        ] {
            let config = format!("{section}:\n  enable: false\n  {key}: {value}\n");
            let error = match config.parse::<Config>() {
                Ok(_) => panic!(
                    "unsupported {section}.{key} must not be silently accepted"
                ),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&format!("{section}.{key}"))
                    && error.contains("not implemented"),
                "missing fail-closed diagnostic for {section}.{key}: {error}"
            );
            // Errors must not print potentially private DNS policy values.
            assert!(
                !error.contains("example.test"),
                "error leaked a DNS policy value"
            );
        }
    }

    #[test]
    fn mihomo_privacy_field_guard_applies_after_yaml_merge() {
        let config = r#"
common: &unsafe_tun
  dns-mode: hijack
tun:
  <<: *unsafe_tun
  enable: false
"#;
        let error = match config.parse::<Config>() {
            Ok(_) => panic!("YAML merge must not bypass the privacy field guard"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("tun.dns-mode"), "{error}");
    }

    #[test]
    fn unsupported_mihomo_fallback_geosite_is_never_silently_ignored() {
        let config = r#"
dns:
  enable: false
  fallback-filter:
    geosite: [private]
"#;
        let error = match config.parse::<Config>() {
            Ok(_) => {
                panic!("unsupported geosite fallback filter must not be ignored")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("dns.fallback-filter.geosite"), "{error}");
    }

    #[test]
    fn unrelated_legacy_vendor_extensions_remain_accepted() {
        let config: Config = r#"
tun:
  enable: false
  custom-vendor-option: 1
dns:
  enable: false
  custom-vendor-option: true
"#
        .parse()
        .expect("do not globally reject unrelated legacy vendor fields");
        assert!(!config.tun.expect("tun section").enable);
        assert!(!config.dns.enable);
    }

    #[test]
    fn experimental_proxy_resolve_local_parses() {
        let cfg: Config = "experimental:\n  proxy-resolve-local: true"
            .parse()
            .expect("config should parse");

        assert!(cfg.experimental.is_some_and(|exp| exp.proxy_resolve_local));
    }

    /// Feature-gated test for WireGuard proxy type parsing through the full config.
    #[cfg(feature = "wireguard")]
    #[test]
    fn parse_wireguard_proxy() {
        let cfg = r#"
proxies:
  - name: "wg"
    type: wireguard
    server: server
    port: 51820
    private-key: "base64privatekey"
    public-key: "base64publickey"
    ip: 10.0.0.2
    dns:
      - 1.1.1.1
"#;
        let c = cfg.parse::<Config>().expect("should parse wireguard");
        let proxies = c.proxy.unwrap();
        assert_eq!(proxies.len(), 1);
        if let OutboundProxyProtocol::Wireguard(w) = &proxies[0] {
            assert_eq!(w.common_opts.name, "wg");
            assert_eq!(w.ip, "10.0.0.2");
        } else {
            panic!("expected wireguard proxy");
        }
    }

    #[test]
    fn rule_providers_ignore_unknown_fields() {
        let cfg: Config = r#"
rule-providers:
  remote:
    type: http
    url: https://example.com/rules.yaml
    behavior: domain
    future-http-option: true
  local:
    type: file
    path: rules.yaml
    behavior: ipcidr
    future-file-option: 42
  embedded:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,example.com
    future-inline-option: value
"#
        .parse()
        .expect("unknown rule-provider fields should be ignored");

        assert_eq!(
            cfg.rule_provider.as_ref().map(|providers| providers.len()),
            Some(3)
        );
    }
}
