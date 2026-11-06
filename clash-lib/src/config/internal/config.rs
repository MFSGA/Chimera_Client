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
            proxy::{
                OutboundProxy, OutboundProxyProtocol, OutboundProxyProviderDef,
            },
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

/// Some XHTTP secondary connections resolve their target with
/// tokio::net::lookup_host rather than Chimera's managed node DNS resolver.
/// In TUN + Fake-IP this hostname would escape to the OS resolver, including
/// macOS service-scoped DNS paths which the TUN DNS hijack cannot guarantee.
fn xhttp_secondary_system_dns_risk(
    vless: &crate::config::internal::proxy::OutboundVless,
) -> Option<&'static str> {
    if vless.network.as_deref() != Some("xhttp") {
        return None;
    }
    let opts = vless.xhttp_opts.as_ref()?;
    // The HTTP/3 transport uses the managed connector instead.
    if matches!(vless.alpn.as_deref(), Some([version]) if version == "h3") {
        return None;
    }
    if let Some(download) = opts
        .extra
        .as_ref()
        .and_then(|extra| extra.download_settings.as_ref())
        .or(opts.download_settings.as_ref())
    {
        let server = if download.address.is_empty() {
            &vless.common_opts.server
        } else {
            &download.address
        };
        if server.parse::<IpAddr>().is_err() {
            return Some("download-settings");
        }
    }
    if matches!(vless.alpn.as_deref(), Some([version]) if version == "http/1.1")
        && vless.common_opts.server.parse::<IpAddr>().is_err()
    {
        return Some("http/1.1");
    }
    None
}

/// Shared security gate for static configuration and later provider refreshes.
/// Diagnostics intentionally exclude endpoint hostnames.
pub(crate) fn validate_xhttp_secondary_managed_dns(
    outbound: &OutboundProxyProtocol,
) -> Result<(), Error> {
    if let OutboundProxyProtocol::Vless(vless) = outbound
        && let Some(context) = xhttp_secondary_system_dns_risk(vless)
    {
        return Err(Error::InvalidConfig(format!(
            "vless xhttp {context} requires an IP-literal secondary endpoint in TUN + Fake-IP; system DNS lookup is not protected by proxy-server-nameserver"
        )));
    }
    Ok(())
}

/// Validate bootstrap for internal configs and reloads, not only YAML.
/// Resolving an upstream via itself, a proxy, or DHCP can escape managed DNS.
fn validate_default_nameserver_bootstrap(
    servers: &[dns::config::NameServer],
) -> Result<(), Error> {
    if servers.is_empty() {
        return Err(Error::InvalidConfig(
            "dns.default-nameserver requires at least one IP-literal upstream"
                .to_owned(),
        ));
    }
    for server in servers {
        if matches!(server.host, url::Host::Domain(_))
            || server.proxy.is_some()
            || server.net == dns::config::DNSNetMode::Dhcp
        {
            return Err(Error::InvalidConfig(
                "dns.default-nameserver must use IP-literal upstreams without #proxy or DHCP bootstrap".to_owned(),
            ));
        }
    }
    Ok(())
}

impl Config {
    pub fn validate(self) -> Result<Self, crate::Error> {
        validate_default_nameserver_bootstrap(&self.dns.default_nameserver)?;
        #[cfg(not(feature = "tun"))]
        if self.tun.enable {
            return Err(Error::InvalidConfig(
                "tun is enabled in the configuration, but clash-lib was built without the `tun` feature"
                    .to_owned(),
            ));
        }

        // An explicitly empty dedicated node-DNS pool is different from no
        // override. Internal config reloads must fail closed before startup.
        if self
            .dns
            .proxy_server_nameserver
            .as_ref()
            .is_some_and(Vec::is_empty)
        {
            return Err(Error::InvalidConfig(
                "dns.proxy-server-nameserver cannot be explicitly empty".to_owned(),
            ));
        }

        if self.tun.enable
            && self.dns.enable
            && self.dns.enhance_mode == def::DNSMode::FakeIp
        {
            for outbound in self.proxies.values() {
                if let OutboundProxy::ProxyServer(server) = outbound {
                    validate_xhttp_secondary_managed_dns(server)?;
                }
            }
        }

        // Do not bootstrap proxy-node DNS through the same rule-routed DNS
        // transport which could itself depend on that proxy. Mihomo requires
        // proxy-server-nameserver when respect-rules is enabled.
        if self.dns.respect_rules
            && self
                .dns
                .proxy_server_nameserver
                .as_ref()
                .is_none_or(Vec::is_empty)
        {
            return Err(Error::InvalidConfig(
                "dns.respect-rules requires non-empty dns.proxy-server-nameserver (Mihomo compatibility; avoid proxy DNS bootstrap loops)".to_owned(),
            ));
        }

        // A Fake-IP destination recovered into a domain must reach the
        // selected PROXY outbound by name; the optional local resolution
        // setting would otherwise turn it back into a real-IP lookup.
        // Validate here, not only in YAML conversion: Internal configs and
        // runtime reloads also pass through this boundary.
        if self.tun.enable
            && self.dns.enable
            && self.dns.enhance_mode == def::DNSMode::FakeIp
            && self
                .experimental
                .as_ref()
                .is_some_and(|exp| exp.proxy_resolve_local)
        {
            return Err(Error::InvalidConfig(
                "experimental.proxy-resolve-local cannot be enabled with TUN + Fake-IP: it resolves proxy-routed destination domains locally".to_owned(),
            ));
        }

        self.validate_ipv6_policy()?;

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
                common_opts,
                users,
                fallback,
                ..
            } = opts
            {
                // The camouflage fallback invokes tokio::lookup_host on
                // authentication failure. Only literal socket endpoints are
                // safe without a managed resolver in TUN + Fake-IP.
                if self.tun.enable
                    && self.dns.enable
                    && self.dns.enhance_mode == def::DNSMode::FakeIp
                    && fallback
                        .as_ref()
                        .is_some_and(|addr| addr.parse::<SocketAddr>().is_err())
                {
                    return Err(Error::InvalidConfig(
                        "anytls inbound fallback requires an IP-literal host:port in TUN + Fake-IP; system DNS lookup is not protected"
                            .to_owned(),
                    ));
                }
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

    fn validate_ipv6_policy(&self) -> Result<(), crate::Error> {
        if self.general.ipv6 {
            if self.tun.enable && self.tun.gateway_v6.is_none() {
                return Err(Error::InvalidConfig(
                    "global IPv6 requires tun.ipv6 when TUN is enabled".to_owned(),
                ));
            }
            return Ok(());
        }

        let invalid = |message: &str| {
            Error::InvalidConfig(format!("ipv6 is disabled but {message}"))
        };
        if self.general.bind_address.0.is_ipv6() {
            return Err(invalid("bind-address uses an IPv6 address"));
        }
        if self
            .listeners
            .iter()
            .any(|listener| listener.common_opts().listen.0.is_ipv6())
        {
            return Err(invalid("a listener uses an IPv6 address"));
        }
        #[cfg(feature = "anytls")]
        if self.listeners.iter().any(|listener| {
            matches!(
                listener,
                InboundOpts::Anytls {
                    fallback: Some(fallback),
                    ..
                } if fallback
                    .parse::<SocketAddr>()
                    .is_ok_and(|address| address.is_ipv6())
            )
        }) {
            return Err(invalid("an AnyTLS fallback uses an IPv6 address"));
        }
        if let Some(name) = self.proxies.values().find_map(|proxy| {
            let OutboundProxy::ProxyServer(server) = proxy else {
                return None;
            };
            server
                .server_address()
                .filter(|address| is_ipv6_literal(address))
                .map(|_| server.name())
        }) {
            return Err(invalid(&format!(
                "proxy `{}` uses an IPv6 server address",
                name
            )));
        }

        let name_servers = self
            .dns
            .nameserver
            .iter()
            .chain(self.dns.fallback.iter())
            .chain(self.dns.default_nameserver.iter())
            .chain(self.dns.proxy_server_nameserver.iter().flatten())
            .chain(self.dns.direct_nameserver.iter().flatten())
            .chain(self.dns.nameserver_policy.values());
        if name_servers
            .into_iter()
            .any(|nameserver| matches!(&nameserver.host, url::Host::Ipv6(_)))
        {
            return Err(invalid("a DNS nameserver uses an IPv6 address"));
        }
        let listen = &self.dns.listen;
        let listen_addresses = [
            listen.udp,
            listen.tcp,
            listen.doh.as_ref().map(|value| value.addr),
            listen.dot.as_ref().map(|value| value.addr),
            listen.doh3.as_ref().map(|value| value.addr),
        ];
        if listen_addresses
            .into_iter()
            .flatten()
            .any(|address| address.is_ipv6())
        {
            return Err(invalid("a DNS listener uses an IPv6 address"));
        }
        if self
            .dns
            .edns_client_subnet
            .as_ref()
            .is_some_and(|subnet| subnet.ipv6.is_some())
            || self.dns.fake_ip_range6.is_some()
        {
            return Err(invalid(
                "DNS IPv6 client-subnet or fake-IP settings are configured",
            ));
        }
        let mut has_ipv6_host = false;
        if let Some(hosts) = &self.dns.hosts {
            hosts.traverse(|_, address| {
                has_ipv6_host |= address.is_ipv6();
                true
            });
        }
        if has_ipv6_host {
            return Err(invalid("hosts contains an IPv6 address"));
        }
        if self.tun.gateway_v6.is_some()
            || self
                .tun
                .routes
                .iter()
                .chain(self.tun.route_exclude_address.iter())
                .any(|route| route.addr().is_ipv6())
        {
            return Err(invalid("TUN IPv6 gateway or routes are configured"));
        }
        if self
            .tun
            .dns_hijack_rules
            .iter()
            .any(|rule| matches!(rule.address, DnsHijackAddress::Ip(IpAddr::V6(_))))
        {
            return Err(invalid("a TUN DNS hijack rule uses an IPv6 address"));
        }
        if self.general.interface.as_ref().is_some_and(|interface| {
            matches!(interface, Interface::IpAddr(IpAddr::V6(_)))
        }) {
            return Err(invalid("interface-name selects an IPv6 address"));
        }
        if self
            .general
            .controller
            .external_controller
            .as_deref()
            .and_then(|address| address.parse::<SocketAddr>().ok())
            .is_some_and(|address| address.is_ipv6())
        {
            return Err(invalid("external-controller uses an IPv6 address"));
        }

        Ok(())
    }
}

fn is_ipv6_literal(address: &str) -> bool {
    let address = address.trim();
    let address = address
        .strip_prefix('[')
        .and_then(|address| address.strip_suffix(']'))
        .unwrap_or(address);
    address.parse::<Ipv6Addr>().is_ok()
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
    pub route_table_v6: u32,
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

    pub fn matches_tcp(&self, destination: SocketAddr) -> bool {
        self.protocol == DnsHijackProtocol::Tcp
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
    fn explicit_empty_proxy_node_bootstrap_fails_internal_reload() {
        // A deliberately empty dedicated node pool must not be treated as
        // an absent setting and fall back to ordinary DNS during reload.
        let yaml = "dns:\n  enable: true\n  nameserver: [1.1.1.1]\n";
        let mut config = crate::Config::Str(yaml.to_owned())
            .try_parse()
            .expect("baseline must be accepted");
        config.dns.proxy_server_nameserver = Some(Vec::new());
        let error = match config.validate() {
            Ok(_) => panic!("explicit empty node DNS silently accepted"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("proxy-server-nameserver"),
            "empty explicit bootstrap must fail closed: {error}"
        );
    }

    #[test]
    fn internal_default_nameserver_bootstrap_rejects_non_ip_and_proxy_dialers() {
        use crate::app::dns::config::Config as DnsConfig;

        for server in [
            "https://dns.example/dns-query",
            "1.1.1.1#proxy=PROXY",
            "dhcp://en0",
        ] {
            let parsed = DnsConfig::parse_nameserver(&[server.to_owned()]).unwrap();
            assert!(
                super::validate_default_nameserver_bootstrap(&parsed).is_err(),
                "internal DNS bootstrap accepted {server}"
            );
        }
        let parsed =
            DnsConfig::parse_nameserver(&["https://1.1.1.1/dns-query".to_owned()])
                .unwrap();
        assert!(super::validate_default_nameserver_bootstrap(&parsed).is_ok());
    }

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
