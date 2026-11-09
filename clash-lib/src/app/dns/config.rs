pub use super::dns_client::DNSNetMode;
use crate::{
    Error,
    app::net::{OutboundInterface, get_interface_by_name},
    common::trie,
    config::def::{
        DNSListen, DNSMode, DnsPolicyUpstreams, DnsServiceDiscoveryMode,
        DohListenDef, DotListenDef, EdnsClientSubnet as DefEdnsClientSubnet,
        FakeIpFilterMode,
    },
};
pub use chimera_dns::{DNSListenAddr, DoH3Config, DoHConfig, DoTConfig};
use indexmap::IndexMap;
use ipnet::{AddrParseError, Ipv4Net, Ipv6Net};
use percent_encoding::percent_decode_str;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tracing::warn;
use url::Url;

#[derive(Clone, Debug)]
pub struct NameServer {
    pub net: DNSNetMode,
    pub host: url::Host<String>,
    pub port: u16,
    pub interface: Option<OutboundInterface>,
    pub proxy: Option<String>,
    pub doh_path: Option<String>,
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
    pub ip_cidr: Option<Vec<ipnet::IpNet>>,
    pub domain: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EdnsClientSubnet {
    pub ipv4: Option<Ipv4Net>,
    pub ipv6: Option<Ipv6Net>,
}

#[derive(Default)]
pub struct Config {
    pub enable: bool,
    /// Effective global IPv6 policy from the root configuration.
    pub global_ipv6: bool,
    /// The independent `dns.ipv6` policy for client AAAA answers.
    pub dns_ipv6: bool,
    /// Effective DNS IPv6 response setting (`global_ipv6 && dns_ipv6`).
    pub ipv6: bool,
    pub nameserver: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub fallback_filter: FallbackFilter,
    pub listen: DNSListenAddr,
    pub enhance_mode: DNSMode,
    pub default_nameserver: Vec<NameServer>,
    pub proxy_server_nameserver: Option<Vec<NameServer>>,
    pub proxy_server_nameserver_policy: Vec<(String, Vec<NameServer>)>,
    pub direct_nameserver: Option<Vec<NameServer>>,
    pub direct_nameserver_follow_policy: bool,
    pub fake_ip_range: ipnet::IpNet,
    pub fake_ip_range6: Option<ipnet::IpNet>,
    pub fake_ip_filter: Vec<String>,
    pub fake_ip_ttl: u32,
    pub fake_ip_filter_mode: FakeIpFilterMode,
    pub service_discovery_mode: DnsServiceDiscoveryMode,
    pub store_fake_ip: bool,
    pub store_smart_stats: bool,
    pub hosts: Option<trie::StringTrie<IpAddr>>,
    pub nameserver_policy: IndexMap<String, Vec<NameServer>>,
    pub edns_client_subnet: Option<EdnsClientSubnet>,
    pub fw_mark: Option<u32>,
    pub respect_rules: bool,
    /// S01 policy compiler output; deliberately unused by the live resolver
    /// until the S02 planner has separate golden/egress verification.
    pub compiled_policy: super::policy::CompiledDnsPolicy,
}

/// Match the pinned Mihomo policy-domain validation for boundary whitespace
/// and wildcard placement. For privacy, also reject embedded whitespace:
/// a literal trie key containing spaces would silently miss real DNS names.
pub(crate) fn valid_nameserver_policy_domain(domain: &str) -> bool {
    let (parts, valid) = trie::valid_and_split_domain(domain);
    if !valid || domain.chars().any(char::is_whitespace) {
        return false;
    }
    let Some(parts) = parts else {
        return false;
    };
    parts.iter().enumerate().all(|(index, part)| {
        (!part.contains('*') || *part == "*")
            && (!part.contains('+')
                || (index == 0 && *part == "+" && parts.len() > 1))
    })
}

/// Normalize an accepted DNS selector to the ASCII wire representation used
/// by Hickory query names. Wildcard labels remain syntax markers; ordinary
/// labels pass through Hickory's IDNA conversion one label at a time.
pub(crate) fn normalize_dns_domain_pattern(domain: &str) -> Option<String> {
    if !valid_nameserver_policy_domain(domain) {
        return None;
    }

    domain
        .split('.')
        .enumerate()
        .map(|(index, label)| match label {
            "*" | "+" => Some(label.to_owned()),
            "" if index == 0 => Some(String::new()),
            _ => {
                let ascii =
                    hickory_proto::rr::Name::from_utf8(label).ok()?.to_ascii();
                let ascii = ascii.trim_end_matches('.');
                // A single selector label must not expand into several
                // labels (for example through a Unicode dot separator).
                (!ascii.is_empty() && !ascii.contains('.'))
                    .then(|| ascii.to_ascii_lowercase())
            }
        })
        .collect::<Option<Vec<_>>>()
        .map(|labels| labels.join("."))
}

/// Validate a hosts trie supplied through an internal/programmatic config.
/// The YAML path builds an already-normalized trie, but this boundary must
/// reject non-canonical keys that would miss ASCII DNS QNAMEs at runtime.
pub(crate) fn validate_dns_hosts_trie(
    hosts: &trie::StringTrie<IpAddr>,
) -> Result<(), Error> {
    let mut selectors = HashSet::new();
    let mut invalid = false;
    hosts.traverse(|selector, _| {
        let Some(normalized) = normalize_dns_domain_pattern(selector) else {
            invalid = true;
            return false;
        };
        if normalized != selector || !selectors.insert(normalized) {
            invalid = true;
            return false;
        }
        true
    });
    if invalid {
        return Err(Error::InvalidConfig(
            "hosts contains a non-canonical or ambiguous domain selector".to_owned(),
        ));
    }
    Ok(())
}

/// Normalize fallback-filter patterns to the ASCII form used by DNS QNAMEs.
/// This fallback implementation supports domain patterns, not Mihomo
/// GeoSite/RuleSet or comma-delimited rule expressions.
pub(crate) fn normalize_fallback_domain_patterns(
    patterns: &[String],
) -> Result<Vec<String>, Error> {
    let unsupported_prefixes = [
        "geosite:",
        "rule-set:",
        "geosite,",
        "rule-set,",
        "domain,",
        "domain-suffix,",
        "domain-keyword,",
        "domain-regex,",
        "match,",
    ];
    let mut normalized = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        let lower = pattern.trim().to_ascii_lowercase();
        if pattern.contains(',')
            || unsupported_prefixes
                .iter()
                .any(|prefix| lower.starts_with(prefix))
        {
            return Err(Error::InvalidConfig(
                "dns.fallback-filter.domain contains an unsupported selector"
                    .to_owned(),
            ));
        }
        let domain = normalize_dns_domain_pattern(pattern).ok_or_else(|| {
            Error::InvalidConfig(
                "dns.fallback-filter.domain contains an invalid domain pattern"
                    .to_owned(),
            )
        })?;
        normalized.push(domain);
    }
    Ok(normalized)
}

impl Config {
    pub fn parse_nameserver(servers: &[String]) -> Result<Vec<NameServer>, Error> {
        let mut nameservers = vec![];

        for (i, server) in servers.iter().enumerate() {
            let mut server = server.clone();

            if server.eq_ignore_ascii_case("system") {
                warn!("'system' is not supported as dns nameserver, skipping");
                continue;
            }

            // If the server doesn't contain a scheme, assume it's a UDP address.
            if !server.contains("://") {
                if server.contains(':') && !server.starts_with('[') {
                    server = format!("udp://[{}]", server);
                } else {
                    server = "udp://".to_owned() + &server;
                }
            }

            let url = Url::parse(&server).map_err(|_error| {
                // A malformed DoH URI may contain credentials or a signed
                // query in its authority/query. The index is safe to log.
                Error::InvalidConfig(format!(
                    "invalid dns server at index {i}: malformed URI"
                ))
            })?;

            let host = url.host().ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "invalid dns server at index {i}: no host found"
                ))
            })?;

            let host = match host {
                url::Host::Domain(v) => {
                    // Try to parse domain as IPv4 address because of WHATWG standard
                    match v.parse::<std::net::Ipv4Addr>() {
                        Ok(ipv4) => url::Host::Ipv4(ipv4),
                        Err(_) => url::Host::Domain(v),
                    }
                }
                v => v,
            };

            let iface = Self::parse_outbound_interface(&url);
            let proxy = Self::parse_outbound_proxy(&url);
            let doh_path = if url.scheme() == "https" {
                let path = if url.path().is_empty() || url.path() == "/" {
                    "/dns-query"
                } else {
                    url.path()
                };
                Some(match url.query() {
                    Some(query) => format!("{path}?{query}"),
                    None => path.to_owned(),
                })
            } else {
                None
            };
            let net: &str;
            let port: u16;

            match url.scheme() {
                "udp" => {
                    port = url.port().unwrap_or(53);
                    net = "UDP";
                }
                "tcp" => {
                    port = url.port().unwrap_or(53);
                    net = "TCP";
                }
                "tls" => {
                    #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
                    return Err(Error::InvalidConfig(
                        "encrypted DNS requires the `aws-lc-rs` or `ring` feature"
                            .to_owned(),
                    ));
                    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
                    {
                        port = url.port().unwrap_or(853);
                        net = "DoT";
                    }
                }
                "https" => {
                    #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
                    return Err(Error::InvalidConfig(
                        "encrypted DNS requires the `aws-lc-rs` or `ring` feature"
                            .to_owned(),
                    ));
                    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
                    {
                        port = url.port().unwrap_or(443);
                        net = "DoH";
                    }
                }
                "dhcp" => {
                    port = url.port().unwrap_or(0);
                    net = "DHCP";
                }

                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "DNS nameserver [{i}] unsupported scheme"
                    )));
                }
            }

            let net = net.parse()?;
            nameservers.push(NameServer {
                host: host.to_owned(),
                port,
                net,
                interface: iface
                    .filter(|name| name != "auto")
                    .map(|name| {
                        get_interface_by_name(&name).ok_or(Error::InvalidConfig(
                            format!("DNS nameserver [{i}] invalid interface"),
                        ))
                    })
                    .transpose()?,
                proxy,
                doh_path,
            });
        }

        Ok(nameservers)
    }

    /// Compatibility entry point for existing callers with scalar policy
    /// values and unordered maps. Retain the historical one-server output.
    /// New runtime policy construction must use the ordered multi-server API.
    pub fn parse_nameserver_policy(
        policy_map: &HashMap<String, String>,
    ) -> Result<HashMap<String, NameServer>, Error> {
        let ordered = policy_map
            .iter()
            .map(|(selector, value)| {
                (selector.clone(), DnsPolicyUpstreams::Single(value.clone()))
            })
            .collect();
        Self::parse_nameserver_policy_ordered(&ordered)?
            .into_iter()
            .map(|(selector, upstreams)| {
                let upstream = upstreams.into_iter().next().ok_or_else(|| {
                    Error::InvalidConfig(format!(
                        "DNS nameserver-policy for {selector} has no usable nameserver"
                    ))
                })?;
                Ok((selector, upstream))
            })
            .collect()
    }

    /// Preserve YAML selector declaration order and all configured upstreams
    /// through runtime matcher construction.
    pub fn parse_nameserver_policy_ordered(
        policy_map: &IndexMap<String, DnsPolicyUpstreams>,
    ) -> Result<IndexMap<String, Vec<NameServer>>, Error> {
        let mut policy = IndexMap::new();

        for (selector_group, servers) in policy_map {
            // Reject skipped entries even when another server is valid. Such
            // omissions would silently change the selected privacy boundary.
            if servers.as_servers().is_empty()
                || servers
                    .as_servers()
                    .iter()
                    .any(|server| server.eq_ignore_ascii_case("system"))
            {
                return Err(Error::InvalidConfig(
                    "DNS nameserver-policy has no usable nameserver".to_owned(),
                ));
            }
            let nameservers = Config::parse_nameserver(servers.as_servers())?;
            if nameservers.len() != servers.as_servers().len() {
                return Err(Error::InvalidConfig(
                    "DNS nameserver-policy has no usable nameserver".to_owned(),
                ));
            }

            // Mihomo expands comma-delimited domain keys into individual
            // policies. Keep geosite/rule-set unsupported until their
            // matchers exist; never register inert trie literals for them.
            for selector in selector_group.split(',') {
                let lower = selector.to_ascii_lowercase();
                if selector.is_empty()
                    || selector.chars().any(char::is_whitespace)
                    || lower.starts_with("geosite:")
                    || lower.starts_with("rule-set:")
                {
                    return Err(Error::InvalidConfig(
                        "DNS nameserver-policy selector uses unsupported syntax"
                            .into(),
                    ));
                }
                if !valid_nameserver_policy_domain(selector) {
                    return Err(Error::InvalidConfig(
                        "DNS nameserver-policy invalid domain selector".to_owned(),
                    ));
                }
                let normalized = Self::normalize_domain_selector(selector)?;
                if policy.insert(normalized, nameservers.clone()).is_some() {
                    // Ordered input preserves declaration order, but aliases
                    // that normalize to the same selector remain ambiguous.
                    return Err(Error::InvalidConfig(
                        "dns.nameserver-policy repeats domain selector".to_owned(),
                    ));
                }
            }
        }
        Ok(policy)
    }

    fn normalize_domain_selector(selector: &str) -> Result<String, Error> {
        normalize_dns_domain_pattern(selector).ok_or_else(|| {
            Error::InvalidConfig(
                "DNS selector is not a valid ASCII/IDNA domain pattern".to_owned(),
            )
        })
    }

    /// Parse Mihomo per-proxy-node DNS routing in YAML order.
    /// Scalar and list values both represent sets of DNS upstreams.
    /// GeoSite and RuleSet selectors must remain rejected until supported.
    pub fn parse_proxy_server_nameserver_policy(
        mapping: &serde_yaml::Mapping,
    ) -> Result<Vec<(String, Vec<NameServer>)>, Error> {
        let mut policies = Vec::new();
        let mut selectors = HashSet::new();
        for (raw_domain, value) in mapping {
            let domain = raw_domain.as_str().ok_or_else(|| {
                Error::InvalidConfig(
                    "dns.proxy-server-nameserver-policy requires string domain keys"
                        .to_owned(),
                )
            })?;
            let server_strings: Vec<String> = match value {
                serde_yaml::Value::String(server) => vec![server.clone()],
                serde_yaml::Value::Sequence(list) => list
                    .iter()
                    .map(|entry| {
                        entry.as_str().map(str::to_owned).ok_or_else(|| {
                            Error::InvalidConfig("dns.proxy-server-nameserver-policy requires DNS server strings".to_owned())
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => {
                    return Err(Error::InvalidConfig("dns.proxy-server-nameserver-policy requires a server or list".to_owned()));
                }
            };

            if server_strings
                .iter()
                .any(|server| server.trim().eq_ignore_ascii_case("system"))
            {
                return Err(Error::InvalidConfig(
                    "dns.proxy-server-nameserver-policy cannot use unsupported system DNS upstream".to_owned(),
                ));
            }
            let nameservers = Self::parse_nameserver(&server_strings)?;
            if nameservers.is_empty() {
                return Err(Error::InvalidConfig(
                    "dns.proxy-server-nameserver-policy has no usable DNS clients"
                        .to_owned(),
                ));
            }
            if nameservers
                .iter()
                .any(|nameserver| nameserver.proxy.is_some())
            {
                return Err(Error::InvalidConfig(
                    "dns.proxy-server-nameserver-policy cannot use #proxy until explicit node-DNS dialer routing is supported".to_owned(),
                ));
            }
            let lower = domain.to_ascii_lowercase();
            if lower.starts_with("geosite:") || lower.starts_with("rule-set:") {
                return Err(Error::InvalidConfig(
                    "dns.proxy-server-nameserver-policy requires unsupported GeoSite/RuleSet matching".to_owned(),
                ));
            }

            for subdomain in domain.split(',') {
                // Keep the original key: Mihomo validates each token rather
                // than silently trimming a privacy-sensitive DNS selector.
                if !valid_nameserver_policy_domain(subdomain) {
                    return Err(Error::InvalidConfig(
                        "dns.proxy-server-nameserver-policy invalid domain selector"
                            .to_owned(),
                    ));
                }
                let normalized = Self::normalize_domain_selector(subdomain)?;
                if !selectors.insert(normalized.clone()) {
                    return Err(Error::InvalidConfig(
                        "dns.proxy-server-nameserver-policy repeats a normalized domain selector".to_owned(),
                    ));
                }
                policies.push((normalized, nameservers.clone()));
            }
        }
        Ok(policies)
    }

    pub fn parse_fallback_ip_cidr(
        ipcidr: &[String],
    ) -> anyhow::Result<Vec<ipnet::IpNet>> {
        let mut output = vec![];

        for ip in ipcidr.iter() {
            let net: ipnet::IpNet = ip
                .parse()
                .map_err(|x: AddrParseError| Error::InvalidConfig(x.to_string()))?;
            output.push(net);
        }

        Ok(output)
    }

    pub fn parse_hosts(
        hosts_mapping: &HashMap<String, String>,
    ) -> anyhow::Result<trie::StringTrie<IpAddr>> {
        let mut tree = trie::StringTrie::new();
        let mut selectors = HashSet::new();
        tree.insert(
            "localhost",
            Arc::new("127.0.0.1".parse::<IpAddr>().unwrap()),
        );

        for (host, ip_str) in hosts_mapping.iter() {
            let ip = ip_str.parse::<IpAddr>()?;
            // Hickory query names are ASCII wire names. Canonicalize hosts
            // the same way as DNS policies so Unicode aliases cannot miss
            // the local override and fall through to an upstream resolver.
            let host = host.strip_suffix('.').unwrap_or(host);
            let normalized =
                normalize_dns_domain_pattern(host).ok_or_else(|| {
                    Error::InvalidConfig(
                        "hosts contains an invalid domain selector".to_owned(),
                    )
                })?;
            if !selectors.insert(normalized.clone()) {
                return Err(Error::InvalidConfig(
                    "hosts contains duplicate normalized domain selectors"
                        .to_owned(),
                )
                .into());
            }
            if !tree.insert(&normalized, Arc::new(ip)) {
                return Err(Error::InvalidConfig(
                    "hosts contains an unmatchable domain selector".to_owned(),
                )
                .into());
            }
        }

        Ok(tree)
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

fn parse_doh_config(cfg: DohListenDef, protocol: &str) -> Result<DoHConfig, Error> {
    validate_server_certificate(protocol, &cfg.ca_cert, &cfg.ca_key)?;
    Ok(DoHConfig {
        addr: parse_listen_addr(&cfg.addr)?,
        ca_cert: cfg.ca_cert,
        ca_key: cfg.ca_key,
        hostname: cfg.hostname,
    })
}

fn parse_dot_config(cfg: DotListenDef) -> Result<DoTConfig, Error> {
    validate_server_certificate("DoT", &cfg.ca_cert, &cfg.ca_key)?;
    Ok(DoTConfig {
        addr: parse_listen_addr(&cfg.addr)?,
        ca_cert: cfg.ca_cert,
        ca_key: cfg.ca_key,
    })
}

fn validate_server_certificate(
    protocol: &str,
    cert: &Option<String>,
    key: &Option<String>,
) -> Result<(), Error> {
    match (cert, key) {
        (Some(_), Some(_)) => Ok(()),
        _ => Err(Error::InvalidConfig(format!(
            "DNS {protocol} listener requires both ca-cert and ca-key"
        ))),
    }
}

impl Config {
    pub fn parse_outbound_proxy(url: &Url) -> Option<String> {
        let frag = url.fragment()?;
        let pairs = frag.split("&");
        for pair in pairs {
            let outbound = if let Some(outbound) = pair.strip_prefix("proxy=") {
                outbound
            } else if !pair.contains('=') {
                pair
            } else {
                continue;
            };

            return percent_decode_str(outbound)
                .decode_utf8()
                .ok()
                .map(|value| value.into_owned());
        }

        None
    }

    pub fn parse_outbound_interface(url: &Url) -> Option<String> {
        let frag = url.fragment()?;
        let pairs = frag.split("&");
        for first in pairs {
            if first.starts_with("interface=") {
                let iface = first.trim_start_matches("interface=");
                return Some(iface.into());
            }
        }

        None
    }
}

/// Reject Mihomo filter expressions whose ordered RuleSet/GeoSite semantics
/// are not implemented by Chimera's domain-pattern trie. Apply this gate to
/// both YAML conversion and internal configs to protect runtime reloads.
pub(crate) fn validate_fake_ip_filter_patterns(
    patterns: &[String],
) -> Result<(), Error> {
    const UNSUPPORTED_FILTER_PREFIXES: &[&str] = &[
        "rule-set:",
        "geosite:",
        "rule-set,",
        "geosite,",
        "domain,",
        "domain-suffix,",
        "domain-keyword,",
        "domain-regex,",
        "match,",
    ];
    for pattern in patterns {
        let lower = pattern.trim().to_ascii_lowercase();
        if UNSUPPORTED_FILTER_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        {
            // Do not include the rejected pattern: it can contain private
            // domain names and this error may be printed in startup logs.
            return Err(Error::InvalidConfig(
                "dns.fake-ip-filter uses unsupported Mihomo rule-set/geosite/rule syntax; refusing to silently treat it as a literal domain"
                    .to_owned(),
            ));
        }
        if normalize_dns_domain_pattern(pattern).is_none() {
            return Err(Error::InvalidConfig(
                "dns.fake-ip-filter contains an invalid domain pattern; refusing to silently change Fake-IP behavior"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

impl TryFrom<crate::config::def::Config> for Config {
    type Error = Error;

    fn try_from(value: crate::def::Config) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&crate::config::def::Config> for Config {
    type Error = Error;

    fn try_from(c: &crate::config::def::Config) -> Result<Self, Self::Error> {
        let dc = &c.dns;
        validate_fake_ip_filter_patterns(&dc.fake_ip_filter)?;
        let compiled_policy = super::policy::CompiledDnsPolicy::compile(c)?;
        if dc.enable && dc.nameserver.is_empty() {
            return Err(Error::InvalidConfig(String::from(
                "dns enabled, no nameserver specified",
            )));
        }

        let nameservers = Config::parse_nameserver(&dc.nameserver)?;
        let fallback = Config::parse_nameserver(&dc.fallback)?;
        let nameserver_policy =
            Config::parse_nameserver_policy_ordered(&dc.nameserver_policy)?;

        if dc.enable && nameservers.is_empty() {
            return Err(Error::InvalidConfig(
                "dns enabled, no usable nameserver specified".into(),
            ));
        }

        if dc.default_nameserver.is_empty() {
            return Err(Error::InvalidConfig(String::from(
                "default nameserver empty",
            )));
        }

        let default_nameserver = Config::parse_nameserver(&dc.default_nameserver)?;
        if default_nameserver.is_empty() {
            return Err(Error::InvalidConfig(
                "default nameserver has no usable entries".into(),
            ));
        }

        if dc.enable && matches!(&dc.enhanced_mode, DNSMode::RedirHost) {
            return Err(Error::InvalidConfig(
                "dns enhanced-mode redir-host is not implemented".into(),
            ));
        }

        for ns in &default_nameserver {
            if let url::Host::Domain(_) = ns.host {
                return Err(Error::InvalidConfig(String::from(
                    "default dns must be ip address",
                )));
            }
        }

        // Domain hostnames are allowed here: they are bootstrapped through
        // `default-nameserver` at client-construction time, mirroring how
        // `nameserver` resolves its own DoH/DoT hosts.
        let proxy_server_nameserver_policy =
            Config::parse_proxy_server_nameserver_policy(
                &dc.proxy_server_nameserver_policy,
            )?;
        if !proxy_server_nameserver_policy.is_empty()
            && dc.proxy_server_nameserver.is_empty()
        {
            return Err(Error::InvalidConfig(
                "dns.proxy-server-nameserver-policy requires non-empty dns.proxy-server-nameserver".to_owned(),
            ));
        }

        let proxy_server_nameserver = if !dc.proxy_server_nameserver.is_empty() {
            let ns = Config::parse_nameserver(&dc.proxy_server_nameserver)?;
            if ns.is_empty() {
                return Err(Error::InvalidConfig(String::from(
                    "proxy-server-nameserver has no usable entries (all skipped)",
                )));
            }
            Some(ns)
        } else {
            None
        };

        let direct_nameserver = if !dc.direct_nameserver.is_empty() {
            let ns = Config::parse_nameserver(&dc.direct_nameserver)?;
            if ns.is_empty() {
                return Err(Error::InvalidConfig(String::from(
                    "direct-nameserver has no usable entries (all skipped)",
                )));
            }
            Some(ns)
        } else {
            None
        };

        let edns_client_subnet = dc
            .edns_client_subnet
            .as_ref()
            .map(parse_edns_client_subnet)
            .transpose()?;

        let fallback_ip_cidr = if dc.fallback_filter.ip_cidr.is_empty() {
            None
        } else {
            Some(
                Config::parse_fallback_ip_cidr(&dc.fallback_filter.ip_cidr)
                    .map_err(|err| {
                        Error::InvalidConfig(format!(
                            "invalid DNS fallback-filter ipcidr: {err}"
                        ))
                    })?,
            )
        };
        let fallback_filter = FallbackFilter {
            geo_ip: dc.fallback_filter.geo_ip,
            geo_ip_code: dc.fallback_filter.geo_ip_code.to_uppercase(),
            ip_cidr: fallback_ip_cidr,
            domain: normalize_fallback_domain_patterns(&dc.fallback_filter.domain)?,
        };
        let hosts = if dc.use_hosts {
            Config::parse_hosts(&c.hosts).map_err(|err| {
                Error::InvalidConfig(format!("invalid hosts entry: {err}"))
            })?
        } else {
            let mut tree = trie::StringTrie::new();
            tree.insert(
                "localhost",
                Arc::new("127.0.0.1".parse::<IpAddr>().unwrap()),
            );
            tree
        };

        Ok(Self {
            enable: dc.enable,
            global_ipv6: c.ipv6,
            dns_ipv6: dc.ipv6,
            ipv6: c.ipv6 && dc.ipv6,
            fw_mark: c.routing_mark,
            nameserver: nameservers,
            fallback,
            fallback_filter,
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
                    }
                    DNSListen::Multiple(cfg) => Ok(DNSListenAddr {
                        udp: cfg
                            .udp
                            .as_deref()
                            .map(parse_listen_addr)
                            .transpose()?,
                        tcp: cfg
                            .tcp
                            .as_deref()
                            .map(parse_listen_addr)
                            .transpose()?,
                        doh: cfg
                            .doh
                            .map(|cfg| parse_doh_config(cfg, "DoH"))
                            .transpose()?,
                        dot: cfg.dot.map(parse_dot_config).transpose()?,
                        doh3: cfg
                            .doh3
                            .map(|cfg| parse_doh_config(cfg, "DoH3"))
                            .transpose()?
                            .map(|cfg| DoH3Config {
                                addr: cfg.addr,
                                ca_cert: cfg.ca_cert,
                                ca_key: cfg.ca_key,
                                hostname: cfg.hostname,
                            }),
                    }),
                })
                .transpose()?
                .unwrap_or_default(),
            enhance_mode: dc.enhanced_mode.clone(),
            default_nameserver,
            proxy_server_nameserver,
            proxy_server_nameserver_policy,
            direct_nameserver,
            direct_nameserver_follow_policy: dc.direct_nameserver_follow_policy,
            fake_ip_range: dc.fake_ip_range.parse::<ipnet::IpNet>().map_err(
                |_| Error::InvalidConfig(String::from("invalid fake ip range")),
            )?,
            fake_ip_range6: dc
                .fake_ip_range6
                .as_deref()
                .map(|range| {
                    let parsed = range.parse::<ipnet::IpNet>().map_err(|_| {
                        Error::InvalidConfig("invalid fake IPv6 IP range".to_owned())
                    })?;
                    if !parsed.addr().is_ipv6() {
                        return Err(Error::InvalidConfig(
                            "fake-ip-range6 must be an IPv6 subnet".to_owned(),
                        ));
                    }
                    Ok(parsed)
                })
                .transpose()?,
            fake_ip_filter: dc.fake_ip_filter.clone(),
            fake_ip_ttl: u32::try_from(dc.fake_ip_ttl.max(1)).map_err(|_| {
                Error::InvalidConfig(
                    "dns.fake-ip-ttl exceeds u32 seconds".to_owned(),
                )
            })?,
            fake_ip_filter_mode: dc.fake_ip_filter_mode,
            service_discovery_mode: dc.service_discovery_mode,
            store_fake_ip: c.profile.store_fake_ip,
            store_smart_stats: c.profile.store_smart_stats,
            hosts: Some(hosts),
            nameserver_policy,
            edns_client_subnet,
            respect_rules: dc.respect_rules,
            compiled_policy,
        })
    }
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
            "edns-client-subnet requires at least one of ipv4/ipv6".into(),
        ));
    }

    Ok(EdnsClientSubnet { ipv4, ipv6 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_domain_patterns_normalize_idna_and_reject_invalid_labels() {
        assert_eq!(
            normalize_dns_domain_pattern("BÜCHER.example"),
            Some("xn--bcher-kva.example".to_owned())
        );
        assert_eq!(
            normalize_dns_domain_pattern("+.BÜCHER.example"),
            Some("+.xn--bcher-kva.example".to_owned())
        );
        assert_eq!(
            normalize_dns_domain_pattern(".BÜCHER.example"),
            Some(".xn--bcher-kva.example".to_owned())
        );
        for invalid in [
            " private.example",
            "part*.private.example",
            "private..example",
            "private.example.",
            "private。example",
        ] {
            assert_eq!(normalize_dns_domain_pattern(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn fallback_domain_patterns_normalize_idna_and_reject_unsupported_rules() {
        assert_eq!(
            normalize_fallback_domain_patterns(&["+.BÜCHER.example".to_owned(),])
                .unwrap(),
            ["+.xn--bcher-kva.example"]
        );
        for invalid in [
            "bad..private.example",
            "geosite:private",
            "domain-suffix,private.example",
        ] {
            let error = normalize_fallback_domain_patterns(&[invalid.to_owned()])
                .expect_err("unsupported fallback selector must fail closed")
                .to_string();
            assert!(error.contains("dns.fallback-filter.domain"), "{error}");
            assert!(!error.contains(invalid), "{error}");
        }
    }

    #[test]
    fn hosts_normalize_idna_and_absolute_domain_names() {
        let hosts =
            HashMap::from([("BÜCHER.example.".to_owned(), "192.0.2.25".to_owned())]);
        let parsed = Config::parse_hosts(&hosts).expect("valid IDNA hosts entry");
        assert_eq!(
            parsed
                .search("xn--bcher-kva.example")
                .and_then(|node| node.get_data()),
            Some(&"192.0.2.25".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn hosts_reject_ambiguous_idna_aliases_and_invalid_domains() {
        let aliases = HashMap::from([
            ("bücher.example".to_owned(), "192.0.2.25".to_owned()),
            ("xn--bcher-kva.example".to_owned(), "192.0.2.26".to_owned()),
        ]);
        let error = match Config::parse_hosts(&aliases) {
            Ok(_) => panic!("canonical aliases must not select an arbitrary host"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("duplicate normalized"), "{error}");
        assert!(!error.contains("bücher.example"), "{error}");

        let invalid = HashMap::from([(
            "bad..private.example".to_owned(),
            "192.0.2.25".to_owned(),
        )]);
        let error = match Config::parse_hosts(&invalid) {
            Ok(_) => panic!("unmatchable host must not be ignored"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("invalid domain selector"), "{error}");
        assert!(!error.contains("bad..private.example"), "{error}");
    }

    #[test]
    fn internal_hosts_trie_requires_canonical_idna_keys() {
        let mut canonical = trie::StringTrie::new();
        assert!(canonical.insert(
            "xn--bcher-kva.example",
            Arc::new("192.0.2.25".parse::<IpAddr>().unwrap())
        ));
        validate_dns_hosts_trie(&canonical)
            .expect("ASCII wire-form internal host should validate");

        let mut unicode = trie::StringTrie::new();
        assert!(unicode.insert(
            "bücher.example",
            Arc::new("192.0.2.25".parse::<IpAddr>().unwrap())
        ));
        let error = validate_dns_hosts_trie(&unicode)
            .expect_err("Unicode keys must not miss ASCII DNS QNAMEs")
            .to_string();
        assert!(error.contains("hosts"), "{error}");
        assert!(!error.contains("bücher.example"), "{error}");
    }

    #[test]
    fn auto_nameserver_binding_is_selected_at_dial_time() {
        let nameservers =
            Config::parse_nameserver(&["192.0.2.53#auto".into()]).unwrap();
        assert!(nameservers[0].interface.is_none());
    }

    #[test]
    fn parse_nameserver_ipv6_without_scheme() {
        let servers = vec!["2400:3200::1".to_string()];
        let ns = Config::parse_nameserver(&servers).expect("parse failed");
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].host.to_string(), "[2400:3200::1]");
        assert_eq!(ns[0].port, 53);
        assert_eq!(ns[0].net, DNSNetMode::Udp);
        let _sock: std::net::SocketAddr = format!("{}:{}", ns[0].host, ns[0].port)
            .parse()
            .expect("address should parse to SocketAddr");
    }

    #[test]
    fn parse_nameserver_ipv6_with_brackets_and_port() {
        let servers = vec!["[2400:3200::1]:5353".to_string()];
        let ns = Config::parse_nameserver(&servers).expect("parse failed");
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].host.to_string(), "[2400:3200::1]");
        assert_eq!(ns[0].port, 5353);
        assert_eq!(ns[0].net, DNSNetMode::Udp);
        let _sock: std::net::SocketAddr = format!("{}:{}", ns[0].host, ns[0].port)
            .parse()
            .expect("address should parse to SocketAddr");
    }

    #[test]
    fn nameserver_policy_rejects_selector_ambiguity_before_runtime_trie() {
        // Fixed ref-mihomo component/trie/domain.go rejects boundary
        // whitespace and misplaced wildcards. Embedded whitespace is a
        // privacy-hardening rejection: it would become an unmatchable key.
        for selector in [
            " example.com",
            "example.com ",
            "one.example, two.example",
            "example.com bad.test",
            "partial*.example.com",
            "foo.+.example.com",
            "+",
        ] {
            let policy =
                IndexMap::from([(selector.to_owned(), "9.9.9.9".to_owned().into())]);
            let error = Config::parse_nameserver_policy_ordered(&policy)
                .expect_err("ambiguous DNS policy selector must fail closed");
            assert!(
                error.to_string().contains("nameserver-policy"),
                "{selector:?}: {error}"
            );
        }
        for selector in ["example.com", "*.example.com", ".example.com"] {
            let policy =
                IndexMap::from([(selector.to_owned(), "9.9.9.9".to_owned().into())]);
            assert!(
                Config::parse_nameserver_policy_ordered(&policy).is_ok(),
                "valid existing selector {selector:?} must remain accepted"
            );
        }
    }

    #[test]
    fn nameserver_policies_normalize_idna_and_reject_canonical_duplicates() {
        let unicode = IndexMap::from([(
            "bücher.example".to_owned(),
            "9.9.9.9".to_owned().into(),
        )]);
        let parsed = Config::parse_nameserver_policy_ordered(&unicode)
            .expect("Unicode selector should normalize to its DNS wire name");
        assert!(parsed.contains_key("xn--bcher-kva.example"));

        let aliases = IndexMap::from([
            ("bücher.example".to_owned(), "9.9.9.9".to_owned().into()),
            (
                "xn--bcher-kva.example".to_owned(),
                "1.1.1.1".to_owned().into(),
            ),
        ]);
        assert!(
            Config::parse_nameserver_policy_ordered(&aliases)
                .expect_err("Unicode/ASCII aliases must not race in the trie")
                .to_string()
                .contains("nameserver-policy")
        );
    }

    #[test]
    fn proxy_nameserver_policy_rejects_selector_ambiguity_before_node_dns() {
        for selector in [
            " node.example",
            "node.example ",
            "node-a.example, node-b.example",
            "node.example other.example",
            "part*.example.com",
            "node.+.example.com",
        ] {
            let mut mapping = serde_yaml::Mapping::new();
            mapping.insert(
                serde_yaml::Value::String(selector.to_owned()),
                serde_yaml::Value::String("9.9.9.9".to_owned()),
            );
            let error = Config::parse_proxy_server_nameserver_policy(&mapping)
                .expect_err("node DNS policy selector must not silently change");
            assert!(
                error.to_string().contains("proxy-server-nameserver-policy"),
                "{selector:?}: {error}"
            );
        }
    }

    #[test]
    fn proxy_node_policies_normalize_idna_and_reject_canonical_duplicates() {
        let mut mapping = serde_yaml::Mapping::new();
        mapping.insert(
            serde_yaml::Value::String("bücher.example".to_owned()),
            serde_yaml::Value::String("9.9.9.9".to_owned()),
        );
        let parsed = Config::parse_proxy_server_nameserver_policy(&mapping)
            .expect("Unicode selector should normalize to wire form");
        assert_eq!(parsed[0].0, "xn--bcher-kva.example");

        mapping.insert(
            serde_yaml::Value::String("xn--bcher-kva.example".to_owned()),
            serde_yaml::Value::String("1.1.1.1".to_owned()),
        );
        assert!(
            Config::parse_proxy_server_nameserver_policy(&mapping)
                .expect_err("Unicode/ASCII aliases must not race in node DNS")
                .to_string()
                .contains("proxy-server-nameserver-policy")
        );
    }

    #[test]
    fn proxy_node_policy_accepts_dot_and_plus_suffix_selectors() {
        let mut mapping = serde_yaml::Mapping::new();
        mapping.insert(
            serde_yaml::Value::String("+.example.com".to_owned()),
            serde_yaml::Value::String("9.9.9.9".to_owned()),
        );
        mapping.insert(
            serde_yaml::Value::String(".example.com".to_owned()),
            serde_yaml::Value::String("1.1.1.1".to_owned()),
        );
        let parsed = Config::parse_proxy_server_nameserver_policy(&mapping)
            .expect("different suffix selectors have explicit runtime precedence");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn nameserver_policy_rejects_skipped_system_entry() {
        let policy =
            IndexMap::from([("example.com".to_owned(), "system".to_owned().into())]);

        let error = Config::parse_nameserver_policy_ordered(&policy)
            .expect_err("a policy without a usable nameserver must be rejected");

        assert!(error.to_string().contains("no usable nameserver"));
    }

    #[test]
    fn nameserver_policy_rejects_unsupported_selectors_and_expands_domains() {
        // Reject unsupported GeoSite/RuleSet selectors and unmatchable
        // whitespace; comma-delimited ordinary domains are expanded.
        for selector in [
            "example.com other.test",
            "geosite:private",
            "rule-set:private",
        ] {
            let policy = IndexMap::from([(
                selector.to_owned(),
                "192.0.2.53".to_owned().into(),
            )]);
            assert!(
                Config::parse_nameserver_policy_ordered(&policy).is_err(),
                "unsupported selector {selector:?} must not be silently accepted"
            );
        }
        let combined = IndexMap::from([(
            "example.com,other.test".to_owned(),
            "192.0.2.53".to_owned().into(),
        )]);
        let expanded = Config::parse_nameserver_policy_ordered(&combined)
            .expect("Mihomo-compatible comma domain expansion must be supported");
        assert_eq!(expanded.len(), 2);
        assert!(expanded.contains_key("example.com"));
        assert!(expanded.contains_key("other.test"));

        for selector in ["example.com", "*.example.com", "+.example.com"] {
            let policy = IndexMap::from([(
                selector.to_owned(),
                "192.0.2.53".to_owned().into(),
            )]);
            assert!(
                Config::parse_nameserver_policy_ordered(&policy).is_ok(),
                "existing selector {selector:?} must remain supported"
            );
        }
    }

    #[test]
    fn legacy_hashmap_policy_api_remains_source_compatible() {
        // Existing callers and locally staged regression tests still use
        // HashMap<String,String> and require exactly one upstream per key.
        let valid = std::collections::HashMap::from([(
            "example.com".to_owned(),
            "192.0.2.53".to_owned(),
        )]);
        let parsed: std::collections::HashMap<String, NameServer> =
            Config::parse_nameserver_policy(&valid)
                .expect("legacy API must compile");
        assert_eq!(parsed["example.com"].host.to_string(), "192.0.2.53");
        let invalid = std::collections::HashMap::from([(
            "example.com bad.test".to_owned(),
            "192.0.2.53".to_owned(),
        )]);
        assert!(Config::parse_nameserver_policy(&invalid).is_err());
    }

    #[test]
    fn nameserver_policy_overlapping_exact_and_plus_follow_yaml_order() {
        // Mihomo inserts domain policies in YAML order. '+.' writes
        // both the apex and its wildcard branch; a later exact selector
        // changes the apex, but must leave the wildcard branch intact.
        for (selectors, expected_apex) in [
            (
                "    example.com: 192.0.2.53\n    '+.example.com': 192.0.2.54\n",
                "192.0.2.54",
            ),
            (
                "    '+.example.com': 192.0.2.54\n    example.com: 192.0.2.53\n",
                "192.0.2.53",
            ),
        ] {
            for attempt in 0..64 {
                let raw: crate::config::def::Config =
                    format!("dns:\n  nameserver-policy:\n{selectors}")
                        .parse()
                        .expect("YAML must parse");
                let parsed = Config::parse_nameserver_policy_ordered(
                    &raw.dns.nameserver_policy,
                )
                .expect("policy must convert");
                let mut trie = trie::StringTrie::new();
                for (selector, upstreams) in &parsed {
                    assert!(
                        trie.insert(
                            selector,
                            std::sync::Arc::new(upstreams.clone())
                        )
                    );
                }
                let apex = &trie
                    .search("example.com")
                    .expect("apex must match")
                    .get_data()
                    .expect("apex must have nameservers")[0];
                assert_eq!(
                    apex.host.to_string(),
                    expected_apex,
                    "YAML insertion order changed at iteration {attempt}"
                );
                let wildcard = &trie
                    .search("www.example.com")
                    .expect("subdomain must match")
                    .get_data()
                    .expect("wildcard must have nameservers")[0];
                assert_eq!(wildcard.host.to_string(), "192.0.2.54");
            }
        }
    }

    #[test]
    fn nameserver_policy_expands_comma_selectors_into_runtime_domains() {
        let policy = IndexMap::from([(
            "EXAMPLE.com,*.other.test,+.internal.test".to_owned(),
            "192.0.2.53".to_owned().into(),
        )]);
        let parsed = Config::parse_nameserver_policy_ordered(&policy)
            .expect("comma-delimited domain policy should expand");
        assert_eq!(parsed.len(), 3);
        let mut trie = crate::common::trie::StringTrie::<bool>::new();
        for domain in parsed.keys() {
            assert!(trie.insert(domain, std::sync::Arc::new(true)));
        }
        for domain in [
            "example.com",
            "www.other.test",
            "internal.test",
            "www.internal.test",
        ] {
            assert!(
                trie.search(domain).is_some(),
                "{domain} must match an expanded policy selector"
            );
        }
        assert!(trie.search("unrelated.test").is_none());
    }

    #[test]
    fn nameserver_policy_rejects_ambiguous_or_unsupported_comma_keys() {
        for key in [
            "example.com,",
            ",example.com",
            "example.com,,other.test",
            "example.com, other.test",
            "example.com,geosite:private",
            "example.com,rule-set:private",
            "example.com,example.com",
            "EXAMPLE.COM,example.com",
        ] {
            let policy =
                IndexMap::from([(key.to_owned(), "192.0.2.53".to_owned().into())]);
            assert!(
                Config::parse_nameserver_policy_ordered(&policy).is_err(),
                "ambiguous selector {key:?} must fail closed"
            );
        }
        let policy = IndexMap::from([
            (
                "example.com,other.test".to_owned(),
                "192.0.2.53".to_owned().into(),
            ),
            ("OTHER.TEST".to_owned(), "192.0.2.54".to_owned().into()),
        ]);
        assert!(
            Config::parse_nameserver_policy_ordered(&policy).is_err(),
            "overlapping canonical selectors must not depend on map iteration order"
        );
    }

    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
    #[test]
    fn parse_nameserver_proxy_fragment_for_dns_upstream() {
        let servers =
            vec!["https://dns.cloudflare.com/dns-query#proxy=TESTED".to_string()];
        let ns = Config::parse_nameserver(&servers).expect("parse failed");

        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].net, DNSNetMode::DoH);
        assert_eq!(ns[0].proxy.as_deref(), Some("TESTED"));
        assert_eq!(ns[0].doh_path.as_deref(), Some("/dns-query"));
    }

    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
    #[test]
    fn parse_doh_custom_path_and_query() {
        let servers =
            vec!["https://dns.example/custom/resolve?tenant=alpha".to_owned()];
        let ns = Config::parse_nameserver(&servers).expect("parse failed");

        assert_eq!(
            ns[0].doh_path.as_deref(),
            Some("/custom/resolve?tenant=alpha")
        );
    }

    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
    #[test]
    fn parse_nameserver_proxy_fragment_shorthand() {
        let servers = vec!["tls://8.8.4.4:853#TESTED".to_string()];
        let ns = Config::parse_nameserver(&servers).expect("parse failed");

        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].net, DNSNetMode::DoT);
        assert_eq!(ns[0].proxy.as_deref(), Some("TESTED"));
    }

    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
    #[test]
    fn parse_nameserver_proxy_fragment_decodes_unicode_outbound_name() {
        let servers = vec![
            "https://dns.cloudflare.com/dns-query#proxy=🇺🇸 VLESS WebSocket TLS go"
                .to_string(),
        ];
        let ns = Config::parse_nameserver(&servers).expect("parse failed");

        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].net, DNSNetMode::DoH);
        assert_eq!(ns[0].proxy.as_deref(), Some("🇺🇸 VLESS WebSocket TLS go"));
    }

    #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
    #[test]
    fn reject_encrypted_nameserver_without_crypto_backend() {
        for server in ["tls://1.1.1.1", "https://dns.example/dns-query"] {
            let error = Config::parse_nameserver(&[server.to_owned()])
                .expect_err("encrypted DNS must require a crypto backend");
            assert!(matches!(
                error,
                Error::InvalidConfig(message)
                    if message.contains("requires the `aws-lc-rs` or `ring` feature")
            ));
        }
    }
}
