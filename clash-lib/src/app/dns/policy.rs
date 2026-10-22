//! S01 compile-only DNS policy. No production query path consumes this
//! module yet; S02 must explicitly opt into it and preserve legacy fallback.
//! The compiled decisions only select *DNS* egress, never Business Rules.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use hickory_proto::rr::{Name, RecordType};

use crate::{
    Error,
    config::{
        def::{
            Config as ConfigDef, DnsPolicyActionDef, DnsPolicyMatchDef, DnsQtypeDef,
        },
        internal::proxy::OutboundProxyProtocol,
    },
};

use super::config::{Config, NameServer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsEgress {
    Direct,
    Proxy(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsFailure {
    Fail,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsPolicyAction {
    pub resolver: Option<String>,
    pub egress: Option<DnsEgress>,
    pub on_failure: Option<DnsFailure>,
}

#[derive(Clone, Debug)]
struct DnsRuleMatch {
    domain: Option<String>,
    suffix: Option<String>,
    qtypes: Option<Vec<RecordType>>,
}

impl DnsRuleMatch {
    fn matches(&self, domain: &str, qtype: RecordType) -> bool {
        let name_matches = self.domain.as_deref().is_none_or(|d| domain == d)
            && self.suffix.as_deref().is_none_or(|suffix| {
                domain == suffix
                    || domain
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            });
        name_matches && self.qtypes.as_ref().is_none_or(|v| v.contains(&qtype))
    }
}

#[derive(Clone, Debug)]
pub struct CompiledDnsRule {
    /// 0-based index from the original YAML policy-rules sequence.
    pub ordinal: usize,
    matcher: DnsRuleMatch,
    pub action: DnsPolicyAction,
}

#[derive(Clone, Debug, Default)]
pub struct CompiledDnsPolicy {
    pub profiles: HashMap<String, Vec<NameServer>>,
    pub rules: Vec<CompiledDnsRule>,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(format!("dns policy-rules: {}", message.into()))
}

fn canonical_domain(input: &str, field: &str) -> Result<String, Error> {
    if input.is_empty() || input.trim() != input || input.contains('*') {
        return Err(invalid(format!(
            "{field}: domain must be nonempty, unpadded and non-wildcard"
        )));
    }
    let without_dot = input.trim_end_matches('.');
    if without_dot.is_empty() || without_dot.ends_with('.') {
        return Err(invalid(format!("{field}: invalid DNS domain '{input}'")));
    }
    let name = Name::from_utf8(without_dot).map_err(|err| {
        invalid(format!("{field}: invalid DNS domain '{input}': {err}"))
    })?;
    if name.num_labels() == 0 {
        return Err(invalid(format!("{field}: empty DNS domain")));
    }
    Ok(name
        .to_ascii()
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_owned())
}

fn parse_qtype(value: &str, ordinal: usize) -> Result<RecordType, Error> {
    if value.is_empty() || value.trim() != value {
        return Err(invalid(format!("rule[{ordinal}] invalid qtype '{value}'")));
    }
    let upper = value.to_ascii_uppercase();
    if let Some(numeric) = upper.strip_prefix("TYPE") {
        let value: u16 = numeric.parse().map_err(|_| {
            invalid(format!(
                "rule[{ordinal}] invalid qtype '{value}', use TYPE1..TYPE65535"
            ))
        })?;
        if value == 0 {
            return Err(invalid(format!("rule[{ordinal}] TYPE0 is invalid")));
        }
        return Ok(RecordType::from(value));
    }
    RecordType::from_str(&upper)
        .map_err(|_| invalid(format!("rule[{ordinal}] unknown qtype '{value}'")))
}

fn compile_match(
    value: &DnsPolicyMatchDef,
    ordinal: usize,
) -> Result<DnsRuleMatch, Error> {
    if value.domain.is_some() && value.domain_suffix.is_some() {
        return Err(invalid(format!(
            "rule[{ordinal}] match cannot combine domain and domain-suffix"
        )));
    }
    let domain = value
        .domain
        .as_deref()
        .map(|v| canonical_domain(v, &format!("rule[{ordinal}].match.domain")))
        .transpose()?;
    let suffix = value
        .domain_suffix
        .as_deref()
        .map(|v| {
            canonical_domain(v, &format!("rule[{ordinal}].match.domain-suffix"))
        })
        .transpose()?;
    let qtypes = match &value.qtype {
        None => None,
        Some(DnsQtypeDef::One(value)) => Some(vec![parse_qtype(value, ordinal)?]),
        Some(DnsQtypeDef::Many(values)) => {
            if values.is_empty() {
                return Err(invalid(format!(
                    "rule[{ordinal}] qtype must not be empty"
                )));
            }
            let types = values
                .iter()
                .map(|v| parse_qtype(v, ordinal))
                .collect::<Result<Vec<_>, _>>()?;
            if types.iter().copied().collect::<HashSet<_>>().len() != types.len() {
                return Err(invalid(format!("rule[{ordinal}] duplicate qtype")));
            }
            Some(types)
        }
    };
    if domain.is_none() && suffix.is_none() && qtypes.is_none() {
        return Err(invalid(format!("rule[{ordinal}] match has no conditions")));
    }
    Ok(DnsRuleMatch {
        domain,
        suffix,
        qtypes,
    })
}

fn compile_action(
    value: &DnsPolicyActionDef,
    ordinal: usize,
    c: &ConfigDef,
    profiles: &HashMap<String, Vec<NameServer>>,
) -> Result<DnsPolicyAction, Error> {
    let resolver = value
        .resolver
        .as_ref()
        .map(|name| {
            if name.is_empty() || name.trim() != name || !profiles.contains_key(name)
            {
                Err(invalid(format!(
                    "rule[{ordinal}] unknown or empty resolver profile '{name}'"
                )))
            } else {
                Ok(name.clone())
            }
        })
        .transpose()?;
    let egress = value.egress.as_deref().map(|value| {
        match value {
            "direct" => Ok(DnsEgress::Direct),
            v if v.starts_with("proxy:") => {
                let name = &v[6..];
                if name.is_empty() || name.trim() != name || name == "REJECT" {
                    return Err(invalid(format!("rule[{ordinal}] invalid proxy DNS egress '{value}'")));
                }
                let found_node = c.proxy.as_ref().is_some_and(|nodes| nodes.iter().any(|n| n.name() == name));
                let found_group = c.proxy_group.as_ref().is_some_and(|groups| groups.iter().any(|g| g.name() == name));
                if !found_node && !found_group {
                    return Err(invalid(format!("rule[{ordinal}] DNS egress '{value}' refers to an unknown proxy or group")));
                }
                Ok(DnsEgress::Proxy(name.to_owned()))
            }
            _ => Err(invalid(format!("rule[{ordinal}] invalid DNS egress '{value}'; use 'direct' or 'proxy:<name>'"))),
        }
    }).transpose()?;
    let on_failure = value.on_failure.as_deref().map(|v| {
        match v {
            "fail" => Ok(DnsFailure::Fail),
            _ => Err(invalid(format!("rule[{ordinal}] unsupported on-failure '{v}'; only 'fail' is implemented in S01"))),
        }
    }).transpose()?;

    if resolver.is_none() && egress.is_none() && on_failure.is_none() {
        return Err(invalid(format!("rule[{ordinal}] action has no effect")));
    }
    if egress.is_some() {
        // Explicit DNS egress cannot safely override legacy rule-dispatch or
        // server-level forced paths without an approved precedence contract.
        if c.dns.respect_rules {
            return Err(invalid(format!(
                "rule[{ordinal}] explicit egress conflicts with legacy respect-rules; select one"
            )));
        }
        let candidate_servers = resolver
            .as_ref()
            .and_then(|name| profiles.get(name))
            .map(Vec::as_slice);
        let mut inherited = c
            .dns
            .nameserver
            .iter()
            .chain(c.dns.fallback.iter())
            .chain(c.dns.default_nameserver.iter())
            .chain(c.dns.proxy_server_nameserver.iter())
            .chain(c.dns.direct_nameserver.iter())
            .chain(c.dns.nameserver_policy.values());
        let forced = candidate_servers.map_or_else(
            || inherited.any(|v| v.contains('#')),
            |servers| {
                servers
                    .iter()
                    .any(|ns| ns.proxy.is_some() || ns.interface.is_some())
            },
        );
        if forced {
            return Err(invalid(format!(
                "rule[{ordinal}] explicit egress conflicts with DNS server #proxy/#interface; remove the override or the forced server modifier"
            )));
        }
    }
    Ok(DnsPolicyAction {
        resolver,
        egress,
        on_failure,
    })
}

fn proxy_server_hostname(node: &OutboundProxyProtocol) -> Option<&str> {
    match node {
        OutboundProxyProtocol::Direct(_) | OutboundProxyProtocol::Reject(_) => None,
        #[cfg(feature = "shadowsocks")]
        OutboundProxyProtocol::Ss(node) => Some(&node.common_opts.server),
        OutboundProxyProtocol::Socks5(node) => Some(&node.common_opts.server),
        #[cfg(feature = "anytls")]
        OutboundProxyProtocol::Anytls(node) => Some(&node.common_opts.server),
        OutboundProxyProtocol::Vless(node) => Some(&node.common_opts.server),
        #[cfg(feature = "wireguard")]
        OutboundProxyProtocol::Wireguard(node) => Some(&node.common_opts.server),
        #[cfg(feature = "trojan")]
        OutboundProxyProtocol::Trojan(node) => Some(&node.common_opts.server),
        #[cfg(feature = "hysteria")]
        OutboundProxyProtocol::Hysteria2(node) => Some(&node.server),
    }
}

fn egress_contains_node(
    c: &ConfigDef,
    egress: &str,
    node: &str,
    visited: &mut HashSet<String>,
) -> bool {
    if egress == node {
        return true;
    }
    if !visited.insert(egress.to_owned()) {
        return false;
    }
    c.proxy_group.as_ref().is_some_and(|groups| {
        groups.iter().any(|group| {
            group.name() == egress
                && group.proxies().is_some_and(|members| {
                    members
                        .iter()
                        .any(|member| egress_contains_node(c, member, node, visited))
                })
        })
    })
}

fn reject_obvious_bootstrap_cycles(
    c: &ConfigDef,
    rules: &[CompiledDnsRule],
) -> Result<(), Error> {
    for rule in rules {
        let Some(DnsEgress::Proxy(egress)) = &rule.action.egress else {
            continue;
        };
        for node in c.proxy.iter().flatten() {
            let Some(host) = proxy_server_hostname(node) else {
                continue;
            };
            // IP-literal node endpoints require no DNS bootstrap.
            if host.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            let Ok(host) = canonical_domain(host, "proxy node endpoint") else {
                continue;
            };
            if (rule.matcher.matches(&host, RecordType::A)
                || rule.matcher.matches(&host, RecordType::AAAA))
                && egress_contains_node(c, egress, node.name(), &mut HashSet::new())
            {
                return Err(invalid(format!(
                    "rule[{}] bootstrap dependency cycle: proxy node '{}' needs DNS for '{host}' but its DNS egress uses '{egress}'",
                    rule.ordinal,
                    node.name()
                )));
            }
        }
    }
    Ok(())
}

impl CompiledDnsPolicy {
    /// Validate + compile without dialing, doing DNS lookups or modifying
    /// Business Rules. Returned rules always retain YAML's ordinal.
    pub fn compile(c: &ConfigDef) -> Result<Self, Error> {
        if !c.dns.enable
            && (!c.dns.policy_rules.is_empty()
                || !c.dns.resolver_profiles.is_empty())
        {
            return Err(invalid(
                "DNS must be enabled to use resolver-profiles/policy-rules",
            ));
        }
        let mut profiles = HashMap::with_capacity(c.dns.resolver_profiles.len());
        for (name, def) in &c.dns.resolver_profiles {
            if name.is_empty() || name.trim() != name {
                return Err(invalid(
                    "resolver-profiles key must be nonempty and unpadded",
                ));
            }
            if def.servers.is_empty() {
                return Err(invalid(format!(
                    "resolver profile '{name}' has no servers"
                )));
            }
            let servers = Config::parse_nameserver(&def.servers)?;
            if servers.len() != def.servers.len() {
                return Err(invalid(format!(
                    "resolver profile '{name}' contains an unusable server (e.g. 'system')"
                )));
            }
            profiles.insert(name.clone(), servers);
        }
        let mut rules = Vec::with_capacity(c.dns.policy_rules.len());
        for (ordinal, rule) in c.dns.policy_rules.iter().enumerate() {
            let matcher = compile_match(&rule.r#match, ordinal)?;
            let action = compile_action(&rule.action, ordinal, c, &profiles)?;
            rules.push(CompiledDnsRule {
                ordinal,
                matcher,
                action,
            });
        }
        // Only obvious static self-dependencies are decidable in S01;
        // dynamic provider/selector and runtime recursion guards belong to S04.
        reject_obvious_bootstrap_cycles(c, &rules)?;
        Ok(Self { profiles, rules })
    }

    /// Pure query selection: first matching YAML rule wins, regardless of
    /// exact vs suffix specificity. Input is a single DNS Question.
    pub fn match_query(
        &self,
        qname: &str,
        qtype: RecordType,
    ) -> Option<&CompiledDnsRule> {
        let canonical = canonical_domain(qname, "query name").ok()?;
        self.rules
            .iter()
            .find(|r| r.matcher.matches(&canonical, qtype))
    }
}
