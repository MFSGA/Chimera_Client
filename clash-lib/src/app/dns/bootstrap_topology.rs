//! S04b-d: offline, conservative *configured* strict-DNS bootstrap dependencies.
//! This does not authenticate pins or enumerate mutable provider contents.
//! The production DNS resolver still rejects nonempty policy-rules.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

use crate::config::{
    def::Config as ConfigDef,
    internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
};

use super::config::NameServer;

fn proxy_endpoints(proxy: &OutboundProxyProtocol) -> Option<(&str, Option<&str>)> {
    match proxy {
        OutboundProxyProtocol::Direct(_) | OutboundProxyProtocol::Reject(_) => None,
        #[cfg(feature = "shadowsocks")]
        OutboundProxyProtocol::Ss(p) => {
            Some((&p.common_opts.server, p.common_opts.connect_via.as_deref()))
        }
        OutboundProxyProtocol::Socks5(p) => {
            Some((&p.common_opts.server, p.common_opts.connect_via.as_deref()))
        }
        #[cfg(feature = "anytls")]
        OutboundProxyProtocol::Anytls(p) => {
            Some((&p.common_opts.server, p.common_opts.connect_via.as_deref()))
        }
        OutboundProxyProtocol::Vless(p) => {
            Some((&p.common_opts.server, p.common_opts.connect_via.as_deref()))
        }
        #[cfg(feature = "wireguard")]
        OutboundProxyProtocol::Wireguard(p) => {
            Some((&p.common_opts.server, p.common_opts.connect_via.as_deref()))
        }
        #[cfg(feature = "trojan")]
        OutboundProxyProtocol::Trojan(p) => {
            Some((&p.common_opts.server, p.common_opts.connect_via.as_deref()))
        }
        #[cfg(feature = "hysteria")]
        OutboundProxyProtocol::Hysteria2(p) => Some((&p.server, None)),
    }
}

fn provider_names(group: &OutboundGroupProtocol) -> Option<&Vec<String>> {
    match group {
        OutboundGroupProtocol::UrlTest(g) => g.use_provider.as_ref(),
        OutboundGroupProtocol::Smart(g) => g.use_provider.as_ref(),
        OutboundGroupProtocol::Fallback(g) => g.use_provider.as_ref(),
        OutboundGroupProtocol::LoadBalance(g) => g.use_provider.as_ref(),
        OutboundGroupProtocol::Relay(g) => g.use_provider.as_ref(),
        OutboundGroupProtocol::Select(g) => g.use_provider.as_ref(),
    }
}

/// Does not cache a provider view or assume a group will keep the same leaf.
/// A conservative candidate check: every reachable configured proxy must be
/// safe, rather than relying on which one happens to be selected right now.
pub(crate) fn validate_configured_strict_egress(
    config: &ConfigDef,
    egress: &str,
    servers: &[NameServer],
) -> io::Result<()> {
    const MAX_DEPTH: usize = 16;
    if servers.is_empty() {
        return Err(io::Error::other("strict DNS profile has no upstreams"));
    }

    let mut proxies = HashMap::new();
    for proxy in config.proxy.iter().flatten() {
        if proxies.insert(proxy.name(), proxy).is_some() {
            return Err(io::Error::other(format!(
                "strict DNS bootstrap duplicate proxy name '{}'",
                proxy.name()
            )));
        }
    }
    let mut groups = HashMap::new();
    for group in config.proxy_group.iter().flatten() {
        if groups.insert(group.name(), group).is_some()
            || proxies.contains_key(group.name())
        {
            return Err(io::Error::other(format!(
                "strict DNS bootstrap ambiguous group name '{}'",
                group.name()
            )));
        }
    }

    let upstreams: HashSet<String> = servers
        .iter()
        .map(|server| {
            server
                .host
                .to_string()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .collect();

    fn visit(
        name: &str,
        proxies: &HashMap<&str, &OutboundProxyProtocol>,
        groups: &HashMap<&str, &OutboundGroupProtocol>,
        upstreams: &HashSet<String>,
        active: &mut HashSet<String>,
        depth: usize,
    ) -> io::Result<()> {
        if !active.insert(name.to_owned()) {
            return Err(io::Error::other(format!(
                "strict DNS bootstrap dependency cycle at '{name}'"
            )));
        }
        if depth >= MAX_DEPTH {
            return Err(io::Error::other(format!(
                "strict DNS bootstrap dependency depth exceeded at '{name}'"
            )));
        }
        if let Some(group) = groups.get(name) {
            if provider_names(group).is_some_and(|providers| !providers.is_empty()) {
                return Err(io::Error::other(format!(
                    "strict DNS bootstrap group '{name}' has unverified dynamic provider candidates"
                )));
            }
            let members = group.proxies().filter(|v| !v.is_empty()).ok_or_else(|| {
                io::Error::other(format!(
                    "strict DNS bootstrap group '{name}' has no statically known candidates"
                ))
            })?;
            for member in members {
                visit(member, proxies, groups, upstreams, active, depth + 1)?;
            }
        } else if let Some(proxy) = proxies.get(name) {
            let (host, connect_via) = proxy_endpoints(proxy).ok_or_else(|| {
                io::Error::other(format!(
                    "strict DNS proxy egress '{name}' contains DIRECT/REJECT candidate"
                ))
            })?;
            if host.parse::<IpAddr>().is_err() {
                let canonical = host.trim_end_matches('.').to_ascii_lowercase();
                if upstreams.contains(&canonical) {
                    return Err(io::Error::other(format!(
                        "strict DNS bootstrap dependency cycle: proxy '{name}' requires upstream '{host}'"
                    )));
                }
                return Err(io::Error::other(format!(
                    "strict DNS proxy '{name}' requires independently verified bootstrap for '{host}'"
                )));
            }
            if let Some(via) = connect_via {
                visit(via, proxies, groups, upstreams, active, depth + 1)?;
            }
        } else {
            return Err(io::Error::other(format!(
                "strict DNS bootstrap candidate '{name}' is missing"
            )));
        }
        active.remove(name);
        Ok(())
    }

    visit(
        egress,
        &proxies,
        &groups,
        &upstreams,
        &mut HashSet::new(),
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::Config as DnsConfig;

    fn check(
        proxies_and_groups: &str,
        egress: &str,
        upstream: &str,
    ) -> io::Result<()> {
        let config: ConfigDef = serde_yaml::from_str(proxies_and_groups).unwrap();
        let servers = DnsConfig::parse_nameserver(&[upstream.to_owned()]).unwrap();
        validate_configured_strict_egress(&config, egress, &servers)
    }

    #[test]
    fn s04bd_static_nested_groups_and_dialer_chain_are_bounded() {
        let yaml = r#"
proxies:
  - {name: leaf, type: socks5, server: 192.0.2.10, port: 1080, dialer-proxy: hop}
  - {name: hop, type: socks5, server: 192.0.2.11, port: 1080}
proxy-groups:
  - {name: nested, type: select, proxies: [leaf]}
  - {name: outer, type: select, proxies: [nested]}
"#;
        assert!(check(yaml, "outer", "udp://192.0.2.53").is_ok());
        let cyclic = yaml.replace(
            "server: 192.0.2.11, port: 1080}",
            "server: 192.0.2.11, port: 1080, dialer-proxy: leaf}",
        );
        assert!(
            check(&cyclic, "outer", "udp://192.0.2.53")
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
        let group_cycle = yaml.replace("proxies: [nested]", "proxies: [outer]");
        assert!(
            check(&group_cycle, "outer", "udp://192.0.2.53")
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
    }

    #[test]
    fn s04bd_all_candidates_and_unknown_providers_fail_closed() {
        let yaml = r#"
proxies:
  - {name: numeric, type: socks5, server: 192.0.2.10, port: 1080}
  - {name: named, type: socks5, server: dns.example, port: 1080}
proxy-groups:
  - {name: outer, type: select, proxies: [numeric, named]}
"#;
        assert!(
            check(yaml, "outer", "tls://dns.example")
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
        assert!(
            check(yaml, "outer", "udp://192.0.2.53")
                .unwrap_err()
                .to_string()
                .contains("independently verified")
        );
        let provider = yaml.replace(
            "proxies: [numeric, named]",
            "proxies: [numeric], use: [remote-nodes]",
        );
        assert!(
            check(&provider, "outer", "udp://192.0.2.53")
                .unwrap_err()
                .to_string()
                .contains("unverified dynamic provider")
        );
        let missing =
            yaml.replace("proxies: [numeric, named]", "proxies: [missing]");
        assert!(
            check(&missing, "outer", "udp://192.0.2.53")
                .unwrap_err()
                .to_string()
                .contains("missing")
        );
    }

    #[test]
    fn s04bd_group_direct_and_duplicate_names_fail_closed() {
        let yaml = r#"
proxies:
  - {name: leaf, type: socks5, server: 192.0.2.10, port: 1080}
proxy-groups:
  - {name: outer, type: select, proxies: [leaf, DIRECT]}
"#;
        assert!(check(yaml, "outer", "udp://192.0.2.53").is_err());
        let duplicate = yaml.replace("name: outer", "name: leaf");
        assert!(
            check(&duplicate, "leaf", "udp://192.0.2.53")
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
    }
}
