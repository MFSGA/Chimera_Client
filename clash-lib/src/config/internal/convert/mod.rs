use std::collections::HashMap;

#[cfg(feature = "anytls")]
use crate::config::internal::listener::InboundOpts;

use tracing::warn;

use crate::{
    Error,
    common::auth,
    config::{
        def,
        internal::{
            config::{self, Profile},
            proxy::{
                OutboundDirect, OutboundProxy, OutboundProxyProtocol,
                OutboundReject, PROXY_DIRECT, PROXY_REJECT,
            },
            rule::RuleType,
        },
    },
};

mod general;
/// 3
mod listener;
mod proxy_group;
mod rule_provider;
mod tun;

impl TryFrom<def::Config> for config::Config {
    type Error = crate::Error;

    fn try_from(value: def::Config) -> Result<Self, Self::Error> {
        #[cfg(not(feature = "tun"))]
        if value.tun.as_ref().is_some_and(|tun| tun.enable) {
            return Err(Error::InvalidConfig(
                "tun is enabled in the configuration, but clash-lib was built without the `tun` feature"
                    .to_owned(),
            ));
        }

        convert(value)
    }
}

pub(super) fn convert(mut c: def::Config) -> Result<config::Config, crate::Error> {
    let mut proxy_names =
        vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];

    if c.allow_lan.unwrap_or_default() && c.bind_address.is_localhost() {
        warn!(
            "allow-lan is set to true, but bind-address is set to localhost. This \
             will not allow any connections from the local network."
        );
    }
    if let Some(tun) = &mut c.tun {
        match (c.routing_mark, tun.so_mark) {
            (Some(routing_mark), None) => tun.so_mark = Some(routing_mark),
            (None, Some(tun_so_mark)) if tun.enable => {
                c.routing_mark = Some(tun_so_mark);
            }
            _ => {}
        }
    }
    let dns: crate::app::dns::Config = (&c).try_into()?;
    validate_global_ipv6(&c, &dns)?;
    let mut tun = tun::convert(c.tun.take())?;
    validate_dns_tun_ipv6(c.ipv6, &dns, &tun)?;
    configure_fake_ip_route(&dns, &mut tun)?;

    config::Config {
        proxies: c.proxy.take().unwrap_or_default().into_iter().try_fold(
            HashMap::from([
                (
                    String::from(PROXY_DIRECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Direct(
                        OutboundDirect {
                            name: PROXY_DIRECT.to_string(),
                        },
                    )),
                ),
                (
                    String::from(PROXY_REJECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Reject(
                        OutboundReject {
                            name: PROXY_REJECT.to_string(),
                        },
                    )),
                ),
            ]),
            |mut rv, protocol| {
                let proxy = OutboundProxy::ProxyServer(protocol);
                let name = proxy.name();
                if rv.contains_key(name.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "duplicated proxy name: {name}"
                    )));
                }
                proxy_names.push(name.clone());
                rv.insert(name, proxy);
                Ok(rv)
            },
        )?,
        proxy_groups: proxy_group::convert(c.proxy_group.take(), &mut proxy_names)?,
        proxy_providers: c
            .proxy_provider
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|(name, mut provider)| {
                // `name` is `#[serde(skip)]` so it defaults to ""; populate
                // from the map key.
                provider.set_name(name.clone());
                (name, provider)
            })
            .collect(),
        rule_providers: rule_provider::convert(c.rule_provider.take()),
        proxy_names,
        users: c
            .authentication
            .clone()
            .into_iter()
            .map(|u| {
                let mut parts = u.splitn(2, ':');
                let username = parts.next().unwrap_or_default().to_string();
                let password = parts.next().unwrap_or_default().to_string();
                auth::User::new(username, password)
            })
            .collect(),
        listeners: listener::convert(c.listeners.take(), &c)?,
        rules: c
            .rule
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|x| {
                x.parse::<RuleType>()
                    .map_err(|x| Error::InvalidConfig(x.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        general: general::convert(&c)?,
        dns,
        tun,
        experimental: c.experimental.take(),
        profile: Profile {
            store_selected: c.profile.store_selected,
            store_smart_stats: c.profile.store_smart_stats,
        },
    }
    .validate()
}

fn validate_global_ipv6(
    config: &def::Config,
    dns: &crate::app::dns::Config,
) -> Result<(), Error> {
    if config.ipv6 {
        return Ok(());
    }

    if config.bind_address.0.is_ipv6() {
        return Err(Error::InvalidConfig(
            "ipv6 is disabled but bind-address uses an IPv6 address".to_owned(),
        ));
    }
    if config.listeners.as_ref().is_some_and(|listeners| {
        listeners
            .iter()
            .any(|listener| listener.common_opts().listen.0.is_ipv6())
    }) {
        return Err(Error::InvalidConfig(
            "ipv6 is disabled but a listener uses an IPv6 address".to_owned(),
        ));
    }

    #[cfg(feature = "anytls")]
    if config.listeners.as_ref().is_some_and(|listeners| {
        listeners.iter().any(|listener| {
            matches!(
                listener,
                InboundOpts::Anytls {
                    fallback: Some(fallback),
                    ..
                } if fallback
                    .parse::<std::net::SocketAddr>()
                    .is_ok_and(|address| address.is_ipv6())
            )
        })
    }) {
        return Err(Error::InvalidConfig(
            "ipv6 is disabled but an AnyTLS fallback uses an IPv6 address"
                .to_owned(),
        ));
    }

    for proxy in config.proxy.as_deref().unwrap_or_default() {
        if let Some(server) = proxy.server_address()
            && is_ipv6_literal(server)
        {
            return Err(Error::InvalidConfig(format!(
                "ipv6 is disabled but proxy `{}` uses an IPv6 server address",
                proxy.name()
            )));
        }
    }

    let name_servers = dns
        .nameserver
        .iter()
        .chain(dns.fallback.iter())
        .chain(dns.default_nameserver.iter())
        .chain(dns.proxy_server_nameserver.iter().flatten())
        .chain(dns.direct_nameserver.iter().flatten())
        .chain(dns.nameserver_policy.values());
    if name_servers
        .into_iter()
        .any(|nameserver| matches!(&nameserver.host, url::Host::Ipv6(_)))
    {
        return Err(Error::InvalidConfig(
            "ipv6 is disabled but a DNS nameserver uses an IPv6 address".to_owned(),
        ));
    }

    let listen = &dns.listen;
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
        return Err(Error::InvalidConfig(
            "ipv6 is disabled but a DNS listener uses an IPv6 address".to_owned(),
        ));
    }

    if config
        .dns
        .edns_client_subnet
        .as_ref()
        .is_some_and(|subnet| subnet.ipv6.is_some())
        || config.dns.fake_ip_range6.is_some()
    {
        return Err(Error::InvalidConfig(
            "ipv6 is disabled but DNS IPv6 client-subnet or fake-IP settings are configured"
                .to_owned(),
        ));
    }
    if config
        .hosts
        .values()
        .any(|address| is_ipv6_literal(address))
    {
        return Err(Error::InvalidConfig(
            "ipv6 is disabled but hosts contains an IPv6 address".to_owned(),
        ));
    }

    if let Some(tun) = &config.tun {
        let has_ipv6_route = [
            tun.routes.as_ref(),
            tun.route_exclude_address.as_ref(),
            tun.inet4_route_exclude_address.as_ref(),
            tun.inet6_route_exclude_address.as_ref(),
        ]
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|route| route.parse::<ipnet::IpNet>().ok())
        .any(|route| route.addr().is_ipv6());
        if tun.ipv6 == Some(true)
            || tun.gateway_v6.is_some()
            || !tun
                .inet6_route_exclude_address
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            || has_ipv6_route
        {
            return Err(Error::InvalidConfig(
                "ipv6 is disabled but TUN IPv6 gateway, routes, or enablement are configured"
                    .to_owned(),
            ));
        }
    }

    Ok(())
}

fn is_ipv6_literal(address: &str) -> bool {
    let address = address.trim();
    let address = address
        .strip_prefix('[')
        .and_then(|address| address.strip_suffix(']'))
        .unwrap_or(address);
    address.parse::<std::net::Ipv6Addr>().is_ok()
}

fn validate_dns_tun_ipv6(
    global_ipv6: bool,
    dns: &crate::app::dns::Config,
    tun: &config::TunConfig,
) -> Result<(), Error> {
    if tun.enable && global_ipv6 && tun.gateway_v6.is_none() && dns.ipv6 {
        return Err(Error::InvalidConfig(
            "dns IPv6 responses require tun.ipv6 when TUN is enabled".to_owned(),
        ));
    }
    if tun.enable && global_ipv6 && tun.gateway_v6.is_none() {
        return Err(Error::InvalidConfig(
            "global IPv6 requires tun.ipv6 when TUN is enabled".to_owned(),
        ));
    }
    Ok(())
}

fn configure_fake_ip_route(
    dns: &crate::app::dns::Config,
    tun: &mut config::TunConfig,
) -> Result<(), Error> {
    if !tun.enable || !dns.enable || dns.enhance_mode != def::DNSMode::FakeIp {
        return Ok(());
    }

    let fake_ip_range = match dns.fake_ip_range {
        ipnet::IpNet::V4(range) => range,
        ipnet::IpNet::V6(_) => {
            return Err(Error::InvalidConfig(
                "fake-ip-range must be an IPv4 subnet".to_string(),
            ));
        }
    };

    let tun_network = tun.gateway.trunc();
    if tun_network.contains(&fake_ip_range.network())
        || fake_ip_range.contains(&tun_network.network())
    {
        return Err(Error::InvalidConfig(format!(
            "tun gateway subnet `{tun_network}` overlaps fake-ip-range \
             `{fake_ip_range}`; use separate subnets"
        )));
    }

    let fake_ip_route = ipnet::IpNet::V4(fake_ip_range.trunc());
    if !tun.route_all && !tun.routes.contains(&fake_ip_route) {
        tun.routes.push(fake_ip_route);
    }

    if dns.ipv6 {
        let fake_ip_range6 = match dns.fake_ip_range6 {
            Some(ipnet::IpNet::V6(range)) => range,
            Some(ipnet::IpNet::V4(_)) => {
                return Err(Error::InvalidConfig(
                    "fake-ip-range6 must be an IPv6 subnet".to_string(),
                ));
            }
            None => return Ok(()),
        };
        let tun_network_v6 = tun.gateway_v6.ok_or_else(|| {
            Error::InvalidConfig(
                "DNS IPv6 fake-IP requires tun IPv6 to be enabled".to_owned(),
            )
        })?;
        if tun_network_v6.contains(&fake_ip_range6.network())
            || fake_ip_range6.contains(&tun_network_v6.network())
        {
            return Err(Error::InvalidConfig(format!(
                "tun IPv6 gateway subnet `{tun_network_v6}` overlaps fake-ip-range6 \
                 `{fake_ip_range6}`; use separate subnets"
            )));
        }

        let fake_ip_route6 = ipnet::IpNet::V6(fake_ip_range6.trunc());
        if !tun.route_all && !tun.routes.contains(&fake_ip_route6) {
            tun.routes.push(fake_ip_route6);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{Error, config::def};

    use super::convert;

    fn parse_config(extra_yaml: &str) -> def::Config {
        let yaml = format!(
            r#"
bind_address: "*"
log_level: info
ipv6: false
dns: {{}}
profile: {{}}
{extra_yaml}
"#
        );
        yaml.parse::<def::Config>()
            .expect("def config should parse")
    }

    #[test]
    fn mihomo_respect_rules_requires_proxy_server_nameserver() {
        let mut cfg = parse_config("");
        cfg.dns.respect_rules = true;
        cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
        let err = match convert(cfg) {
            Ok(_) => panic!("respect-rules needs bootstrap DNS for proxy nodes"),
            Err(err) => err,
        };
        assert!(
            matches!(err, Error::InvalidConfig(msg) if msg.contains("proxy-server-nameserver"))
        );
    }

    #[cfg(feature = "tun")]
    #[test]
    fn tun_fake_ip_rejects_local_resolution_of_proxy_destinations() {
        let mut cfg = parse_config("tun:\n  enable: true");
        cfg.dns.enable = true;
        cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.experimental =
            Some(serde_yaml::from_str("proxy-resolve-local: true").unwrap());
        let err = match convert(cfg) {
            Ok(_) => panic!(
                "proxy destination local DNS must not be allowed in Fake-IP TUN"
            ),
            Err(err) => err,
        };
        assert!(
            matches!(err, Error::InvalidConfig(msg) if msg.contains("proxy-resolve-local"))
        );
    }

    #[cfg(feature = "tun")]
    #[test]
    fn tun_fake_ip_accepts_remote_domain_proxy_mode() {
        let mut cfg = parse_config("tun:\n  enable: true\n  dns-hijack: true");
        cfg.dns.enable = true;
        cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.experimental =
            Some(serde_yaml::from_str("proxy-resolve-local: false").unwrap());
        convert(cfg)
            .expect("Fake-IP TUN with proxy remote domain mode must be valid");
    }

    #[test]
    fn internal_dns_config_cannot_bypass_unsupported_mihomo_filter_gate() {
        let mut cfg = parse_config("");
        cfg.dns.enable = true;
        cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        let mut internal =
            convert(cfg).expect("build a valid internal Fake-IP config");
        internal.dns.fake_ip_filter = vec!["geosite:proxy".to_owned()];
        let err = match crate::Config::Internal(internal).try_parse() {
            Ok(_) => {
                panic!("internal config must reject unsupported filter expression")
            }
            Err(err) => err,
        };
        assert!(
            matches!(err, Error::InvalidConfig(msg) if msg.contains("dns.fake-ip-filter") && msg.contains("geosite:proxy"))
        );
    }

    #[cfg(feature = "tun")]
    #[test]
    fn internal_tun_fake_ip_cannot_bypass_proxy_dns_privacy_gate() {
        let mut cfg = parse_config("tun:\n  enable: true");
        cfg.dns.enable = true;
        cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        let mut internal =
            convert(cfg).expect("build a valid internal Fake-IP config");
        internal.experimental =
            Some(serde_yaml::from_str("proxy-resolve-local: true").unwrap());
        let err = match crate::Config::Internal(internal).try_parse() {
            Ok(_) => panic!("internal configs must honor the same DNS privacy gate"),
            Err(err) => err,
        };
        assert!(
            matches!(err, Error::InvalidConfig(msg) if msg.contains("proxy-resolve-local"))
        );
    }

    #[test]
    fn ipv6_disabled_rejects_literal_ipv6_proxy_server() {
        let error = match convert(parse_config(
            "proxies:\n  - name: ipv6-node\n    type: socks5\n    server: '2001:db8::1'\n    port: 1080\n",
        )) {
            Ok(_) => panic!("IPv6 proxy endpoint must be rejected globally"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("ipv6-node"), "{error}");
        assert!(error.contains("IPv6 server address"), "{error}");
    }

    #[test]
    fn ipv6_disabled_keeps_domain_proxy_servers_valid() {
        convert(parse_config(
            "proxies:\n  - name: domain-node\n    type: socks5\n    server: node.example\n    port: 1080\n",
        ))
        .expect("domain endpoints are filtered to IPv4 at runtime");
    }

    #[test]
    fn ipv6_enabled_accepts_literal_ipv6_proxy_server() {
        let mut config = parse_config(
            "proxies:\n  - name: ipv6-node\n    type: socks5\n    server: '2001:db8::1'\n    port: 1080\n",
        );
        config.ipv6 = true;
        convert(config).expect("IPv6 endpoint should be accepted when enabled");
    }

    #[test]
    fn global_ipv6_is_independent_from_dns_aaaa_responses() {
        let mut config = parse_config("");
        config.ipv6 = true;
        config.dns.ipv6 = false;

        let converted = convert(config).expect("global IPv6 should be enabled");
        assert!(converted.general.ipv6);
        assert!(converted.dns.global_ipv6);
        assert!(!converted.dns.dns_ipv6);
        assert!(!converted.dns.ipv6);
    }

    #[test]
    fn ipv6_disabled_rejects_ipv6_tun_dns_hijack_address() {
        let error = match convert(parse_config(
            "tun:\n  enable: true\n  dns-hijack:\n    - 'udp://[2001:db8::1]:53'\n",
        )) {
            Ok(_) => panic!("IPv6 DNS hijack address must be rejected globally"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("DNS hijack rule uses an IPv6 address"),
            "{error}"
        );
    }

    #[cfg(feature = "anytls")]
    #[test]
    fn ipv6_disabled_rejects_literal_ipv6_anytls_fallback() {
        let error = match convert(parse_config(
            "listeners:\n  - name: anytls-in\n    type: anytls\n    listen: 127.0.0.1\n    port: 8443\n    password: test\n    fallback: '[2001:db8::1]:443'\n",
        )) {
            Ok(_) => panic!("IPv6 AnyTLS fallback must be rejected globally"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("AnyTLS fallback uses an IPv6 address"),
            "{error}"
        );
    }

    #[cfg(feature = "tun")]
    #[test]
    fn fake_ip_tun_rejects_xhttp_secondary_system_dns_endpoints() {
        // The XHTTP HTTP/1.1 reconnect and HTTP/2 separate downlink use
        // tokio::lookup_host, not the configured proxy-server-nameserver.
        // These cases may be accepted in ordinary mode but cannot be
        // silently treated as protected DNS inside Fake-IP TUN.
        let scenarios = [
            ("h2", "download.example", "download-settings"),
            ("http/1.1", "primary.example", "http/1.1"),
        ];
        for (alpn, host, offending) in scenarios {
            let download = if alpn == "h2" {
                "      download-settings:\n        address: download.example\n        port: 8443\n"
            } else {
                ""
            };
            let raw = format!(
                "tun:\n  enable: true\nproxies:\n  - name: XHTTP\n    type: vless\n    server: {host}\n    port: 443\n    uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n    network: xhttp\n    alpn: [{alpn}]\n    xhttp-opts:\n      mode: auto\n{download}",
            );
            let err = match convert({
                let mut cfg = parse_config(&raw);
                cfg.dns.enable = true;
                cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
                cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
                cfg
            }) {
                Ok(_) => panic!("unprotected secondary XHTTP DNS must fail"),
                Err(error) => error.to_string(),
            };
            assert!(err.contains("xhttp") && err.contains(offending), "{err}");
            assert!(
                !err.contains("download.example")
                    && !err.contains("primary.example"),
                "{err}"
            );
        }
    }

    #[cfg(feature = "tun")]
    #[test]
    fn fake_ip_tun_allows_literal_xhttp_secondary_and_primary_managed_dns() {
        for (server, alpn, download) in [
            ("primary.example", "h2", ""),
            (
                "primary.example",
                "h2",
                "download-settings:\n        address: 192.0.2.42\n        port: 8443",
            ),
            ("192.0.2.15", "http/1.1", ""),
        ] {
            let raw = format!(
                "tun:\n  enable: true\nproxies:\n  - name: XHTTP\n    type: vless\n    server: {server}\n    port: 443\n    uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n    network: xhttp\n    alpn: [{alpn}]\n    xhttp-opts:\n      mode: auto\n      {download}\n",
            );
            convert({
                let mut cfg = parse_config(&raw);
                cfg.dns.enable = true;
                cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
                cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
                cfg
            })
            .expect("no secondary system-DNS hostname");
        }
    }

    #[cfg(feature = "tun")]
    #[test]
    fn xhttp_extra_download_precedence_cannot_bypass_dns_safety_gate() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
proxies:
  - name: XHTTP
    type: vless
    server: primary.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    alpn: [h2]
    xhttp-opts:
      download-settings:
        address: 192.0.2.10
      extra:
        download-settings:
          address: private.example
"#,
        );
        cfg.dns.enable = true;
        cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        let err = match convert(cfg) {
            Ok(_) => {
                panic!("effective extra.download-settings requires DNS protection")
            }
            Err(err) => err.to_string(),
        };
        assert!(err.contains("xhttp download-settings"), "{err}");
        assert!(!err.contains("private.example"), "{err}");
    }

    #[cfg(feature = "tun")]
    #[test]
    fn xhttp_unsafe_secondary_rejected_after_internal_reload() {
        // Start with a valid non-TUN configuration, then enable TUN through
        // the Internal config path (reloads do not call YAML parsing).
        let mut cfg = parse_config(
            r#"
proxies:
  - name: XHTTP
    type: vless
    server: primary.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    alpn: [h2]
    xhttp-opts:
      download-settings:
        address: hidden.example
"#,
        );
        cfg.dns.enable = true;
        cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        let mut internal =
            convert(cfg).expect("non-TUN allows existing XHTTP semantics");
        internal.tun.enable = true;
        let error = match crate::Config::Internal(internal).try_parse() {
            Ok(_) => panic!("reload must not bypass XHTTP DNS egress gate"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("xhttp download-settings"), "{error}");
        assert!(!error.contains("hidden.example"), "{error}");
    }

    #[cfg(all(feature = "tun", feature = "anytls"))]
    #[test]
    fn fake_ip_tun_rejects_anytls_fallback_system_dns_hostname() {
        for hostname in ["camouflage.example:443", "localhost:443", "192.0.2.53"] {
            let mut cfg = parse_config(&format!(
                "tun:\n  enable: true\nlisteners:\n  - name: tls-in\n    type: anytls\n    listen: 127.0.0.1\n    port: 34432\n    password: test-password\n    fallback: {hostname}\n",
            ));
            cfg.dns.enable = true;
            cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
            cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
            let err = match convert(cfg) {
                Ok(_) => {
                    panic!("AnyTLS hostname fallback may use unprotected OS DNS")
                }
                Err(error) => error.to_string(),
            };
            assert!(err.contains("anytls") && err.contains("fallback"), "{err}");
            assert!(
                !err.contains("camouflage.example") && !err.contains("localhost"),
                "{err}"
            );
        }
    }

    #[cfg(all(feature = "tun", feature = "anytls"))]
    #[test]
    fn fake_ip_tun_allows_anytls_ip_literal_fallback_and_non_tun_hostname() {
        for (tun_enabled, ipv6_enabled, addr) in [
            (true, false, "192.0.2.53:443"),
            (true, true, "[2001:db8::53]:443"),
            (false, false, "camouflage.example:443"),
        ] {
            let mut cfg = parse_config(&format!(
                "tun:\n  enable: {tun_enabled}\nlisteners:\n  - name: tls-in\n    type: anytls\n    listen: 127.0.0.1\n    port: 34432\n    password: test-password\n    fallback: '{addr}'\n",
            ));
            cfg.ipv6 = ipv6_enabled;
            if let Some(tun) = cfg.tun.as_mut() {
                tun.ipv6 = Some(ipv6_enabled);
            }
            cfg.dns.enable = true;
            cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
            cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
            convert(cfg).expect(
                "IP literal needs no system DNS; non-TUN legacy is unchanged",
            );
        }
    }

    #[cfg(all(feature = "tun", feature = "anytls"))]
    #[test]
    fn anytls_inbound_fallback_cannot_bypass_gate_by_internal_reload() {
        let mut cfg = parse_config(
            "listeners:\n  - name: tls-in\n    type: anytls\n    listen: 127.0.0.1\n    port: 34432\n    password: test-password\n    fallback: private.example:443\n",
        );
        cfg.dns.enable = true;
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.dns.nameserver = vec!["1.1.1.1".to_owned()];
        let mut internal = convert(cfg).expect("baseline without TUN is accepted");
        internal.tun.enable = true;
        let error = match crate::Config::Internal(internal).try_parse() {
            Ok(_) => {
                panic!("internal reload must reject unaudited AnyTLS system DNS")
            }
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("anytls") && error.contains("fallback"),
            "{error}"
        );
        assert!(!error.contains("private.example"), "{error}");
    }

    #[cfg(not(feature = "tun"))]
    #[test]
    fn reject_enabled_tun_without_tun_feature() {
        let cfg = parse_config("tun:\n  enable: true");
        let error = match super::config::Config::try_from(cfg) {
            Ok(_) => panic!("enabled TUN must require the tun feature"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            Error::InvalidConfig(message)
                if message.contains("without the `tun` feature")
        ));

        let mut internal = convert(parse_config(""))
            .expect("conversion helper should produce the test fixture");
        internal.tun.enable = true;
        let error = match crate::Config::Internal(internal).try_parse() {
            Ok(_) => panic!("internal config must use the same feature validation"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Error::InvalidConfig(message)
                if message.contains("without the `tun` feature")
        ));
    }

    #[cfg(feature = "wireguard")]
    #[test]
    fn preserve_wireguard_http_proxy_provider() {
        let cfg = parse_config(
            r#"
proxy-providers:
  wg-nodes:
    type: http
    url: https://example.com/wireguard.yaml
    interval: 3600
    path: providers/wireguard.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        let provider = converted
            .proxy_providers
            .get("wg-nodes")
            .expect("wireguard http provider should be preserved");

        match provider {
            crate::config::internal::proxy::OutboundProxyProviderDef::Http(http) => {
                assert_eq!(http.name, "wg-nodes");
                assert_eq!(http.url, "https://example.com/wireguard.yaml");
                assert_eq!(http.interval, 3600);
                assert_eq!(http.path, "providers/wireguard.yaml");
                assert_eq!(http.health_check.enable, Some(true));
                assert_eq!(http.health_check.interval, Some(300));
            }
            _ => panic!("expected http proxy provider"),
        }
    }

    #[cfg(feature = "wireguard")]
    #[test]
    fn preserve_wireguard_file_proxy_provider() {
        let cfg = parse_config(
            r#"
proxy-providers:
  wg-nodes:
    type: file
    path: wireguard-proxies.yaml
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        let provider = converted
            .proxy_providers
            .get("wg-nodes")
            .expect("wireguard file provider should be preserved");

        match provider {
            crate::config::internal::proxy::OutboundProxyProviderDef::File(file) => {
                assert_eq!(file.name, "wg-nodes");
                assert_eq!(file.path, "wireguard-proxies.yaml");
            }
            _ => panic!("expected file proxy provider"),
        }
    }

    #[test]
    fn fill_tun_so_mark_from_routing_mark() {
        let cfg = parse_config(
            r#"
routing-mark: 6666
tun:
  enable: true
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        assert_eq!(converted.tun.so_mark, Some(6666));
    }

    #[cfg(feature = "tun")]
    #[test]
    fn fake_ip_tun_adds_fake_ip_route_without_hijack_or_route_all() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  route-all: false
  dns-hijack: false
"#,
        );
        cfg.dns.enable = true;
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.dns.nameserver.push("114.114.114.114".to_owned());

        let converted = convert(cfg).expect("TUN fake-IP config should convert");
        let fake_ip_route: ipnet::IpNet = "198.19.0.0/16".parse().unwrap();
        assert!(converted.tun.routes.contains(&fake_ip_route));
    }

    #[test]
    fn reject_dns_ipv6_with_ipv4_only_tun() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  ipv6: false
"#,
        );
        cfg.ipv6 = true;
        cfg.dns.ipv6 = true;

        let error = match convert(cfg) {
            Ok(_) => panic!("IPv4-only TUN must reject DNS IPv6"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Error::InvalidConfig(message)
                if message.contains("dns IPv6 responses require tun.ipv6")
        ));
    }

    #[test]
    fn allow_dns_ipv6_with_ipv6_tun() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  ipv6: true
"#,
        );
        cfg.ipv6 = true;
        cfg.dns.ipv6 = true;

        let converted = convert(cfg).expect("dual-stack TUN should be valid");
        assert!(converted.dns.ipv6);
        assert!(converted.tun.gateway_v6.is_some());
    }

    #[test]
    fn keep_tun_so_mark_if_explicitly_set() {
        let cfg = parse_config(
            r#"
routing-mark: 6666
tun:
  enable: true
  so-mark: 7777
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        assert_eq!(converted.tun.so_mark, Some(7777));
    }

    #[test]
    fn fill_routing_mark_from_enabled_tun_so_mark() {
        let cfg = parse_config(
            r#"
tun:
  enable: true
  so-mark: 7777
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        assert_eq!(converted.general.routing_mask, Some(7777));
        assert_eq!(converted.dns.fw_mark, Some(7777));
        assert_eq!(converted.tun.so_mark, Some(7777));
    }

    #[test]
    fn parse_tun_auto_route_alias() {
        let cfg = parse_config(
            r#"
tun:
  enable: true
  auto-route: true
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        assert!(converted.tun.route_all);
    }

    #[test]
    fn fake_ip_mode_adds_route_for_separate_default_pool() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
"#,
        );
        cfg.dns.enable = true;
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.dns.nameserver = vec!["1.1.1.1".to_string()];

        let converted = convert(cfg).expect("internal convert should succeed");
        assert_eq!(converted.tun.gateway.to_string(), "198.18.0.1/30");
        assert!(
            converted
                .tun
                .routes
                .contains(&"198.19.0.0/16".parse().unwrap())
        );
    }

    #[test]
    fn fake_ip_mode_adds_route_for_ipv6_pool() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  ipv6: true
  gateway-v6: fd00:1::1/126
"#,
        );
        cfg.ipv6 = true;
        cfg.dns.enable = true;
        cfg.dns.ipv6 = true;
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.dns.fake_ip_range6 = Some("fd00:198:18::/96".to_string());
        cfg.dns.nameserver = vec!["1.1.1.1".to_string()];

        let converted = convert(cfg).expect("IPv6 fake-IP pool should be valid");
        assert!(
            converted
                .tun
                .routes
                .contains(&"fd00:198:18::/96".parse::<ipnet::IpNet>().unwrap())
        );
    }

    #[test]
    fn reject_overlapping_tun_and_fake_ipv6_subnets() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  ipv6: true
  gateway-v6: fd00:198:18::1/120
"#,
        );
        cfg.ipv6 = true;
        cfg.dns.enable = true;
        cfg.dns.ipv6 = true;
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.dns.fake_ip_range6 = Some("fd00:198:18::/96".to_string());
        cfg.dns.nameserver = vec!["1.1.1.1".to_string()];

        match convert(cfg) {
            Err(Error::InvalidConfig(message)) => {
                assert!(message.contains("overlaps fake-ip-range6"));
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("overlapping IPv6 fake-IP and TUN ranges should fail"),
        }
    }

    #[test]
    fn reject_overlapping_tun_and_fake_ip_subnets() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  gateway: 198.18.0.1/30
"#,
        );
        cfg.dns.enable = true;
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.dns.fake_ip_range = "198.18.0.0/16".to_string();
        cfg.dns.nameserver = vec!["1.1.1.1".to_string()];

        match convert(cfg) {
            Err(Error::InvalidConfig(message)) => {
                assert!(message.contains("overlaps fake-ip-range"));
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("overlapping subnets must be rejected"),
        }
    }

    #[test]
    fn parse_relay_group_with_proxies() {
        let cfg = parse_config(
            r#"
proxies:
  - name: "proxy-a"
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: "proxy-b"
    type: socks5
    server: 127.0.0.1
    port: 1081

proxy-groups:
  - name: "relay-chain"
    type: relay
    proxies:
      - "proxy-a"
      - "proxy-b"
    url: "http://www.gstatic.com/generate_204"
    icon: "relay.svg"
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        let group = converted
            .proxy_groups
            .get("relay-chain")
            .expect("relay-chain group should exist");

        use crate::config::internal::proxy::OutboundGroupProtocol;
        match &group {
            crate::config::internal::proxy::OutboundProxy::ProxyGroup(protocol) => {
                match protocol {
                    OutboundGroupProtocol::Relay(relay) => {
                        assert_eq!(relay.name, "relay-chain");
                        assert_eq!(
                            relay.proxies,
                            Some(vec!["proxy-a".to_string(), "proxy-b".to_string()])
                        );
                        assert_eq!(
                            relay.url,
                            Some("http://www.gstatic.com/generate_204".to_string())
                        );
                        assert_eq!(relay.icon, Some("relay.svg".to_string()));
                    }
                    _ => panic!("expected Relay group, got {protocol:?}"),
                }
            }
            _ => panic!("expected ProxyGroup"),
        }
    }

    #[test]
    fn parse_relay_group_minimal() {
        let cfg = parse_config(
            r#"
proxies:
  - name: "proxy-a"
    type: socks5
    server: 127.0.0.1
    port: 1080

proxy-groups:
  - name: "minimal-relay"
    type: relay
    proxies:
      - "proxy-a"
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        let group = converted
            .proxy_groups
            .get("minimal-relay")
            .expect("minimal-relay group should exist");

        use crate::config::internal::proxy::OutboundGroupProtocol;
        match &group {
            crate::config::internal::proxy::OutboundProxy::ProxyGroup(protocol) => {
                match protocol {
                    OutboundGroupProtocol::Relay(relay) => {
                        assert_eq!(relay.name, "minimal-relay");
                        assert_eq!(relay.proxies, Some(vec!["proxy-a".to_string()]));
                        assert!(relay.url.is_none());
                        assert!(relay.icon.is_none());
                    }
                    _ => panic!("expected Relay group, got {protocol:?}"),
                }
            }
            _ => panic!("expected ProxyGroup"),
        }
    }
}
