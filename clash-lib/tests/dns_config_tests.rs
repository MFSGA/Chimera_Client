use clash_lib::{
    Config, Options, TokioRuntime,
    app::dns::{Config as DnsConfig, config::DNSNetMode},
};

fn parse_dns(yaml: &str) -> DnsConfig {
    Config::Str(yaml.to_owned())
        .try_parse()
        .expect("config should parse")
        .dns
}

fn parse_error(yaml: String) -> clash_lib::Error {
    match Config::Str(yaml).try_parse() {
        Ok(_) => panic!("config should fail"),
        Err(err) => err,
    }
}

fn base_config(dns_yaml: &str) -> String {
    format!(
        r#"
mixed-port: 0
bind-address: '*'
allow-lan: false
mode: rule
log-level: info
ipv6: true

dns:
{dns_yaml}

profile:
  store-selected: false
  store-fake-ip: false

proxies: []

rules:
  - MATCH,DIRECT
"#
    )
}

fn reserve_occupied_dns_sockets() -> (
    std::net::TcpListener,
    std::net::UdpSocket,
    std::net::SocketAddr,
) {
    fn is_retryable_bind_error(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::AddrInUse
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::PermissionDenied
        )
    }

    let mut last_error = None;
    for _ in 0..64 {
        let tcp = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(tcp) => tcp,
            Err(error) if is_retryable_bind_error(&error) => {
                last_error = Some(error);
                continue;
            }
            Err(error) => panic!("failed to reserve TCP DNS port: {error}"),
        };
        let addr = tcp.local_addr().expect("failed to read DNS address");
        match std::net::UdpSocket::bind(addr) {
            Ok(udp) => return (tcp, udp, addr),
            Err(error) if is_retryable_bind_error(&error) => {
                last_error = Some(error);
            }
            Err(error) => panic!("failed to reserve UDP DNS port: {error}"),
        }
    }

    panic!(
        "failed to reserve matching TCP and UDP DNS ports after 64 attempts: {}",
        last_error.expect("at least one bind attempt must fail")
    );
}

#[test]
#[serial_test::serial]
fn occupied_dns_listeners_fail_runtime_startup() {
    let (tcp, udp, addr) = reserve_occupied_dns_sockets();
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let yaml = format!(
        r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
mmdb: null
tun:
  enable: false
dns:
  enable: true
  ipv6: false
  listen:
    udp: {addr}
    tcp: {addr}
  enhanced-mode: normal
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 1.1.1.1
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
rules:
  - MATCH,DIRECT
"#
    );

    let err = clash_lib::start_scaffold(Options {
        config: Config::Str(yaml),
        cwd: Some(temp.path().to_string_lossy().to_string()),
        rt: Some(TokioRuntime::SingleThread),
        log_file: None,
        config_path: None,
    })
    .expect_err("runtime startup must fail when every DNS listener is occupied");

    assert!(err.to_string().contains("no listener started"));
    assert!(!clash_lib::shutdown());
    drop(udp);
    drop(tcp);
}

#[test]
#[serial_test::serial]
fn partial_dns_listener_startup_failure_is_reported() {
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve TCP DNS port");
    let addr = tcp.local_addr().expect("failed to read DNS address");
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let yaml = base_config(&format!(
        r#"
  enable: true
  ipv6: false
  listen:
    udp: {addr}
    tcp: {addr}
  enhanced-mode: normal
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 1.1.1.1
"#
    ));

    let err = clash_lib::start_scaffold(Options {
        config: Config::Str(yaml),
        cwd: Some(temp.path().to_string_lossy().to_string()),
        rt: Some(TokioRuntime::SingleThread),
        log_file: None,
        config_path: None,
    })
    .expect_err("runtime startup must fail if any configured listener fails");

    assert!(err.to_string().contains("no listener started"));
    assert!(!clash_lib::shutdown());
    drop(tcp);
}

#[test]
#[serial_test::serial]
fn missing_dhcp_interface_fails_runtime_startup() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let yaml = r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
mmdb: null
tun:
  enable: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: normal
  nameserver:
    - dhcp://__chimera_missing_interface__
  default-nameserver:
    - 1.1.1.1
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
rules:
  - MATCH,DIRECT
"#;

    let err = clash_lib::start_scaffold(Options {
        config: Config::Str(yaml.to_owned()),
        cwd: Some(temp.path().to_string_lossy().to_string()),
        rt: Some(TokioRuntime::SingleThread),
        log_file: None,
        config_path: None,
    })
    .expect_err("missing DHCP interface must fail runtime startup");

    assert!(
        err.to_string().contains("__chimera_missing_interface__"),
        "unexpected error: {err}"
    );
    assert!(!clash_lib::shutdown());
}

#[test]
#[serial_test::serial]
fn invalid_fake_ip_ranges_fail_runtime_startup() {
    for (range, expected) in [
        ("2001:db8::/64", "IPv4 subnet"),
        ("198.18.0.0/31", "at least one allocatable address"),
    ] {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let yaml = format!(
            r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
mmdb: null
tun:
  enable: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: {range}
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 1.1.1.1
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
rules:
  - MATCH,DIRECT
"#
        );

        let err = clash_lib::start_scaffold(Options {
            config: Config::Str(yaml),
            cwd: Some(temp.path().to_string_lossy().to_string()),
            rt: Some(TokioRuntime::SingleThread),
            log_file: None,
            config_path: None,
        })
        .expect_err("invalid fake IP range must fail runtime startup");

        assert!(
            err.to_string().contains(expected),
            "unexpected error for {range}: {err}"
        );
        assert!(!clash_lib::shutdown());
    }
}

#[test]
fn full_dns_fixture_parses_expected_runtime_shape() {
    let yaml = include_str!("data/config/dns/full_dns.yaml");
    let dns = parse_dns(yaml);

    assert!(dns.enable);
    assert!(dns.ipv6);
    assert_eq!(dns.listen.udp.unwrap().to_string(), "127.0.0.1:0");
    assert_eq!(dns.listen.tcp.unwrap().to_string(), "127.0.0.1:0");
    assert_eq!(dns.nameserver.len(), 4);
    assert_eq!(dns.nameserver[0].net, DNSNetMode::Udp);
    assert_eq!(dns.nameserver[0].host.to_string(), "1.1.1.1");
    assert_eq!(dns.nameserver[0].port, 53);
    assert_eq!(dns.nameserver[1].net, DNSNetMode::Tcp);
    assert_eq!(dns.nameserver[1].port, 5353);
    assert_eq!(dns.nameserver[2].net, DNSNetMode::DoT);
    assert_eq!(dns.nameserver[2].port, 853);
    assert_eq!(dns.nameserver[3].net, DNSNetMode::DoH);
    assert_eq!(dns.nameserver[3].port, 443);
    assert_eq!(dns.nameserver[3].proxy.as_deref(), Some("DIRECT"));
    assert_eq!(dns.default_nameserver.len(), 2);
    assert_eq!(dns.proxy_server_nameserver.as_ref().unwrap().len(), 1);
    assert_eq!(dns.fallback.len(), 1);
    assert!(dns.nameserver_policy.contains_key("example.com"));
    assert_eq!(dns.fallback_filter.geo_ip_code, "CN");
    assert_eq!(dns.fallback_filter.ip_cidr.as_ref().unwrap().len(), 1);
    assert_eq!(dns.fake_ip_range.to_string(), "198.18.0.1/16");
    assert_eq!(dns.fake_ip_range6.unwrap().to_string(), "fd00:198:18::/96");
    assert_eq!(dns.fake_ip_filter, vec!["*.lan", "+.local"]);
    assert_eq!(
        dns.service_discovery_mode,
        clash_lib::config::def::DnsServiceDiscoveryMode::Legacy
    );
    assert_eq!(
        dns.edns_client_subnet.unwrap().ipv4.unwrap().to_string(),
        "1.2.3.0/24"
    );
}

#[test]
fn nameserver_policy_compound_selectors_fail_closed_at_yaml_conversion() {
    for enabled in [false, true] {
        for selector in [
            "example.com other.test",
            "geosite:private",
            "rule-set:private",
        ] {
            let yaml = base_config(&format!(
                "  enable: {enabled}\n  enhanced-mode: normal\n  nameserver: [1.1.1.1]\n  default-nameserver: [1.1.1.1]\n  nameserver-policy:\n    '{selector}': 192.0.2.53\n"
            ));
            let error = parse_error(yaml);
            assert!(
                error.to_string().contains("nameserver-policy"),
                "unsupported DNS selector {selector:?} must be rejected even with enable={enabled}: {error}"
            );
        }
    }
}

#[test]
fn nameserver_policy_comma_selectors_reach_internal_runtime() {
    let yaml = base_config(
        "  enable: true
  enhanced-mode: normal
  nameserver: [1.1.1.1]
  default-nameserver: [1.1.1.1]
  nameserver-policy:
    'EXAMPLE.com,other.test': 192.0.2.53
",
    );
    let dns = parse_dns(&yaml);
    assert_eq!(dns.nameserver_policy.len(), 2);
    assert!(dns.nameserver_policy.contains_key("example.com"));
    assert!(dns.nameserver_policy.contains_key("other.test"));
}

#[test]
fn fake_ip_ttl_is_applied_and_misspelling_is_rejected() {
    // The feature branch implements Mihomo's synthetic Fake-IP TTL.
    // Preserve the runtime value; reject a near-miss alias instead.
    for enabled in [true, false] {
        let yaml = base_config(&format!(
            "  enable: {enabled}\n  enhanced-mode: fake-ip\n  nameserver: [1.1.1.1]\n  default-nameserver: [1.1.1.1]\n  fake-ip-ttl: 42\n"
        ));
        let dns = parse_dns(&yaml);
        assert_eq!(dns.fake_ip_ttl, 42);
        let typo = base_config(&format!(
            "  enable: {enabled}\n  enhanced-mode: fake-ip\n  nameserver: [1.1.1.1]\n  default-nameserver: [1.1.1.1]\n  fake_ip_ttl: 42\n"
        ));
        let error = parse_error(typo).to_string();
        assert!(error.contains("fake_ip_ttl"), "{error}");
        assert!(!error.contains("42"), "{error}");
    }

    let existing = base_config(
        "  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [1.1.1.1]\n  default-nameserver: [1.1.1.1]\n  fake-ip-range: 198.18.0.1/16\n",
    );
    assert!(
        Config::Str(existing).try_parse().is_ok(),
        "supported legacy fake-ip-range must remain accepted"
    );
}

#[test]
fn unimplemented_mihomo_dns_privacy_controls_must_fail_closed() {
    for (field, value) in [
        ("fake_ip_filter_mode", "whitelist"),
        (
            "proxy_server_nameserver_policy",
            "{example.com: 192.0.2.53}",
        ),
        ("direct_nameserver_follow_policy", "true"),
        ("use-system-hosts", "true"),
        ("fallback-lazy-query", "true"),
        ("use_system_hosts", "true"),
        ("fallback_lazy_query", "true"),
    ] {
        for enabled in [true, false] {
            let yaml = base_config(&format!(
                "  enable: {enabled}\n  nameserver: [1.1.1.1]\n  default-nameserver: [1.1.1.1]\n  {field}: {value}\n"
            ));
            let error = parse_error(yaml);
            assert!(
                error.to_string().contains(field),
                "explicit {field} must be rejected even with enable={enabled}: {error}"
            );
            assert!(
                !error.to_string().contains("192.0.2.53")
                    && !error.to_string().contains("whitelist"),
                "privacy field error must not print a configured value"
            );
        }
    }

    // Validation must happen after expanding YAML merge keys.
    let merged = format!(
        "x-dns-privacy: &privacy\n  use-system-hosts: true\n{}",
        base_config(
            "  <<: *privacy\n  enable: false\n  nameserver: [1.1.1.1]\n  default-nameserver: [1.1.1.1]\n"
        )
    );
    assert!(
        parse_error(merged).to_string().contains("use-system-hosts"),
        "merged unsupported privacy controls must be rejected"
    );

    let unrelated_vendor_setting = base_config(
        "  enable: false\n  nameserver: [1.1.1.1]\n  default-nameserver: [1.1.1.1]\n  unrelated-vendor-extension: true\n",
    );
    assert!(
        Config::Str(unrelated_vendor_setting).try_parse().is_ok(),
        "privacy validation must not break unrelated legacy/vendor YAML"
    );
}

#[test]
fn service_discovery_safe_mode_is_opt_in_and_parsed() {
    let dns = parse_dns(&base_config(
        r#"  enable: true
  enhanced-mode: fake-ip
  service-discovery-mode: safe
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 1.1.1.1
"#,
    ));

    assert_eq!(
        dns.service_discovery_mode,
        clash_lib::config::def::DnsServiceDiscoveryMode::Safe
    );
}

#[test]
fn fake_ip_range6_rejects_ipv4_prefix() {
    let yaml = base_config(
        r#"
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range6: 198.18.0.0/16
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 1.1.1.1
"#,
    );

    let error = parse_error(yaml);
    assert!(
        error
            .to_string()
            .contains("fake-ip-range6 must be an IPv6 subnet")
    );
}

#[test]
fn dns_enabled_requires_at_least_one_nameserver() {
    let yaml = base_config(
        r#"
  enable: true
  default-nameserver:
    - 223.5.5.5
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string()
            .contains("dns enabled, no nameserver specified"),
        "unexpected error: {err}"
    );
}

#[test]
fn dns_enabled_rejects_only_skipped_nameserver_entries() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - system
  default-nameserver:
    - 223.5.5.5
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("no usable nameserver"),
        "unexpected error: {err}"
    );
}

#[test]
fn default_nameserver_rejects_only_skipped_entries() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - system
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("no usable entries"),
        "unexpected error: {err}"
    );
}

#[test]
fn proxy_server_nameserver_cannot_fall_back_when_all_entries_are_skipped() {
    let yaml = base_config(
        r#"
  enable: true
  respect-rules: true
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 223.5.5.5
  proxy-server-nameserver:
    - system
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("proxy-server-nameserver")
            && err.to_string().contains("no usable entries"),
        "proxy bootstrap must not quietly revert to main DNS: {err}"
    );
}

#[test]
fn fake_ip_tun_proxy_bootstrap_rejects_proxy_routing_and_dhcp() {
    // Mihomo's ProxyServerNameserver uses parseNameServer(..., respectRules=false).
    // A proxy-selected bootstrap could recursively require the very node it resolves.
    // DHCP discovers a service-scoped resolver, outside the TUN DNS hijack contract.
    for (upstream, reason) in [
        ("'udp://9.9.9.9#proxy=PROXY'", "#proxy"),
        ("'dhcp://en0'", "DHCP"),
    ] {
        let yaml = base_config(&format!(
            "  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [1.1.1.1]\n  default-nameserver: [223.5.5.5]\n  proxy-server-nameserver: [{upstream}]\n"
        ))
        .replacen("dns:\n", "tun:\n  enable: true\ndns:\n", 1).replacen("ipv6: true\n", "ipv6: false\n", 1);
        let error = parse_error(yaml).to_string();
        assert!(
            error.contains("proxy-server-nameserver") && error.contains(reason),
            "{upstream} must fail closed: {error}"
        );
    }
}

#[test]
fn fake_ip_tun_node_policy_rejects_dhcp_service_scoped_resolver() {
    let yaml = base_config(
        "  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [1.1.1.1]\n  default-nameserver: [223.5.5.5]\n  proxy-server-nameserver: [9.9.9.9]\n  proxy-server-nameserver-policy:\n    'node.example': 'dhcp://en0'\n"
    ).replacen("dns:\n", "tun:\n  enable: true\ndns:\n", 1).replacen("ipv6: true\n", "ipv6: false\n", 1);
    let error = parse_error(yaml).to_string();
    assert!(
        error.contains("proxy-server-nameserver-policy") && error.contains("DHCP"),
        "{error}"
    );
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[test]
fn macos_fake_ip_tun_rejects_dhcp_in_all_dns_egress_pools() {
    // ref-mihomo parses dhcp://, but Chimera's DHCP discovery sends a
    // physical-interface request and does not guarantee service-scoped DNS
    // egress through the TUN. Until runtime capture proves isolation, refuse
    // to accept these upstreams in macOS TUN + Fake-IP.
    for (scope, body) in [
        ("nameserver", "  nameserver: ['dhcp://en0']\n"),
        (
            "fallback",
            "  nameserver: [1.1.1.1]\n  fallback: ['dhcp://en0']\n",
        ),
        (
            "direct-nameserver",
            "  nameserver: [1.1.1.1]\n  direct-nameserver: ['dhcp://en0']\n",
        ),
        (
            "nameserver-policy",
            "  nameserver: [1.1.1.1]\n  nameserver-policy:\n    'internal.example': 'dhcp://en0'\n",
        ),
    ] {
        let yaml = base_config(&format!(
            "  enable: true\n  enhanced-mode: fake-ip\n  default-nameserver: [223.5.5.5]\n{body}"
        ))
        .replacen("dns:\n", "tun:\n  enable: true\ndns:\n", 1).replacen("ipv6: true\n", "ipv6: false\n", 1);
        let error = parse_error(yaml).to_string();
        assert!(
            error.contains(&format!("dns.{scope}")) && error.contains("DHCP"),
            "{scope} must not silently discover service-scoped DNS: {error}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_non_tun_dhcp_nameserver_remains_compatible() {
    // Deliberately retain all legacy DHCP-upstream forms outside the narrow
    // high-privacy TUN + Fake-IP mode, without actually probing DHCP.
    for (scope, body) in [
        ("nameserver", "  nameserver: ['dhcp://en0']\n"),
        (
            "fallback",
            "  nameserver: [1.1.1.1]\n  fallback: ['dhcp://en0']\n",
        ),
        (
            "direct-nameserver",
            "  nameserver: [1.1.1.1]\n  direct-nameserver: ['dhcp://en0']\n",
        ),
        (
            "nameserver-policy",
            "  nameserver: [1.1.1.1]\n  nameserver-policy:\n    'internal.example': 'dhcp://en0'\n",
        ),
    ] {
        let yaml = base_config(&format!(
            "  enable: true\n  enhanced-mode: fake-ip\n  default-nameserver: [223.5.5.5]\n{body}"
        ));
        let dns = parse_dns(&yaml);
        let net = match scope {
            "nameserver" => &dns.nameserver[0].net,
            "fallback" => &dns.fallback[0].net,
            "direct-nameserver" => &dns.direct_nameserver.as_ref().unwrap()[0].net,
            "nameserver-policy" => &dns.nameserver_policy["internal.example"].net,
            _ => unreachable!(),
        };
        assert_eq!(*net, DNSNetMode::Dhcp, "legacy {scope} must still parse");
    }
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[test]
fn macos_tun_normal_dns_mode_keeps_dhcp_legacy_compatibility() {
    let yaml = base_config(
        "  enable: true\n  enhanced-mode: normal\n  nameserver: ['dhcp://en0']\n  default-nameserver: [223.5.5.5]\n",
    )
    .replacen("dns:\n", "tun:\n  enable: true\ndns:\n", 1).replacen("ipv6: true\n", "ipv6: false\n", 1);
    let dns = parse_dns(&yaml);
    assert_eq!(dns.nameserver[0].net, DNSNetMode::Dhcp);
}

#[test]
fn non_tun_proxy_bootstrap_preserves_legacy_proxy_modifier() {
    let dns = parse_dns(&base_config(
        "  enable: true\n  nameserver: [1.1.1.1]\n  default-nameserver: [223.5.5.5]\n  proxy-server-nameserver: ['udp://9.9.9.9#proxy=PROXY']\n",
    ));
    assert_eq!(
        dns.proxy_server_nameserver.unwrap()[0].proxy.as_deref(),
        Some("PROXY")
    );
}

#[test]
fn mihomo_proxy_server_nameserver_policy_preserves_scalar_and_multiple_upstreams() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
  proxy-server-nameserver: [8.8.8.8]
  proxy-server-nameserver-policy:
    "Node-A.Example": "tls://9.9.9.9:853"
    "node-b.example": ["1.1.1.1", "1.0.0.1"]
"#,
    );
    let dns = parse_dns(&yaml);
    assert_eq!(
        dns.proxy_server_nameserver_policy.len(),
        2,
        "per-node policy should be built, not silently ignored",
    );
    let entries = &dns.proxy_server_nameserver_policy;
    assert_eq!(entries[0].0, "node-a.example");
    assert_eq!(entries[0].1.len(), 1);
    assert_eq!(entries[1].0, "node-b.example");
    assert_eq!(entries[1].1.len(), 2);
}

#[test]
fn mihomo_proxy_server_policy_requires_dedicated_bootstrap_nameservers() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
  proxy-server-nameserver-policy:
    "node-a.example": "9.9.9.9"
"#,
    );
    let error = parse_error(yaml).to_string();
    assert!(
        error.contains("proxy-server-nameserver"),
        "per-node policy without a dedicated default cannot use main DNS: {error}"
    );
}

#[test]
fn mihomo_unsupported_proxy_server_policy_sources_are_rejected() {
    for domain in ["geosite:gfw", "rule-set:proxy-nodes"] {
        let yaml = base_config(&format!(
            "  enable: true\n  nameserver: [1.1.1.1]\n  proxy-server-nameserver: [8.8.8.8]\n  proxy-server-nameserver-policy:\n    '{domain}': 9.9.9.9\n"
        ));
        let error = parse_error(yaml).to_string();
        assert!(
            error.contains("proxy-server-nameserver-policy"),
            "unsupported selector must be explicitly rejected: {error}"
        );
    }
}

#[test]
fn mihomo_proxy_server_policy_rejects_whitespace_and_malformed_wildcards() {
    for selector in [
        " node.example",
        "node.example ",
        "node.example, second.example",
        "node.example other.example",
        "partial*.node.example",
        "node.+.example",
    ] {
        let yaml = base_config(&format!(
            "  enable: true\n  nameserver: [1.1.1.1]\n  proxy-server-nameserver: [8.8.8.8]\n  proxy-server-nameserver-policy:\n    '{selector}': 9.9.9.9\n"
        ));
        let error = parse_error(yaml).to_string();
        assert!(
            error.contains("proxy-server-nameserver-policy"),
            "selector {selector:?} was not explicitly rejected: {error}"
        );
    }
}

#[test]
fn mihomo_proxy_server_policy_expands_comma_separated_domains_in_order() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  proxy-server-nameserver: [8.8.8.8]
  proxy-server-nameserver-policy:
    "node-a.example,node-b.example": ["9.9.9.9", "149.112.112.112"]
    "node-c.example": "1.0.0.1"
"#,
    );
    let policies = parse_dns(&yaml).proxy_server_nameserver_policy;
    let names: Vec<&str> =
        policies.iter().map(|(domain, _)| domain.as_str()).collect();
    assert_eq!(
        names,
        ["node-a.example", "node-b.example", "node-c.example"]
    );
    assert_eq!(policies[0].1.len(), 2);
    assert_eq!(policies[1].1.len(), 2);
}

#[test]
fn mihomo_proxy_server_policy_never_silently_skips_system_upstream() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  proxy-server-nameserver: [8.8.8.8]
  proxy-server-nameserver-policy:
    "proxy.example": ["system", "9.9.9.9"]
"#,
    );
    let error = parse_error(yaml).to_string();
    assert!(
        error.contains("proxy-server-nameserver-policy") && error.contains("system"),
        "system upstream is not implemented and must not be silently dropped: {error}"
    );
}

#[test]
fn mihomo_proxy_server_policy_rejects_explicit_outbound_modifier_until_routable() {
    // The dedicated node bootstrap client registry currently contains no
    // user proxy handlers, so an accepted #proxy= reference could not honor
    // Mihomo's explicit outbound selection semantics.
    let yaml = base_config(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  proxy-server-nameserver: [8.8.8.8]
  proxy-server-nameserver-policy:
    "proxy.example": "tls://9.9.9.9:853#proxy=PROXY"
"#,
    );
    let error = parse_error(yaml).to_string();
    assert!(
        error.contains("proxy-server-nameserver-policy") && error.contains("#proxy"),
        "unimplemented explicit DNS dialer must not be silently accepted: {error}"
    );
}

#[test]
fn mihomo_direct_nameserver_follow_policy_parses_explicit_values() {
    let body = r#"
  enable: true
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
  direct-nameserver: [192.0.2.53]
  nameserver-policy:
    "protected.example": 9.9.9.9
"#;
    let without_flag = parse_dns(&base_config(body));
    assert!(!without_flag.direct_nameserver_follow_policy);
    assert_eq!(without_flag.nameserver_policy.len(), 1);
    assert_eq!(
        without_flag.direct_nameserver.as_ref().unwrap()[0]
            .host
            .to_string(),
        "192.0.2.53"
    );

    for (value, expected) in [("true", true), ("false", false)] {
        let yaml = base_config(&format!(
            "{body}  direct-nameserver-follow-policy: {value}\n"
        ));
        let parsed = parse_dns(&yaml);
        assert_eq!(parsed.direct_nameserver_follow_policy, expected);
        assert_eq!(parsed.nameserver_policy.len(), 1);
    }
}

#[test]
fn mihomo_respect_rules_requires_dedicated_proxy_bootstrap() {
    let bad = base_config(
        "  enable: true\n  nameserver: ['udp://1.1.1.1#proxy=PROXY']\n  respect-rules: true\n",
    );
    let error = parse_error(bad).to_string();
    assert!(
        error.contains("dns.respect-rules")
            && error.contains("proxy-server-nameserver"),
        "{error}"
    );

    let good = base_config(
        "  enable: true\n  nameserver: ['udp://1.1.1.1#proxy=PROXY']\n  respect-rules: true\n  proxy-server-nameserver: [9.9.9.9]\n",
    );
    let dns = parse_dns(&good);
    assert!(dns.respect_rules);
    assert_eq!(dns.nameserver[0].proxy.as_deref(), Some("PROXY"));
    assert_eq!(dns.proxy_server_nameserver.as_ref().unwrap().len(), 1);
}

#[test]
fn dns_listener_privacy_typos_fail_before_any_listener_is_started() {
    for (detail, body) in [
        ("listen.tpc", "  listen:\n    tpc: 127.0.0.1:5353\n"),
        (
            "listen.doh.ca-kye",
            "  listen:\n    doh:\n      addr: 127.0.0.1:5353\n      ca-kye: secret.example\n",
        ),
    ] {
        let yaml =
            base_config(&format!("  enable: true\n  nameserver: [1.1.1.1]\n{body}"));
        let error = parse_error(yaml).to_string();
        assert!(
            error.contains(&format!("dns.{detail}")) && error.contains("unknown"),
            "invalid listener {detail} must abort startup: {error}"
        );
        assert!(!error.contains("secret.example"), "{error}");
    }
}

#[test]
fn tun_fake_ip_privacy_field_typos_fail_before_runtime() {
    for (section, field, value) in [
        ("dns", "nameserver-polcy", "secret.example"),
        ("dns", "fake-ip-filtre-mode", "whitelist"),
        ("tun", "dns-hijak", "true"),
        ("tun", "strict-rout", "true"),
    ] {
        let dns_extension = if section == "dns" {
            format!("  {field}: {value}\n")
        } else {
            String::new()
        };
        let tun_extension = if section == "tun" {
            format!("  {field}: {value}\n")
        } else {
            String::new()
        };
        let yaml = format!(
            "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [1.1.1.1]\n{dns_extension}tun:\n  enable: false\n{tun_extension}"
        );
        let error = parse_error(yaml).to_string();
        assert!(
            error.contains(&format!("{section}.{field}"))
                && error.contains("unknown"),
            "privacy typo must stop runtime before DNS starts: {error}"
        );
        assert!(
            !error.contains("secret.example"),
            "DNS policy value must not appear in diagnostic"
        );
    }
}

#[test]
fn mihomo_nameserver_policy_rejects_unsafe_whitespace_and_wildcards() {
    for selector in [
        " example.com",
        "example.com ",
        "one.example, two.example",
        "example.com bad.test",
        "prefix*.example.com",
        "example.+.com",
    ] {
        let yaml = base_config(&format!(
            "  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n    '{selector}': 9.9.9.9\n"
        ));
        let error = parse_error(yaml).to_string();
        assert!(
            error.contains("nameserver-policy"),
            "selector {selector:?} was not explicitly rejected: {error}"
        );
    }
}

#[test]
fn mihomo_nameserver_policy_multiple_domains_split_without_silent_literal_match() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy:
    "one.example,two.example": 9.9.9.9
    "*.other.example": 149.112.112.112
"#,
    );
    let dns = parse_dns(&yaml);
    assert_eq!(dns.nameserver_policy.len(), 3);
    assert!(dns.nameserver_policy.contains_key("one.example"));
    assert!(dns.nameserver_policy.contains_key("two.example"));
    assert!(dns.nameserver_policy.contains_key("*.other.example"));
    assert!(
        !dns.nameserver_policy
            .contains_key("one.example,two.example")
    );
}

#[test]
fn mihomo_nameserver_policy_rejects_unsupported_geosite_and_ruleset_selectors() {
    for domain in [
        "geosite:gfw",
        "GEOSITE:private",
        "rule-set:protected",
        "example.com,rule-set:protected",
    ] {
        let yaml = base_config(&format!(
            "  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n    '{domain}': 9.9.9.9\n"
        ));
        let error = parse_error(yaml).to_string();
        assert!(
            error.contains("nameserver-policy") && error.contains(domain),
            "unsupported Mihomo policy selectors must not be literal domain matches: {error}",
        );
    }
}

#[test]
fn mihomo_nameserver_policy_rejects_case_insensitive_duplicate_selectors() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy:
    "Primary.Example,secondary.example": 9.9.9.9
    "primary.example": 149.112.112.112
"#,
    );
    let error = parse_error(yaml).to_string();
    assert!(
        error.contains("nameserver-policy") && error.contains("repeats domain"),
        "ambiguous overlapping policy keys must not have HashMap-dependent precedence: {error}"
    );
}

#[test]
fn mihomo_fake_ip_ttl_defaults_to_one_and_clamps_nonpositive_values() {
    let base = r#"
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
"#;
    assert_eq!(parse_dns(&base_config(base)).fake_ip_ttl, 1);
    for (raw, expected) in [("0", 1), ("-17", 1), ("45", 45)] {
        let yaml = base_config(&format!("{base}  fake-ip-ttl: {raw}\n"));
        assert_eq!(parse_dns(&yaml).fake_ip_ttl, expected, "{raw}");
    }
}

#[test]
fn invalid_hosts_entry_is_rejected() {
    let yaml = base_config(
        r#"
  enable: true
  use-hosts: true
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 223.5.5.5
"#,
    )
    .replace("dns:\n", "hosts:\n  invalid.example: not-an-ip\ndns:\n");

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("invalid hosts entry"),
        "unexpected error: {err}"
    );
}

#[test]
fn invalid_fallback_cidr_is_rejected() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 223.5.5.5
  fallback-filter:
    ipcidr:
      - not-a-cidr
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string()
            .contains("invalid DNS fallback-filter ipcidr"),
        "unexpected error: {err}"
    );
}

#[test]
fn enabled_redir_host_mode_is_rejected_as_unimplemented() {
    let yaml = base_config(
        r#"
  enable: true
  enhanced-mode: redir-host
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 223.5.5.5
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("redir-host is not implemented"),
        "unexpected error: {err}"
    );
}

#[test]
fn encrypted_dns_listeners_require_certificate_pairs() {
    for protocol in ["doh", "dot", "doh3"] {
        let listener =
            format!("  listen:\n    {protocol}:\n      addr: 127.0.0.1:8443\n");
        let listener_without_certificate = base_config(&format!(
            "\n  enable: true\n  nameserver:\n    - 1.1.1.1\n  default-nameserver:\n    - 223.5.5.5\n{listener}"
        ));
        let err = parse_error(listener_without_certificate);
        assert!(
            err.to_string().contains("requires both ca-cert and ca-key"),
            "unexpected error for {protocol}: {err}"
        );

        for field in ["ca-cert: server.crt", "ca-key: server.key"] {
            let listener = format!("{listener}      {field}\n");
            let yaml = base_config(&format!(
                "\n  enable: true\n  nameserver:\n    - 1.1.1.1\n  default-nameserver:\n    - 223.5.5.5\n{listener}"
            ));
            let err = parse_error(yaml);
            assert!(
                err.to_string().contains("requires both ca-cert and ca-key"),
                "unexpected error for {protocol}: {err}"
            );
        }

        let listener = format!(
            "{listener}      ca-cert: server.crt\n      ca-key: server.key\n"
        );
        parse_dns(&base_config(&format!(
            "\n  enable: true\n  nameserver:\n    - 1.1.1.1\n  default-nameserver:\n    - 223.5.5.5\n{listener}"
        )));
    }
}

#[test]
fn default_nameserver_must_be_ip_address() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - dns.google
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("default dns must be ip address"),
        "unexpected error: {err}"
    );
}

#[test]
fn unsupported_nameserver_scheme_is_rejected() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - quic://1.1.1.1
  default-nameserver:
    - 223.5.5.5
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("unsupported scheme"),
        "unexpected error: {err}"
    );
}

#[test]
fn edns_client_subnet_requires_at_least_one_family() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 223.5.5.5
  edns-client-subnet: {}
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string()
            .contains("edns-client-subnet requires at least one"),
        "unexpected error: {err}"
    );
}
