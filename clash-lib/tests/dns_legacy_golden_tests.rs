//! S00 golden fixtures: observable legacy DNS configuration contract.
//! These tests deliberately avoid new policy-rules/resolver-profiles and
//! external DNS/network access. Keep expected values stable when adding S01.

use clash_lib::{
    Config,
    app::dns::{Config as DnsConfig, config::DNSNetMode},
};

fn yaml_with_dns(body: &str, global_ipv6: bool) -> String {
    format!(
        r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: {global_ipv6}
dns:
{body}
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
rules:
  - GEOIP,CN,DIRECT,no-resolve
  - DOMAIN-SUFFIX,example.com,DIRECT
  - MATCH,DIRECT
"#
    )
}

fn load(body: &str, global_ipv6: bool) -> DnsConfig {
    Config::Str(yaml_with_dns(body, global_ipv6))
        .try_parse()
        .expect("legacy DNS fixture must remain accepted")
        .dns
}

fn error(body: &str) -> String {
    match Config::Str(yaml_with_dns(body, false)).try_parse() {
        Ok(_) => panic!("legacy invalid fixture must be rejected"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn s00_dns_disabled_remains_disabled_without_upstream() {
    let dns = load("  enable: false\n", false);
    assert!(!dns.enable);
    assert!(!dns.ipv6);
    assert!(dns.nameserver.is_empty());
    assert!(dns.proxy_server_nameserver.is_none());
    assert!(dns.direct_nameserver.is_none());
    assert!(!dns.respect_rules);
}

#[test]
fn s00_legacy_normal_nameserver_order_protocol_port_and_listeners() {
    let dns = load(
        r#"
  enable: true
  enhanced-mode: normal
  ipv6: false
  listen:
    udp: 127.0.0.1:0
    tcp: 127.0.0.1:0
  nameserver:
    - 1.1.1.1
    - tcp://8.8.8.8:5353
  default-nameserver:
    - 223.5.5.5
"#,
        true,
    );
    assert!(dns.enable);
    assert!(!dns.ipv6);
    assert_eq!(format!("{:?}", dns.enhance_mode), "Normal");
    assert!(dns.listen.udp.is_some());
    assert!(dns.listen.tcp.is_some());
    assert_eq!(dns.nameserver.len(), 2);
    assert_eq!(dns.nameserver[0].net, DNSNetMode::Udp);
    assert_eq!(dns.nameserver[0].host.to_string(), "1.1.1.1");
    assert_eq!(dns.nameserver[0].port, 53);
    assert_eq!(dns.nameserver[1].net, DNSNetMode::Tcp);
    assert_eq!(dns.nameserver[1].host.to_string(), "8.8.8.8");
    assert_eq!(dns.nameserver[1].port, 5353);
    assert_eq!(dns.default_nameserver.len(), 1);
}

#[test]
fn s00_ipv6_requires_global_and_dns_flags() {
    let body = r#"
  enable: true
  ipv6: true
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
"#;
    assert!(!load(body, false).ipv6);
    assert!(load(body, true).ipv6);
}

#[test]
fn s00_fake_ip_filter_and_range_remain_legacy_values() {
    let dns = load(
        r#"
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
  fake-ip-range: 198.18.0.0/16
  fake-ip-filter:
    - "*.lan"
    - "+.corp.internal"
"#,
        false,
    );
    assert_eq!(format!("{:?}", dns.enhance_mode), "FakeIp");
    assert_eq!(dns.fake_ip_range.to_string(), "198.18.0.0/16");
    assert_eq!(dns.fake_ip_filter, ["*.lan", "+.corp.internal"]);
    // Fake-IP v6 config parsing is *not* proof of a working v6 dataplane.
    assert!(dns.fake_ip_range6.is_none());
}

#[test]
fn s00_nameserver_policy_single_string_keeps_original_server() {
    let dns = load(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
  nameserver-policy:
    "+.corp.internal": "tcp://192.0.2.53:1053"
"#,
        false,
    );
    assert_eq!(dns.nameserver_policy.len(), 1);
    let server = &dns.nameserver_policy["+.corp.internal"];
    assert_eq!(server.net, DNSNetMode::Tcp);
    assert_eq!(server.host.to_string(), "192.0.2.53");
    assert_eq!(server.port, 1053);
}

#[test]
fn s00_fallback_filter_keeps_geoip_cidr_and_domain_values() {
    let dns = load(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  fallback: [9.9.9.9]
  default-nameserver: [223.5.5.5]
  fallback-filter:
    geoip: true
    geoip-code: cn
    ipcidr: [240.0.0.0/4]
    domain: ["+.example.com"]
"#,
        false,
    );
    assert_eq!(dns.fallback.len(), 1);
    assert_eq!(dns.fallback[0].host.to_string(), "9.9.9.9");
    assert!(dns.fallback_filter.geo_ip);
    assert_eq!(dns.fallback_filter.geo_ip_code, "CN");
    assert_eq!(
        dns.fallback_filter.ip_cidr.as_ref().unwrap()[0].to_string(),
        "240.0.0.0/4"
    );
    assert_eq!(dns.fallback_filter.domain, ["+.example.com"]);
}

#[test]
fn s00_proxy_and_direct_nameservers_remain_distinct() {
    let dns = load(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
  proxy-server-nameserver: [9.9.9.9]
  direct-nameserver: [192.0.2.53]
"#,
        false,
    );
    assert_eq!(dns.nameserver[0].host.to_string(), "1.1.1.1");
    assert_eq!(
        dns.proxy_server_nameserver.as_ref().unwrap()[0]
            .host
            .to_string(),
        "9.9.9.9"
    );
    assert_eq!(
        dns.direct_nameserver.as_ref().unwrap()[0].host.to_string(),
        "192.0.2.53"
    );
}

#[test]
fn s00_respect_rules_and_legacy_proxy_modifier_are_preserved() {
    let dns = load(
        r#"
  enable: true
  nameserver: ["udp://1.1.1.1#proxy=PROXY"]
  default-nameserver: [223.5.5.5]
  respect-rules: true
"#,
        false,
    );
    assert!(dns.respect_rules);
    assert_eq!(dns.nameserver[0].proxy.as_deref(), Some("PROXY"));
}

#[test]
fn s00_legacy_invalid_values_remain_explicit_errors() {
    for (body, expected) in [
        ("  enable: true\n", "no nameserver"),
        (
            "  enable: true\n  nameserver: [system]\n",
            "no usable nameserver",
        ),
        (
            "  enable: true\n  nameserver: [1.1.1.1]\n  enhanced-mode: redir-host\n",
            "redir-host is not implemented",
        ),
        (
            "  enable: true\n  nameserver: [1.1.1.1]\n  default-nameserver: [dns.example]\n",
            "default dns must be ip address",
        ),
    ] {
        assert!(
            error(body).contains(expected),
            "{expected} expected for {body}"
        );
    }
}

#[test]
fn s00_business_rule_order_and_no_resolve_options_are_preserved() {
    use clash_lib::config::internal::rule::RuleType;

    let input = yaml_with_dns(
        "  enable: true\n  nameserver: [1.1.1.1]\n  default-nameserver: [223.5.5.5]\n",
        false,
    );
    let config = Config::Str(input)
        .try_parse()
        .expect("legacy ordered rules are valid");
    assert_eq!(config.rules.len(), 3);
    match &config.rules[0] {
        RuleType::GeoIP {
            country_code,
            target,
            no_resolve,
        } => {
            assert_eq!(country_code, "CN");
            assert_eq!(target, "DIRECT");
            assert!(*no_resolve);
        }
        _ => panic!("GEOIP no-resolve must stay first"),
    }
    match &config.rules[1] {
        RuleType::DomainSuffix {
            domain_suffix,
            target,
        } => {
            assert_eq!(domain_suffix, "example.com");
            assert_eq!(target, "DIRECT");
        }
        _ => panic!("DOMAIN-SUFFIX must stay second"),
    }
    assert!(
        matches!(&config.rules[2], RuleType::Match { target } if target == "DIRECT")
    );
}

#[test]
fn s00_old_nameserver_policy_does_not_accept_new_array_syntax() {
    let result = error(
        r#"
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy:
    example.com: [1.1.1.1, 8.8.8.8]
"#,
    );
    assert!(
        result.contains("invalid type") || result.contains("expected a string"),
        "unexpected error for legacy single-string policy: {result}"
    );
}
