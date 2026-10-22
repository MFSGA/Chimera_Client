//! S01 compile-only DNS policy acceptance and rejection tests.
//! These tests parse YAML but never create a DNS transport or select an
//! actual outbound. Business Rules must remain in their original order.
use clash_lib::{
    Config,
    app::dns::policy::{DnsEgress, DnsFailure},
};
use hickory_proto::rr::RecordType;

fn fixture(dns_fields: &str, business_rules: &str) -> String {
    format!(
        r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
{dns_fields}
profile:
  store-selected: false
  store-fake-ip: false
proxies:
  - name: DNS-OUT
    type: socks5
    server: 192.0.2.9
    port: 1080
rules:
{business_rules}
"#
    )
}
const BUSINESS_RULES: &str = "  - GEOIP,CN,DIRECT,no-resolve\n  - DOMAIN-SUFFIX,example.com,DNS-OUT\n  - MATCH,DIRECT\n";

fn compile(yaml: &str) -> clash_lib::config::internal::config::Config {
    Config::Str(yaml.into())
        .try_parse()
        .expect("S01 valid fixture must parse")
}

fn fail(yaml: &str) -> String {
    match Config::Str(yaml.into()).try_parse() {
        Ok(_) => panic!("invalid S01 fixture must be rejected"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn s01_absent_new_fields_still_compile_legacy_dns_unchanged() {
    let cfg = compile(&fixture("", BUSINESS_RULES));
    assert!(cfg.dns.compiled_policy.rules.is_empty());
    assert!(cfg.dns.compiled_policy.profiles.is_empty());
    assert_eq!(cfg.dns.nameserver[0].host.to_string(), "1.1.1.1");
    assert_eq!(cfg.rules.len(), 3);
    assert_eq!(cfg.rules[0].target(), "DIRECT");
    assert_eq!(cfg.rules[1].target(), "DNS-OUT");
    assert_eq!(cfg.rules[2].target(), "DIRECT");
}

#[test]
fn s01_policy_qtype_and_ordinal_are_independent_of_business_rule_order() {
    let cfg = compile(&fixture(
        r#"
  resolver-profiles:
    trusted:
      servers: ["https://cloudflare-dns.com/dns-query"]
    local:
      servers: ["192.0.2.53"]
  policy-rules:
    - match: {domain: video.example, qtype: A}
      action: {resolver: trusted, egress: "proxy:DNS-OUT", on-failure: fail}
    - match: {domain: video.example, qtype: [AAAA]}
      action: {resolver: local, egress: direct}
    - match: {domain: _minecraft._tcp.play.example, qtype: SRV}
      action: {resolver: trusted, on-failure: fail}
"#,
        BUSINESS_RULES,
    ));
    let policy = &cfg.dns.compiled_policy;
    assert_eq!(policy.rules.len(), 3);
    assert_eq!(policy.profiles.len(), 2);
    let a = policy.match_query("VIDEO.EXAMPLE.", RecordType::A).unwrap();
    assert_eq!(a.ordinal, 0);
    assert_eq!(a.action.resolver.as_deref(), Some("trusted"));
    assert_eq!(a.action.egress, Some(DnsEgress::Proxy("DNS-OUT".into())));
    assert_eq!(a.action.on_failure, Some(DnsFailure::Fail));
    let aaaa = policy
        .match_query("video.example", RecordType::AAAA)
        .unwrap();
    assert_eq!(aaaa.ordinal, 1);
    assert_eq!(aaaa.action.egress, Some(DnsEgress::Direct));
    assert!(
        aaaa.action.on_failure.is_none(),
        "unprovided action fields must inherit legacy"
    );
    assert_eq!(
        policy
            .match_query("_minecraft._tcp.play.example.", RecordType::SRV)
            .unwrap()
            .ordinal,
        2
    );
    assert!(
        policy
            .match_query("video.example.", RecordType::TXT)
            .is_none()
    );
    assert_eq!(cfg.rules[0].target(), "DIRECT");
    assert_eq!(cfg.rules[1].target(), "DNS-OUT");
}

#[test]
fn s01_first_matching_rule_beats_more_specific_later_rule() {
    let suffix_first = fixture(
        r#"
  policy-rules:
    - match: {domain-suffix: example.com}
      action: {on-failure: fail}
    - match: {domain: node.example.com}
      action: {egress: direct}
"#,
        BUSINESS_RULES,
    );
    let exact_first = fixture(
        r#"
  policy-rules:
    - match: {domain: node.example.com}
      action: {egress: direct}
    - match: {domain-suffix: example.com}
      action: {on-failure: fail}
"#,
        BUSINESS_RULES,
    );
    for (yaml, expected_direct) in [(suffix_first, false), (exact_first, true)] {
        let config = compile(&yaml);
        let selected = config
            .dns
            .compiled_policy
            .match_query("Node.Example.Com.", RecordType::A)
            .unwrap();
        assert_eq!(selected.ordinal, 0);
        assert_eq!(
            selected.action.egress,
            expected_direct.then_some(DnsEgress::Direct)
        );
        assert_eq!(
            config.rules.len(),
            3,
            "Business Rules ordering must be untouched"
        );
    }
}

#[test]
fn s01_suffix_requires_label_boundary_and_matches_apex() {
    let policy = compile(&fixture(
        "  policy-rules:\n    - match: {domain-suffix: example.com}\n      action: {on-failure: fail}\n",
        BUSINESS_RULES,
    ));
    let p = &policy.dns.compiled_policy;
    assert!(p.match_query("example.com", RecordType::HTTPS).is_some());
    assert!(p.match_query("child.example.com.", RecordType::A).is_some());
    assert!(p.match_query("notexample.com", RecordType::A).is_none());
    assert!(p.match_query("example.com.evil", RecordType::A).is_none());
}

#[test]
fn s01_numeric_record_types_and_case_normalization() {
    let cfg = compile(&fixture(
        "  policy-rules:\n    - match: {domain: MiXeD.Example, qtype: [type65400, https, SVCB]}\n      action: {on-failure: fail}\n",
        BUSINESS_RULES,
    ));
    let p = &cfg.dns.compiled_policy;
    assert!(
        p.match_query("mixed.example.", RecordType::Unknown(65400))
            .is_some()
    );
    assert!(p.match_query("mixed.example", RecordType::HTTPS).is_some());
    assert!(p.match_query("mixed.example", RecordType::SVCB).is_some());
    assert!(p.match_query("mixed.example", RecordType::A).is_none());
}

#[test]
fn s01_domain_normalization_accepts_idna_and_srv_labels() {
    let cfg = compile(&fixture(
        "  policy-rules:\n    - match: {domain: bücher.example, qtype: SRV}\n      action: {on-failure: fail}\n",
        BUSINESS_RULES,
    ));
    assert!(
        cfg.dns
            .compiled_policy
            .match_query("xn--bcher-kva.example.", RecordType::SRV)
            .is_some()
    );
}

#[test]
fn s01_qtype_only_rule_is_allowed_but_empty_match_is_rejected() {
    let cfg = compile(&fixture(
        "  policy-rules:\n    - match: {qtype: SRV}\n      action: {on-failure: fail}\n",
        BUSINESS_RULES,
    ));
    assert_eq!(
        cfg.dns
            .compiled_policy
            .match_query("anything.test", RecordType::SRV)
            .unwrap()
            .ordinal,
        0
    );
    assert!(
        cfg.dns
            .compiled_policy
            .match_query("anything.test", RecordType::A)
            .is_none()
    );
    let err = fail(&fixture(
        "  policy-rules:\n    - match: {}\n      action: {on-failure: fail}\n",
        BUSINESS_RULES,
    ));
    assert!(err.contains("no conditions"), "{err}");
}

#[test]
fn s01_rejects_unknown_fields_in_new_strict_objects() {
    for fields in [
        "  resolver-profiles:\n    local: {servers: [192.0.2.53], prefer-h3: true}\n",
        "  policy-rules:\n    - match: {domain: example.com, fake-field: true}\n      action: {on-failure: fail}\n",
        "  policy-rules:\n    - match: {domain: example.com}\n      action: {on-failure: fail, fallback-lazy-query: true}\n",
    ] {
        let error = fail(&fixture(fields, BUSINESS_RULES));
        assert!(error.contains("unknown field"), "{error}");
    }
}

#[test]
fn s01_rejects_invalid_match_qtypes_and_conflicts() {
    for (value, expected) in [
        (
            "{domain: a.example, domain-suffix: example}",
            "cannot combine",
        ),
        ("{domain: '', qtype: A}", "domain"),
        ("{domain-suffix: '*.example', qtype: A}", "domain"),
        ("{domain: a.example, qtype: FOOBAR}", "unknown qtype"),
        ("{domain: a.example, qtype: TYPE65536}", "invalid qtype"),
        ("{domain: a.example, qtype: TYPE0}", "TYPE0"),
        ("{domain: a.example, qtype: []}", "qtype must not be empty"),
        ("{domain: a.example, qtype: [A, A]}", "duplicate qtype"),
    ] {
        let error = fail(&fixture(
            &format!(
                "  policy-rules:\n    - match: {value}\n      action: {{on-failure: fail}}\n"
            ),
            BUSINESS_RULES,
        ));
        assert!(
            error.contains(expected),
            "expected {expected} for {value}, got: {error}"
        );
    }
}

#[test]
fn s01_rejects_empty_actions_unknown_resolvers_and_strict_unimplemented_failure() {
    for (fields, expected) in [
        (
            "  policy-rules:\n    - match: {domain: example.com}\n      action: {}\n",
            "no effect",
        ),
        (
            "  policy-rules:\n    - match: {domain: example.com}\n      action: {resolver: missing}\n",
            "unknown or empty resolver",
        ),
        (
            "  policy-rules:\n    - match: {domain: example.com}\n      action: {on-failure: fallback}\n",
            "unsupported on-failure",
        ),
        (
            "  policy-rules:\n    - match: {domain: example.com}\n      action: {egress: legacy}\n",
            "invalid DNS egress",
        ),
        (
            "  policy-rules:\n    - match: {domain: example.com}\n      action: {egress: 'proxy:MISSING'}\n",
            "unknown proxy",
        ),
        (
            "  policy-rules:\n    - match: {domain: example.com}\n      action: {egress: 'proxy:REJECT'}\n",
            "invalid proxy",
        ),
    ] {
        let error = fail(&fixture(fields, BUSINESS_RULES));
        assert!(error.contains(expected), "expected {expected}: {error}");
    }
}

#[test]
fn s01_rejects_unusable_or_empty_profiles() {
    for profile in [
        "  resolver-profiles:\n    broken: {servers: []}\n",
        "  resolver-profiles:\n    broken: {servers: [system]}\n",
        "  resolver-profiles:\n    broken: {servers: ['quic://192.0.2.53']}\n",
    ] {
        let error = fail(&fixture(profile, BUSINESS_RULES));
        assert!(
            error.contains("has no servers")
                || error.contains("unusable")
                || error.contains("unsupported scheme"),
            "{error}"
        );
    }
}

#[test]
fn s01_rejects_explicit_egress_when_legacy_respect_rules_is_true() {
    let error = fail(&fixture(
        "  respect-rules: true\n  policy-rules:\n    - match: {qtype: A}\n      action: {egress: direct}\n",
        BUSINESS_RULES,
    ));
    assert!(error.contains("respect-rules"), "{error}");
}

#[test]
fn s01_rejects_egress_conflicting_with_profile_forced_proxy_path() {
    let error = fail(&fixture(
        "  resolver-profiles:\n    forced: {servers: ['udp://192.0.2.53#proxy=DNS-OUT']}\n  policy-rules:\n    - match: {domain: example.com}\n      action: {resolver: forced, egress: direct}\n",
        BUSINESS_RULES,
    ));
    assert!(error.contains("#proxy/#interface"), "{error}");
}

#[test]
fn s01_rejects_egress_conflicting_with_inherited_forced_proxy_path() {
    let yaml = fixture(
        "  policy-rules:\n    - match: {domain: example.com}\n      action: {egress: direct}\n",
        BUSINESS_RULES,
    ).replace("nameserver: [1.1.1.1]", "nameserver: ['udp://1.1.1.1#DNS-OUT']");
    let error = fail(&yaml);
    assert!(error.contains("#proxy/#interface"), "{error}");
}

#[tokio::test]
async fn s01_runtime_refuses_rules_until_egress_enforcement_is_available() {
    let cfg = compile(&fixture(
        "  policy-rules:\n    - match: {domain: secure.example}\n      action: {egress: 'proxy:DNS-OUT', on-failure: fail}\n",
        BUSINESS_RULES,
    ));
    let registry = std::sync::Arc::new(tokio::sync::RwLock::new(
        std::collections::HashMap::new(),
    ));
    let error =
        match clash_lib::app::dns::new_resolver(cfg.dns, None, None, registry, None)
            .await
        {
            Ok(_) => panic!(
                "compile-only S01 rules must never silently execute legacy DNS"
            ),
            Err(error) => error.to_string(),
        };
    assert!(
        error.contains("compiled but not executable yet (S01)"),
        "{error}"
    );
}

#[test]
fn s01_rejects_obvious_proxy_bootstrap_self_dependency() {
    let yaml = fixture(
        "  policy-rules:\n    - match: {domain: proxy.example, qtype: [A, AAAA]}\n      action: {egress: 'proxy:DNS-OUT', on-failure: fail}\n",
        BUSINESS_RULES,
    ).replace("server: 192.0.2.9", "server: proxy.example");
    let error = fail(&yaml);
    assert!(error.contains("bootstrap dependency cycle"), "{error}");
    assert!(error.contains("DNS-OUT"), "{error}");
}

#[test]
fn s01_rejects_rules_when_dns_disabled_instead_of_silent_ignore() {
    let yaml = fixture(
        "  policy-rules:\n    - match: {qtype: A}\n      action: {egress: direct}\n",
        BUSINESS_RULES,
    )
    .replace("enable: true", "enable: false");
    let error = fail(&yaml);
    assert!(error.contains("DNS must be enabled"), "{error}");
}
