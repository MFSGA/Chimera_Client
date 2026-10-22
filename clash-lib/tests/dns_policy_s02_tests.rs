//! S02: deterministic plan-only fixtures. The live DNS runtime still refuses
//! S01/S02 policy-rules until S03 can enforce DNS egress and failure bounds.

use clash_lib::{
    Config,
    app::dns::{
        plan::{
            DnsPurpose, DnsQueryContext, DnsSourceScope, EgressChoice,
            FailureChoice, LegacyDnsPlan, LegacyDnsRoute, ResolverChoice,
        },
        policy::{DnsEgress, DnsFailure},
    },
};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{DNSClass, Name, RecordType},
};

const BUSINESS: &str = "  - GEOIP,CN,DIRECT,no-resolve\n  - DOMAIN-SUFFIX,example.com,DNS-OUT\n  - MATCH,DIRECT\n";

fn fixture(extra: &str) -> String {
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
  fallback: [9.9.9.9]
  default-nameserver: [223.5.5.5]
  nameserver-policy:
    "+.corp.internal": 192.0.2.53
  fake-ip-filter: ["*.lan"]
{extra}
profile:
  store-selected: false
  store-fake-ip: false
proxies:
  - name: DNS-OUT
    type: socks5
    server: 192.0.2.9
    port: 1080
rules:
{BUSINESS}
"#
    )
}

fn config(extra: &str) -> clash_lib::config::internal::config::Config {
    Config::Str(fixture(extra))
        .try_parse()
        .expect("S02 config fixture valid")
}

fn context(qname: &str, qtype: RecordType, purpose: DnsPurpose) -> DnsQueryContext {
    DnsQueryContext::new(qname, qtype, DNSClass::IN, purpose).unwrap()
}

fn legacy(route: LegacyDnsRoute) -> LegacyDnsPlan {
    LegacyDnsPlan::new(route)
}

#[test]
fn s02_absent_policy_fields_retains_exact_legacy_route_and_business_rules() {
    let cfg = config("");
    assert_eq!(cfg.rules.len(), 3);
    assert_eq!(cfg.rules[0].target(), "DIRECT");
    assert_eq!(cfg.rules[1].target(), "DNS-OUT");
    assert_eq!(cfg.rules[2].target(), "DIRECT");

    for route in [
        LegacyDnsRoute::Main,
        LegacyDnsRoute::MainWithResponseDependentFallback,
        LegacyDnsRoute::FallbackOnly,
        LegacyDnsRoute::NameserverPolicy {
            selector: "+.corp.internal".into(),
        },
        LegacyDnsRoute::ProxyServerNameserver,
        LegacyDnsRoute::DirectWithMainFallback,
        LegacyDnsRoute::LocalAnswer,
    ] {
        let existing = legacy(route);
        let planned = cfg
            .dns
            .compiled_policy
            .build_effective_plan(
                context(
                    "site.example.",
                    RecordType::A,
                    DnsPurpose::ClientRealAnswer,
                ),
                existing.clone(),
            )
            .unwrap();
        assert_eq!(planned.legacy, existing);
        assert_eq!(planned.matched_rule, None);
        assert_eq!(planned.resolver, ResolverChoice::InheritLegacy);
        assert_eq!(planned.egress, EgressChoice::InheritLegacy);
        assert_eq!(planned.failure, FailureChoice::InheritLegacy);
    }
}

#[test]
fn s02_unmatched_policy_rules_retain_nameserver_policy_and_dynamic_fallback() {
    let cfg = config(
        "  resolver-profiles:\n    trusted: {servers: [192.0.2.12]}\n  policy-rules:\n    - match: {domain: other.example, qtype: A}\n      action: {resolver: trusted}\n",
    );
    for route in [
        LegacyDnsRoute::NameserverPolicy {
            selector: "+.corp.internal".into(),
        },
        LegacyDnsRoute::MainWithResponseDependentFallback,
    ] {
        let previous = legacy(route);
        let planned = cfg
            .dns
            .compiled_policy
            .build_effective_plan(
                context(
                    "node.corp.internal",
                    RecordType::A,
                    DnsPurpose::RouteClassification,
                ),
                previous.clone(),
            )
            .unwrap();
        assert_eq!(
            planned.legacy, previous,
            "must preserve response-dependent fallback or policy"
        );
        assert_eq!(planned.matched_rule, None);
        assert_eq!(planned.resolver, ResolverChoice::InheritLegacy);
    }
}

#[test]
fn s02_a_aaaa_srv_have_different_rule_ordinals_and_explicit_dns_egresses() {
    let cfg = config(
        r#"
  resolver-profiles:
    local: {servers: [192.0.2.53]}
    trusted: {servers: ["https://dns.example/dns-query"]}
  policy-rules:
    - match: {domain: video.example, qtype: A}
      action: {resolver: trusted, egress: "proxy:DNS-OUT", on-failure: fail}
    - match: {domain: video.example, qtype: AAAA}
      action: {resolver: local, egress: direct}
    - match: {domain: _minecraft._tcp.video.example, qtype: SRV}
      action: {resolver: trusted}
"#,
    );
    let policy = &cfg.dns.compiled_policy;
    let original = legacy(LegacyDnsRoute::MainWithResponseDependentFallback);
    let a = policy
        .build_effective_plan(
            context(
                "VIDEO.EXAMPLE.",
                RecordType::A,
                DnsPurpose::ClientRealAnswer,
            ),
            original.clone(),
        )
        .unwrap();
    assert_eq!(a.matched_rule, Some(0));
    assert_eq!(a.resolver, ResolverChoice::Profile("trusted".into()));
    assert_eq!(
        a.egress,
        EgressChoice::Explicit(DnsEgress::Proxy("DNS-OUT".into()))
    );
    assert_eq!(a.failure, FailureChoice::Explicit(DnsFailure::Fail));
    assert_eq!(a.legacy, original);

    let aaaa = policy
        .build_effective_plan(
            context(
                "video.example",
                RecordType::AAAA,
                DnsPurpose::ClientRealAnswer,
            ),
            original.clone(),
        )
        .unwrap();
    assert_eq!(aaaa.matched_rule, Some(1));
    assert_eq!(aaaa.resolver, ResolverChoice::Profile("local".into()));
    assert_eq!(aaaa.egress, EgressChoice::Explicit(DnsEgress::Direct));
    assert_eq!(aaaa.failure, FailureChoice::InheritLegacy);

    let srv = policy
        .build_effective_plan(
            context(
                "_minecraft._tcp.video.example",
                RecordType::SRV,
                DnsPurpose::ClientRealAnswer,
            ),
            original.clone(),
        )
        .unwrap();
    assert_eq!(srv.matched_rule, Some(2));
    assert_eq!(srv.resolver, ResolverChoice::Profile("trusted".into()));
    assert_eq!(srv.egress, EgressChoice::InheritLegacy);
    assert_eq!(srv.failure, FailureChoice::InheritLegacy);

    let txt = policy
        .build_effective_plan(
            context(
                "video.example",
                RecordType::TXT,
                DnsPurpose::ClientRealAnswer,
            ),
            original.clone(),
        )
        .unwrap();
    assert_eq!(txt.matched_rule, None);
    assert_eq!(txt.legacy, original);
    assert_eq!(cfg.rules[0].target(), "DIRECT");
    assert_eq!(cfg.rules[1].target(), "DNS-OUT");
}

#[test]
fn s02_explicit_failure_only_keeps_legacy_resolver_and_egress() {
    let cfg = config(
        "  policy-rules:\n    - match: {domain-suffix: example.com}\n      action: {on-failure: fail}\n",
    );
    let existing = legacy(LegacyDnsRoute::MainWithResponseDependentFallback);
    let plan = cfg
        .dns
        .compiled_policy
        .build_effective_plan(
            context(
                "cdn.example.com",
                RecordType::A,
                DnsPurpose::DirectDestination,
            ),
            existing.clone(),
        )
        .unwrap();
    assert_eq!(plan.matched_rule, Some(0));
    assert_eq!(plan.resolver, ResolverChoice::InheritLegacy);
    assert_eq!(plan.egress, EgressChoice::InheritLegacy);
    assert_eq!(plan.failure, FailureChoice::Explicit(DnsFailure::Fail));
    assert_eq!(
        plan.legacy, existing,
        "S03 must explicitly enforce fail instead of silently executing inherited fallback"
    );
}

#[test]
fn s02_explicit_resolver_only_keeps_all_other_legacy_dimensions() {
    let cfg = config(
        "  resolver-profiles:\n    trusted: {servers: [192.0.2.100]}\n  policy-rules:\n    - match: {domain: cdn.example.com}\n      action: {resolver: trusted}\n",
    );
    let inherited = legacy(LegacyDnsRoute::NameserverPolicy {
        selector: "+.corp.internal".into(),
    });
    let plan = cfg
        .dns
        .compiled_policy
        .build_effective_plan(
            context(
                "cdn.example.com",
                RecordType::A,
                DnsPurpose::RouteClassification,
            ),
            inherited.clone(),
        )
        .unwrap();
    assert_eq!(plan.resolver, ResolverChoice::Profile("trusted".into()));
    assert_eq!(plan.egress, EgressChoice::InheritLegacy);
    assert_eq!(plan.failure, FailureChoice::InheritLegacy);
    assert_eq!(plan.legacy, inherited);
}

#[test]
fn s02_first_match_is_user_order_even_if_exact_rule_more_specific() {
    let cfg = config(
        "  policy-rules:\n    - match: {domain-suffix: example.com}\n      action: {on-failure: fail}\n    - match: {domain: api.example.com}\n      action: {egress: direct}\n",
    );
    let plan = cfg
        .dns
        .compiled_policy
        .build_effective_plan(
            context(
                "API.EXAMPLE.COM.",
                RecordType::A,
                DnsPurpose::ClientRealAnswer,
            ),
            legacy(LegacyDnsRoute::Main),
        )
        .unwrap();
    assert_eq!(plan.matched_rule, Some(0));
    assert_eq!(plan.egress, EgressChoice::InheritLegacy);
    assert_eq!(plan.failure, FailureChoice::Explicit(DnsFailure::Fail));
}

#[test]
fn s02_same_dns_name_different_purposes_keep_distinct_legacy_paths() {
    let cfg = config(
        "  resolver-profiles:\n    trusted: {servers: [192.0.2.101]}\n  policy-rules:\n    - match: {domain: node.example.com, qtype: A}\n      action: {resolver: trusted, on-failure: fail}\n",
    );
    for (purpose, route) in [
        (
            DnsPurpose::RouteClassification,
            LegacyDnsRoute::MainWithResponseDependentFallback,
        ),
        (
            DnsPurpose::DirectDestination,
            LegacyDnsRoute::DirectWithMainFallback,
        ),
        (DnsPurpose::ProxyDestinationLocal, LegacyDnsRoute::Main),
        (
            DnsPurpose::ProxyNodeBootstrap,
            LegacyDnsRoute::ProxyServerNameserver,
        ),
        (DnsPurpose::ResolverBootstrap, LegacyDnsRoute::Main),
        (
            DnsPurpose::Diagnostic,
            LegacyDnsRoute::NameserverPolicy {
                selector: "legacy".into(),
            },
        ),
        (DnsPurpose::ClientRealAnswer, LegacyDnsRoute::Main),
    ] {
        let plan = cfg
            .dns
            .compiled_policy
            .build_effective_plan(
                context("node.example.com", RecordType::A, purpose),
                legacy(route.clone()),
            )
            .unwrap();
        assert_eq!(plan.context.purpose, purpose);
        assert_eq!(plan.legacy.route, route);
        assert_eq!(
            plan.matched_rule,
            Some(0),
            "S01 has no purpose predicate; caller's legacy route remains purpose-specific"
        );
        assert_eq!(plan.resolver, ResolverChoice::Profile("trusted".into()));
    }
}

#[test]
fn s02_local_fake_ip_or_hosts_answer_never_forced_to_real_dns() {
    let cfg = config(
        "  resolver-profiles:\n    trusted: {servers: [192.0.2.53]}\n  policy-rules:\n    - match: {qtype: A}\n      action: {resolver: trusted, egress: 'proxy:DNS-OUT', on-failure: fail}\n",
    );
    let plan = cfg
        .dns
        .compiled_policy
        .build_effective_plan(
            context(
                "fake.example.com",
                RecordType::A,
                DnsPurpose::ClientRealAnswer,
            ),
            legacy(LegacyDnsRoute::LocalAnswer),
        )
        .unwrap();
    assert_eq!(plan.matched_rule, None);
    assert_eq!(plan.legacy.route, LegacyDnsRoute::LocalAnswer);
    assert_eq!(plan.resolver, ResolverChoice::InheritLegacy);
    assert_eq!(plan.egress, EgressChoice::InheritLegacy);
    assert_eq!(plan.failure, FailureChoice::InheritLegacy);
}

#[test]
fn s02_context_scope_and_generations_are_preserved_without_affecting_business_egress()
 {
    let cfg = config(
        "  policy-rules:\n    - match: {qtype: A}\n      action: {on-failure: fail}\n",
    );
    let mut ctx = context(
        "gw.example.com",
        RecordType::A,
        DnsPurpose::DirectDestination,
    );
    ctx.source = DnsSourceScope::Gateway {
        namespace: "tenant-A".into(),
    };
    ctx.network_generation = 27;
    ctx.config_generation = 5;
    let plan = cfg
        .dns
        .compiled_policy
        .build_effective_plan(
            ctx.clone(),
            legacy(LegacyDnsRoute::DirectWithMainFallback),
        )
        .unwrap();
    assert_eq!(plan.context, ctx);
    assert_eq!(plan.legacy.route, LegacyDnsRoute::DirectWithMainFallback);
    assert_eq!(plan.egress, EgressChoice::InheritLegacy);
    assert_eq!(cfg.rules[1].target(), "DNS-OUT");
}

#[test]
fn s02_non_in_dns_class_does_not_apply_an_internet_dns_policy() {
    let cfg = config(
        "  policy-rules:\n    - match: {qtype: A}\n      action: {on-failure: fail}\n",
    );
    let ctx = DnsQueryContext::new(
        "host.example",
        RecordType::A,
        DNSClass::CH,
        DnsPurpose::ClientRealAnswer,
    )
    .unwrap();
    let plan = cfg
        .dns
        .compiled_policy
        .build_effective_plan(ctx, legacy(LegacyDnsRoute::Main))
        .unwrap();
    assert_eq!(plan.matched_rule, None);
    assert_eq!(plan.failure, FailureChoice::InheritLegacy);
}

#[test]
fn s02_dns_message_metadata_is_captured_without_a_network_call() {
    let cfg = config("");
    let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_ascii("HOST.Example.COM.").unwrap(),
        RecordType::A,
    ));
    msg.metadata.recursion_desired = true;
    msg.metadata.checking_disabled = true;
    msg.metadata.authentic_data = true;
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_dnssec_ok(true);
    msg.set_edns(edns);
    let ctx = DnsQueryContext::from_message(&msg, DnsPurpose::Diagnostic).unwrap();
    assert_eq!(ctx.qname, "host.example.com");
    assert_eq!(ctx.qtype, RecordType::A);
    assert_eq!(ctx.qclass, DNSClass::IN);
    assert!(ctx.flags.has_edns);
    assert!(ctx.flags.dnssec_ok);
    assert!(ctx.flags.checking_disabled);
    assert!(ctx.flags.authentic_data);
    assert!(ctx.flags.recursion_desired);
    let plan = cfg
        .dns
        .compiled_policy
        .build_effective_plan(ctx.clone(), legacy(LegacyDnsRoute::Main))
        .unwrap();
    assert_eq!(plan.context, ctx);
    assert_eq!(plan.matched_rule, None);
}

#[test]
fn s02_multiple_empty_nonquery_messages_are_rejected() {
    let mut empty = Message::new(0x2222, MessageType::Query, OpCode::Query);
    assert!(DnsQueryContext::from_message(&empty, DnsPurpose::Diagnostic).is_err());
    empty.add_query(Query::query(
        Name::from_ascii("one.example.").unwrap(),
        RecordType::A,
    ));
    empty.add_query(Query::query(
        Name::from_ascii("two.example.").unwrap(),
        RecordType::AAAA,
    ));
    assert!(DnsQueryContext::from_message(&empty, DnsPurpose::Diagnostic).is_err());
    let mut response = Message::new(0x2222, MessageType::Response, OpCode::Query);
    response.add_query(Query::query(
        Name::from_ascii("one.example.").unwrap(),
        RecordType::A,
    ));
    assert!(
        DnsQueryContext::from_message(&response, DnsPurpose::Diagnostic).is_err()
    );
}

#[test]
fn s02_rejects_invalid_qnames_even_when_no_policy_matches() {
    assert!(
        DnsQueryContext::new(
            "",
            RecordType::A,
            DNSClass::IN,
            DnsPurpose::Diagnostic
        )
        .is_err()
    );
    assert!(
        DnsQueryContext::new(
            "   ",
            RecordType::A,
            DNSClass::IN,
            DnsPurpose::Diagnostic
        )
        .is_err()
    );
    assert!(
        DnsQueryContext::new(
            "name..example",
            RecordType::A,
            DNSClass::IN,
            DnsPurpose::Diagnostic
        )
        .is_err()
    );
}

#[test]
fn s02_planner_fails_closed_if_compiled_profile_has_been_removed() {
    let mut cfg = config(
        "  resolver-profiles:\n    trusted: {servers: [192.0.2.12]}\n  policy-rules:\n    - match: {domain: video.example}\n      action: {resolver: trusted}\n",
    );
    cfg.dns.compiled_policy.profiles.clear();
    let result = cfg.dns.compiled_policy.build_effective_plan(
        context("video.example", RecordType::A, DnsPurpose::Diagnostic),
        legacy(LegacyDnsRoute::Main),
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("missing resolver profile"), "{err}");
}
