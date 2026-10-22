//! S03a: real handler registry selection + fake DNS transport.
//! This never dials a DNS server or enables S01 policy-rules in the runtime.

use std::{
    collections::HashMap,
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use crate::{
    Config,
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::{
            ThreadSafeDNSResolver,
            config::NameServer,
            execution::{
                DnsStrictTransport, PreparedDnsExecution, StrictDnsExecution,
                prepare_dns_execution,
            },
            plan::{
                DnsPurpose, DnsQueryContext, EgressChoice, FailureChoice,
                LegacyDnsPlan, LegacyDnsRoute, ResolverChoice,
            },
            policy::DnsEgress,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, OutboundHandler,
        OutboundType, utils::OutboundHandlerRegistry,
    },
    session::Session,
};
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::A},
};
use tokio::sync::RwLock;

const BUSINESS_RULES: &str = "  - GEOIP,CN,DIRECT,no-resolve\n  - DOMAIN-SUFFIX,example.com,DNS-OUT\n  - MATCH,DIRECT\n";
fn yaml(new_dns: &str) -> String {
    format!(
        r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
  fallback: [9.9.9.9]
  default-nameserver: [223.5.5.5]
{new_dns}
profile:
  store-selected: false
  store-fake-ip: false
proxies:
  - name: DNS-OUT
    type: socks5
    server: 192.0.2.9
    port: 1080
rules:
{BUSINESS_RULES}
"#
    )
}

fn config(new_dns: &str) -> crate::config::internal::config::Config {
    Config::Str(yaml(new_dns)).try_parse().unwrap()
}

fn policy_fixture() -> crate::config::internal::config::Config {
    config(
        r#"
  resolver-profiles:
    trusted:
      servers: ["udp://192.0.2.53", "tcp://192.0.2.54"]
  policy-rules:
    - match: {domain: protected.example, qtype: A}
      action: {resolver: trusted, egress: "proxy:DNS-OUT", on-failure: fail}
    - match: {domain: direct.example, qtype: SRV}
      action: {resolver: trusted, egress: direct, on-failure: fail}
    - match: {domain: partial.example, qtype: A}
      action: {resolver: trusted, on-failure: fail}
    - match: {domain: nofail.example, qtype: A}
      action: {resolver: trusted, egress: "proxy:DNS-OUT"}
"#,
    )
}

fn request(host: &str, ty: RecordType) -> Message {
    let mut m = Message::new(0x5151, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii(host).unwrap(), ty));
    m
}

fn plan(
    cfg: &crate::config::internal::config::Config,
    domain: &str,
    ty: RecordType,
    legacy: LegacyDnsRoute,
) -> crate::app::dns::plan::EffectiveDnsPlan {
    cfg.dns
        .compiled_policy
        .build_effective_plan(
            DnsQueryContext::new(
                domain,
                ty,
                DNSClass::IN,
                DnsPurpose::ClientRealAnswer,
            )
            .unwrap(),
            LegacyDnsPlan::new(legacy),
        )
        .unwrap()
}

#[derive(Debug)]
struct MockProxy {
    name: String,
    ty: OutboundType,
}

#[async_trait]
impl DialWithConnector for MockProxy {}
#[async_trait]
impl OutboundHandler for MockProxy {
    fn name(&self) -> &str {
        &self.name
    }
    fn proto(&self) -> OutboundType {
        self.ty
    }
    async fn connect_stream(
        &self,
        _: &Session,
        _: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        Err(io::Error::other(
            "mock transport intentionally has no socket",
        ))
    }
    async fn connect_datagram(
        &self,
        _: &Session,
        _: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::other(
            "mock transport intentionally has no socket",
        ))
    }
    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}

fn registry(with_proxy: bool, proxy_ty: OutboundType) -> OutboundHandlerRegistry {
    let mut registry: HashMap<String, AnyOutboundHandler> = HashMap::new();
    if with_proxy {
        registry.insert(
            "DNS-OUT".to_owned(),
            Arc::new(MockProxy {
                name: "DNS-OUT".to_owned(),
                ty: proxy_ty,
            }),
        );
    }
    registry.insert(
        "DIRECT".to_owned(),
        Arc::new(MockProxy {
            name: "DIRECT".to_owned(),
            ty: OutboundType::Direct,
        }),
    );
    Arc::new(RwLock::new(registry))
}

#[derive(Clone)]
enum Reply {
    Ok,
    Fail,
    Servfail,
    WrongId,
    WrongQuestion,
    Truncated,
}

#[derive(Default)]
struct FakeDnsTransport {
    calls: Mutex<Vec<String>>,
    replies: Mutex<Vec<Reply>>,
}

impl FakeDnsTransport {
    fn with_replies(replies: Vec<Reply>) -> Self {
        Self {
            calls: Mutex::new(vec![]),
            replies: Mutex::new(replies),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}
#[async_trait]
impl DnsStrictTransport for FakeDnsTransport {
    async fn exchange(
        &self,
        server: &NameServer,
        outbound: AnyOutboundHandler,
        request: &Message,
    ) -> io::Result<Message> {
        self.calls.lock().unwrap().push(format!(
            "{}|{}|{}",
            outbound.name(),
            server.host,
            server.port,
        ));
        let reply = self.replies.lock().unwrap().remove(0);
        if matches!(reply, Reply::Fail) {
            return Err(io::Error::other("proxy dial failed"));
        }
        let mut message = Message::response(request.metadata.id, OpCode::Query);
        message.add_queries(request.queries.iter().cloned());
        match reply {
            Reply::Servfail => {
                message.metadata.response_code = ResponseCode::ServFail;
            }
            Reply::WrongId => {
                message.metadata.id ^= 1;
            }
            Reply::WrongQuestion => {
                message.queries.clear();
                message.add_query(Query::query(
                    Name::from_ascii("wrong.example.").unwrap(),
                    RecordType::A,
                ));
            }
            Reply::Truncated => {
                message.metadata.truncation = true;
            }
            _ => {}
        }
        if message.metadata.response_code == ResponseCode::NoError {
            message.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                40,
                RData::A(A(Ipv4Addr::new(198, 51, 100, 3))),
            ));
        }
        Ok(message)
    }
}

async fn strict(
    cfg: &crate::config::internal::config::Config,
    qname: &str,
    qtype: RecordType,
    registry: &OutboundHandlerRegistry,
) -> StrictDnsExecution {
    let plan = plan(
        cfg,
        qname,
        qtype,
        LegacyDnsRoute::MainWithResponseDependentFallback,
    );
    match prepare_dns_execution(
        &plan,
        &cfg.dns.compiled_policy,
        registry,
        &Session::default(),
    )
    .await
    .unwrap()
    {
        PreparedDnsExecution::Strict(strict) => strict,
        _ => panic!("expected an explicit DNS execution"),
    }
}

#[tokio::test]
async fn s03_explicit_proxy_is_selected_by_actual_registry_without_legacy_router() {
    let cfg = policy_fixture();
    let registry = registry(true, OutboundType::Socks5);
    let execution =
        strict(&cfg, "protected.example", RecordType::A, &registry).await;
    assert_eq!(execution.ordinal, 0);
    assert_eq!(execution.profile, "trusted");
    assert_eq!(execution.egress, DnsEgress::Proxy("DNS-OUT".to_owned()));
    assert_eq!(execution.outbound.name(), "DNS-OUT");
    assert_eq!(execution.servers.len(), 2);
    assert_eq!(cfg.rules[0].target(), "DIRECT");
    assert_eq!(cfg.rules[1].target(), "DNS-OUT");
    let fake = FakeDnsTransport::with_replies(vec![Reply::Ok]);
    let reply = execution
        .exchange(&fake, &request("protected.example.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(fake.calls(), ["DNS-OUT|192.0.2.53|53"]);
}

#[tokio::test]
async fn s03_absent_proxy_never_downgrades_to_direct_even_when_registry_has_direct()
{
    let cfg = policy_fixture();
    let registry = registry(false, OutboundType::Socks5);
    let plan = plan(
        &cfg,
        "protected.example",
        RecordType::A,
        LegacyDnsRoute::Main,
    );
    let result = prepare_dns_execution(
        &plan,
        &cfg.dns.compiled_policy,
        &registry,
        &Session::default(),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("missing proxy must fail"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("refusing DIRECT fallback"), "{error}");
}

#[tokio::test]
async fn s03_proxy_alias_selected_direct_or_reject_leaf_fails_closed() {
    let cfg = policy_fixture();
    for ty in [OutboundType::Direct, OutboundType::Reject] {
        let registry = registry(true, ty);
        let plan = plan(
            &cfg,
            "protected.example",
            RecordType::A,
            LegacyDnsRoute::Main,
        );
        let result = prepare_dns_execution(
            &plan,
            &cfg.dns.compiled_policy,
            &registry,
            &Session::default(),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("selected direct/reject under proxy name"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("refusing downgrade"), "{error}");
    }
}

#[tokio::test]
async fn s03_explicit_direct_uses_direct_handler_not_a_proxy_or_business_route() {
    let cfg = policy_fixture();
    let registry = registry(true, OutboundType::Socks5);
    let execution = strict(&cfg, "direct.example", RecordType::SRV, &registry).await;
    assert_eq!(execution.outbound.name(), "DIRECT");
    assert!(matches!(execution.outbound.proto(), OutboundType::Direct));
    assert_eq!(execution.egress, DnsEgress::Direct);
}

#[tokio::test]
async fn s03_proxy_transport_failure_never_uses_legacy_fallback_or_direct() {
    let cfg = policy_fixture();
    let registry = registry(true, OutboundType::Socks5);
    let execution =
        strict(&cfg, "protected.example", RecordType::A, &registry).await;
    let fake = FakeDnsTransport::with_replies(vec![Reply::Fail, Reply::Fail]);
    let error = execution
        .exchange(&fake, &request("protected.example.", RecordType::A))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("no DIRECT/legacy fallback permitted"),
        "{error}"
    );
    assert_eq!(
        fake.calls(),
        ["DNS-OUT|192.0.2.53|53", "DNS-OUT|192.0.2.54|53",]
    );
}

#[tokio::test]
async fn s03_servfail_retries_only_within_declared_profile_and_same_proxy() {
    let cfg = policy_fixture();
    let registry = registry(true, OutboundType::Socks5);
    let execution =
        strict(&cfg, "protected.example", RecordType::A, &registry).await;
    let fake = FakeDnsTransport::with_replies(vec![Reply::Servfail, Reply::Ok]);
    let response = execution
        .exchange(&fake, &request("protected.example.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        fake.calls(),
        ["DNS-OUT|192.0.2.53|53", "DNS-OUT|192.0.2.54|53",]
    );
}

#[tokio::test]
async fn s03_bad_id_or_question_and_truncated_reply_are_not_successes() {
    let cfg = policy_fixture();
    let registry = registry(true, OutboundType::Socks5);
    for first in [Reply::WrongId, Reply::WrongQuestion, Reply::Truncated] {
        let execution =
            strict(&cfg, "protected.example", RecordType::A, &registry).await;
        let fake = FakeDnsTransport::with_replies(vec![first, Reply::Ok]);
        let response = execution
            .exchange(&fake, &request("protected.example.", RecordType::A))
            .await
            .unwrap();
        assert_eq!(response.metadata.id, 0x5151);
        assert_eq!(
            fake.calls(),
            ["DNS-OUT|192.0.2.53|53", "DNS-OUT|192.0.2.54|53",]
        );
    }
}

#[tokio::test]
async fn s03_explicit_partial_actions_must_not_silently_assume_defaults() {
    let cfg = policy_fixture();
    let registry = registry(true, OutboundType::Socks5);
    for (domain, expected) in [
        ("partial.example", "without an explicit DNS egress"),
        ("nofail.example", "requires on-failure: fail"),
    ] {
        let plan = plan(&cfg, domain, RecordType::A, LegacyDnsRoute::Main);
        let result = prepare_dns_execution(
            &plan,
            &cfg.dns.compiled_policy,
            &registry,
            &Session::default(),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("unsafe partial action should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(expected), "{error}");
    }
}

#[tokio::test]
async fn s03_unmatched_policy_plan_retains_original_legacy_route_without_dial() {
    let cfg = policy_fixture();
    let registry = registry(false, OutboundType::Socks5);
    let route = LegacyDnsRoute::NameserverPolicy {
        selector: "+.corp.internal".to_owned(),
    };
    let plan = plan(&cfg, "unmatched.example", RecordType::HTTPS, route.clone());
    assert_eq!(plan.resolver, ResolverChoice::InheritLegacy);
    assert_eq!(plan.egress, EgressChoice::InheritLegacy);
    assert_eq!(plan.failure, FailureChoice::InheritLegacy);
    match prepare_dns_execution(
        &plan,
        &cfg.dns.compiled_policy,
        &registry,
        &Session::default(),
    )
    .await
    .unwrap()
    {
        PreparedDnsExecution::Legacy(original) => assert_eq!(original.route, route),
        _ => panic!("unmatched must remain legacy"),
    }
}

#[tokio::test]
async fn s03_fakeip_local_answer_bypasses_registry_and_strict_execution() {
    let cfg = policy_fixture();
    let registry = registry(false, OutboundType::Socks5);
    let plan = plan(
        &cfg,
        "protected.example",
        RecordType::A,
        LegacyDnsRoute::LocalAnswer,
    );
    match prepare_dns_execution(
        &plan,
        &cfg.dns.compiled_policy,
        &registry,
        &Session::default(),
    )
    .await
    .unwrap()
    {
        PreparedDnsExecution::LocalAnswer => {}
        _ => panic!("Fake-IP/hosts local response must never dial"),
    }
}

#[tokio::test]
async fn s03_unavailable_resolver_profile_fails_without_proxy_or_direct_dial() {
    let mut cfg = policy_fixture();
    cfg.dns.compiled_policy.profiles.clear();
    let registry = registry(true, OutboundType::Socks5);
    let mut plan = plan(
        &policy_fixture(),
        "protected.example",
        RecordType::A,
        LegacyDnsRoute::Main,
    );
    plan.matched_rule = Some(0);
    let result = prepare_dns_execution(
        &plan,
        &cfg.dns.compiled_policy,
        &registry,
        &Session::default(),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("missing profile must fail"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("unavailable"), "{error}");
}
