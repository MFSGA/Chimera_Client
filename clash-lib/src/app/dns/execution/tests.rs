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

// S03b loopback integration: Hickory's real UDP/TCP wire transport crosses
// the exact pinned outbound, with no public resolver or Internet dependency.
#[derive(Debug)]
struct CountingWireProxy {
    name: &'static str,
    endpoint: &'static str,
    tcp: Arc<std::sync::atomic::AtomicUsize>,
    udp: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl DialWithConnector for CountingWireProxy {}

#[async_trait]
impl OutboundHandler for CountingWireProxy {
    fn name(&self) -> &str {
        self.name
    }
    fn server_name(&self) -> Option<&str> {
        Some(self.endpoint)
    }
    fn proto(&self) -> OutboundType {
        OutboundType::Socks5
    }
    async fn support_udp(&self) -> bool {
        true
    }
    async fn connect_stream(
        &self,
        session: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        self.tcp.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let direct = crate::proxy::direct::Handler::new("DIRECT");
        direct.connect_stream(session, resolver).await
    }
    async fn connect_datagram(
        &self,
        session: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        self.udp.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let direct = crate::proxy::direct::Handler::new("DIRECT");
        direct.connect_datagram(session, resolver).await
    }
}

fn server(addr: std::net::SocketAddr, mode: &str) -> NameServer {
    crate::app::dns::Config::parse_nameserver(&[format!("{mode}://{addr}")])
        .unwrap()
        .remove(0)
}

fn answer(request: &Message) -> Message {
    let mut msg = Message::response(request.metadata.id, request.metadata.op_code);
    msg.add_queries(request.queries.iter().cloned());
    msg.add_answer(Record::from_rdata(
        request.queries[0].name().clone(),
        60,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 123))),
    ));
    msg
}

async fn local_exchange(mode: &str, use_proxy: bool) {
    use crate::app::dns::execution::DnsStrictWireTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    let tcp_hits = Arc::new(AtomicUsize::new(0));
    let udp_hits = Arc::new(AtomicUsize::new(0));
    let (addr, task) = if mode == "udp" {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let incoming = Message::from_vec(&buffer[..n]).unwrap();
            let reply = answer(&incoming);
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        (addr, task)
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await.unwrap();
            let mut bytes = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut bytes).await.unwrap();
            let incoming = Message::from_vec(&bytes).unwrap();
            let data = answer(&incoming).to_vec().unwrap();
            stream
                .write_all(&(data.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&data).await.unwrap();
        });
        (addr, task)
    };

    let outbound: AnyOutboundHandler = if use_proxy {
        Arc::new(CountingWireProxy {
            name: "DNS-OUT",
            endpoint: "192.0.2.9",
            tcp: tcp_hits.clone(),
            udp: udp_hits.clone(),
        })
    } else {
        Arc::new(crate::proxy::direct::Handler::new("DIRECT"))
    };
    let execution = StrictDnsExecution {
        ordinal: 0,
        profile: "loopback".into(),
        egress: if use_proxy {
            DnsEgress::Proxy("DNS-OUT".into())
        } else {
            DnsEgress::Direct
        },
        servers: vec![server(addr, mode)],
        outbound,
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        execution.exchange(
            &DnsStrictWireTransport,
            &request("protected.example.", RecordType::A),
        ),
    )
    .await
    .expect("strict UDP/TCP exchange should be bounded")
    .expect("loopback DNS reply should be valid");
    assert_eq!(result.answers.len(), 1);
    assert_eq!(
        result.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 123)))
    );
    task.await.unwrap();
    if use_proxy {
        if mode == "udp" {
            assert_eq!(udp_hits.load(Ordering::SeqCst), 1);
            assert_eq!(tcp_hits.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(tcp_hits.load(Ordering::SeqCst), 1);
            assert_eq!(udp_hits.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn s03b_udp_direct_wire_uses_local_dns_server() {
    local_exchange("udp", false).await;
}

#[tokio::test]
async fn s03b_tcp_direct_wire_uses_local_dns_server() {
    local_exchange("tcp", false).await;
}

#[tokio::test]
async fn s03b_udp_proxy_wire_invokes_selected_outbound_only() {
    local_exchange("udp", true).await;
}

#[tokio::test]
async fn s03b_tcp_proxy_wire_invokes_selected_outbound_only() {
    local_exchange("tcp", true).await;
}

#[tokio::test]
async fn s03b_hostname_bootstrap_and_unimplemented_wire_fail_closed() {
    use crate::app::dns::ClashResolver;
    use crate::app::dns::execution::{DnsStrictWireTransport, LiteralOnlyResolver};
    let guard = LiteralOnlyResolver::default();
    assert!(guard.resolve("bootstrap.example", false).await.is_err());
    assert_eq!(
        guard.resolve("192.0.2.8", false).await.unwrap(),
        Some("192.0.2.8".parse().unwrap())
    );
    let outbound: AnyOutboundHandler =
        Arc::new(crate::proxy::direct::Handler::new("DIRECT"));
    let config = crate::app::dns::Config::parse_nameserver(&[
        "udp://resolver.example".to_owned(),
    ])
    .unwrap()
    .remove(0);
    let result = DnsStrictWireTransport
        .exchange(
            &config,
            outbound.clone(),
            &request("protected.example.", RecordType::A),
        )
        .await
        .unwrap_err();
    assert!(
        result.to_string().contains("needs explicit bootstrap"),
        "{result}"
    );

    // S03c no longer treats DoT as entirely unsupported; an IP
    // hostname is rejected because it cannot provide a safe DNS TLS
    // identity under the strict DoT/DoH policy.
    let unsafe_ip_tls = crate::app::dns::Config::parse_nameserver(&[
        "tls://127.0.0.1:853".to_owned(),
    ])
    .unwrap()
    .remove(0);
    let result = DnsStrictWireTransport
        .exchange(
            &unsafe_ip_tls,
            outbound,
            &request("protected.example.", RecordType::A),
        )
        .await
        .unwrap_err();
    assert!(
        result.to_string().contains("IP-hostname bypass forbidden"),
        "{result}"
    );
}

#[tokio::test]
async fn s03b_proxy_hostname_cannot_resolve_through_system_dns() {
    use crate::app::dns::execution::DnsStrictWireTransport;
    let tcp_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let udp_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outbound: AnyOutboundHandler = Arc::new(CountingWireProxy {
        name: "DNS-OUT",
        endpoint: "node.example",
        tcp: tcp_hits.clone(),
        udp: udp_hits.clone(),
    });
    let result = DnsStrictWireTransport
        .exchange(
            &server("127.0.0.1:1".parse().unwrap(), "udp"),
            outbound,
            &request("protected.example.", RecordType::A),
        )
        .await
        .unwrap_err();
    assert!(
        result.to_string().contains("requires unresolved bootstrap"),
        "{result}"
    );
    assert_eq!(tcp_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(udp_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn s03b_truncated_udp_retries_tcp_through_same_pinned_proxy() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = tcp_listener.local_addr().unwrap();
    let udp_socket = UdpSocket::bind(endpoint).await.unwrap();

    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (size, peer) = udp_socket.recv_from(&mut buf).await.unwrap();
        let query = Message::from_vec(&buf[..size]).unwrap();
        let mut truncated =
            Message::response(query.metadata.id, query.metadata.op_code);
        truncated.metadata.truncation = true;
        truncated.add_queries(query.queries);
        udp_socket
            .send_to(&truncated.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp_listener.accept().await.unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut packet = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut packet).await.unwrap();
        let query = Message::from_vec(&packet).unwrap();
        let response = answer(&query).to_vec().unwrap();
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
    });

    let tcp_hits = Arc::new(AtomicUsize::new(0));
    let udp_hits = Arc::new(AtomicUsize::new(0));
    let outbound: AnyOutboundHandler = Arc::new(CountingWireProxy {
        name: "DNS-OUT",
        endpoint: "192.0.2.9",
        tcp: tcp_hits.clone(),
        udp: udp_hits.clone(),
    });
    let execution = StrictDnsExecution {
        ordinal: 0,
        profile: "truncated".into(),
        egress: DnsEgress::Proxy("DNS-OUT".into()),
        servers: vec![server(endpoint, "udp")],
        outbound,
    };
    let query = request("protected.example.", RecordType::A);
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        execution
            .exchange(&crate::app::dns::execution::DnsStrictWireTransport, &query),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.metadata.id, query.metadata.id);
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
    assert_eq!(udp_hits.load(Ordering::SeqCst), 1);
    assert_eq!(tcp_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn s03b_mixed_unsupported_encrypted_profile_is_rejected_before_udp_dial() {
    use crate::app::dns::execution::DnsStrictWireTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let tcp = Arc::new(AtomicUsize::new(0));
    let udp = Arc::new(AtomicUsize::new(0));
    let outbound: AnyOutboundHandler = Arc::new(CountingWireProxy {
        name: "DNS-OUT",
        endpoint: "192.0.2.9",
        tcp: tcp.clone(),
        udp: udp.clone(),
    });
    let execution = StrictDnsExecution {
        ordinal: 3,
        profile: "mixed".into(),
        egress: DnsEgress::Proxy("DNS-OUT".into()),
        servers: vec![
            server("127.0.0.1:55335".parse().unwrap(), "udp"),
            crate::app::dns::Config::parse_nameserver(&[
                "tls://127.0.0.1:853".to_string()
            ])
            .unwrap()
            .remove(0),
        ],
        outbound,
    };
    let err = execution
        .exchange(
            &DnsStrictWireTransport,
            &request("protected.example.", RecordType::A),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("cannot be safely executed"),
        "{err}"
    );
    assert_eq!(udp.load(Ordering::SeqCst), 0);
    assert_eq!(tcp.load(Ordering::SeqCst), 0);
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
async fn s03c_self_signed_tls_listener()
-> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    crate::setup_default_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["dns.strict.example".into()])
            .unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
            .unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        // A rejected certificate can cause the client to retry, but it must
        // never complete the TLS handshake successfully.
        for _ in 0..8 {
            let Ok(Ok((stream, _))) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                listener.accept(),
            )
            .await
            else {
                break;
            };
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                acceptor.accept(stream),
            )
            .await;
        }
    });
    (address, handle)
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
#[tokio::test]
async fn s03c_encrypted_dns_rejects_untrusted_tls_cert_even_with_pinned_ip() {
    use crate::app::dns::execution::DnsStrictPinnedWireTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for scheme in ["tls", "https"] {
        let (address, task) = s03c_self_signed_tls_listener().await;
        let url = if scheme == "https" {
            format!(
                "https://dns.strict.example:{}/dns-query?custom=1",
                address.port()
            )
        } else {
            format!("tls://dns.strict.example:{}", address.port())
        };
        let server = crate::app::dns::Config::parse_nameserver(&[url])
            .unwrap()
            .remove(0);
        if scheme == "https" {
            assert_eq!(server.doh_path.as_deref(), Some("/dns-query?custom=1"));
        }
        let wire = DnsStrictPinnedWireTransport::new(HashMap::from([(
            "dns.strict.example".to_owned(),
            address.ip(),
        )]))
        .unwrap();
        let tcp = Arc::new(AtomicUsize::new(0));
        let udp = Arc::new(AtomicUsize::new(0));
        let outbound: AnyOutboundHandler = Arc::new(CountingWireProxy {
            name: "DNS-OUT",
            endpoint: "192.0.2.9",
            tcp: tcp.clone(),
            udp: udp.clone(),
        });
        let execution = StrictDnsExecution {
            ordinal: 1,
            profile: "trusted".to_owned(),
            egress: DnsEgress::Proxy("DNS-OUT".to_owned()),
            servers: vec![server],
            outbound,
        };
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(14),
            execution.exchange(&wire, &request("protected.example.", RecordType::A)),
        )
        .await
        .unwrap()
        .unwrap_err();
        let reason = err.to_string();
        assert!(
            reason.contains("no DIRECT/legacy fallback permitted"),
            "{reason}"
        );
        assert!(
            reason.to_ascii_lowercase().contains("certificate")
                || reason.to_ascii_lowercase().contains("cert"),
            "expected real rustls certificate-verification error: {reason}"
        );
        assert!(
            tcp.load(Ordering::SeqCst) > 0,
            "verified TLS must use pinned outbound"
        );
        assert_eq!(udp.load(Ordering::SeqCst), 0, "must not fall back to UDP");
        task.abort();
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
#[tokio::test]
async fn s03c_tls_hostname_without_ip_pin_is_rejected_before_network() {
    use crate::app::dns::execution::DnsStrictPinnedWireTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for scheme in ["tls", "https"] {
        let server = crate::app::dns::Config::parse_nameserver(&[format!(
            "{scheme}://dns.strict.example:853"
        )])
        .unwrap()
        .remove(0);
        let wire = DnsStrictPinnedWireTransport::default();
        let tcp = Arc::new(AtomicUsize::new(0));
        let udp = Arc::new(AtomicUsize::new(0));
        let outbound: AnyOutboundHandler = Arc::new(CountingWireProxy {
            name: "DNS-OUT",
            endpoint: "192.0.2.9",
            tcp: tcp.clone(),
            udp: udp.clone(),
        });
        let execution = StrictDnsExecution {
            ordinal: 0,
            profile: "trusted".into(),
            egress: DnsEgress::Proxy("DNS-OUT".into()),
            servers: vec![server],
            outbound,
        };
        let err = execution
            .exchange(&wire, &request("protected.example.", RecordType::A))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("explicit IP bootstrap pin"),
            "{err}"
        );
        assert_eq!(tcp.load(Ordering::SeqCst), 0);
        assert_eq!(udp.load(Ordering::SeqCst), 0);
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
#[tokio::test]
async fn s03c_doh_ip_host_and_mixed_plaintext_profile_fail_pre_dial() {
    use crate::app::dns::execution::DnsStrictPinnedWireTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let wire = DnsStrictPinnedWireTransport::new(HashMap::from([(
        "dns.strict.example".to_owned(),
        "127.0.0.1".parse().unwrap(),
    )]))
    .unwrap();
    let tcp = Arc::new(AtomicUsize::new(0));
    let udp = Arc::new(AtomicUsize::new(0));
    let outbound: AnyOutboundHandler = Arc::new(CountingWireProxy {
        name: "DNS-OUT",
        endpoint: "192.0.2.9",
        tcp: tcp.clone(),
        udp: udp.clone(),
    });
    for urls in [
        vec!["https://127.0.0.1:443/dns-query".to_owned()],
        vec![
            "udp://127.0.0.1:5353".to_owned(),
            "https://dns.strict.example:443/dns-query".to_owned(),
        ],
    ] {
        let servers = crate::app::dns::Config::parse_nameserver(&urls).unwrap();
        let execution = StrictDnsExecution {
            ordinal: 2,
            profile: "encrypted".into(),
            egress: DnsEgress::Proxy("DNS-OUT".into()),
            servers,
            outbound: outbound.clone(),
        };
        let err = execution
            .exchange(&wire, &request("protected.example.", RecordType::A))
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("IP-hostname bypass forbidden")
                || message.contains("cannot mix encrypted"),
            "{message}"
        );
    }
    assert_eq!(tcp.load(Ordering::SeqCst), 0);
    assert_eq!(udp.load(Ordering::SeqCst), 0);
}

#[test]
fn s03c_pinned_host_names_reject_noncanonical_input() {
    use crate::app::dns::execution::DnsStrictPinnedWireTransport;
    for key in ["", " DNS.example", "DNS.example", "dns.example."] {
        assert!(
            DnsStrictPinnedWireTransport::new(HashMap::from([(
                key.to_owned(),
                "127.0.0.1".parse().unwrap()
            )]))
            .is_err()
        );
    }
}
