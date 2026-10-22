use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    time::Instant,
};

use async_trait::async_trait;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, SOA, TSIG, tsig::TsigAlgorithm},
    },
};

use super::*;
use crate::{
    app::dns::{
        config::NameServer, execution::StrictDnsExecution, plan::DnsPurpose,
    },
    proxy::{AnyOutboundHandler, direct},
};

struct FakeWire {
    hits: AtomicUsize,
    reply: Mutex<Message>,
    identity: Option<String>,
}
impl FakeWire {
    fn new(reply: Message, identity: Option<&str>) -> Self {
        Self {
            hits: AtomicUsize::new(0),
            reply: Mutex::new(reply),
            identity: identity.map(str::to_owned),
        }
    }
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}
#[async_trait]
impl DnsStrictTransport for FakeWire {
    fn isolation_fingerprint(&self) -> Option<String> {
        self.identity.clone()
    }
    async fn exchange(
        &self,
        _: &NameServer,
        _: AnyOutboundHandler,
        request: &Message,
    ) -> io::Result<Message> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        let mut reply = self.reply.lock().unwrap().clone();
        reply.metadata.id = request.metadata.id;
        reply.queries = request.queries.clone();
        Ok(reply)
    }
}

fn question(qname: &str, qtype: RecordType, id: u16) -> Message {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(Name::from_ascii(qname).unwrap(), qtype));
    msg.metadata.recursion_desired = true;
    msg
}

fn ctx(message: &Message) -> DnsQueryContext {
    let mut ctx =
        DnsQueryContext::from_message(message, DnsPurpose::ClientRealAnswer)
            .unwrap();
    ctx.network_generation = 7;
    ctx.config_generation = 9;
    ctx
}

fn positive(req: &Message) -> Message {
    let mut msg = Message::response(req.metadata.id, OpCode::Query);
    msg.add_queries(req.queries.iter().cloned());
    msg.add_answer(Record::from_rdata(
        req.queries[0].name().clone(),
        30,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
    ));
    msg
}
fn negative(req: &Message) -> Message {
    let mut msg = Message::response(req.metadata.id, OpCode::Query);
    msg.add_queries(req.queries.iter().cloned());
    msg.metadata.response_code = ResponseCode::NXDomain;
    msg.add_authority(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        120,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            1,
            5,
            5,
            60,
            18,
        )),
    ));
    msg
}
fn add_test_signature(message: &mut Message) {
    // The MAC is intentionally synthetic: the cache must bypass all TSIG
    // messages, not try to validate or replay transaction-specific signatures.
    message.signature = Some(Box::new(Record::from_rdata(
        Name::from_ascii("test-key.example.").unwrap(),
        0,
        TSIG::new(
            TsigAlgorithm::HmacSha256,
            0,
            300,
            vec![0xa5; 16],
            message.metadata.id,
            None,
            Vec::new(),
        ),
    )));
}

fn execution(
    profile: &str,
    egress: DnsEgress,
    leaf: AnyOutboundHandler,
    server: &str,
) -> StrictDnsExecution {
    StrictDnsExecution {
        ordinal: 0,
        profile: profile.into(),
        egress,
        outbound: leaf,
        servers: crate::app::dns::Config::parse_nameserver(&[server.into()])
            .unwrap(),
    }
}
fn leaf(name: &str) -> AnyOutboundHandler {
    Arc::new(direct::Handler::new(name))
}

#[tokio::test]
async fn s04_positive_cache_returns_original_answer_without_repeated_dial() {
    let req = question("www.example.com.", RecordType::A, 0x1001);
    let response = positive(&req);
    let fake = FakeWire::new(response, Some("static-pins"));
    let cache = StrictDnsCache::new(4, 7, 9, 0);
    let exec =
        execution("main", DnsEgress::Direct, leaf("LEAF"), "udp://192.0.2.53");
    let first = cache
        .exchange_scoped(&exec, &fake, &req, &ctx(&req), 0)
        .await
        .unwrap();
    assert_eq!(
        first.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 9)))
    );
    let req2 = question("WWW.EXAMPLE.COM.", RecordType::A, 0x3003);
    let second = cache
        .exchange_scoped(&exec, &fake, &req2, &ctx(&req2), 0)
        .await
        .unwrap();
    assert_eq!(second.metadata.id, 0x3003);
    assert_eq!(second.queries, req2.queries);
    assert_eq!(fake.hits(), 1);
    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn s04_same_domain_separate_egress_profile_leaf_and_server() {
    let req = question("www.example.com.", RecordType::A, 12);
    let wire = FakeWire::new(positive(&req), Some("same-pin-set"));
    let cache = StrictDnsCache::new(32, 7, 9, 0);
    let first_leaf = leaf("one");
    let second_leaf = leaf("one");
    let variants = [
        execution(
            "A",
            DnsEgress::Direct,
            first_leaf.clone(),
            "udp://192.0.2.53",
        ),
        execution(
            "A",
            DnsEgress::Proxy("group".into()),
            first_leaf.clone(),
            "udp://192.0.2.53",
        ),
        execution(
            "B",
            DnsEgress::Proxy("group".into()),
            first_leaf.clone(),
            "udp://192.0.2.53",
        ),
        execution(
            "B",
            DnsEgress::Proxy("group".into()),
            second_leaf,
            "udp://192.0.2.53",
        ),
        execution(
            "B",
            DnsEgress::Proxy("group".into()),
            first_leaf.clone(),
            "udp://192.0.2.54",
        ),
    ];
    for exec in &variants {
        cache
            .exchange_scoped(exec, &wire, &req, &ctx(&req), 0)
            .await
            .unwrap();
    }
    assert_eq!(wire.hits(), 5);
    assert_eq!(cache.len(), 5);
    cache
        .exchange_scoped(&variants[0], &wire, &req, &ctx(&req), 0)
        .await
        .unwrap();
    assert_eq!(wire.hits(), 5);
}

#[tokio::test]
async fn s04_gateway_namespace_purpose_qtype_and_network_epoch_are_isolated() {
    let req = question("www.example.com.", RecordType::A, 12);
    let wire = FakeWire::new(positive(&req), Some("pins"));
    let cache = StrictDnsCache::new(32, 7, 9, 0);
    let exec = execution(
        "main",
        DnsEgress::Direct,
        leaf("direct"),
        "udp://192.0.2.53",
    );
    let base = ctx(&req);
    let mut host_context = base.clone();
    host_context.purpose = DnsPurpose::RouteClassification;
    let mut tenant_a = base.clone();
    tenant_a.source = DnsSourceScope::Gateway {
        namespace: "tenant-A".into(),
    };
    let mut tenant_b = base.clone();
    tenant_b.source = DnsSourceScope::Gateway {
        namespace: "tenant-B".into(),
    };
    for scope in [&base, &host_context, &tenant_a, &tenant_b] {
        cache
            .exchange_scoped(&exec, &wire, &req, scope, 0)
            .await
            .unwrap();
    }
    assert_eq!(wire.hits(), 4);
    let mut next = tenant_b.clone();
    next.network_generation = 8;
    assert!(
        cache
            .exchange_scoped(&exec, &wire, &req, &next, 0)
            .await
            .unwrap_err()
            .to_string()
            .contains("epoch is stale")
    );
    cache.advance_epoch(8, 9, 0);
    cache
        .exchange_scoped(&exec, &wire, &req, &next, 0)
        .await
        .unwrap();
    assert_eq!(cache.len(), 1);
    assert_eq!(wire.hits(), 5);
}

#[tokio::test]
async fn s04_bootstrap_revision_and_transport_pin_snapshot_partition_cache() {
    let req = question("www.example.com.", RecordType::A, 12);
    let wire_a = FakeWire::new(positive(&req), Some("dns.example=192.0.2.1"));
    let wire_b = FakeWire::new(positive(&req), Some("dns.example=192.0.2.2"));
    let cache = StrictDnsCache::new(6, 7, 9, 1);
    let exec = execution(
        "trusted",
        DnsEgress::Direct,
        leaf("direct"),
        "udp://192.0.2.53",
    );
    cache
        .exchange_scoped(&exec, &wire_a, &req, &ctx(&req), 1)
        .await
        .unwrap();
    cache
        .exchange_scoped(&exec, &wire_b, &req, &ctx(&req), 1)
        .await
        .unwrap();
    assert_eq!(wire_a.hits(), 1);
    assert_eq!(wire_b.hits(), 1);
    cache.advance_epoch(7, 9, 2);
    assert_eq!(cache.len(), 0);
    assert!(
        cache
            .exchange_scoped(&exec, &wire_a, &req, &ctx(&req), 1)
            .await
            .is_err()
    );
    cache
        .exchange_scoped(&exec, &wire_a, &req, &ctx(&req), 2)
        .await
        .unwrap();
    assert_eq!(wire_a.hits(), 2);
}

#[tokio::test]
async fn s04_no_cache_without_transport_fingerprint() {
    let req = question("www.example.com.", RecordType::A, 12);
    let wire = FakeWire::new(positive(&req), None);
    let cache = StrictDnsCache::new(10, 7, 9, 0);
    let exec = execution(
        "main",
        DnsEgress::Direct,
        leaf("direct"),
        "udp://192.0.2.53",
    );
    for _ in 0..2 {
        cache
            .exchange_scoped(&exec, &wire, &req, &ctx(&req), 0)
            .await
            .unwrap();
    }
    assert_eq!(wire.hits(), 2);
    assert_eq!(cache.len(), 0);
}

#[tokio::test]
async fn s04_edns_dnssec_ecs_and_non_in_query_bypass_cache() {
    let req = question("www.example.com.", RecordType::A, 12);
    let wire = FakeWire::new(positive(&req), Some("pins"));
    let cache = StrictDnsCache::new(10, 7, 9, 0);
    let exec = execution(
        "main",
        DnsEgress::Direct,
        leaf("direct"),
        "udp://192.0.2.53",
    );
    for tweak in 0..4 {
        let mut context = ctx(&req);
        match tweak {
            0 => context.flags.has_edns = true,
            1 => context.flags.dnssec_ok = true,
            2 => context.ecs = Some("192.0.2.0/24".parse().unwrap()),
            3 => context.qclass = DNSClass::CH,
            _ => unreachable!(),
        }
        cache
            .exchange_scoped(&exec, &wire, &req, &context, 0)
            .await
            .unwrap();
    }
    assert_eq!(wire.hits(), 4);
    assert_eq!(cache.len(), 0);
}

#[tokio::test]
async fn s04_signed_requests_bypass_existing_positive_and_negative_cache_entries() {
    let req = question("www.example.com.", RecordType::A, 12);
    for (kind, answer) in
        [("positive", positive(&req)), ("negative", negative(&req))]
    {
        let wire = FakeWire::new(answer, Some("pins"));
        let cache = StrictDnsCache::new(4, 7, 9, 0);
        let exec = execution(
            "main",
            DnsEgress::Direct,
            leaf("direct"),
            "udp://192.0.2.53",
        );

        cache
            .exchange_scoped(&exec, &wire, &req, &ctx(&req), 0)
            .await
            .unwrap();
        assert_eq!(cache.len(), 1, "{kind} baseline must be cacheable");

        let mut signed = question("www.example.com.", RecordType::A, 55);
        add_test_signature(&mut signed);
        cache
            .exchange_scoped(&exec, &wire, &signed, &ctx(&signed), 0)
            .await
            .unwrap();
        assert_eq!(wire.hits(), 2, "{kind} signed request must bypass hit");
        assert_eq!(cache.len(), 1, "{kind} bypass must not alter cache");
    }
}

#[tokio::test]
async fn s04_signed_positive_and_negative_responses_are_never_cached() {
    let req = question("www.example.com.", RecordType::A, 12);
    for (kind, mut answer) in
        [("positive", positive(&req)), ("negative", negative(&req))]
    {
        add_test_signature(&mut answer);
        let wire = FakeWire::new(answer, Some("pins"));
        let cache = StrictDnsCache::new(4, 7, 9, 0);
        let exec = execution(
            "main",
            DnsEgress::Direct,
            leaf("direct"),
            "udp://192.0.2.53",
        );

        for _ in 0..2 {
            let response = cache
                .exchange_scoped(&exec, &wire, &req, &ctx(&req), 0)
                .await
                .unwrap();
            assert!(
                response.signature.is_some(),
                "signed response must pass through"
            );
        }
        assert_eq!(wire.hits(), 2, "{kind} signed reply must not be replayed");
        assert_eq!(cache.len(), 0, "{kind} signed reply must not be stored");
    }
}

#[tokio::test]
async fn s04_rfc2308_soa_negative_age_and_non_soas_not_cached() {
    let req = question("missing.example.com.", RecordType::A, 12);
    let wire = FakeWire::new(negative(&req), Some("pins"));
    let cache = StrictDnsCache::new(4, 7, 9, 0);
    let exec = execution(
        "main",
        DnsEgress::Direct,
        leaf("direct"),
        "udp://192.0.2.53",
    );
    cache
        .exchange_scoped(&exec, &wire, &req, &ctx(&req), 0)
        .await
        .unwrap();
    let req2 = question("missing.example.com.", RecordType::A, 55);
    let second = cache
        .exchange_scoped(&exec, &wire, &req2, &ctx(&req2), 0)
        .await
        .unwrap();
    assert_eq!(second.metadata.id, 55);
    assert_eq!(second.metadata.response_code, ResponseCode::NXDomain);
    assert!(second.authorities[0].ttl <= 18);
    assert_eq!(wire.hits(), 1);
    let mut invalid = negative(&req);
    invalid.authorities.clear();
    let separate = FakeWire::new(invalid, Some("different-pin"));
    cache
        .exchange_scoped(&exec, &separate, &req, &ctx(&req), 0)
        .await
        .unwrap();
    assert_eq!(cache.len(), 1);
}

#[test]
fn s04_expired_cached_answer_not_reused_and_capacity_is_bounded() {
    let req = question("www.example.com.", RecordType::A, 1);
    let cache = StrictDnsCache::new(1, 7, 9, 0);
    let exec = execution(
        "main",
        DnsEgress::Direct,
        leaf("direct"),
        "udp://192.0.2.53",
    );
    let wire = FakeWire::new(positive(&req), Some("pins"));
    let key = StrictDnsCache::key(&exec, &ctx(&req), &req, &wire, 0).unwrap();
    let now = Instant::now();
    cache.store(key.clone(), &req, positive(&req), now, (7, 9, 0));
    assert_eq!(cache.len(), 1);
    assert!(
        cache
            .lookup(&key, &req, now + Duration::from_secs(29), (7, 9, 0))
            .is_some()
    );
    assert!(
        cache
            .lookup(&key, &req, now + Duration::from_secs(31), (7, 9, 0))
            .is_none()
    );
    assert_eq!(cache.len(), 0);
    cache.store(key, &req, positive(&req), now, (7, 9, 0));
    let other = question("other.example.com.", RecordType::A, 3);
    let second_key =
        StrictDnsCache::key(&exec, &ctx(&other), &other, &wire, 0).unwrap();
    cache.store(second_key, &other, positive(&other), now, (7, 9, 0));
    assert_eq!(cache.len(), 1);
}

#[test]
fn s04_bootstrap_static_graph_catches_indirect_cycles_and_depth() {
    let mut graph = BootstrapGraph::default();
    let a = BootstrapNode::Profile("trusted".into());
    let b = BootstrapNode::Upstream("doh.example".into());
    let c = BootstrapNode::Proxy("proxy-node".into());
    graph.require(a.clone(), b.clone());
    graph.require(b, c.clone());
    graph.validate(4).unwrap();
    assert!(
        graph
            .validate(2)
            .unwrap_err()
            .to_string()
            .contains("depth exceeded")
    );
    graph.require(c, a);
    assert!(graph.validate(4).unwrap_err().to_string().contains("cycle"));
}

#[test]
fn s04_bootstrap_runtime_trace_detects_recursion_without_global_state() {
    let a = BootstrapNode::Profile("trusted".into());
    let b = BootstrapNode::Proxy("leaf".into());
    let first = BootstrapTrace::default().enter(a.clone(), 2).unwrap();
    let second = first.enter(b.clone(), 2).unwrap();
    assert!(
        second
            .enter(a.clone(), 4)
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
    assert!(
        second
            .enter(BootstrapNode::Upstream("dns".into()), 2)
            .unwrap_err()
            .to_string()
            .contains("depth")
    );
    let parallel = BootstrapTrace::default().enter(a, 2).unwrap();
    assert!(
        parallel.enter(b, 2).is_ok(),
        "independent requests cannot share a global recursion stack"
    );
}

struct PausedWire {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    reply: Message,
}

#[async_trait]
impl DnsStrictTransport for PausedWire {
    fn isolation_fingerprint(&self) -> Option<String> {
        Some("pins-v1".into())
    }
    async fn exchange(
        &self,
        _: &NameServer,
        _: AnyOutboundHandler,
        request: &Message,
    ) -> io::Result<Message> {
        if let Some(tx) = self.entered.lock().unwrap().take() {
            let _ = tx.send(());
        }
        if let Some(rx) = self.release.lock().await.take() {
            let _ = rx.await;
        }
        let mut response = self.reply.clone();
        response.metadata.id = request.metadata.id;
        response.queries = request.queries.clone();
        Ok(response)
    }
}

#[tokio::test]
async fn s04_inflight_old_network_answer_is_discarded_on_generation_change() {
    let req = question("www.example.com.", RecordType::A, 17);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let wire = PausedWire {
        entered: Mutex::new(Some(entered_tx)),
        release: tokio::sync::Mutex::new(Some(release_rx)),
        reply: positive(&req),
    };
    let cache = Arc::new(StrictDnsCache::new(8, 7, 9, 1));
    let running = cache.clone();
    let job = tokio::spawn(async move {
        let exec = execution(
            "main",
            DnsEgress::Direct,
            leaf("direct"),
            "udp://192.0.2.53",
        );
        running
            .exchange_scoped(&exec, &wire, &req, &ctx(&req), 1)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    cache.advance_epoch(8, 9, 1);
    release_tx.send(()).unwrap();
    let err = job.await.unwrap().unwrap_err().to_string();
    assert!(err.contains("discarding old answer"), "{err}");
    assert_eq!(cache.len(), 0);
}

#[tokio::test]
async fn s04_a_and_aaaa_cache_questions_are_separate() {
    use hickory_proto::rr::rdata::AAAA;
    use std::net::Ipv6Addr;
    let a = question("dual.example.com.", RecordType::A, 1);
    let aaaa = question("dual.example.com.", RecordType::AAAA, 2);
    let wire_a = FakeWire::new(positive(&a), Some("pins"));
    let mut answer6 = Message::response(aaaa.metadata.id, OpCode::Query);
    answer6.add_queries(aaaa.queries.iter().cloned());
    answer6.add_answer(Record::from_rdata(
        aaaa.queries[0].name().clone(),
        23,
        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
    ));
    let wire_aaaa = FakeWire::new(answer6, Some("pins"));
    let exec =
        execution("main", DnsEgress::Direct, leaf("leaf"), "udp://192.0.2.53");
    let cache = StrictDnsCache::new(8, 7, 9, 0);
    cache
        .exchange_scoped(&exec, &wire_a, &a, &ctx(&a), 0)
        .await
        .unwrap();
    cache
        .exchange_scoped(&exec, &wire_aaaa, &aaaa, &ctx(&aaaa), 0)
        .await
        .unwrap();
    assert_eq!(cache.len(), 2);
    cache
        .exchange_scoped(&exec, &wire_a, &a, &ctx(&a), 0)
        .await
        .unwrap();
    assert_eq!(wire_a.hits(), 1);
    assert_eq!(wire_aaaa.hits(), 1);
}
