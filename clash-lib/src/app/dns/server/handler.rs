use super::DEFAULT_DNS_SERVER_TTL;
use crate::app::dns::{ThreadSafeDNSResolver, helper::build_dns_response_message};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        RData, Record,
        rdata::{A, AAAA, PTR},
    },
};
use std::net::{IpAddr, Ipv4Addr};
use tracing::debug;

/// An IPv4 PTR question uses reverse-order decimal octets. Only names under
/// in-addr.arpa are candidates for a synthetic Fake-IP reverse answer.
fn ipv4_from_ptr_name(name: &str) -> Option<Ipv4Addr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let reversed = name.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<_> = reversed.split('.').collect();
    let [d, c, b, a] = parts.as_slice() else {
        return None;
    };
    Some(Ipv4Addr::new(
        a.parse().ok()?,
        b.parse().ok()?,
        c.parse().ok()?,
        d.parse().ok()?,
    ))
}

async fn fake_ip_ptr_response(
    req: &Message,
    resolver: &ThreadSafeDNSResolver,
) -> Option<Message> {
    let question = req.queries.first()?;
    if question.query_type() != hickory_proto::rr::RecordType::PTR
        || !resolver.fake_ip_enabled()
    {
        return None;
    }
    let ip = IpAddr::V4(ipv4_from_ptr_name(&question.name().to_ascii())?);
    if !resolver.is_fake_ip(ip).await {
        return None;
    }
    let mut response = build_dns_response_message(req, false, false);
    if let Some(domain) = resolver.reverse_lookup(ip).await {
        let target = hickory_proto::rr::Name::from_ascii(format!(
            "{}.",
            domain.trim_end_matches('.')
        ))
        .ok()?;
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            DEFAULT_DNS_SERVER_TTL,
            RData::PTR(PTR(target)),
        ));
    }
    Some(response)
}

/// Build a DNS protocol error for hijacked requests. Keep the original
/// transaction ID and EDNS metadata; a malformed multi-question response
/// deliberately contains no echoed questions, like chimera-dns's listener.
pub(crate) fn dns_error_response(req: &Message, code: ResponseCode) -> Message {
    let mut response = build_dns_response_message(req, false, false);
    response.metadata.response_code = code;
    if code == ResponseCode::FormErr {
        response.queries.clear();
    }
    response
}

fn should_filter_aaaa(req: &Message, ipv6_enabled: bool) -> bool {
    !ipv6_enabled
        && req.queries.first().map(|query| query.query_type())
            == Some(hickory_proto::rr::RecordType::AAAA)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FakeIpQueryHandling {
    Normal,
    Suppress,
    SafeSrv,
}

fn fake_ip_filter_name(query: &hickory_proto::op::Query) -> String {
    let name = query.name().to_ascii().trim_end_matches('.').to_string();
    if query.query_type() != hickory_proto::rr::RecordType::SRV {
        return name;
    }

    let mut labels = name.splitn(3, '.');
    let Some(service) = labels.next() else {
        return name;
    };
    let Some(protocol) = labels.next() else {
        return name;
    };
    let Some(domain) = labels.next() else {
        return name;
    };

    // SRV owner names prepend _service._protocol to the domain whose
    // Fake-IP filter should govern service discovery.
    if service.starts_with('_') && protocol.starts_with('_') {
        domain.to_string()
    } else {
        name
    }
}

async fn fake_ip_query_handling(
    req: &Message,
    resolver: &ThreadSafeDNSResolver,
) -> FakeIpQueryHandling {
    // HTTPS/SVCB and other record types also reveal the queried hostname.
    // DNS messages can contain multiple questions. Check all of them so a
    // later non-A question cannot leak merely because the first question is A.
    for query in &req.queries {
        let query_type = query.query_type();
        let safe_srv_request = query_type == hickory_proto::rr::RecordType::SRV
            && resolver.safe_srv_enabled();
        if query_type == hickory_proto::rr::RecordType::A
            || (query_type == hickory_proto::rr::RecordType::AAAA
                && resolver.fake_ip_v6_enabled())
        {
            continue;
        }
        let filter_name = if safe_srv_request {
            fake_ip_filter_name(query)
        } else {
            query.name().to_ascii().trim_end_matches('.').to_string()
        };
        if resolver.should_fake_ip(&filter_name).await {
            if safe_srv_request {
                return FakeIpQueryHandling::SafeSrv;
            }
            return FakeIpQueryHandling::Suppress;
        }
    }

    FakeIpQueryHandling::Normal
}

fn strip_unsafe_srv_additionals(req: &Message, mut response: Message) -> Message {
    use hickory_proto::rr::RecordType;

    let has_address_additional = response.additionals.iter().any(|record| {
        matches!(record.record_type(), RecordType::A | RecordType::AAAA)
    });
    if !has_address_additional {
        // Signed messages must pass through untouched when there is nothing
        // to sanitize; changing their sections would invalidate signatures.
        return response;
    }

    let dnssec_requested = req.metadata.authentic_data
        || req.metadata.checking_disabled
        || req.signature.is_some()
        || req.edns.as_ref().is_some_and(|edns| edns.flags().dnssec_ok);
    let dnssec_response = response.metadata.authentic_data
        || response.signature.is_some()
        || response
            .all_sections()
            .any(|record| record.record_type() == RecordType::RRSIG);
    if dnssec_requested || dnssec_response {
        return dns_error_response(req, ResponseCode::ServFail);
    }

    response.additionals.retain(|record| {
        !matches!(record.record_type(), RecordType::A | RecordType::AAAA)
    });
    response
}

fn should_resolve_fake_ip(
    req: &Message,
    fake_ip_enabled: bool,
    fake_ip_v6_enabled: bool,
) -> bool {
    match req.queries.first().map(|query| query.query_type()) {
        Some(hickory_proto::rr::RecordType::A) => fake_ip_enabled,
        Some(hickory_proto::rr::RecordType::AAAA) => fake_ip_v6_enabled,
        _ => false,
    }
}

pub async fn exchange_with_resolver<'a>(
    resolver: &'a ThreadSafeDNSResolver,
    req: &'a Message,
    enhanced: bool,
) -> Result<Message, chimera_dns::DNSError> {
    // RFC 1035 queries normally carry one question. The DNS listener already
    // rejects multiple questions; TUN hijack must enforce the same contract.
    if req.queries.len() != 1 {
        return Ok(dns_error_response(req, ResponseCode::FormErr));
    }

    if let Some(answer) = fake_ip_ptr_response(req, resolver).await {
        return Ok(answer);
    }

    if should_filter_aaaa(req, resolver.ipv6()) {
        return Ok(build_dns_response_message(req, false, false));
    }

    let fake_ip_handling = fake_ip_query_handling(req, resolver).await;
    if fake_ip_handling == FakeIpQueryHandling::Suppress {
        return Ok(build_dns_response_message(req, false, false));
    }

    let safe_srv_request = fake_ip_handling == FakeIpQueryHandling::SafeSrv;
    if safe_srv_request
        || !should_resolve_fake_ip(
            req,
            resolver.fake_ip_enabled(),
            resolver.fake_ip_v6_enabled(),
        )
    {
        return match resolver.exchange(req).await {
            Ok(m) if safe_srv_request => Ok(strip_unsafe_srv_additionals(req, m)),
            Ok(m) => Ok(m),
            Err(e) => {
                debug!("dns resolve error: {}", e);
                Err(chimera_dns::DNSError::QueryFailed(e.to_string()))
            }
        };
    }

    let name = req
        .queries
        .first()
        .ok_or(chimera_dns::DNSError::InvalidOpQuery(
            "malformed query message".to_string(),
        ))?
        .name()
        .clone();

    let host = req
        .queries
        .first()
        .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
        .unwrap();

    let mut res = build_dns_response_message(req, false, false);

    let answer = match req.queries.first().map(|query| query.query_type()) {
        Some(hickory_proto::rr::RecordType::A) => resolver
            .resolve_v4(&host, enhanced)
            .await
            .map(|ip| ip.map(|ip| RData::A(A(ip)))),
        Some(hickory_proto::rr::RecordType::AAAA) => resolver
            .resolve_v6(&host, enhanced)
            .await
            .map(|ip| ip.map(|ip| RData::AAAA(AAAA(ip)))),
        _ => unreachable!("only A and AAAA questions receive fake IPs"),
    };

    match answer {
        Ok(Some(rdata)) => {
            let records =
                vec![Record::from_rdata(name, DEFAULT_DNS_SERVER_TTL, rdata)];
            res.metadata.response_code = ResponseCode::NoError;
            res.add_answers(records);
            Ok(res)
        }
        Ok(None) => {
            // A missing address-family record is NODATA, not NXDOMAIN: the
            // hostname can still exist in hosts or in another record type.
            res.metadata.response_code = ResponseCode::NoError;
            Ok(res)
        }
        Err(e) => {
            debug!("dns resolve error: {}", e);
            Err(chimera_dns::DNSError::QueryFailed(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RecordType},
    };

    use crate::{
        app::dns::{
            MockClashResolver, ThreadSafeDNSResolver,
            fakeip::{FakeDns, InMemStore, Opts},
        },
        common::trie,
    };

    use super::{
        dns_error_response, exchange_with_resolver, should_filter_aaaa,
        should_resolve_fake_ip,
    };

    fn query(record_type: RecordType) -> Message {
        let mut message = Message::new(0, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            record_type,
        ));
        message
    }

    fn fake_dns_with_filter(rule: &str) -> FakeDns {
        let mut skipped_hostnames = trie::StringTrie::new();
        skipped_hostnames.insert(rule, Arc::new(true));
        FakeDns::new(Opts {
            ipnet: "198.18.0.0/16".parse().unwrap(),
            skipped_hostnames: Some(skipped_hostnames),
            store: Box::new(InMemStore::new(1)),
        })
        .unwrap()
    }

    #[test]
    fn filters_aaaa_when_ipv6_is_disabled() {
        assert!(should_filter_aaaa(&query(RecordType::AAAA), false));
    }

    #[test]
    fn keeps_aaaa_when_ipv6_is_enabled() {
        assert!(!should_filter_aaaa(&query(RecordType::AAAA), true));
    }

    #[test]
    fn keeps_ipv4_queries_when_ipv6_is_disabled() {
        assert!(!should_filter_aaaa(&query(RecordType::A), false));
    }

    #[test]
    fn fake_ip_is_only_used_for_a_queries() {
        assert!(should_resolve_fake_ip(&query(RecordType::A), true, false));
        assert!(!should_resolve_fake_ip(
            &query(RecordType::AAAA),
            true,
            false
        ));
        assert!(should_resolve_fake_ip(&query(RecordType::AAAA), true, true));
        assert!(!should_resolve_fake_ip(&query(RecordType::TXT), true, true));
    }

    #[tokio::test]
    async fn a_query_returns_fake_ip_without_forwarding_to_upstream() {
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver.expect_fake_ip_v6_enabled().return_const(false);
        resolver
            .expect_resolve_v4()
            .with(
                mockall::predicate::eq("example.com"),
                mockall::predicate::eq(true),
            )
            .once()
            .returning(|_, _| Ok(Some("198.18.0.7".parse().unwrap())));
        resolver.expect_exchange().never();

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response =
            exchange_with_resolver(&resolver, &query(RecordType::A), true)
                .await
                .expect("fake-IP A query should be answered locally");

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].data.to_string(), "198.18.0.7");
    }

    #[tokio::test]
    async fn non_a_queries_are_not_forwarded_for_fake_ip_domains() {
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(true);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("example.com"))
            .once()
            .return_const(true);
        resolver.expect_exchange().never();

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response =
            exchange_with_resolver(&resolver, &query(RecordType::TXT), true)
                .await
                .expect(
                    "TXT query for fake-IP domain should return an empty answer",
                );

        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn s00_legacy_srv_is_preserved_only_for_fake_ip_excluded_domains() {
        // S00 golden: SRV records contain service-discovery identity and
        // priority/weight/port. Preserve existing privacy behavior and
        // upstream-provided SRV RDATA; never silently rewrite its target.
        let qname = Name::from_ascii("_minecraft._tcp.play.example.").unwrap();
        let target = Name::from_ascii("node1.game.example.").unwrap();
        let mut request = Message::new(0x1414, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(qname.clone(), RecordType::SRV));
        let srv = hickory_proto::rr::RData::SRV(hickory_proto::rr::rdata::SRV::new(
            7, 21, 25565, target,
        ));

        for (excluded, expected_answers) in [(true, 1), (false, 0)] {
            let mut resolver = MockClashResolver::new();
            resolver.expect_ipv6().return_const(false);
            resolver.expect_safe_srv_enabled().return_const(false);
            resolver
                .expect_should_fake_ip()
                .once()
                .return_const(!excluded);
            if excluded {
                resolver.expect_fake_ip_enabled().return_const(true);
                resolver.expect_fake_ip_v6_enabled().return_const(false);
                let record = hickory_proto::rr::Record::from_rdata(
                    qname.clone(),
                    60,
                    srv.clone(),
                );
                resolver.expect_exchange().once().returning(move |query| {
                    let mut answer =
                        Message::response(query.metadata.id, query.metadata.op_code);
                    answer.add_queries(query.queries.iter().cloned());
                    answer.add_answer(record.clone());
                    Ok(answer)
                });
            } else {
                resolver.expect_exchange().never();
            }
            let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
            let response = exchange_with_resolver(&resolver, &request, true)
                .await
                .unwrap();
            assert_eq!(
                response.metadata.response_code,
                hickory_proto::op::ResponseCode::NoError
            );
            assert_eq!(response.answers.len(), expected_answers);
            if excluded {
                assert_eq!(response.answers[0].data, srv);
                assert_eq!(response.answers[0].ttl, 60);
            }
        }
    }

    fn srv_response(request: &Message) -> Message {
        use hickory_proto::rr::{RData, Record};
        use std::net::{Ipv4Addr, Ipv6Addr};

        let target = Name::from_ascii("node1.game.example.").unwrap();
        let query = &request.queries[0];
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.add_query(query.clone());
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::SRV(hickory_proto::rr::rdata::SRV::new(
                7,
                21,
                25565,
                target.clone(),
            )),
        ));
        response.add_additional(Record::from_rdata(
            target.clone(),
            30,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 45))),
        ));
        response.add_additional(Record::from_rdata(
            target,
            30,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::LOCALHOST)),
        ));
        response
    }

    // These fixtures exercise TSIG-message preservation, not MAC verification.
    fn tsig_signature(
        id: u16,
    ) -> Box<hickory_proto::rr::Record<hickory_proto::rr::rdata::TSIG>> {
        Box::new(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("key.example.").unwrap(),
            0,
            hickory_proto::rr::rdata::TSIG::new(
                hickory_proto::rr::rdata::tsig::TsigAlgorithm::HmacSha256,
                1,
                300,
                vec![1],
                id,
                None,
                vec![],
            ),
        ))
    }

    #[tokio::test]
    async fn safe_srv_mode_preserves_signed_responses_without_glue() {
        let mut request = query(RecordType::SRV);
        request.signature = Some(tsig_signature(request.metadata.id));

        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_safe_srv_enabled().return_const(true);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("example.com"))
            .once()
            .return_const(true);
        resolver.expect_exchange().once().returning(|request| {
            let mut response = srv_response(request);
            response.additionals.clear();
            response.signature = Some(tsig_signature(request.metadata.id));
            Ok(response)
        });

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect(
                "a signed response without unsafe additionals should pass through",
            );

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::SRV);
        assert!(response.additionals.is_empty());
        assert!(response.signature.is_some());
    }

    #[tokio::test]
    async fn safe_srv_mode_preserves_srv_answer_and_removes_address_additionals() {
        let request = query(RecordType::SRV);
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_safe_srv_enabled().return_const(true);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("example.com"))
            .once()
            .return_const(true);
        resolver
            .expect_exchange()
            .once()
            .returning(|request| Ok(srv_response(request)));

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect("safe SRV query should reach the configured resolver");

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::SRV);
        assert_eq!(
            response.answers[0].data,
            hickory_proto::rr::RData::SRV(hickory_proto::rr::rdata::SRV::new(
                7,
                21,
                25565,
                Name::from_ascii("node1.game.example.").unwrap(),
            ))
        );
        assert!(response.additionals.is_empty());
    }

    #[tokio::test]
    async fn safe_srv_mode_fails_closed_when_dnssec_additionals_need_sanitizing() {
        let mut request = query(RecordType::SRV);
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_dnssec_ok(true);
        request.set_edns(edns);

        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_safe_srv_enabled().return_const(true);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("example.com"))
            .once()
            .return_const(true);
        resolver
            .expect_exchange()
            .once()
            .returning(|request| Ok(srv_response(request)));

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect("unsafe DNSSEC response should become SERVFAIL");

        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(response.answers.is_empty());
        assert!(response.additionals.is_empty());
    }

    #[tokio::test]
    async fn safe_srv_mode_fails_closed_for_cd_ad_and_signed_requests() {
        for request_signal in ["checking-disabled", "authenticated-data", "tsig"] {
            let mut request = query(RecordType::SRV);
            match request_signal {
                "checking-disabled" => request.metadata.checking_disabled = true,
                "authenticated-data" => request.metadata.authentic_data = true,
                "tsig" => {
                    request.signature = Some(tsig_signature(request.metadata.id));
                }
                _ => unreachable!("test case is defined in the fixed list"),
            }

            let mut resolver = MockClashResolver::new();
            resolver.expect_ipv6().return_const(false);
            resolver.expect_safe_srv_enabled().return_const(true);
            resolver.expect_fake_ip_enabled().return_const(true);
            resolver
                .expect_should_fake_ip()
                .with(mockall::predicate::eq("example.com"))
                .once()
                .return_const(true);
            resolver
                .expect_exchange()
                .once()
                .returning(|request| Ok(srv_response(request)));

            let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
            let response = exchange_with_resolver(&resolver, &request, true)
                .await
                .expect("request authentication signals should fail closed");

            assert_eq!(
                response.metadata.response_code,
                ResponseCode::ServFail,
                "unexpected response for {request_signal}"
            );
            assert!(response.answers.is_empty());
            assert!(response.additionals.is_empty());
        }
    }

    #[tokio::test]
    async fn safe_srv_mode_fails_closed_for_authenticated_dnssec_responses() {
        let request = query(RecordType::SRV);
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_safe_srv_enabled().return_const(true);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("example.com"))
            .once()
            .return_const(true);
        resolver.expect_exchange().once().returning(|request| {
            let mut response = srv_response(request);
            response.metadata.authentic_data = true;
            Ok(response)
        });

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect("authenticated DNSSEC response should fail closed");

        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(response.answers.is_empty());
        assert!(response.additionals.is_empty());
    }

    #[tokio::test]
    async fn safe_srv_mode_fails_closed_for_rrsig_and_message_signatures() {
        for use_message_signature in [false, true] {
            let request = query(RecordType::SRV);
            let mut resolver = MockClashResolver::new();
            resolver.expect_ipv6().return_const(false);
            resolver.expect_safe_srv_enabled().return_const(true);
            resolver.expect_fake_ip_enabled().return_const(true);
            resolver
                .expect_should_fake_ip()
                .with(mockall::predicate::eq("example.com"))
                .once()
                .return_const(true);
            resolver.expect_exchange().once().returning(move |request| {
                let mut response = srv_response(request);
                if use_message_signature {
                    response.signature = Some(tsig_signature(request.metadata.id));
                } else {
                    response.add_additional(hickory_proto::rr::Record::from_rdata(
                        request.queries[0].name().clone(),
                        60,
                        hickory_proto::rr::RData::Unknown {
                            code: RecordType::RRSIG,
                            rdata: hickory_proto::rr::rdata::NULL::with(vec![1]),
                        },
                    ));
                }
                Ok(response)
            });

            let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
            let response = exchange_with_resolver(&resolver, &request, true)
                .await
                .expect("signed response requiring sanitization should fail closed");

            assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
            assert!(response.answers.is_empty());
            assert!(response.additionals.is_empty());
        }
    }

    #[tokio::test]
    async fn safe_srv_mode_keeps_filtered_domains_on_the_legacy_wire_path() {
        let request = query(RecordType::SRV);
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_safe_srv_enabled().return_const(true);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("example.com"))
            .once()
            .return_const(false);
        resolver.expect_fake_ip_v6_enabled().return_const(false);
        resolver
            .expect_exchange()
            .once()
            .returning(|request| Ok(srv_response(request)));

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect("Fake-IP-excluded SRV query should retain legacy behavior");

        assert_eq!(response.additionals.len(), 2);
        assert_eq!(response.additionals[0].record_type(), RecordType::A);
        assert_eq!(response.additionals[1].record_type(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn safe_srv_mode_applies_fake_ip_filter_to_service_domain() {
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("_minecraft._tcp.printer.lan.").unwrap(),
            RecordType::SRV,
        ));
        let fake_dns = Arc::new(Mutex::new(fake_dns_with_filter("*.lan")));

        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_safe_srv_enabled().return_const(true);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("printer.lan"))
            .once()
            .returning(move |host| !fake_dns.lock().unwrap().should_skip(host));
        resolver.expect_fake_ip_v6_enabled().return_const(false);
        resolver
            .expect_exchange()
            .once()
            .returning(|request| Ok(srv_response(request)));

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect("excluded SRV domain should retain its upstream additionals");

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.additionals.len(), 2);
        assert_eq!(response.additionals[0].record_type(), RecordType::A);
        assert_eq!(response.additionals[1].record_type(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn legacy_srv_mode_keeps_original_fake_ip_filter_lookup() {
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("_minecraft._tcp.printer.lan.").unwrap(),
            RecordType::SRV,
        ));
        let fake_dns = Arc::new(Mutex::new(fake_dns_with_filter("*.lan")));

        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_safe_srv_enabled().return_const(false);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("_minecraft._tcp.printer.lan"))
            .once()
            .returning(move |host| !fake_dns.lock().unwrap().should_skip(host));
        resolver.expect_exchange().never();

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect("legacy SRV filtering should remain unchanged");

        assert!(response.answers.is_empty());
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn https_and_svcb_queries_remain_suppressed_for_fake_ip_domains() {
        for record_type in [RecordType::HTTPS, RecordType::SVCB] {
            let mut resolver = MockClashResolver::new();
            resolver.expect_ipv6().return_const(true);
            resolver
                .expect_should_fake_ip()
                .with(mockall::predicate::eq("example.com"))
                .once()
                .return_const(true);
            resolver.expect_exchange().never();

            let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
            let response =
                exchange_with_resolver(&resolver, &query(record_type), true)
                    .await
                    .expect("unsafe service-discovery records stay suppressed");

            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.answers.is_empty());
        }
    }

    #[tokio::test]
    async fn filtered_domain_non_address_queries_reach_upstream() {
        // The actual resolver's should_fake_ip implementation consults the
        // fake-ip-filter. In this test false denotes an explicitly excluded
        // domain and must preserve the requested record type.
        for record_type in [
            RecordType::TXT,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::MX,
            RecordType::SRV,
            RecordType::CNAME,
        ] {
            let mut resolver = MockClashResolver::new();
            resolver.expect_ipv6().return_const(false);
            if record_type == RecordType::SRV {
                resolver.expect_safe_srv_enabled().return_const(false);
            }
            resolver.expect_should_fake_ip().once().return_const(false);
            resolver.expect_fake_ip_enabled().return_const(true);
            resolver.expect_fake_ip_v6_enabled().return_const(false);
            resolver
                .expect_exchange()
                .once()
                .returning(|_| Ok(Message::response(0, OpCode::Query)));
            let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
            let response =
                exchange_with_resolver(&resolver, &query(record_type), true)
                    .await
                    .expect("excluded host must be allowed to query upstream");
            assert_eq!(
                response.metadata.response_code,
                hickory_proto::op::ResponseCode::NoError
            );
        }
    }

    #[tokio::test]
    async fn shared_dns_entry_rejects_multiple_questions_without_resolver_access() {
        let mut req = query(RecordType::A);
        req.metadata.id = 0x7123;
        req.add_query(Query::query(
            Name::from_ascii("second.example.").unwrap(),
            RecordType::TXT,
        ));
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let response = exchange_with_resolver(&resolver, &req, true).await.unwrap();
        assert_eq!(response.metadata.id, req.metadata.id);
        assert_eq!(
            response.metadata.response_code,
            hickory_proto::op::ResponseCode::FormErr
        );
        assert!(response.queries.is_empty());
        assert!(response.answers.is_empty());
    }

    #[test]
    fn tun_dns_errors_preserve_transaction_and_use_servfail() {
        let mut req = query(RecordType::A);
        req.metadata.id = 0x600d;
        req.metadata.recursion_desired = true;
        let response =
            dns_error_response(&req, hickory_proto::op::ResponseCode::ServFail);
        assert_eq!(response.metadata.id, 0x600d);
        assert_eq!(
            response.metadata.response_code,
            hickory_proto::op::ResponseCode::ServFail
        );
        assert_eq!(response.queries.len(), 1);
        assert!(response.metadata.recursion_desired);
        let wire = response.to_vec().unwrap();
        let decoded = Message::from_vec(&wire).unwrap();
        assert_eq!(
            decoded.metadata.response_code,
            hickory_proto::op::ResponseCode::ServFail
        );
    }

    #[tokio::test]
    async fn allocated_fake_ipv4_ptr_returns_local_hostname_without_upstream() {
        let mut message = Message::new(0x2011, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("15.0.18.198.in-addr.arpa.").unwrap(),
            RecordType::PTR,
        ));
        let addr: std::net::IpAddr = "198.18.0.15".parse().unwrap();
        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_is_fake_ip()
            .with(mockall::predicate::eq(addr))
            .once()
            .return_const(true);
        resolver
            .expect_reverse_lookup()
            .with(mockall::predicate::eq(addr))
            .once()
            .returning(|_| Some("example.com".into()));
        resolver.expect_exchange().never();
        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);

        let response = exchange_with_resolver(&resolver, &message, true)
            .await
            .unwrap();
        assert_eq!(response.metadata.id, 0x2011);
        assert_eq!(
            response.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::PTR);
        assert_eq!(response.answers[0].data.to_string(), "example.com.");
    }

    #[tokio::test]
    async fn fake_ipv4_pool_exhaustion_is_propagated_as_dns_error() {
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(false);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver.expect_fake_ip_v6_enabled().return_const(false);
        resolver
            .expect_resolve_v4()
            .once()
            .returning(|_, _| Err(anyhow::anyhow!("fake-ip pool exhausted")));
        resolver.expect_exchange().never();
        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let err = exchange_with_resolver(&resolver, &query(RecordType::A), true)
            .await
            .expect_err("pool exhaustion must become a DNS error");
        assert!(err.to_string().contains("pool exhausted"), "{err}");
    }

    #[tokio::test]
    async fn aaaa_query_returns_fake_ipv6_when_pool_is_enabled() {
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(true);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver.expect_fake_ip_v6_enabled().return_const(true);
        resolver
            .expect_resolve_v6()
            .with(
                mockall::predicate::eq("example.com"),
                mockall::predicate::eq(true),
            )
            .once()
            .returning(|_, _| Ok(Some("fd00::5".parse().unwrap())));
        resolver.expect_exchange().never();

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response =
            exchange_with_resolver(&resolver, &query(RecordType::AAAA), true)
                .await
                .expect(
                    "AAAA query should receive fake IPv6 from the configured pool",
                );

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn aaaa_query_without_fake_ipv6_pool_is_not_forwarded() {
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(true);
        resolver.expect_fake_ip_v6_enabled().return_const(false);
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("example.com"))
            .once()
            .return_const(true);
        resolver.expect_exchange().never();

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response =
            exchange_with_resolver(&resolver, &query(RecordType::AAAA), true)
                .await
                .expect(
                    "AAAA query without fake IPv6 pool should be answered locally",
                );

        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn later_non_a_question_for_fake_ip_domain_is_not_forwarded() {
        let mut request = query(RecordType::A);
        request.add_query(Query::query(
            Name::from_ascii("private.example.").unwrap(),
            RecordType::HTTPS,
        ));

        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(true);
        resolver.expect_exchange().never();

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect("multi-question fake-IP DNS message should be answered locally");

        assert!(response.answers.is_empty());
        assert_eq!(
            response.metadata.response_code,
            hickory_proto::op::ResponseCode::FormErr
        );
        assert!(response.queries.is_empty());
    }
}
