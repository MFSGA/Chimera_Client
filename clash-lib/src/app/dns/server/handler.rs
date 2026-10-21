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

async fn should_skip_fake_ip_upstream(
    req: &Message,
    resolver: &ThreadSafeDNSResolver,
) -> bool {
    // HTTPS/SVCB and other record types also reveal the queried hostname.
    // DNS messages can contain multiple questions. Check all of them so a
    // later non-A question cannot leak merely because the first question is A.
    for query in &req.queries {
        let query_type = query.query_type();
        if query_type == hickory_proto::rr::RecordType::A
            || (query_type == hickory_proto::rr::RecordType::AAAA
                && resolver.fake_ip_v6_enabled())
        {
            continue;
        }
        if resolver
            .should_fake_ip(query.name().to_ascii().trim_end_matches('.'))
            .await
        {
            return true;
        }
    }

    false
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

    if should_filter_aaaa(req, resolver.ipv6())
        || should_skip_fake_ip_upstream(req, resolver).await
    {
        return Ok(build_dns_response_message(req, false, false));
    }

    if !should_resolve_fake_ip(
        req,
        resolver.fake_ip_enabled(),
        resolver.fake_ip_v6_enabled(),
    ) {
        return match resolver.exchange(req).await {
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
    use std::sync::Arc;

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };

    use crate::app::dns::{MockClashResolver, ThreadSafeDNSResolver};

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
