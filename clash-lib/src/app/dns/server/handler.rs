use super::DEFAULT_DNS_SERVER_TTL;
use crate::app::dns::{ThreadSafeDNSResolver, helper::build_dns_response_message};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        RData, Record,
        rdata::{A, AAAA},
    },
};
use tracing::debug;

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
            res.metadata.response_code = ResponseCode::NXDomain;
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
        exchange_with_resolver, should_filter_aaaa, should_resolve_fake_ip,
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
        resolver
            .expect_should_fake_ip()
            .with(mockall::predicate::eq("private.example"))
            .once()
            .return_const(true);
        resolver.expect_exchange().never();

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response = exchange_with_resolver(&resolver, &request, true)
            .await
            .expect("multi-question fake-IP DNS message should be answered locally");

        assert!(response.answers.is_empty());
        assert_eq!(response.queries.len(), 2);
    }
}
