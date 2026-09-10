use super::DEFAULT_DNS_SERVER_TTL;
use crate::app::dns::{ThreadSafeDNSResolver, helper::build_dns_response_message};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, rdata::A},
};
use tracing::debug;

fn should_filter_aaaa(req: &Message, ipv6_enabled: bool) -> bool {
    !ipv6_enabled
        && req.queries.first().map(|query| query.query_type())
            == Some(hickory_proto::rr::RecordType::AAAA)
}

fn should_resolve_fake_ip(req: &Message, fake_ip_enabled: bool) -> bool {
    fake_ip_enabled
        && req.queries.first().map(|query| query.query_type())
            == Some(hickory_proto::rr::RecordType::A)
}

pub async fn exchange_with_resolver<'a>(
    resolver: &'a ThreadSafeDNSResolver,
    req: &'a Message,
    enhanced: bool,
) -> Result<Message, chimera_dns::DNSError> {
    if should_filter_aaaa(req, resolver.ipv6()) {
        return Ok(build_dns_response_message(req, false, false));
    }

    if !should_resolve_fake_ip(req, resolver.fake_ip_enabled()) {
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

    match resolver.resolve_v4(&host, enhanced).await {
        Ok(resp) => match resp {
            Some(ip) => {
                let rdata = RData::A(A(ip));

                let records =
                    vec![Record::from_rdata(name, DEFAULT_DNS_SERVER_TTL, rdata)];

                res.metadata.response_code = ResponseCode::NoError;
                res.add_answers(records);

                Ok(res)
            }
            None => {
                res.metadata.response_code = ResponseCode::NXDomain;
                Ok(res)
            }
        },
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
        assert!(should_resolve_fake_ip(&query(RecordType::A), true));
        assert!(!should_resolve_fake_ip(&query(RecordType::AAAA), true));
        assert!(!should_resolve_fake_ip(&query(RecordType::TXT), true));
        assert!(!should_resolve_fake_ip(&query(RecordType::A), false));
    }

    #[tokio::test]
    async fn non_a_queries_use_upstream_in_fake_ip_mode() {
        let mut resolver = MockClashResolver::new();
        resolver.expect_ipv6().return_const(true);
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_exchange()
            .once()
            .returning(|_| Ok(Message::response(0, OpCode::Query)));

        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let response =
            exchange_with_resolver(&resolver, &query(RecordType::TXT), true)
                .await
                .expect("TXT query should use the upstream resolver");

        assert!(response.answers.is_empty());
    }
}
