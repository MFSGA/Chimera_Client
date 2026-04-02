use super::DEFAULT_DNS_SERVER_TTL;
use crate::app::dns::{ThreadSafeDNSResolver, helper::build_dns_response_message};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, rdata::A},
};
use tracing::debug;

fn normalize_upstream_response(
    req: &Message,
    mut res: Message,
) -> Message {
    if res.id() != req.id() {
        debug!(
            request_id = req.id(),
            upstream_response_id = res.id(),
            "normalizing upstream dns response id to match request"
        );
        res.set_id(req.id());
    }

    if res.queries().is_empty() {
        res.add_queries(req.queries().iter().cloned());
    }

    res
}

pub async fn exchange_with_resolver<'a>(
    resolver: &'a ThreadSafeDNSResolver,
    req: &'a Message,
    enhanced: bool,
) -> Result<Message, chimera_dns::DNSError> {
    if req.query().map(|q| q.query_type())
        == Some(hickory_proto::rr::RecordType::AAAA)
        || !resolver.fake_ip_enabled()
    {
        return match resolver.exchange(req).await {
            Ok(m) => Ok(normalize_upstream_response(req, m)),
            Err(e) => {
                debug!("dns resolve error: {}", e);
                Err(chimera_dns::DNSError::QueryFailed(e.to_string()))
            }
        };
    }

    let name = req
        .query()
        .ok_or(chimera_dns::DNSError::InvalidOpQuery(
            "malformed query message".to_string(),
        ))?
        .name();

    let host = req
        .query()
        .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
        .unwrap();

    let mut res = build_dns_response_message(req, false, false);

    match resolver.resolve_v4(&host, enhanced).await {
        Ok(resp) => match resp {
            Some(ip) => {
                let rdata = RData::A(A(ip));

                let records = vec![Record::from_rdata(
                    name.clone(),
                    DEFAULT_DNS_SERVER_TTL,
                    rdata,
                )];

                res.set_response_code(ResponseCode::NoError);
                res.set_answer_count(records.len() as u16);

                res.add_answers(records);

                Ok(res)
            }
            None => {
                res.set_response_code(ResponseCode::NXDomain);
                Ok(res)
            }
        },
        Err(e) => {
            debug!("dns resolve error: {}", e);
            Err(chimera_dns::DNSError::QueryFailed(e.to_string()))
        }
    }
}
