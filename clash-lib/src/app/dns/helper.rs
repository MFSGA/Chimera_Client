use hickory_proto::{
    op::{Message, MessageType},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};

pub fn build_dns_response_message(
    req: &Message,
    recursive_available: bool,
    authoritative: bool,
) -> Message {
    let mut res = Message::new();

    res.set_id(req.id());
    res.set_op_code(req.op_code());
    res.set_message_type(MessageType::Response);
    res.add_queries(req.queries().iter().cloned());
    res.set_recursion_available(recursive_available);
    res.set_authoritative(authoritative);
    res.set_recursion_desired(req.recursion_desired());
    res.set_checking_disabled(req.checking_disabled());
    if let Some(edns) = req.extensions().clone() {
        res.set_edns(edns);
    }

    if let Some(edns) = res.extensions_mut() {
        edns.options_mut()
            .remove(hickory_proto::rr::rdata::opt::EdnsCode::Padding);
    }

    res
}

pub fn ip_records(
    name: hickory_proto::rr::Name,
    ttl: u32,
    query_type: RecordType,
    ips: &[std::net::IpAddr],
) -> Vec<Record> {
    ips.iter()
        .filter_map(|ip| match (query_type, ip) {
            (RecordType::A, std::net::IpAddr::V4(ip)) => {
                Some(Record::from_rdata(name.clone(), ttl, RData::A(A(*ip))))
            }
            (RecordType::AAAA, std::net::IpAddr::V6(ip)) => Some(
                Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(*ip))),
            ),
            _ => None,
        })
        .collect()
}
