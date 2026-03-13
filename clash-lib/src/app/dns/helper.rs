use tracing::{debug, warn};

use crate::{
    app::dns::{
        ClashResolver, ThreadSafeDNSClient,
        config::{EdnsClientSubnet, NameServer},
        dns_client::DnsClient,
        dns_client::Opts,
    },
    proxy,
};

use hickory_proto::{
    op::{Message, MessageType},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};

pub async fn make_clients(
    servers: &[NameServer],
    resolver: Option<std::sync::Arc<dyn ClashResolver>>,
    outbounds: std::collections::HashMap<
        String,
        std::sync::Arc<dyn crate::proxy::OutboundHandler>,
    >,
    edns_client_subnet: Option<EdnsClientSubnet>,
    fw_mark: Option<u32>,
    ipv6: bool,
) -> Vec<ThreadSafeDNSClient> {
    let mut rv = Vec::new();

    for server in servers {
        debug!(
            host = %server.host,
            port = server.port,
            "building nameserver"
        );

        match DnsClient::new_client(Opts {
            father: resolver.as_ref().cloned(),
            host: server.host.clone(),
            port: server.port,
            net: server.net.clone(),
            iface: server.interface.clone(),
            proxy: outbounds
                .get(server.proxy.as_deref().unwrap_or("DIRECT"))
                .cloned()
                .unwrap_or_else(|| {
                    std::sync::Arc::new(proxy::direct::Handler::new("DIRECT"))
                }),
            ecs: edns_client_subnet.clone(),
            fw_mark,
            ipv6,
        })
        .await
        {
            Ok(client) => rv.push(client),
            Err(err) => warn!(
                host = %server.host,
                port = server.port,
                err = ?err,
                "initializing dns client failed"
            ),
        }
    }

    rv
}

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
