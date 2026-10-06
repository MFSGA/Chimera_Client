use crate::{
    config::internal::proxy::PROXY_DIRECT,
    dns::{
        ClashResolver, EdnsClientSubnet, RuleDispatch, ThreadSafeDNSClient,
        dns_client::{DNSNetMode, DnsClient, Opts},
    },
    proxy::{
        self,
        utils::{NetworkPathSource, OutboundHandlerRegistry, SharedOutboundHandler},
    },
};
use hickory_proto::rr::rdata::opt::EdnsCode;
use std::sync::Arc;
use tracing::{debug, warn};

use super::config::NameServer;

#[derive(Clone, Default)]
pub(crate) struct DnsClientNetworkOptions {
    pub fw_mark: Option<u32>,
    pub rule_dispatch: Option<Arc<RuleDispatch>>,
    pub network_path_source: Option<NetworkPathSource>,
}

pub async fn make_clients(
    servers: Vec<NameServer>,
    resolver: Option<Arc<dyn ClashResolver>>,
    outbound_resolver: Option<Arc<dyn ClashResolver>>,
    outbounds: OutboundHandlerRegistry,
    edns_client_subnet: Option<EdnsClientSubnet>,
    network_options: DnsClientNetworkOptions,
) -> Result<Vec<ThreadSafeDNSClient>, crate::Error> {
    let mut rv = Vec::new();
    let had_configured_servers = !servers.is_empty();

    for s in servers {
        debug!("building nameserver: {}", s);

        let proxy_name = s.proxy.clone().unwrap_or(PROXY_DIRECT.to_string());
        let proxy: Arc<dyn proxy::OutboundHandler> =
            Arc::new(SharedOutboundHandler::new(proxy_name, outbounds.clone()));

        // An explicit `#proxy=...` always wins; rule-engine routing is only
        // applied to nameservers that use the default DIRECT path.
        let rd = if s.proxy.is_none() {
            network_options.rule_dispatch.clone()
        } else {
            None
        };

        let port = if s.net == DNSNetMode::Dhcp { 0 } else { s.port };

        match DnsClient::new_client(Opts {
            father: resolver.as_ref().cloned(),
            outbound_resolver: outbound_resolver.as_ref().cloned(),
            host: s.host.clone(),
            port,
            net: s.net.to_owned(),
            // Unspecified bindings follow the current default at each dial.
            // Capturing the default here would pin DNS to the startup network.
            iface: s
                .interface
                .as_ref()
                .inspect(|x| debug!("DNS client interface: {:?}", x))
                .cloned(),
            proxy,
            ecs: edns_client_subnet.clone(),
            doh_path: s.doh_path.clone(),
            fw_mark: network_options.fw_mark,
            rule_dispatch: rd,
            network_path_source: network_options.network_path_source.clone(),
        })
        .await
        {
            Ok(c) => rv.push(c),
            Err(e) if s.net == DNSNetMode::Dhcp => {
                return Err(crate::Error::InvalidConfig(format!(
                    "initializing DHCP DNS client {s}: {e}"
                )));
            }
            Err(e) => warn!("initializing DNS client {} with error {}", &s, e),
        }
    }

    if had_configured_servers && rv.is_empty() {
        return Err(crate::Error::InvalidConfig(
            "DNS upstream configuration contains no usable clients".into(),
        ));
    }

    Ok(rv)
}

pub fn build_dns_response_message(
    req: &hickory_proto::op::Message,
    recursive_available: bool,
    authoritative: bool,
) -> hickory_proto::op::Message {
    let mut res =
        hickory_proto::op::Message::response(req.metadata.id, req.metadata.op_code);

    res.metadata.recursion_available = recursive_available;
    res.metadata.authoritative = authoritative;
    res.metadata.recursion_desired = req.metadata.recursion_desired;
    res.metadata.checking_disabled = req.metadata.checking_disabled;

    res.add_queries(req.queries.iter().cloned());

    if let Some(edns) = req.edns.clone() {
        res.set_edns(edns);
    }

    if let Some(edns) = res.edns.as_mut() {
        // Remove only padding options, keep everything else
        edns.options_mut().remove(EdnsCode::Padding);
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;

    #[tokio::test]
    async fn all_unresolvable_upstreams_return_a_configuration_error() {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve()
            .with(
                mockall::predicate::eq("unresolvable.example"),
                mockall::predicate::eq(false),
            )
            .once()
            .returning(|_, _| Ok(None));

        let result = make_clients(
            vec![NameServer {
                net: DNSNetMode::Udp,
                host: url::Host::Domain("unresolvable.example".to_owned()),
                port: 53,
                interface: None,
                proxy: None,
                doh_path: None,
            }],
            Some(Arc::new(resolver)),
            None,
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            None,
            DnsClientNetworkOptions::default(),
        )
        .await;

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("all unusable upstreams must fail initialization"),
        };
        assert!(error.to_string().contains("no usable clients"));
    }
}
