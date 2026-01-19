use std::sync::Arc;

use crate::{
    config::internal::proxy::OutboundProxyProtocol,
    proxy::{AnyOutboundHandler, direct, reject},
};

pub struct OutboundManager {}

/// Init process:
/// 1. Load all plaint outbounds from config using the unbounded function
///    `load_plain_outbounds`, so that any bootstrap proxy can be used to
///    download datasets
/// 2. Load all proxy providers from config, this should happen before loading
///    groups as groups my reference providers with `use_provider`
/// 3. Finally load all groups, and create `PlainProvider` for each explicit
///    referenced proxies in each group and register them in the
///    `proxy_providers` map.
/// 4. Create a `PlainProvider` for the global proxy set, which is the GLOBAL
///    selector, which should contain all plain outbound + provider proxies +
///    groups
///
/// Note that the `PlainProvider` is a special provider that contains plain
/// proxies for API compatibility with actual remote providers.
/// TODO: refactor this giant class
impl OutboundManager {
    pub fn load_plain_outbounds(outbounds: Vec<OutboundProxyProtocol>) -> Vec<AnyOutboundHandler> {
        outbounds
            .into_iter()
            .filter_map(|outbound| match outbound {
                OutboundProxyProtocol::Direct(d) => {
                    Some(Arc::new(direct::Handler::new(&d.name)) as _)
                }
                OutboundProxyProtocol::Reject(r) => {
                    Some(Arc::new(reject::Handler::new(&r.name)) as _)
                }
                // todo: support more outbound protocols
                _ => {
                    todo!(
                        "unsupported outbound protocol in plain outbound: {:?}",
                        outbound
                    )
                }
            })
            .collect()
    }
}
