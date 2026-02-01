use std::{collections::HashMap, sync::Arc};

use tracing::{debug, error};

use crate::{
    Error,
    app::{
        dns::ThreadSafeDNSResolver, profile::ThreadSafeCacheFile,
        remote_content_manager::ProxyManager,
    },
    config::internal::proxy::{
        OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
    },
    proxy::{
        AnyOutboundHandler, direct, reject,
        utils::{DirectConnector, ProxyConnector},
    },
};

#[cfg(feature = "snell")]
use crate::proxy::snell;
#[cfg(feature = "trojan")]
use crate::proxy::trojan;

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
    proxy_manager: ProxyManager,
    // proxy_names: Vec<String>,
}

pub type ThreadSafeOutboundManager = Arc<OutboundManager>;

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
#[allow(clippy::too_many_arguments)]
impl OutboundManager {
    pub async fn new(
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        proxy_names: Vec<String>,
        dns_resolver: ThreadSafeDNSResolver,
        _cache_store: ThreadSafeCacheFile,
        _cwd: String,
        // fw_mark: Option<u32>,
    ) -> Result<Self, Error> {
        let handlers = HashMap::new();

        let proxy_manager = ProxyManager::new(dns_resolver.clone());

        let mut m = Self {
            handlers,
            proxy_manager,
            // selector_control,
            // proxy_providers: provider_registry,
        };

        if !proxy_providers.is_empty() {
            return Err(Error::InvalidConfig(
                "proxy providers are not supported yet".to_string(),
            ));
        }

        if !outbound_groups.is_empty() {
            return Err(Error::InvalidConfig(
                "proxy groups are not supported yet".to_string(),
            ));
        }

        m.load_handlers(outbounds)?;

        debug!("initializing connectors");
        m.init_handler_connectors().await?;

        Ok(m)
    }

    pub fn get_outbound(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(name).cloned()
    }

    pub fn proxy_names(&self) -> &[String] {
        todo!()
        // &self.proxy_names
    }

    fn load_handlers(&mut self, outbounds: Vec<AnyOutboundHandler>) -> Result<(), Error> {
        for outbound in outbounds {
            let name = outbound.name().to_string();
            if self.handlers.contains_key(&name) {
                return Err(Error::InvalidConfig(format!(
                    "duplicated proxy name: {name}"
                )));
            }
            self.handlers.insert(name, outbound);
        }

        Ok(())
    }

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
                #[cfg(feature = "trojan")]
                OutboundProxyProtocol::Trojan(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: trojan::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load trojan outbound {}: {}", name, e);
                        })
                        .ok()
                }
                #[cfg(feature = "snell")]
                OutboundProxyProtocol::Snell(s) => {
                    let name = s.common_opts.name.clone();
                    snell::Handler::try_from(&s)
                        .map(|x| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load snell outbound {}: {}", name, e);
                        })
                        .ok()
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

    /// Lazy initialization of connectors for each handler.
    async fn init_handler_connectors(&self) -> Result<(), Error> {
        let mut connectors = HashMap::new();
        for handler in self.handlers.values() {
            if let Some(connector_name) = handler.support_dialer() {
                let outbound = self
                    .get_outbound(connector_name)
                    .ok_or(Error::InvalidConfig(format!(
                        "connector {connector_name} not found"
                    )))?;
                let connector = connectors.entry(connector_name).or_insert_with(|| {
                    Arc::new(ProxyConnector::new(
                        outbound,
                        Box::new(DirectConnector::new()),
                    ))
                });
                handler.register_connector(connector.clone()).await;
            }
        }

        Ok(())
    }
}
