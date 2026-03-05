use std::{collections::HashMap, sync::Arc};

use tracing::{debug, error};

use erased_serde::Serialize;

use crate::{
    Error,
    app::{
        dns::ThreadSafeDNSResolver,
        profile::ThreadSafeCacheFile,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ThreadSafeProxyProvider,
        },
    },
    config::internal::proxy::{
        OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
    },
    proxy::{
        AnyOutboundHandler, direct,
        group::selector::ThreadSafeSelectorControl,
        reject,
        utils::{DirectConnector, ProxyConnector},
        vless,
    },
};

#[cfg(feature = "hysteria")]
use crate::proxy::hysteria2;
#[cfg(feature = "trojan")]
use crate::proxy::trojan;

pub struct OutboundManager {
    /// name -> handler
    handlers: HashMap<String, AnyOutboundHandler>,
    /// name -> provider
    proxy_providers: HashMap<String, ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
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
        cache_store: ThreadSafeCacheFile,
        cwd: String,
        fw_mark: Option<u32>,
    ) -> Result<Self, Error> {
        let handlers = HashMap::new();
        let provider_registry = HashMap::new();
        let selector_control = HashMap::new();
        let proxy_manager = ProxyManager::new(dns_resolver.clone(), fw_mark);

        let mut m = Self {
            handlers,
            proxy_manager,
            selector_control,
            proxy_providers: provider_registry,
        };

        debug!("initializing proxy providers");
        m.load_proxy_providers(cwd, proxy_providers, dns_resolver)
            .await?;

        debug!("todo initializing handlers");
        /* m.load_handlers(outbounds, outbound_groups, proxy_names, cache_store)
        .await?; */

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

    /// Get all proxies in the manager, excluding those in providers.
    pub async fn get_proxies(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = HashMap::new();

        let proxy_manager = &self.proxy_manager;

        for (k, v) in self.handlers.iter() {
            let mut m = if let Some(g) = v.try_as_group_handler() {
                g.as_map().await
            } else {
                let mut m = HashMap::new();
                m.insert("type".to_string(), Box::new(v.proto()) as _);
                m
            };

            let alive = proxy_manager.alive(k).await;
            let history = proxy_manager.delay_history(k).await;
            let support_udp = v.support_udp().await;

            m.insert("history".to_string(), Box::new(history));
            m.insert("alive".to_string(), Box::new(alive));
            m.insert("name".to_string(), Box::new(k.to_owned()));
            m.insert("udp".to_string(), Box::new(support_udp));

            r.insert(k.clone(), Box::new(m) as _);
        }

        r
    }

    fn load_handlers(
        &mut self,
        outbounds: Vec<AnyOutboundHandler>,
    ) -> Result<(), Error> {
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

    pub fn load_plain_outbounds(
        outbounds: Vec<OutboundProxyProtocol>,
    ) -> Vec<AnyOutboundHandler> {
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
                #[cfg(feature = "hysteria")]
                OutboundProxyProtocol::Hysteria2(v) => {
                    let name = v.name.clone();
                    v.try_into()
                        .map(|x: hysteria2::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!(
                                "failed to load hysteria2 outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
                OutboundProxyProtocol::Vless(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: vless::Handler| Arc::new(x) as AnyOutboundHandler)
                        .inspect_err(|e| {
                            error!("failed to load vless outbound {}: {}", name, e);
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
                let outbound = self.get_outbound(connector_name).ok_or(
                    Error::InvalidConfig(format!(
                        "connector {connector_name} not found"
                    )),
                )?;
                let connector =
                    connectors.entry(connector_name).or_insert_with(|| {
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

    async fn load_proxy_providers(
        &mut self,
        cwd: String,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<(), Error> {
        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        for (name, provider) in proxy_providers.into_iter() {
            match provider {
                OutboundProxyProviderDef::Http(http) => {
                    todo!()
                }
                OutboundProxyProviderDef::File(file) => {
                    todo!()
                }
            }
        }

        for p in provider_registry.values() {
            todo!()
        }

        Ok(())
    }
}
