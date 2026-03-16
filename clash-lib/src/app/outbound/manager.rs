use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::RwLock;
use tracing::{debug, error};

use erased_serde::Serialize;
use serde::Deserialize;
use serde_yaml::Value;

use crate::{
    Error,
    app::{
        dns::ThreadSafeDNSResolver,
        outbound::utils::proxy_groups_dag_sort,
        profile::ThreadSafeCacheFile,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::proxy_provider::{
                ThreadSafeProxyProvider, plain_provider::PlainProvider,
            },
        },
    },
    config::internal::proxy::{
        OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
        PROXY_DIRECT, PROXY_GLOBAL, PROXY_REJECT,
    },
    proxy::{
        AnyOutboundHandler, direct,
        group::{
            fallback,
            selector::{self, ThreadSafeSelectorControl},
            urltest,
        },
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
    proxy_names: Vec<String>,
    /// name -> provider
    proxy_providers: HashMap<String, ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
    cache_store: ThreadSafeCacheFile,
}

pub type ThreadSafeOutboundManager = Arc<OutboundManager>;
static DEFAULT_LATENCY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

#[derive(Deserialize)]
struct ProviderScheme {
    proxies: Option<Vec<HashMap<String, Value>>>,
}

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
        let proxy_names_ref = proxy_names;
        let provider_registry = HashMap::new();
        let selector_control = HashMap::new();
        let proxy_manager = ProxyManager::new(dns_resolver.clone(), fw_mark);

        let mut m = Self {
            handlers,
            proxy_names: proxy_names_ref,
            proxy_manager,
            selector_control,
            proxy_providers: provider_registry,
            cache_store: cache_store.clone(),
        };

        debug!("initializing proxy providers");
        m.load_proxy_providers(cwd, proxy_providers, dns_resolver)
            .await?;

        debug!("todo initializing handlers");
        m.load_handlers(outbounds, outbound_groups, cache_store)
            .await?;

        debug!("initializing connectors");
        m.init_handler_connectors().await?;

        Ok(m)
    }

    pub fn get_outbound(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(name).cloned()
    }

    pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }

    pub async fn select(&self, group: &str, proxy: &str) -> Result<(), Error> {
        let selector = self.selector_control.get(group).ok_or_else(|| {
            Error::Operation(format!("selector group `{group}` not found"))
        })?;
        selector.select(proxy).await?;
        self.cache_store.set_selected(group, proxy).await;
        Ok(())
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

    /// A thin wrapper so the API layer does not access proxy_manager directly.
    pub async fn url_test(
        &self,
        outbounds: &Vec<AnyOutboundHandler>,
        url: &str,
        timeout: Duration,
    ) -> Vec<std::io::Result<(Duration, Duration)>> {
        self.proxy_manager
            .check(outbounds, url, Some(timeout))
            .await
    }

    async fn load_handlers(
        &mut self,
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        self.handlers.extend(outbounds.into_iter().map(|h| {
            let name = h.name().to_owned();
            (name, h)
        }));

        self.load_group_outbounds(outbound_groups, cache_store.clone())
            .await?;

        // insert GLOBAL selector to keep behavior aligned with clash-rs bootstrap
        let mut all = vec![];
        let mut keys = self.handlers.keys().collect::<Vec<_>>();
        keys.sort_by(|a, b| {
            self.proxy_names
                .iter()
                .position(|x| x == *a)
                .cmp(&self.proxy_names.iter().position(|x| x == *b))
        });
        for name in keys {
            if let Some(handler) = self.handlers.get(name) {
                all.push(handler.clone());
            }
        }

        if !all.is_empty() {
            let hc = HealthCheck::new(
                all.clone(),
                DEFAULT_LATENCY_TEST_URL.to_owned(),
                0,
                true,
                self.proxy_manager.clone(),
            );
            let pd = Arc::new(RwLock::new(
                PlainProvider::new(PROXY_GLOBAL.to_owned(), all, hc).map_err(
                    |x| {
                        Error::InvalidConfig(format!("invalid provider config: {x}"))
                    },
                )?,
            ));
            let stored_selection = cache_store.get_selected(PROXY_GLOBAL).await;
            let selector = selector::Handler::new(
                selector::HandlerOptions {
                    name: PROXY_GLOBAL.to_owned(),
                    udp: true,
                    common_opts: crate::proxy::HandlerCommonOptions::default(),
                },
                vec![pd.clone()],
                stored_selection,
            )
            .await;

            self.handlers
                .insert(PROXY_GLOBAL.to_owned(), Arc::new(selector.clone()));
            self.selector_control
                .insert(PROXY_GLOBAL.to_owned(), Arc::new(selector));
            self.proxy_providers.insert(PROXY_GLOBAL.to_owned(), pd);
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

    async fn load_group_outbounds(
        &mut self,
        outbound_groups: Vec<OutboundGroupProtocol>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        // Sort outbound groups to ensure dependencies are resolved
        let mut outbound_groups = outbound_groups;
        proxy_groups_dag_sort(&mut outbound_groups)?;

        let handlers = &mut self.handlers;
        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        let selector_control = &mut self.selector_control;

        #[allow(clippy::too_many_arguments)]
        fn make_provider_from_proxies(
            name: &str,
            proxies: &[String],
            interval: u64,
            lazy: bool,
            handlers: &HashMap<String, AnyOutboundHandler>,
            proxy_manager: ProxyManager,
            provider_registry: &mut HashMap<String, ThreadSafeProxyProvider>,
        ) -> Result<ThreadSafeProxyProvider, Error> {
            if name == PROXY_DIRECT || name == PROXY_REJECT {
                return Err(Error::InvalidConfig(format!(
                    "proxy group name `{name}` is reserved"
                )));
            }
            let proxies = proxies
                .iter()
                .map(|x| {
                    handlers
                        .get(x)
                        .ok_or_else(|| {
                            Error::InvalidConfig(format!("proxy {x} not found"))
                        })
                        .cloned()
                })
                .collect::<Result<Vec<_>, _>>()?;

            debug!("todo creating PlainProvider for group ");

            let hc = HealthCheck::new(
                proxies.clone(),
                DEFAULT_LATENCY_TEST_URL.to_owned(),
                interval,
                lazy,
                proxy_manager,
            );

            let pd = Arc::new(RwLock::new(
                PlainProvider::new(name.to_owned(), proxies, hc).map_err(|x| {
                    Error::InvalidConfig(format!("invalid provider config: {x}"))
                })?,
            ));

            provider_registry.insert(name.to_owned(), pd.clone());

            Ok(pd)
        }

        fn check_group_empty(
            proxies: &Option<Vec<String>>,
            use_provider: &Option<Vec<String>>,
        ) -> bool {
            proxies.as_ref().map(|x| x.len()).unwrap_or_default()
                + use_provider.as_ref().map(|x| x.len()).unwrap_or_default()
                == 0
        }

        fn maybe_append_use_providers(
            provider_names: &Option<Vec<String>>,
            provider_registry: &HashMap<String, ThreadSafeProxyProvider>,
            providers: &mut Vec<ThreadSafeProxyProvider>,
        ) -> Result<(), Error> {
            if let Some(provider_names) = provider_names {
                for provider_name in provider_names {
                    let provider = provider_registry
                        .get(provider_name)
                        .cloned()
                        .ok_or_else(|| {
                            Error::InvalidConfig(format!(
                                "provider {provider_name} not found"
                            ))
                        })?;
                    providers.push(provider);
                }
            }
            Ok(())
        }

        // Initialize handlers for each outbound group protocol
        for outbound_group in outbound_groups.iter() {
            match outbound_group {
                OutboundGroupProtocol::UrlTest(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            proto.interval,
                            proto.lazy.unwrap_or_default(),
                            handlers,
                            proxy_manager.clone(),
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    );

                    let url_test = urltest::Handler::new(
                        urltest::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: Some(proto.url.clone()),
                                connector: None,
                            },
                            ..Default::default()
                        },
                        proto.tolerance.unwrap_or_default(),
                        providers,
                        proxy_manager.clone(),
                    );

                    handlers.insert(proto.name.clone(), Arc::new(url_test));
                }

                OutboundGroupProtocol::Fallback(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            proto.interval,
                            proto.lazy.unwrap_or_default(),
                            handlers,
                            proxy_manager.clone(),
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    );

                    let fallback = fallback::Handler::new(
                        fallback::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: Some(proto.url.clone()),
                                connector: None,
                            },
                            ..Default::default()
                        },
                        providers,
                        proxy_manager.clone(),
                    );

                    handlers.insert(proto.name.clone(), Arc::new(fallback));
                }

                OutboundGroupProtocol::Select(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }

                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            0,
                            true,
                            handlers,
                            proxy_manager.clone(),
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    )?;
                    let stored_selection =
                        cache_store.get_selected(&proto.name).await;

                    let selector = selector::Handler::new(
                        selector::HandlerOptions {
                            name: proto.name.clone(),
                            udp: proto.udp.unwrap_or(true),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: proto.url.clone(),
                                connector: None,
                            },
                        },
                        providers,
                        stored_selection,
                    )
                    .await;

                    handlers.insert(proto.name.clone(), Arc::new(selector.clone()));
                    selector_control.insert(proto.name.clone(), Arc::new(selector));
                }
            }
        }

        Ok(())
    }

    async fn load_proxy_providers(
        &mut self,
        cwd: String,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        _resolver: ThreadSafeDNSResolver,
    ) -> Result<(), Error> {
        let provider_registry = &mut self.proxy_providers;
        for (name, provider) in proxy_providers.into_iter() {
            match provider {
                OutboundProxyProviderDef::Http(_http) => {
                    debug!(
                        "http proxy provider `{}` is not implemented yet, skipping",
                        name
                    );
                }
                OutboundProxyProviderDef::File(file) => {
                    debug!("loading file proxy provider `{}`", name);
                    let path_buf = PathBuf::from(&file.path);
                    let path = if path_buf.is_absolute() {
                        path_buf
                    } else {
                        PathBuf::from(&cwd).join(path_buf)
                    };

                    let content = tokio::fs::read(&path).await.map_err(|e| {
                        Error::InvalidConfig(format!(
                            "failed to read file provider `{name}` from {}: {e}",
                            path.display()
                        ))
                    })?;

                    let scheme: ProviderScheme = serde_yaml::from_slice(&content).map_err(|e| {
                        Error::InvalidConfig(format!(
                            "failed to parse file provider `{name}` from {}: {e}",
                            path.display()
                        ))
                    })?;

                    let proxy_defs = scheme.proxies.ok_or_else(|| {
                        Error::InvalidConfig(format!(
                            "file provider `{name}` has empty proxies"
                        ))
                    })?;

                    let mut proxies = Vec::with_capacity(proxy_defs.len());
                    for def in proxy_defs {
                        let protocol = OutboundProxyProtocol::try_from(def)?;
                        let mut loaded = Self::load_plain_outbounds(vec![protocol]);
                        if let Some(handler) = loaded.pop() {
                            proxies.push(handler);
                        }
                    }

                    let provider = Arc::new(RwLock::new(
                        PlainProvider::new(
                            name.clone(),
                            proxies.clone(),
                            HealthCheck::new(
                                proxies,
                                DEFAULT_LATENCY_TEST_URL.to_owned(),
                                file.interval.unwrap_or_default(),
                                true,
                                self.proxy_manager.clone(),
                            ),
                        )
                        .map_err(|x| {
                            Error::InvalidConfig(format!(
                                "invalid provider config: {x}"
                            ))
                        })?,
                    ));
                    provider_registry.insert(name, provider);
                }
            }
        }

        Ok(())
    }
}
