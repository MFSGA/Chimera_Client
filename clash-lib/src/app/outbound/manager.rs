use std::{
    collections::{HashMap, HashSet},
    io,
    path::PathBuf,
    sync::{Arc, Weak},
    time::Duration,
};

use futures::StreamExt;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info};
use uuid::Uuid;

use erased_serde::Serialize;

use crate::{
    Error,
    app::{
        dns::ThreadSafeDNSResolver,
        outbound::utils::proxy_groups_dag_sort,
        profile::ThreadSafeCacheFile,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::{
                ProviderVehicleType, ThreadSafeProviderVehicle, file_vehicle,
                http_vehicle,
                proxy_provider::{
                    ThreadSafeProxyProvider, plain_provider::PlainProvider,
                    proxy_set_provider::ProxySetProvider,
                },
            },
        },
    },
    config::internal::proxy::{
        HealthCheckProbe, OutboundGroupProtocol, OutboundProxyProtocol,
        OutboundProxyProviderDef, PROXY_DIRECT, PROXY_GLOBAL, PROXY_REJECT,
    },
    proxy::{
        AnyOutboundHandler, direct,
        group::{
            fallback, loadbalance, relay,
            selector::{self, ThreadSafeSelectorControl},
            smart, urltest,
        },
        reject, socks,
        utils::{
            DirectConnector, NetworkPathSource, OutboundHandlerRegistry,
            ProxyConnector,
        },
        vless,
    },
};

static RESERVED_PROVIDER_NAME: &str = "default";

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundValidationResult {
    pub name: String,
    pub protocol: String,
    pub valid: bool,
    pub error: Option<String>,
}

#[cfg(feature = "anytls")]
use crate::proxy::anytls;
#[cfg(feature = "hysteria")]
use crate::proxy::hysteria2;
#[cfg(feature = "trojan")]
use crate::proxy::trojan;
#[cfg(feature = "wireguard")]
use crate::proxy::wg;

pub struct OutboundManager {
    /// name -> handler
    /// handlers: HashMap<String, AnyOutboundHandler>,
    /// proxy_names: Vec<String>,
    /// name -> provider
    proxy_providers: HashMap<String, ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
    cache_store: ThreadSafeCacheFile,
    /// Shared registry used by both OutboundManager lookups and the DNS /
    /// HTTP bootstrap clients.  Populated at the end of `new()` and is the
    /// single source of truth for all handlers after initialization.
    registry: OutboundHandlerRegistry,
    network_path_source: NetworkPathSource,
    pool_reset_gate: Mutex<()>,
    pool_network_generation: Mutex<Option<u64>>,
    pool_retirement: Mutex<PoolRetirementState>,
}

#[derive(Default)]
struct PoolRetirementState {
    generation: Option<u64>,
    ready: HashMap<usize, Weak<dyn crate::proxy::OutboundHandler>>,
    failed: HashMap<usize, String>,
}

struct PoolResetOutcome {
    identity: usize,
    handler: Weak<dyn crate::proxy::OutboundHandler>,
    result: io::Result<u32>,
}

fn handler_identity(handler: &AnyOutboundHandler) -> usize {
    Arc::as_ptr(handler) as *const () as usize
}

async fn reset_unique_connection_pools_detailed(
    handlers: Vec<AnyOutboundHandler>,
) -> Vec<PoolResetOutcome> {
    let mut seen = HashSet::new();
    let mut pending = futures::stream::FuturesUnordered::new();
    for handler in handlers {
        let identity = handler_identity(&handler);
        if seen.insert(identity) {
            let weak = Arc::downgrade(&handler);
            pending.push(async move {
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    handler.reset_connection_pool(),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "outbound pool reset timed out",
                    ))
                });
                PoolResetOutcome {
                    identity,
                    handler: weak,
                    result,
                }
            });
        }
    }
    let mut outcomes = Vec::new();
    while let Some(outcome) = pending.next().await {
        outcomes.push(outcome);
    }
    outcomes
}

fn summarize_pool_resets(outcomes: &[PoolResetOutcome]) -> io::Result<u32> {
    let mut reset = 0_u32;
    let mut errors = Vec::new();
    for outcome in outcomes {
        match &outcome.result {
            Ok(count) => reset = reset.saturating_add(*count),
            Err(error) => errors.push(error.to_string()),
        }
    }
    if errors.is_empty() {
        Ok(reset)
    } else {
        Err(io::Error::other(errors.join("; ")))
    }
}

pub type ThreadSafeOutboundManager = Arc<OutboundManager>;
static DEFAULT_LATENCY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

impl PoolRetirementState {
    fn record(&mut self, generation: u64, outcomes: &[PoolResetOutcome]) {
        self.generation = Some(generation);
        self.ready.clear();
        self.failed.clear();
        for outcome in outcomes {
            match &outcome.result {
                Ok(_) => {
                    self.ready.insert(outcome.identity, outcome.handler.clone());
                }
                Err(error) => {
                    self.failed.insert(outcome.identity, error.to_string());
                }
            }
        }
    }
}

#[cfg(test)]
async fn reset_unique_connection_pools(
    handlers: Vec<AnyOutboundHandler>,
) -> io::Result<u32> {
    summarize_pool_resets(&reset_unique_connection_pools_detailed(handlers).await)
}

async fn ensure_pool_generation_current<F, Fut>(
    network_path_source: &NetworkPathSource,
    reset_gate: &Mutex<()>,
    pool_generation: &Mutex<Option<u64>>,
    mut reset_pools: F,
) -> io::Result<bool>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = io::Result<()>>,
{
    let _reset_gate = reset_gate.lock().await;
    let mut pool_generation = pool_generation.lock().await;
    // A flow can wait behind manual recovery or another flow's pool reset.
    // Read the observed generation only after acquiring the reset gate.
    // If a second network change happens during retirement, retry against
    // the newest generation, but bound the work under a flapping network.
    const MAX_GENERATION_ATTEMPTS: usize = 3;
    for _ in 0..MAX_GENERATION_ATTEMPTS {
        let Some((generation, ..)) = network_path_source.snapshot().await else {
            return Ok(false);
        };
        if *pool_generation == Some(generation) {
            return Ok(false);
        }

        reset_pools(generation).await?;
        let current_generation = network_path_source
            .snapshot()
            .await
            .map(|(current, ..)| current);
        if current_generation == Some(generation) {
            *pool_generation = Some(generation);
            return Ok(true);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "network changed repeatedly while retiring stale outbound pools",
    ))
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
        registry: OutboundHandlerRegistry,
    ) -> Result<Self, Error> {
        Self::new_with_network_path_source(
            outbounds,
            outbound_groups,
            proxy_providers,
            proxy_names,
            dns_resolver,
            cache_store,
            cwd,
            fw_mark,
            registry,
            NetworkPathSource::default(),
        )
        .await
    }

    pub(crate) async fn new_with_network_path_source(
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        proxy_names: Vec<String>,
        dns_resolver: ThreadSafeDNSResolver,
        cache_store: ThreadSafeCacheFile,
        cwd: String,
        fw_mark: Option<u32>,
        registry: OutboundHandlerRegistry,
        network_path_source: NetworkPathSource,
    ) -> Result<Self, Error> {
        // Build all handlers in a plain HashMap during initialization.
        // Once fully assembled it is written into the shared registry so that
        // DNS clients and the HTTP client can look up any handler by name.
        let mut handlers: HashMap<String, AnyOutboundHandler> = HashMap::new();
        // let proxy_names_ref = proxy_names;
        let provider_registry = HashMap::new();
        let selector_control = HashMap::new();
        let proxy_manager = ProxyManager::new(dns_resolver.clone(), fw_mark);
        let mut m = Self {
            registry,
            // proxy_names: proxy_names_ref,
            proxy_manager,
            selector_control,
            proxy_providers: provider_registry,
            cache_store: cache_store.clone(),
            network_path_source,
            pool_reset_gate: Mutex::new(()),
            pool_network_generation: Mutex::new(None),
            pool_retirement: Mutex::new(PoolRetirementState::default()),
        };

        debug!("initializing proxy providers");
        m.load_proxy_providers(cwd, proxy_providers, dns_resolver)
            .await?;

        debug!("initializing handlers");
        m.load_handlers(
            &mut handlers,
            outbounds,
            outbound_groups,
            proxy_names,
            cache_store,
        )
        .await?;

        debug!("initializing connectors");
        m.init_handler_connectors(&handlers).await?;

        // Replace the shared registry with the freshly assembled handler map.
        // Using `clone()` + `*reg = ...` ensures stale entries from previous
        // initialisation rounds (e.g. across hot reloads) are removed.
        {
            let mut reg = m.registry.write().await;
            *reg = handlers
                .iter()
                .map(|(k, v)| {
                    debug!("registering outbound '{}' in bootstrap registry", k);
                    (k.clone(), v.clone())
                })
                .collect();
        }

        Ok(m)
    }

    /// Look up a handler by name. Returns `None` when the name is not
    /// registered.  The registry is read under a shared lock, so this method
    /// is `async` — callers must `.await` the result.
    pub async fn get_outbound(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.registry.read().await.get(name).cloned()
    }

    /// Retire every known pool for a new network generation, retaining
    /// handler-specific failures instead of blocking unrelated new flows.
    async fn ensure_pools_current(&self) -> io::Result<()> {
        ensure_pool_generation_current(
            &self.network_path_source,
            &self.pool_reset_gate,
            &self.pool_network_generation,
            |generation| async move {
                let outcomes = self.reset_connection_pools_inner_detailed().await;
                {
                    let mut state = self.pool_retirement.lock().await;
                    state.record(generation, &outcomes);
                }
                for outcome in &outcomes {
                    if let Err(error) = &outcome.result {
                        tracing::warn!(
                            handler_identity = outcome.identity,
                            generation,
                            error = %error,
                            "outbound pool retirement failed; affected handler will retry before dialing"
                        );
                    }
                }
                Ok(())
            },
        )
        .await?;
        Ok(())
    }

    /// Check the final socket-owning handler after dynamic group selection.
    /// An independently failed pool may only be used after its own reset
    /// succeeds. A newly loaded provider handler is also checked once.
    pub(crate) async fn ensure_outbound_ready_for_new_flow(
        &self,
        handler: &AnyOutboundHandler,
    ) -> io::Result<()> {
        // Network observation can advance after the first pool retirement
        // but before this handler's readiness check. Retry only against the
        // newly observed generation; never authorize a stale pool.
        const MAX_VALIDATION_ATTEMPTS: usize = 3;
        for _ in 0..MAX_VALIDATION_ATTEMPTS {
            self.ensure_pools_current().await?;

            // Relay can dial several proxies; all constituent pools must be safe.
            // Dynamic group selection is pinned by Dispatcher before this call.
            let mut pending = vec![handler.clone()];
            let mut checked = HashSet::new();
            let mut handles = Vec::new();
            while let Some(candidate) = pending.pop() {
                let identity = handler_identity(&candidate);
                if !checked.insert(identity) {
                    continue;
                }
                if checked.len() > 256 {
                    return Err(io::Error::other(
                        "outbound group dependency tree exceeds safe limit",
                    ));
                }
                if let Some(group) = candidate.try_as_group_handler() {
                    let children = group.get_proxies().await;
                    pending.extend(children);
                }
                handles.push(candidate);
            }

            let _gate = self.pool_reset_gate.lock().await;
            let Some((generation, ..)) = self.network_path_source.snapshot().await
            else {
                return Ok(());
            };
            if *self.pool_network_generation.lock().await != Some(generation) {
                // A sampler or recovery task advanced the generation while we
                // were preparing the handler list. Re-retire on the next attempt.
                continue;
            }

            for candidate in handles {
                let identity = handler_identity(&candidate);
                {
                    let state = self.pool_retirement.lock().await;
                    if state.generation == Some(generation)
                        && state
                            .ready
                            .get(&identity)
                            .and_then(Weak::upgrade)
                            .is_some_and(|existing| {
                                Arc::ptr_eq(&existing, &candidate)
                            })
                    {
                        continue;
                    }
                }

                // Do not hold the bookkeeping lock across a potentially slow
                // transport reset. The reset gate serializes callers instead.
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    candidate.reset_connection_pool(),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "outbound pool reset timed out",
                    ))
                });
                let mut state = self.pool_retirement.lock().await;
                if state.generation != Some(generation) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "pool retirement generation changed during handler reset",
                    ));
                }
                match result {
                    Ok(_) => {
                        state.failed.remove(&identity);
                        state.ready.insert(identity, Arc::downgrade(&candidate));
                    }
                    Err(error) => {
                        state.ready.remove(&identity);
                        state.failed.insert(identity, error.to_string());
                        return Err(io::Error::new(
                            error.kind(),
                            format!(
                                "outbound '{}' pool is not safe to reuse: {error}",
                                candidate.name()
                            ),
                        ));
                    }
                }
            }
            // Do not authorize a newly opened connection on a stale generation.
            if self
                .network_path_source
                .snapshot()
                .await
                .map(|(version, ..)| version)
                != Some(generation)
            {
                continue;
            }
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "network changed while validating outbound pool retirement",
        ))
    }

    pub(crate) async fn get_outbound_for_new_flow(
        &self,
        name: &str,
    ) -> io::Result<Option<AnyOutboundHandler>> {
        self.ensure_pools_current().await?;
        let handler = self.get_outbound(name).await;
        // Group selection is performed by Dispatcher later. Checking all
        // possible group members here would wrongly reject healthy choices.
        if let Some(handler) = &handler
            && handler.try_as_group_handler().is_none()
        {
            self.ensure_outbound_ready_for_new_flow(handler).await?;
        }
        Ok(handler)
    }

    pub(crate) async fn attach_network_status(
        &self,
        status: Arc<tokio::sync::RwLock<crate::app::network::NetworkStatus>>,
    ) {
        self.network_path_source.attach(status).await;
    }

    pub(crate) async fn attach_traffic_reporter(
        &self,
        reporter: crate::app::runtime_state::TrafficReporter,
    ) {
        self.network_path_source
            .attach_traffic_reporter(reporter)
            .await;
    }

    /// Invalidate every reusable network-bound connection owned by configured
    /// outbounds, including proxies that only exist inside remote providers.
    pub async fn reset_connection_pools(&self) -> Result<u32, Error> {
        let _reset_gate = self.pool_reset_gate.lock().await;
        let generation_before = self
            .network_path_source
            .snapshot()
            .await
            .map(|(generation, ..)| generation);
        let outcomes = self.reset_connection_pools_inner_detailed().await;
        let stable = generation_before.is_some()
            && self
                .network_path_source
                .snapshot()
                .await
                .is_some_and(|(current, ..)| Some(current) == generation_before);
        if stable {
            let generation =
                generation_before.expect("stable generation is present");
            self.pool_retirement
                .lock()
                .await
                .record(generation, &outcomes);
            *self.pool_network_generation.lock().await = Some(generation);
        }
        summarize_pool_resets(&outcomes).map_err(|error| {
            Error::Operation(format!(
                "failed to reset outbound connection pool: {error}"
            ))
        })
    }

    async fn reset_connection_pools_inner_detailed(&self) -> Vec<PoolResetOutcome> {
        let mut handlers: Vec<AnyOutboundHandler> =
            self.registry.read().await.values().cloned().collect();
        let providers: Vec<ThreadSafeProxyProvider> =
            self.proxy_providers.values().cloned().collect();
        for provider in providers {
            handlers.extend(provider.read().await.proxies().await);
        }
        reset_unique_connection_pools_detailed(handlers).await
    }

    /// This does not populate history/liveness information.
    pub fn get_proxy_provider(&self, name: &str) -> Option<ThreadSafeProxyProvider> {
        self.proxy_providers.get(name).cloned()
    }

    // API handles start
    pub fn get_selector_control(
        &self,
        name: &str,
    ) -> Option<ThreadSafeSelectorControl> {
        self.selector_control.get(name).cloned()
    }

    /* pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    } */

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

        // Snapshot the registry without holding the lock across async calls.
        let handlers: Vec<(String, AnyOutboundHandler)> = self
            .registry
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (k, v) in handlers {
            let mut m = if let Some(g) = v.try_as_group_handler() {
                g.as_map().await
            } else if let Some(p) = v.try_as_plain_handler() {
                p.as_map().await
            } else {
                HashMap::new()
            };

            self.apply_common_proxy_fields(&mut m, &v, &k).await;

            r.insert(k.clone(), Box::new(m) as _);
        }

        r
    }

    pub async fn get_proxy(
        &self,
        proxy: &AnyOutboundHandler,
    ) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = if let Some(g) = proxy.try_as_group_handler() {
            g.as_map().await
        } else if let Some(p) = proxy.try_as_plain_handler() {
            p.as_map().await
        } else {
            HashMap::new()
        };

        self.apply_common_proxy_fields(&mut r, proxy, proxy.name())
            .await;

        r
    }

    pub async fn delay_history(
        &self,
        name: &str,
        url: Option<&str>,
    ) -> Vec<crate::app::remote_content_manager::DelayHistory> {
        match url {
            Some(url) => self.proxy_manager.delay_history_for_url(name, url).await,
            None => self.proxy_manager.delay_history(name).await,
        }
    }

    async fn apply_common_proxy_fields(
        &self,
        m: &mut HashMap<String, Box<dyn Serialize + Send>>,
        proxy: &AnyOutboundHandler,
        name: &str,
    ) {
        let alive = self.proxy_manager.alive(name).await;
        let history = self.proxy_manager.delay_history(name).await;
        let support_udp = proxy.support_udp().await;

        let id = Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes());
        m.insert("id".to_string(), Box::new(id.to_string()));
        m.insert("history".to_string(), Box::new(history));
        m.insert("alive".to_string(), Box::new(alive));
        m.insert("name".to_string(), Box::new(name.to_owned()));
        m.insert("type".to_string(), Box::new(proxy.proto().to_string()));
        m.insert("udp".to_string(), Box::new(support_udp));
        m.insert("uot".to_string(), Box::new(false));
        m.insert("xudp".to_string(), Box::new(false));
        m.insert("tfo".to_string(), Box::new(false));
        m.insert("mptcp".to_string(), Box::new(false));
        m.insert("smux".to_string(), Box::new(false));
        m.insert("interface".to_string(), Box::new(""));
        m.insert("dialer-proxy".to_string(), Box::new(""));
        m.insert("routing-mark".to_string(), Box::new(0));
        m.insert("provider-name".to_string(), Box::new(""));
        m.insert(
            "extra".to_string(),
            Box::new(HashMap::<String, String>::new()),
        );
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

    pub fn get_proxy_providers(&self) -> HashMap<String, ThreadSafeProxyProvider> {
        self.proxy_providers.clone()
    }

    /// S04b-l: prove that this manager's *socket path planning* source
    /// observes the same RuntimeStatus and generation as the strict DNS
    /// transaction. This is not a claim about the path that a socket won;
    /// actual dial-time path attestation remains a separate prerequisite.
    pub(crate) async fn strict_dns_path_generation(
        &self,
        status: &crate::proxy::utils::SharedNetworkStatus,
    ) -> io::Result<u64> {
        let (path_generation, _, _, attached, _) =
            self.network_path_source.snapshot().await.ok_or_else(|| {
                io::Error::other(
                    "strict DNS manager has no observed socket path source",
                )
            })?;
        if !Arc::ptr_eq(&attached, status) {
            return Err(io::Error::other(
                "strict DNS socket path belongs to a different runtime",
            ));
        }
        let observed =
            status
                .read()
                .await
                .strict_dns_generations()
                .ok_or_else(|| {
                    io::Error::other(
                        "strict DNS socket path has no current network observation",
                    )
                })?;
        if observed.0 != path_generation {
            return Err(io::Error::other(
                "strict DNS socket path generation differs from DNS observation",
            ));
        }
        Ok(path_generation)
    }

    /// S04b-h read-only identity check: strict DNS preflight must not prepare
    /// a leaf using a registry unrelated to the observed outbound manager.
    pub(crate) fn owns_outbound_registry(
        &self,
        registry: &OutboundHandlerRegistry,
    ) -> bool {
        Arc::ptr_eq(&self.registry, registry)
    }

    /// Load handlers from the provided outbound protocols and groups.
    /// handlers in proxy_providers are not loaded here as they are stored in
    /// the provider separately.
    async fn load_handlers(
        &mut self,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_names: Vec<String>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        handlers.extend(outbounds.into_iter().map(|h| {
            let name = h.name().to_owned();
            (name, h)
        }));

        self.load_group_outbounds(handlers, outbound_groups, cache_store.clone())
            .await?;

        // insert GLOBAL
        let mut g = vec![];
        let mut keys = handlers.keys().collect::<Vec<_>>();
        keys.sort_by(|a, b| {
            proxy_names
                .iter()
                .position(|x| &x == a)
                .cmp(&proxy_names.iter().position(|x| &x == b))
        });
        for name in keys {
            g.push(handlers.get(name).unwrap().clone());
        }
        let hc = HealthCheck::new(
            g.clone(),
            DEFAULT_LATENCY_TEST_URL.to_owned(),
            0, // this is a manual HC
            true,
            self.proxy_manager.clone(),
        );

        let pd = Arc::new(RwLock::new(PlainProvider::new(
            PROXY_GLOBAL.to_owned(),
            g,
            hc,
        )?));

        let stored_selection = cache_store.get_selected(PROXY_GLOBAL).await;
        let mut providers: Vec<ThreadSafeProxyProvider> = vec![pd.clone()];
        for p in self.proxy_providers.values() {
            let vehicle_type = p.read().await.vehicle_type();
            if matches!(
                vehicle_type,
                ProviderVehicleType::Http | ProviderVehicleType::File
            ) {
                providers.push(p.clone());
            }
        }

        let h = selector::Handler::new(
            selector::HandlerOptions {
                name: PROXY_GLOBAL.to_owned(),
                udp: true,
                common_opts: crate::proxy::HandlerCommonOptions {
                    icon: None,
                    ..Default::default()
                },
            },
            providers,
            stored_selection,
        )
        .await;

        self.proxy_providers
            .insert(RESERVED_PROVIDER_NAME.to_owned(), pd);
        handlers.insert(PROXY_GLOBAL.to_owned(), Arc::new(h.clone()));
        self.selector_control
            .insert(PROXY_GLOBAL.to_owned(), Arc::new(h));

        Ok(())
    }

    #[cfg(feature = "wireguard")]
    pub(crate) fn load_provider_outbound(
        outbound: OutboundProxyProtocol,
    ) -> Result<Option<AnyOutboundHandler>, Error> {
        match outbound {
            OutboundProxyProtocol::Wireguard(wg) => {
                let handler: wg::Handler = wg.try_into()?;
                Ok(Some(Arc::new(handler) as AnyOutboundHandler))
            }
            outbound => Ok(Self::load_plain_outbounds(vec![outbound]).pop()),
        }
    }

    #[cfg(not(feature = "wireguard"))]
    pub(crate) fn load_provider_outbound(
        outbound: OutboundProxyProtocol,
    ) -> Result<Option<AnyOutboundHandler>, Error> {
        Ok(Self::load_plain_outbounds(vec![outbound]).pop())
    }

    pub fn load_plain_outbounds(
        outbounds: Vec<OutboundProxyProtocol>,
    ) -> Vec<AnyOutboundHandler> {
        outbounds
            .into_iter()
            .filter_map(|outbound| {
                let name = outbound.name().to_owned();
                let protocol = outbound.to_string().to_ascii_lowercase();
                match Self::try_load_plain_outbound(outbound) {
                    Ok(handler) => Some(handler),
                    Err(err) => {
                        error!(
                            "failed to load {} outbound {}: {}",
                            protocol, name, err
                        );
                        None
                    }
                }
            })
            .collect()
    }

    pub fn validate_plain_outbounds(
        &self,
        outbounds: Vec<OutboundProxyProtocol>,
    ) -> Vec<OutboundValidationResult> {
        outbounds
            .into_iter()
            .map(|outbound| {
                let name = outbound.name().to_owned();
                let protocol = outbound.type_name().to_owned();
                match Self::try_load_plain_outbound(outbound) {
                    Ok(_) => OutboundValidationResult {
                        name,
                        protocol,
                        valid: true,
                        error: None,
                    },
                    Err(err) => OutboundValidationResult {
                        name,
                        protocol,
                        valid: false,
                        error: Some(err.to_string()),
                    },
                }
            })
            .collect()
    }

    pub fn validate_proxy_group_dependencies(
        groups: &[OutboundGroupProtocol],
    ) -> Result<(), Error> {
        let mut groups = groups.to_vec();
        proxy_groups_dag_sort(&mut groups)
    }

    fn try_load_plain_outbound(
        outbound: OutboundProxyProtocol,
    ) -> Result<AnyOutboundHandler, Error> {
        match outbound {
            OutboundProxyProtocol::Direct(d) => {
                Ok(Arc::new(direct::Handler::new(&d.name)))
            }
            OutboundProxyProtocol::Reject(r) => {
                Ok(Arc::new(reject::Handler::new(&r.name)))
            }
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ss(s) => {
                let handler: crate::proxy::shadowsocks::outbound::Handler =
                    s.try_into()?;
                Ok(Arc::new(handler))
            }
            OutboundProxyProtocol::Socks5(s) => {
                let handler: socks::outbound::Handler = s.try_into()?;
                Ok(Arc::new(handler))
            }
            #[cfg(feature = "anytls")]
            OutboundProxyProtocol::Anytls(anytls) => {
                let handler: anytls::Handler = anytls.try_into()?;
                Ok(Arc::new(handler))
            }
            #[cfg(feature = "trojan")]
            OutboundProxyProtocol::Trojan(trojan) => {
                let handler: trojan::Handler = trojan.try_into()?;
                Ok(Arc::new(handler))
            }
            #[cfg(feature = "hysteria")]
            OutboundProxyProtocol::Hysteria2(hysteria) => {
                let handler: hysteria2::Handler = hysteria.try_into()?;
                Ok(Arc::new(handler))
            }
            OutboundProxyProtocol::Vless(vless) => {
                let handler: vless::Handler = vless.try_into()?;
                Ok(Arc::new(handler))
            }
            #[cfg(feature = "wireguard")]
            OutboundProxyProtocol::Wireguard(wireguard) => {
                let handler: wg::Handler = wireguard.try_into()?;
                Ok(Arc::new(handler))
            }
        }
    }

    /// Lazy initialization of connectors for each handler.
    async fn init_handler_connectors(
        &self,
        handlers: &HashMap<String, AnyOutboundHandler>,
    ) -> Result<(), Error> {
        let mut connectors = HashMap::new();
        for handler in handlers.values() {
            if let Some(connector_name) = handler.support_dialer() {
                let outbound = handlers
                    .get(connector_name)
                    .ok_or(Error::InvalidConfig(format!(
                        "connector {connector_name} not found"
                    )))?
                    .clone();
                let connector =
                    connectors.entry(connector_name).or_insert_with(|| {
                        Arc::new(ProxyConnector::new(
                            outbound,
                            Box::new(DirectConnector::with_path_source(
                                self.network_path_source.clone(),
                            )),
                        ))
                    });
                handler.register_connector(connector.clone()).await;
            } else {
                handler
                    .register_connector(Arc::new(DirectConnector::with_path_source(
                        self.network_path_source.clone(),
                    )))
                    .await;
            }
        }

        Ok(())
    }

    async fn load_group_outbounds(
        &mut self,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        // Sort outbound groups to ensure dependencies are resolved
        let mut outbound_groups = outbound_groups;
        proxy_groups_dag_sort(&mut outbound_groups)?;

        // let handlers = &mut self.handlers;
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
                OutboundGroupProtocol::Smart(proto) => {
                    proto.validate()?;
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
                        return Err(Error::InvalidConfig(format!(
                            "smart proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];
                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            proto.interval.unwrap_or(300),
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
                    )?;
                    handlers.insert(
                        proto.name.clone(),
                        Arc::new(smart::Handler::new(
                            smart::HandlerOptions {
                                name: proto.name.clone(),
                                udp: proto.udp.unwrap_or(true),
                                common_opts: crate::proxy::HandlerCommonOptions {
                                    icon: proto.icon.clone(),
                                    url: proto.url.clone(),
                                    connector: None,
                                },
                            },
                            proto.tolerance.unwrap_or_default(),
                            providers,
                            proxy_manager.clone(),
                        )),
                    );
                }
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
                    )?;

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
                    )?;

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

                OutboundGroupProtocol::LoadBalance(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers = vec![];
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
                    )?;
                    handlers.insert(
                        proto.name.clone(),
                        Arc::new(loadbalance::Handler::new(
                            loadbalance::HandlerOptions {
                                name: proto.name.clone(),
                                udp: proto.udp.unwrap_or(true),
                                strategy: proto.strategy,
                                common_opts: crate::proxy::HandlerCommonOptions {
                                    icon: proto.icon.clone(),
                                    url: Some(proto.url.clone()),
                                    connector: None,
                                },
                            },
                            providers,
                            proxy_manager.clone(),
                        )),
                    );
                }

                OutboundGroupProtocol::Relay(proto) => {
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

                    let relay = relay::Handler::new_with_path_source(
                        relay::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: proto.url.clone(),
                                connector: None,
                            },
                        },
                        providers,
                        self.network_path_source.clone(),
                    );

                    handlers.insert(proto.name.clone(), relay);
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
        resolver: ThreadSafeDNSResolver,
    ) -> Result<(), Error> {
        let provider_registry = &mut self.proxy_providers;
        for (name, provider) in proxy_providers.into_iter() {
            match provider {
                OutboundProxyProviderDef::Http(http) => {
                    debug!("loading http proxy provider `{}`", name);
                    let vehicle = Arc::new(http_vehicle::Vehicle::new(
                        http.url.parse::<hyper::Uri>().map_err(|e| {
                            Error::InvalidConfig(format!(
                                "invalid http proxy provider `{name}` url: {e}"
                            ))
                        })?,
                        &http.path,
                        Some(&cwd),
                        resolver.clone(),
                    ))
                        as ThreadSafeProviderVehicle;
                    let health = http.health_check;
                    let health_check = HealthCheck::new(
                        vec![],
                        health
                            .url
                            .unwrap_or_else(|| DEFAULT_LATENCY_TEST_URL.to_owned()),
                        if health.enable == Some(false) {
                            0
                        } else {
                            health.interval.unwrap_or(http.interval)
                        },
                        health.lazy.unwrap_or(true),
                        self.proxy_manager.clone(),
                    );
                    let provider: ThreadSafeProxyProvider = Arc::new(RwLock::new(
                        ProxySetProvider::new(
                            name.clone(),
                            Duration::from_secs(http.interval),
                            vehicle,
                            health_check,
                        )
                        .map_err(|x| {
                            Error::InvalidConfig(format!(
                                "invalid provider config: {x}"
                            ))
                        })?,
                    ));
                    provider_registry.insert(name, provider);
                }
                OutboundProxyProviderDef::File(file) => {
                    debug!("loading file proxy provider `{}`", name);
                    let path_buf = PathBuf::from(&file.path);
                    let path = if path_buf.is_absolute() {
                        path_buf
                    } else {
                        PathBuf::from(&cwd).join(path_buf)
                    };
                    let vehicle = Arc::new(file_vehicle::Vehicle::new(
                        path.to_str().ok_or_else(|| {
                            Error::InvalidConfig(format!(
                                "file provider `{name}` path is not valid UTF-8"
                            ))
                        })?,
                    ))
                        as ThreadSafeProviderVehicle;

                    let health = file.health_check;
                    if matches!(
                        health.probe,
                        HealthCheckProbe::Download | HealthCheckProbe::Sse
                    ) && !cfg!(feature = "extended-health-check")
                    {
                        return Err(Error::InvalidConfig(format!(
                            "file provider `{name}` uses download health probe, \
                             but extended-health-check is disabled"
                        )));
                    }
                    if health.probe == HealthCheckProbe::Websocket
                        && !cfg!(all(
                            feature = "extended-health-check",
                            feature = "ws"
                        ))
                    {
                        return Err(Error::InvalidConfig(format!(
                            "file provider `{name}` uses WebSocket health probe, \
                             but extended-health-check or ws is disabled"
                        )));
                    }
                    let minimum_bytes = health.minimum_bytes.unwrap_or(65_536);
                    if health.probe == HealthCheckProbe::Download
                        && minimum_bytes == 0
                    {
                        return Err(Error::InvalidConfig(format!(
                            "file provider `{name}` download health probe requires \
                             minimum-bytes greater than zero"
                        )));
                    }
                    let minimum_events = health.minimum_events.unwrap_or(3);
                    if health.probe == HealthCheckProbe::Sse && minimum_events == 0 {
                        return Err(Error::InvalidConfig(format!(
                            "file provider `{name}` SSE health probe requires \
                             minimum-events greater than zero"
                        )));
                    }
                    let maximum_first_byte = Duration::from_millis(
                        health.maximum_first_byte_ms.unwrap_or(3_000),
                    );
                    if health.probe == HealthCheckProbe::Sse
                        && maximum_first_byte.is_zero()
                    {
                        return Err(Error::InvalidConfig(format!(
                            "file provider `{name}` SSE health probe requires \
                             maximum-first-byte-ms greater than zero"
                        )));
                    }
                    let expected_echo = health
                        .expect_echo
                        .unwrap_or_else(|| "chimera-health".to_owned());
                    if health.probe == HealthCheckProbe::Websocket
                        && expected_echo.is_empty()
                    {
                        return Err(Error::InvalidConfig(format!(
                            "file provider `{name}` WebSocket health probe requires \
                             non-empty expect-echo"
                        )));
                    }
                    let interval = if health.enable == Some(false) {
                        0
                    } else {
                        health.interval.or(file.interval).unwrap_or_default()
                    };
                    let health_check = HealthCheck::new(
                        vec![],
                        health
                            .url
                            .unwrap_or_else(|| DEFAULT_LATENCY_TEST_URL.to_owned()),
                        interval,
                        health.lazy.unwrap_or(true),
                        self.proxy_manager.clone(),
                    )
                    .with_probe(
                        health.probe,
                        minimum_bytes,
                        minimum_events,
                        maximum_first_byte,
                        expected_echo,
                        health.timeout.map(Duration::from_secs),
                    );

                    let provider: ThreadSafeProxyProvider = Arc::new(RwLock::new(
                        ProxySetProvider::new(
                            name.clone(),
                            Duration::from_secs(file.interval.unwrap_or_default()),
                            vehicle,
                            health_check,
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

        let providers: Vec<(String, ThreadSafeProxyProvider)> = provider_registry
            .iter()
            .map(|(name, provider)| (name.clone(), provider.clone()))
            .collect();
        let mut failed = Vec::new();
        for (name, provider) in providers {
            info!("initializing provider {}", name);
            if let Err(err) = provider.read().await.initialize().await {
                error!("failed to initialize proxy provider {}: {}", name, err);
                failed.push(name);
                continue;
            }
            info!("initialized provider {}", name);
        }
        for name in failed {
            provider_registry.remove(&name);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt::Debug,
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;

    use super::{
        OutboundManager, PoolRetirementState, ensure_pool_generation_current,
        reset_unique_connection_pools,
    };
    use crate::{
        app::{
            dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
            dns::ThreadSafeDNSResolver,
            network::{NetworkSnapshot, NetworkStatus},
        },
        proxy::{
            AnyOutboundHandler, DialWithConnector, OutboundHandler, OutboundType,
            utils::NetworkPathSource,
        },
        session::Session,
    };

    #[cfg(feature = "wireguard")]
    use crate::config::internal::proxy::{OutboundProxyProtocol, OutboundWireguard};

    #[derive(Debug)]
    struct CountingHandler {
        name: &'static str,
        resets: Arc<AtomicUsize>,
        reset_count: u32,
        fail: bool,
    }

    impl DialWithConnector for CountingHandler {}

    #[async_trait]
    impl OutboundHandler for CountingHandler {
        fn name(&self) -> &str {
            self.name
        }

        fn proto(&self) -> OutboundType {
            OutboundType::Direct
        }

        async fn reset_connection_pool(&self) -> io::Result<u32> {
            self.resets.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(io::Error::other("injected pool failure"))
            } else {
                Ok(self.reset_count)
            }
        }

        async fn connect_stream(
            &self,
            _sess: &Session,
            _resolver: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedStream> {
            unreachable!("connection-pool reset test does not dial")
        }

        async fn connect_datagram(
            &self,
            _sess: &Session,
            _resolver: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedDatagram> {
            unreachable!("connection-pool reset test does not dial")
        }
    }

    #[tokio::test]
    async fn failed_pool_reset_does_not_skip_other_handlers() {
        let resets = Arc::new(AtomicUsize::new(0));
        let handlers: Vec<AnyOutboundHandler> = vec![
            Arc::new(CountingHandler {
                name: "broken",
                resets: resets.clone(),
                reset_count: 0,
                fail: true,
            }),
            Arc::new(CountingHandler {
                name: "healthy",
                resets: resets.clone(),
                reset_count: 1,
                fail: false,
            }),
        ];
        let error = reset_unique_connection_pools(handlers).await.unwrap_err();
        assert!(error.to_string().contains("injected pool failure"));
        assert_eq!(resets.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "wireguard")]
    #[test]
    fn provider_wireguard_conversion_is_strict() {
        let valid: OutboundWireguard = serde_yaml::from_str(
            r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2/32
udp: true
"#,
        )
        .expect("wireguard config should parse");
        let handler = OutboundManager::load_provider_outbound(
            OutboundProxyProtocol::Wireguard(valid),
        )
        .expect("valid provider wireguard should convert")
        .expect("wireguard provider should produce a handler");
        assert!(matches!(handler.proto(), OutboundType::WireGuard));

        let invalid: OutboundWireguard = serde_yaml::from_str(
            r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: not-an-ip
"#,
        )
        .expect("wireguard config shape should parse");
        assert!(
            OutboundManager::load_provider_outbound(
                OutboundProxyProtocol::Wireguard(invalid),
            )
            .is_err(),
            "provider loading must propagate WireGuard conversion errors"
        );
    }

    #[tokio::test]
    async fn reset_connection_pools_deduplicates_shared_handlers() {
        let first_resets = Arc::new(AtomicUsize::new(0));
        let second_resets = Arc::new(AtomicUsize::new(0));
        let first: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "first",
            resets: first_resets.clone(),
            reset_count: 1,
            fail: false,
        });
        let second: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "second",
            resets: second_resets.clone(),
            reset_count: 2,
            fail: false,
        });

        let reset =
            reset_unique_connection_pools(vec![first.clone(), second, first])
                .await
                .unwrap();

        assert_eq!(reset, 3);
        assert_eq!(first_resets.load(Ordering::SeqCst), 1);
        assert_eq!(second_resets.load(Ordering::SeqCst), 1);
    }

    #[derive(Debug)]
    struct RecoverableHandler {
        resets: Arc<AtomicUsize>,
        should_fail: Arc<std::sync::atomic::AtomicBool>,
    }

    impl DialWithConnector for RecoverableHandler {}

    #[async_trait]
    impl OutboundHandler for RecoverableHandler {
        fn name(&self) -> &str {
            "recoverable"
        }
        fn proto(&self) -> OutboundType {
            OutboundType::Vless
        }
        async fn reset_connection_pool(&self) -> io::Result<u32> {
            self.resets.fetch_add(1, Ordering::SeqCst);
            if self.should_fail.load(Ordering::SeqCst) {
                Err(io::Error::other("temporary pool failure"))
            } else {
                Ok(1)
            }
        }
        async fn connect_stream(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedStream> {
            unreachable!("pool readiness test does not dial")
        }
        async fn connect_datagram(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedDatagram> {
            unreachable!("pool readiness test does not dial")
        }
    }

    #[tokio::test]
    async fn failed_pool_recovery_is_scoped_and_not_retried_after_success() {
        let failures = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let resets = Arc::new(AtomicUsize::new(0));
        let recoverable: AnyOutboundHandler = Arc::new(RecoverableHandler {
            resets: resets.clone(),
            should_fail: failures.clone(),
        });
        let good: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "DIRECT",
            resets: Arc::new(AtomicUsize::new(0)),
            reset_count: 0,
            fail: false,
        });
        let manager = isolated_pool_manager(vec![good, recoverable.clone()]).await;
        assert!(
            manager
                .get_outbound_for_new_flow("DIRECT")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(resets.load(Ordering::SeqCst), 1);
        assert!(
            manager
                .get_outbound_for_new_flow("recoverable")
                .await
                .is_err()
        );
        assert_eq!(resets.load(Ordering::SeqCst), 2);
        failures.store(false, Ordering::SeqCst);
        assert!(
            manager
                .get_outbound_for_new_flow("recoverable")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(resets.load(Ordering::SeqCst), 3);
        assert!(
            manager
                .get_outbound_for_new_flow("recoverable")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(resets.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retirement_bookkeeping_does_not_keep_replaced_provider_handler_alive() {
        let handler: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "provider",
            resets: Arc::new(AtomicUsize::new(0)),
            reset_count: 0,
            fail: false,
        });
        let weak = Arc::downgrade(&handler);
        let outcomes =
            super::reset_unique_connection_pools_detailed(vec![handler.clone()])
                .await;
        let mut state = PoolRetirementState::default();
        state.record(2, &outcomes);
        assert_eq!(state.ready.len(), 1);
        drop(handler);
        assert!(
            weak.upgrade().is_none(),
            "retirement status must not pin old provider objects"
        );
    }

    async fn isolated_pool_manager(
        handlers: Vec<AnyOutboundHandler>,
    ) -> OutboundManager {
        use crate::{
            app::{
                profile::ThreadSafeCacheFile, remote_content_manager::ProxyManager,
            },
            proxy::utils::test_utils::noop::NoopResolver,
        };
        use std::collections::HashMap;
        use tokio::sync::{Mutex, RwLock};

        let source = NetworkPathSource::default();
        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        status.observed(&NetworkSnapshot::default());
        source.attach(Arc::new(RwLock::new(status))).await;
        let dns = Arc::new(NoopResolver);
        let registry = handlers
            .into_iter()
            .map(|handler| (handler.name().to_owned(), handler))
            .collect::<HashMap<_, _>>();
        OutboundManager {
            proxy_providers: HashMap::new(),
            proxy_manager: ProxyManager::new(dns, None),
            selector_control: HashMap::new(),
            cache_store: ThreadSafeCacheFile::new(
                "/tmp/chimera-isolation-test-unused",
                false,
            ),
            registry: Arc::new(RwLock::new(registry)),
            network_path_source: source,
            pool_reset_gate: Mutex::new(()),
            pool_network_generation: Mutex::new(None),
            pool_retirement: Mutex::new(PoolRetirementState::default()),
        }
    }

    #[derive(Debug)]
    struct StrictDnsProviderLeaf;

    impl DialWithConnector for StrictDnsProviderLeaf {}

    #[async_trait]
    impl OutboundHandler for StrictDnsProviderLeaf {
        fn name(&self) -> &str {
            "provider-leaf"
        }
        fn server_name(&self) -> Option<&str> {
            Some("192.0.2.10")
        }
        fn proto(&self) -> OutboundType {
            OutboundType::Socks5
        }
        async fn connect_stream(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedStream> {
            unreachable!("strict DNS manager inspection does not dial")
        }
        async fn connect_datagram(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedDatagram> {
            unreachable!("strict DNS manager inspection does not dial")
        }
    }

    #[derive(Debug)]
    struct StrictConnectorTestNode {
        name: &'static str,
        host: &'static str,
        via: Option<&'static str>,
        proto: OutboundType,
    }

    #[async_trait]
    impl DialWithConnector for StrictConnectorTestNode {
        fn support_dialer(&self) -> Option<&str> {
            self.via
        }
    }

    #[async_trait]
    impl OutboundHandler for StrictConnectorTestNode {
        fn name(&self) -> &str {
            self.name
        }
        fn server_name(&self) -> Option<&str> {
            Some(self.host)
        }
        fn proto(&self) -> OutboundType {
            self.proto
        }
        async fn connect_stream(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedStream> {
            unreachable!("strict connector dependency inspection never dials")
        }
        async fn connect_datagram(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedDatagram> {
            unreachable!("strict connector dependency inspection never dials")
        }
    }

    #[tokio::test]
    async fn s04bj_connector_dependency_checks_actual_named_hop_identity() {
        use crate::app::dns::bootstrap_dialer::StrictDnsConnectorChain;

        let node = |name, host, via, proto| -> AnyOutboundHandler {
            Arc::new(StrictConnectorTestNode {
                name,
                host,
                via,
                proto,
            })
        };
        let leaf = node("leaf", "192.0.2.10", Some("via"), OutboundType::Socks5);
        let via = node("via", "198.51.100.20", None, OutboundType::Socks5);
        let manager = Arc::new(isolated_pool_manager(vec![via.clone()]).await);
        let registry = manager.registry.clone();

        let chain = StrictDnsConnectorChain::capture(&manager, &registry, &leaf)
            .await
            .unwrap();
        chain
            .ensure_current(&manager, &registry, &leaf)
            .await
            .unwrap();
        let impostor = node("leaf", "192.0.2.10", Some("via"), OutboundType::Socks5);
        let err = chain
            .ensure_current(&manager, &registry, &impostor)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("leaf identity changed"), "{err}");

        // Same configured name, new handler Arc: no silent dialer-proxy reroute.
        let replacement = node("via", "198.51.100.20", None, OutboundType::Socks5);
        registry.write().await.insert("via".into(), replacement);
        let err = chain
            .ensure_current(&manager, &registry, &leaf)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("dependency 'via' identity changed"), "{err}");

        // The verification does not accept an unrelated handler registry even
        // if it contains an identical handler.
        let fake_registry =
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::from([
                ("via".into(), via),
            ])));
        assert!(
            StrictDnsConnectorChain::capture(&manager, &fake_registry, &leaf)
                .await
                .unwrap_err()
                .to_string()
                .contains("does not belong")
        );
    }

    #[tokio::test]
    async fn s04bj_connector_dependency_rejects_unproven_chains() {
        use crate::app::dns::bootstrap_dialer::StrictDnsConnectorChain;
        let node = |name, host, via, proto| -> AnyOutboundHandler {
            Arc::new(StrictConnectorTestNode {
                name,
                host,
                via,
                proto,
            })
        };
        let via = node("via", "192.0.2.20", None, OutboundType::Socks5);
        let manager = Arc::new(isolated_pool_manager(vec![via]).await);
        let registry = manager.registry.clone();
        for (leaf, marker) in [
            (
                node("leaf", "192.0.2.10", Some("missing"), OutboundType::Socks5),
                "missing",
            ),
            (
                node("leaf", "192.0.2.10", Some("leaf"), OutboundType::Socks5),
                "cycles",
            ),
            (
                node("leaf", "proxy.example", Some("via"), OutboundType::Socks5),
                "trusted bootstrap",
            ),
            (
                node("leaf", "192.0.2.10", None, OutboundType::Direct),
                "fixed proxy leaf",
            ),
        ] {
            let err = StrictDnsConnectorChain::capture(&manager, &registry, &leaf)
                .await
                .expect_err("invalid connector chain must fail")
                .to_string();
            assert!(err.contains(marker), "{err}");
        }
        registry.write().await.insert(
            "via".into(),
            node("via", "192.0.2.20", Some("next"), OutboundType::Socks5),
        );
        let leaf = node("leaf", "192.0.2.10", Some("via"), OutboundType::Socks5);
        let err = StrictDnsConnectorChain::capture(&manager, &registry, &leaf)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("nested dialer-proxy"), "{err}");
        registry.write().await.insert(
            "via".into(),
            node("via", "192.0.2.20", None, OutboundType::Selector),
        );
        let err = StrictDnsConnectorChain::capture(&manager, &registry, &leaf)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("fixed proxy leaf"), "{err}");
    }

    #[tokio::test]
    async fn s04bj_manager_guard_rechecks_named_dialer_on_attempt_boundary() {
        use crate::app::{
            dns::{
                bootstrap_provider::{
                    StrictDnsManagerLeafGuard, StrictProviderObservation,
                },
                execution::DnsStrictAttemptGuard,
            },
            remote_content_manager::{
                healthcheck::HealthCheck,
                providers::proxy_provider::{
                    ThreadSafeProxyProvider, plain_provider::PlainProvider,
                },
            },
        };
        use tokio::sync::RwLock;
        let node = |name, host, via| -> AnyOutboundHandler {
            Arc::new(StrictConnectorTestNode {
                name,
                host,
                via,
                proto: OutboundType::Socks5,
            })
        };
        let leaf = node("leaf", "192.0.2.10", Some("via"));
        let via = node("via", "192.0.2.20", None);
        let mut manager = isolated_pool_manager(vec![via.clone()]).await;
        let provider: ThreadSafeProxyProvider = Arc::new(RwLock::new(
            PlainProvider::new(
                "remote".into(),
                vec![leaf.clone()],
                HealthCheck::new(
                    vec![],
                    "http://example.invalid/health".into(),
                    0,
                    true,
                    manager.proxy_manager.clone(),
                ),
            )
            .unwrap(),
        ));
        manager.proxy_providers.insert("remote".into(), provider);
        let manager = Arc::new(manager);
        let registry = manager.registry.clone();
        let status = Arc::new(RwLock::new(NetworkStatus::default()));
        status.write().await.observed(&NetworkSnapshot::default());
        let observed = StrictProviderObservation::capture_manager(&status, &manager)
            .await
            .unwrap();
        let guard = StrictDnsManagerLeafGuard::bind(
            observed,
            &manager,
            &status,
            &registry,
            "remote",
            leaf.clone(),
        )
        .await
        .unwrap();
        guard.ensure_current(&leaf).await.unwrap();

        registry
            .write()
            .await
            .insert("via".into(), node("via", "192.0.2.20", None));
        let err = guard.ensure_current(&leaf).await.unwrap_err().to_string();
        assert!(err.contains("dependency 'via' identity changed"), "{err}");
    }

    struct S04bkPausedTransport {
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    #[async_trait]
    impl crate::app::dns::execution::DnsStrictTransport for S04bkPausedTransport {
        async fn exchange(
            &self,
            _: &crate::app::dns::config::NameServer,
            _: AnyOutboundHandler,
            query: &hickory_proto::op::Message,
        ) -> io::Result<hickory_proto::op::Message> {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                entered.send(()).unwrap();
            }
            if let Some(release) = self.release.lock().await.take() {
                release.await.unwrap();
            }
            let mut answer = hickory_proto::op::Message::response(
                query.metadata.id,
                hickory_proto::op::OpCode::Query,
            );
            answer.add_queries(query.queries.iter().cloned());
            Ok(answer)
        }
    }

    fn s04bm_path(generation: u64) -> crate::app::flow::NetworkPathId {
        use crate::app::flow::{AddressFamily, InterfaceId, NetworkPathId};
        NetworkPathId {
            interface: InterfaceId {
                name: "fake-en0".into(),
                index: 17,
            },
            family: AddressFamily::Ipv4,
            source_address: Some("192.0.2.77".parse().unwrap()),
            network_generation: generation,
        }
    }

    /// The transport is deliberately inert: cancellation/timeout exercises
    /// lease ownership without opening sockets or mutating answer caches.
    async fn s04bl_fixture() -> (
        Arc<OutboundManager>,
        crate::proxy::utils::SharedNetworkStatus,
        crate::app::dns::bootstrap_provider::StrictDnsManagerLeafGuard,
        crate::app::dns::execution::StrictDnsExecution,
        hickory_proto::op::Message,
    ) {
        use crate::app::{
            dns::{
                bootstrap_provider::{
                    StrictDnsManagerLeafGuard, StrictProviderObservation,
                },
                execution::StrictDnsExecution,
                policy::DnsEgress,
            },
            remote_content_manager::{
                healthcheck::HealthCheck,
                providers::proxy_provider::{
                    ThreadSafeProxyProvider, plain_provider::PlainProvider,
                },
            },
        };
        use hickory_proto::{
            op::{Message, MessageType, OpCode, Query},
            rr::{Name, RecordType},
        };
        use tokio::sync::RwLock;

        let leaf: AnyOutboundHandler = Arc::new(StrictConnectorTestNode {
            name: "leaf",
            host: "192.0.2.10",
            via: Some("via"),
            proto: OutboundType::Socks5,
        });
        let hop: AnyOutboundHandler = Arc::new(StrictConnectorTestNode {
            name: "via",
            host: "192.0.2.20",
            via: None,
            proto: OutboundType::Socks5,
        });
        let mut manager = isolated_pool_manager(vec![hop]).await;
        let provider: ThreadSafeProxyProvider = Arc::new(RwLock::new(
            PlainProvider::new(
                "remote".into(),
                vec![leaf.clone()],
                HealthCheck::new(
                    vec![],
                    "http://example.invalid/health".into(),
                    0,
                    true,
                    manager.proxy_manager.clone(),
                ),
            )
            .unwrap(),
        ));
        manager.proxy_providers.insert("remote".into(), provider);
        let manager = Arc::new(manager);
        let status = Arc::new(RwLock::new(NetworkStatus::default()));
        {
            let mut state = status.write().await;
            use crate::app::{
                flow::InterfaceKind,
                network::{
                    BindingStatus, DefaultRouteEvidence, PathCandidateObservation,
                },
            };
            state.set_automatic_supported_for_test(true);
            state.observed(&NetworkSnapshot {
                path_candidates: vec![PathCandidateObservation {
                    interface: s04bm_path(0).interface,
                    interface_kind: InterfaceKind::Ethernet,
                    family: crate::app::flow::AddressFamily::Ipv4,
                    source_address: "192.0.2.77".parse().unwrap(),
                    scope_id: None,
                    gateway: Some("192.0.2.1".parse().unwrap()),
                    default_route: DefaultRouteEvidence::PrimaryDefaultRoute,
                    binding: BindingStatus::Verified,
                    binding_error: None,
                }],
                ..NetworkSnapshot::default()
            });
        }
        manager.attach_network_status(status.clone()).await;
        let observed = StrictProviderObservation::capture_manager(&status, &manager)
            .await
            .unwrap();
        let guard = StrictDnsManagerLeafGuard::bind(
            observed,
            &manager,
            &status,
            &manager.registry,
            "remote",
            leaf.clone(),
        )
        .await
        .unwrap();
        let execution = StrictDnsExecution {
            ordinal: 0,
            egress: DnsEgress::Proxy("DNS-OUT".into()),
            profile: "trusted".into(),
            servers: crate::app::dns::Config::parse_nameserver(&[
                "udp://192.0.2.53".into(),
                "udp://192.0.2.54".into(),
            ])
            .unwrap(),
            outbound: leaf,
        };
        let mut query = Message::new(45, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
        ));
        (manager, status, guard, execution, query)
    }

    struct S04bmEvidenceWire {
        reported: Option<crate::app::flow::NetworkPathId>,
        calls: Arc<AtomicUsize>,
        flip_network: Option<crate::proxy::utils::SharedNetworkStatus>,
    }

    #[async_trait]
    impl crate::app::dns::execution::DnsStrictTransport for S04bmEvidenceWire {
        async fn exchange(
            &self,
            _: &crate::app::dns::config::NameServer,
            _: AnyOutboundHandler,
            _: &hickory_proto::op::Message,
        ) -> io::Result<hickory_proto::op::Message> {
            panic!(
                "the ordinary DNS transport must never bypass the attested entrypoint"
            )
        }
    }

    #[async_trait]
    impl crate::app::dns::bootstrap_socket::DnsStrictSocketPathTransport
        for S04bmEvidenceWire
    {
        async fn exchange_with_socket_evidence(
            &self,
            _: &crate::app::dns::config::NameServer,
            _: AnyOutboundHandler,
            query: &hickory_proto::op::Message,
        ) -> io::Result<(
            hickory_proto::op::Message,
            crate::app::dns::bootstrap_socket::StrictDnsSocketPathEvidence,
        )> {
            use crate::app::{
                dispatcher::{BoxedChainedStream, ChainedStreamWrapper},
                dns::bootstrap_socket::StrictDnsSocketPathEvidence,
            };
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (physical_stream, _other_end) = tokio::io::duplex(64);
            // Production must derive these identities from the connector
            // which opened this socket. This synthetic socket only tests
            // the proof boundary, not OS routing or interface binding.
            let stream: BoxedChainedStream =
                Box::new(ChainedStreamWrapper::new_with_network_path_ids(
                    physical_stream,
                    self.reported.clone().into_iter().collect(),
                ));
            let evidence = StrictDnsSocketPathEvidence::from_stream(&stream)?;
            if let Some(status) = &self.flip_network {
                status.write().await.observed(&NetworkSnapshot {
                    dns: "changed-in-flight".into(),
                    ..NetworkSnapshot::default()
                });
            }
            let mut answer = hickory_proto::op::Message::response(
                query.metadata.id,
                hickory_proto::op::OpCode::Query,
            );
            answer.add_queries(query.queries.iter().cloned());
            Ok((answer, evidence))
        }
    }

    /// This wire mock deliberately has no client-side NetworkPathSource.
    /// Its path IDs are synthetic and only exercise the manager/transport
    /// guard; they do not claim any OS socket egress or DNS wire activity.
    struct S04baaObservedWire {
        status: crate::proxy::utils::SharedNetworkStatus,
        calls: Arc<AtomicUsize>,
        switch_epoch: bool,
        fail_after_switch: bool,
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        resume: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    #[async_trait]
    impl crate::app::dns::execution::DnsStrictTransport for S04baaObservedWire {
        async fn exchange(
            &self,
            _: &crate::app::dns::config::NameServer,
            _: AnyOutboundHandler,
            _: &hickory_proto::op::Message,
        ) -> io::Result<hickory_proto::op::Message> {
            panic!("evidence-required DNS cannot downgrade to unchecked exchange")
        }
    }

    #[async_trait]
    impl crate::app::dns::bootstrap_socket::DnsStrictSocketPathTransport
        for S04baaObservedWire
    {
        async fn exchange_with_socket_evidence(
            &self,
            _: &crate::app::dns::config::NameServer,
            _: AnyOutboundHandler,
            request: &hickory_proto::op::Message,
        ) -> io::Result<(
            hickory_proto::op::Message,
            crate::app::dns::bootstrap_socket::StrictDnsSocketPathEvidence,
        )> {
            use crate::app::dns::bootstrap_socket::StrictDnsSocketPathEvidence;
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            if let Some(resume) = self.resume.lock().await.take() {
                let _ = resume.await;
            }
            if self.switch_epoch {
                let mut network = self.status.write().await;
                let (_, candidates, _, _) = network
                    .path_planning_snapshot()
                    .expect("fixture must have observed candidates");
                network.observed(&NetworkSnapshot {
                    dns: "s04baa-network-switch".into(),
                    path_candidates: candidates,
                    ..Default::default()
                });
            }
            if self.fail_after_switch {
                return Err(io::Error::other(
                    "synthetic upstream transport failure",
                ));
            }
            let current =
                self.status.read().await.strict_dns_generations().unwrap().0;
            let (raw, _) = tokio::io::duplex(64);
            let stream: crate::app::dispatcher::BoxedChainedStream = Box::new(
                crate::app::dispatcher::ChainedStreamWrapper::new_with_network_path_ids(
                    raw, vec![s04bm_path(current)],
                ),
            );
            let evidence = StrictDnsSocketPathEvidence::from_stream(&stream)?;
            let mut response = hickory_proto::op::Message::response(
                request.metadata.id,
                hickory_proto::op::OpCode::Query,
            );
            response.add_queries(request.queries.iter().cloned());
            Ok((response, evidence))
        }
    }

    #[tokio::test]
    async fn s04baa_manager_evidence_adapter_binds_begin_and_end_epoch_without_client_observer()
     {
        use crate::app::dns::bootstrap_socket::StrictDnsEvidenceCheckedTransport;
        for (switch_epoch, fail_after_switch) in
            [(false, false), (true, false), (true, true)]
        {
            let (manager, status, _guard, execution, request) =
                s04bl_fixture().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let wire = S04baaObservedWire {
                status: status.clone(),
                calls: calls.clone(),
                switch_epoch,
                fail_after_switch,
                entered: std::sync::Mutex::new(None),
                resume: tokio::sync::Mutex::new(None),
            };
            let checked =
                StrictDnsEvidenceCheckedTransport::new(&wire, &manager, &status);
            // No outer leased guard in this focused test: the adapter must
            // independently detect in-flight changes, even when the wire
            // returns valid *new-epoch* socket IDs.
            let result = execution.exchange(&checked, &request).await;
            if switch_epoch {
                let error =
                    result.expect_err("network update must prevent proof handoff");
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                assert!(
                    error
                        .to_string()
                        .contains("during socket-evidence exchange")
                );
            } else {
                assert_eq!(result.unwrap().queries, request.queries);
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "never retry with another DNS server after epoch mismatch"
            );
        }
    }

    #[tokio::test]
    async fn s04bab_binding_probe_aba_rejects_attested_dns_without_network_version_bump()
     {
        use crate::{
            app::dns::bootstrap_socket::StrictDnsEvidenceCheckedTransport,
            app::network::BindingStatus,
        };
        let (manager, status, _guard, execution, request) = s04bl_fixture().await;
        let network_version =
            manager.strict_dns_path_generation(&status).await.unwrap();
        let original_revision =
            status.read().await.strict_dns_path_revision().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let wire = S04baaObservedWire {
            status: status.clone(),
            calls: calls.clone(),
            switch_epoch: false,
            fail_after_switch: false,
            entered: std::sync::Mutex::new(Some(entered_tx)),
            resume: tokio::sync::Mutex::new(Some(resume_rx)),
        };
        let observed_manager = manager.clone();
        let observed_status = status.clone();
        let query = tokio::spawn(async move {
            let checked = StrictDnsEvidenceCheckedTransport::new(
                &wire,
                &observed_manager,
                &observed_status,
            );
            execution.exchange(&checked, &request).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), entered_rx)
            .await
            .unwrap()
            .unwrap();
        let mut state = status.write().await;
        let (_, mut candidates, _, _) = state.path_planning_snapshot().unwrap();
        assert_eq!(candidates.len(), 1);
        candidates[0].binding = BindingStatus::Failed;
        candidates[0].binding_error = Some("transient bind error".into());
        state.observed(&NetworkSnapshot {
            path_candidates: candidates.clone(),
            ..Default::default()
        });
        let failed_revision = state.strict_dns_path_revision().unwrap();
        assert!(failed_revision > original_revision);
        assert_eq!(
            state.strict_dns_generations().unwrap().0,
            network_version,
            "diagnostic bind failure must not force global transport recovery"
        );
        state.observed(&NetworkSnapshot {
            path_candidates: candidates.clone(),
            ..Default::default()
        });
        assert_eq!(
            state.strict_dns_path_revision().unwrap(),
            failed_revision,
            "an unchanged failed probe must not spuriously advance the proof revision"
        );
        candidates[0].binding = BindingStatus::Verified;
        candidates[0].binding_error = None;
        state.observed(&NetworkSnapshot {
            path_candidates: candidates,
            ..Default::default()
        });
        assert!(state.strict_dns_path_revision().unwrap() > failed_revision);
        assert_eq!(
            state.strict_dns_generations().unwrap().0,
            network_version,
            "A->B->A bind probes retain the public network version"
        );
        drop(state);
        resume_tx.send(()).unwrap();
        let error = tokio::time::timeout(std::time::Duration::from_secs(3), query)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(error.to_string().contains("proof changed"), "{error}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a strict proof ABA violation is terminal, never a DNS retry"
        );
    }

    #[tokio::test]
    async fn s04baa_cancelled_evidence_exchange_releases_registry_lease() {
        for abort_directly in [false, true] {
            let (manager, status, guard, execution, request) = s04bl_fixture().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (_release_tx, release_rx) = tokio::sync::oneshot::channel();
            let wire = S04baaObservedWire {
                status,
                calls: calls.clone(),
                switch_epoch: false,
                fail_after_switch: false,
                entered: std::sync::Mutex::new(Some(entered_tx)),
                resume: tokio::sync::Mutex::new(Some(release_rx)),
            };
            let task = tokio::spawn(async move {
                if abort_directly {
                    guard
                        .exchange_with_socket_evidence(&execution, &wire, &request)
                        .await
                } else {
                    tokio::time::timeout(
                        std::time::Duration::from_millis(70),
                        guard.exchange_with_socket_evidence(
                            &execution, &wire, &request,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "strict DNS test deadline expired",
                        )
                    })?
                }
            });
            tokio::time::timeout(std::time::Duration::from_secs(3), entered_rx)
                .await
                .unwrap()
                .unwrap();
            let registry = manager.registry.clone();
            let mut writer = tokio::spawn(async move {
                registry.write().await.clear();
            });
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(25),
                    &mut writer
                )
                .await
                .is_err(),
                "active evidence attempt must hold the registry lease"
            );
            if abort_directly {
                task.abort();
                assert!(
                    tokio::time::timeout(std::time::Duration::from_secs(3), task)
                        .await
                        .unwrap()
                        .unwrap_err()
                        .is_cancelled()
                );
            } else {
                let error =
                    tokio::time::timeout(std::time::Duration::from_secs(3), task)
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            }
            tokio::time::timeout(std::time::Duration::from_secs(3), writer)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "timeout or abort must never initiate another server attempt"
            );
        }
    }

    #[tokio::test]
    async fn s04bm_attested_socket_path_accepts_current_connector_report() {
        let (manager, status, guard, execution, request) = s04bl_fixture().await;
        let version = manager.strict_dns_path_generation(&status).await.unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let wire = S04bmEvidenceWire {
            reported: Some(s04bm_path(version)),
            calls: count.clone(),
            flip_network: None,
        };
        let answer = guard
            .exchange_with_socket_evidence(&execution, &wire, &request)
            .await
            .unwrap();
        assert_eq!(answer.queries, request.queries);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn s04bm_missing_stale_or_wrong_socket_paths_abort_without_retry() {
        for invalid in 0..4 {
            let (manager, status, guard, execution, request) = s04bl_fixture().await;
            let generation =
                manager.strict_dns_path_generation(&status).await.unwrap();
            let reported = match invalid {
                0 => None,
                1 => Some(s04bm_path(generation + 1)),
                2 => {
                    let mut other = s04bm_path(generation);
                    other.interface.name = "other-nic".into();
                    Some(other)
                }
                3 => {
                    let mut other = s04bm_path(generation);
                    other.source_address = Some("198.51.100.21".parse().unwrap());
                    Some(other)
                }
                _ => unreachable!(),
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let wire = S04bmEvidenceWire {
                reported,
                calls: calls.clone(),
                flip_network: None,
            };
            let error = guard
                .exchange_with_socket_evidence(&execution, &wire, &request)
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("strict DNS socket path"),
                "case {invalid}: {error}",
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "no second upstream after unverified path"
            );
        }
    }

    #[tokio::test]
    async fn s04bm_inflight_network_switch_rejects_attested_answer_without_retry() {
        let (manager, status, guard, execution, request) = s04bl_fixture().await;
        let generation = manager.strict_dns_path_generation(&status).await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let wire = S04bmEvidenceWire {
            reported: Some(s04bm_path(generation)),
            calls: calls.clone(),
            flip_network: Some(status),
        };
        let err = guard
            .exchange_with_socket_evidence(&execution, &wire, &request)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("strict DNS"), "{err}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn s04bm_socket_evidence_rejects_unlabelled_or_invalid_streams() {
        use crate::app::{
            dispatcher::{BoxedChainedStream, ChainedStreamWrapper},
            dns::bootstrap_socket::StrictDnsSocketPathEvidence,
        };
        let (raw, _) = tokio::io::duplex(64);
        let unlabelled: BoxedChainedStream =
            Box::new(ChainedStreamWrapper::new(raw));
        assert!(
            StrictDnsSocketPathEvidence::from_stream(&unlabelled)
                .err()
                .unwrap()
                .to_string()
                .contains("missing")
        );

        let (raw, _) = tokio::io::duplex(64);
        let mut bad = s04bm_path(1);
        bad.source_address = None;
        let bad_stream: BoxedChainedStream = Box::new(
            ChainedStreamWrapper::new_with_network_path_ids(raw, vec![bad]),
        );
        assert!(
            StrictDnsSocketPathEvidence::from_stream(&bad_stream)
                .err()
                .unwrap()
                .to_string()
                .contains("invalid")
        );
    }

    #[tokio::test]
    async fn s04bl_leased_exchange_timeout_releases_writer() {
        use std::time::Duration;
        let (manager, _, guard, execution, query) = s04bl_fixture().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel();
        let wire = S04bkPausedTransport {
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
        };
        let job = tokio::spawn(async move {
            guard
                .exchange_with_lease_budget(
                    &execution,
                    &wire,
                    &query,
                    Duration::from_millis(200),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), entered_rx)
            .await
            .unwrap()
            .unwrap();
        let registry = manager.registry.clone();
        let mut writer = tokio::spawn(async move {
            registry.write().await.insert(
                "via".into(),
                Arc::new(StrictConnectorTestNode {
                    name: "via",
                    host: "192.0.2.21",
                    via: None,
                    proto: OutboundType::Socks5,
                }) as AnyOutboundHandler,
            );
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(40), &mut writer)
                .await
                .is_err(),
            "registry writer must block during DNS I/O"
        );
        let error = tokio::time::timeout(Duration::from_secs(3), job)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        tokio::time::timeout(Duration::from_secs(3), writer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn s04bl_aborting_leased_exchange_releases_writer() {
        use std::time::Duration;
        let (manager, _, guard, execution, query) = s04bl_fixture().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel();
        let wire = S04bkPausedTransport {
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
        };
        let job = tokio::spawn(async move {
            guard
                .exchange_with_leased_connector(&execution, &wire, &query)
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), entered_rx)
            .await
            .unwrap()
            .unwrap();
        let registry = manager.registry.clone();
        let mut writer = tokio::spawn(async move {
            registry.write().await.clear();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(40), &mut writer)
                .await
                .is_err(),
            "writer must await active lease"
        );
        job.abort();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), job)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled()
        );
        tokio::time::timeout(Duration::from_secs(3), writer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn s04bl_waiting_for_registry_lease_times_out_without_leaking_waiter() {
        use std::time::Duration;
        let (manager, _, guard, execution, query) = s04bl_fixture().await;
        let writer_lease = manager.registry.write().await;
        let (entered_tx, mut entered_rx) = tokio::sync::oneshot::channel();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel();
        let wire = S04bkPausedTransport {
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            guard.exchange_with_lease_budget(
                &execution,
                &wire,
                &query,
                Duration::from_millis(60),
            ),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(
            entered_rx.try_recv().is_err(),
            "no transport call before lease"
        );
        drop(writer_lease);
        // An abandoned read waiter must not lock out a subsequent write.
        let new_writer =
            tokio::time::timeout(Duration::from_secs(3), manager.registry.write())
                .await
                .unwrap();
        drop(new_writer);
    }

    #[tokio::test]
    async fn s04bl_socket_path_generation_rejects_foreign_or_detached_runtime() {
        use tokio::sync::RwLock;
        let (manager, status, guard, execution, query) = s04bl_fixture().await;
        assert!(manager.strict_dns_path_generation(&status).await.is_ok());
        let other = Arc::new(RwLock::new(NetworkStatus::default()));
        other.write().await.observed(&NetworkSnapshot::default());
        let error = manager
            .strict_dns_path_generation(&other)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("different runtime"), "{error}");

        // Simulate a manager whose socket path source was swapped after
        // successful bind. Guard must reject before it enters any transport.
        manager.attach_network_status(other).await;
        let (entered_tx, _entered_rx) = tokio::sync::oneshot::channel();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel();
        let wire = S04bkPausedTransport {
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
        };
        let error = guard
            .exchange_with_leased_connector(&execution, &wire, &query)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("different runtime"), "{error}");
    }

    #[tokio::test]
    async fn s04bk_registry_lease_blocks_inflight_aba_and_network_change_still_fails()
     {
        use crate::app::{
            dns::{
                bootstrap_provider::{
                    StrictDnsManagerLeafGuard, StrictProviderObservation,
                },
                execution::StrictDnsExecution,
                policy::DnsEgress,
            },
            remote_content_manager::{
                healthcheck::HealthCheck,
                providers::proxy_provider::{
                    ThreadSafeProxyProvider, plain_provider::PlainProvider,
                },
            },
        };
        use hickory_proto::{
            op::{Message, MessageType, OpCode, Query},
            rr::{Name, RecordType},
        };
        use tokio::sync::RwLock;

        let node = |host| -> AnyOutboundHandler {
            Arc::new(StrictConnectorTestNode {
                name: "via",
                host,
                via: None,
                proto: OutboundType::Socks5,
            })
        };
        let leaf: AnyOutboundHandler = Arc::new(StrictConnectorTestNode {
            name: "leaf",
            host: "192.0.2.10",
            via: Some("via"),
            proto: OutboundType::Socks5,
        });
        let original_hop = node("192.0.2.20");
        let mut manager = isolated_pool_manager(vec![original_hop.clone()]).await;
        let provider: ThreadSafeProxyProvider = Arc::new(RwLock::new(
            PlainProvider::new(
                "remote".into(),
                vec![leaf.clone()],
                HealthCheck::new(
                    vec![],
                    "http://example.invalid/health".into(),
                    0,
                    true,
                    manager.proxy_manager.clone(),
                ),
            )
            .unwrap(),
        ));
        manager.proxy_providers.insert("remote".into(), provider);
        let manager = Arc::new(manager);
        let registry = manager.registry.clone();
        let status = Arc::new(RwLock::new(NetworkStatus::default()));
        {
            let mut state = status.write().await;
            state.set_automatic_supported_for_test(true);
            state.observed(&NetworkSnapshot::default());
        }
        manager.attach_network_status(status.clone()).await;
        let observed = StrictProviderObservation::capture_manager(&status, &manager)
            .await
            .unwrap();
        let guard = StrictDnsManagerLeafGuard::bind(
            observed,
            &manager,
            &status,
            &registry,
            "remote",
            leaf.clone(),
        )
        .await
        .unwrap();
        let execution = StrictDnsExecution {
            ordinal: 0,
            egress: DnsEgress::Proxy("DNS-OUT".into()),
            profile: "trusted".into(),
            servers: crate::app::dns::Config::parse_nameserver(&[
                "udp://192.0.2.53".into(),
                "udp://192.0.2.54".into(),
            ])
            .unwrap(),
            outbound: leaf,
        };
        let mut query = Message::new(33, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
        ));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let wire = S04bkPausedTransport {
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
        };
        let job = tokio::spawn(async move {
            guard
                .exchange_with_leased_connector(&execution, &wire, &query)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), entered_rx)
            .await
            .unwrap()
            .unwrap();

        // A writer starts *after* the fake DNS request reaches its transport.
        // It cannot install B, then A, until the scoped registry lease drops.
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let writer_registry = registry.clone();
        let restored = original_hop.clone();
        let replacement = node("192.0.2.21");
        let mut writer = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            let mut entries = writer_registry.write().await;
            entries.insert("via".into(), replacement);
            entries.insert("via".into(), restored);
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
                .await
                .is_err(),
            "named-hop mutation must not complete during a leased DNS attempt",
        );

        // Network observation still changes independently of the registry
        // read lease. The stale DNS result must be discarded.
        status.write().await.observed(&NetworkSnapshot {
            dns: "new network".into(),
            ..NetworkSnapshot::default()
        });
        release_tx.send(()).unwrap();
        let error = tokio::time::timeout(std::time::Duration::from_secs(3), job)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(error.contains("stale network/config"), "{error}");
        tokio::time::timeout(std::time::Duration::from_secs(3), writer)
            .await
            .unwrap()
            .unwrap();
        let current = registry.read().await.get("via").cloned().unwrap();
        assert!(Arc::ptr_eq(&current, &original_hop));
    }

    #[tokio::test]
    async fn s04bk_acquiring_registry_lease_rejects_a_stale_named_hop() {
        use crate::app::dns::bootstrap_dialer::StrictDnsConnectorChain;
        let leaf: AnyOutboundHandler = Arc::new(StrictConnectorTestNode {
            name: "leaf",
            host: "192.0.2.10",
            via: Some("via"),
            proto: OutboundType::Socks5,
        });
        let original: AnyOutboundHandler = Arc::new(StrictConnectorTestNode {
            name: "via",
            host: "192.0.2.20",
            via: None,
            proto: OutboundType::Socks5,
        });
        let manager = Arc::new(isolated_pool_manager(vec![original]).await);
        let registry = manager.registry.clone();
        let observed = StrictDnsConnectorChain::capture(&manager, &registry, &leaf)
            .await
            .unwrap();
        registry.write().await.insert(
            "via".into(),
            Arc::new(StrictConnectorTestNode {
                name: "via",
                host: "192.0.2.20",
                via: None,
                proto: OutboundType::Socks5,
            }),
        );
        let error = observed
            .lease_for_exchange(&manager, &registry, &leaf)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("identity changed"), "{error}");
    }

    #[tokio::test]
    async fn s04bh_observation_uses_real_outbound_manager_and_rejects_foreign_registry()
     {
        use crate::{
            app::{
                dns::{
                    bootstrap_provider::StrictProviderObservation,
                    isolation::{StrictDnsCache, StrictDnsPlanSelection},
                    plan::{
                        DnsPurpose, DnsQueryContext, EffectiveDnsPlan, EgressChoice,
                        FailureChoice, LegacyDnsPlan, LegacyDnsRoute,
                        ResolverChoice,
                    },
                    policy::{CompiledDnsPolicy, DnsEgress, DnsFailure},
                },
                remote_content_manager::{
                    healthcheck::HealthCheck,
                    providers::proxy_provider::{
                        ThreadSafeProxyProvider, plain_provider::PlainProvider,
                    },
                },
            },
            config::def::Config as RawConfig,
            proxy::utils::OutboundHandlerRegistry,
        };
        use hickory_proto::{
            op::{Message, MessageType, OpCode, Query},
            rr::{Name, RecordType},
        };
        use std::collections::HashMap;
        use tokio::sync::RwLock;

        let leaf: AnyOutboundHandler = Arc::new(StrictDnsProviderLeaf);
        let mut manager = isolated_pool_manager(vec![]).await;
        manager
            .registry
            .write()
            .await
            .insert("DNS-OUT".into(), leaf.clone());
        let provider = PlainProvider::new(
            "remote".into(),
            vec![leaf.clone()],
            HealthCheck::new(
                vec![],
                "http://example.invalid/health".into(),
                0,
                true,
                manager.proxy_manager.clone(),
            ),
        )
        .unwrap();
        let handle: ThreadSafeProxyProvider = Arc::new(RwLock::new(provider));
        manager
            .proxy_providers
            .insert("remote".into(), handle.clone());
        let manager = Arc::new(manager);
        let status = Arc::new(RwLock::new(NetworkStatus::default()));
        status.write().await.observed(&NetworkSnapshot::default());
        let observed = StrictProviderObservation::capture_manager(&status, &manager)
            .await
            .unwrap();
        observed
            .ensure_current_manager(&status, &manager)
            .await
            .unwrap();

        let config: RawConfig = serde_yaml::from_str(
            "proxy-groups:\n  - {name: DNS-OUT, type: select, use: [remote]}\n",
        )
        .unwrap();
        let mut req = Message::new(7, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
        ));
        let plan = EffectiveDnsPlan {
            context: DnsQueryContext::from_message(
                &req,
                DnsPurpose::ClientRealAnswer,
            )
            .unwrap(),
            legacy: LegacyDnsPlan::new(LegacyDnsRoute::Main),
            matched_rule: Some(0),
            resolver: ResolverChoice::Profile("trusted".into()),
            egress: EgressChoice::Explicit(DnsEgress::Proxy("DNS-OUT".into())),
            failure: FailureChoice::Explicit(DnsFailure::Fail),
        };
        let profiles = CompiledDnsPolicy {
            profiles: HashMap::from([(
                "trusted".into(),
                crate::app::dns::Config::parse_nameserver(&[
                    "udp://192.0.2.53".into()
                ])
                .unwrap(),
            )]),
            rules: vec![],
        };
        let session = Session::default();
        let selected_registry = manager.registry.clone();
        fn selection<'a>(
            registry: &'a OutboundHandlerRegistry,
            plan: &'a EffectiveDnsPlan,
            profiles: &'a CompiledDnsPolicy,
            session: &'a Session,
        ) -> StrictDnsPlanSelection<'a> {
            StrictDnsPlanSelection {
                plan,
                profiles,
                registry,
                session,
            }
        }
        assert_eq!(
            StrictDnsCache::inspect_manager_provider_selection(
                selection(&selected_registry, &plan, &profiles, &session),
                &config,
                &manager,
                &status,
            )
            .await
            .unwrap(),
            "remote",
        );

        // An unrelated registry containing the *same exact handler Arc* is
        // still not authorized to act on behalf of this OutboundManager.
        let cloned_registry: OutboundHandlerRegistry = Arc::new(RwLock::new(
            HashMap::from([("DNS-OUT".into(), leaf.clone())]),
        ));
        let err = StrictDnsCache::inspect_manager_provider_selection(
            selection(&cloned_registry, &plan, &profiles, &session),
            &config,
            &manager,
            &status,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not belong"), "{err}");

        let mut other = isolated_pool_manager(vec![]).await;
        other.proxy_providers.insert("remote".into(), handle);
        let other = Arc::new(other);
        let err = observed
            .ensure_current_manager(&status, &other)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("different outbound manager"), "{err}");

        let pinned =
            crate::app::dns::bootstrap_provider::StrictDnsManagerLeafGuard::bind(
                StrictProviderObservation::capture_manager(&status, &manager)
                    .await
                    .unwrap(),
                &manager,
                &status,
                &selected_registry,
                "remote",
                leaf.clone(),
            )
            .await
            .unwrap();
        crate::app::dns::execution::DnsStrictAttemptGuard::ensure_current(
            &pinned, &leaf,
        )
        .await
        .unwrap();
        let impostor: AnyOutboundHandler = Arc::new(StrictDnsProviderLeaf);
        assert!(
            crate::app::dns::execution::DnsStrictAttemptGuard::ensure_current(
                &pinned, &impostor,
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("leaf identity changed")
        );

        status.write().await.observed(&NetworkSnapshot {
            dns: "changed network".into(),
            ..NetworkSnapshot::default()
        });
        let err = observed
            .ensure_current_manager(&status, &manager)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("stale network/config"), "{err}");
        assert!(
            crate::app::dns::execution::DnsStrictAttemptGuard::ensure_current(
                &pinned, &leaf,
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("stale network/config")
        );
    }

    /// Simulate a new network observation after initial pool retirement, while
    /// validating a selected provider/group leaf that was not in the registry.
    #[derive(Debug)]
    struct GenerationChangingHandler {
        status: Arc<tokio::sync::RwLock<NetworkStatus>>,
        resets: Arc<AtomicUsize>,
        change_on_every_reset: bool,
    }

    impl DialWithConnector for GenerationChangingHandler {}

    #[async_trait]
    impl OutboundHandler for GenerationChangingHandler {
        fn name(&self) -> &str {
            "provider-leaf"
        }

        fn proto(&self) -> OutboundType {
            OutboundType::Direct
        }

        async fn reset_connection_pool(&self) -> io::Result<u32> {
            let attempt = self.resets.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 || self.change_on_every_reset {
                let mut updated = NetworkSnapshot::default();
                updated.interfaces.push(format!("network-{attempt}"));
                self.status.write().await.observed(&updated);
            }
            Ok(0)
        }

        async fn connect_stream(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedStream> {
            unreachable!("generation-change test does not dial")
        }

        async fn connect_datagram(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedDatagram> {
            unreachable!("generation-change test does not dial")
        }
    }

    #[tokio::test]
    async fn new_observation_during_leaf_validation_retires_pools_again() {
        let direct: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "DIRECT",
            resets: Arc::new(AtomicUsize::new(0)),
            reset_count: 0,
            fail: false,
        });
        let manager = isolated_pool_manager(vec![direct]).await;
        let status = manager.network_path_source.snapshot().await.unwrap().3;
        let resets = Arc::new(AtomicUsize::new(0));
        let leaf: AnyOutboundHandler = Arc::new(GenerationChangingHandler {
            status,
            resets: resets.clone(),
            change_on_every_reset: false,
        });

        manager
            .ensure_outbound_ready_for_new_flow(&leaf)
            .await
            .unwrap();
        assert_eq!(resets.load(Ordering::SeqCst), 2);
        let generation = manager.network_path_source.snapshot().await.unwrap().0;
        assert_eq!(
            *manager.pool_network_generation.lock().await,
            Some(generation)
        );
    }

    #[tokio::test]
    async fn constantly_changing_observation_cannot_authorize_leaf_pool() {
        let direct: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "DIRECT",
            resets: Arc::new(AtomicUsize::new(0)),
            reset_count: 0,
            fail: false,
        });
        let manager = isolated_pool_manager(vec![direct]).await;
        let status = manager.network_path_source.snapshot().await.unwrap().3;
        let resets = Arc::new(AtomicUsize::new(0));
        let leaf: AnyOutboundHandler = Arc::new(GenerationChangingHandler {
            status,
            resets: resets.clone(),
            change_on_every_reset: true,
        });

        let error = manager
            .ensure_outbound_ready_for_new_flow(&leaf)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(resets.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn failing_pool_does_not_block_unrelated_outbound_and_stays_fail_closed() {
        let good_resets = Arc::new(AtomicUsize::new(0));
        let broken_resets = Arc::new(AtomicUsize::new(0));
        let good: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "DIRECT",
            resets: good_resets.clone(),
            reset_count: 0,
            fail: false,
        });
        let broken: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "VLESS",
            resets: broken_resets.clone(),
            reset_count: 0,
            fail: true,
        });
        let manager =
            isolated_pool_manager(vec![good.clone(), broken.clone()]).await;

        let selected = manager
            .get_outbound_for_new_flow("DIRECT")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.name(), "DIRECT");
        assert_eq!(good_resets.load(Ordering::SeqCst), 1);
        assert_eq!(broken_resets.load(Ordering::SeqCst), 1);

        let error = match manager.get_outbound_for_new_flow("VLESS").await {
            Ok(_) => panic!("failed pool must not be returned as dial-ready"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not safe to reuse"));
        assert_eq!(broken_resets.load(Ordering::SeqCst), 2);
        manager
            .get_outbound_for_new_flow("DIRECT")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(good_resets.load(Ordering::SeqCst), 1);

        // Dynamic proxy-group leaves are verified after being selected.
        let missing_from_registry: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "dynamic",
            resets: Arc::new(AtomicUsize::new(0)),
            reset_count: 0,
            fail: true,
        });
        assert!(
            manager
                .ensure_outbound_ready_for_new_flow(&missing_from_registry)
                .await
                .is_err()
        );
        assert!(
            manager
                .ensure_outbound_ready_for_new_flow(&good)
                .await
                .is_ok()
        );
        assert!(
            manager
                .ensure_outbound_ready_for_new_flow(&broken)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn manual_pool_reset_reports_failed_pool_without_poisoning_healthy_flow() {
        let good: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "DIRECT",
            resets: Arc::new(AtomicUsize::new(0)),
            reset_count: 2,
            fail: false,
        });
        let broken: AnyOutboundHandler = Arc::new(CountingHandler {
            name: "VLESS",
            resets: Arc::new(AtomicUsize::new(0)),
            reset_count: 0,
            fail: true,
        });
        let manager =
            isolated_pool_manager(vec![good.clone(), broken.clone()]).await;
        assert!(manager.reset_connection_pools().await.is_err());
        assert_eq!(manager.pool_retirement.lock().await.failed.len(), 1);
        assert_eq!(manager.pool_retirement.lock().await.ready.len(), 1);
        manager
            .get_outbound_for_new_flow("DIRECT")
            .await
            .unwrap()
            .unwrap();
        assert!(manager.get_outbound_for_new_flow("VLESS").await.is_err());
    }

    #[tokio::test]
    async fn stale_pool_generation_resets_once_and_retries_after_failure() {
        let source = NetworkPathSource::default();
        let mut initial_status = NetworkStatus::default();
        initial_status.set_automatic_supported_for_test(true);
        let initial = NetworkSnapshot::default();
        initial_status.observed(&initial);
        let shared_status = Arc::new(tokio::sync::RwLock::new(initial_status));
        source.attach(shared_status.clone()).await;

        let reset_gate = tokio::sync::Mutex::new(());
        let pool_generation = tokio::sync::Mutex::new(None);
        let resets = Arc::new(AtomicUsize::new(0));
        let reset_counter = resets.clone();
        assert!(
            ensure_pool_generation_current(
                &source,
                &reset_gate,
                &pool_generation,
                move |_| {
                    let reset_counter = reset_counter.clone();
                    async move {
                        reset_counter.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await
            .unwrap()
        );

        let reset_counter = resets.clone();
        assert!(
            !ensure_pool_generation_current(
                &source,
                &reset_gate,
                &pool_generation,
                move |_| {
                    let reset_counter = reset_counter.clone();
                    async move {
                        reset_counter.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await
            .unwrap()
        );

        let mut changed = initial;
        changed.interfaces.push("wifi0".to_owned());
        shared_status.write().await.observed(&changed);
        assert!(
            ensure_pool_generation_current(
                &source,
                &reset_gate,
                &pool_generation,
                |_| async { Err(io::Error::other("injected reset failure")) },
            )
            .await
            .is_err()
        );

        let reset_counter = resets.clone();
        assert!(
            ensure_pool_generation_current(
                &source,
                &reset_gate,
                &pool_generation,
                move |_| {
                    let reset_counter = reset_counter.clone();
                    async move {
                        reset_counter.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await
            .unwrap()
        );
        assert_eq!(resets.load(Ordering::SeqCst), 2);
        assert_eq!(*pool_generation.lock().await, Some(2));
    }

    #[tokio::test]
    async fn network_change_during_pool_retirement_retries_new_generation() {
        let source = NetworkPathSource::default();
        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        let initial = NetworkSnapshot::default();
        status.observed(&initial);
        let status = Arc::new(tokio::sync::RwLock::new(status));
        source.attach(status.clone()).await;
        let gate = tokio::sync::Mutex::new(());
        let pool_generation = tokio::sync::Mutex::new(None);
        let resets = Arc::new(AtomicUsize::new(0));

        let reset_count = resets.clone();
        let status_for_reset = status.clone();
        let changed = {
            let mut snapshot = initial;
            snapshot.interfaces.push("wifi0".to_owned());
            snapshot
        };
        assert!(
            ensure_pool_generation_current(
                &source,
                &gate,
                &pool_generation,
                move |_| {
                    let count = reset_count.clone();
                    let status = status_for_reset.clone();
                    let changed = changed.clone();
                    async move {
                        if count.fetch_add(1, Ordering::SeqCst) == 0 {
                            status.write().await.observed(&changed);
                        }
                        Ok(())
                    }
                },
            )
            .await
            .unwrap()
        );
        assert_eq!(resets.load(Ordering::SeqCst), 2);
        assert_eq!(*pool_generation.lock().await, Some(2));
    }

    #[tokio::test]
    async fn queued_flow_uses_latest_generation_after_concurrent_reset() {
        let source = Arc::new(NetworkPathSource::default());
        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        let mut changed = NetworkSnapshot::default();
        status.observed(&changed);
        let status = Arc::new(tokio::sync::RwLock::new(status));
        source.attach(status.clone()).await;
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let pool_generation = Arc::new(tokio::sync::Mutex::new(None));
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let resets = Arc::new(AtomicUsize::new(0));

        let first = {
            let source = source.clone();
            let gate = gate.clone();
            let pool_generation = pool_generation.clone();
            let started = started.clone();
            let release = release.clone();
            let resets = resets.clone();
            tokio::spawn(async move {
                ensure_pool_generation_current(
                    &source,
                    &gate,
                    &pool_generation,
                    move |_| {
                        let started = started.clone();
                        let release = release.clone();
                        let resets = resets.clone();
                        async move {
                            if resets.fetch_add(1, Ordering::SeqCst) == 0 {
                                started.notify_one();
                                release.notified().await;
                            }
                            Ok(())
                        }
                    },
                )
                .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
            .await
            .expect("first pool reset did not begin");

        changed.interfaces.push("wifi0".to_owned());
        status.write().await.observed(&changed);
        let second_resets = Arc::new(AtomicUsize::new(0));
        let queued = {
            let source = source.clone();
            let gate = gate.clone();
            let pool_generation = pool_generation.clone();
            let resets = second_resets.clone();
            tokio::spawn(async move {
                ensure_pool_generation_current(
                    &source,
                    &gate,
                    &pool_generation,
                    move |_| {
                        let resets = resets.clone();
                        async move {
                            resets.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        }
                    },
                )
                .await
            })
        };
        release.notify_one();
        assert!(first.await.unwrap().unwrap());
        assert!(!queued.await.unwrap().unwrap());
        assert_eq!(second_resets.load(Ordering::SeqCst), 0);
        assert_eq!(*pool_generation.lock().await, Some(2));
    }

    #[tokio::test]
    async fn continuously_changing_network_bounds_pool_retirement_retries() {
        let source = NetworkPathSource::default();
        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        status.observed(&NetworkSnapshot::default());
        let status = Arc::new(tokio::sync::RwLock::new(status));
        source.attach(status.clone()).await;
        let gate = tokio::sync::Mutex::new(());
        let pool_generation = tokio::sync::Mutex::new(None);
        let resets = Arc::new(AtomicUsize::new(0));
        let reset_count = resets.clone();
        let status_for_reset = status.clone();
        let error = ensure_pool_generation_current(
            &source,
            &gate,
            &pool_generation,
            move |_| {
                let resets = reset_count.clone();
                let status = status_for_reset.clone();
                async move {
                    let iteration = resets.fetch_add(1, Ordering::SeqCst);
                    let mut next = NetworkSnapshot::default();
                    next.interfaces.push(format!("wifi{iteration}"));
                    status.write().await.observed(&next);
                    Ok(())
                }
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(resets.load(Ordering::SeqCst), 3);
        assert_eq!(*pool_generation.lock().await, None);
    }
}
