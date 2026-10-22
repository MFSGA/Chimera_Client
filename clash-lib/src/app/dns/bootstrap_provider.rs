//! S04b-e: runtime-coherent proxy-provider candidate observations.
//!
//! Candidate revision proves *change detection*, not that provider input is
//! authenticated. This is intentionally not a production strict-DNS dial path.

use std::{
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
};

use hickory_proto::op::Message;

use crate::{
    app::{
        dns::{
            bootstrap_dialer::{StrictDnsConnectorChain, StrictDnsConnectorLease},
            execution::{
                DnsStrictAttemptGuard, DnsStrictTransport, StrictDnsExecution,
            },
        },
        outbound::manager::OutboundManager,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    proxy::{
        AnyOutboundHandler,
        utils::{OutboundHandlerRegistry, SharedNetworkStatus},
    },
};

/// S04b-g opt-in registry for strict observation only. All mutations must go
/// through this wrapper; the production Provider registry remains untouched.
/// Its monotonic revision detects short-lived A -> B -> A rebindings even if
/// the original handler identity is restored before the next read.
pub(crate) type StrictProviderRegistry = Arc<StrictProviderRegistryStore>;

struct RegistryState {
    revision: u64,
    sources: HashMap<String, ThreadSafeProxyProvider>,
}

pub(crate) struct StrictProviderRegistryStore {
    inner: tokio::sync::RwLock<RegistryState>,
}

impl StrictProviderRegistryStore {
    pub(crate) fn new(sources: HashMap<String, ThreadSafeProxyProvider>) -> Self {
        Self {
            inner: tokio::sync::RwLock::new(RegistryState {
                revision: 1,
                sources,
            }),
        }
    }

    /// A replacement always advances the revision, including replacements by
    /// the exact same Arc; callers cannot erase an intervening rebind.
    pub(crate) async fn replace(
        &self,
        name: String,
        provider: ThreadSafeProxyProvider,
    ) -> io::Result<u64> {
        let mut state = self.inner.write().await;
        let next = state.revision.checked_add(1).ok_or_else(|| {
            io::Error::other("strict DNS provider registry revision exhausted")
        })?;
        state.sources.insert(name, provider);
        state.revision = next;
        Ok(next)
    }

    async fn snapshot(&self) -> (u64, HashMap<String, ThreadSafeProxyProvider>) {
        let state = self.inner.read().await;
        (state.revision, state.sources.clone())
    }

    async fn matches(
        &self,
        revision: u64,
        observed: &HashMap<String, ObservedProvider>,
    ) -> bool {
        let state = self.inner.read().await;
        state.revision == revision
            && state.sources.len() == observed.len()
            && observed.iter().all(|(name, source)| {
                state
                    .sources
                    .get(name)
                    .is_some_and(|current| Arc::ptr_eq(current, &source.handle))
            })
    }
}

/// Pinned identity guard for S04b-i's internal non-caching DNS exchange.
/// It is deliberately NOT a trusted-source certificate or a permit to dial.
/// The exact selected handler object must belong to an observed real Manager
/// and Provider. The transport must use the pinned execution's own outbound.
pub(crate) struct StrictDnsManagerLeafGuard {
    observed: StrictProviderObservation,
    manager: Arc<OutboundManager>,
    status: SharedNetworkStatus,
    registry: OutboundHandlerRegistry,
    provider: String,
    selected: AnyOutboundHandler,
    connector: StrictDnsConnectorChain,
}

struct LeasedStrictAttempt<'a> {
    owner: &'a StrictDnsManagerLeafGuard,
    lease: &'a StrictDnsConnectorLease,
}

#[async_trait::async_trait]
impl DnsStrictAttemptGuard for LeasedStrictAttempt<'_> {
    async fn ensure_current(&self, outbound: &AnyOutboundHandler) -> io::Result<()> {
        self.owner.ensure_current_leased(outbound, self.lease).await
    }
}

impl StrictDnsManagerLeafGuard {
    /// The read lease spans all upstream attempts and their I/O. A writer to
    /// the actual manager registry cannot complete a transient A->B->A while
    /// the exchange is in flight. This is internal and deliberately unconnected
    /// to production DNS and the shared answer cache.
    pub(crate) async fn exchange_with_leased_connector<T: DnsStrictTransport>(
        &self,
        execution: &StrictDnsExecution,
        transport: &T,
        request: &Message,
    ) -> io::Result<Message> {
        let lease = self
            .connector
            .lease_for_exchange(&self.manager, &self.registry, &execution.outbound)
            .await?;
        self.ensure_current_leased(&execution.outbound, &lease)
            .await?;
        let check = LeasedStrictAttempt {
            owner: self,
            lease: &lease,
        };
        execution.exchange_guarded(transport, request, &check).await
    }

    async fn ensure_current_leased(
        &self,
        outbound: &AnyOutboundHandler,
        lease: &StrictDnsConnectorLease,
    ) -> io::Result<()> {
        if !Arc::ptr_eq(&self.selected, outbound) {
            return Err(io::Error::other(
                "strict DNS attempt selected leaf identity changed",
            ));
        }
        if !self.manager.owns_outbound_registry(&self.registry) {
            return Err(io::Error::other(
                "strict DNS attempt registry belongs to a different outbound manager",
            ));
        }
        self.observed
            .ensure_current_manager(&self.status, &self.manager)
            .await?;
        self.connector.ensure_leased(lease, outbound)?;
        self.observed
            .require_selected(&self.status, &self.provider, &self.selected)
            .await?;
        self.connector.ensure_leased(lease, outbound)?;
        self.observed
            .ensure_current_manager(&self.status, &self.manager)
            .await
    }

    pub(crate) async fn bind(
        observed: StrictProviderObservation,
        manager: &Arc<OutboundManager>,
        status: &SharedNetworkStatus,
        registry: &OutboundHandlerRegistry,
        provider: &str,
        selected: AnyOutboundHandler,
    ) -> io::Result<Self> {
        let connector =
            StrictDnsConnectorChain::capture(manager, registry, &selected).await?;
        let guard = Self {
            observed,
            connector,
            manager: manager.clone(),
            status: status.clone(),
            registry: registry.clone(),
            provider: provider.to_owned(),
            selected,
        };
        guard.ensure_current(&guard.selected).await?;
        Ok(guard)
    }
}

#[async_trait::async_trait]
impl DnsStrictAttemptGuard for StrictDnsManagerLeafGuard {
    async fn ensure_current(&self, outbound: &AnyOutboundHandler) -> io::Result<()> {
        if !Arc::ptr_eq(&self.selected, outbound) {
            return Err(io::Error::other(
                "strict DNS attempt selected leaf identity changed",
            ));
        }
        if !self.manager.owns_outbound_registry(&self.registry) {
            return Err(io::Error::other(
                "strict DNS attempt registry belongs to a different outbound manager",
            ));
        }
        self.observed
            .ensure_current_manager(&self.status, &self.manager)
            .await?;
        self.connector
            .ensure_current(&self.manager, &self.registry, &self.selected)
            .await?;
        self.observed
            .require_selected(&self.status, &self.provider, &self.selected)
            .await?;
        self.connector
            .ensure_current(&self.manager, &self.registry, &self.selected)
            .await?;
        self.observed
            .ensure_current_manager(&self.status, &self.manager)
            .await
    }
}

struct ObservedProvider {
    handle: ThreadSafeProxyProvider,
    revision: u64,
    candidates: Vec<AnyOutboundHandler>,
}

/// A candidate view bound to one runtime object, observed config/network epoch,
/// and the actual provider objects. Each source supplies its own atomic
/// content revision and candidates. No source is treated as authenticated.
pub(crate) struct StrictProviderObservation {
    runtime: SharedNetworkStatus,
    epoch: (u64, u64),
    sources: HashMap<String, ObservedProvider>,
    registry: Option<(StrictProviderRegistry, u64)>,
    manager: Option<Arc<OutboundManager>>,
}

impl StrictProviderObservation {
    pub(crate) async fn capture(
        runtime: &SharedNetworkStatus,
        sources: &HashMap<String, ThreadSafeProxyProvider>,
    ) -> io::Result<Self> {
        let epoch = runtime.read().await.strict_dns_generations().ok_or_else(|| {
            io::Error::other("strict DNS provider snapshot requires a current network observation")
        })?;
        if sources.is_empty() {
            return Err(io::Error::other(
                "strict DNS provider snapshot has no sources",
            ));
        }
        let mut observed = HashMap::new();
        for (name, handle) in sources {
            let provider = handle.read().await;
            if provider.name() != name {
                return Err(io::Error::other(format!(
                    "strict DNS provider '{name}' does not match its registered identity"
                )));
            }
            let data =
                provider.strict_content_snapshot().await.ok_or_else(|| {
                    io::Error::other(format!(
                        "strict DNS provider '{name}' has no atomic content revision"
                    ))
                })?;
            if data.revision == 0 || data.proxies.is_empty() {
                return Err(io::Error::other(format!(
                    "strict DNS provider '{name}' is uninitialized or has no candidates"
                )));
            }
            let mut names = HashSet::new();
            for candidate in &data.proxies {
                if candidate.name().is_empty() || !names.insert(candidate.name()) {
                    return Err(io::Error::other(format!(
                        "strict DNS provider '{name}' has duplicate or empty candidate names"
                    )));
                }
            }
            observed.insert(
                name.clone(),
                ObservedProvider {
                    handle: handle.clone(),
                    revision: data.revision,
                    candidates: data.proxies,
                },
            );
        }
        let snapshot = Self {
            runtime: runtime.clone(),
            epoch,
            sources: observed,
            registry: None,
            manager: None,
        };
        snapshot.ensure_current(runtime).await?;
        Ok(snapshot)
    }

    /// Bind provider handles to the actual registry rather than only to a
    /// caller-supplied temporary name map. Rebinding a name is a hard miss.
    pub(crate) async fn capture_registered(
        runtime: &SharedNetworkStatus,
        registry: &StrictProviderRegistry,
    ) -> io::Result<Self> {
        let (revision, handles) = registry.snapshot().await;
        let mut view = Self::capture(runtime, &handles).await?;
        view.registry = Some((registry.clone(), revision));
        view.ensure_current(runtime).await?;
        Ok(view)
    }

    /// Observe the handles actually owned by an initialized OutboundManager,
    /// not a caller-assembled map. The manager is immutable after construction;
    /// provider content versions are checked separately on every validation.
    /// Keeping its Arc identity prevents confusing a hot-reloaded manager with
    /// the old instance even when all proxy names match.
    pub(crate) async fn capture_manager(
        runtime: &SharedNetworkStatus,
        manager: &Arc<OutboundManager>,
    ) -> io::Result<Self> {
        let sources = manager.get_proxy_providers();
        let mut view = Self::capture(runtime, &sources).await?;
        view.manager = Some(manager.clone());
        view.ensure_current_manager(runtime, manager).await?;
        Ok(view)
    }

    /// A manager-bound observation is valid only for that same Manager and the
    /// very same provider handles. This method does not authorize dialing or
    /// replace the S04b-d configuration/topology fail-closed policy.
    pub(crate) async fn ensure_current_manager(
        &self,
        runtime: &SharedNetworkStatus,
        manager: &Arc<OutboundManager>,
    ) -> io::Result<()> {
        if !self
            .manager
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, manager))
        {
            return Err(io::Error::other(
                "strict DNS provider observation belongs to a different outbound manager",
            ));
        }
        self.ensure_current(runtime).await?;
        let handles = manager.get_proxy_providers();
        if handles.len() != self.sources.len()
            || self.sources.iter().any(|(name, source)| {
                !handles
                    .get(name)
                    .is_some_and(|handle| Arc::ptr_eq(handle, &source.handle))
            })
        {
            return Err(io::Error::other(
                "strict DNS outbound manager provider handles changed",
            ));
        }
        self.ensure_current(runtime).await
    }

    /// Check again immediately before cache access and after upstream I/O.
    /// Detect even an A->B->A replacement when the provider revision advances.
    /// This does not freeze mutable provider content during the network call.
    pub(crate) async fn ensure_current(
        &self,
        runtime: &SharedNetworkStatus,
    ) -> io::Result<()> {
        if !Arc::ptr_eq(&self.runtime, runtime) {
            return Err(io::Error::other(
                "strict DNS provider snapshot belongs to another runtime",
            ));
        }
        if runtime.read().await.strict_dns_generations() != Some(self.epoch) {
            return Err(io::Error::other(
                "strict DNS provider snapshot has a stale network/config epoch",
            ));
        }
        if let Some((registry, revision)) = &self.registry
            && !registry.matches(*revision, &self.sources).await
        {
            return Err(io::Error::other(
                "strict DNS provider registry changed during the observed snapshot",
            ));
        }
        for (name, source) in &self.sources {
            let provider = source.handle.read().await;
            if provider.name() != name {
                return Err(io::Error::other(format!(
                    "strict DNS provider '{name}' changed registered identity"
                )));
            }
            let current =
                provider.strict_content_snapshot().await.ok_or_else(|| {
                    io::Error::other(format!(
                        "strict DNS provider '{name}' lost atomic content revision"
                    ))
                })?;
            if current.revision != source.revision
                || current.proxies.len() != source.candidates.len()
                || current
                    .proxies
                    .iter()
                    .zip(&source.candidates)
                    .any(|(a, b)| !Arc::ptr_eq(a, b))
            {
                return Err(io::Error::other(format!(
                    "strict DNS provider '{name}' changed during the observed snapshot"
                )));
            }
        }
        if let Some((registry, revision)) = &self.registry
            && !registry.matches(*revision, &self.sources).await
        {
            return Err(io::Error::other(
                "strict DNS provider registry changed during the observed snapshot",
            ));
        }
        // A concurrent network change between provider reads and now is also
        // rejected; no attempt is made to heal the snapshot automatically.
        if runtime.read().await.strict_dns_generations() != Some(self.epoch) {
            return Err(io::Error::other(
                "strict DNS provider snapshot has a stale network/config epoch",
            ));
        }
        Ok(())
    }

    /// Enforce the chosen dynamic leaf's *object identity*, not just its name.
    /// This proves membership in a coherent snapshot, not trustworthy origin.
    pub(crate) async fn require_selected(
        &self,
        runtime: &SharedNetworkStatus,
        provider: &str,
        selected: &AnyOutboundHandler,
    ) -> io::Result<()> {
        self.ensure_current(runtime).await?;
        let candidates = self.candidates(provider).ok_or_else(|| {
            io::Error::other(format!(
                "strict DNS provider '{provider}' not observed"
            ))
        })?;
        if !candidates
            .iter()
            .any(|candidate| Arc::ptr_eq(candidate, selected))
        {
            return Err(io::Error::other(format!(
                "strict DNS selected leaf '{}' not in observed provider '{provider}'",
                selected.name()
            )));
        }
        self.ensure_current(runtime).await
    }

    /// This guard only validates a read-only or non-caching operation. It must
    /// never be used to authorize transport dialing or mutate a shared cache.
    pub(crate) async fn validate_during<F: std::future::Future>(
        &self,
        runtime: &SharedNetworkStatus,
        operation: F,
    ) -> io::Result<F::Output> {
        self.ensure_current(runtime).await?;
        let outcome = operation.await;
        self.ensure_current(runtime).await?;
        Ok(outcome)
    }

    /// Identity-preserving read for future topology validation. Returning a
    /// provider view does not authorize resolving its hostname or dialing it.
    pub(crate) fn candidates(&self, name: &str) -> Option<&[AnyOutboundHandler]> {
        self.sources
            .get(name)
            .map(|source| source.candidates.as_slice())
    }
}
