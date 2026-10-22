//! S04b-e: runtime-coherent proxy-provider candidate observations.
//!
//! Candidate revision proves *change detection*, not that provider input is
//! authenticated. This is intentionally not a production strict-DNS dial path.

use std::{
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
};

use crate::{
    app::remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    proxy::AnyOutboundHandler, proxy::utils::SharedNetworkStatus,
};

/// Registry identity matters independently of provider content revisions:
/// replacing a provider object with a fresh revision=1 is not a safe no-op.
pub(crate) type StrictProviderRegistry =
    Arc<tokio::sync::RwLock<HashMap<String, ThreadSafeProxyProvider>>>;

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
    registry: Option<StrictProviderRegistry>,
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
        let handles = registry.read().await.clone();
        let mut view = Self::capture(runtime, &handles).await?;
        view.registry = Some(registry.clone());
        view.ensure_current(runtime).await?;
        Ok(view)
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
        if let Some(registry) = &self.registry {
            let registered = registry.read().await;
            if registered.len() != self.sources.len()
                || self.sources.iter().any(|(name, source)| {
                    !registered
                        .get(name)
                        .is_some_and(|current| Arc::ptr_eq(current, &source.handle))
                })
            {
                return Err(io::Error::other(
                    "strict DNS provider registry changed during the observed snapshot",
                ));
            }
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
        if let Some(registry) = &self.registry {
            let registered = registry.read().await;
            if registered.len() != self.sources.len()
                || self.sources.iter().any(|(name, source)| {
                    !registered
                        .get(name)
                        .is_some_and(|current| Arc::ptr_eq(current, &source.handle))
                })
            {
                return Err(io::Error::other(
                    "strict DNS provider registry changed during the observed snapshot",
                ));
            }
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
