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
        };
        snapshot.ensure_current(runtime).await?;
        Ok(snapshot)
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
        // A concurrent network change between provider reads and now is also
        // rejected; no attempt is made to heal the snapshot automatically.
        if runtime.read().await.strict_dns_generations() != Some(self.epoch) {
            return Err(io::Error::other(
                "strict DNS provider snapshot has a stale network/config epoch",
            ));
        }
        Ok(())
    }

    /// Identity-preserving read for future topology validation. Returning a
    /// provider view does not authorize resolving its hostname or dialing it.
    pub(crate) fn candidates(&self, name: &str) -> Option<&[AnyOutboundHandler]> {
        self.sources
            .get(name)
            .map(|source| source.candidates.as_slice())
    }
}
