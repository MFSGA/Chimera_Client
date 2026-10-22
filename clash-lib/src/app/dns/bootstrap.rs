//! S04b-b: explicit strict-DNS bootstrap pin snapshots and revision lifecycle.
//!
//! This store does NOT discover or authenticate DNS answers. A future trusted
//! bootstrap source must verify every input before calling `install_explicit`.
//! No production resolver consumes this module while policy-rules are gated.

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use crate::proxy::utils::SharedNetworkStatus;

use super::execution::DnsStrictPinnedWireTransport;

struct State {
    owner: Option<SharedNetworkStatus>,
    epoch: Option<(u64, u64)>,
    revision: u64,
    pins: HashMap<String, IpAddr>,
}

/// All revisions remain monotonic for this store's lifetime, including after
/// network changes and successful configuration reloads.
pub(crate) struct StrictBootstrapPinStore {
    inner: Mutex<State>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StrictBootstrapPinSnapshot {
    epoch: (u64, u64),
    revision: u64,
    pins: HashMap<String, IpAddr>,
}

impl StrictBootstrapPinSnapshot {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn epoch(&self) -> (u64, u64) {
        self.epoch
    }

    pub fn transport(&self) -> io::Result<DnsStrictPinnedWireTransport> {
        DnsStrictPinnedWireTransport::new(self.pins.clone())
    }
}

impl Default for StrictBootstrapPinStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(State {
                owner: None,
                epoch: None,
                revision: 0,
                pins: HashMap::new(),
            }),
        }
    }
}

impl StrictBootstrapPinStore {
    /// Install a caller-verified, canonical explicit pin set for the *current*
    /// observed runtime. Empty sets deliberately revoke all hostname pins.
    /// Any change (including a network/config change) increments the revision.
    /// Keeping the RuntimeStatus read guard prevents a concurrent reload from
    /// invalidating the observed epoch between validation and installation.
    /// Production callers are intentionally absent until pin provenance exists.
    #[allow(dead_code)]
    pub async fn install_explicit(
        &self,
        status: &SharedNetworkStatus,
        pins: HashMap<String, IpAddr>,
    ) -> io::Result<u64> {
        DnsStrictPinnedWireTransport::new(pins.clone())?;
        let guard = status.read().await;
        let epoch = guard.strict_dns_generations().ok_or_else(|| {
            io::Error::other(
                "strict DNS bootstrap pins require current network observation",
            )
        })?;
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .owner
            .as_ref()
            .is_some_and(|owner| !Arc::ptr_eq(owner, status))
        {
            return Err(io::Error::other(
                "strict DNS bootstrap pin store belongs to a different runtime",
            ));
        }
        if state.epoch == Some(epoch) && state.pins == pins {
            return Ok(state.revision);
        }
        state.revision = state.revision.checked_add(1).ok_or_else(|| {
            io::Error::other("strict DNS bootstrap pin revision exhausted")
        })?;
        state.owner = Some(status.clone());
        state.epoch = Some(epoch);
        state.pins = pins;
        Ok(state.revision)
    }

    /// Never silently reuse pins from an older network or config generation.
    /// Callers must explicitly reverify/reinstall pins after a runtime change.
    pub async fn snapshot_current(
        &self,
        status: &SharedNetworkStatus,
    ) -> io::Result<StrictBootstrapPinSnapshot> {
        let guard = status.read().await;
        let epoch = guard.strict_dns_generations().ok_or_else(|| {
            io::Error::other(
                "strict DNS bootstrap pins require current network observation",
            )
        })?;
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .owner
            .as_ref()
            .is_some_and(|owner| !Arc::ptr_eq(owner, status))
        {
            return Err(io::Error::other(
                "strict DNS bootstrap pin store belongs to a different runtime",
            ));
        }
        if state.epoch != Some(epoch) {
            return Err(io::Error::other(
                "strict DNS bootstrap pins are stale or missing for current network/config generation",
            ));
        }
        Ok(StrictBootstrapPinSnapshot {
            epoch,
            revision: state.revision,
            pins: state.pins.clone(),
        })
    }

    pub async fn still_current(
        &self,
        status: &SharedNetworkStatus,
        original: &StrictBootstrapPinSnapshot,
    ) -> io::Result<bool> {
        let current = self.snapshot_current(status).await?;
        Ok(current == *original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{
        dns::execution::DnsStrictTransport,
        network::{NetworkSnapshot, NetworkStatus},
        runtime_state::Lifecycle,
    };
    use std::sync::Arc;

    fn runtime() -> SharedNetworkStatus {
        Arc::new(tokio::sync::RwLock::new(NetworkStatus::default()))
    }

    fn pin(ip: [u8; 4]) -> HashMap<String, IpAddr> {
        HashMap::from([("dns.example".into(), IpAddr::from(ip))])
    }

    #[tokio::test]
    async fn s04bb_pin_revisions_rotate_without_reusing_stale_network_or_config() {
        let status = runtime();
        let store = StrictBootstrapPinStore::default();
        assert!(
            store
                .install_explicit(&status, pin([192, 0, 2, 1]))
                .await
                .is_err()
        );
        assert!(store.snapshot_current(&status).await.is_err());
        let first_network = NetworkSnapshot::default();
        status.write().await.observed(&first_network);
        assert_eq!(
            store
                .install_explicit(&status, pin([192, 0, 2, 1]))
                .await
                .unwrap(),
            1
        );
        let first = store.snapshot_current(&status).await.unwrap();
        assert_eq!(first.revision(), 1);
        assert_eq!(
            store
                .install_explicit(&status, pin([192, 0, 2, 1]))
                .await
                .unwrap(),
            1
        );
        assert!(store.still_current(&status, &first).await.unwrap());
        assert_eq!(
            store
                .install_explicit(&status, pin([192, 0, 2, 2]))
                .await
                .unwrap(),
            2
        );
        assert!(!store.still_current(&status, &first).await.unwrap());
        let second = store.snapshot_current(&status).await.unwrap();
        assert_ne!(
            first.transport().unwrap().isolation_fingerprint(),
            second.transport().unwrap().isolation_fingerprint()
        );

        status.write().await.observed(&NetworkSnapshot {
            dns: "changed network".into(),
            ..first_network
        });
        assert!(store.snapshot_current(&status).await.is_err());
        assert_eq!(
            store
                .install_explicit(&status, pin([192, 0, 2, 2]))
                .await
                .unwrap(),
            3
        );
        let third = store.snapshot_current(&status).await.unwrap();
        assert_ne!(third.epoch(), second.epoch());

        {
            let mut state = status.write().await;
            assert!(state.lifecycle(Lifecycle::Running, "testReady"));
            assert!(state.lifecycle(Lifecycle::Reloading, "configReload"));
            state.reload_finished(None);
        }
        assert!(store.snapshot_current(&status).await.is_err());
        assert!(
            store
                .install_explicit(&status, pin([192, 0, 2, 2]))
                .await
                .is_err()
        );
        status.write().await.observed(&NetworkSnapshot::default());
        assert_eq!(
            store
                .install_explicit(&status, pin([192, 0, 2, 2]))
                .await
                .unwrap(),
            4
        );
        assert!(!store.still_current(&status, &third).await.unwrap());
    }

    #[tokio::test]
    async fn s04bb_different_runtimes_cannot_share_same_generation_pins() {
        let first_runtime = runtime();
        let second_runtime = runtime();
        first_runtime
            .write()
            .await
            .observed(&NetworkSnapshot::default());
        second_runtime
            .write()
            .await
            .observed(&NetworkSnapshot::default());
        assert_eq!(
            first_runtime.read().await.strict_dns_generations(),
            second_runtime.read().await.strict_dns_generations()
        );
        let store = StrictBootstrapPinStore::default();
        store
            .install_explicit(&first_runtime, pin([192, 0, 2, 1]))
            .await
            .unwrap();
        assert!(
            store
                .snapshot_current(&second_runtime)
                .await
                .unwrap_err()
                .to_string()
                .contains("different runtime")
        );
        assert!(
            store
                .install_explicit(&second_runtime, pin([192, 0, 2, 2]))
                .await
                .unwrap_err()
                .to_string()
                .contains("different runtime")
        );
        assert_eq!(
            store
                .snapshot_current(&first_runtime)
                .await
                .unwrap()
                .revision(),
            1
        );
    }

    #[tokio::test]
    async fn s04bb_invalid_or_revoked_pins_fail_closed() {
        let status = runtime();
        status.write().await.observed(&NetworkSnapshot::default());
        let store = StrictBootstrapPinStore::default();
        assert!(
            store
                .install_explicit(
                    &status,
                    HashMap::from([(
                        "DNS.EXAMPLE".into(),
                        IpAddr::from([192, 0, 2, 1])
                    )])
                )
                .await
                .is_err()
        );
        assert!(store.snapshot_current(&status).await.is_err());
        assert_eq!(
            store
                .install_explicit(&status, pin([192, 0, 2, 1]))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .install_explicit(&status, HashMap::new())
                .await
                .unwrap(),
            2
        );
        let empty = store.snapshot_current(&status).await.unwrap();
        assert_eq!(empty.revision(), 2);
        assert!(
            empty
                .transport()
                .unwrap()
                .validate_server(
                    &crate::app::dns::Config::parse_nameserver(&[
                        "tls://dns.example".into()
                    ])
                    .unwrap()[0]
                )
                .is_err()
        );
    }
}
