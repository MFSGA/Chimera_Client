use super::{ProxyProvider, ProxyProviderContentSnapshot};
use crate::{
    Error,
    app::{
        outbound::manager::OutboundManager,
        remote_content_manager::{
            healthcheck::HealthCheck,
            providers::{
                Provider, ProviderType, ProviderVehicleType,
                ThreadSafeProviderVehicle,
                fetcher::{CacheCommitAccepted, CacheCommitRollback, Fetcher},
                initialize_provider_with_retry,
            },
        },
    },
    common::errors::map_io_error,
    config::internal::{
        config::validate_xhttp_secondary_managed_dns, proxy::OutboundProxyProtocol,
    },
    proxy::AnyOutboundHandler,
};
use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::{debug, warn};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    proxies: Option<Vec<HashMap<String, Value>>>,
}

#[derive(Clone)]
struct Inner {
    proxies: Vec<AnyOutboundHandler>,
    revision: u64,
}

type ProxyUpdater = Box<
    dyn Fn(Vec<AnyOutboundHandler>) -> BoxFuture<'static, anyhow::Result<()>>
        + Send
        + Sync
        + 'static,
>;
type ProxyParser = Box<
    dyn Fn(&[u8]) -> anyhow::Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static,
>;

#[cfg(test)]
type BeforeCacheCommit = Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

pub struct ProxySetProvider {
    fetcher: Fetcher<ProxyUpdater, ProxyParser>,
    hc: Arc<HealthCheck>,
    inner: Arc<tokio::sync::RwLock<Inner>>,
    /// Prevent readers from observing an uncommitted proxy revision while
    /// provider DNS ownership and the backing cache are in transition.
    publication_gate: Arc<tokio::sync::RwLock<()>>,
    #[cfg(test)]
    before_cache_commit: Arc<tokio::sync::Mutex<Option<BeforeCacheCommit>>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        hc: HealthCheck,
    ) -> anyhow::Result<Self> {
        Self::new_with_dns_privacy(name, interval, vehicle, hc, false)
    }

    /// Provider refreshes bypass Config::validate. Apply the same fail-closed
    /// XHTTP DNS policy to all subsequent versions of a provider.
    pub(crate) fn new_with_dns_privacy(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        hc: HealthCheck,
        protect_provider_dns: bool,
    ) -> anyhow::Result<Self> {
        let hc = Arc::new(hc);

        if hc.auto() {
            let hc = hc.clone();
            debug!("kicking off healthcheck for: {}", &name);
            tokio::spawn(async move {
                hc.kick_off().await;
            });
        }

        let inner = Arc::new(tokio::sync::RwLock::new(Inner {
            proxies: vec![],
            revision: 0,
        }));
        let inner_clone = inner.clone();
        // The fetcher serializes candidate updates through its own lock.
        // Keep the previous visible revision until the corresponding cache
        // rename succeeds, so a late rename error can restore both provider
        // visibility and the registrar's owner-scoped DNS mapping.
        let rollback_revision = Arc::new(tokio::sync::Mutex::new(None::<Inner>));
        let updater_rollback_revision = rollback_revision.clone();
        let publication_gate = Arc::new(tokio::sync::RwLock::new(()));
        let updater_gate = publication_gate.clone();
        let pending_publication = Arc::new(tokio::sync::Mutex::new(
            None::<tokio::sync::OwnedRwLockWriteGuard<()>>,
        ));
        let updater_pending_publication = pending_publication.clone();
        #[cfg(test)]
        let before_cache_commit: Arc<
            tokio::sync::Mutex<Option<BeforeCacheCommit>>,
        > = Arc::new(tokio::sync::Mutex::new(None));
        #[cfg(test)]
        let updater_before_commit = before_cache_commit.clone();

        let updater_hc = hc.clone();
        let updater_name = name.clone();
        let updater: ProxyUpdater = Box::new(move |input| {
            let hc = updater_hc.clone();
            let name = updater_name.clone();
            let inner = inner_clone.clone();
            let rollback_revision = updater_rollback_revision.clone();
            let publication_gate = updater_gate.clone();
            let pending_publication = updater_pending_publication.clone();
            #[cfg(test)]
            let before_commit = updater_before_commit.clone();
            Box::pin(async move {
                // Hold reader admission across registration, provisional
                // publication and final cache commit/compensation. Readers
                // cannot observe a candidate that later fails persistence.
                let admission = publication_gate.write_owned().await;
                // Store the owned guard *before* any fallible/awaited DNS
                // registration. Otherwise cancellation after changing the
                // visible proxy revision but before handing over the guard
                // can silently reopen readers on uncommitted content.
                *pending_publication.lock().await = Some(admission);
                // Serialise registration with publication: two overlapping
                // refreshes must never publish A after B has replaced A's
                // node-DNS ownership, even briefly.
                {
                    let mut inner = inner.write().await;
                    debug!("updating {} proxies for: {}", input.len(), name);
                    let Some(next_revision) = inner.revision.checked_add(1) else {
                        warn!(
                            "proxy provider {name} exhausted content revision; refusing update"
                        );
                        pending_publication.lock().await.take();
                        return Err(anyhow::anyhow!(
                            "provider content revision exhausted"
                        ));
                    };
                    if let Err(error) =
                        hc.replace_provider_dns_domains(&name, &input).await
                    {
                        // Retain the last accepted revision if its DNS
                        // ownership could not be installed beforehand.
                        warn!(
                            provider = name.as_str(),
                            error = %error,
                            "retaining previous provider revision: node DNS domain registration failed"
                        );
                        pending_publication.lock().await.take();
                        return Err(error);
                    }
                    *rollback_revision.lock().await = Some(inner.clone());
                    inner.proxies.clone_from(&input);
                    inner.revision = next_revision;
                }
                // The guard remains in the slot after the updater returns;
                // Fetcher releases it only after commit or rollback.
                // Do not run health probes against a provisional revision:
                // the final cache rename has not succeeded yet.
                #[cfg(test)]
                if let Some(pause) = before_commit.lock().await.as_ref().cloned() {
                    pause().await;
                }
                Ok(())
            })
        });

        let parser_name = name.clone();
        let parser: ProxyParser = Box::new(move |input| {
            let scheme: ProviderScheme =
                serde_yaml::from_slice(input).map_err(|x| {
                    Error::InvalidConfig(format!(
                        "proxy provider parse error {parser_name}: {x}"
                    ))
                })?;
            let proxies = scheme.proxies.ok_or_else(|| {
                Error::InvalidConfig(format!("{parser_name}: proxies is empty"))
            })?;
            let declared_count = proxies.len();

            let accepted: Vec<AnyOutboundHandler> = proxies
                .into_iter()
                .filter_map(|mapping| {
                    match OutboundProxyProtocol::try_from(mapping) {
                        Ok(proxy) => Some(proxy),
                        Err(e) => {
                            warn!(
                                provider = parser_name.as_str(),
                                "skipping proxy due to parse error: {e}"
                            );
                            None
                        }
                    }
                })
                .filter_map(|proxy| {
                    if protect_provider_dns
                        && let Err(error) =
                            validate_xhttp_secondary_managed_dns(&proxy)
                    {
                        // Reject this entire update rather than publish only
                        // the safe subset, retaining last good proxies/cache.
                        return Some(Err(error));
                    }
                    match OutboundManager::load_provider_outbound(proxy) {
                        Ok(handler) => handler.map(Ok),
                        Err(e) => Some(Err(e)),
                    }
                })
                .collect::<Result<Vec<_>, Error>>()?;

            // Empty lists may intentionally remove all proxies, but an update
            // containing only invalid entries must not replace a working
            // provider with an empty set or overwrite its last good cache.
            if declared_count != 0 && accepted.is_empty() {
                return Err(Error::InvalidConfig(format!(
                    "{parser_name}: no usable proxies in nonempty provider update"
                ))
                .into());
            }
            Ok(accepted)
        });

        let rollback_hc = hc.clone();
        let rollback_name = name.clone();
        let rollback_inner = inner.clone();
        let rollback_slot = rollback_revision.clone();
        let rollback_admission = pending_publication.clone();
        let rollback: CacheCommitRollback = Arc::new(move || {
            let hc = rollback_hc.clone();
            let name = rollback_name.clone();
            let inner = rollback_inner.clone();
            let slot = rollback_slot.clone();
            let admission = rollback_admission.clone();
            Box::pin(async move {
                // Keep the owned admission guard in its slot until the
                // previous snapshot has really been restored. Cancelling an
                // in-flight DNS rollback must not *release* an untrusted new
                // revision to readers.
                let Some(previous) = slot.lock().await.take() else {
                    return Err(anyhow::anyhow!(
                        "provider cache commit rollback missing previous revision"
                    ));
                };
                // The provider inner lock prevents old/new proxy snapshots
                // from being read while DNS ownership is restored.
                let mut current = inner.write().await;
                if let Err(error) = hc
                    .replace_provider_dns_domains(&name, &previous.proxies)
                    .await
                {
                    // If the registrar itself fails during compensation,
                    // disable this provider instead of exposing a revision
                    // whose DNS bootstrap owner is no longer trustworthy.
                    current.proxies.clear();
                    current.revision = 0;
                    hc.update(vec![]).await;
                    admission.lock().await.take();
                    return Err(error);
                }
                current.proxies.clone_from(&previous.proxies);
                current.revision = previous.revision;
                hc.update(previous.proxies).await;
                admission.lock().await.take();
                Ok(())
            })
        });
        let accepted_slot = rollback_revision;
        let accepted_admission = pending_publication;
        let accepted_inner = inner.clone();
        let accepted_hc = hc.clone();
        let accepted: CacheCommitAccepted = Arc::new(move || {
            let slot = accepted_slot.clone();
            let admission = accepted_admission.clone();
            let inner = accepted_inner.clone();
            let hc = accepted_hc.clone();
            Box::pin(async move {
                slot.lock().await.take();
                // The atomic cache rename succeeded and its DNS ownership
                // was registered. This does not imply power-loss durability
                // of the containing directory. Release reader admission
                // before awaiting health-check state, to prevent unrelated
                // cancellation from stranding the publication gate.
                admission.lock().await.take();
                let proxies = inner.read().await.proxies.clone();
                hc.update(proxies).await;
                tokio::spawn(async move {
                    hc.check().await;
                });
            })
        });
        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater))
            .with_cache_commit_hooks(rollback, accepted);
        Ok(Self {
            fetcher,
            hc,
            inner,
            publication_gate,
            #[cfg(test)]
            before_cache_commit,
        })
    }
}

#[async_trait]
impl Provider for ProxySetProvider {
    fn name(&self) -> &str {
        self.fetcher.name()
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        self.fetcher.vehicle_type()
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Proxy
    }

    async fn initialize(&self) -> std::io::Result<()> {
        // Fetcher applies the fallible DNS registration updater before
        // persisting the initial remote/cache revision.
        self.fetcher.initial().await.map_err(map_io_error)?;
        debug!("{} initialized", self.name());
        self.fetcher.start_polling().await;
        if let Err(e) = self.fetcher.start_watch().await {
            warn!(
                "proxy provider '{}': live file watching unavailable, falling back to interval polling: {}",
                self.name(),
                e
            );
        }
        Ok(())
    }

    async fn prepare_candidate_from_cache(&self) -> std::io::Result<bool> {
        self.fetcher
            .prepare_candidate_from_cache()
            .await
            .map_err(map_io_error)
    }

    async fn activate_after_commit(&self) -> std::io::Result<()> {
        let result = initialize_provider_with_retry(self).await;
        if result.is_err() {
            // Keep the provider handle available to groups. If periodic
            // refresh is configured, its first tick provides another retry.
            self.fetcher.start_polling().await;
        }
        result
    }

    async fn update(&self) -> std::io::Result<()> {
        let same = self.fetcher.update().await.map_err(map_io_error)?;
        debug!("{} updated with same content? {}", self.name(), same);
        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut map: HashMap<String, Box<dyn ESerialize + Send>> = HashMap::new();
        map.insert("name".to_owned(), Box::new(self.name().to_string()));
        map.insert("type".to_owned(), Box::new(self.typ().to_string()));
        map.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );
        map.insert(
            "updatedAt".to_owned(),
            Box::new(self.fetcher.updated_at().await),
        );
        map
    }
}

#[async_trait]
impl ProxyProvider for ProxySetProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        let _admission = self.publication_gate.read().await;
        self.inner.read().await.proxies.to_vec()
    }

    async fn strict_content_snapshot(&self) -> Option<ProxyProviderContentSnapshot> {
        let _admission = self.publication_gate.read().await;
        let inner = self.inner.read().await;
        (inner.revision != 0).then(|| ProxyProviderContentSnapshot {
            revision: inner.revision,
            proxies: inner.proxies.clone(),
        })
    }

    async fn touch(&self) {
        self.hc.touch().await;
    }

    async fn healthcheck(&self) {
        self.hc.check().await;
    }
}

#[cfg(test)]
mod update_reliability_tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::{ProxyProvider, ProxySetProvider};
    use crate::app::{
        dns::{MockClashResolver, bootstrap_provider::StrictProviderObservation},
        network::{NetworkSnapshot, NetworkStatus},
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::{MockProviderVehicle, Provider, ProviderVehicleType},
        },
    };

    const VALID: &[u8] = b"proxies:\n  - name: last-good\n    type: socks5\n    server: 198.51.100.10\n    port: 1080\n";
    const INVALID: &[u8] =
        b"proxies:\n  - name: broken\n    type: unsupported-protocol\n";
    const EMPTY: &[u8] = b"proxies: []\n";
    const SAME_NAME_NEW_HOST: &[u8] = b"proxies:\n  - name: last-good\n    type: socks5\n    server: 198.51.100.12\n    port: 1080\n";
    const PARTIAL: &[u8] = b"proxies:\n  - name: broken\n    type: unknown-protocol\n  - name: recovered\n    type: socks5\n    server: 198.51.100.11\n    port: 1081\n";
    const UNSAFE_XHTTP_DOWNLINK: &[u8] = br#"
proxies:
  - name: leaking-xhttp
    type: vless
    server: managed.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    alpn: [h2]
    xhttp-opts:
      mode: stream-up
      download-settings:
        address: private-secondary.example
        port: 443
"#;
    const UNSAFE_XHTTP_UPLOAD: &[u8] = br#"
proxies:
  - name: leaking-xhttp-upload
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    alpn: [http/1.1]
    xhttp-opts:
      mode: auto
      upload-settings:
        address: private-upload.example
        port: 443
"#;
    const SAFE_XHTTP_DOWNLINK: &[u8] = br#"
proxies:
  - name: safe-xhttp
    type: vless
    server: managed.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    alpn: [h2]
    xhttp-opts:
      mode: stream-up
      download-settings:
        address: 192.0.2.48
        port: 443
"#;
    const MIXED_SAFE_AND_UNSAFE_XHTTP: &[u8] = br#"
proxies:
  - name: safe-socks
    type: socks5
    server: 198.51.100.44
    port: 1080
  - name: unsafe-http1
    type: vless
    server: private-reconnect.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    alpn: [http/1.1]
    xhttp-opts:
      mode: auto
"#;

    fn provider_with_refresh(
        path: String,
        refreshed_content: &'static [u8],
    ) -> ProxySetProvider {
        provider_with_refresh_dns_mode(path, refreshed_content, false)
    }

    fn provider_with_refresh_dns_mode(
        path: String,
        refreshed_content: &'static [u8],
        protect_provider_dns: bool,
    ) -> ProxySetProvider {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut vehicle = MockProviderVehicle::new();
        vehicle.expect_path().return_const(path);
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle.expect_read().times(2).returning(move || {
            if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(VALID.to_vec())
            } else {
                Ok(refreshed_content.to_vec())
            }
        });
        let mut dns_resolver = MockClashResolver::new();
        dns_resolver
            .expect_replace_proxy_provider_dns_domains()
            .returning(|_, _| Ok(()));
        let manager = ProxyManager::new(Arc::new(dns_resolver), None);
        let health = HealthCheck::new(
            vec![],
            "http://example.invalid/check".to_owned(),
            0,
            true,
            manager,
        );
        ProxySetProvider::new_with_dns_privacy(
            "synthetic-provider".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            health,
            protect_provider_dns,
        )
        .expect("offline provider should construct")
    }

    async fn assert_provider_registers_new_proxy_host_before_refresh(
        protect_provider_dns: bool,
    ) {
        // Provider hosts are absent from the resolver's startup proxy-domain
        // trie. Every accepted revision must replace the provider-owned set
        // before its new endpoints become connectable.
        const FIRST: &[u8] = b"proxies:\n  - name: dynamic\n    type: socks5\n    server: Node.One.Example\n    port: 1080\n";
        const SECOND: &[u8] = b"proxies:\n  - name: dynamic\n    type: socks5\n    server: node.two.example\n    port: 1080\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dynamic-provider.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().to_string());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        let reads = Arc::new(AtomicUsize::new(0));
        vehicle.expect_read().times(2).returning(move || {
            Ok(if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                FIRST
            } else {
                SECOND
            }
            .to_vec())
        });
        let calls =
            Arc::new(std::sync::Mutex::new(Vec::<(String, Vec<String>)>::new()));
        let captured = calls.clone();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_replace_proxy_provider_dns_domains()
            .times(2)
            .returning(move |owner, names| {
                captured.lock().unwrap().push((owner.to_owned(), names));
                Ok(())
            });
        let manager = ProxyManager::new(Arc::new(resolver), None);
        let hc = HealthCheck::new(
            vec![],
            "http://example.invalid/health".to_owned(),
            0,
            true,
            manager,
        );
        let provider = ProxySetProvider::new_with_dns_privacy(
            "dynamic-owner".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            hc,
            protect_provider_dns,
        )
        .unwrap();
        provider.initialize().await.unwrap();
        let snapshot = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(snapshot.proxies[0].server_name(), Some("Node.One.Example"));
        provider.update().await.unwrap();
        let snapshot = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(snapshot.proxies[0].server_name(), Some("node.two.example"));
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                (
                    "dynamic-owner".to_owned(),
                    vec!["Node.One.Example".to_owned()]
                ),
                (
                    "dynamic-owner".to_owned(),
                    vec!["node.two.example".to_owned()]
                ),
            ],
            "accepted provider refresh must publish its exact endpoint ownership to node DNS",
        );
    }

    #[tokio::test]
    async fn protected_provider_registers_new_proxy_host_before_publishing_refresh()
    {
        assert_provider_registers_new_proxy_host_before_refresh(true).await;
    }

    #[tokio::test]
    async fn provider_node_dns_registration_is_not_limited_to_tun_fake_ip() {
        // An explicitly configured proxy-server-nameserver also applies to
        // provider nodes when TUN/Fake-IP privacy enforcement is not enabled.
        assert_provider_registers_new_proxy_host_before_refresh(false).await;
    }

    #[tokio::test]
    async fn provider_dns_registration_failure_preserves_last_visible_revision() {
        const NEW_HOST: &[u8] = b"proxies:\n  - name: new-proxy\n    type: socks5\n    server: dynamic-node.example\n    port: 1080\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registrar-failure.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().to_string());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        let reads = Arc::new(AtomicUsize::new(0));
        vehicle.expect_read().times(3).returning(move || {
            Ok(if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                VALID
            } else {
                NEW_HOST
            }
            .to_vec())
        });
        let mut resolver = MockClashResolver::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let hits = calls.clone();
        resolver
            .expect_replace_proxy_provider_dns_domains()
            .times(3)
            .returning(move |_, _| match hits.fetch_add(1, Ordering::SeqCst) {
                0 | 2 => Ok(()),
                _ => Err(anyhow::anyhow!("synthetic registrar outage")),
            });
        let health = HealthCheck::new(
            vec![],
            "http://example.invalid/check".to_owned(),
            0,
            true,
            ProxyManager::new(Arc::new(resolver), None),
        );
        let provider = ProxySetProvider::new_with_dns_privacy(
            "unstable-dns".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            health,
            true,
        )
        .unwrap();
        provider.initialize().await.unwrap();
        let before = provider.strict_content_snapshot().await.unwrap();
        let diagnostic = provider.update().await.expect_err(
            "a failed DNS node registration must not report successful provider refresh"
        ).to_string();
        assert!(
            diagnostic.contains("synthetic registrar outage"),
            "{diagnostic}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            VALID,
            "failed DNS registration must not replace last-good provider cache"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "rejected provider must not leave a staged file containing endpoint data"
        );
        let after = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(before.revision, after.revision);
        assert!(Arc::ptr_eq(&before.proxies[0], &after.proxies[0]));
        assert_eq!(after.proxies[0].server_name(), Some("198.51.100.10"));
        provider
            .update()
            .await
            .expect("same remote version must retry after registration failure");
        let recovered = provider.strict_content_snapshot().await.unwrap();
        assert!(recovered.revision > before.revision);
        assert_eq!(
            recovered.proxies[0].server_name(),
            Some("dynamic-node.example")
        );
        assert_eq!(std::fs::read(&path).unwrap(), NEW_HOST);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn failed_refresh_cache_rename_restores_own_dns_without_affecting_other_owner()
     {
        use std::collections::HashMap;
        const FIRST: &[u8] = b"proxies:\n  - name: same-node\n    type: socks5\n    server: shared.example\n    port: 1080\n";
        const NEXT: &[u8] = b"proxies:\n  - name: same-node\n    type: socks5\n    server: replacement.example\n    port: 1080\n";
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("owner-a.yaml");
        let saved_a = dir.path().join("owner-a-last-good.yaml");
        let path_b = dir.path().join("owner-b.yaml");

        let reads = Arc::new(AtomicUsize::new(0));
        let hit = reads.clone();
        let mut vehicle_a = MockProviderVehicle::new();
        vehicle_a
            .expect_path()
            .return_const(path_a.to_string_lossy().into_owned());
        vehicle_a
            .expect_typ()
            .return_const(ProviderVehicleType::Http);
        vehicle_a.expect_read().times(3).returning(move || {
            Ok(if hit.fetch_add(1, Ordering::SeqCst) == 0 {
                FIRST
            } else {
                NEXT
            }
            .to_vec())
        });
        let mut vehicle_b = MockProviderVehicle::new();
        vehicle_b
            .expect_path()
            .return_const(path_b.to_string_lossy().into_owned());
        vehicle_b
            .expect_typ()
            .return_const(ProviderVehicleType::Http);
        vehicle_b
            .expect_read()
            .times(1)
            .returning(|| Ok(FIRST.to_vec()));

        let registered =
            Arc::new(std::sync::Mutex::new(HashMap::<String, Vec<String>>::new()));
        let events =
            Arc::new(std::sync::Mutex::new(Vec::<(String, Vec<String>)>::new()));
        let owned = registered.clone();
        let history = events.clone();
        let target = path_a.clone();
        let retained = saved_a.clone();
        let sabotaged = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let one_time = sabotaged.clone();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_replace_proxy_provider_dns_domains()
            .returning(move |owner, domains| {
                if owner == "owner-a"
                    && domains == ["replacement.example"]
                    && !one_time.swap(true, Ordering::SeqCst)
                {
                    std::fs::rename(&target, &retained).unwrap();
                    std::fs::create_dir(&target).unwrap();
                }
                history
                    .lock()
                    .unwrap()
                    .push((owner.to_owned(), domains.clone()));
                owned.lock().unwrap().insert(owner.to_owned(), domains);
                Ok(())
            });
        let resolver = Arc::new(resolver);
        let health_b = HealthCheck::new(
            vec![],
            "http://example.invalid/check".into(),
            0,
            true,
            ProxyManager::new(resolver.clone(), None),
        );
        let health_a = HealthCheck::new(
            vec![],
            "http://example.invalid/check".into(),
            0,
            true,
            ProxyManager::new(resolver, None),
        );
        let provider_b = ProxySetProvider::new_with_dns_privacy(
            "owner-b".into(),
            Duration::ZERO,
            Arc::new(vehicle_b),
            health_b,
            true,
        )
        .unwrap();
        let provider_a = ProxySetProvider::new_with_dns_privacy(
            "owner-a".into(),
            Duration::ZERO,
            Arc::new(vehicle_a),
            health_a,
            true,
        )
        .unwrap();
        provider_b.initialize().await.unwrap();
        provider_a.initialize().await.unwrap();
        let before = provider_a.strict_content_snapshot().await.unwrap();

        let failure = provider_a.update().await.unwrap_err().to_string();
        assert!(
            !failure.is_empty(),
            "simulated final cache rename must fail"
        );
        let after = provider_a.strict_content_snapshot().await.unwrap();
        assert_eq!(before.revision, after.revision);
        assert!(Arc::ptr_eq(&before.proxies[0], &after.proxies[0]));
        assert_eq!(after.proxies[0].server_name(), Some("shared.example"));
        assert_eq!(std::fs::read(&saved_a).unwrap(), FIRST);
        assert!(path_a.is_dir());
        assert_eq!(std::fs::read(&path_b).unwrap(), FIRST);
        assert_eq!(
            *registered.lock().unwrap(),
            HashMap::from([
                ("owner-a".to_owned(), vec!["shared.example".to_owned()]),
                ("owner-b".to_owned(), vec!["shared.example".to_owned()]),
            ]),
            "rollback must restore only the failed owner's DNS domains"
        );
        let snapshot_b = provider_b.strict_content_snapshot().await.unwrap();
        assert_eq!(snapshot_b.proxies[0].server_name(), Some("shared.example"));

        // Once the external destination is repaired the *identical* remote
        // revision must be retried and committed rather than hash-skipped.
        std::fs::remove_dir(&path_a).unwrap();
        std::fs::rename(&saved_a, &path_a).unwrap();
        provider_a
            .update()
            .await
            .expect("retry must persist accepted revision");
        let committed = provider_a.strict_content_snapshot().await.unwrap();
        assert_eq!(committed.revision, before.revision + 1);
        assert_eq!(
            committed.proxies[0].server_name(),
            Some("replacement.example")
        );
        assert_eq!(std::fs::read(&path_a).unwrap(), NEXT);
        assert_eq!(
            *registered.lock().unwrap(),
            HashMap::from([
                ("owner-a".to_owned(), vec!["replacement.example".to_owned()]),
                ("owner-b".to_owned(), vec!["shared.example".to_owned()]),
            ])
        );
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|(owner, _)| owner == "owner-a")
                .count(),
            4,
            "initial + failed candidate + rollback + successful retry"
        );
    }

    #[tokio::test]
    async fn failed_rename_and_dns_rollback_disables_provisional_provider() {
        const OLD: &[u8] = b"proxies:\n  - name: node\n    type: socks5\n    server: previously-accepted.example\n    port: 1080\n";
        const NEW: &[u8] = b"proxies:\n  - name: node\n    type: socks5\n    server: never-committed.example\n    port: 1080\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rename-rollback.yaml");
        let saved = dir.path().join("last-good-archive.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        let reads = Arc::new(AtomicUsize::new(0));
        let next_read = reads.clone();
        vehicle.expect_read().times(2).returning(move || {
            Ok(if next_read.fetch_add(1, Ordering::SeqCst) == 0 {
                OLD
            } else {
                NEW
            }
            .to_vec())
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let sabotaged_path = path.clone();
        let saved_path = saved.clone();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_replace_proxy_provider_dns_domains()
            .times(3)
            .returning(move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(()),
                1 => {
                    std::fs::rename(&sabotaged_path, &saved_path).unwrap();
                    std::fs::create_dir(&sabotaged_path).unwrap();
                    Ok(())
                }
                _ => Err(anyhow::anyhow!("synthetic node DNS restoration failure")),
            });
        let health = HealthCheck::new(
            vec![],
            "http://example.invalid/check".into(),
            0,
            true,
            ProxyManager::new(Arc::new(resolver), None),
        );
        let provider = ProxySetProvider::new_with_dns_privacy(
            "rollback-outage".into(),
            Duration::ZERO,
            Arc::new(vehicle),
            health,
            true,
        )
        .unwrap();
        provider.initialize().await.unwrap();
        assert!(provider.strict_content_snapshot().await.is_some());

        let diagnostic = provider.update().await.unwrap_err().to_string();
        assert!(diagnostic.contains("rollback failed"), "{diagnostic}");
        assert!(
            diagnostic.contains("synthetic node DNS restoration failure"),
            "{diagnostic}"
        );
        assert!(
            provider.strict_content_snapshot().await.is_none(),
            "failed compensation must fail closed, never expose new or stale nodes"
        );
        assert!(provider.proxies().await.is_empty());
        assert_eq!(std::fs::read(&saved).unwrap(), OLD);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn cancelled_refresh_request_still_compensates_failed_cache_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cancel-rename-failure.yaml");
        let saved = dir.path().join("retained-accepted.yaml");
        let provider = Arc::new(provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            SAME_NAME_NEW_HOST,
            true,
        ));
        provider.initialize().await.unwrap();
        let before = provider.strict_content_snapshot().await.unwrap();

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let resume = release.clone();
        *provider.before_cache_commit.lock().await = Some(Arc::new(move || {
            let signal = signal.clone();
            let resume = resume.clone();
            Box::pin(async move {
                signal.notify_one();
                resume.notified().await;
            })
        }));
        let updating = provider.clone();
        let request = tokio::spawn(async move { updating.update().await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("must reach pre-commit barrier");
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        // An external writer replaces the target after preflight. The
        // detached commit worker must compensate instead of wedging readers.
        std::fs::rename(&path, &saved).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                provider.strict_content_snapshot()
            )
            .await
            .is_err()
        );
        release.notify_one();

        let reverted = tokio::time::timeout(
            Duration::from_secs(2),
            provider.strict_content_snapshot(),
        )
        .await
        .expect("failed commit must not strand reader admission")
        .expect("the previous revision must remain visible");
        assert_eq!(reverted.revision, before.revision);
        assert!(Arc::ptr_eq(&reverted.proxies[0], &before.proxies[0]));
        assert_eq!(std::fs::read(&saved).unwrap(), VALID);
        assert!(path.is_dir());
    }

    #[tokio::test]
    async fn cancelling_refresh_request_must_not_strand_accepted_cache_revision() {
        // Cancelling the API caller must not cancel a provider transaction
        // after it has registered its node DNS and before the cache rename.
        // A detached commit worker must finish and unblock the next reader.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cancel-commit.yaml");
        let provider = Arc::new(provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            SAME_NAME_NEW_HOST,
            true,
        ));
        provider.initialize().await.unwrap();
        let before = provider.strict_content_snapshot().await.unwrap();

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let entry = entered.clone();
        let resume = release.clone();
        *provider.before_cache_commit.lock().await = Some(Arc::new(move || {
            let entry = entry.clone();
            let resume = resume.clone();
            Box::pin(async move {
                entry.notify_one();
                resume.notified().await;
            })
        }));
        let updating = provider.clone();
        let request = tokio::spawn(async move { updating.update().await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("candidate must reach its pre-commit barrier");
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());

        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                provider.strict_content_snapshot()
            )
            .await
            .is_err(),
            "uncommitted candidates still must not become observable"
        );
        release.notify_one();
        let accepted = tokio::time::timeout(
            Duration::from_secs(2),
            provider.strict_content_snapshot(),
        )
        .await
        .expect("cancelled caller must not strand provider admission")
        .expect("committed revision must be visible");
        assert_eq!(accepted.revision, before.revision + 1);
        assert_eq!(accepted.proxies[0].server_name(), Some("198.51.100.12"));
        assert_eq!(std::fs::read(&path).unwrap(), SAME_NAME_NEW_HOST);
    }

    #[tokio::test]
    async fn cancellation_of_provisional_provider_update_fails_closed_to_readers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cancelled-pending.yaml");
        let provider = Arc::new(provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            SAME_NAME_NEW_HOST,
            true,
        ));
        provider.initialize().await.unwrap();

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let hold = release.clone();
        *provider.before_cache_commit.lock().await = Some(Arc::new(move || {
            let signal = signal.clone();
            let hold = hold.clone();
            Box::pin(async move {
                signal.notify_one();
                hold.notified().await;
            })
        }));
        let updating = provider.clone();
        let task = tokio::spawn(async move { updating.update().await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("provisional publication must be reached");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        assert!(
            tokio::time::timeout(
                Duration::from_millis(125),
                provider.strict_content_snapshot(),
            )
            .await
            .is_err(),
            "a cancelled provisional revision must not become visible"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(125), provider.proxies(),)
                .await
                .is_err(),
            "cancelled update must block ordinary proxy readers too"
        );
        // The worker remains paused, so neither API should expose the
        // provisional revision. Releasing the pause must let it commit and
        // reopen admission even though the requesting task is gone.
        release.notify_one();
        let accepted = tokio::time::timeout(
            Duration::from_secs(2),
            provider.strict_content_snapshot(),
        )
        .await
        .expect("canceled caller must not strand the commit worker")
        .expect("accepted snapshot");
        assert_eq!(accepted.proxies[0].server_name(), Some("198.51.100.12"));
        assert_eq!(std::fs::read(&path).unwrap(), SAME_NAME_NEW_HOST);
    }

    #[tokio::test]
    async fn failed_pending_commit_releases_readers_with_only_last_good_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-failure.yaml");
        let saved = dir.path().join("preexisting-cache.yaml");
        let provider = Arc::new(provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            SAME_NAME_NEW_HOST,
            true,
        ));
        provider.initialize().await.unwrap();
        let before = provider.strict_content_snapshot().await.unwrap();

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let trigger = entered.clone();
        let resumed = release.clone();
        *provider.before_cache_commit.lock().await = Some(Arc::new(move || {
            let trigger = trigger.clone();
            let resumed = resumed.clone();
            Box::pin(async move {
                trigger.notify_one();
                resumed.notified().await;
            })
        }));
        let updating = provider.clone();
        let task = tokio::spawn(async move { updating.update().await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("refresh must reach pre-persist barrier");

        std::fs::rename(&path, &saved).unwrap();
        std::fs::create_dir(&path).unwrap();
        let reading_snapshot = provider.clone();
        let mut snapshot =
            tokio::spawn(
                async move { reading_snapshot.strict_content_snapshot().await },
            );
        let reading_proxies = provider.clone();
        let mut proxies =
            tokio::spawn(async move { reading_proxies.proxies().await });
        let snapshot_early =
            tokio::time::timeout(Duration::from_millis(125), &mut snapshot).await;
        let proxies_early =
            tokio::time::timeout(Duration::from_millis(125), &mut proxies).await;
        release.notify_one();
        assert!(task.await.unwrap().is_err());
        assert!(snapshot_early.is_err(), "snapshot must wait for rollback");
        assert!(proxies_early.is_err(), "proxy list must wait for rollback");
        let restored = snapshot.await.unwrap().unwrap();
        let restored_proxies = proxies.await.unwrap();
        assert_eq!(restored.revision, before.revision);
        assert!(Arc::ptr_eq(&restored.proxies[0], &before.proxies[0]));
        assert!(Arc::ptr_eq(&restored_proxies[0], &before.proxies[0]));
        assert_eq!(std::fs::read(&saved).unwrap(), VALID);
        assert!(path.is_dir());
    }

    #[tokio::test]
    async fn pending_cache_commit_blocks_provider_readers_until_cache_rename_succeeds()
     {
        const NEXT: &[u8] = b"proxies:\n  - name: future-node\n    type: socks5\n    server: 198.51.100.12\n    port: 1080\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admission-gate.yaml");
        let provider = Arc::new(provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            NEXT,
            true,
        ));
        provider.initialize().await.unwrap();
        let before = provider.strict_content_snapshot().await.unwrap();

        let entered = Arc::new(tokio::sync::Notify::new());
        let continue_commit = Arc::new(tokio::sync::Notify::new());
        let pause_entered = entered.clone();
        let pause_release = continue_commit.clone();
        *provider.before_cache_commit.lock().await = Some(Arc::new(move || {
            let entered = pause_entered.clone();
            let release = pause_release.clone();
            Box::pin(async move {
                entered.notify_one();
                release.notified().await;
            })
        }));

        let updating = provider.clone();
        let update_task = tokio::spawn(async move { updating.update().await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("injected commit barrier must be reached");

        let observing = provider.clone();
        let mut snapshot_task =
            tokio::spawn(async move { observing.strict_content_snapshot().await });
        let early =
            tokio::time::timeout(Duration::from_millis(125), &mut snapshot_task)
                .await;
        let saw_uncommitted = early.is_ok();
        continue_commit.notify_one();
        update_task.await.unwrap().unwrap();
        let after = match early {
            Ok(joined) => joined.unwrap().unwrap(),
            Err(_) => snapshot_task.await.unwrap().unwrap(),
        };
        assert!(
            !saw_uncommitted,
            "provider readers must not observe the next revision before cache commit"
        );
        assert_eq!(after.revision, before.revision + 1);
        assert_eq!(after.proxies[0].server_name(), Some("198.51.100.12"));
        assert_eq!(std::fs::read(&path).unwrap(), NEXT);
    }

    #[tokio::test]
    async fn cancelling_initial_provider_request_after_staging_finishes_dns_and_cache()
     {
        const FIRST: &[u8] = b"proxies:\n  - name: first-node\n    type: socks5\n    server: first.example\n    port: 1080\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cancel-initial-provider.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(1)
            .returning(|| Ok(FIRST.to_vec()));
        let changes = Arc::new(std::sync::Mutex::new(Vec::<Vec<String>>::new()));
        let captured = changes.clone();
        let mut resolver = MockClashResolver::new();
        resolver.expect_resolve_all().returning(|_, _| {
            Err(anyhow::anyhow!(
                "offline test intentionally denies node DNS"
            ))
        });
        resolver
            .expect_replace_proxy_provider_dns_domains()
            .returning(move |_owner, domains| {
                captured.lock().unwrap().push(domains);
                Ok(())
            });
        let health = HealthCheck::new(
            vec![],
            "http://example.invalid/check".into(),
            0,
            true,
            ProxyManager::new(Arc::new(resolver), None),
        );
        let provider = Arc::new(
            ProxySetProvider::new_with_dns_privacy(
                "cancelled-initial".into(),
                Duration::ZERO,
                Arc::new(vehicle),
                health,
                true,
            )
            .unwrap(),
        );
        let entered = Arc::new(tokio::sync::Notify::new());
        let continue_commit = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let resume = continue_commit.clone();
        *provider.before_cache_commit.lock().await = Some(Arc::new(move || {
            let signal = signal.clone();
            let resume = resume.clone();
            Box::pin(async move {
                signal.notify_one();
                resume.notified().await;
            })
        }));

        let initializing = provider.clone();
        let initial_request =
            tokio::spawn(async move { initializing.initialize().await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("initial revision must reach pre-persist barrier");
        initial_request.abort();
        assert!(initial_request.await.unwrap_err().is_cancelled());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                provider.strict_content_snapshot(),
            )
            .await
            .is_err(),
            "an uncommitted initial revision must remain invisible"
        );
        continue_commit.notify_one();
        let accepted = tokio::time::timeout(
            Duration::from_secs(2),
            provider.strict_content_snapshot(),
        )
        .await
        .expect("cancelled initial request must not strand reader admission")
        .expect("initial revision must be accepted");
        assert_eq!(accepted.revision, 1);
        assert_eq!(accepted.proxies[0].server_name(), Some("first.example"));
        assert_eq!(std::fs::read(&path).unwrap(), FIRST);
        assert_eq!(*changes.lock().unwrap(), [vec!["first.example".to_owned()]]);
    }

    #[tokio::test]
    async fn failed_initial_cache_rename_retracts_node_dns_and_provider_revision() {
        const REMOTE: &[u8] = b"proxies:\n  - name: staged-node\n    type: socks5\n    server: staged.example\n    port: 1080\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("first-cache.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(1)
            .returning(|| Ok(REMOTE.to_vec()));

        let changes = Arc::new(std::sync::Mutex::new(Vec::<Vec<String>>::new()));
        let recorded = changes.clone();
        let blocked_path = path.clone();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_replace_proxy_provider_dns_domains()
            .returning(move |owner, domains| {
                assert_eq!(owner, "initial-rename-owner");
                if domains == ["staged.example"] {
                    // The destination changes *after* successful preflight and
                    // DNS registration, but before NamedTempFile::persist.
                    std::fs::create_dir(&blocked_path).unwrap();
                }
                recorded.lock().unwrap().push(domains);
                Ok(())
            });
        let health = HealthCheck::new(
            vec![],
            "http://example.invalid/check".into(),
            0,
            true,
            ProxyManager::new(Arc::new(resolver), None),
        );
        let provider = ProxySetProvider::new_with_dns_privacy(
            "initial-rename-owner".into(),
            Duration::ZERO,
            Arc::new(vehicle),
            health,
            true,
        )
        .unwrap();

        let error = provider.initialize().await.unwrap_err().to_string();
        assert!(!error.is_empty(), "final rename must fail explicitly");
        assert!(
            provider.strict_content_snapshot().await.is_none(),
            "a nonpersisted initial revision must not remain visible"
        );
        assert_eq!(
            *changes.lock().unwrap(),
            vec![vec!["staged.example".to_owned()], vec![]],
            "failed commit must remove its provider-owned node DNS domains"
        );
        assert!(
            path.is_dir(),
            "external destination replacement is preserved"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "failed commit must remove its temporary staged cache"
        );
    }

    #[tokio::test]
    async fn provider_initial_dns_failure_rejects_startup_without_polling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("initial-node-dns-failure.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        let reads = Arc::new(AtomicUsize::new(0));
        let read_counter = reads.clone();
        vehicle.expect_read().returning(move || {
            read_counter.fetch_add(1, Ordering::SeqCst);
            Ok(VALID.to_vec())
        });
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_replace_proxy_provider_dns_domains()
            .times(1)
            .returning(|_, _| {
                Err(anyhow::anyhow!("synthetic initial node DNS outage"))
            });
        let health = HealthCheck::new(
            vec![],
            "http://example.invalid/check".to_owned(),
            0,
            true,
            ProxyManager::new(Arc::new(resolver), None),
        );
        let provider = ProxySetProvider::new_with_dns_privacy(
            "init-failure".to_owned(),
            Duration::from_millis(5),
            Arc::new(vehicle),
            health,
            true,
        )
        .unwrap();
        let diagnostic = provider.initialize().await.expect_err(
            "initial proxy DNS registration must fail startup rather than expose empty readiness"
        ).to_string();
        assert!(
            diagnostic.contains("synthetic initial node DNS outage"),
            "{diagnostic}"
        );
        assert!(provider.strict_content_snapshot().await.is_none());
        assert!(
            !path.exists(),
            "failed initial node-DNS registration must not persist rejected provider content"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "rejected initial provider must clean up staged endpoint content"
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "failed startup must not run provider refresh"
        );
    }

    #[tokio::test]
    async fn failed_initial_dns_registration_preserves_corrupt_cache_until_accepted_recovery()
     {
        const REMOTE: &[u8] = b"proxies:\n  - name: recovered-proxy\n    type: socks5\n    server: accepted-node.example\n    port: 1080\n";
        const CORRUPT: &[u8] = b"provider-cache-is-not-valid-yaml";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid-previous-cache.yaml");
        std::fs::write(&path, CORRUPT).unwrap();
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(2)
            .returning(|| Ok(REMOTE.to_vec()));

        let mut resolver = MockClashResolver::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let hits = calls.clone();
        resolver
            .expect_replace_proxy_provider_dns_domains()
            .times(2)
            .returning(move |owner, domains| {
                assert_eq!(owner, "recovering-provider");
                assert_eq!(domains, vec!["accepted-node.example".to_owned()]);
                if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(anyhow::anyhow!(
                        "synthetic recovery DNS registration failure"
                    ))
                } else {
                    Ok(())
                }
            });
        let health = HealthCheck::new(
            vec![],
            "http://example.invalid/check".to_owned(),
            0,
            true,
            ProxyManager::new(Arc::new(resolver), None),
        );
        let provider = ProxySetProvider::new_with_dns_privacy(
            "recovering-provider".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            health,
            true,
        )
        .unwrap();

        let diagnostic = provider.initialize().await.unwrap_err().to_string();
        assert!(diagnostic.contains("synthetic recovery DNS registration failure"));
        assert_eq!(std::fs::read(&path).unwrap(), CORRUPT);
        assert!(provider.strict_content_snapshot().await.is_none());

        provider
            .initialize()
            .await
            .expect("DNS registration recovered");
        assert_eq!(std::fs::read(&path).unwrap(), REMOTE);
        let revision = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(
            revision.proxies[0].server_name(),
            Some("accepted-node.example")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn protected_provider_rejects_xhttp_dns_leak_without_replacing_last_good()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("protected-provider.yaml");
        let provider = provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            UNSAFE_XHTTP_DOWNLINK,
            true,
        );
        provider.initialize().await.expect("safe initial provider");
        let before = provider.strict_content_snapshot().await.unwrap();
        let error = provider
            .update()
            .await
            .expect_err("unsafe XHTTP domain must not enter the provider");
        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains("xhttp") && diagnostic.contains("download-settings"),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("private-secondary.example"));

        let after = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(before.revision, after.revision);
        assert!(Arc::ptr_eq(&before.proxies[0], &after.proxies[0]));
        assert_eq!(after.proxies[0].name(), "last-good");
        assert_eq!(std::fs::read(&path).unwrap(), VALID);
    }

    #[tokio::test]
    async fn protected_provider_rejects_xhttp_upload_dns_leak_without_replacing_last_good()
     {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("protected-upload-provider.yaml");
        let provider = provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            UNSAFE_XHTTP_UPLOAD,
            true,
        );
        provider.initialize().await.expect("safe initial provider");
        let before = provider.strict_content_snapshot().await.unwrap();
        let error = provider
            .update()
            .await
            .expect_err("unsafe XHTTP upload hostname must not enter provider");
        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains("xhttp") && diagnostic.contains("upload-settings"),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("private-upload.example"));

        let after = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(before.revision, after.revision);
        assert!(Arc::ptr_eq(&before.proxies[0], &after.proxies[0]));
        assert_eq!(after.proxies[0].name(), "last-good");
        assert_eq!(std::fs::read(&path).unwrap(), VALID);
    }

    #[tokio::test]
    async fn mixed_safe_and_unsafe_provider_refresh_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed-protected-provider.yaml");
        let provider = provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            MIXED_SAFE_AND_UNSAFE_XHTTP,
            true,
        );
        provider.initialize().await.expect("safe initial provider");
        let before = provider.strict_content_snapshot().await.unwrap();
        let diagnostic = provider
            .update()
            .await
            .expect_err("a safe candidate must not mask unsafe XHTTP reconnect")
            .to_string();
        assert!(
            diagnostic.contains("xhttp") && diagnostic.contains("http/1.1"),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("private-reconnect.example"));

        let after = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.proxies.len(), 1);
        assert!(Arc::ptr_eq(&before.proxies[0], &after.proxies[0]));
        assert_eq!(std::fs::read(&path).unwrap(), VALID);
    }

    #[tokio::test]
    async fn protected_provider_accepts_literal_xhttp_downlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("literal-provider.yaml");
        let provider = provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            SAFE_XHTTP_DOWNLINK,
            true,
        );
        provider.initialize().await.expect("safe initial provider");
        provider
            .update()
            .await
            .expect("IP-literal secondary avoids OS DNS");
        let snapshot = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.proxies[0].name(), "safe-xhttp");
    }

    #[tokio::test]
    async fn unprotected_provider_preserves_existing_domain_downlink_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-provider.yaml");
        let provider = provider_with_refresh_dns_mode(
            path.to_string_lossy().into_owned(),
            UNSAFE_XHTTP_DOWNLINK,
            false,
        );
        provider
            .initialize()
            .await
            .expect("non-TUN initial provider");
        provider
            .update()
            .await
            .expect("legacy mode still allows domain downlinks");
        assert_eq!(provider.proxies().await[0].name(), "leaking-xhttp");
    }

    #[tokio::test]
    async fn malformed_refresh_keeps_last_good_proxy_set_and_cache() {
        let dir = tempfile::tempdir().expect("temporary cache dir");
        let cache_path = dir.path().join("provider.yaml");
        let provider = provider_with_refresh(
            cache_path.to_string_lossy().into_owned(),
            INVALID,
        );
        assert!(provider.strict_content_snapshot().await.is_none());
        provider.initialize().await.expect("valid initial provider");
        let before = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(before.revision, 1);
        assert_eq!(before.proxies[0].name(), "last-good");
        assert_eq!(provider.proxies().await[0].name(), "last-good");
        assert_eq!(std::fs::read(&cache_path).unwrap(), VALID);

        assert!(
            provider.update().await.is_err(),
            "a nonempty provider containing no valid proxies must fail closed"
        );
        let after = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(after.revision, before.revision);
        assert!(Arc::ptr_eq(&after.proxies[0], &before.proxies[0]));
        let proxies = provider.proxies().await;
        assert_eq!(proxies.len(), 1, "last good proxy set must survive");
        assert_eq!(proxies[0].name(), "last-good");
        assert_eq!(
            std::fs::read(&cache_path).unwrap(),
            VALID,
            "invalid remote refresh must not poison the cached provider"
        );
    }

    #[tokio::test]
    async fn mixed_valid_and_invalid_refresh_keeps_usable_entries() {
        let dir = tempfile::tempdir().expect("temporary cache dir");
        let cache_path = dir.path().join("provider.yaml");
        let provider = provider_with_refresh(
            cache_path.to_string_lossy().into_owned(),
            PARTIAL,
        );
        provider.initialize().await.expect("valid initial provider");
        let initial = provider.strict_content_snapshot().await.unwrap();
        provider
            .update()
            .await
            .expect("usable entries in mixed provider should be accepted");
        let refreshed = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(refreshed.revision, initial.revision + 1);
        assert!(!Arc::ptr_eq(&refreshed.proxies[0], &initial.proxies[0]));
        let proxies = provider.proxies().await;
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name(), "recovered");
        assert_eq!(std::fs::read(&cache_path).unwrap(), PARTIAL);
    }

    #[tokio::test]
    async fn strict_dns_observation_rejects_live_provider_rotation_and_network_changes()
     {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.yaml");
        let handle: ThreadSafeProxyProvider = Arc::new(tokio::sync::RwLock::new(
            provider_with_refresh(path.to_string_lossy().into_owned(), PARTIAL),
        ));
        let status = Arc::new(tokio::sync::RwLock::new(NetworkStatus::default()));
        status.write().await.observed(&NetworkSnapshot::default());
        let source = std::collections::HashMap::from([(
            "synthetic-provider".to_owned(),
            handle.clone(),
        )]);
        assert!(
            StrictProviderObservation::capture(&status, &source)
                .await
                .is_err(),
            "uninitialized content must never enter strict DNS"
        );
        handle.read().await.initialize().await.unwrap();
        let original = StrictProviderObservation::capture(&status, &source)
            .await
            .unwrap();
        original.ensure_current(&status).await.unwrap();
        assert_eq!(
            original.candidates("synthetic-provider").unwrap()[0].name(),
            "last-good"
        );

        handle.read().await.update().await.unwrap();
        assert!(
            original
                .ensure_current(&status)
                .await
                .unwrap_err()
                .to_string()
                .contains("changed during")
        );
        let refreshed = StrictProviderObservation::capture(&status, &source)
            .await
            .unwrap();
        refreshed.ensure_current(&status).await.unwrap();
        assert_eq!(
            refreshed.candidates("synthetic-provider").unwrap()[0].name(),
            "recovered"
        );
        status.write().await.observed(&NetworkSnapshot {
            dns: "second network".into(),
            ..NetworkSnapshot::default()
        });
        assert!(
            refreshed
                .ensure_current(&status)
                .await
                .unwrap_err()
                .to_string()
                .contains("stale network/config")
        );
    }

    #[tokio::test]
    async fn strict_dns_observation_rejects_aba_replacement_with_same_candidate_name()
     {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.yaml");
        let handle: ThreadSafeProxyProvider =
            Arc::new(tokio::sync::RwLock::new(provider_with_refresh(
                path.to_string_lossy().into_owned(),
                SAME_NAME_NEW_HOST,
            )));
        let status = Arc::new(tokio::sync::RwLock::new(NetworkStatus::default()));
        status.write().await.observed(&NetworkSnapshot::default());
        let source = std::collections::HashMap::from([(
            "synthetic-provider".to_owned(),
            handle.clone(),
        )]);
        handle.read().await.initialize().await.unwrap();
        let before = StrictProviderObservation::capture(&status, &source)
            .await
            .unwrap();
        handle.read().await.update().await.unwrap();
        let after = StrictProviderObservation::capture(&status, &source)
            .await
            .unwrap();
        assert_eq!(
            before.candidates("synthetic-provider").unwrap()[0].name(),
            after.candidates("synthetic-provider").unwrap()[0].name()
        );
        assert!(
            before
                .ensure_current(&status)
                .await
                .unwrap_err()
                .to_string()
                .contains("changed during")
        );
        after.ensure_current(&status).await.unwrap();
    }

    #[tokio::test]
    async fn strict_dns_observation_keeps_last_good_on_invalid_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.yaml");
        let handle: ThreadSafeProxyProvider = Arc::new(tokio::sync::RwLock::new(
            provider_with_refresh(path.to_string_lossy().into_owned(), INVALID),
        ));
        let status = Arc::new(tokio::sync::RwLock::new(NetworkStatus::default()));
        status.write().await.observed(&NetworkSnapshot::default());
        let source = std::collections::HashMap::from([(
            "synthetic-provider".to_owned(),
            handle.clone(),
        )]);
        handle.read().await.initialize().await.unwrap();
        let captured = StrictProviderObservation::capture(&status, &source)
            .await
            .unwrap();
        assert!(handle.read().await.update().await.is_err());
        captured.ensure_current(&status).await.unwrap();
        let other_status =
            Arc::new(tokio::sync::RwLock::new(NetworkStatus::default()));
        other_status
            .write()
            .await
            .observed(&NetworkSnapshot::default());
        assert!(
            captured
                .ensure_current(&other_status)
                .await
                .unwrap_err()
                .to_string()
                .contains("another runtime")
        );
    }

    #[tokio::test]
    async fn s04bf_registry_selection_is_identity_bound_and_rebinding_rejected() {
        use crate::{
            app::dns::{
                bootstrap_provider::{
                    StrictProviderRegistry, StrictProviderRegistryStore,
                },
                isolation::{StrictDnsCache, StrictDnsPlanSelection},
                plan::{
                    DnsPurpose, DnsQueryContext, EffectiveDnsPlan, EgressChoice,
                    FailureChoice, LegacyDnsPlan, LegacyDnsRoute, ResolverChoice,
                },
                policy::{CompiledDnsPolicy, DnsEgress, DnsFailure},
            },
            config::def::Config as RawConfig,
            proxy::utils::OutboundHandlerRegistry,
            session::Session,
        };
        use hickory_proto::{
            op::{Message, MessageType, OpCode, Query},
            rr::{Name, RecordType},
        };

        let dir = tempfile::tempdir().unwrap();
        let make = |name: &str| {
            Arc::new(tokio::sync::RwLock::new(provider_with_refresh(
                dir.path().join(name).to_string_lossy().into_owned(),
                SAME_NAME_NEW_HOST,
            ))) as ThreadSafeProxyProvider
        };
        let source = make("first.yaml");
        source.read().await.initialize().await.unwrap();
        let runtime = Arc::new(tokio::sync::RwLock::new(NetworkStatus::default()));
        runtime.write().await.observed(&NetworkSnapshot::default());
        let provider_registry: StrictProviderRegistry = Arc::new(
            StrictProviderRegistryStore::new(std::collections::HashMap::from([(
                "synthetic-provider".into(),
                source.clone(),
            )])),
        );
        let observation = StrictProviderObservation::capture_registered(
            &runtime,
            &provider_registry,
        )
        .await
        .unwrap();
        let selected =
            observation.candidates("synthetic-provider").unwrap()[0].clone();

        let config: RawConfig = serde_yaml::from_str(
            r#"
proxy-groups:
  - {name: DNS-OUT, type: select, use: [synthetic-provider]}
"#,
        )
        .unwrap();
        let mut request = Message::new(23, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
        ));
        let plan = EffectiveDnsPlan {
            context: DnsQueryContext::from_message(
                &request,
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
            profiles: std::collections::HashMap::from([(
                "trusted".into(),
                crate::app::dns::Config::parse_nameserver(&[
                    "udp://192.0.2.53".into()
                ])
                .unwrap(),
            )]),
            rules: Vec::new(),
        };
        let outbound_registry: OutboundHandlerRegistry =
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::from([
                ("DNS-OUT".into(), selected.clone()),
            ])));
        let session = Session::default();
        let selection = || StrictDnsPlanSelection {
            plan: &plan,
            profiles: &profiles,
            registry: &outbound_registry,
            session: &session,
        };

        assert_eq!(
            StrictDnsCache::inspect_observed_provider_selection(
                selection(),
                &config,
                &observation,
                &runtime,
            )
            .await
            .unwrap(),
            "synthetic-provider",
        );

        let second = make("second.yaml");
        second.read().await.initialize().await.unwrap();
        second.read().await.update().await.unwrap();
        let foreign = second.read().await.proxies().await[0].clone();
        assert_eq!(foreign.name(), selected.name());
        outbound_registry
            .write()
            .await
            .insert("DNS-OUT".into(), foreign);
        let error = StrictDnsCache::inspect_observed_provider_selection(
            selection(),
            &config,
            &observation,
            &runtime,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("not in configured provider candidates"),
            "{error}"
        );

        provider_registry
            .replace("synthetic-provider".into(), second)
            .await
            .unwrap();
        let error = observation
            .ensure_current(&runtime)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("provider registry changed"), "{error}");
        // Consume this fixture's expected second fetch without affecting the
        // already verified, stale provider observation.
        source.read().await.update().await.unwrap();
    }

    #[tokio::test]
    async fn s04bg_registry_aba_replacement_invalidates_observation_even_if_restored()
     {
        use crate::app::dns::bootstrap_provider::{
            StrictProviderRegistry, StrictProviderRegistryStore,
        };
        let dir = tempfile::tempdir().unwrap();
        let provider = |name: &str| -> ThreadSafeProxyProvider {
            Arc::new(tokio::sync::RwLock::new(provider_with_refresh(
                dir.path().join(name).to_string_lossy().into_owned(),
                SAME_NAME_NEW_HOST,
            )))
        };
        let original = provider("original.yaml");
        let replacement = provider("replacement.yaml");
        original.read().await.initialize().await.unwrap();
        replacement.read().await.initialize().await.unwrap();
        let status = Arc::new(tokio::sync::RwLock::new(NetworkStatus::default()));
        status.write().await.observed(&NetworkSnapshot::default());
        let registry: StrictProviderRegistry = Arc::new(
            StrictProviderRegistryStore::new(std::collections::HashMap::from([(
                "synthetic-provider".to_owned(),
                original.clone(),
            )])),
        );
        let initial =
            StrictProviderObservation::capture_registered(&status, &registry)
                .await
                .unwrap();
        registry
            .replace("synthetic-provider".into(), replacement.clone())
            .await
            .unwrap();
        registry
            .replace("synthetic-provider".into(), original.clone())
            .await
            .unwrap();
        // The complete registry appears unchanged, including every Arc.
        // Monotonic revision still rejects the old snapshot.
        let err = initial
            .ensure_current(&status)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("provider registry changed"), "{err}");
        let current =
            StrictProviderObservation::capture_registered(&status, &registry)
                .await
                .unwrap();
        current.ensure_current(&status).await.unwrap();

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (proceed_tx, proceed_rx) = tokio::sync::oneshot::channel::<()>();
        let observed_status = status.clone();
        let job = tokio::spawn(async move {
            current
                .validate_during(&observed_status, async {
                    entered_tx.send(()).unwrap();
                    proceed_rx.await.unwrap();
                    42
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        registry
            .replace("synthetic-provider".into(), replacement.clone())
            .await
            .unwrap();
        registry
            .replace("synthetic-provider".into(), original.clone())
            .await
            .unwrap();
        proceed_tx.send(()).unwrap();
        assert!(
            job.await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("provider registry changed")
        );

        // Complete both synthetic Provider fixtures' scheduled reads.
        original.read().await.update().await.unwrap();
        replacement.read().await.update().await.unwrap();
    }

    #[tokio::test]
    async fn s04bf_provider_rotation_during_read_only_operation_discards_result() {
        let dir = tempfile::tempdir().unwrap();
        let handle: ThreadSafeProxyProvider =
            Arc::new(tokio::sync::RwLock::new(provider_with_refresh(
                dir.path()
                    .join("provider.yaml")
                    .to_string_lossy()
                    .into_owned(),
                SAME_NAME_NEW_HOST,
            )));
        handle.read().await.initialize().await.unwrap();
        let runtime = Arc::new(tokio::sync::RwLock::new(NetworkStatus::default()));
        runtime.write().await.observed(&NetworkSnapshot::default());
        let sources = std::collections::HashMap::from([(
            "synthetic-provider".to_owned(),
            handle.clone(),
        )]);
        let snapshot = StrictProviderObservation::capture(&runtime, &sources)
            .await
            .unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (continue_tx, continue_rx) = tokio::sync::oneshot::channel::<()>();
        let observed_runtime = runtime.clone();
        let job = tokio::spawn(async move {
            snapshot
                .validate_during(&observed_runtime, async {
                    entered_tx.send(()).unwrap();
                    continue_rx.await.unwrap();
                    42
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        handle.read().await.update().await.unwrap();
        continue_tx.send(()).unwrap();
        let error = job.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("changed during"), "{error}");
    }

    #[tokio::test]
    async fn explicitly_empty_refresh_remains_supported() {
        let dir = tempfile::tempdir().expect("temporary cache dir");
        let cache_path = dir.path().join("provider.yaml");
        let provider =
            provider_with_refresh(cache_path.to_string_lossy().into_owned(), EMPTY);
        provider.initialize().await.expect("valid initial provider");
        provider
            .update()
            .await
            .expect("explicit empty list is valid");
        assert!(provider.proxies().await.is_empty());
        let revoked = provider.strict_content_snapshot().await.unwrap();
        assert_eq!(revoked.revision, 2);
        assert!(revoked.proxies.is_empty());
        assert_eq!(std::fs::read(&cache_path).unwrap(), EMPTY);
    }
}

#[cfg(all(test, feature = "wireguard"))]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::{ProxyProvider, ProxySetProvider};
    use crate::{
        app::{
            dns::MockClashResolver,
            remote_content_manager::{
                ProxyManager,
                healthcheck::HealthCheck,
                providers::{MockProviderVehicle, Provider, ProviderVehicleType},
            },
        },
        proxy::OutboundType,
    };

    #[tokio::test]
    async fn remote_provider_builds_wireguard_handler() {
        let mut vehicle = MockProviderVehicle::new();
        vehicle.expect_read().returning(|| {
            Ok(br#"
proxies:
  - name: wg
    type: wireguard
    server: 198.51.100.10
    port: 51820
    private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
    public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
    ip: 10.0.0.2/32
    udp: true
"#
            .to_vec())
        });
        vehicle
            .expect_path()
            .return_const("/tmp/chimera-wireguard-provider".to_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);

        let mut dns_resolver = MockClashResolver::new();
        dns_resolver
            .expect_replace_proxy_provider_dns_domains()
            .returning(|_, _| Ok(()));
        let manager = ProxyManager::new(Arc::new(dns_resolver), None);
        let health = HealthCheck::new(
            vec![],
            "http://www.gstatic.com/generate_204".to_owned(),
            0,
            true,
            manager,
        );
        let provider = ProxySetProvider::new(
            "wireguard".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            health,
        )
        .expect("wireguard provider should construct");

        provider
            .initialize()
            .await
            .expect("wireguard provider should initialize");
        let proxies = provider.proxies().await;
        assert_eq!(proxies.len(), 1);
        assert!(matches!(proxies[0].proto(), OutboundType::WireGuard));
    }

    #[tokio::test]
    async fn remote_provider_refreshes_wireguard_handler() {
        let cache_dir =
            tempfile::tempdir().expect("provider cache dir should create");
        let cache_path = cache_dir.path().join("wireguard.yaml");
        let reads = Arc::new(AtomicUsize::new(0));
        let reads_clone = reads.clone();
        let mut vehicle = MockProviderVehicle::new();
        vehicle.expect_read().returning(move || {
            let name = if reads_clone.fetch_add(1, Ordering::SeqCst) == 0 {
                "wg-first"
            } else {
                "wg-second"
            };
            Ok(format!(
                r#"
proxies:
  - name: {name}
    type: wireguard
    server: 198.51.100.10
    port: 51820
    private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
    public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
    ip: 10.0.0.2/32
    udp: true
"#
            )
            .into_bytes())
        });
        vehicle
            .expect_path()
            .return_const(cache_path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);

        let mut dns_resolver = MockClashResolver::new();
        dns_resolver
            .expect_replace_proxy_provider_dns_domains()
            .returning(|_, _| Ok(()));
        let manager = ProxyManager::new(Arc::new(dns_resolver), None);
        let health = HealthCheck::new(
            vec![],
            "http://www.gstatic.com/generate_204".to_owned(),
            0,
            true,
            manager,
        );
        let provider = ProxySetProvider::new(
            "wireguard".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            health,
        )
        .expect("wireguard provider should construct");

        provider
            .initialize()
            .await
            .expect("wireguard provider should initialize");
        assert_eq!(provider.proxies().await[0].name(), "wg-first");

        provider
            .update()
            .await
            .expect("wireguard provider should refresh");
        let proxies = provider.proxies().await;
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name(), "wg-second");
        assert!(matches!(proxies[0].proto(), OutboundType::WireGuard));
    }
}
