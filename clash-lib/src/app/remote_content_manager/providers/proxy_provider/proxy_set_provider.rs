use super::{ProxyProvider, ProxyProviderContentSnapshot};
use crate::{
    Error,
    app::{
        outbound::manager::OutboundManager,
        remote_content_manager::{
            healthcheck::HealthCheck,
            providers::{
                Provider, ProviderType, ProviderVehicleType,
                ThreadSafeProviderVehicle, fetcher::Fetcher,
            },
        },
    },
    common::errors::map_io_error,
    config::internal::proxy::OutboundProxyProtocol,
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

struct Inner {
    proxies: Vec<AnyOutboundHandler>,
    revision: u64,
}

type ProxyUpdater = Box<
    dyn Fn(Vec<AnyOutboundHandler>) -> BoxFuture<'static, ()>
        + Send
        + Sync
        + 'static,
>;
type ProxyParser = Box<
    dyn Fn(&[u8]) -> anyhow::Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static,
>;

pub struct ProxySetProvider {
    fetcher: Fetcher<ProxyUpdater, ProxyParser>,
    hc: Arc<HealthCheck>,
    inner: Arc<tokio::sync::RwLock<Inner>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        hc: HealthCheck,
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

        let updater_hc = hc.clone();
        let updater_name = name.clone();
        let updater: ProxyUpdater = Box::new(move |input| {
            let hc = updater_hc.clone();
            let name = updater_name.clone();
            let inner = inner_clone.clone();
            Box::pin(async move {
                {
                    let mut inner = inner.write().await;
                    debug!("updating {} proxies for: {}", input.len(), name);
                    let Some(next_revision) = inner.revision.checked_add(1) else {
                        warn!(
                            "proxy provider {name} exhausted content revision; refusing update"
                        );
                        return;
                    };
                    inner.proxies.clone_from(&input);
                    inner.revision = next_revision;
                }
                hc.update(input).await;
                tokio::spawn(async move {
                    hc.check().await;
                });
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

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater));
        Ok(Self { fetcher, hc, inner })
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
        let proxies = self.fetcher.initial().await.map_err(map_io_error)?;
        debug!("{} initialized with {} proxies", self.name(), proxies.len());
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(proxies).await;
        }
        if let Err(e) = self.fetcher.start_watch().await {
            warn!(
                "proxy provider '{}': live file watching unavailable, falling back to interval polling: {}",
                self.name(),
                e
            );
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        let (proxies, same) = self.fetcher.update().await.map_err(map_io_error)?;
        debug!(
            "{} updated with {} proxies, same? {}",
            self.name(),
            proxies.len(),
            same
        );
        if !same && let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(proxies).await;
        }
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
        self.inner.read().await.proxies.to_vec()
    }

    async fn strict_content_snapshot(&self) -> Option<ProxyProviderContentSnapshot> {
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

    fn provider_with_refresh(
        path: String,
        refreshed_content: &'static [u8],
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
        let manager = ProxyManager::new(Arc::new(MockClashResolver::new()), None);
        let health = HealthCheck::new(
            vec![],
            "http://example.invalid/check".to_owned(),
            0,
            true,
            manager,
        );
        ProxySetProvider::new(
            "synthetic-provider".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            health,
        )
        .expect("offline provider should construct")
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
                bootstrap_provider::StrictProviderRegistry,
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
        let provider_registry: StrictProviderRegistry =
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::from([
                ("synthetic-provider".into(), source.clone()),
            ])));
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
            .write()
            .await
            .insert("synthetic-provider".into(), second);
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

        let manager = ProxyManager::new(Arc::new(MockClashResolver::new()), None);
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

        let manager = ProxyManager::new(Arc::new(MockClashResolver::new()), None);
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
