use super::ProxyProvider;
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

        let inner = Arc::new(tokio::sync::RwLock::new(Inner { proxies: vec![] }));
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
                    inner.proxies.clone_from(&input);
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

            proxies
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
                .collect::<Result<Vec<_>, Error>>()
                .map_err(Into::into)
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

    async fn touch(&self) {
        self.hc.touch().await;
    }

    async fn healthcheck(&self) {
        self.hc.check().await;
    }
}

#[cfg(all(test, feature = "wireguard"))]
mod tests {
    use std::{sync::Arc, time::Duration};

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
    private-key: private
    public-key: public
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
}
