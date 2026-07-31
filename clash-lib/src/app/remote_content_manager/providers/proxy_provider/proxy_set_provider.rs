use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use erased_serde::Serialize;
use futures::future::BoxFuture;
use tokio::sync::RwLock;
use tracing::debug;

use crate::{
    app::remote_content_manager::{
        healthcheck::HealthCheck,
        providers::{
            Provider, ProviderType, ProviderVehicleType, ThreadSafeProviderVehicle,
            fetcher::Fetcher,
        },
    },
    common::errors::map_io_error,
    proxy::AnyOutboundHandler,
};

pub type ProxyParser = Box<
    dyn Fn(&[u8]) -> anyhow::Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static,
>;

type ProxyUpdater = Box<
    dyn Fn(Vec<AnyOutboundHandler>) -> BoxFuture<'static, ()>
        + Send
        + Sync
        + 'static,
>;

pub struct ProxySetProvider {
    fetcher: Fetcher<ProxyUpdater, ProxyParser>,
    health_check: Arc<HealthCheck>,
    proxies: Arc<RwLock<Vec<AnyOutboundHandler>>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        health_check: HealthCheck,
        parser: ProxyParser,
    ) -> Self {
        let health_check = Arc::new(health_check);
        if health_check.auto() {
            let health_check = health_check.clone();
            tokio::spawn(async move {
                health_check.kick_off().await;
            });
        }

        let proxies = Arc::new(RwLock::new(Vec::new()));
        let updater_proxies = proxies.clone();
        let updater_health_check = health_check.clone();
        let updater: ProxyUpdater = Box::new(move |updated| {
            let proxies = updater_proxies.clone();
            let health_check = updater_health_check.clone();
            Box::pin(async move {
                *proxies.write().await = updated.clone();
                health_check.update(updated).await;
            })
        });
        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater));

        Self {
            fetcher,
            health_check,
            proxies,
        }
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
        let (proxies, unchanged) =
            self.fetcher.update().await.map_err(map_io_error)?;
        if !unchanged && let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(proxies).await;
        }
        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        HashMap::from([
            ("name".to_owned(), Box::new(self.name().to_owned()) as _),
            ("type".to_owned(), Box::new(self.typ().to_string()) as _),
            (
                "vehicleType".to_owned(),
                Box::new(self.vehicle_type().to_string()) as _,
            ),
            (
                "updatedAt".to_owned(),
                Box::new(self.fetcher.updated_at().await) as _,
            ),
        ])
    }
}

#[async_trait]
impl super::ProxyProvider for ProxySetProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        self.proxies.read().await.clone()
    }

    async fn touch(&self) {
        self.health_check.touch().await;
    }

    async fn healthcheck(&self) {
        self.health_check.check().await;
    }
}
