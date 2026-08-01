use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::{
    app::remote_content_manager::providers::{
        ThreadSafeProviderVehicle, fetcher::Fetcher,
    },
    config::internal::listener::InboundOpts,
};

/// The YAML structure expected at the provider URL or file.
///
/// ```yaml
/// listeners:
///   - name: socks-node
///     type: socks
///     listen: 0.0.0.0
///     port: 1080
///     udp: true
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    listeners: Option<Vec<InboundOpts>>,
}

type InboundUpdater =
    Box<dyn Fn(Vec<InboundOpts>) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
type InboundParser =
    Box<dyn Fn(&[u8]) -> anyhow::Result<Vec<InboundOpts>> + Send + Sync + 'static>;

pub struct InboundSetProvider {
    fetcher: Fetcher<InboundUpdater, InboundParser>,
}

impl InboundSetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        on_update: impl Fn(Vec<InboundOpts>) -> BoxFuture<'static, ()>
        + Send
        + Sync
        + 'static,
    ) -> anyhow::Result<Self> {
        let provider_name = name.clone();
        let parser: InboundParser = Box::new(move |input: &[u8]| {
            let scheme: ProviderScheme =
                serde_yaml::from_slice(input).map_err(|error| {
                    anyhow::anyhow!(
                        "inbound provider {provider_name} parse error: {error}"
                    )
                })?;
            Ok(scheme.listeners.unwrap_or_default())
        });
        let updater: InboundUpdater = Box::new(on_update);

        Ok(Self {
            fetcher: Fetcher::new(name, interval, vehicle, parser, Some(updater)),
        })
    }

    pub async fn initialize(&self) -> anyhow::Result<Vec<InboundOpts>> {
        let listeners = self.fetcher.initial().await?;
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(listeners.clone()).await;
        }
        Ok(listeners)
    }
}

pub type ThreadSafeInboundProvider = Arc<InboundSetProvider>;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::*;
    use crate::app::remote_content_manager::providers::{
        MockProviderVehicle, ProviderVehicleType,
    };

    fn make_vehicle(content: &'static [u8]) -> Arc<MockProviderVehicle> {
        let path = std::env::temp_dir()
            .join(format!("inbound_provider_test_{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, content).unwrap();

        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_str().unwrap().to_owned());
        vehicle
            .expect_read()
            .returning(move || Ok(content.to_vec()));
        vehicle.expect_typ().return_const(ProviderVehicleType::File);
        Arc::new(vehicle)
    }

    #[tokio::test]
    async fn initializes_listeners_and_calls_update() {
        let yaml = b"\
listeners:
  - name: socks-test
    type: socks
    listen: 0.0.0.0
    port: 1080
    udp: true
";
        let received = Arc::new(Mutex::new(Vec::<InboundOpts>::new()));
        let received_for_update = received.clone();
        let provider = InboundSetProvider::new(
            "test".to_owned(),
            Duration::ZERO,
            make_vehicle(yaml),
            move |listeners| {
                let received = received_for_update.clone();
                Box::pin(async move {
                    received.lock().await.extend(listeners);
                })
            },
        )
        .unwrap();

        let initial = provider.initialize().await.unwrap();
        assert_eq!(initial.len(), 1);

        let received = received.lock().await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].common_opts().name, "socks-test");
        assert_eq!(received[0].common_opts().port, 1080);
    }

    #[tokio::test]
    async fn invalid_listener_fails_the_provider_load() {
        let yaml = b"\
listeners:
  - name: valid
    type: socks
    listen: 0.0.0.0
    port: 1080
  - name: invalid
    type: unknown-protocol
    listen: 0.0.0.0
    port: 9999
";
        let provider = InboundSetProvider::new(
            "test".to_owned(),
            Duration::ZERO,
            make_vehicle(yaml),
            |_| Box::pin(async {}),
        )
        .unwrap();

        assert!(provider.initialize().await.is_err());
    }

    #[tokio::test]
    async fn empty_listener_set_calls_update_with_empty_list() {
        let called = Arc::new(Mutex::new(false));
        let called_for_update = called.clone();
        let provider = InboundSetProvider::new(
            "test".to_owned(),
            Duration::ZERO,
            make_vehicle(b"listeners:\n"),
            move |listeners| {
                let called = called_for_update.clone();
                Box::pin(async move {
                    assert!(listeners.is_empty());
                    *called.lock().await = true;
                })
            },
        )
        .unwrap();

        let initial = provider.initialize().await.unwrap();
        assert!(initial.is_empty());
        assert!(*called.lock().await);
    }
}
