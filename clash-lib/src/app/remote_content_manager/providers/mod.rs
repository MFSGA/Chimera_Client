use async_trait::async_trait;
use erased_serde::Serialize;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    io,
    sync::Arc,
    time::Duration,
};

pub mod fetcher;
pub mod file_vehicle;
pub mod http_vehicle;
pub mod proxy_provider;
pub mod rule_provider;

#[cfg(test)]
use mockall::automock;

#[derive(Deserialize, PartialEq, Clone, Copy, Debug)]
pub enum ProviderVehicleType {
    File,
    Http,
    Compatible,
    Inline, /* InlineRuleProvider doesn't have a vehicle type, but we use it for
             * compatibility */
}

impl Display for ProviderVehicleType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderVehicleType::File => write!(f, "File"),
            ProviderVehicleType::Http => write!(f, "HTTP"),
            ProviderVehicleType::Compatible => write!(f, "Compatible"),
            ProviderVehicleType::Inline => write!(f, "Inline"),
        }
    }
}

pub type ThreadSafeProviderVehicle = Arc<dyn ProviderVehicle + Send + Sync>;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait ProviderVehicle {
    async fn read(&self) -> io::Result<Vec<u8>>;
    fn path(&self) -> &str;
    fn typ(&self) -> ProviderVehicleType;
}

pub enum ProviderType {
    Proxy,
    Rule,
}

impl Display for ProviderType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::Proxy => write!(f, "Proxy"),
            ProviderType::Rule => write!(f, "Rule"),
        }
    }
}

/// either Proxy or Rule provider
#[async_trait]
pub trait Provider {
    fn name(&self) -> &str;
    fn vehicle_type(&self) -> ProviderVehicleType;
    fn typ(&self) -> ProviderType;
    async fn initialize(&self) -> io::Result<()>;
    async fn update(&self) -> io::Result<()>;

    /// Load a local HTTP-provider cache while preparing an unpublished
    /// runtime candidate. Implementations must not contact the remote source.
    async fn prepare_candidate_from_cache(&self) -> io::Result<bool> {
        Ok(false)
    }

    /// Start deferred provider initialization after the candidate is
    /// committed. Implementations may keep retrying after an initial error.
    async fn activate_after_commit(&self) -> io::Result<()> {
        self.initialize().await
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>>;
}

/// Retry the first remote initialization after a candidate is committed.
/// This bootstrap retry is independent of the configured refresh interval,
/// which may be zero to disable periodic updates.
pub(crate) async fn initialize_provider_with_retry<P>(provider: &P) -> io::Result<()>
where
    P: Provider + Sync + ?Sized,
{
    const RETRY_DELAYS: [Duration; 2] =
        [Duration::from_millis(250), Duration::from_secs(1)];

    let mut retries = RETRY_DELAYS.iter();
    let mut attempt = 1;
    loop {
        match provider.initialize().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                let Some(delay) = retries.next() else {
                    return Err(error);
                };
                tracing::warn!(
                    provider = provider.name(),
                    attempt,
                    retry_in_ms = delay.as_millis(),
                    %error,
                    "deferred provider initialization failed; retrying"
                );
                attempt += 1;
                tokio::time::sleep(*delay).await;
            }
        }
    }
}
