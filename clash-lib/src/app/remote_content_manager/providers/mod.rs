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
                    "deferred provider initialization failed; retrying (details withheld)"
                );
                attempt += 1;
                tokio::time::sleep(*delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Provider, ProviderType, ProviderVehicleType, initialize_provider_with_retry,
    };
    use async_trait::async_trait;
    use erased_serde::Serialize;
    use std::{
        collections::HashMap,
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl io::Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct RetryOnceProvider {
        attempts: AtomicUsize,
    }

    #[async_trait]
    impl Provider for RetryOnceProvider {
        fn name(&self) -> &str {
            "private-provider"
        }

        fn vehicle_type(&self) -> ProviderVehicleType {
            ProviderVehicleType::Http
        }

        fn typ(&self) -> ProviderType {
            ProviderType::Proxy
        }

        async fn initialize(&self) -> io::Result<()> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(io::Error::other("private-node.example resolution failed"))
            } else {
                Ok(())
            }
        }

        async fn update(&self) -> io::Result<()> {
            Ok(())
        }

        async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
            HashMap::new()
        }
    }

    #[tokio::test]
    async fn deferred_initialization_retry_log_withholds_error_text() {
        let captured = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || CaptureWriter(writer.clone()))
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let provider = RetryOnceProvider {
            attempts: AtomicUsize::new(0),
        };

        initialize_provider_with_retry(&provider).await.unwrap();

        let log = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(log.contains("details withheld"), "{log}");
        assert!(!log.contains("private-node.example"), "{log}");
        assert_eq!(provider.attempts.load(Ordering::SeqCst), 2);
    }
}
