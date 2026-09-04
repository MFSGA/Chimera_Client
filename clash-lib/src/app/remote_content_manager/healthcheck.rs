use std::sync::Arc;

use tokio::time::Instant;
use tracing::debug;

use crate::config::internal::proxy::HealthCheckProbe;
use crate::proxy::AnyOutboundHandler;

use super::ProxyManager;

struct HealCheckInner {
    last_check: Instant,
    proxies: Vec<AnyOutboundHandler>,
    task_handle: Option<Arc<tokio::task::JoinHandle<()>>>,
}

pub struct HealthCheck {
    url: String,
    interval: u64,
    lazy: bool,
    probe: HealthCheckProbe,
    minimum_bytes: usize,
    minimum_events: usize,
    maximum_first_byte: std::time::Duration,
    expected_echo: String,
    timeout: Option<std::time::Duration>,
    proxy_manager: ProxyManager,
    inner: Arc<tokio::sync::RwLock<HealCheckInner>>,
}

impl HealthCheck {
    pub fn new(
        proxies: Vec<AnyOutboundHandler>,
        url: String,
        interval: u64,
        lazy: bool,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            url,
            interval,
            lazy,
            probe: HealthCheckProbe::Http,
            minimum_bytes: 0,
            minimum_events: 0,
            maximum_first_byte: std::time::Duration::ZERO,
            expected_echo: String::new(),
            timeout: None,
            proxy_manager,
            inner: Arc::new(tokio::sync::RwLock::new(HealCheckInner {
                last_check: tokio::time::Instant::now(),
                proxies,
                task_handle: None,
            })),
        }
    }

    pub fn with_probe(
        mut self,
        probe: HealthCheckProbe,
        minimum_bytes: usize,
        minimum_events: usize,
        maximum_first_byte: std::time::Duration,
        expected_echo: String,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        self.probe = probe;
        self.minimum_bytes = minimum_bytes;
        self.minimum_events = minimum_events;
        self.maximum_first_byte = maximum_first_byte;
        self.expected_echo = expected_echo;
        self.timeout = timeout;
        self
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_check(
        proxy_manager: &ProxyManager,
        proxies: &Vec<AnyOutboundHandler>,
        url: &str,
        probe: HealthCheckProbe,
        minimum_bytes: usize,
        minimum_events: usize,
        maximum_first_byte: std::time::Duration,
        expected_echo: &str,
        timeout: Option<std::time::Duration>,
    ) {
        #[cfg(not(feature = "extended-health-check"))]
        let _ = (
            minimum_bytes,
            minimum_events,
            maximum_first_byte,
            expected_echo,
        );
        #[cfg(all(feature = "extended-health-check", not(feature = "ws")))]
        let _ = expected_echo;

        match probe {
            HealthCheckProbe::Http => {
                proxy_manager.check(proxies, url, timeout).await;
            }
            #[cfg(feature = "extended-health-check")]
            HealthCheckProbe::Download => {
                proxy_manager
                    .check_download(proxies, url, timeout, minimum_bytes)
                    .await;
            }
            #[cfg(feature = "extended-health-check")]
            HealthCheckProbe::Sse => {
                for proxy in proxies {
                    if let Err(error) = proxy_manager
                        .sse_test(
                            proxy.clone(),
                            url,
                            timeout,
                            minimum_events,
                            maximum_first_byte,
                        )
                        .await
                    {
                        tracing::warn!(
                            "SSE healthcheck {} -> {} failed: {}",
                            proxy.name(),
                            url,
                            error
                        );
                    }
                }
            }
            #[cfg(not(feature = "extended-health-check"))]
            HealthCheckProbe::Sse => {
                tracing::warn!(
                    "SSE health probe requires extended-health-check feature"
                );
            }
            #[cfg(all(feature = "extended-health-check", feature = "ws"))]
            HealthCheckProbe::Websocket => {
                for proxy in proxies {
                    if let Err(error) = proxy_manager
                        .websocket_test(proxy.clone(), url, timeout, expected_echo)
                        .await
                    {
                        tracing::warn!(
                            "WebSocket healthcheck {} -> {} failed: {}",
                            proxy.name(),
                            url,
                            error
                        );
                    }
                }
            }
            #[cfg(not(all(feature = "extended-health-check", feature = "ws")))]
            HealthCheckProbe::Websocket => {
                tracing::warn!(
                    "WebSocket health probe requires extended-health-check and ws features"
                );
            }
            #[cfg(not(feature = "extended-health-check"))]
            HealthCheckProbe::Download => {
                tracing::warn!(
                    "download health probe requires extended-health-check feature"
                );
            }
        }
    }

    pub async fn kick_off(&self) {
        let proxy_manager = self.proxy_manager.clone();
        let interval = self.interval;
        let lazy = self.lazy;
        let probe = self.probe;
        let minimum_bytes = self.minimum_bytes;
        let timeout = self.timeout;
        let minimum_events = self.minimum_events;
        let maximum_first_byte = self.maximum_first_byte;
        let expected_echo = self.expected_echo.clone();
        let proxies = self.inner.read().await.proxies.clone();

        {
            let url = self.url.clone();
            let proxies = proxies.clone();
            tokio::spawn(async move {
                Self::run_check(
                    &proxy_manager,
                    &proxies,
                    &url,
                    probe,
                    minimum_bytes,
                    minimum_events,
                    maximum_first_byte,
                    &expected_echo,
                    timeout,
                )
                .await;
            });
        }

        let inner = self.inner.clone();
        let proxy_manager = self.proxy_manager.clone();
        let url = self.url.clone();
        let probe = self.probe;
        let minimum_bytes = self.minimum_bytes;
        let timeout = self.timeout;
        let minimum_events = self.minimum_events;
        let maximum_first_byte = self.maximum_first_byte;
        let expected_echo = self.expected_echo.clone();
        let task_handle = tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(tokio::time::Duration::from_secs(interval));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        debug!("healthcheck ticking: {}, lazy: {}", url, lazy);
                        let now = tokio::time::Instant::now();
                        let last_check = inner.read().await.last_check;
                        if !lazy || now.duration_since(last_check).as_secs() >= interval {
                            Self::run_check(
                                &proxy_manager,
                                &proxies,
                                &url,
                                probe,
                                minimum_bytes,
                                minimum_events,
                                maximum_first_byte,
                                &expected_echo,
                                timeout,
                            ).await;
                            let mut w = inner.write().await;
                            w.last_check = now;
                        }
                    },
                }
            }
        });

        self.inner.write().await.task_handle = Some(Arc::new(task_handle));
    }

    pub async fn touch(&self) {
        self.inner.write().await.last_check = tokio::time::Instant::now();
    }

    pub async fn check(&self) {
        let proxies = self.inner.read().await.proxies.clone();
        Self::run_check(
            &self.proxy_manager,
            &proxies,
            &self.url,
            self.probe,
            self.minimum_bytes,
            self.minimum_events,
            self.maximum_first_byte,
            &self.expected_echo,
            self.timeout,
        )
        .await;
    }

    pub async fn update(&self, proxies: Vec<AnyOutboundHandler>) {
        self.inner.write().await.proxies = proxies;
    }

    pub fn auto(&self) -> bool {
        self.interval != 0
    }
}
