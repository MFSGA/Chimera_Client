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
        timeout: Option<std::time::Duration>,
    ) -> Self {
        self.probe = probe;
        self.minimum_bytes = minimum_bytes;
        self.timeout = timeout;
        self
    }

    async fn run_check(
        proxy_manager: &ProxyManager,
        proxies: &Vec<AnyOutboundHandler>,
        url: &str,
        probe: HealthCheckProbe,
        minimum_bytes: usize,
        timeout: Option<std::time::Duration>,
    ) {
        #[cfg(not(feature = "extended-health-check"))]
        let _ = minimum_bytes;

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
            self.timeout,
        )
        .await;
    }

    // pub async fn update(&self, proxies: Vec<AnyOutboundHandler>) {
    //     self.inner.write().await.proxies = proxies;
    // }

    pub fn auto(&self) -> bool {
        self.interval != 0
    }
}
