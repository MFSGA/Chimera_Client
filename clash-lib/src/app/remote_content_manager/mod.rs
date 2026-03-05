use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use futures::{StreamExt, stream::FuturesUnordered};
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::warn;

use crate::{app::dns::ThreadSafeDNSResolver, proxy::AnyOutboundHandler, session::{Session, SocksAddr, Type, Network}};
use crate::common::utils::serialize_duration;

pub mod providers;
pub mod healthcheck;

#[derive(Default)]
struct ProxyState {
    alive: AtomicBool,
    delay_history: VecDeque<DelayHistory>,
}

#[derive(Clone, Serialize)]
pub struct DelayHistory {
    time: DateTime<Utc>,
    #[serde(serialize_with = "serialize_duration")]
    delay: Duration,
}

/// ProxyManager is the latency registry.
#[derive(Clone)]
pub struct ProxyManager {
    proxy_state: Arc<RwLock<HashMap<String, ProxyState>>>,
    dns_resolver: ThreadSafeDNSResolver,
    fw_mark: Option<u32>,
}

impl ProxyManager {
    pub fn new(dns_resolver: ThreadSafeDNSResolver, fw_mark: Option<u32>) -> Self {
        Self {
            dns_resolver,
            proxy_state: Default::default(),
            fw_mark,
        }
    }

    pub async fn alive(&self, name: &str) -> bool {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|state| state.alive.load(Ordering::Relaxed))
            .unwrap_or(true)
    }

    pub async fn report_alive(&self, name: &str, alive: bool) {
        let mut states = self.proxy_state.write().await;
        let state = states.entry(name.to_owned()).or_default();
        state.alive.store(alive, Ordering::Relaxed);
    }

    pub async fn delay_history(&self, name: &str) -> Vec<DelayHistory> {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|state| state.delay_history.clone())
            .unwrap_or_default()
            .into()
    }

    pub async fn last_delay(&self, name: &str) -> Option<Duration> {
        self.proxy_state
            .read()
            .await
            .get(name)
            .and_then(|state| state.delay_history.back().map(|x| x.delay))
    }

    pub async fn report_delay(
        &self,
        name: &str,
        alive: bool,
        delay: Option<Duration>,
    ) {
        let mut states = self.proxy_state.write().await;
        let state = states.entry(name.to_owned()).or_default();
        state.alive.store(alive, Ordering::Relaxed);

        if let Some(delay) = delay {
            state.delay_history.push_back(DelayHistory {
                time: Utc::now(),
                delay,
            });
            while state.delay_history.len() > 20 {
                let _ = state.delay_history.pop_front();
            }
        }
    }

    pub async fn check(
        &self,
        outbounds: &Vec<AnyOutboundHandler>,
        url: &str,
        timeout: Option<Duration>,
    ) -> Vec<std::io::Result<(Duration, Duration)>> {
        let mut futs = vec![];
        for outbound in outbounds {
            let outbound = outbound.clone();
            let url = url.to_owned();
            let manager = self.clone();
            futs.push(tokio::spawn(async move {
                let proxy_name = outbound.name().to_owned();
                manager.url_test(outbound, &url, timeout).await.inspect_err(|e| {
                    warn!("healthcheck {} -> {} failed: {}", proxy_name, url, e);
                })
            }));
        }

        let futs: FuturesUnordered<_> = futs.into_iter().collect();
        let joined: Vec<_> = futs.collect().await;

        let mut results = vec![];
        for res in joined {
            match res {
                Ok(r) => results.push(r),
                Err(e) => results.push(Err(std::io::Error::other(e.to_string()))),
            }
        }
        results
    }

    pub async fn url_test(
        &self,
        outbound: AnyOutboundHandler,
        url: &str,
        timeout: Option<Duration>,
    ) -> std::io::Result<(Duration, Duration)> {
        let name = outbound.name().to_owned();
        let timeout = timeout.unwrap_or(Duration::from_secs(5));

        let uri: http::Uri = url.parse().map_err(std::io::Error::other)?;
        let host = uri
            .host()
            .ok_or_else(|| std::io::Error::other("url has no host"))?
            .to_owned();
        let port = uri.port_u16().unwrap_or_else(|| {
            if uri.scheme_str() == Some("https") { 443 } else { 80 }
        });

        let sess = Session {
            network: Network::Tcp,
            typ: Type::Tunnel,
            destination: SocksAddr::Domain(host, port),
            so_mark: self.fw_mark,
            ..Default::default()
        };

        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            timeout,
            outbound.connect_stream(&sess, self.dns_resolver.clone()),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "urltest timeout"))
        .and_then(|r| r);

        let elapsed = started.elapsed();
        self.report_alive(&name, result.is_ok()).await;
        self.report_delay(
            &name,
            result.is_ok(),
            if result.is_ok() { Some(elapsed) } else { None },
        )
        .await;

        result.map(|_| (elapsed, elapsed))
    }

    pub fn dns_resolver(&self) -> ThreadSafeDNSResolver {
        self.dns_resolver.clone()
    }

    pub fn fw_mark(&self) -> Option<u32> {
        self.fw_mark
    }
}
