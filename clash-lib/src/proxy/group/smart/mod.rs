use std::{collections::HashSet, io, sync::Arc, time::Instant};

use async_trait::async_trait;
use tracing::{debug, info};

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        profile::ThreadSafeCacheFile,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ThreadSafeProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

pub mod penalty;
pub mod state;
pub mod stats;

pub use state::SmartState;

#[derive(Debug)]
enum SmartError {
    NoProxy,
    AllProxiesFailed(Vec<String>),
}

impl std::fmt::Display for SmartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProxy => write!(f, "no available proxy in smart group"),
            Self::AllProxiesFailed(names) => {
                write!(f, "all proxies failed: {names:?}")
            }
        }
    }
}

impl std::error::Error for SmartError {}

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
    pub max_retries: Option<u32>,
    pub bandwidth_weight: Option<f64>,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    smart_state: Arc<tokio::sync::Mutex<SmartState>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartHandler")
            .field("name", &self.opts.name)
            .field("udp", &self.opts.udp)
            .field("max_retries", &self.opts.max_retries)
            .finish()
    }
}

impl Handler {
    pub fn new_with_cache(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
        proxy_manager: ProxyManager,
        cache_store: ThreadSafeCacheFile,
    ) -> Self {
        let group_name = opts.name.clone();
        let thread_group_name = group_name.clone();
        let thread_cache_store = cache_store.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(0);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new()
                .expect("failed to create smart cache runtime");
            let state = rt.block_on(async {
                info!(
                    "{} attempting to load smart stats from cache",
                    thread_group_name
                );
                SmartState::new_with_imported_data(
                    thread_cache_store.get_smart_stats(&thread_group_name).await,
                )
            });
            tx.send(state).expect("failed to send smart state");
        });

        let smart_state = rx.recv().expect("failed to receive smart state");
        let handler = Self {
            opts,
            providers,
            proxy_manager,
            smart_state: Arc::new(tokio::sync::Mutex::new(smart_state)),
        };

        let cache_store = cache_store.clone();
        let state = Arc::clone(&handler.smart_state);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let data = state.lock().await.export_data();
                cache_store.set_smart_stats(&group_name, data).await;
            }
        });

        handler
    }

    fn name(&self) -> &str {
        &self.opts.name
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    async fn pick_smart(&self, sess: &Session) -> Option<AnyOutboundHandler> {
        let proxies = self.get_proxies(false).await;
        if proxies.is_empty() {
            return None;
        }

        let site = sess.destination.host();
        let dest_ip = sess.destination.ip().map(|ip| ip.to_string());
        let mut state = self.smart_state.lock().await;
        state.cleanup_stale();

        let mut enhanced_sess = sess.clone();
        if let Some(traffic_stats) = state.get_traffic_stats(sess) {
            enhanced_sess.traffic_stats = Some(traffic_stats);
        }
        drop(state);

        let site_tuning = self.proxy_manager.get_site_tuning(&enhanced_sess).await;
        let state = self.smart_state.lock().await;
        let mut candidates = Vec::with_capacity(proxies.len());

        for proxy in proxies {
            let name = proxy.name().to_string();
            let delay = self
                .proxy_manager
                .last_delay(&name)
                .await
                .map(|delay| delay.as_secs_f64() * 1000.0)
                .unwrap_or(9999.0);
            let packet_loss = self
                .proxy_manager
                .get_packet_loss(&name)
                .await
                .unwrap_or(1.0);
            let rtt = self.proxy_manager.get_rtt(&name).await.unwrap_or(9999.0);
            let alive = self.proxy_manager.alive(&name).await;

            let site_stats = state.get_site_stats(&name, &site).map(|stats| {
                (
                    stats.get_delay_score(),
                    stats.success_rate(),
                    stats.get_trend(),
                    stats.latency_stability(),
                )
            });
            let ip_stats = dest_ip.as_ref().and_then(|ip| {
                state.get_site_stats(&name, ip).map(|stats| {
                    (
                        stats.get_delay_score(),
                        stats.success_rate(),
                        stats.get_trend(),
                        stats.latency_stability(),
                    )
                })
            });

            let weighted_delay = |stats: Option<(f64, f64, i8, f64)>| {
                stats
                    .map(|(delay, rate, trend, _)| {
                        let trend_multiplier = match trend {
                            1 => 0.9,
                            -1 => 1.1,
                            _ => 1.0,
                        };
                        delay * (2.0 - rate) * trend_multiplier
                    })
                    .unwrap_or(delay)
            };
            let stability_penalty = site_stats
                .map(|(_, _, _, stability)| stability * 0.5)
                .unwrap_or(0.0)
                + ip_stats
                    .map(|(_, _, _, stability)| stability * 0.5)
                    .unwrap_or(0.0);
            let penalty_score = state
                .get_penalty(&name)
                .map(|penalty| penalty.value())
                .unwrap_or(0.0);

            let mut score = (weighted_delay(site_stats) + weighted_delay(ip_stats))
                / 2.0
                * site_tuning.delay_weight.unwrap_or(1.0)
                + packet_loss * site_tuning.packet_loss_weight.unwrap_or(1000.0)
                + rtt * site_tuning.rtt_weight.unwrap_or(1.0)
                + stability_penalty
                + if alive {
                    0.0
                } else {
                    site_tuning.alive_penalty.unwrap_or(5000.0)
                }
                + penalty_score;

            if self.opts.bandwidth_weight.unwrap_or(0.0) > 0.0 {
                score += delay * 0.1 * self.opts.bandwidth_weight.unwrap_or(0.0);
            }
            candidates.push((score, proxy));
        }

        candidates.sort_by(|a, b| {
            a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
        });
        let selected = candidates.first().map(|(_, proxy)| proxy.clone());
        if let Some(proxy) = selected.as_ref() {
            debug!("{} selected proxy: {}", self.name(), proxy.name());
        }
        selected
    }

    async fn calculate_max_retries(&self, site: &str) -> u32 {
        let state = self.smart_state.lock().await;
        let site_stats: Vec<_> = state
            .site_stats
            .values()
            .filter_map(|stats| stats.get(site))
            .collect();
        let avg_success_rate = if site_stats.is_empty() {
            0.5
        } else {
            site_stats
                .iter()
                .map(|stats| stats.success_rate())
                .sum::<f64>()
                / site_stats.len() as f64
        };
        drop(state);

        let configured_max = self.opts.max_retries.unwrap_or(0);
        if configured_max > 0 {
            configured_max
        } else {
            (3.0 * (2.0 - avg_success_rate)).round().clamp(2.0, 6.0) as u32
        }
    }

    async fn record_success(
        &self,
        proxy_name: &str,
        site: &str,
        dest_ip: Option<&str>,
        delay: f64,
        sess: &Session,
    ) {
        let mut state = self.smart_state.lock().await;
        state.record_connection_result(proxy_name, site, dest_ip, delay, true);
        state.record_traffic(sess, 500, 500);
    }

    async fn record_failure(
        &self,
        proxy_name: &str,
        site: &str,
        dest_ip: Option<&str>,
        sess: &Session,
    ) {
        let mut state = self.smart_state.lock().await;
        state.record_connection_result(proxy_name, site, dest_ip, 9999.0, false);
        state.record_request(sess);
    }

    async fn adaptive_retry(
        &self,
        sess: &Session,
        resolver: &ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let site = sess.destination.host();
        let dest_ip = sess.destination.ip().map(|ip| ip.to_string());
        let mut tried = HashSet::new();
        let mut retry_delay = 100;

        {
            let mut state = self.smart_state.lock().await;
            state.start_traffic_tracking(sess);
            state.record_request(sess);
        }

        let max_retries = self.calculate_max_retries(&site).await;
        let mut retries = 0;
        while retries < max_retries {
            let Some(proxy) = self.pick_smart(sess).await else {
                break;
            };
            let name = proxy.name().to_string();
            if !tried.insert(name.clone()) {
                retries += 1;
                continue;
            }

            let start = Instant::now();
            match proxy.connect_stream(sess, resolver.clone()).await {
                Ok(stream) => {
                    self.record_success(
                        &name,
                        &site,
                        dest_ip.as_deref(),
                        start.elapsed().as_secs_f64() * 1000.0,
                        sess,
                    )
                    .await;
                    stream.append_to_chain(self.name()).await;
                    return Ok(stream);
                }
                Err(_) => {
                    self.record_failure(&name, &site, dest_ip.as_deref(), sess)
                        .await;
                    tokio::time::sleep(std::time::Duration::from_millis(
                        retry_delay,
                    ))
                    .await;
                    retry_delay = (retry_delay * 2).min(5000);
                    retries += 1;
                }
            }
        }

        if tried.is_empty() {
            Err(io::Error::other(SmartError::NoProxy))
        } else {
            Err(io::Error::other(SmartError::AllProxiesFailed(
                tried.into_iter().collect(),
            )))
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Smart
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        self.adaptive_retry(sess, &resolver).await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        if let Some(proxy) = self.pick_smart(sess).await {
            let datagram = proxy.connect_datagram(sess, resolver).await?;
            datagram.append_to_chain(self.name()).await;
            Ok(datagram)
        } else {
            Err(io::Error::other("no available proxy in smart group"))
        }
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        if let Some(proxy) = self.pick_smart(sess).await {
            proxy
                .connect_stream_with_connector(sess, resolver, connector)
                .await
        } else {
            Err(io::Error::other("no available proxy in smart group"))
        }
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        Handler::get_proxies(self, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        None
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;
    use crate::{
        app::remote_content_manager::{
            healthcheck::HealthCheck,
            providers::proxy_provider::plain_provider::PlainProvider,
        },
        proxy::utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        session::SocksAddr,
    };

    fn test_handler(
        proxy_manager: ProxyManager,
        providers: Vec<ThreadSafeProxyProvider>,
    ) -> Handler {
        Handler {
            opts: HandlerOptions {
                name: "smart".to_string(),
                udp: true,
                ..Default::default()
            },
            providers,
            proxy_manager,
            smart_state: Arc::new(tokio::sync::Mutex::new(SmartState::new())),
        }
    }

    #[tokio::test]
    async fn lower_latency_proxy_wins_reference_scoring() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler {
                name: "fast".to_string(),
            }),
            Arc::new(NoopOutboundHandler {
                name: "slow".to_string(),
            }),
        ];
        manager
            .report_delay("fast", true, Some(std::time::Duration::from_millis(50)))
            .await;
        manager
            .report_delay("slow", true, Some(std::time::Duration::from_millis(200)))
            .await;

        let health = HealthCheck::new(
            proxies.clone(),
            "http://example.invalid".to_string(),
            0,
            true,
            manager.clone(),
        );
        let provider: ThreadSafeProxyProvider = Arc::new(RwLock::new(
            PlainProvider::new("test".to_string(), proxies, health).unwrap(),
        ));
        let handler = test_handler(manager, vec![provider]);
        let mut session = Session::default();
        session.destination = SocksAddr::Domain("example.com".to_string(), 443);

        assert_eq!(handler.pick_smart(&session).await.unwrap().name(), "fast");
    }

    #[tokio::test]
    async fn retry_count_uses_reference_default_and_explicit_override() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let mut handler = test_handler(manager, vec![]);
        assert_eq!(handler.calculate_max_retries("example.com").await, 5);

        handler.opts.max_retries = Some(3);
        assert_eq!(handler.calculate_max_retries("example.com").await, 3);
    }

    #[tokio::test]
    async fn empty_smart_group_fails_without_network_io() {
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let manager = ProxyManager::new(resolver.clone(), None);
        let handler = test_handler(manager, vec![]);

        assert!(matches!(handler.proto(), OutboundType::Smart));
        assert!(handler.support_udp().await);
        let error = match handler.connect_stream(&Session::default(), resolver).await
        {
            Ok(_) => panic!("empty smart group must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no available proxy"));
    }
}
