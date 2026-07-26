use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{FutureExt, StreamExt, stream::FuturesOrdered};
#[cfg(feature = "extended-health-check")]
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::warn;

#[cfg(feature = "tun")]
use crate::app::net::DEFAULT_OUTBOUND_INTERFACE;
#[cfg(feature = "tls")]
use crate::common::tls::GLOBAL_ROOT_STORE;
use crate::common::utils::serialize_duration;
use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::AnyOutboundHandler,
    session::{Network, Session, SocksAddr, Type},
};

pub mod healthcheck;
pub mod providers;

#[derive(Clone, Debug, Default, Serialize)]
pub struct TrafficStats {
    /// Total bytes uploaded in this session
    pub bytes_uploaded: u64,
    /// Total bytes downloaded in this session
    pub bytes_downloaded: u64,
    /// Duration of the connection
    pub connection_duration: Duration,
    /// Average throughput in bytes per second
    pub average_throughput: f64,
    /// Peak throughput observed
    pub peak_throughput: f64,
    /// Frequency of requests per second
    pub request_frequency: f64,
    /// Whether traffic flows both ways significantly
    pub is_bidirectional: bool,
}

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
        if !self.alive(name).await {
            return None;
        }
        self.delay_history(name)
            .await
            .last()
            .map(|x| x.delay.to_owned())
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
                manager
                    .url_test(outbound, &url, timeout)
                    .await
                    .inspect_err(|e| {
                        warn!("healthcheck {} -> {} failed: {}", proxy_name, url, e);
                    })
            }));
        }

        let futs: FuturesOrdered<_> = futs.into_iter().collect();
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

    #[cfg(feature = "extended-health-check")]
    pub async fn check_download(
        &self,
        outbounds: &Vec<AnyOutboundHandler>,
        url: &str,
        timeout: Option<Duration>,
        minimum_bytes: usize,
    ) -> Vec<std::io::Result<(Duration, Duration)>> {
        let mut tasks = Vec::new();
        for outbound in outbounds {
            let outbound = outbound.clone();
            let url = url.to_owned();
            let manager = self.clone();
            tasks.push(tokio::spawn(async move {
                let proxy_name = outbound.name().to_owned();
                manager
                    .download_test(outbound, &url, timeout, minimum_bytes)
                    .await
                    .inspect_err(|error| {
                        warn!(
                            "download healthcheck {} -> {} failed: {}",
                            proxy_name, url, error
                        );
                    })
            }));
        }

        let joined: Vec<_> = tasks
            .into_iter()
            .collect::<FuturesOrdered<_>>()
            .collect()
            .await;
        joined
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|error| {
                    Err(std::io::Error::other(error.to_string()))
                })
            })
            .collect()
    }

    pub async fn url_test(
        &self,
        outbound: AnyOutboundHandler,
        url: &str,
        timeout: Option<Duration>,
    ) -> std::io::Result<(Duration, Duration)> {
        self.url_test_inner(outbound, url, timeout, None).await
    }

    #[cfg(feature = "extended-health-check")]
    pub async fn download_test(
        &self,
        outbound: AnyOutboundHandler,
        url: &str,
        timeout: Option<Duration>,
        minimum_bytes: usize,
    ) -> std::io::Result<(Duration, Duration)> {
        self.url_test_inner(outbound, url, timeout, Some(minimum_bytes))
            .await
    }

    async fn url_test_inner(
        &self,
        outbound: AnyOutboundHandler,
        url: &str,
        timeout: Option<Duration>,
        minimum_bytes: Option<usize>,
    ) -> std::io::Result<(Duration, Duration)> {
        #[cfg(not(feature = "extended-health-check"))]
        let _ = minimum_bytes;

        let name = outbound.name().to_owned();
        let timeout = timeout.unwrap_or(Duration::from_secs(5));
        #[cfg(feature = "tun")]
        let default_outbound_interface =
            DEFAULT_OUTBOUND_INTERFACE.read().await.clone();
        #[cfg(not(feature = "tun"))]
        let default_outbound_interface = None;

        let uri: http::Uri = url.parse().map_err(std::io::Error::other)?;
        let host = uri
            .host()
            .ok_or_else(|| std::io::Error::other("url has no host"))?
            .to_owned();
        let port = uri.port_u16().unwrap_or_else(|| {
            if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            }
        });

        let sess = Session {
            network: Network::Tcp,
            typ: Type::Tunnel,
            destination: SocksAddr::Domain(host.clone(), port),
            so_mark: self.fw_mark,
            iface: default_outbound_interface,
            ..Default::default()
        };

        let connect_started = tokio::time::Instant::now();
        let stream = tokio::time::timeout(
            timeout,
            outbound.connect_stream(&sess, self.dns_resolver.clone()),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "urltest timeout")
        })??;
        let connect_delay = connect_started.elapsed();

        let req = Request::get(url)
            .header(hyper::header::HOST, host.as_str())
            .header("Connection", "Close")
            .version(hyper::Version::HTTP_11)
            .body(Empty::<Bytes>::new())
            .map_err(std::io::Error::other)?;

        #[allow(unused_mut)]
        let mut tls_handshake_delay = Duration::default();

        let request_started = tokio::time::Instant::now();
        let request_result = match uri.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                let io = TokioIo::new(stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(std::io::Error::other)?;
                tokio::task::spawn(async move {
                    let _ = conn.await;
                });
                tokio::time::timeout(timeout, sender.send_request(req).boxed())
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "urltest request timeout",
                        )
                    })?
                    .map_err(std::io::Error::other)
            }
            #[cfg(feature = "tls")]
            Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                let tls_config = rustls::ClientConfig::builder()
                    .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                    .with_no_client_auth();
                let connector = tokio_rustls::TlsConnector::from(
                    std::sync::Arc::new(tls_config),
                );
                let tls_started = tokio::time::Instant::now();
                let tls_stream = tokio::time::timeout(
                    timeout,
                    connector.connect(
                        host.try_into().map_err(|_| {
                            std::io::Error::other("invalid SNI host")
                        })?,
                        stream,
                    ),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "urltest tls timeout",
                    )
                })?
                .map_err(std::io::Error::other)?;
                tls_handshake_delay = tls_started.elapsed();

                let io = TokioIo::new(tls_stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(std::io::Error::other)?;
                tokio::task::spawn(async move {
                    let _ = conn.await;
                });
                tokio::time::timeout(timeout, sender.send_request(req).boxed())
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "urltest request timeout",
                        )
                    })?
                    .map_err(std::io::Error::other)
            }
            #[cfg(not(feature = "tls"))]
            Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "https requires tls feature",
                ))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsupported scheme",
            )),
        };
        let probe_result = match request_result {
            Ok(response) if !response.status().is_success() => {
                Err(std::io::Error::other(format!(
                    "healthcheck returned HTTP {}",
                    response.status()
                )))
            }
            #[cfg(feature = "extended-health-check")]
            Ok(mut response) if minimum_bytes.is_some() => {
                let minimum_bytes = minimum_bytes.unwrap_or_default();
                tokio::time::timeout(timeout, async {
                    let mut received = 0usize;
                    while let Some(frame) = response.body_mut().frame().await {
                        let frame = frame.map_err(std::io::Error::other)?;
                        if let Some(data) = frame.data_ref() {
                            received = received.saturating_add(data.len());
                            if received >= minimum_bytes {
                                return Ok(());
                            }
                        }
                    }
                    Err(std::io::Error::other(format!(
                        "healthcheck download ended after {received} bytes; \
                         expected at least {minimum_bytes}"
                    )))
                })
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "healthcheck download timeout",
                    )
                })?
            }
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        };
        let request_delay = request_started.elapsed();

        let ok = probe_result.is_ok();
        self.report_alive(&name, ok).await;
        self.report_delay(
            &name,
            ok,
            Some(if ok {
                request_delay
            } else {
                Duration::default()
            }),
        )
        .await;

        probe_result.map(|_| {
            (
                request_delay,
                connect_delay + tls_handshake_delay + request_delay,
            )
        })
    }

    // pub fn dns_resolver(&self) -> ThreadSafeDNSResolver {
    //     self.dns_resolver.clone()
    // }

    // pub fn fw_mark(&self) -> Option<u32> {
    //     self.fw_mark
    // }
}

#[cfg(all(test, feature = "extended-health-check"))]
mod tests {
    use std::{sync::Arc, time::Duration};

    use httpmock::{Method::GET, MockServer};

    use super::ProxyManager;
    use crate::{
        app::dns::SystemResolver,
        config::internal::proxy::PROXY_DIRECT,
        proxy::{AnyOutboundHandler, direct},
    };

    fn direct_manager() -> (ProxyManager, AnyOutboundHandler) {
        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let manager = ProxyManager::new(resolver, None);
        let outbound = Arc::new(direct::Handler::new(PROXY_DIRECT));
        (manager, outbound)
    }

    #[tokio::test]
    async fn download_probe_requires_minimum_response_bytes() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/download");
            then.status(200).body(vec![b'x'; 64]);
        });
        let (manager, outbound) = direct_manager();

        manager
            .download_test(
                outbound,
                &server.url("/download"),
                Some(Duration::from_secs(2)),
                64,
            )
            .await
            .unwrap();

        assert!(manager.alive(PROXY_DIRECT).await);
    }

    #[tokio::test]
    async fn short_download_marks_proxy_unhealthy() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/short");
            then.status(200).body(vec![b'x'; 16]);
        });
        let (manager, outbound) = direct_manager();

        let error = manager
            .download_test(
                outbound,
                &server.url("/short"),
                Some(Duration::from_secs(2)),
                64,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("expected at least 64"));
        assert!(!manager.alive(PROXY_DIRECT).await);
    }
}
