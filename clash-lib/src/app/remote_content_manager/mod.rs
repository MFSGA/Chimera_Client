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

    pub async fn url_test(
        &self,
        outbound: AnyOutboundHandler,
        url: &str,
        timeout: Option<Duration>,
    ) -> std::io::Result<(Duration, Duration)> {
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
        let request_delay = request_started.elapsed();

        let ok = request_result.is_ok();
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

        request_result.map(|_| {
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
