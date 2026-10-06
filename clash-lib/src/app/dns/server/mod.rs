use futures::FutureExt;
use hickory_proto::op::Message;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::sync::{Mutex, oneshot};

use chimera_dns::DNSListenAddr;

use tracing::{error, info, instrument};

use crate::runner::Runner;

use super::ThreadSafeDNSResolver;

mod handler;
pub use handler::exchange_with_resolver;

static DEFAULT_DNS_SERVER_TTL: u32 = 60;
const MACOS_DNS_PROXY_BRIDGE_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1053));

struct DnsMessageExchanger {
    resolver: ThreadSafeDNSResolver,
}

impl chimera_dns::DnsMessageExchanger for DnsMessageExchanger {
    fn ipv6(&self) -> bool {
        self.resolver.ipv6()
    }

    #[instrument(skip(self))]
    async fn exchange(
        &self,
        message: &Message,
    ) -> Result<Message, chimera_dns::DNSError> {
        exchange_with_resolver(&self.resolver, message, true).await
    }
}

pub struct DnsRunner {
    enable: bool,
    listener: DNSListenAddr,
    managed_dns_proxy_bridge: bool,
    bridge_listener: Option<DNSListenAddr>,
    resolver: ThreadSafeDNSResolver,
    cwd: std::path::PathBuf,

    cancellation_token: tokio_util::sync::CancellationToken,
    task:
        std::sync::Mutex<Option<tokio::task::JoinHandle<Result<(), crate::Error>>>>,
    ready_tx: std::sync::Mutex<Option<oneshot::Sender<Result<(), String>>>>,
    ready_rx: Mutex<Option<oneshot::Receiver<Result<(), String>>>>,
}

impl DnsRunner {
    pub fn new(
        enable: bool,
        listen: DNSListenAddr,
        resolver: ThreadSafeDNSResolver,
        cwd: &std::path::Path,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self::new_with_dns_proxy_bridge(
            enable,
            listen,
            resolver,
            cwd,
            cancellation_token,
            false,
        )
    }

    pub(crate) fn new_with_dns_proxy_bridge(
        enable: bool,
        listen: DNSListenAddr,
        resolver: ThreadSafeDNSResolver,
        cwd: &std::path::Path,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
        managed_dns_proxy_bridge: bool,
    ) -> Self {
        let (ready_tx, ready_rx) = oneshot::channel();
        let bridge_listener = managed_dns_proxy_bridge
            .then(|| managed_bridge_listener(&listen))
            .flatten();
        Self {
            enable,
            listener: listen,
            managed_dns_proxy_bridge,
            bridge_listener,
            resolver,
            cwd: cwd.to_path_buf(),
            cancellation_token: cancellation_token.unwrap_or_default(),
            task: std::sync::Mutex::new(None),
            ready_tx: std::sync::Mutex::new(Some(ready_tx)),
            ready_rx: Mutex::new(Some(ready_rx)),
        }
    }

    pub(crate) fn fresh(
        &self,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self::new_with_dns_proxy_bridge(
            self.enable,
            self.listener.clone(),
            self.resolver.clone(),
            &self.cwd,
            Some(cancellation_token),
            self.managed_dns_proxy_bridge,
        )
    }

    pub async fn wait_ready(&self) -> Result<(), crate::Error> {
        let receiver = self.ready_rx.lock().await.take();
        match receiver {
            Some(receiver) => match tokio::time::timeout(
                crate::app::runtime_state::COMPONENT_READINESS_TIMEOUT,
                receiver,
            )
            .await
            {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(Ok(Err(message))) => Err(crate::Error::Operation(message)),
                Ok(Err(_)) => Err(crate::Error::Operation(
                    "DNS listener exited before becoming ready".to_owned(),
                )),
                Err(_) => Err(crate::Error::Operation(
                    "DNS listener readiness timed out after 30 seconds".to_owned(),
                )),
            },
            None => Err(crate::Error::Operation(
                "DNS listener readiness was already consumed".to_owned(),
            )),
        }
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.enable
            && (has_listener(&self.listener) || self.bridge_listener.is_some())
    }

    pub(crate) fn task_finished(&self) -> bool {
        self.task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
    }
}

impl Runner for DnsRunner {
    fn run_async(&self) {
        let mut ready_tx = self.ready_tx.lock().unwrap().take();
        if !self.enable {
            info!("dns listener is disabled, skipping");
            if let Some(sender) = ready_tx.take() {
                let _ = sender.send(Ok(()));
            }
            return;
        }
        let mut listen_configs = Vec::new();
        if has_listener(&self.listener) {
            listen_configs.push(self.listener.clone());
        }
        if let Some(bridge_listener) = &self.bridge_listener {
            listen_configs.push(bridge_listener.clone());
        }
        if listen_configs.is_empty() {
            info!(
                "dns listener is not configured; internal resolver remains available"
            );
            if let Some(sender) = ready_tx.take() {
                let _ = sender.send(Ok(()));
            }
            return;
        }

        let resolver = self.resolver.clone();
        let cwd = self.cwd.clone();
        let cancellation_token = self.cancellation_token.clone();

        let handle = tokio::spawn(async move {
            let mut runners = Vec::with_capacity(listen_configs.len());
            for listen in listen_configs {
                let exchanger = DnsMessageExchanger {
                    resolver: resolver.clone(),
                };
                match chimera_dns::get_dns_listener(listen, exchanger, &cwd).await {
                    Some(runner) => runners.push(runner),
                    None => {
                        let message = "dns listener: no listener started or one or more configured listeners failed to start";
                        error!("{}", message);
                        if let Some(sender) = ready_tx.take() {
                            let _ = sender.send(Err(message.to_owned()));
                        }
                        return Err(crate::Error::Operation(message.to_owned()));
                    }
                }
            }

            if let Some(sender) = ready_tx.take() {
                let _ = sender.send(Ok(()));
            }
            tokio::select! {
                res = futures::future::try_join_all(runners) => {
                    res.map(|_| ()).map_err(|err: chimera_dns::DNSError| {
                        error!("dns listener error: {}", err);
                        crate::Error::DNSError(err.to_string())
                    })
                },
                _ = cancellation_token.cancelled() => {
                    info!("dns listener is closed");
                    Ok(())
                },
            }
        });

        let mut task = self.task.lock().unwrap();
        *task = Some(handle);
    }

    fn shutdown(&self) {
        info!("Shutting down DNS server");
        self.cancellation_token.cancel();
    }

    fn join(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        let handle = self.task.lock().unwrap().take();
        async move {
            if let Some(handle) = handle {
                handle.await.map_err(|err| {
                    crate::Error::Operation(format!(
                        "dns listener join error: {err}"
                    ))
                })??;
            }

            Ok(())
        }
        .boxed()
    }
}

fn has_listener(listen: &DNSListenAddr) -> bool {
    listen.udp.is_some()
        || listen.tcp.is_some()
        || listen.doh.is_some()
        || listen.dot.is_some()
        || listen.doh3.is_some()
}

fn listener_covers_dns_proxy_bridge(listen: Option<SocketAddr>) -> bool {
    listen.is_some_and(|listen| {
        listen.port() == MACOS_DNS_PROXY_BRIDGE_ADDR.port()
            && match listen {
                SocketAddr::V4(address) => {
                    address.ip().is_unspecified()
                        || *address.ip() == Ipv4Addr::LOCALHOST
                }
                SocketAddr::V6(_) => false,
            }
    })
}

fn managed_bridge_listener(existing: &DNSListenAddr) -> Option<DNSListenAddr> {
    let udp = (!listener_covers_dns_proxy_bridge(existing.udp))
        .then_some(MACOS_DNS_PROXY_BRIDGE_ADDR);
    let tcp = (!listener_covers_dns_proxy_bridge(existing.tcp))
        .then_some(MACOS_DNS_PROXY_BRIDGE_ADDR);
    (udp.is_some() || tcp.is_some()).then_some(DNSListenAddr {
        udp,
        tcp,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
    };

    use super::*;
    use crate::app::dns::{SystemResolver, ThreadSafeDNSResolver};

    #[test]
    fn managed_bridge_adds_local_udp_and_tcp_when_dns_has_no_listeners() {
        let bridge = managed_bridge_listener(&DNSListenAddr::default())
            .expect("managed DNS proxy bridge should add listeners");
        let expected = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1053));

        assert_eq!(bridge.udp, Some(expected));
        assert_eq!(bridge.tcp, Some(expected));
    }

    #[test]
    fn managed_bridge_reuses_matching_user_listener_and_adds_missing_transport() {
        let expected = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1053));
        let existing = DNSListenAddr {
            udp: Some(expected),
            ..Default::default()
        };

        let bridge = managed_bridge_listener(&existing)
            .expect("TCP side of managed DNS proxy bridge should be added");
        assert_eq!(bridge.udp, None);
        assert_eq!(bridge.tcp, Some(expected));
    }

    #[test]
    fn managed_bridge_avoids_binding_against_matching_ipv4_wildcard_listener() {
        let wildcard =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1053));
        let existing = DNSListenAddr {
            udp: Some(wildcard),
            tcp: Some(wildcard),
            ..Default::default()
        };

        assert!(managed_bridge_listener(&existing).is_none());
    }

    #[tokio::test]
    async fn dns_bind_failure_is_reported_by_readiness_and_join() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("failed to reserve TCP DNS port");
        let addr: SocketAddr = tcp.local_addr().expect("failed to read DNS address");
        let udp =
            std::net::UdpSocket::bind(addr).expect("failed to reserve UDP DNS port");
        let resolver: ThreadSafeDNSResolver = Arc::new(
            SystemResolver::new(false).expect("system resolver should initialize"),
        );
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let runner = DnsRunner::new(
            true,
            DNSListenAddr {
                udp: Some(addr),
                tcp: Some(addr),
                ..Default::default()
            },
            resolver,
            temp.path(),
            None,
        );

        runner.run_async();
        let ready_err = runner
            .wait_ready()
            .await
            .expect_err("DNS readiness must fail when every listener is occupied");
        assert!(ready_err.to_string().contains("no listener started"));

        let join_err = runner
            .join()
            .await
            .expect_err("DNS task error must remain observable through join");
        assert!(join_err.to_string().contains("no listener started"));

        drop(udp);
        drop(tcp);
    }
}
