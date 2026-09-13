use futures::FutureExt;
use hickory_proto::op::Message;
use tokio::sync::{Mutex, oneshot};

use chimera_dns::DNSListenAddr;

use tracing::{error, info, instrument};

use crate::runner::Runner;

use super::ThreadSafeDNSResolver;

mod handler;
pub use handler::exchange_with_resolver;

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

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
        let (ready_tx, ready_rx) = oneshot::channel();
        Self {
            enable,
            listener: listen,
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
        Self::new(
            self.enable,
            self.listener.clone(),
            self.resolver.clone(),
            &self.cwd,
            Some(cancellation_token),
        )
    }

    pub async fn wait_ready(&self) -> Result<(), crate::Error> {
        let receiver = self.ready_rx.lock().await.take();
        match receiver {
            Some(receiver) => match receiver.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(message)) => Err(crate::Error::Operation(message)),
                Err(_) => Err(crate::Error::Operation(
                    "DNS listener exited before becoming ready".to_owned(),
                )),
            },
            None => Err(crate::Error::Operation(
                "DNS listener readiness was already consumed".to_owned(),
            )),
        }
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
        if self.listener.udp.is_none()
            && self.listener.tcp.is_none()
            && self.listener.doh.is_none()
            && self.listener.dot.is_none()
            && self.listener.doh3.is_none()
        {
            info!(
                "dns listener is not configured; internal resolver remains available"
            );
            if let Some(sender) = ready_tx.take() {
                let _ = sender.send(Ok(()));
            }
            return;
        }

        let resolver = self.resolver.clone();
        let listen = self.listener.clone();
        let cwd = self.cwd.clone();
        let cancellation_token = self.cancellation_token.clone();

        let handle = tokio::spawn(async move {
            let h = DnsMessageExchanger { resolver };
            let r = chimera_dns::get_dns_listener(listen, h, &cwd).await;
            if let Some(r) = r {
                if let Some(sender) = ready_tx.take() {
                    let _ = sender.send(Ok(()));
                }
                tokio::select! {
                    res = r => {
                        res.map_err(|err| {
                            error!("dns listener error: {}", err);
                            crate::Error::DNSError(err.to_string())
                        })
                    },
                    _ = cancellation_token.cancelled() => {
                        info!("dns listener is closed");
                        Ok(())
                    },
                }
            } else {
                let message = "dns listener: no listener started; no addresses were configured or all configured addresses failed to bind";
                error!("{}", message);
                if let Some(sender) = ready_tx.take() {
                    let _ = sender.send(Err(message.to_owned()));
                }
                Err(crate::Error::Operation(message.to_owned()))
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

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use super::*;
    use crate::app::dns::{SystemResolver, ThreadSafeDNSResolver};

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
