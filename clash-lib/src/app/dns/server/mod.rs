use futures::FutureExt;
use hickory_proto::op::Message;

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
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DnsRunner {
    pub fn new(
        enable: bool,
        listen: DNSListenAddr,
        resolver: ThreadSafeDNSResolver,
        cwd: &std::path::Path,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            enable,
            listener: listen,
            resolver,
            cwd: cwd.to_path_buf(),
            cancellation_token: cancellation_token.unwrap_or_default(),
            task: std::sync::Mutex::new(None),
        }
    }
}

impl Runner for DnsRunner {
    fn run_async(&self) {
        if !self.enable {
            info!("dns listener is disabled, skipping");
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
                tokio::select! {
                    res = r => {
                        match res {
                            Ok(()) => {},
                            Err(err) => {
                                error!("dns listener error: {}", err);
                            }
                        }
                    },
                    _ = cancellation_token.cancelled() => {
                        info!("dns listener is closed");
                    },
                }
            } else {
                info!("dns listener: no listen addresses configured, skipping");
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
            match handle {
                Some(handle) => handle.await.map_err(|err| {
                    crate::Error::Operation(format!(
                        "dns listener join error: {err}"
                    ))
                })?,
                None => {}
            }

            Ok(())
        }
        .boxed()
    }
}
