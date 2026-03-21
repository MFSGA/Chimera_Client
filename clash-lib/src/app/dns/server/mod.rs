use hickory_proto::op::Message;
use tracing::{error, info, instrument};

use chimera_dns::DNSListenAddr;

use crate::{Runner, app::dns::ThreadSafeDNSResolver};

mod handler;
pub use handler::exchange_with_resolver;

pub(crate) static DEFAULT_DNS_SERVER_TTL: u32 = 60;

struct DnsMessageExchanger {
    resolver: ThreadSafeDNSResolver,
}

#[async_trait::async_trait]
impl chimera_dns::DnsMessageExchanger for DnsMessageExchanger {
    fn ipv6(&self) -> bool {
        self.resolver.ipv6()
    }

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
        }
    }
}

impl Runner for DnsRunner {
    fn run_async(&self) {
        if !self.enable {
            info!("dns listener is disabled, skipping");
            return;
        }

        let resolver = self.resolver.clone();
        let listen = self.listener.clone();
        let cwd = self.cwd.clone();
        let cancellation_token = self.cancellation_token.clone();

        tokio::spawn(async move {
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
    }

    fn shutdown(&self) {
        info!("Shutting down DNS server");
        self.cancellation_token.cancel();
    }

    fn join(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move { Ok(()) })
    }
}
/*
pub async fn get_dns_listener(
    listen: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
    cwd: &std::path::Path,
) -> Option<Runner> {
    let h = DnsMessageExchanger { resolver };
    let r = chimera_dns::get_dns_listener(listen, h, cwd).await;
    match r {
        Some(r) => Some(Box::pin(async move {
            match r.await {
                Ok(()) => Ok(()),
                Err(err) => {
                    error!("dns listener error: {}", err);
                    Err(crate::Error::Io(std::io::Error::other(err.to_string())))
                }
            }
        })),
        _ => None,
    }
}
 */
