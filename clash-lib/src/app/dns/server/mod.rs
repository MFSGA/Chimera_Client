use hickory_proto::op::Message;

use chimera_dns::DNSListenAddr;
use std::sync::{Arc, Mutex};
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
    manage_system_resolver: bool,
    managed_resolv_conf_backup: Arc<Mutex<Option<String>>>,

    cancellation_token: tokio_util::sync::CancellationToken,
}

impl DnsRunner {
    pub fn new(
        enable: bool,
        listen: DNSListenAddr,
        resolver: ThreadSafeDNSResolver,
        cwd: &std::path::Path,
        manage_system_resolver: bool,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            enable,
            listener: listen,
            resolver,
            cwd: cwd.to_path_buf(),
            manage_system_resolver,
            managed_resolv_conf_backup: Arc::new(Mutex::new(None)),
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }
}

#[cfg(target_os = "linux")]
const MANAGED_RESOLV_CONF_MARKER: &str =
    "# managed by Chimera Client while tun dns-hijack is active";

#[cfg(target_os = "linux")]
async fn maybe_take_over_linux_stub_resolver(
    listen: &DNSListenAddr,
    backup: &Arc<Mutex<Option<String>>>,
    enabled: bool,
) {
    if !enabled {
        return;
    }

    let Some(addr) = listen.udp else {
        return;
    };

    if !addr.ip().is_loopback() || addr.port() != 53 {
        return;
    }

    let path = "/etc/resolv.conf";
    let current = match tokio::fs::read_to_string(path).await {
        Ok(current) => current,
        Err(err) => {
            error!("failed to read {}: {}", path, err);
            return;
        }
    };

    if current.contains(MANAGED_RESOLV_CONF_MARKER) {
        info!("linux stub resolver takeover is already active");
        return;
    }

    if !current.contains("127.0.0.53")
        && !current.contains("managed by man:systemd-resolved")
    {
        info!("linux stub resolver takeover skipped because /etc/resolv.conf is not using systemd-resolved stub");
        return;
    }

    {
        let mut guard = backup.lock().unwrap();
        if guard.is_none() {
            *guard = Some(current.clone());
        }
    }

    let replacement = format!(
        "{MANAGED_RESOLV_CONF_MARKER}\nnameserver {}\noptions edns0 trust-ad\nsearch .\n",
        addr.ip()
    );

    match tokio::fs::write(path, replacement).await {
        Ok(()) => {
            info!(
                "temporarily redirected linux stub resolver to local dns listener {}",
                addr
            );
        }
        Err(err) => {
            error!("failed to update {}: {}", path, err);
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn maybe_take_over_linux_stub_resolver(
    _: &DNSListenAddr,
    _: &Arc<Mutex<Option<String>>>,
    _: bool,
) {
}

#[cfg(target_os = "linux")]
async fn maybe_restore_linux_stub_resolver(backup: &Arc<Mutex<Option<String>>>) {
    let previous = {
        let mut guard = backup.lock().unwrap();
        guard.take()
    };

    let Some(previous) = previous else {
        return;
    };

    let path = "/etc/resolv.conf";
    match tokio::fs::write(path, previous).await {
        Ok(()) => {
            info!("restored original linux stub resolver configuration");
        }
        Err(err) => {
            error!("failed to restore {}: {}", path, err);
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn maybe_restore_linux_stub_resolver(_: &Arc<Mutex<Option<String>>>) {}

impl Runner for DnsRunner {
    fn run_async(&self) {
        if !self.enable {
            info!("dns listener is disabled, skipping");
            return;
        }

        let resolver = self.resolver.clone();
        let listen = self.listener.clone();
        let listen_for_server = listen.clone();
        let cwd = self.cwd.clone();
        let manage_system_resolver = self.manage_system_resolver;
        let managed_resolv_conf_backup = self.managed_resolv_conf_backup.clone();
        let cancellation_token = self.cancellation_token.clone();

        tokio::spawn(async move {
            let h = DnsMessageExchanger { resolver };
            let r = chimera_dns::get_dns_listener(listen_for_server, h, &cwd).await;
            if let Some(r) = r {
                maybe_take_over_linux_stub_resolver(
                    &listen,
                    &managed_resolv_conf_backup,
                    manage_system_resolver,
                )
                .await;
                tokio::select! {
                    res = r => {
                        match res {
                            Ok(()) => {},
                            Err(err) => {
                                error!("dns listener error: {}", err);
                            }
                        }
                        maybe_restore_linux_stub_resolver(&managed_resolv_conf_backup).await;
                    },
                    _ = cancellation_token.cancelled() => {
                        info!("dns listener is closed");
                        maybe_restore_linux_stub_resolver(&managed_resolv_conf_backup).await;
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
