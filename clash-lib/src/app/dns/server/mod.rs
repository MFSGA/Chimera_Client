use futures::FutureExt;
use hickory_proto::op::Message;
#[cfg(target_os = "linux")]
use network_interface::NetworkInterfaceConfig;

use chimera_dns::DNSListenAddr;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
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
    managed_resolved_link: Arc<Mutex<Option<String>>>,

    cancellation_token: tokio_util::sync::CancellationToken,
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
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
            managed_resolved_link: Arc::new(Mutex::new(None)),
            cancellation_token: cancellation_token.unwrap_or_default(),
            task: std::sync::Mutex::new(None),
        }
    }
}

#[cfg(target_os = "linux")]
const MANAGED_RESOLV_CONF_MARKER: &str =
    "# managed by Chimera Client while tun dns-hijack is active";

#[cfg(target_os = "linux")]
const DNS_BIND_TARGET_READY_MAX_ATTEMPTS: u32 = 100;

#[cfg(target_os = "linux")]
const DNS_BIND_TARGET_READY_POLL_INTERVAL_MS: u64 = 50;

#[cfg(target_os = "linux")]
fn linux_listener_target_ips(listen: &DNSListenAddr) -> Vec<IpAddr> {
    let mut targets = Vec::new();

    for ip in listen
        .udp
        .iter()
        .map(|addr| addr.ip())
        .chain(listen.tcp.iter().map(|addr| addr.ip()))
        .chain(listen.doh.iter().map(|cfg| cfg.addr.ip()))
        .chain(listen.dot.iter().map(|cfg| cfg.addr.ip()))
        .chain(listen.doh3.iter().map(|cfg| cfg.addr.ip()))
    {
        if !targets.contains(&ip) {
            targets.push(ip);
        }
    }

    targets
}

#[cfg(target_os = "linux")]
fn find_interface_name_by_ip(ip: IpAddr) -> Result<Option<String>, std::io::Error> {
    let interfaces = network_interface::NetworkInterface::show()
        .map_err(|err| std::io::Error::other(err.to_string()))?;

    for iface in interfaces {
        for addr in iface.addr {
            match (ip, addr) {
                (IpAddr::V4(target), network_interface::Addr::V4(addr))
                    if addr.ip == target =>
                {
                    return Ok(Some(iface.name));
                }
                (IpAddr::V6(target), network_interface::Addr::V6(addr))
                    if addr.ip == target =>
                {
                    return Ok(Some(iface.name));
                }
                _ => {}
            }
        }
    }

    Ok(None)
}

#[cfg(target_os = "linux")]
async fn wait_for_linux_dns_listener_targets(
    listen: &DNSListenAddr,
    cancellation_token: &tokio_util::sync::CancellationToken,
) -> bool {
    let targets = linux_listener_target_ips(listen)
        .into_iter()
        .filter(|ip| !ip.is_loopback())
        .collect::<Vec<_>>();

    if targets.is_empty() {
        return true;
    }

    for _ in 0..DNS_BIND_TARGET_READY_MAX_ATTEMPTS {
        let mut ready = true;
        for target in &targets {
            match find_interface_name_by_ip(*target) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    ready = false;
                    break;
                }
                Err(err) => {
                    error!(
                        "failed to inspect interfaces while waiting for dns bind target {}: {}",
                        target, err
                    );
                    ready = false;
                    break;
                }
            }
        }

        if ready {
            return true;
        }

        tokio::select! {
            _ = cancellation_token.cancelled() => return false,
            _ = tokio::time::sleep(Duration::from_millis(
                DNS_BIND_TARGET_READY_POLL_INTERVAL_MS,
            )) => {}
        }
    }

    error!(
        "dns listener bind targets never became ready: {:?}",
        targets
    );
    false
}

#[cfg(not(target_os = "linux"))]
async fn wait_for_linux_dns_listener_targets(
    _: &DNSListenAddr,
    _: &tokio_util::sync::CancellationToken,
) -> bool {
    true
}

#[cfg(target_os = "linux")]
fn run_resolvectl(args: &[&str]) -> Result<(), std::io::Error> {
    let output = std::process::Command::new("resolvectl").args(args).output()?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let details = if stderr.is_empty() {
        stdout
    } else {
        stderr
    };

    Err(std::io::Error::other(format!(
        "resolvectl {} failed: {}",
        args.join(" "),
        details
    )))
}

#[cfg(target_os = "linux")]
async fn maybe_take_over_linux_resolved_link(
    listen: &DNSListenAddr,
    managed_link: &Arc<Mutex<Option<String>>>,
    enabled: bool,
) -> bool {
    if !enabled {
        return false;
    }

    let Some(addr) = listen.udp else {
        return false;
    };

    if addr.port() != 53 || addr.ip().is_loopback() {
        return false;
    }

    let link_name = match find_interface_name_by_ip(addr.ip()) {
        Ok(Some(link_name)) => link_name,
        Ok(None) => {
            info!(
                "linux per-link dns takeover skipped because no interface owns {}",
                addr.ip()
            );
            return false;
        }
        Err(err) => {
            error!(
                "failed to resolve interface for linux per-link dns takeover: {}",
                err
            );
            return false;
        }
    };

    let dns_ip = addr.ip().to_string();
    let commands = [
        vec!["dns", link_name.as_str(), dns_ip.as_str()],
        vec!["domain", link_name.as_str(), "~."],
        vec!["default-route", link_name.as_str(), "yes"],
        vec!["llmnr", link_name.as_str(), "no"],
        vec!["mdns", link_name.as_str(), "no"],
        vec!["dnssec", link_name.as_str(), "no"],
        vec!["dnsovertls", link_name.as_str(), "no"],
    ];

    for command in &commands {
        if let Err(err) = run_resolvectl(command) {
            error!(
                "failed to configure systemd-resolved per-link dns on {}: {}",
                link_name, err
            );
            let _ = run_resolvectl(&["revert", link_name.as_str()]);
            return false;
        }
    }

    {
        let mut guard = managed_link.lock().unwrap();
        *guard = Some(link_name.clone());
    }

    info!(
        "configured systemd-resolved per-link dns on {} via {}",
        link_name, addr
    );
    true
}

#[cfg(not(target_os = "linux"))]
async fn maybe_take_over_linux_resolved_link(
    _: &DNSListenAddr,
    _: &Arc<Mutex<Option<String>>>,
    _: bool,
) -> bool {
    false
}

#[cfg(target_os = "linux")]
async fn maybe_take_over_linux_stub_resolver(
    listen: &DNSListenAddr,
    backup: &Arc<Mutex<Option<String>>>,
    managed_link: &Arc<Mutex<Option<String>>>,
    enabled: bool,
) {
    if !enabled {
        return;
    }

    if maybe_take_over_linux_resolved_link(listen, managed_link, enabled).await {
        return;
    }

    let Some(addr) = listen.udp else {
        return;
    };

    if addr.port() != 53 {
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
    _: &Arc<Mutex<Option<String>>>,
    _: bool,
) {
}

#[cfg(target_os = "linux")]
async fn maybe_restore_linux_stub_resolver(
    backup: &Arc<Mutex<Option<String>>>,
    managed_link: &Arc<Mutex<Option<String>>>,
) {
    if let Some(link_name) = {
        let mut guard = managed_link.lock().unwrap();
        guard.take()
    } {
        match run_resolvectl(&["revert", link_name.as_str()]) {
            Ok(()) => {
                info!(
                    "restored original systemd-resolved per-link dns configuration for {}",
                    link_name
                );
            }
            Err(err) => {
                error!(
                    "failed to revert systemd-resolved per-link dns for {}: {}",
                    link_name, err
                );
            }
        }
    }

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
async fn maybe_restore_linux_stub_resolver(
    _: &Arc<Mutex<Option<String>>>,
    _: &Arc<Mutex<Option<String>>>,
) {
}

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
        let managed_resolved_link = self.managed_resolved_link.clone();
        let cancellation_token = self.cancellation_token.clone();

        let handle = tokio::spawn(async move {
            if !wait_for_linux_dns_listener_targets(&listen, &cancellation_token).await
            {
                return;
            }

            let h = DnsMessageExchanger { resolver };
            let r = chimera_dns::get_dns_listener(listen_for_server, h, &cwd).await;
            if let Some(r) = r {
                maybe_take_over_linux_stub_resolver(
                    &listen,
                    &managed_resolv_conf_backup,
                    &managed_resolved_link,
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
                        maybe_restore_linux_stub_resolver(
                            &managed_resolv_conf_backup,
                            &managed_resolved_link,
                        )
                        .await;
                    },
                    _ = cancellation_token.cancelled() => {
                        info!("dns listener is closed");
                        maybe_restore_linux_stub_resolver(
                            &managed_resolv_conf_backup,
                            &managed_resolved_link,
                        )
                        .await;
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
