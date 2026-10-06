//! Network-change observation shared by automatic and requested recovery.

#[cfg(target_os = "macos")]
use std::collections::HashMap;
use std::{io, net::IpAddr, time::Duration};

use serde::Serialize;
use tokio::time::Instant;

use super::flow::{AddressFamily, InterfaceId, InterfaceKind};

pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const RECOVERY_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const AUTOMATIC_SUPPORTED: bool = cfg!(target_os = "macos");

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkResetResponse {
    pub dns_transports_reset: u32,
    pub connection_pools_reset: u32,
}

/// Each independent component gets an attempt even if another one fails.
pub(crate) async fn reset_resources_report<D, P, DE, PE>(
    dns: D,
    pools: P,
) -> super::runtime_state::RecoveryReport
where
    D: std::future::Future<Output = Result<u32, DE>>,
    P: std::future::Future<Output = Result<u32, PE>>,
    DE: std::fmt::Display,
    PE: std::fmt::Display,
{
    use super::runtime_state::{ComponentResult, RecoveryReport};
    async fn attempt<F, E>(future: F) -> ComponentResult
    where
        F: std::future::Future<Output = Result<u32, E>>,
        E: std::fmt::Display,
    {
        match tokio::time::timeout(RECOVERY_TIMEOUT / 2, future).await {
            Ok(Ok(count)) => ComponentResult::refreshed(count),
            Ok(Err(error)) => ComponentResult::failed(error),
            Err(_) => ComponentResult::timed_out(),
        }
    }
    let dns = attempt(dns).await;
    let pools = attempt(pools).await;
    RecoveryReport {
        interface: ComponentResult::skipped(),
        dns,
        pools,
        observation_error: None,
        offline: false,
    }
}
#[cfg(test)]
async fn reset_resources<D, P, DE, PE>(
    dns: D,
    pools: P,
) -> Result<NetworkResetResponse, String>
where
    D: std::future::Future<Output = Result<u32, DE>>,
    P: std::future::Future<Output = Result<u32, PE>>,
    DE: std::fmt::Display,
    PE: std::fmt::Display,
{
    reset_resources_report(dns, pools)
        .await
        .into_result()
        .map_err(|error| error.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetworkPath {
    pub interface: String,
    pub index: u32,
    pub gateway: String,
    pub addresses: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum DefaultRouteEvidence {
    PrimaryDefaultRoute,
    OtherInterface,
    NoPrimaryRouteObserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum BindingStatus {
    Verified,
    Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "mode", content = "interfaceName")]
pub(crate) enum TunCandidateExclusion {
    #[default]
    Disabled,
    Named(String),
    /// A TUN is enabled but its interface name is unavailable (for example,
    /// an externally-created file-descriptor device). Conservatively exclude
    /// TUN-like names rather than risk selecting the client's own tunnel.
    Unidentified,
}

impl TunCandidateExclusion {
    #[cfg(target_os = "macos")]
    fn excludes(&self, interface_name: &str) -> bool {
        match self {
            Self::Disabled => false,
            Self::Named(name) => name == interface_name,
            Self::Unidentified => {
                interface_name.starts_with("utun")
                    || interface_name.starts_with("tun")
            }
        }
    }
}

/// Read-only observation of one local source-address/interface pair.
/// `Verified` proves local socket binding only; it is not a reachability probe.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PathCandidateObservation {
    pub interface: InterfaceId,
    pub interface_kind: InterfaceKind,
    pub family: AddressFamily,
    pub source_address: IpAddr,
    pub scope_id: Option<u32>,
    pub gateway: Option<IpAddr>,
    pub default_route: DefaultRouteEvidence,
    pub binding: BindingStatus,
    pub binding_error: Option<String>,
}

impl PartialEq for PathCandidateObservation {
    fn eq(&self, other: &Self) -> bool {
        // Link classification and local bind probes are diagnostic metadata;
        // transient changes there must not advance networkVersion or trigger
        // transport recovery. Address, interface, family, and route evidence
        // define the observed path identity.
        self.interface == other.interface
            && self.family == other.family
            && self.source_address == other.source_address
            && self.scope_id == other.scope_id
            && self.gateway == other.gateway
            && self.default_route == other.default_route
    }
}

impl Eq for PathCandidateObservation {}

/// The per-address capability list is bounded before it reaches status/API.
#[cfg(target_os = "macos")]
const MAX_PATH_CANDIDATES: usize = 128;

#[derive(Clone, Debug, Default)]
pub(crate) struct NetworkSnapshot {
    pub ipv4: Option<NetworkPath>,
    pub ipv6: Option<NetworkPath>,
    pub dns: String,
    pub interfaces: Vec<String>,
    pub path_candidates: Vec<PathCandidateObservation>,
    pub path_candidates_truncated: usize,
    pub tun_candidate_exclusion: TunCandidateExclusion,
}

impl PartialEq for NetworkSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.ipv4 == other.ipv4
            && self.ipv6 == other.ipv6
            && self.dns == other.dns
            && self.interfaces == other.interfaces
            && self.path_candidates == other.path_candidates
            && self.path_candidates_truncated == other.path_candidates_truncated
            && self.tun_candidate_exclusion == other.tun_candidate_exclusion
    }
}

impl Eq for NetworkSnapshot {}

#[derive(Clone, Debug)]
pub(crate) struct NetworkSample {
    pub sequence: u64,
    pub sampled_at: Instant,
    pub result: Result<NetworkSnapshot, String>,
}

/// Poll independently from resource recovery and retain only the newest sample.
pub(crate) async fn run_sampler<F, Fut>(
    cancellation: tokio_util::sync::CancellationToken,
    samples: tokio::sync::watch::Sender<Option<NetworkSample>>,
    mut snapshot: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = io::Result<NetworkSnapshot>>,
{
    let mut interval = tokio::time::interval(POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sequence = 0_u64;
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            _ = interval.tick() => {
                let result = tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    result = snapshot() => result.map_err(|error| error.to_string()),
                };
                sequence = sequence.saturating_add(1);
                samples.send_replace(Some(NetworkSample {
                    sequence,
                    sampled_at: Instant::now(),
                    result,
                }));
            }
        }
    }
}

/// Consume the latest sample once and discard any sample taken before an operation.
pub(crate) fn take_sample_after(
    samples: &mut tokio::sync::watch::Receiver<Option<NetworkSample>>,
    started_at: Instant,
) -> Option<NetworkSample> {
    if samples.has_changed().ok() != Some(true) {
        return None;
    }
    samples
        .borrow_and_update()
        .clone()
        .filter(|sample| sample.sampled_at > started_at)
}

impl NetworkSnapshot {
    pub fn has_path(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }

    pub fn path_changed(&self, previous: &Self) -> bool {
        self.ipv4 != previous.ipv4
            || self.ipv6 != previous.ipv6
            || self.interfaces != previous.interfaces
            || self.path_candidates != previous.path_candidates
    }
}

pub(crate) use super::runtime_state::RuntimeStatus as NetworkStatus;

/// Retry failures without confusing an observed snapshot with applied state.
pub(crate) struct NetworkObserver {
    observed: Option<NetworkSnapshot>,
    applied: Option<NetworkSnapshot>,
    next_attempt: Instant,
    failures: u32,
    retry_required: bool,
    retry_path_changed: bool,
}

impl Default for NetworkObserver {
    fn default() -> Self {
        Self {
            observed: None,
            applied: None,
            next_attempt: Instant::now(),
            failures: 0,
            retry_required: false,
            retry_path_changed: false,
        }
    }
}

impl NetworkObserver {
    pub fn is_applied(&self, snapshot: &NetworkSnapshot) -> bool {
        self.applied.as_ref() == Some(snapshot)
    }

    pub fn observe(
        &mut self,
        snapshot: &NetworkSnapshot,
        now: Instant,
    ) -> Option<bool> {
        if self.observed.as_ref() != Some(snapshot) {
            self.observed = Some(snapshot.clone());
            self.next_attempt = now;
            self.failures = 0;
        }
        if (self.applied.as_ref() == Some(snapshot) && !self.retry_required)
            || now < self.next_attempt
        {
            return None;
        }
        Some(
            self.retry_path_changed
                || self
                    .applied
                    .as_ref()
                    .is_none_or(|previous| snapshot.path_changed(previous)),
        )
    }

    pub fn applied(&mut self, snapshot: NetworkSnapshot) {
        self.observed = Some(snapshot.clone());
        self.applied = Some(snapshot);
        self.failures = 0;
        self.retry_required = false;
        self.retry_path_changed = false;
    }

    pub fn retry(&mut self, path_changed: bool, now: Instant) -> Duration {
        self.retry_path_changed |= path_changed;
        self.failed(now);
        self.next_attempt.saturating_duration_since(now)
    }

    pub fn failed(&mut self, now: Instant) -> u32 {
        self.retry_required = true;
        self.failures = self.failures.saturating_add(1);
        let seconds = 1_u64 << self.failures.min(5);
        self.next_attempt = now + Duration::from_secs(seconds);
        self.failures
    }
}

#[cfg(target_os = "macos")]
fn scutil_field(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(" : ")?;
        (key == name).then(|| value.trim().to_owned())
    })
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PrimaryRoute {
    interface_index: u32,
    gateway: Option<IpAddr>,
}

#[cfg(target_os = "macos")]
fn parse_primary_route(
    output: &str,
    interfaces: &[network_interface::NetworkInterface],
) -> Option<PrimaryRoute> {
    let name = scutil_field(output, "PrimaryInterface")?;
    let interface = interfaces.iter().find(|interface| interface.name == name)?;
    let gateway = scutil_field(output, "Router").and_then(|value| {
        value
            .split('%')
            .next()
            .and_then(|address| address.parse().ok())
    });
    Some(PrimaryRoute {
        interface_index: interface.index,
        gateway,
    })
}

#[cfg(target_os = "macos")]
fn parse_path(
    output: &str,
    interfaces: &[network_interface::NetworkInterface],
    ipv6: bool,
) -> Option<NetworkPath> {
    let interface = scutil_field(output, "PrimaryInterface")?;
    if interface.starts_with("utun")
        || interface.starts_with("tun")
        || interface == "lo0"
    {
        return None;
    }
    let iface = interfaces.iter().find(|iface| iface.name == interface)?;
    let mut addresses = iface
        .addr
        .iter()
        .filter(|addr| matches!(addr, network_interface::Addr::V6(_)) == ipv6)
        .map(|addr| format!("{addr:?}"))
        .collect::<Vec<_>>();
    addresses.sort();
    if addresses.is_empty() {
        return None;
    }
    Some(NetworkPath {
        interface,
        index: iface.index,
        gateway: scutil_field(output, "Router").unwrap_or_default(),
        addresses,
    })
}

#[cfg(target_os = "macos")]
fn classify_hardware_port(name: &str) -> InterfaceKind {
    let name = name.to_ascii_lowercase();
    if name.contains("wi-fi") || name == "wifi" {
        InterfaceKind::Wifi
    } else if name.contains("ethernet") {
        InterfaceKind::Ethernet
    } else if name.contains("thunderbolt bridge") {
        InterfaceKind::Virtual
    } else if name.contains("bluetooth") {
        InterfaceKind::Other
    } else {
        InterfaceKind::Unknown
    }
}

#[cfg(target_os = "macos")]
fn parse_hardware_port_kinds(output: &str) -> HashMap<String, InterfaceKind> {
    let mut pending_port = None;
    let mut kinds = HashMap::new();
    for line in output.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("Hardware Port:") {
            pending_port = Some(name.trim().to_owned());
        } else if let Some(device) = line.strip_prefix("Device:")
            && let Some(name) = pending_port.take()
        {
            kinds.insert(device.trim().to_owned(), classify_hardware_port(&name));
        }
    }
    kinds
}

#[cfg(target_os = "macos")]
fn collect_path_candidates<F>(
    interfaces: &[network_interface::NetworkInterface],
    ipv4_route: Option<&PrimaryRoute>,
    ipv6_route: Option<&PrimaryRoute>,
    hardware_kinds: &HashMap<String, InterfaceKind>,
    tun_exclusion: &TunCandidateExclusion,
    mut bind_probe: F,
) -> Vec<PathCandidateObservation>
where
    F: FnMut(&str, u32, IpAddr) -> Result<(), String>,
{
    let mut candidates = Vec::new();
    for interface in interfaces.iter().filter(|interface| {
        !interface.internal
            && !tun_exclusion.excludes(&interface.name)
            && interface.index != 0
    }) {
        for address in &interface.addr {
            let ip = address.ip();
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            let family = AddressFamily::from(ip);
            let primary_route = match family {
                AddressFamily::Ipv4 => ipv4_route,
                AddressFamily::Ipv6 => ipv6_route,
            };
            let default_route = match primary_route {
                Some(route) if route.interface_index == interface.index => {
                    DefaultRouteEvidence::PrimaryDefaultRoute
                }
                Some(_) => DefaultRouteEvidence::OtherInterface,
                None => DefaultRouteEvidence::NoPrimaryRouteObserved,
            };
            let gateway = primary_route
                .filter(|route| route.interface_index == interface.index)
                .and_then(|route| route.gateway);
            let (binding, binding_error) =
                match bind_probe(&interface.name, interface.index, ip) {
                    Ok(()) => (BindingStatus::Verified, None),
                    Err(error) => (BindingStatus::Failed, Some(error)),
                };
            let scope_id = match ip {
                IpAddr::V6(address) if address.is_unicast_link_local() => {
                    Some(interface.index)
                }
                _ => None,
            };
            candidates.push(PathCandidateObservation {
                interface: InterfaceId {
                    name: interface.name.clone(),
                    index: interface.index,
                },
                interface_kind: hardware_kinds
                    .get(&interface.name)
                    .copied()
                    .unwrap_or(InterfaceKind::Unknown),
                family,
                source_address: ip,
                scope_id,
                gateway,
                default_route,
                binding,
                binding_error,
            });
        }
    }
    candidates.sort_by_key(|candidate| {
        (
            candidate.interface.name.clone(),
            candidate.interface.index,
            candidate.family as u8,
            candidate.source_address.to_string(),
        )
    });
    candidates
}

#[cfg(target_os = "macos")]
async fn scutil_key(key: &str) -> io::Result<String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("scutil stdin unavailable"))?;
    stdin
        .write_all(format!("show {key}\nquit\n").as_bytes())
        .await?;
    drop(stdin);
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(io::Error::other(
            "failed to read macOS network configuration",
        ));
    }
    String::from_utf8(output.stdout).map_err(io::Error::other)
}

#[cfg(target_os = "macos")]
async fn macos_hardware_port_kinds() -> io::Result<HashMap<String, InterfaceKind>> {
    tokio::time::timeout(Duration::from_millis(500), async {
        let output = tokio::process::Command::new("/usr/sbin/networksetup")
            .arg("-listallhardwareports")
            .kill_on_drop(true)
            .output()
            .await?;
        if !output.status.success() {
            return Err(io::Error::other(
                "failed to read macOS hardware port metadata",
            ));
        }
        let output = String::from_utf8(output.stdout).map_err(io::Error::other)?;
        Ok(parse_hardware_port_kinds(&output))
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "macOS hardware port metadata timed out",
        )
    })?
}

/// Read system configuration, excluding TUN's own synthetic default routes.
#[cfg(target_os = "macos")]
pub(crate) async fn snapshot() -> io::Result<NetworkSnapshot> {
    snapshot_with_tun(TunCandidateExclusion::Disabled).await
}

/// Read system configuration and apply the stated TUN-candidate exclusion.
#[cfg(target_os = "macos")]
pub(crate) async fn snapshot_with_tun(
    tun_candidate_exclusion: TunCandidateExclusion,
) -> io::Result<NetworkSnapshot> {
    use network_interface::NetworkInterfaceConfig;

    tokio::time::timeout(Duration::from_secs(2), async {
        let (v4_result, v6_result, dns_result, hardware_result) = tokio::join!(
            scutil_key("State:/Network/Global/IPv4"),
            scutil_key("State:/Network/Global/IPv6"),
            scutil_key("State:/Network/Global/DNS"),
            macos_hardware_port_kinds(),
        );
        let (v4, v6, dns) = (v4_result?, v6_result?, dns_result?);
        let interfaces =
            network_interface::NetworkInterface::show().map_err(io::Error::other)?;
        let hardware_kinds = match hardware_result {
            Ok(kinds) => kinds,
            Err(error) => {
                tracing::debug!(%error, "interface kinds unavailable; retaining unknown classifications");
                HashMap::new()
            }
        };
        let ipv4_route = parse_primary_route(&v4, &interfaces);
        let ipv6_route = parse_primary_route(&v6, &interfaces);
        let mut path_candidates = collect_path_candidates(
            &interfaces,
            ipv4_route.as_ref(),
            ipv6_route.as_ref(),
            &hardware_kinds,
            &tun_candidate_exclusion,
            |name, index, address| {
                crate::proxy::utils::socket_helpers::probe_outbound_path_binding(
                    name, index, address,
                )
                .map_err(|error| error.to_string())
            },
        );
        let path_candidates_truncated =
            path_candidates.len().saturating_sub(MAX_PATH_CANDIDATES);
        path_candidates.truncate(MAX_PATH_CANDIDATES);
        let mut physical_interfaces = interfaces
            .iter()
            .filter(|iface| {
                !iface.internal
                    && !iface.name.starts_with("utun")
                    && !iface.name.starts_with("tun")
            })
            .map(|iface| {
                let mut addresses = iface
                    .addr
                    .iter()
                    .map(|addr| format!("{addr:?}"))
                    .collect::<Vec<_>>();
                addresses.sort();
                format!("{}:{}:{addresses:?}", iface.name, iface.index)
            })
            .collect::<Vec<_>>();
        physical_interfaces.sort();
        Ok(NetworkSnapshot {
            ipv4: parse_path(&v4, &interfaces, false),
            ipv6: parse_path(&v6, &interfaces, true),
            dns,
            interfaces: physical_interfaces,
            path_candidates,
            path_candidates_truncated,
            tun_candidate_exclusion,
        })
    })
    .await
    .map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "network snapshot timed out")
    })?
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn snapshot() -> io::Result<NetworkSnapshot> {
    snapshot_with_tun(TunCandidateExclusion::Disabled).await
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn snapshot_with_tun(
    _tun_candidate_exclusion: TunCandidateExclusion,
) -> io::Result<NetworkSnapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "automatic network observation is currently supported on macOS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sampler_publishes_latest_sample_and_stops_on_cancellation() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let cancellation = tokio_util::sync::CancellationToken::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let sampler = {
            let calls = calls.clone();
            let cancellation = cancellation.clone();
            tokio::spawn(run_sampler(cancellation, tx, move || {
                calls.fetch_add(1, Ordering::Relaxed);
                async { Ok(NetworkSnapshot::default()) }
            }))
        };
        tokio::time::timeout(Duration::from_millis(500), rx.changed())
            .await
            .expect("sampler did not publish its first snapshot")
            .unwrap();
        let first = rx.borrow_and_update().clone().unwrap();
        assert_eq!(first.sequence, 1);
        assert!(first.result.is_ok());
        cancellation.cancel();
        tokio::time::timeout(Duration::from_millis(500), sampler)
            .await
            .expect("sampler did not stop after cancellation")
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn latest_sample_replaces_intermediate_samples_and_rejects_old_time() {
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let started = Instant::now();
        tx.send_replace(Some(NetworkSample {
            sequence: 1,
            sampled_at: started - Duration::from_millis(1),
            result: Ok(NetworkSnapshot::default()),
        }));
        tx.send_replace(Some(NetworkSample {
            sequence: 3,
            sampled_at: started + Duration::from_millis(1),
            result: Ok(NetworkSnapshot::default()),
        }));
        let sample = take_sample_after(&mut rx, started).unwrap();
        assert_eq!(sample.sequence, 3);
        assert!(take_sample_after(&mut rx, started).is_none());
    }

    fn online(name: &str, address: &str) -> NetworkSnapshot {
        NetworkSnapshot {
            ipv4: Some(NetworkPath {
                interface: name.into(),
                index: 1,
                gateway: "192.0.2.1".into(),
                addresses: vec![address.into()],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn same_card_address_change_is_a_path_change() {
        let first = online("en0", "192.0.2.2");
        let next = online("en0", "192.0.2.3");
        let mut observer = NetworkObserver::default();
        observer.applied(first);
        assert_eq!(observer.observe(&next, Instant::now()), Some(true));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_primary_route_wins_over_interface_name_order() {
        use network_interface::{Addr, NetworkInterface, V4IfAddr};
        let iface = |name: &str, index| NetworkInterface {
            name: name.into(),
            index,
            internal: false,
            mac_addr: None,
            addr: vec![Addr::V4(V4IfAddr {
                ip: "192.0.2.2".parse().unwrap(),
                broadcast: None,
                netmask: None,
            })],
        };
        let interfaces = vec![iface("en0", 1), iface("en1", 2), iface("utun4", 3)];
        let path = parse_path(
            "<dictionary> {\n PrimaryInterface : en1\n Router : 192.0.2.1\n}",
            &interfaces,
            false,
        )
        .unwrap();
        assert_eq!(path.interface, "en1");
        assert_eq!(path.index, 2);
        assert!(
            parse_path("PrimaryInterface : utun4", &interfaces, false).is_none()
        );
        assert!(parse_path("No such key", &interfaces, false).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn hardware_port_names_classify_known_links_and_leave_unknowns_unknown() {
        let kinds = parse_hardware_port_kinds(
            "Hardware Port: Wi-Fi\nDevice: en0\n\n\
             Hardware Port: USB 10/100/1000 LAN (Ethernet)\nDevice: en7\n\n\
             Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n\n\
             Hardware Port: Example Adapter\nDevice: en9\n",
        );

        assert_eq!(kinds.get("en0"), Some(&InterfaceKind::Wifi));
        assert_eq!(kinds.get("en7"), Some(&InterfaceKind::Ethernet));
        assert_eq!(kinds.get("bridge0"), Some(&InterfaceKind::Virtual));
        assert_eq!(kinds.get("en9"), Some(&InterfaceKind::Unknown));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn path_candidates_separate_family_route_and_bind_evidence() {
        use network_interface::{Addr, NetworkInterface, V4IfAddr, V6IfAddr};

        let interface = |name: &str, index, addr| NetworkInterface {
            name: name.to_owned(),
            index,
            internal: false,
            mac_addr: None,
            addr,
        };
        let interfaces = vec![
            interface(
                "en0",
                5,
                vec![
                    Addr::V4(V4IfAddr {
                        ip: "192.0.2.2".parse().unwrap(),
                        netmask: None,
                        broadcast: None,
                    }),
                    Addr::V6(V6IfAddr {
                        ip: "2001:db8::2".parse().unwrap(),
                        netmask: None,
                        broadcast: None,
                    }),
                    Addr::V6(V6IfAddr {
                        ip: "fe80::2".parse().unwrap(),
                        netmask: None,
                        broadcast: None,
                    }),
                ],
            ),
            interface(
                "en1",
                6,
                vec![
                    Addr::V4(V4IfAddr {
                        ip: "198.51.100.2".parse().unwrap(),
                        netmask: None,
                        broadcast: None,
                    }),
                    Addr::V6(V6IfAddr {
                        ip: "2001:db8::3".parse().unwrap(),
                        netmask: None,
                        broadcast: None,
                    }),
                ],
            ),
            interface(
                "utun4",
                7,
                vec![Addr::V4(V4IfAddr {
                    ip: "203.0.113.2".parse().unwrap(),
                    netmask: None,
                    broadcast: None,
                })],
            ),
        ];
        let kinds = HashMap::from([
            ("en0".to_string(), InterfaceKind::Wifi),
            ("en1".to_string(), InterfaceKind::Ethernet),
        ]);
        let ipv4_route = PrimaryRoute {
            interface_index: 5,
            gateway: Some("192.0.2.1".parse().unwrap()),
        };
        let ipv6_route = PrimaryRoute {
            interface_index: 6,
            gateway: Some("2001:db8::1".parse().unwrap()),
        };
        let candidates = collect_path_candidates(
            &interfaces,
            Some(&ipv4_route),
            Some(&ipv6_route),
            &kinds,
            &TunCandidateExclusion::Named("utun4".to_owned()),
            |name, _, address| {
                if name == "en1" && address.is_ipv4() {
                    Err("source address bind rejected".to_owned())
                } else {
                    Ok(())
                }
            },
        );

        assert_eq!(candidates.len(), 5);
        assert!(candidates.iter().all(|item| item.interface.name != "utun4"));
        let wifi_v4 = candidates
            .iter()
            .find(|item| {
                item.interface.name == "en0" && item.family == AddressFamily::Ipv4
            })
            .unwrap();
        assert_eq!(wifi_v4.interface_kind, InterfaceKind::Wifi);
        assert_eq!(
            wifi_v4.default_route,
            DefaultRouteEvidence::PrimaryDefaultRoute
        );
        assert_eq!(wifi_v4.gateway, Some("192.0.2.1".parse().unwrap()));
        let ethernet_v6 = candidates
            .iter()
            .find(|item| {
                item.interface.name == "en1"
                    && item.source_address
                        == "2001:db8::3".parse::<IpAddr>().unwrap()
            })
            .unwrap();
        assert_eq!(
            ethernet_v6.default_route,
            DefaultRouteEvidence::PrimaryDefaultRoute
        );
        let link_local_v6 = candidates
            .iter()
            .find(|item| item.source_address == "fe80::2".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!(link_local_v6.scope_id, Some(5));
        let rejected_v4 = candidates
            .iter()
            .find(|item| {
                item.interface.name == "en1" && item.family == AddressFamily::Ipv4
            })
            .unwrap();
        assert_eq!(rejected_v4.binding, BindingStatus::Failed);
        assert_eq!(
            rejected_v4.default_route,
            DefaultRouteEvidence::OtherInterface
        );

        let unidentified_tun = collect_path_candidates(
            &interfaces,
            Some(&ipv4_route),
            Some(&ipv6_route),
            &kinds,
            &TunCandidateExclusion::Unidentified,
            |_, _, _| Ok(()),
        );
        assert!(
            unidentified_tun
                .iter()
                .all(|item| !item.interface.name.starts_with("utun"))
        );

        let vpn_candidates = collect_path_candidates(
            &interfaces,
            Some(&ipv4_route),
            Some(&ipv6_route),
            &kinds,
            &TunCandidateExclusion::Disabled,
            |_, _, _| Ok(()),
        );
        let vpn = vpn_candidates
            .iter()
            .find(|item| item.interface.name == "utun4")
            .unwrap();
        assert_eq!(vpn.interface_kind, InterfaceKind::Unknown);
    }

    #[test]
    fn status_exposes_bounded_path_candidates_without_dns_configuration() {
        let snapshot = NetworkSnapshot {
            dns: "private resolver data".to_owned(),
            path_candidates: vec![PathCandidateObservation {
                interface: InterfaceId {
                    name: "en0".to_owned(),
                    index: 5,
                },
                interface_kind: InterfaceKind::Unknown,
                family: AddressFamily::Ipv4,
                source_address: "192.0.2.2".parse().unwrap(),
                scope_id: None,
                gateway: None,
                default_route: DefaultRouteEvidence::NoPrimaryRouteObserved,
                binding: BindingStatus::Verified,
                binding_error: None,
            }],
            ..Default::default()
        };
        let mut status = NetworkStatus::default();
        status.observed(&snapshot);

        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json["pathCandidates"].as_array().unwrap().len(), 1);
        assert_eq!(json["pathCandidates"][0]["interfaceKind"], "unknown");
        assert_eq!(json["tunCandidateExclusion"]["mode"], "disabled");
        assert!(!json.to_string().contains("private resolver data"));
    }

    #[test]
    fn bind_probe_updates_diagnostics_without_changing_network_generation() {
        let candidate = PathCandidateObservation {
            interface: InterfaceId {
                name: "en0".to_owned(),
                index: 5,
            },
            interface_kind: InterfaceKind::Wifi,
            family: AddressFamily::Ipv4,
            source_address: "192.0.2.2".parse().unwrap(),
            scope_id: None,
            gateway: Some("192.0.2.1".parse().unwrap()),
            default_route: DefaultRouteEvidence::PrimaryDefaultRoute,
            binding: BindingStatus::Verified,
            binding_error: None,
        };
        let first = NetworkSnapshot {
            path_candidates: vec![candidate],
            ..Default::default()
        };
        let mut latest = first.clone();
        latest.path_candidates[0].binding = BindingStatus::Failed;
        latest.path_candidates[0].binding_error =
            Some("permission denied".to_owned());
        latest.path_candidates[0].interface_kind = InterfaceKind::Unknown;

        assert_eq!(first, latest);
        assert!(!latest.path_changed(&first));
        let mut status = NetworkStatus::default();
        status.observed(&first);
        let before = serde_json::to_value(&status).unwrap()["networkVersion"]
            .as_u64()
            .unwrap();
        status.observed(&latest);
        let after = serde_json::to_value(&status).unwrap();

        assert_eq!(after["networkVersion"], before);
        assert_eq!(after["pathCandidates"][0]["binding"], "failed");
        assert_eq!(
            after["pathCandidates"][0]["bindingError"],
            "permission denied"
        );
    }

    #[test]
    fn interface_recreation_changes_observed_path_identity() {
        let path = PathCandidateObservation {
            interface: InterfaceId {
                name: "en0".to_owned(),
                index: 5,
            },
            interface_kind: InterfaceKind::Wifi,
            family: AddressFamily::Ipv4,
            source_address: "192.0.2.2".parse().unwrap(),
            scope_id: None,
            gateway: Some("192.0.2.1".parse().unwrap()),
            default_route: DefaultRouteEvidence::PrimaryDefaultRoute,
            binding: BindingStatus::Verified,
            binding_error: None,
        };
        let first = NetworkSnapshot {
            path_candidates: vec![path],
            ..Default::default()
        };
        let mut recreated = first.clone();
        recreated.path_candidates[0].interface.index = 9;

        assert!(recreated.path_changed(&first));
        assert_ne!(recreated, first);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "reads local interfaces and binds temporary UDP sockets; sends no traffic"]
    async fn live_macos_snapshot_reports_local_bind_capabilities() {
        let snapshot = snapshot_with_tun(TunCandidateExclusion::Unidentified)
            .await
            .unwrap();
        assert!(snapshot.path_candidates.len() <= MAX_PATH_CANDIDATES);
        assert!(snapshot.path_candidates.iter().all(|candidate| {
            let family_matches = matches!(
                (candidate.family, candidate.source_address),
                (AddressFamily::Ipv4, IpAddr::V4(_))
                    | (AddressFamily::Ipv6, IpAddr::V6(_))
            );
            let scope_matches = candidate.scope_id.is_none_or(|scope| {
                candidate.source_address.is_ipv6()
                    && scope == candidate.interface.index
            });
            family_matches && scope_matches
        }));
    }

    #[test]
    fn pinned_non_primary_interface_change_triggers_recovery() {
        let first = online("en0", "192.0.2.2");
        let mut next = first.clone();
        next.interfaces = vec!["en7:9:198.51.100.3".into()];
        let mut observer = NetworkObserver::default();
        observer.applied(first);
        assert_eq!(observer.observe(&next, Instant::now()), Some(true));
    }

    #[test]
    fn dns_change_does_not_invalidate_data_sessions() {
        let first = online("en0", "192.0.2.2");
        let mut next = first.clone();
        next.dns = "new DNS".into();
        let mut observer = NetworkObserver::default();
        observer.applied(first);
        assert_eq!(observer.observe(&next, Instant::now()), Some(false));
    }

    #[test]
    fn failures_retry_and_new_network_bypasses_backoff() {
        let first = online("en0", "192.0.2.2");
        let next = online("en1", "198.51.100.2");
        let now = Instant::now();
        let mut observer = NetworkObserver::default();
        assert_eq!(observer.observe(&first, now), Some(true));
        observer.failed(now);
        assert_eq!(observer.observe(&first, now), None);
        assert_eq!(
            observer.observe(&first, now + Duration::from_secs(2)),
            Some(true)
        );
        assert_eq!(observer.observe(&next, now), Some(true));
        observer.applied(next.clone());
        assert_eq!(observer.observe(&next, now), None);
    }

    #[test]
    fn repeated_switches_and_offline_recovery_converge() {
        let mut observer = NetworkObserver::default();
        for cycle in 0..20 {
            let snapshot =
                online(if cycle % 2 == 0 { "en0" } else { "en1" }, "192.0.2.2");
            assert_eq!(observer.observe(&snapshot, Instant::now()), Some(true));
            observer.applied(snapshot.clone());
            assert_eq!(observer.observe(&snapshot, Instant::now()), None);
        }
        assert_eq!(
            observer.observe(&NetworkSnapshot::default(), Instant::now()),
            Some(true)
        );
        observer.failed(Instant::now());
        assert_eq!(
            observer.observe(&online("en0", "192.0.2.3"), Instant::now()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn stalled_dns_reset_is_bounded_and_still_attempts_pools() {
        let attempted = std::sync::atomic::AtomicBool::new(false);
        let result =
            reset_resources(std::future::pending::<Result<u32, &str>>(), async {
                attempted.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok::<u32, &str>(1)
            })
            .await;
        assert!(attempted.load(std::sync::atomic::Ordering::Relaxed));
        assert!(result.unwrap_err().contains("DNS: reset timed out"));
    }

    #[tokio::test]
    async fn dns_failure_does_not_skip_outbound_recovery() {
        let attempted = std::sync::atomic::AtomicBool::new(false);
        let result = reset_resources(async { Err::<u32, _>("DNS failed") }, async {
            attempted.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok::<u32, &str>(1)
        })
        .await;
        assert!(attempted.load(std::sync::atomic::Ordering::Relaxed));
        assert!(result.unwrap_err().contains("DNS failed"));
    }
}
