//! Network-change observation shared by automatic and requested recovery.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{io, net::IpAddr, time::Duration};

use serde::Serialize;
use tokio::time::Instant;

use super::flow::{AddressFamily, InterfaceId, InterfaceKind};

pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const RECOVERY_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const AUTOMATIC_SUPPORTED: bool =
    cfg!(any(target_os = "linux", target_os = "macos"));

#[cfg(target_os = "linux")]
static LINUX_NETLINK_HANDLE: tokio::sync::OnceCell<rtnetlink::Handle> =
    tokio::sync::OnceCell::const_new();

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
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    AmbiguousDefaultRoute,
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn excludes(&self, interface_name: &str) -> bool {
        match self {
            Self::Disabled => false,
            Self::Named(name) => name == interface_name,
            Self::Unidentified => {
                interface_name.starts_with("utun")
                    || interface_name.starts_with("tun")
                    || (cfg!(target_os = "linux")
                        && (interface_name.starts_with("tap")
                            || interface_name.starts_with("wg")))
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_PATH_CANDIDATES: usize = 128;

#[derive(Clone, Debug, Default)]
pub(crate) struct NetworkSnapshot {
    pub ipv4: Option<NetworkPath>,
    pub ipv6: Option<NetworkPath>,
    pub dns: String,
    pub interfaces: Vec<String>,
    /// Route-table facts that affect candidate selection, including ambiguous
    /// defaults that cannot be reduced to one primary path.
    pub route_signatures: Vec<String>,
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
            && self.route_signatures == other.route_signatures
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
            || self.route_signatures != previous.route_signatures
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
        let route_signatures = [
            ipv4_route.as_ref().map(|route| {
                format!("ipv4:{}:{:?}", route.interface_index, route.gateway)
            }),
            ipv6_route.as_ref().map(|route| {
                format!("ipv6:{}:{:?}", route.interface_index, route.gateway)
            }),
        ]
        .into_iter()
        .flatten()
        .collect();
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
            route_signatures,
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

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct LinuxLinkState {
    admin_up: bool,
    lower_up: Option<bool>,
    oper_down: bool,
    carrier: Option<bool>,
}

#[cfg(target_os = "linux")]
impl LinuxLinkState {
    /// A local bind probe alone can succeed on an administratively-down link.
    /// Reject known-down links before advertising them as selectable paths.
    fn unavailable_reason(&self) -> Option<String> {
        if !self.admin_up {
            Some("interface is administratively down".to_owned())
        } else if self.oper_down {
            Some("interface operational state is down".to_owned())
        } else if self.lower_up == Some(false) || self.carrier == Some(false) {
            Some("interface has no lower-layer carrier".to_owned())
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxDefaultRoute {
    interface_index: u32,
    family: AddressFamily,
    gateway: Option<IpAddr>,
    metric: u32,
}

#[cfg(target_os = "linux")]
struct LinuxPathRouteState<'a> {
    ipv4_route: Option<&'a LinuxDefaultRoute>,
    ipv6_route: Option<&'a LinuxDefaultRoute>,
    ipv4_ambiguous: bool,
    ipv6_ambiguous: bool,
}

#[cfg(target_os = "linux")]
async fn linux_netlink_handle() -> io::Result<&'static rtnetlink::Handle> {
    LINUX_NETLINK_HANDLE
        .get_or_try_init(|| async {
            let (connection, handle, _) =
                rtnetlink::new_connection().map_err(io::Error::other)?;
            tokio::spawn(connection);
            Ok(handle)
        })
        .await
}

#[cfg(target_os = "linux")]
fn linux_route_address_to_ip(
    address: &rtnetlink::packet_route::route::RouteAddress,
) -> Option<IpAddr> {
    use rtnetlink::packet_route::route::RouteAddress;

    match address {
        RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
        RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn linux_route_table(message: &rtnetlink::packet_route::route::RouteMessage) -> u32 {
    use rtnetlink::packet_route::route::RouteAttribute;

    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table))
}

/// Keep only effective main-table unicast defaults. Policy-routing rules and
/// multipath nexthop groups are not flattened into a guessed primary path; the
/// host snapshot and later Linux acceptance need to preserve that distinction.
#[cfg(target_os = "linux")]
fn parse_linux_default_route(
    message: &rtnetlink::packet_route::route::RouteMessage,
) -> Option<LinuxDefaultRoute> {
    use rtnetlink::packet_route::{
        AddressFamily as NetlinkFamily,
        route::{RouteAttribute, RouteType},
    };

    if message.header.destination_prefix_length != 0
        || message.header.kind != RouteType::Unicast
    {
        return None;
    }

    let family = match message.header.address_family {
        NetlinkFamily::Inet => AddressFamily::Ipv4,
        NetlinkFamily::Inet6 => AddressFamily::Ipv6,
        _ => return None,
    };
    let mut interface_index = None;
    let mut gateway = None;
    let table = linux_route_table(message);
    let mut metric = 0;
    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Destination(address) => {
                // Linux normally omits RTA_DST for a default route. If it is
                // present, only accept the family-specific unspecified value.
                if linux_route_address_to_ip(address)
                    .is_some_and(|address| !address.is_unspecified())
                {
                    return None;
                }
            }
            RouteAttribute::Oif(index) => interface_index = Some(*index),
            RouteAttribute::Gateway(address) => {
                gateway = linux_route_address_to_ip(address);
            }
            RouteAttribute::Priority(value) => metric = *value,
            _ => {}
        }
    }

    // Table 254 is RT_TABLE_MAIN. Other tables may only apply under an
    // unobserved policy rule, so treating one as global default would guess.
    if table != 254 {
        return None;
    }

    Some(LinuxDefaultRoute {
        interface_index: interface_index?,
        family,
        gateway,
        metric,
    })
}

#[cfg(target_os = "linux")]
fn select_linux_default_route(
    routes: &[LinuxDefaultRoute],
    family: AddressFamily,
) -> Option<LinuxDefaultRoute> {
    let minimum_metric = routes
        .iter()
        .filter(|route| route.family == family)
        .map(|route| route.metric)
        .min()?;
    let mut best = routes
        .iter()
        .filter(|route| route.family == family && route.metric == minimum_metric);
    let first = best.next()?.clone();

    // Equal-cost defaults on distinct interfaces are real alternatives. Keep
    // them in the candidate list and avoid labeling either one "primary".
    best.all(|route| {
        route.interface_index == first.interface_index
            && route.gateway == first.gateway
    })
    .then_some(first)
}

#[cfg(target_os = "linux")]
fn linux_default_route_is_ambiguous(
    routes: &[LinuxDefaultRoute],
    family: AddressFamily,
) -> bool {
    let Some(minimum_metric) = routes
        .iter()
        .filter(|route| route.family == family)
        .map(|route| route.metric)
        .min()
    else {
        return false;
    };
    let mut best = routes
        .iter()
        .filter(|route| route.family == family && route.metric == minimum_metric);
    let Some(first) = best.next() else {
        return false;
    };
    best.any(|route| {
        route.interface_index != first.interface_index
            || route.gateway != first.gateway
    })
}

#[cfg(target_os = "linux")]
fn linux_interface_kind(interface_name: &str) -> InterfaceKind {
    let sysfs_interface = Path::new("/sys/class/net").join(interface_name);
    if sysfs_interface.join("wireless").exists() {
        InterfaceKind::Wifi
    } else {
        // A sysfs device alone cannot distinguish Ethernet, cellular, and
        // several virtual drivers. Keep the classification conservative;
        // route and local-bind evidence still make the path usable.
        InterfaceKind::Unknown
    }
}

#[cfg(target_os = "linux")]
fn linux_interface_path(
    interfaces: &[network_interface::NetworkInterface],
    route: Option<&LinuxDefaultRoute>,
    tun_exclusion: &TunCandidateExclusion,
) -> Option<NetworkPath> {
    let route = route?;
    let interface = interfaces.iter().find(|interface| {
        interface.index == route.interface_index
            && !interface.internal
            && !tun_exclusion.excludes(&interface.name)
    })?;
    let mut addresses = interface
        .addr
        .iter()
        .filter(|address| match route.family {
            AddressFamily::Ipv4 => matches!(address, network_interface::Addr::V4(_)),
            AddressFamily::Ipv6 => matches!(address, network_interface::Addr::V6(_)),
        })
        .map(|address| format!("{address:?}"))
        .collect::<Vec<_>>();
    addresses.sort();
    if addresses.is_empty() {
        return None;
    }

    Some(NetworkPath {
        interface: interface.name.clone(),
        index: interface.index,
        gateway: route.gateway.map_or_else(String::new, |ip| ip.to_string()),
        addresses,
    })
}

#[cfg(target_os = "linux")]
fn collect_linux_path_candidates<F>(
    interfaces: &[network_interface::NetworkInterface],
    links: &HashMap<u32, LinuxLinkState>,
    route_state: LinuxPathRouteState<'_>,
    tun_exclusion: &TunCandidateExclusion,
    mut bind_probe: F,
) -> Vec<PathCandidateObservation>
where
    F: FnMut(&str, u32, IpAddr) -> Result<(), String>,
{
    let mut candidates = Vec::new();
    for interface in interfaces.iter().filter(|interface| {
        !interface.internal
            && interface.index != 0
            && !tun_exclusion.excludes(&interface.name)
    }) {
        let link_state = links.get(&interface.index);
        for address in &interface.addr {
            let ip = address.ip();
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            let family = AddressFamily::from(ip);
            let route = match family {
                AddressFamily::Ipv4 => route_state.ipv4_route,
                AddressFamily::Ipv6 => route_state.ipv6_route,
            };
            let route_ambiguous = match family {
                AddressFamily::Ipv4 => route_state.ipv4_ambiguous,
                AddressFamily::Ipv6 => route_state.ipv6_ambiguous,
            };
            let default_route = match route {
                Some(route) if route.interface_index == interface.index => {
                    DefaultRouteEvidence::PrimaryDefaultRoute
                }
                Some(_) => DefaultRouteEvidence::OtherInterface,
                None if route_ambiguous => {
                    DefaultRouteEvidence::AmbiguousDefaultRoute
                }
                None => DefaultRouteEvidence::NoPrimaryRouteObserved,
            };
            let gateway = route
                .filter(|route| route.interface_index == interface.index)
                .and_then(|route| route.gateway);
            let bind_result = match link_state {
                Some(state) => match state.unavailable_reason() {
                    Some(reason) => Err(reason),
                    None => bind_probe(&interface.name, interface.index, ip),
                },
                None => Err("link metadata unavailable from rtnetlink".to_owned()),
            };
            let (binding, binding_error) = match bind_result {
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
                interface_kind: linux_interface_kind(&interface.name),
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

#[cfg(target_os = "linux")]
fn linux_dns_signature(content: &str) -> String {
    content
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            let mut fields = line.split_whitespace();
            let kind = fields.next()?;
            let value = fields.collect::<Vec<_>>().join(" ");
            matches!(kind, "nameserver" | "search" | "domain" | "options")
                .then(|| format!("{kind} {value}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Sample Linux interface/address state with rtnetlink and compare it to the
/// main-table default route. This deliberately does no reachability probing;
/// the existing traffic evidence remains the source of online health.
#[cfg(target_os = "linux")]
pub(crate) async fn snapshot_with_tun(
    tun_candidate_exclusion: TunCandidateExclusion,
) -> io::Result<NetworkSnapshot> {
    use futures::TryStreamExt;
    use network_interface::NetworkInterfaceConfig;
    use rtnetlink::packet_route::{
        link::{LinkAttribute, LinkFlags, State},
        route::RouteMessage,
    };

    tokio::time::timeout(Duration::from_secs(2), async {
        let handle = linux_netlink_handle().await?;
        let mut links = HashMap::new();
        let mut link_messages = handle.link().get().execute();
        while let Some(message) =
            link_messages.try_next().await.map_err(io::Error::other)?
        {
            let mut name = None;
            let lower_up = Some(message.header.flags.contains(LinkFlags::LowerUp));
            let mut oper_down = false;
            let mut carrier = None;
            for attribute in &message.attributes {
                match attribute {
                    LinkAttribute::IfName(value) => name = Some(value.clone()),
                    LinkAttribute::OperState(
                        State::Down | State::LowerLayerDown,
                    ) => {
                        oper_down = true;
                    }
                    LinkAttribute::OperState(_) => oper_down = false,
                    LinkAttribute::Carrier(value) => carrier = Some(*value != 0),
                    _ => {}
                }
            }
            if name.is_some() {
                links.insert(
                    message.header.index,
                    LinuxLinkState {
                        admin_up: message.header.flags.contains(LinkFlags::Up),
                        lower_up,
                        oper_down,
                        carrier,
                    },
                );
            }
        }

        let interfaces =
            network_interface::NetworkInterface::show().map_err(io::Error::other)?;
        let mut route_messages =
            handle.route().get(RouteMessage::default()).execute();
        let mut routes = Vec::new();
        let mut route_signatures = Vec::new();
        while let Some(message) =
            route_messages.try_next().await.map_err(io::Error::other)?
        {
            if message.header.destination_prefix_length == 0
                && message.header.kind
                    == rtnetlink::packet_route::route::RouteType::Unicast
                && linux_route_table(&message) == 254
            {
                // Retain raw default-route facts as a change signature even
                // when ECMP/multipath cannot be represented by one interface.
                route_signatures.push(format!("{message:?}"));
            }
            if let Some(route) = parse_linux_default_route(&message) {
                routes.push(route);
            }
        }
        route_signatures.sort();
        let ipv4_ambiguous =
            linux_default_route_is_ambiguous(&routes, AddressFamily::Ipv4);
        let ipv6_ambiguous =
            linux_default_route_is_ambiguous(&routes, AddressFamily::Ipv6);
        let ipv4_route = select_linux_default_route(&routes, AddressFamily::Ipv4);
        let ipv6_route = select_linux_default_route(&routes, AddressFamily::Ipv6);
        let mut path_candidates = collect_linux_path_candidates(
            &interfaces,
            &links,
            LinuxPathRouteState {
                ipv4_route: ipv4_route.as_ref(),
                ipv6_route: ipv6_route.as_ref(),
                ipv4_ambiguous,
                ipv6_ambiguous,
            },
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

        let mut interface_signatures = interfaces
            .iter()
            .filter(|interface| {
                !interface.internal
                    && !tun_candidate_exclusion.excludes(&interface.name)
            })
            .map(|interface| {
                let mut addresses = interface
                    .addr
                    .iter()
                    .map(|address| format!("{address:?}"))
                    .collect::<Vec<_>>();
                addresses.sort();
                format!(
                    "{}:{}:{addresses:?}:{:?}",
                    interface.name,
                    interface.index,
                    links.get(&interface.index)
                )
            })
            .collect::<Vec<_>>();
        interface_signatures.sort();

        // resolv.conf may point at a local systemd-resolved stub. We record
        // exactly the visible resolver configuration and keep DNS failures
        // from disabling link/address observation; backend-specific resolver
        // changes remain a Linux integration-test item.
        let dns = match tokio::fs::read_to_string("/etc/resolv.conf").await {
            Ok(content) => linux_dns_signature(&content),
            Err(error) => {
                tracing::debug!(%error, "Linux resolver configuration unavailable");
                format!("unavailable:{:?}", error.kind())
            }
        };

        Ok(NetworkSnapshot {
            ipv4: linux_interface_path(
                &interfaces,
                ipv4_route.as_ref(),
                &tun_candidate_exclusion,
            ),
            ipv6: linux_interface_path(
                &interfaces,
                ipv6_route.as_ref(),
                &tun_candidate_exclusion,
            ),
            dns,
            interfaces: interface_signatures,
            route_signatures,
            path_candidates,
            path_candidates_truncated,
            tun_candidate_exclusion,
        })
    })
    .await
    .map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "Linux network snapshot timed out")
    })?
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn snapshot_with_tun(
    _tun_candidate_exclusion: TunCandidateExclusion,
) -> io::Result<NetworkSnapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "automatic network observation is currently supported on Linux and macOS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn linux_default_route(
        destination: IpAddr,
        interface_index: u32,
        gateway: IpAddr,
        metric: u32,
    ) -> rtnetlink::packet_route::route::RouteMessage {
        use rtnetlink::RouteMessageBuilder;

        RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(destination, 0)
            .unwrap()
            .output_interface(interface_index)
            .gateway(gateway)
            .unwrap()
            .priority(metric)
            .build()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_route_parser_preserves_family_gateway_and_metric() {
        let message = linux_default_route(
            "0.0.0.0".parse().unwrap(),
            12,
            "192.0.2.1".parse().unwrap(),
            40,
        );

        let route = parse_linux_default_route(&message).unwrap();
        assert_eq!(route.family, AddressFamily::Ipv4);
        assert_eq!(route.interface_index, 12);
        assert_eq!(route.gateway, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(route.metric, 40);

        // A subnet route must never become system-default evidence.
        let subnet = linux_default_route(
            "192.0.2.0".parse().unwrap(),
            12,
            "192.0.2.1".parse().unwrap(),
            1,
        );
        assert!(parse_linux_default_route(&subnet).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_route_selection_uses_metric_and_keeps_ecmp_ambiguous() {
        let slow = parse_linux_default_route(&linux_default_route(
            "0.0.0.0".parse().unwrap(),
            12,
            "192.0.2.1".parse().unwrap(),
            100,
        ))
        .unwrap();
        let fast = parse_linux_default_route(&linux_default_route(
            "0.0.0.0".parse().unwrap(),
            13,
            "198.51.100.1".parse().unwrap(),
            20,
        ))
        .unwrap();
        assert_eq!(
            select_linux_default_route(&[slow, fast], AddressFamily::Ipv4),
            Some(fast)
        );

        let equal_cost = LinuxDefaultRoute {
            metric: fast.metric,
            interface_index: 14,
            ..fast
        };
        let ecmp = [fast, equal_cost];
        assert!(linux_default_route_is_ambiguous(&ecmp, AddressFamily::Ipv4));
        assert_eq!(select_linux_default_route(&ecmp, AddressFamily::Ipv4), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_dns_signature_tracks_resolver_directives_without_comments() {
        let before = linux_dns_signature(
            "# generated file\nnameserver 192.0.2.53 # local stub\nsearch corp.example\noptions timeout:2\n",
        );
        let after = linux_dns_signature(
            "nameserver 192.0.2.54\nsearch corp.example\noptions timeout:2\n",
        );

        assert_ne!(before, after);
        assert_eq!(linux_dns_signature("# only comments\n\n"), String::new());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_known_link_failure_is_not_overridden_by_local_bind_evidence() {
        use network_interface::{Addr, NetworkInterface, V4IfAddr};

        let interface = NetworkInterface {
            name: "offline-test0".to_owned(),
            index: 12,
            internal: false,
            mac_addr: None,
            addr: vec![Addr::V4(V4IfAddr {
                ip: "192.0.2.2".parse().unwrap(),
                broadcast: None,
                netmask: None,
            })],
        };
        let link = LinuxLinkState {
            admin_up: true,
            lower_up: Some(false),
            oper_down: false,
            carrier: Some(false),
        };
        let links = HashMap::from([(12, link.clone())]);
        let route = LinuxDefaultRoute {
            interface_index: 12,
            family: AddressFamily::Ipv4,
            gateway: Some("192.0.2.1".parse().unwrap()),
            metric: 10,
        };
        let mut bind_probe_called = false;
        let candidates = collect_linux_path_candidates(
            &[interface],
            &links,
            LinuxPathRouteState {
                ipv4_route: Some(&route),
                ipv6_route: None,
                ipv4_ambiguous: false,
                ipv6_ambiguous: false,
            },
            &TunCandidateExclusion::Disabled,
            |_, _, _| {
                bind_probe_called = true;
                Ok(())
            },
        );

        assert_eq!(
            link.unavailable_reason().as_deref(),
            Some("interface has no lower-layer carrier")
        );
        assert!(!bind_probe_called);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].binding, BindingStatus::Failed);
        assert_eq!(
            candidates[0].binding_error.as_deref(),
            Some("interface has no lower-layer carrier")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_equal_cost_routes_are_reported_as_ambiguous_candidates() {
        use network_interface::{Addr, NetworkInterface, V4IfAddr};

        let interfaces = [12, 13].map(|index| NetworkInterface {
            name: format!("test{index}"),
            index,
            internal: false,
            mac_addr: None,
            addr: vec![Addr::V4(V4IfAddr {
                ip: format!("192.0.2.{}", index - 10).parse().unwrap(),
                broadcast: None,
                netmask: None,
            })],
        });
        let links = HashMap::from([12, 13].map(|index| {
            (
                index,
                LinuxLinkState {
                    admin_up: true,
                    lower_up: Some(true),
                    oper_down: false,
                    carrier: Some(true),
                },
            )
        }));
        let routes = [
            LinuxDefaultRoute {
                interface_index: 12,
                family: AddressFamily::Ipv4,
                gateway: Some("192.0.2.1".parse().unwrap()),
                metric: 10,
            },
            LinuxDefaultRoute {
                interface_index: 13,
                family: AddressFamily::Ipv4,
                gateway: Some("192.0.2.129".parse().unwrap()),
                metric: 10,
            },
        ];
        let candidates = collect_linux_path_candidates(
            &interfaces,
            &links,
            LinuxPathRouteState {
                ipv4_route: None,
                ipv6_route: None,
                ipv4_ambiguous: true,
                ipv6_ambiguous: false,
            },
            &TunCandidateExclusion::Disabled,
            |_, _, _| Ok(()),
        );

        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|candidate| {
            candidate.default_route == DefaultRouteEvidence::AmbiguousDefaultRoute
                && candidate.binding == BindingStatus::Verified
                && candidate.gateway.is_none()
        }));
        assert!(linux_default_route_is_ambiguous(
            &routes,
            AddressFamily::Ipv4
        ));
    }

    // These pure parser tests are the contract layer for future `ip netns`
    // validation. The runtime test must additionally flip each veth and verify
    // `/network` generations, direct dials, DNS, and service-side responses.

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

    #[test]
    fn default_route_table_change_is_a_path_change_even_when_no_primary_is_selected()
    {
        let first = NetworkSnapshot {
            route_signatures: vec!["default via 192.0.2.1 metric 100".to_owned()],
            ..Default::default()
        };
        let next = NetworkSnapshot {
            route_signatures: vec!["default via 192.0.2.2 metric 100".to_owned()],
            ..Default::default()
        };

        assert!(next.path_changed(&first));
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
