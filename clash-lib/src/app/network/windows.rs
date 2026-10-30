//! Read-only Windows network snapshot using IP Helper route and adapter APIs.

use std::{
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use super::{
    AddressFamily, BindingStatus, DefaultRouteEvidence, MAX_PATH_CANDIDATES,
    NetworkPath, NetworkSnapshot, PathCandidateObservation, TunCandidateExclusion,
};
use crate::app::flow::{InterfaceId, InterfaceKind};
use windows::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS},
    NetworkManagement::{
        IpHelper::{
            FreeMibTable, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_INCLUDE_PREFIX,
            GetAdaptersAddresses, GetIpForwardTable2, IF_TYPE_ETHERNET_CSMACD,
            IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_PPPMULTILINKBUNDLE,
            IF_TYPE_PROP_VIRTUAL, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL,
            IF_TYPE_WWANPP, IF_TYPE_WWANPP2, IP_ADAPTER_ADDRESSES_LH,
            IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, NldsDeprecated, NldsPreferred, SOCKADDR_INET,
    },
};

const INITIAL_ADAPTER_BUFFER_BYTES: usize = 15 * 1024;
const MAX_ADAPTER_BUFFER_ATTEMPTS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowsAddress {
    address: IpAddr,
    interface_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowsAdapter {
    name: String,
    ipv4_index: u32,
    ipv6_index: u32,
    operational_up: bool,
    interface_type: u32,
    ipv4_metric: u32,
    ipv6_metric: u32,
    addresses: Vec<WindowsAddress>,
    dns_servers: Vec<IpAddr>,
    dns_suffix: Option<String>,
    search_suffixes: Vec<String>,
}

impl WindowsAdapter {
    fn index_for(&self, family: AddressFamily) -> u32 {
        match family {
            AddressFamily::Ipv4 => self.ipv4_index,
            AddressFamily::Ipv6 => self.ipv6_index,
        }
    }

    fn metric_for(&self, family: AddressFamily) -> u32 {
        match family {
            AddressFamily::Ipv4 => self.ipv4_metric,
            AddressFamily::Ipv6 => self.ipv6_metric,
        }
    }

    fn excluded(
        &self,
        tun_exclusion: &TunCandidateExclusion,
        tun_interface_index: Option<u32>,
    ) -> bool {
        tun_exclusion.excludes(&self.name)
            || tun_interface_index.is_some_and(|index| {
                index == self.ipv4_index || index == self.ipv6_index
            })
            || (tun_exclusion.is_unidentified()
                && self.interface_type == IF_TYPE_TUNNEL)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowsDefaultRoute {
    family: AddressFamily,
    interface_index: u32,
    gateway: Option<IpAddr>,
    route_metric: u32,
    protocol: i32,
    origin: i32,
}

#[derive(Clone, Debug, Default)]
struct WindowsRouteSelection {
    primary: Option<WindowsDefaultRoute>,
    best_routes: Vec<WindowsDefaultRoute>,
    ambiguous: bool,
}

/// Collect route/address/DNS facts without sending traffic or changing system
/// network settings. The outer caller runs this blocking IP Helper work off the
/// async executor and applies its own two-second deadline.
pub(super) fn snapshot(
    tun_exclusion: TunCandidateExclusion,
    tun_interface_index: Option<u32>,
) -> io::Result<NetworkSnapshot> {
    let adapters = windows_adapters()?;
    let routes = windows_default_routes()?;
    let ipv4_routes = select_default_routes(
        &routes,
        &adapters,
        AddressFamily::Ipv4,
        &tun_exclusion,
        tun_interface_index,
    );
    let ipv6_routes = select_default_routes(
        &routes,
        &adapters,
        AddressFamily::Ipv6,
        &tun_exclusion,
        tun_interface_index,
    );

    let mut route_signatures = routes
        .iter()
        .filter_map(|route| {
            let adapter = adapters.iter().find(|adapter| {
                adapter.index_for(route.family) == route.interface_index
            });
            if adapter.is_some_and(|adapter| {
                adapter.excluded(&tun_exclusion, tun_interface_index)
            }) {
                return None;
            }
            let interface_metric = adapter
                .map(|adapter| adapter.metric_for(route.family))
                .unwrap_or_default();
            Some(format!(
                "{:?}:{}:{:?}:{}:{}:{}:{}",
                route.family,
                route.interface_index,
                route.gateway,
                route.route_metric,
                interface_metric,
                route.protocol,
                route.origin
            ))
        })
        .collect::<Vec<_>>();
    route_signatures.sort();

    let mut interfaces = adapters
        .iter()
        .filter(|adapter| !adapter.excluded(&tun_exclusion, tun_interface_index))
        .map(|adapter| {
            let mut addresses = adapter
                .addresses
                .iter()
                .map(|address| address.address.to_string())
                .collect::<Vec<_>>();
            addresses.sort();
            format!(
                "{}:{}:{}:{:?}:{}:{}/{}:{addresses:?}",
                adapter.name,
                adapter.ipv4_index,
                adapter.ipv6_index,
                adapter.operational_up,
                adapter.interface_type,
                adapter.ipv4_metric,
                adapter.ipv6_metric
            )
        })
        .collect::<Vec<_>>();
    interfaces.sort();

    let dns = dns_signature(&adapters);

    let (path_candidates, path_candidates_truncated) = collect_path_candidates(
        &adapters,
        &ipv4_routes,
        &ipv6_routes,
        &tun_exclusion,
        tun_interface_index,
        MAX_PATH_CANDIDATES,
        crate::proxy::utils::socket_helpers::probe_outbound_path_binding,
    );

    Ok(NetworkSnapshot {
        ipv4: path_for_route(&adapters, &ipv4_routes.primary),
        ipv6: path_for_route(&adapters, &ipv6_routes.primary),
        dns,
        interfaces,
        route_signatures,
        path_candidates,
        path_candidates_truncated,
        tun_candidate_exclusion: tun_exclusion,
    })
}

fn windows_adapters() -> io::Result<Vec<WindowsAdapter>> {
    let mut buffer_bytes = INITIAL_ADAPTER_BUFFER_BYTES;
    for _ in 0..MAX_ADAPTER_BUFFER_ATTEMPTS {
        let word_count = buffer_bytes.div_ceil(size_of::<u64>());
        let mut buffer = vec![0_u64; word_count];
        let mut available_bytes = (buffer.len() * size_of::<u64>()) as u32;
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut available_bytes,
            )
        };
        if status == ERROR_SUCCESS.0 {
            let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            return unsafe { parse_adapters(first) };
        }
        if status == ERROR_NO_DATA.0 {
            return Ok(Vec::new());
        }
        if status == ERROR_BUFFER_OVERFLOW.0 {
            buffer_bytes = (available_bytes as usize).max(buffer_bytes + 1);
            continue;
        }
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Err(io::Error::other(
        "GetAdaptersAddresses exceeded the bounded buffer retry count",
    ))
}

fn dns_signature(adapters: &[WindowsAdapter]) -> String {
    let mut settings = adapters
        .iter()
        .filter(|adapter| adapter.operational_up)
        .map(|adapter| {
            let servers = adapter
                .dns_servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let suffixes = adapter.search_suffixes.join(",");
            format!(
                "{}:{}:{}:servers=[{}]:suffix={}:search=[{}]",
                adapter.name,
                adapter.ipv4_index,
                adapter.ipv6_index,
                servers,
                adapter.dns_suffix.as_deref().unwrap_or_default(),
                suffixes
            )
        })
        .collect::<Vec<_>>();
    settings.sort();
    settings.join("\n")
}

/// `GetAdaptersAddresses` returns an OS-owned linked list embedded in the
/// aligned buffer passed to it. Every pointer is consumed before that buffer is
/// dropped. IP Helper guarantees valid linked-list nodes and NUL-terminated
/// friendly names for the duration of the call.
unsafe fn parse_adapters(
    first: *mut IP_ADAPTER_ADDRESSES_LH,
) -> io::Result<Vec<WindowsAdapter>> {
    let mut adapters = Vec::new();
    let mut current = first;
    while !current.is_null() {
        let raw = unsafe { &*current };
        let name = unsafe { wide_string(raw.FriendlyName.0) }
            .ok()
            .filter(|name| !name.is_empty())
            .or_else(|| unsafe { narrow_string(raw.AdapterName.0) }.ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows adapter has no usable name",
                )
            })?;
        let indexes = unsafe { raw.Anonymous1.Anonymous };
        let ipv4_index = indexes.IfIndex;
        let ipv6_index = raw.Ipv6IfIndex;

        let mut addresses = Vec::new();
        let mut raw_address = raw.FirstUnicastAddress;
        while !raw_address.is_null() {
            let unicast = unsafe { &*raw_address };
            if (unicast.DadState == NldsPreferred
                || unicast.DadState == NldsDeprecated)
                && let Some(address) = unsafe { socket_address_ip(&unicast.Address) }
            {
                let interface_index = match address {
                    IpAddr::V4(_) => ipv4_index,
                    IpAddr::V6(_) => ipv6_index,
                };
                if interface_index != 0 {
                    addresses.push(WindowsAddress {
                        address,
                        interface_index,
                    });
                }
            }
            raw_address = unicast.Next;
        }

        let mut dns_servers = Vec::new();
        let mut raw_dns = raw.FirstDnsServerAddress;
        while !raw_dns.is_null() {
            let dns = unsafe { &*raw_dns };
            if let Some(address) = unsafe { socket_address_ip(&dns.Address) }
                && !address.is_unspecified()
            {
                dns_servers.push(address);
            }
            raw_dns = dns.Next;
        }

        let dns_suffix = if raw.DnsSuffix.0.is_null() {
            None
        } else {
            let suffix = unsafe { wide_string(raw.DnsSuffix.0)? };
            (!suffix.is_empty()).then_some(suffix)
        };
        let mut search_suffixes = Vec::new();
        let mut raw_suffix = raw.FirstDnsSuffix;
        while !raw_suffix.is_null() {
            let suffix = unsafe { &*raw_suffix };
            let length = suffix
                .String
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(suffix.String.len());
            let value = String::from_utf16_lossy(&suffix.String[..length]);
            if !value.is_empty() {
                search_suffixes.push(value);
            }
            raw_suffix = suffix.Next;
        }
        addresses.sort_by_key(|address| {
            (address.interface_index, address.address.to_string())
        });
        addresses.dedup();
        adapters.push(WindowsAdapter {
            name,
            ipv4_index,
            ipv6_index,
            operational_up: raw.OperStatus == IfOperStatusUp,
            interface_type: raw.IfType,
            ipv4_metric: raw.Ipv4Metric,
            ipv6_metric: raw.Ipv6Metric,
            addresses,
            dns_servers,
            dns_suffix,
            search_suffixes,
        });
        current = raw.Next;
    }
    Ok(adapters)
}

unsafe fn wide_string(value: *const u16) -> io::Result<String> {
    if value.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows adapter has no friendly name",
        ));
    }
    const MAX_FRIENDLY_NAME_UNITS: usize = 32_768;
    let length = (0..MAX_FRIENDLY_NAME_UNITS)
        .find(|index| unsafe { *value.add(*index) == 0 })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows adapter friendly name is not terminated",
            )
        })?;
    let wide = unsafe { std::slice::from_raw_parts(value, length) };
    Ok(String::from_utf16_lossy(wide))
}

unsafe fn narrow_string(value: *const u8) -> io::Result<String> {
    if value.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows adapter has no stable identifier",
        ));
    }
    const MAX_ADAPTER_NAME_BYTES: usize = 32_768;
    let length = (0..MAX_ADAPTER_NAME_BYTES)
        .find(|index| unsafe { *value.add(*index) == 0 })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows adapter identifier is not terminated",
            )
        })?;
    let bytes = unsafe { std::slice::from_raw_parts(value, length) };
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

unsafe fn socket_address_ip(
    address: &windows::Win32::Networking::WinSock::SOCKET_ADDRESS,
) -> Option<IpAddr> {
    if address.lpSockaddr.is_null()
        || address.iSockaddrLength < size_of::<u16>() as i32
    {
        return None;
    }
    let family =
        unsafe { (*(address.lpSockaddr.cast::<SOCKADDR_INET>())).si_family };
    match family {
        AF_INET
            if address.iSockaddrLength as usize
                >= size_of::<windows::Win32::Networking::WinSock::SOCKADDR_IN>() =>
        {
            let sockaddr = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_INET>() };
            let raw = unsafe { sockaddr.Ipv4.sin_addr.S_un.S_addr };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))))
        }
        AF_INET6
            if address.iSockaddrLength as usize
                >= size_of::<windows::Win32::Networking::WinSock::SOCKADDR_IN6>(
                ) =>
        {
            let sockaddr = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_INET>() };
            let bytes = unsafe { sockaddr.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn windows_default_routes() -> io::Result<Vec<WindowsDefaultRoute>> {
    let mut table = ptr::null_mut::<MIB_IPFORWARD_TABLE2>();
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if status == ERROR_NO_DATA {
        return Ok(Vec::new());
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }
    if table.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GetIpForwardTable2 returned a null table",
        ));
    }
    let table_guard = MibTableGuard(table);
    let raw_table = unsafe { &*table_guard.0 };
    let rows = unsafe {
        std::slice::from_raw_parts(
            raw_table.Table.as_ptr(),
            raw_table.NumEntries as usize,
        )
    };
    Ok(rows.iter().filter_map(parse_default_route).collect())
}

struct MibTableGuard(*mut MIB_IPFORWARD_TABLE2);

impl Drop for MibTableGuard {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0.cast()) };
    }
}

fn parse_default_route(row: &MIB_IPFORWARD_ROW2) -> Option<WindowsDefaultRoute> {
    if row.Loopback || row.DestinationPrefix.PrefixLength != 0 {
        return None;
    }
    let prefix = unsafe { sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix) }?;
    if !prefix.is_unspecified() {
        return None;
    }
    let family = match prefix {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    };
    let gateway = unsafe { sockaddr_inet_to_ip(&row.NextHop) }
        .filter(|gateway| !gateway.is_unspecified());
    Some(WindowsDefaultRoute {
        family,
        interface_index: row.InterfaceIndex,
        gateway,
        route_metric: row.Metric,
        protocol: row.Protocol.0,
        origin: row.Origin.0,
    })
}

unsafe fn sockaddr_inet_to_ip(address: &SOCKADDR_INET) -> Option<IpAddr> {
    match unsafe { address.si_family } {
        AF_INET => {
            let raw = unsafe { address.Ipv4.sin_addr.S_un.S_addr };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))))
        }
        AF_INET6 => {
            let bytes = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn select_default_routes(
    routes: &[WindowsDefaultRoute],
    adapters: &[WindowsAdapter],
    family: AddressFamily,
    tun_exclusion: &TunCandidateExclusion,
    tun_interface_index: Option<u32>,
) -> WindowsRouteSelection {
    let mut candidates = routes
        .iter()
        .filter(|route| route.family == family)
        .filter_map(|route| {
            let adapter = adapters.iter().find(|adapter| {
                adapter.index_for(family) == route.interface_index
                    && adapter.operational_up
                    && adapter.interface_type != IF_TYPE_SOFTWARE_LOOPBACK
                    && !adapter.excluded(tun_exclusion, tun_interface_index)
            })?;
            Some((
                route
                    .route_metric
                    .saturating_add(adapter.metric_for(family)),
                *route,
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(metric, route)| {
        (
            *metric,
            route.interface_index,
            route.gateway.map(|gateway| gateway.to_string()),
        )
    });
    let Some((best_metric, _)) = candidates.first().copied() else {
        return WindowsRouteSelection::default();
    };
    let mut best_routes = candidates
        .into_iter()
        .take_while(|(metric, _)| *metric == best_metric)
        .map(|(_, route)| route)
        .collect::<Vec<_>>();
    best_routes.dedup();
    let ambiguous = best_routes.iter().skip(1).any(|route| {
        route.interface_index != best_routes[0].interface_index
            || route.gateway != best_routes[0].gateway
    });
    let primary = (!ambiguous).then(|| best_routes[0]);
    WindowsRouteSelection {
        primary,
        best_routes,
        ambiguous,
    }
}

fn path_for_route(
    adapters: &[WindowsAdapter],
    route: &Option<WindowsDefaultRoute>,
) -> Option<NetworkPath> {
    let route = route.as_ref()?;
    let adapter = adapters
        .iter()
        .find(|adapter| adapter.index_for(route.family) == route.interface_index)?;
    if !adapter.operational_up {
        return None;
    }
    let mut addresses = adapter
        .addresses
        .iter()
        .filter(|address| address.interface_index == route.interface_index)
        .map(|address| address.address.to_string())
        .collect::<Vec<_>>();
    addresses.sort();
    if addresses.is_empty() {
        return None;
    }
    Some(NetworkPath {
        interface: adapter.name.clone(),
        index: route.interface_index,
        gateway: route
            .gateway
            .map(|gateway| gateway.to_string())
            .unwrap_or_default(),
        addresses,
    })
}

fn collect_path_candidates(
    adapters: &[WindowsAdapter],
    ipv4_routes: &WindowsRouteSelection,
    ipv6_routes: &WindowsRouteSelection,
    tun_exclusion: &TunCandidateExclusion,
    tun_interface_index: Option<u32>,
    max_candidates: usize,
    mut bind_probe: impl FnMut(&str, u32, IpAddr) -> io::Result<()>,
) -> (Vec<PathCandidateObservation>, usize) {
    let mut addresses = adapters
        .iter()
        .filter(|adapter| {
            adapter.interface_type != IF_TYPE_SOFTWARE_LOOPBACK
                && !adapter.excluded(tun_exclusion, tun_interface_index)
        })
        .flat_map(|adapter| {
            adapter.addresses.iter().filter_map(move |address| {
                let ip = address.address;
                (!ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
                    .then_some((adapter, address))
            })
        })
        .collect::<Vec<_>>();
    addresses.sort_by_key(|(adapter, address)| {
        (
            adapter.name.clone(),
            address.interface_index,
            AddressFamily::from(address.address) as u8,
            address.address.to_string(),
        )
    });
    let path_candidates_truncated = addresses.len().saturating_sub(max_candidates);
    addresses.truncate(max_candidates);

    let mut candidates = Vec::with_capacity(addresses.len());
    for (adapter, address) in addresses {
        let ip = address.address;
        let family = AddressFamily::from(ip);
        let selection = match family {
            AddressFamily::Ipv4 => ipv4_routes,
            AddressFamily::Ipv6 => ipv6_routes,
        };
        let default_route = if selection
            .primary
            .is_some_and(|route| route.interface_index == address.interface_index)
        {
            DefaultRouteEvidence::PrimaryDefaultRoute
        } else if selection.ambiguous
            && selection
                .best_routes
                .iter()
                .any(|route| route.interface_index == address.interface_index)
        {
            DefaultRouteEvidence::AmbiguousDefaultRoute
        } else if selection.primary.is_some() || selection.ambiguous {
            DefaultRouteEvidence::OtherInterface
        } else {
            DefaultRouteEvidence::NoPrimaryRouteObserved
        };
        let gateway = selection
            .primary
            .filter(|route| route.interface_index == address.interface_index)
            .and_then(|route| route.gateway);
        let bind_result = if adapter.operational_up {
            bind_probe(&adapter.name, address.interface_index, ip)
                .map_err(|error| error.to_string())
        } else {
            Err("interface operational state is not up".to_owned())
        };
        let (binding, binding_error) = match bind_result {
            Ok(()) => (BindingStatus::Verified, None),
            Err(error) => (BindingStatus::Failed, Some(error)),
        };
        let scope_id = match ip {
            IpAddr::V6(ipv6) if ipv6.is_unicast_link_local() => {
                Some(address.interface_index)
            }
            _ => None,
        };
        candidates.push(PathCandidateObservation {
            interface: InterfaceId {
                name: adapter.name.clone(),
                index: address.interface_index,
            },
            interface_kind: windows_interface_kind(adapter.interface_type),
            family,
            source_address: ip,
            scope_id,
            gateway,
            default_route,
            binding,
            binding_error,
        });
    }
    (candidates, path_candidates_truncated)
}

fn windows_interface_kind(interface_type: u32) -> InterfaceKind {
    match interface_type {
        IF_TYPE_ETHERNET_CSMACD => InterfaceKind::Ethernet,
        IF_TYPE_IEEE80211 => InterfaceKind::Wifi,
        IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => InterfaceKind::Cellular,
        IF_TYPE_PPP | IF_TYPE_PPPMULTILINKBUNDLE | IF_TYPE_TUNNEL => {
            InterfaceKind::Vpn
        }
        IF_TYPE_SOFTWARE_LOOPBACK => InterfaceKind::Loopback,
        IF_TYPE_PROP_VIRTUAL => InterfaceKind::Virtual,
        _ => InterfaceKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_adapter(
        name: &str,
        ipv4_index: u32,
        ipv6_index: u32,
        ipv4_metric: u32,
        operational_up: bool,
    ) -> WindowsAdapter {
        WindowsAdapter {
            name: name.to_owned(),
            ipv4_index,
            ipv6_index,
            operational_up,
            interface_type: IF_TYPE_ETHERNET_CSMACD,
            ipv4_metric,
            ipv6_metric: ipv4_metric,
            addresses: Vec::new(),
            dns_servers: Vec::new(),
            dns_suffix: None,
            search_suffixes: Vec::new(),
        }
    }

    fn default_route(
        interface_index: u32,
        route_metric: u32,
    ) -> WindowsDefaultRoute {
        WindowsDefaultRoute {
            family: AddressFamily::Ipv4,
            interface_index,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            route_metric,
            protocol: 3,
            origin: 0,
        }
    }

    #[test]
    fn default_route_selection_uses_combined_route_and_interface_metrics() {
        let adapters = [
            test_adapter("wifi", 4, 14, 20, true),
            test_adapter("ethernet", 7, 17, 5, true),
        ];
        let routes = [default_route(4, 10), default_route(7, 30)];

        let selection = select_default_routes(
            &routes,
            &adapters,
            AddressFamily::Ipv4,
            &TunCandidateExclusion::Disabled,
            None,
        );

        assert_eq!(selection.primary, Some(default_route(4, 10)));
        assert!(!selection.ambiguous);
    }

    #[test]
    fn equal_cost_default_routes_are_reported_as_ambiguous() {
        let adapters = [
            test_adapter("wifi", 4, 14, 10, true),
            test_adapter("ethernet", 7, 17, 10, true),
        ];
        let routes = [default_route(4, 20), default_route(7, 20)];

        let selection = select_default_routes(
            &routes,
            &adapters,
            AddressFamily::Ipv4,
            &TunCandidateExclusion::Disabled,
            None,
        );

        assert_eq!(selection.primary, None);
        assert!(selection.ambiguous);
        assert_eq!(selection.best_routes.len(), 2);
    }

    #[test]
    fn down_and_excluded_tunnel_routes_cannot_become_primary() {
        let adapters = [
            test_adapter("wifi", 4, 14, 10, true),
            test_adapter("Chimera TUN", 7, 17, 1, true),
            test_adapter("down", 9, 19, 1, false),
        ];
        let routes = [
            default_route(4, 50),
            default_route(7, 0),
            default_route(9, 0),
        ];

        let selection = select_default_routes(
            &routes,
            &adapters,
            AddressFamily::Ipv4,
            &TunCandidateExclusion::Named("Chimera TUN".to_owned()),
            None,
        );

        assert_eq!(selection.primary, Some(default_route(4, 50)));
    }

    #[test]
    fn ipv6_default_route_uses_ipv6_interface_index() {
        let adapter = test_adapter("wifi", 4, 14, 10, true);
        let route = WindowsDefaultRoute {
            family: AddressFamily::Ipv6,
            interface_index: 14,
            gateway: None,
            route_metric: 10,
            protocol: 3,
            origin: 0,
        };

        let selection = select_default_routes(
            &[route],
            &[adapter],
            AddressFamily::Ipv6,
            &TunCandidateExclusion::Disabled,
            None,
        );

        assert_eq!(selection.primary, Some(route));
    }

    #[test]
    fn dns_signature_tracks_server_order_and_search_suffixes() {
        let mut adapter = test_adapter("wifi", 4, 14, 10, true);
        adapter.dns_servers =
            vec!["192.0.2.53".parse().unwrap(), "192.0.2.54".parse().unwrap()];
        adapter.dns_suffix = Some("lan.example".to_owned());
        adapter.search_suffixes =
            vec!["corp.example".to_owned(), "example".to_owned()];
        let original = dns_signature(std::slice::from_ref(&adapter));

        adapter.dns_servers.reverse();
        assert_ne!(dns_signature(std::slice::from_ref(&adapter)), original);

        adapter.dns_servers.reverse();
        adapter.search_suffixes.reverse();
        assert_ne!(dns_signature(std::slice::from_ref(&adapter)), original);

        adapter.search_suffixes.reverse();
        adapter.dns_suffix = Some("guest.example".to_owned());
        assert_ne!(dns_signature(&[adapter]), original);
    }

    #[test]
    fn path_candidate_socket_probes_stop_at_the_output_bound() {
        use std::cell::Cell;

        let mut adapter = test_adapter("wifi", 4, 14, 10, true);
        adapter.addresses = (1..=MAX_PATH_CANDIDATES + 2)
            .map(|octet| WindowsAddress {
                address: IpAddr::V4(Ipv4Addr::new(10, 1, 0, octet as u8)),
                interface_index: 4,
            })
            .collect();
        let calls = Cell::new(0);

        let (candidates, truncated) = collect_path_candidates(
            &[adapter],
            &WindowsRouteSelection::default(),
            &WindowsRouteSelection::default(),
            &TunCandidateExclusion::Disabled,
            None,
            MAX_PATH_CANDIDATES,
            |_, _, _| {
                calls.set(calls.get() + 1);
                Ok(())
            },
        );

        assert_eq!(candidates.len(), MAX_PATH_CANDIDATES);
        assert_eq!(truncated, 2);
        assert_eq!(calls.get(), MAX_PATH_CANDIDATES);
    }

    #[test]
    fn route_parser_keeps_only_zero_prefix_defaults_and_preserves_gateway() {
        use std::net::SocketAddr;
        use windows::Win32::Networking::WinSock::SOCKADDR_INET;

        let mut row = MIB_IPFORWARD_ROW2 {
            DestinationPrefix: IP_ADDRESS_PREFIX {
                Prefix: SOCKADDR_INET::from(
                    "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
                ),
                PrefixLength: 0,
            },
            NextHop: SOCKADDR_INET::from(
                "192.0.2.1:0".parse::<SocketAddr>().unwrap(),
            ),
            InterfaceIndex: 12,
            Metric: 40,
            ..Default::default()
        };

        assert_eq!(
            parse_default_route(&row),
            Some(WindowsDefaultRoute {
                family: AddressFamily::Ipv4,
                interface_index: 12,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                route_metric: 40,
                protocol: 0,
                origin: 0,
            })
        );

        row.DestinationPrefix.PrefixLength = 24;
        assert_eq!(parse_default_route(&row), None);

        let ipv6 = MIB_IPFORWARD_ROW2 {
            DestinationPrefix: IP_ADDRESS_PREFIX {
                Prefix: SOCKADDR_INET::from("[::]:0".parse::<SocketAddr>().unwrap()),
                PrefixLength: 0,
            },
            NextHop: SOCKADDR_INET::from(
                "[2001:db8::1]:0".parse::<SocketAddr>().unwrap(),
            ),
            InterfaceIndex: 14,
            Metric: 25,
            ..Default::default()
        };
        assert_eq!(
            parse_default_route(&ipv6),
            Some(WindowsDefaultRoute {
                family: AddressFamily::Ipv6,
                interface_index: 14,
                gateway: Some(IpAddr::V6("2001:db8::1".parse().unwrap())),
                route_metric: 25,
                protocol: 0,
                origin: 0,
            })
        );
    }

    #[test]
    fn live_snapshot_is_read_only_and_returns_bounded_observations() {
        let snapshot = snapshot(TunCandidateExclusion::Unidentified, None).unwrap();

        assert!(snapshot.path_candidates.len() <= MAX_PATH_CANDIDATES);
        assert!(snapshot.path_candidates.iter().all(|candidate| {
            !candidate.source_address.is_loopback()
                && !candidate.source_address.is_unspecified()
                && !candidate.source_address.is_multicast()
        }));
    }
}
