use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

#[cfg(feature = "tun")]
use network_interface::{
    NetworkInterface, NetworkInterfaceConfig, V4IfAddr, V6IfAddr,
};
use serde::Serialize;
use std::sync::{Arc, LazyLock};
#[cfg(feature = "tun")]
use tracing::trace;

#[cfg(feature = "tun")]
use crate::{Error, Result};

pub static DEFAULT_OUTBOUND_INTERFACE: LazyLock<
    Arc<tokio::sync::RwLock<Option<OutboundInterface>>>,
> = LazyLock::new(Default::default);
#[cfg(feature = "tun")]
pub static TUN_SOMARK: LazyLock<tokio::sync::RwLock<Option<u32>>> =
    LazyLock::new(Default::default);
#[cfg(all(feature = "tun", target_os = "linux"))]
static ROUTE_NETLINK_HANDLE: tokio::sync::OnceCell<rtnetlink::Handle> =
    tokio::sync::OnceCell::const_new();
#[cfg(all(feature = "tun", target_os = "windows"))]
static WINDOWS_TUN_INTERFACE_INDEX: LazyLock<tokio::sync::RwLock<Option<u32>>> =
    LazyLock::new(Default::default);
#[cfg(all(feature = "tun", target_os = "windows"))]
static WINDOWS_FALLBACK_OUTBOUND_INTERFACES: LazyLock<
    tokio::sync::RwLock<WindowsFallbackOutboundInterfaces>,
> = LazyLock::new(Default::default);

#[cfg(all(feature = "tun", target_os = "windows"))]
#[derive(Debug, Clone, Default)]
struct WindowsFallbackOutboundInterfaces {
    ipv4: Option<OutboundInterface>,
    ipv6: Option<OutboundInterface>,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub family: AddressFamily,
    pub destination: IpAddr,
    pub interface_index: u32,
    pub interface_name: String,
    pub gateway: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub table: u32,
    pub metric: Option<u32>,
}

#[derive(thiserror::Error, Debug)]
pub enum RouteSelectionError {
    #[error("failed to initialize route netlink connection: {0}")]
    Connection(#[source] std::io::Error),
    #[error("netlink route query for {destination} failed: {message}")]
    Netlink {
        destination: IpAddr,
        message: String,
    },
    #[error("route query for {destination} failed: {message}")]
    QueryFailed {
        destination: IpAddr,
        message: String,
    },
    #[error("failed to {operation} route {destination}: {message}")]
    NetlinkOperation {
        operation: &'static str,
        destination: ipnet::IpNet,
        message: String,
    },
    #[error("invalid route query output for {destination}: {message}")]
    InvalidOutput {
        destination: IpAddr,
        message: String,
    },
    #[error("route to {destination} uses unknown interface index {interface_index}")]
    InterfaceNotFound {
        destination: IpAddr,
        interface_index: u32,
    },
    #[error("route lookup is unsupported on this platform")]
    Unsupported,
}

#[cfg(all(feature = "tun", target_os = "linux"))]
#[derive(Debug, PartialEq, Eq)]
struct ParsedRoute {
    interface_index: u32,
    gateway: Option<IpAddr>,
    preferred_source: Option<IpAddr>,
    table: u32,
    metric: Option<u32>,
}

#[cfg(all(feature = "tun", target_os = "linux"))]
async fn route_netlink_handle()
-> std::result::Result<&'static rtnetlink::Handle, RouteSelectionError> {
    ROUTE_NETLINK_HANDLE
        .get_or_try_init(|| async {
            let (connection, handle, _) = rtnetlink::new_connection()
                .map_err(RouteSelectionError::Connection)?;
            tokio::spawn(connection);
            Ok(handle)
        })
        .await
}

#[cfg(all(feature = "tun", target_os = "linux"))]
fn route_address_to_ip(
    address: &rtnetlink::packet_route::route::RouteAddress,
) -> Option<IpAddr> {
    use rtnetlink::packet_route::route::RouteAddress;

    match address {
        RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
        RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
        _ => None,
    }
}

#[cfg(all(feature = "tun", target_os = "linux"))]
fn parse_netlink_route(
    destination: IpAddr,
    message: &rtnetlink::packet_route::route::RouteMessage,
) -> std::result::Result<ParsedRoute, RouteSelectionError> {
    use rtnetlink::packet_route::route::RouteAttribute;

    let mut interface_index = None;
    let mut gateway = None;
    let mut preferred_source = None;
    let mut table = message.header.table as u32;
    let mut metric = None;

    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Oif(index) => interface_index = Some(*index),
            RouteAttribute::Gateway(address) => {
                gateway = route_address_to_ip(address);
            }
            RouteAttribute::PrefSource(address) => {
                preferred_source = route_address_to_ip(address);
            }
            RouteAttribute::Table(value) => table = *value,
            RouteAttribute::Priority(value) => metric = Some(*value),
            _ => {}
        }
    }

    let interface_index =
        interface_index.ok_or_else(|| RouteSelectionError::InvalidOutput {
            destination,
            message: "missing output interface index".to_owned(),
        })?;

    Ok(ParsedRoute {
        interface_index,
        gateway,
        preferred_source,
        table,
        metric,
    })
}

#[cfg(all(feature = "tun", target_os = "linux"))]
pub async fn route_for_destination(
    destination: IpAddr,
    fwmark: Option<u32>,
) -> std::result::Result<RouteDecision, RouteSelectionError> {
    use futures::TryStreamExt;
    use rtnetlink::RouteMessageBuilder;

    let prefix_length = if destination.is_ipv4() { 32 } else { 128 };
    let mut request = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(destination, prefix_length)
        .map_err(|error| RouteSelectionError::InvalidOutput {
            destination,
            message: error.to_string(),
        })?;
    if let Some(fwmark) = fwmark {
        request = request.mark(fwmark);
    }

    let handle = route_netlink_handle().await?;
    let mut routes = handle.route().get(request.build()).execute();
    let message = routes
        .try_next()
        .await
        .map_err(|error| RouteSelectionError::Netlink {
            destination,
            message: error.to_string(),
        })?
        .ok_or_else(|| RouteSelectionError::QueryFailed {
            destination,
            message: "kernel returned no matching route".to_owned(),
        })?;

    let parsed = parse_netlink_route(destination, &message)?;
    let interface =
        get_interface_by_index(parsed.interface_index).ok_or_else(|| {
            RouteSelectionError::InterfaceNotFound {
                destination,
                interface_index: parsed.interface_index,
            }
        })?;

    Ok(RouteDecision {
        family: if destination.is_ipv4() {
            AddressFamily::Ipv4
        } else {
            AddressFamily::Ipv6
        },
        destination,
        interface_index: parsed.interface_index,
        interface_name: interface.name,
        gateway: parsed.gateway,
        preferred_source: parsed.preferred_source,
        table: parsed.table,
        metric: parsed.metric,
    })
}

#[cfg(all(feature = "tun", target_os = "windows"))]
fn windows_sockaddr_to_ip(
    address: &windows::Win32::Networking::WinSock::SOCKADDR_INET,
) -> Option<IpAddr> {
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let family = unsafe { address.si_family };
    let address = if family == AF_INET {
        IpAddr::V4(unsafe { address.Ipv4.sin_addr }.into())
    } else if family == AF_INET6 {
        IpAddr::V6(unsafe { address.Ipv6.sin6_addr }.into())
    } else {
        return None;
    };

    (!address.is_unspecified()).then_some(address)
}

#[cfg(all(feature = "tun", target_os = "windows"))]
pub async fn route_for_destination(
    destination: IpAddr,
    _fwmark: Option<u32>,
) -> std::result::Result<RouteDecision, RouteSelectionError> {
    use windows::Win32::{
        NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2},
        Networking::WinSock::SOCKADDR_INET,
    };

    let destination_address = SOCKADDR_INET::from(SocketAddr::new(destination, 0));
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut preferred_source = SOCKADDR_INET::default();
    let result = unsafe {
        GetBestRoute2(
            None,
            0,
            None,
            &destination_address,
            0,
            &mut route,
            &mut preferred_source,
        )
    };
    result
        .to_hresult()
        .ok()
        .map_err(|error| RouteSelectionError::QueryFailed {
            destination,
            message: error.message(),
        })?;

    let interface = get_interface_by_index(route.InterfaceIndex).ok_or(
        RouteSelectionError::InterfaceNotFound {
            destination,
            interface_index: route.InterfaceIndex,
        },
    )?;

    Ok(RouteDecision {
        family: if destination.is_ipv4() {
            AddressFamily::Ipv4
        } else {
            AddressFamily::Ipv6
        },
        destination,
        interface_index: route.InterfaceIndex,
        interface_name: interface.name,
        gateway: windows_sockaddr_to_ip(&route.NextHop),
        preferred_source: windows_sockaddr_to_ip(&preferred_source),
        table: 0,
        metric: Some(route.Metric),
    })
}

#[cfg(all(feature = "tun", target_os = "linux"))]
fn build_interface_route(
    destination: ipnet::IpNet,
    interface_index: u32,
) -> std::result::Result<
    rtnetlink::packet_route::route::RouteMessage,
    RouteSelectionError,
> {
    use rtnetlink::{RouteMessageBuilder, packet_route::route::RouteScope};

    Ok(RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(destination.addr(), destination.prefix_len())
        .map_err(|error| RouteSelectionError::NetlinkOperation {
            operation: "build",
            destination,
            message: error.to_string(),
        })?
        .output_interface(interface_index)
        .scope(RouteScope::Link)
        .build())
}

#[cfg(all(feature = "tun", target_os = "linux"))]
pub async fn add_route_to_interface(
    destination: ipnet::IpNet,
    interface_index: u32,
) -> std::result::Result<(), RouteSelectionError> {
    let route = build_interface_route(destination, interface_index)?;

    route_netlink_handle()
        .await?
        .route()
        .add(route)
        .execute()
        .await
        .map_err(|error| RouteSelectionError::NetlinkOperation {
            operation: "add",
            destination,
            message: error.to_string(),
        })
}

#[cfg(any(
    not(feature = "tun"),
    not(any(target_os = "linux", target_os = "windows"))
))]
pub async fn route_for_destination(
    _destination: IpAddr,
    _fwmark: Option<u32>,
) -> std::result::Result<RouteDecision, RouteSelectionError> {
    Err(RouteSelectionError::Unsupported)
}

#[cfg(not(feature = "tun"))]
pub fn get_interface_by_name(_name: &str) -> Option<OutboundInterface> {
    None
}

#[cfg(not(feature = "tun"))]
pub fn get_outbound_interface() -> Option<OutboundInterface> {
    None
}

#[cfg(feature = "tun")]
fn is_documentation_v6(addr: Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8
}

#[cfg(feature = "tun")]
fn is_global_unicast_like(addr: Ipv6Addr) -> bool {
    !addr.is_unspecified()
        && !addr.is_loopback()
        && !addr.is_multicast()
        && !addr.is_unicast_link_local()
        && !addr.is_unique_local()
        && !is_documentation_v6(addr)
}

#[cfg(feature = "tun")]
fn is_candidate_outbound_v6(addr: Ipv6Addr) -> bool {
    addr.is_unique_local() || is_global_unicast_like(addr)
}

#[cfg(all(feature = "tun", target_os = "windows"))]
async fn resolve_windows_fallback_interface(
    destination: IpAddr,
) -> Option<OutboundInterface> {
    route_for_destination(destination, None)
        .await
        .ok()
        .and_then(|route| get_interface_by_index(route.interface_index))
}

#[cfg(all(feature = "tun", target_os = "windows"))]
async fn refresh_windows_fallback_outbound_interfaces() {
    // GetBestRoute2 only inspects the route table; these probes do not send any
    // network traffic. Capture both families before the TUN split routes exist.
    let ipv4 =
        resolve_windows_fallback_interface(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .await;
    let ipv6 = resolve_windows_fallback_interface(IpAddr::V6(Ipv6Addr::new(
        0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
    )))
    .await;
    let interfaces = WindowsFallbackOutboundInterfaces { ipv4, ipv6 };
    trace!(?interfaces, "cached Windows fallback outbound interfaces");
    *WINDOWS_FALLBACK_OUTBOUND_INTERFACES.write().await = interfaces;
}

#[cfg(all(feature = "tun", target_os = "windows"))]
pub(crate) async fn set_windows_tun_interface_index(index: Option<u32>) {
    *WINDOWS_TUN_INTERFACE_INDEX.write().await = index;
}

#[cfg(all(feature = "tun", target_os = "windows"))]
pub(crate) async fn windows_tun_interface_index() -> Option<u32> {
    *WINDOWS_TUN_INTERFACE_INDEX.read().await
}

#[cfg(all(feature = "tun", target_os = "windows"))]
pub(crate) async fn windows_fallback_outbound_interface(
    destination: IpAddr,
) -> Option<OutboundInterface> {
    let interfaces = WINDOWS_FALLBACK_OUTBOUND_INTERFACES.read().await;
    if destination.is_ipv4() {
        interfaces.ipv4.clone()
    } else {
        interfaces.ipv6.clone()
    }
}

#[cfg(feature = "tun")]
pub async fn init_net_config(
    tun_somark: Option<u32>,
    interface: Option<&Interface>,
) -> Result<()> {
    let configured_interface = resolve_outbound_interface(interface).await?;
    #[cfg(target_os = "windows")]
    let should_cache_fallback = configured_interface.is_none();
    *DEFAULT_OUTBOUND_INTERFACE.write().await = configured_interface;
    *TUN_SOMARK.write().await = tun_somark;
    #[cfg(target_os = "windows")]
    {
        set_windows_tun_interface_index(None).await;
        if should_cache_fallback {
            refresh_windows_fallback_outbound_interfaces().await;
        } else {
            *WINDOWS_FALLBACK_OUTBOUND_INTERFACES.write().await =
                WindowsFallbackOutboundInterfaces::default();
        }
    }
    trace!(
        "default outbound interface: {:?}, tun somark: {:?}",
        *DEFAULT_OUTBOUND_INTERFACE.read().await,
        *TUN_SOMARK.read().await
    );
    Ok(())
}

#[cfg(feature = "tun")]
pub async fn clear_net_config() {
    *DEFAULT_OUTBOUND_INTERFACE.write().await = None;
    *TUN_SOMARK.write().await = None;
    #[cfg(target_os = "windows")]
    {
        set_windows_tun_interface_index(None).await;
        *WINDOWS_FALLBACK_OUTBOUND_INTERFACES.write().await =
            WindowsFallbackOutboundInterfaces::default();
    }
}

/// Represents a parsed outbound interface for use in runtime.
#[derive(Serialize, Debug, Clone)]
pub struct OutboundInterface {
    pub name: String,
    pub addr_v4: Option<Ipv4Addr>,
    pub netmask_v4: Option<Ipv4Addr>,
    pub broadcast_v4: Option<Ipv4Addr>,
    pub addr_v6: Option<Ipv6Addr>,
    pub netmask_v6: Option<Ipv6Addr>,
    pub broadcast_v6: Option<Ipv6Addr>,
    pub index: u32,
    pub mac_addr: Option<String>,
}

#[cfg(feature = "tun")]
impl From<NetworkInterface> for OutboundInterface {
    fn from(iface: NetworkInterface) -> Self {
        fn get_outbound_ip_from_interface(
            iface: &NetworkInterface,
        ) -> (Option<V4IfAddr>, Option<V6IfAddr>) {
            let mut v4 = None;
            let mut v6 = None;

            for addr in &iface.addr {
                trace!("inspect interface address: {:?} on {}", addr, iface.name);

                if v4.is_some() && v6.is_some() {
                    break;
                }

                match addr {
                    network_interface::Addr::V4(addr) => {
                        if !addr.ip.is_loopback()
                            && !addr.ip.is_link_local()
                            && !addr.ip.is_unspecified()
                        {
                            v4 = Some(*addr);
                        }
                    }
                    network_interface::Addr::V6(addr) => {
                        if is_candidate_outbound_v6(addr.ip) {
                            v6 = Some(*addr);
                        }
                    }
                }
            }

            (v4, v6)
        }

        let addr = get_outbound_ip_from_interface(&iface);
        OutboundInterface {
            name: iface.name,
            addr_v4: addr.0.map(|x| x.ip),
            netmask_v4: addr.0.and_then(|x| x.netmask),
            broadcast_v4: addr.0.and_then(|x| x.broadcast),
            addr_v6: addr.1.map(|x| x.ip),
            netmask_v6: addr.1.and_then(|x| x.netmask),
            broadcast_v6: addr.1.and_then(|x| x.broadcast),
            index: iface.index,
            mac_addr: iface.mac_addr,
        }
    }
}

impl std::fmt::Display for OutboundInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (v4: {}, v6: {}, index: {}, mac: {})",
            self.name,
            self.addr_v4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.addr_v6
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.index,
            self.mac_addr.clone().unwrap_or_else(|| "None".to_string())
        )
    }
}

#[cfg(feature = "tun")]
pub fn get_interface_by_name(name: &str) -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let outbound = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .find(|iface| iface.name == name)?
        .into();

    trace!(
        "found interface by name: {:?}, took: {}ms",
        outbound,
        now.elapsed().as_millis()
    );

    Some(outbound)
}

#[cfg(all(feature = "tun", any(target_os = "linux", target_os = "windows")))]
fn get_interface_by_index(index: u32) -> Option<OutboundInterface> {
    network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .find(|interface| interface.index == index)
        .map(Into::into)
}

#[cfg(feature = "tun")]
pub fn get_interface_by_ip(ip: IpAddr) -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let outbound = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .find(|iface| {
            iface.addr.iter().any(|addr| match (ip, addr) {
                (IpAddr::V4(target), network_interface::Addr::V4(addr)) => {
                    addr.ip == target
                }
                (IpAddr::V6(target), network_interface::Addr::V6(addr)) => {
                    addr.ip == target
                }
                _ => false,
            })
        })?
        .into();

    trace!(
        "found interface by ip: {:?}, took: {}ms",
        outbound,
        now.elapsed().as_millis()
    );

    Some(outbound)
}

#[cfg(all(feature = "tun", target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxOperState {
    Unknown,
    Down,
    Up,
    Other,
}

#[cfg(all(feature = "tun", target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxInterfaceState {
    index: u32,
    name: String,
    admin_up: bool,
    lower_up: Option<bool>,
    oper_state: Option<LinuxOperState>,
    carrier: Option<bool>,
}

#[cfg(all(feature = "tun", target_os = "linux"))]
fn validate_linux_interface_state(
    interface: &OutboundInterface,
    state: &LinuxInterfaceState,
) -> Result<()> {
    let families = match (interface.addr_v4.is_some(), interface.addr_v6.is_some()) {
        (true, true) => "IPv4/IPv6",
        (true, false) => "IPv4",
        (false, true) => "IPv6",
        (false, false) => "none",
    };

    if !state.admin_up {
        return Err(Error::InvalidConfig(format!(
            "configured outbound interface \"{}\" is not administratively UP: \
             index={}, family={families}, admin_up={}, lower_up={:?}, \
             oper_state={:?}, carrier={:?}; enable the interface or choose \
             another interface-name",
            state.name,
            state.index,
            state.admin_up,
            state.lower_up,
            state.oper_state,
            state.carrier,
        )));
    }

    Ok(())
}

#[cfg(all(feature = "tun", target_os = "linux"))]
async fn inspect_linux_interface_state(
    interface: &OutboundInterface,
) -> Result<LinuxInterfaceState> {
    use futures::TryStreamExt;
    use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, State};

    let handle = route_netlink_handle().await.map_err(|error| {
        Error::InvalidConfig(format!(
            "failed to inspect configured outbound interface \"{}\" via \
             rtnetlink: index={}, error={error}",
            interface.name, interface.index
        ))
    })?;
    let mut links = handle.link().get().match_index(interface.index).execute();
    let message = links
        .try_next()
        .await
        .map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to inspect configured outbound interface \"{}\" via \
                 rtnetlink: index={}, error={error}",
                interface.name, interface.index
            ))
        })?
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "configured outbound interface \"{}\" disappeared during \
                 rtnetlink inspection: index={}",
                interface.name, interface.index
            ))
        })?;

    let mut oper_state = None;
    let mut carrier = None;
    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::OperState(value) => {
                oper_state = Some(match value {
                    State::Unknown => LinuxOperState::Unknown,
                    State::Down | State::LowerLayerDown => LinuxOperState::Down,
                    State::Up => LinuxOperState::Up,
                    _ => LinuxOperState::Other,
                });
            }
            LinkAttribute::Carrier(value) => carrier = Some(*value != 0),
            _ => {}
        }
    }

    Ok(LinuxInterfaceState {
        index: message.header.index,
        name: interface.name.clone(),
        admin_up: message.header.flags.contains(LinkFlags::Up),
        lower_up: Some(message.header.flags.contains(LinkFlags::LowerUp)),
        oper_state,
        carrier,
    })
}

#[cfg(all(feature = "tun", target_os = "linux"))]
async fn validate_configured_interface_state(
    interface: &OutboundInterface,
) -> Result<()> {
    let state = inspect_linux_interface_state(interface).await?;
    validate_linux_interface_state(interface, &state)
}

#[cfg(all(feature = "tun", target_os = "windows"))]
async fn validate_configured_interface_state(
    interface: &OutboundInterface,
) -> Result<()> {
    use windows::Win32::NetworkManagement::{
        IpHelper::{GetIfEntry2, MIB_IF_ROW2},
        Ndis::{
            IfOperStatusDown, IfOperStatusLowerLayerDown, IfOperStatusNotPresent,
            IfOperStatusTesting, MediaConnectStateDisconnected,
            NET_IF_ADMIN_STATUS_UP,
        },
    };

    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: interface.index,
        ..Default::default()
    };
    let result = unsafe { GetIfEntry2(&mut row) };
    result.to_hresult().ok().map_err(|error| {
        Error::InvalidConfig(format!(
            "failed to inspect configured outbound interface \"{}\" via \
             GetIfEntry2: index={}, error={}",
            interface.name,
            interface.index,
            error.message()
        ))
    })?;

    if row.AdminStatus != NET_IF_ADMIN_STATUS_UP {
        return Err(Error::InvalidConfig(format!(
            "configured outbound interface \"{}\" is not administratively UP: \
             index={}, admin_status={:?}; enable the interface or choose another \
             interface-name",
            interface.name, interface.index, row.AdminStatus
        )));
    }

    if row.OperStatus == IfOperStatusDown
        || row.OperStatus == IfOperStatusLowerLayerDown
        || row.OperStatus == IfOperStatusNotPresent
        || row.OperStatus == IfOperStatusTesting
    {
        return Err(Error::InvalidConfig(format!(
            "configured outbound interface \"{}\" is not operational: index={}, \
             oper_status={:?}, media_state={:?}; connect the interface or choose \
             another interface-name",
            interface.name, interface.index, row.OperStatus, row.MediaConnectState
        )));
    }

    if row.MediaConnectState == MediaConnectStateDisconnected {
        return Err(Error::InvalidConfig(format!(
            "configured outbound interface \"{}\" has no connected media: \
             index={}, oper_status={:?}, media_state={:?}; connect the interface \
             or choose another interface-name",
            interface.name, interface.index, row.OperStatus, row.MediaConnectState
        )));
    }

    Ok(())
}

#[cfg(all(feature = "tun", not(any(target_os = "linux", target_os = "windows"))))]
async fn validate_configured_interface_state(
    _interface: &OutboundInterface,
) -> Result<()> {
    Ok(())
}

#[cfg(feature = "tun")]
pub async fn resolve_outbound_interface(
    interface: Option<&Interface>,
) -> Result<Option<OutboundInterface>> {
    let Some(interface) = interface else {
        return Ok(None);
    };

    let configured = match interface {
        Interface::IpAddr(ip) => get_interface_by_ip(*ip),
        Interface::Name(name) => get_interface_by_name(name),
    }
    .ok_or_else(|| {
        Error::InvalidConfig(format!(
            "configured outbound interface \"{interface}\" does not exist"
        ))
    })?;

    if configured.addr_v4.is_none() && configured.addr_v6.is_none() {
        return Err(Error::InvalidConfig(format!(
            "configured outbound interface \"{}\" has no usable IP address",
            configured.name
        )));
    }

    validate_configured_interface_state(&configured).await?;

    Ok(Some(configured))
}

#[cfg(feature = "tun")]
pub fn get_outbound_interface() -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let mut all_outbounds = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .map(Into::into)
        .filter(|iface: &OutboundInterface| {
            !iface.name.contains("tun")
                && (iface.addr_v4.is_some() || iface.addr_v6.is_some())
        })
        .collect::<Vec<_>>();

    let priority: &[&str] = if cfg!(target_os = "android") {
        &[
            "wlan",  // Android Wi-Fi interface
            "rmnet", // Android mobile data interface
        ]
    } else if cfg!(target_os = "windows") {
        &["Ethernet", "Wi-Fi", "Tailscale"]
    } else if cfg!(target_os = "linux") {
        &["eth", "wlp", "en", "Tailscale"]
    } else if cfg!(target_os = "macos") {
        &["en", "pdp_ip", "Tailscale"]
    } else {
        &["eth", "en", "wlp"]
    };

    all_outbounds.sort_by(|left, right| {
        match (left.addr_v6, right.addr_v6) {
            (Some(_), None) => return std::cmp::Ordering::Less,
            (None, Some(_)) => return std::cmp::Ordering::Greater,
            (Some(left), Some(right)) => {
                if left.is_unicast_global() && !right.is_unicast_global() {
                    return std::cmp::Ordering::Less;
                } else if !left.is_unicast_global() && right.is_unicast_global() {
                    return std::cmp::Ordering::Greater;
                }
            }
            _ => {}
        }
        let left = priority
            .iter()
            .position(|x| left.name.contains(x) && left.name.starts_with(x))
            .unwrap_or(usize::MAX);
        let right = priority
            .iter()
            .position(|x| right.name.contains(x) && right.name.starts_with(x))
            .unwrap_or(usize::MAX);

        left.cmp(&right)
    });

    trace!(
        "sorted outbound interfaces: {:?}, took: {}ms",
        all_outbounds,
        now.elapsed().as_millis()
    );

    all_outbounds.into_iter().next()
}

/// Represents a network interface in configuration.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum Interface {
    IpAddr(IpAddr),
    Name(String),
}

impl From<&str> for Interface {
    fn from(s: &str) -> Self {
        Self::Name(s.to_owned())
    }
}

impl From<IpAddr> for Interface {
    fn from(ip: IpAddr) -> Self {
        Self::IpAddr(ip)
    }
}

impl Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interface::IpAddr(ip) => write!(f, "{ip}"),
            Interface::Name(name) => write!(f, "{name}"),
        }
    }
}

impl Interface {
    pub fn into_ip_addr(self) -> Option<IpAddr> {
        match self {
            Interface::IpAddr(ip) => Some(ip),
            _ => None,
        }
    }

    pub fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Interface::IpAddr(ip) => Some(SocketAddr::new(ip, 0)),
            _ => None,
        }
    }

    pub fn into_iface_name(self) -> Option<String> {
        match self {
            Interface::IpAddr(_) => None,
            Interface::Name(name) => Some(name),
        }
    }
}

#[cfg(all(test, feature = "tun"))]
mod tests {
    #[cfg(target_os = "linux")]
    use super::OutboundInterface;
    use super::{Interface, resolve_outbound_interface};
    use crate::Error;

    #[cfg(target_os = "linux")]
    fn test_interface() -> OutboundInterface {
        OutboundInterface {
            name: "test0".to_owned(),
            addr_v4: Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            netmask_v4: None,
            broadcast_v4: None,
            addr_v6: None,
            netmask_v6: None,
            broadcast_v6: None,
            index: 42,
            mac_addr: None,
        }
    }

    #[tokio::test]
    async fn configured_interface_does_not_fall_back_when_missing() {
        let interface = Interface::Name("__chimera_missing_interface__".to_owned());

        let error = resolve_outbound_interface(Some(&interface))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            Error::InvalidConfig(message)
                if message
                    == "configured outbound interface \
                       \"__chimera_missing_interface__\" does not exist"
        ));
    }

    #[tokio::test]
    async fn unconfigured_interface_does_not_guess_an_outbound() {
        assert!(resolve_outbound_interface(None).await.unwrap().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_sockaddr_conversion_preserves_family_and_ignores_unspecified() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
        use windows::Win32::Networking::WinSock::SOCKADDR_INET;

        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10));
        let ipv4_sockaddr = SOCKADDR_INET::from(SocketAddr::new(ipv4, 0));
        let ipv6_sockaddr = SOCKADDR_INET::from(SocketAddr::new(ipv6, 0));
        let unspecified = SOCKADDR_INET::from(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        ));

        assert_eq!(super::windows_sockaddr_to_ip(&ipv4_sockaddr), Some(ipv4));
        assert_eq!(super::windows_sockaddr_to_ip(&ipv6_sockaddr), Some(ipv6));
        assert_eq!(super::windows_sockaddr_to_ip(&unspecified), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn netlink_interface_state_requires_admin_up() {
        let interface = test_interface();
        let state = super::LinuxInterfaceState {
            index: 42,
            name: "test0".to_owned(),
            admin_up: false,
            lower_up: Some(true),
            oper_state: Some(super::LinuxOperState::Up),
            carrier: Some(true),
        };
        let down =
            super::validate_linux_interface_state(&interface, &state).unwrap_err();
        assert!(matches!(
            down,
            Error::InvalidConfig(message)
                if message.contains("is not administratively UP")
                    && message.contains("index=42")
                    && message.contains("family=IPv4")
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sysfs_0x1003_does_not_override_healthy_netlink_state() {
        let interface = test_interface();
        let sysfs_flags = 0x1003_u32;
        assert_eq!(sysfs_flags & libc::IFF_RUNNING as u32, 0);

        let state = super::LinuxInterfaceState {
            index: 42,
            name: "test0".to_owned(),
            admin_up: true,
            lower_up: Some(true),
            oper_state: Some(super::LinuxOperState::Up),
            carrier: Some(true),
        };
        super::validate_linux_interface_state(&interface, &state).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unknown_operstate_and_carrier_do_not_mean_down() {
        let interface = test_interface();
        let state = super::LinuxInterfaceState {
            index: 42,
            name: "test0".to_owned(),
            admin_up: true,
            lower_up: None,
            oper_state: Some(super::LinuxOperState::Unknown),
            carrier: None,
        };

        super::validate_linux_interface_state(&interface, &state).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_route_decision_fields() {
        use std::net::IpAddr;

        use rtnetlink::RouteMessageBuilder;

        let destination = "185.148.13.16".parse().unwrap();
        let message = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(destination, 32)
            .unwrap()
            .output_interface(42)
            .gateway("192.168.1.1".parse().unwrap())
            .unwrap()
            .pref_source("192.168.1.9".parse().unwrap())
            .unwrap()
            .table_id(100)
            .priority(20)
            .build();
        let route = super::parse_netlink_route(destination, &message).unwrap();

        assert_eq!(route.interface_index, 42);
        assert_eq!(route.gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(route.preferred_source, Some("192.168.1.9".parse().unwrap()));
        assert_eq!(route.table, 100);
        assert_eq!(route.metric, Some(20));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_parser_defaults_to_main_table() {
        use std::net::IpAddr;

        use rtnetlink::RouteMessageBuilder;

        let destination = "2606:4700::1111".parse().unwrap();
        let message = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(destination, 128)
            .unwrap()
            .output_interface(7)
            .pref_source("fd00::2".parse().unwrap())
            .unwrap()
            .priority(5)
            .build();
        let route = super::parse_netlink_route(destination, &message).unwrap();

        assert_eq!(route.interface_index, 7);
        assert_eq!(route.gateway, None);
        assert_eq!(route.table, 254);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn builds_link_scoped_interface_route() {
        use rtnetlink::packet_route::route::{RouteAttribute, RouteScope};

        let destination = "fd00:198:18::/64".parse().unwrap();
        let message = super::build_interface_route(destination, 42).unwrap();

        assert_eq!(message.header.destination_prefix_length, 64);
        assert_eq!(message.header.scope, RouteScope::Link);
        assert!(
            message
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, RouteAttribute::Oif(42)))
        );
        assert!(message.attributes.iter().any(|attribute| matches!(
            attribute,
            RouteAttribute::Destination(address)
                if super::route_address_to_ip(address)
                    == Some("fd00:198:18::".parse().unwrap())
        )));
    }
}
