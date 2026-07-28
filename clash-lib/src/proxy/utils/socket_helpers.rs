#[cfg(all(feature = "tun", target_os = "windows"))]
use std::net::IpAddr;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use socket2::TcpKeepalive;

use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;
#[cfg(all(feature = "tun", target_os = "windows"))]
use tracing::warn;
use tracing::{debug, error, instrument, trace};

use crate::app::net::OutboundInterface;
#[cfg(feature = "tun")]
use crate::app::net::{DEFAULT_OUTBOUND_INTERFACE, TUN_ENABLED};
#[cfg(all(feature = "tun", any(target_os = "linux", target_os = "windows")))]
use crate::app::net::{get_interface_by_name, route_for_destination};
#[cfg(all(feature = "tun", target_os = "windows"))]
use crate::app::net::{
    windows_fallback_outbound_interface, windows_tun_interface_index,
};
#[cfg(all(feature = "tun", any(target_os = "linux", target_os = "windows")))]
use crate::common::errors::new_io_error;
use crate::proxy::utils::platform::{
    maybe_protect_socket, must_bind_socket_on_interface,
};

// todo: support in linux to protect dataflow.
#[allow(unused)]
fn bind_addr_for_iface(
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> Option<SocketAddr> {
    match family {
        socket2::Domain::IPV4 => iface.addr_v4.map(|ip| SocketAddr::from((ip, 0))),
        socket2::Domain::IPV6 => iface.addr_v6.map(|ip| SocketAddr::from((ip, 0))),
        _ => None,
    }
}

fn should_prefer_ipv4_udp_socket(iface: Option<&OutboundInterface>) -> bool {
    iface
        .map(|iface| iface.addr_v4.is_some() && iface.addr_v6.is_none())
        .unwrap_or(false)
}

pub fn apply_tcp_options(s: &TcpStream) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        let sock_ref = socket2::SockRef::from(s);
        sock_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;
    }
    #[cfg(target_os = "windows")]
    {
        let sock_ref = socket2::SockRef::from(s);
        sock_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )?;
    }
    s.set_nodelay(true)
}

/// Create dualstack socket if it can
/// If failed, fallback to single stack silently
pub fn try_create_dualstack_socket(
    addr: SocketAddr,
    tcp_or_udp: socket2::Type,
) -> std::io::Result<(socket2::Socket, bool)> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let mut dualstack = false;
    let socket = socket2::Socket::new(domain, tcp_or_udp, None)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        if let Err(e) = socket.set_only_v6(false) {
            // If setting dualstack fails, fallback to single stack
            tracing::warn!(
                "dualstack not supported, falling back to ipv6 only: {e}"
            );
        } else {
            dualstack = true;
        }
    };
    Ok((socket, dualstack))
}

pub fn try_create_dualstack_tcplistener(
    addr: SocketAddr,
) -> io::Result<TcpListener> {
    let (socket, _dualstack) =
        try_create_dualstack_socket(addr, socket2::Type::STREAM)?;

    socket.set_nonblocking(true)?;
    // For fast restart avoid Address In Use Error
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}

/// Create a dual-stack UDP socket bound to `[::]`, falling back to an IPv4
/// socket bound to `0.0.0.0` if IPv6 is unavailable. The socket can be reused
/// for destinations from different address families.
pub fn new_dual_stack_udp_socket(
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<UdpSocket> {
    let dual_stack = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let ipv4_only = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let prefer_ipv4 = should_prefer_ipv4_udp_socket(iface);

    let (socket, bind_addr) = if prefer_ipv4 {
        (
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
            ipv4_only,
        )
    } else {
        match try_create_dualstack_socket(dual_stack, socket2::Type::DGRAM) {
            Ok((socket, true)) => (socket, dual_stack),
            Ok((_, false)) | Err(_) => (
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    None,
                )?,
                ipv4_only,
            ),
        }
    };

    if let Some(iface) = iface {
        let family = socket2::Domain::for_address(bind_addr);
        must_bind_socket_on_interface(&socket, iface, family).inspect_err(|x| {
            error!("failed to bind socket to interface: {}", x);
        })?;
    }

    socket.bind(&bind_addr.into())?;
    trace!(addr = ?bind_addr, iface = ?iface, "dual-stack udp socket bound");

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    #[cfg(target_os = "android")]
    maybe_protect_socket(&socket)?;
    #[cfg(not(target_os = "android"))]
    if iface.is_none() {
        maybe_protect_socket(&socket)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

#[cfg(feature = "tun")]
fn select_effective_iface<'a>(
    explicit: Option<&'a OutboundInterface>,
    default: &'a Option<OutboundInterface>,
) -> Option<&'a OutboundInterface> {
    explicit.or(default.as_ref())
}

#[cfg(all(feature = "tun", any(target_os = "linux", target_os = "windows")))]
fn should_auto_bind_destination(
    destination: std::net::IpAddr,
    has_effective_iface: bool,
    tun_enabled: bool,
) -> bool {
    tun_enabled && !has_effective_iface && !destination.is_loopback()
}

#[cfg(feature = "tun")]
async fn default_outbound_interface() -> Option<OutboundInterface> {
    DEFAULT_OUTBOUND_INTERFACE.read().await.clone()
}

#[cfg(feature = "tun")]
async fn effective_interface_for_destination(
    destination: Option<std::net::IpAddr>,
    explicit: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<Option<OutboundInterface>> {
    let default_iface = default_outbound_interface().await;
    let effective_iface = select_effective_iface(explicit, &default_iface).cloned();

    #[cfg(target_os = "linux")]
    let effective_iface = {
        let mut effective_iface = effective_iface;
        if let Some(destination) = destination
            && should_auto_bind_destination(
                destination,
                effective_iface.is_some(),
                TUN_ENABLED.load(std::sync::atomic::Ordering::Acquire),
            )
        {
            let route = route_for_destination(destination, so_mark)
                .await
                .map_err(new_io_error)?;
            debug!(
                destination = %destination,
                interface = %route.interface_name,
                interface_index = route.interface_index,
                gateway = ?route.gateway,
                preferred_source = ?route.preferred_source,
                table = route.table,
                metric = ?route.metric,
                fwmark = ?so_mark,
                "selected outbound route"
            );
            effective_iface = Some(
                get_interface_by_name(&route.interface_name).ok_or_else(|| {
                    new_io_error(format!(
                        "route interface \"{}\" disappeared before connecting \
                             to {destination}",
                        route.interface_name
                    ))
                })?,
            );
        }
        effective_iface
    };

    #[cfg(target_os = "windows")]
    let effective_iface = {
        let mut effective_iface = effective_iface;
        if let Some(destination) = destination
            && should_auto_bind_destination(
                destination,
                effective_iface.is_some(),
                TUN_ENABLED.load(std::sync::atomic::Ordering::Acquire),
            )
        {
            let tun_interface_index = windows_tun_interface_index().await;
            let selected = match route_for_destination(destination, None).await {
                Ok(route) if tun_interface_index == Some(route.interface_index) => {
                    let fallback = windows_fallback_outbound_interface(destination)
                        .await
                        .ok_or_else(|| {
                            new_io_error(format!(
                                "Windows route for {destination} resolves to the \
                                 Chimera TUN interface (index {}) and no pre-TUN \
                                 fallback interface is available",
                                route.interface_index
                            ))
                        })?;
                    if fallback.index == route.interface_index {
                        return Err(new_io_error(format!(
                            "cached Windows fallback interface for {destination} \
                             is the Chimera TUN interface itself (index {})",
                            route.interface_index
                        )));
                    }
                    warn!(
                        destination = %destination,
                        tun_interface_index = route.interface_index,
                        fallback_interface = %fallback.name,
                        fallback_interface_index = fallback.index,
                        "Windows best route points at TUN; using the pre-TUN fallback interface"
                    );
                    Some(fallback)
                }
                Ok(route) => {
                    debug!(
                        destination = %destination,
                        interface = %route.interface_name,
                        interface_index = route.interface_index,
                        gateway = ?route.gateway,
                        preferred_source = ?route.preferred_source,
                        metric = ?route.metric,
                        "selected Windows outbound route"
                    );
                    if let Some(interface) =
                        get_interface_by_name(&route.interface_name)
                    {
                        Some(interface)
                    } else if let Some(fallback) =
                        windows_fallback_outbound_interface(destination).await
                    {
                        warn!(
                            destination = %destination,
                            route_interface = %route.interface_name,
                            fallback_interface = %fallback.name,
                            fallback_interface_index = fallback.index,
                            "Windows route interface disappeared; using the pre-TUN fallback interface"
                        );
                        Some(fallback)
                    } else if tun_interface_index.is_none() {
                        warn!(
                            destination = %destination,
                            route_interface = %route.interface_name,
                            "Windows route interface disappeared; leaving the socket unbound for system routing"
                        );
                        None
                    } else {
                        return Err(new_io_error(format!(
                            "route interface \"{}\" disappeared before connecting \
                             to {destination}, and no pre-TUN fallback interface is \
                             available",
                            route.interface_name
                        )));
                    }
                }
                Err(error) => {
                    if let Some(fallback) =
                        windows_fallback_outbound_interface(destination).await
                    {
                        warn!(
                            destination = %destination,
                            fallback_interface = %fallback.name,
                            fallback_interface_index = fallback.index,
                            error = %error,
                            "Windows route lookup failed; using the pre-TUN fallback interface"
                        );
                        Some(fallback)
                    } else if tun_interface_index.is_none() {
                        warn!(
                            destination = %destination,
                            error = %error,
                            "Windows route lookup failed before TUN routing; leaving the socket unbound for system routing"
                        );
                        None
                    } else {
                        return Err(new_io_error(error.to_string()));
                    }
                }
            };
            effective_iface = selected;
        }
        effective_iface
    };

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let effective_iface = {
        let _ = destination;
        effective_iface
    };

    Ok(effective_iface)
}

/// Create an outbound TCP socket protected from being routed back into TUN.
///
/// A per-session or configured interface wins. On Linux, automatic mode
/// queries the kernel route for this concrete destination before binding.
pub async fn new_protected_tcp_stream(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    #[cfg(feature = "tun")]
    {
        let effective_iface = effective_interface_for_destination(
            Some(endpoint.ip()),
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await?;
        return new_tcp_stream(
            endpoint,
            effective_iface.as_ref(),
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await;
    }

    #[cfg(not(feature = "tun"))]
    {
        new_tcp_stream(
            endpoint,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await
    }
}

/// Create an outbound dual-stack UDP socket protected from TUN re-entry.
pub async fn new_protected_dual_stack_udp_socket(
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<UdpSocket> {
    #[cfg(feature = "tun")]
    {
        let default_iface = default_outbound_interface().await;
        #[cfg(target_os = "windows")]
        let automatic_iface = if select_effective_iface(iface, &default_iface)
            .is_none()
            && windows_tun_interface_index().await.is_some()
        {
            let mut fallback = windows_fallback_outbound_interface(IpAddr::V4(
                Ipv4Addr::UNSPECIFIED,
            ))
            .await;
            if fallback.is_none() {
                fallback = windows_fallback_outbound_interface(IpAddr::V6(
                    Ipv6Addr::UNSPECIFIED,
                ))
                .await;
            }
            if let Some(fallback) = fallback.as_ref() {
                warn!(
                    interface = %fallback.name,
                    interface_index = fallback.index,
                    "pinning multi-destination Windows UDP socket to the pre-TUN fallback interface"
                );
            }
            fallback
        } else {
            None
        };
        #[cfg(target_os = "windows")]
        let effective_iface = select_effective_iface(iface, &default_iface)
            .cloned()
            .or(automatic_iface);
        #[cfg(not(target_os = "windows"))]
        let effective_iface = select_effective_iface(iface, &default_iface).cloned();
        return new_dual_stack_udp_socket(
            effective_iface.as_ref(),
            #[cfg(target_os = "linux")]
            so_mark,
        );
    }

    #[cfg(not(feature = "tun"))]
    {
        new_dual_stack_udp_socket(
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
    }
}

/// Convert ipv6 mapped ipv4 address back to ipv4. Other address remain
/// unchanged. e.g. ::ffff:127.0.0.1 -> 127.0.0.1
pub trait ToCanonical {
    fn to_canonical(self) -> SocketAddr;
}

impl ToCanonical for SocketAddr {
    fn to_canonical(mut self) -> SocketAddr {
        self.set_ip(self.ip().to_canonical());
        self
    }
}

// #[instrument(skip(so_mark))]
pub async fn new_tcp_stream(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    #[cfg(target_os = "windows")]
    const MAX_RETRY_ATTEMPTS: usize = 3;

    #[cfg(not(target_os = "windows"))]
    {
        let socket = prepare_outbound_tcp_socket(
            endpoint,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )?;
        return timeout(
            TCP_CONNECT_TIMEOUT,
            TcpSocket::from_std_stream(socket.into()).connect(endpoint),
        )
        .await?;
    }

    #[cfg(target_os = "windows")]
    {
        let mut last_err = None;

        for attempt in 0..MAX_RETRY_ATTEMPTS {
            let socket = prepare_outbound_tcp_socket(
                endpoint,
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
            )?;

            match timeout(
                TCP_CONNECT_TIMEOUT,
                TcpSocket::from_std_stream(socket.into()).connect(endpoint),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(err))
                    if should_retry_tcp_connect(&err)
                        && attempt + 1 < MAX_RETRY_ATTEMPTS =>
                {
                    tracing::warn!(
                        endpoint = %endpoint,
                        attempt = attempt + 1,
                        max_attempts = MAX_RETRY_ATTEMPTS,
                        err = ?err,
                        "tcp connect hit a transient local address conflict; recreating socket and retrying"
                    );
                    last_err = Some(err);
                    tokio::time::sleep(Duration::from_millis(
                        25 * (attempt as u64 + 1),
                    ))
                    .await;
                }
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(err.into()),
            }
        }

        return Err(last_err.unwrap_or_else(|| {
            io::Error::other(
                "tcp connect retry loop exited without a captured error",
            )
        }));
    }
}

fn prepare_outbound_tcp_socket(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<socket2::Socket> {
    let (socket, family) = match endpoint {
        SocketAddr::V4(_) => (
            socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV4,
        ),
        SocketAddr::V6(_) => (
            socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV6,
        ),
    };
    debug!("created tcp socket");

    if let Some(iface) = iface.filter(|_| !endpoint.ip().is_loopback()) {
        must_bind_socket_on_interface(&socket, iface, family)?;
        #[cfg(target_os = "windows")]
        if let Some(addr) = bind_addr_for_iface(iface, family) {
            socket.bind(&addr.into())?;
        }
        trace!(iface = ?iface, "tcp socket prepared for outbound interface");
    }
    #[cfg(target_os = "android")]
    maybe_protect_socket(&socket)?;
    #[cfg(not(target_os = "android"))]
    if iface.is_none() {
        maybe_protect_socket(&socket)?;
    }

    #[cfg(not(target_os = "android"))]
    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_keepalive(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;

    Ok(socket)
}

#[cfg(target_os = "windows")]
fn should_retry_tcp_connect(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(10048))
}

#[instrument(skip(so_mark))]
pub async fn new_udp_socket(
    src: Option<SocketAddr>,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
    // Optional family hint for the socket.
    // If not provided, the family will be determined based on the source
    // address or interface.
    family_hint: Option<std::net::SocketAddr>,
) -> std::io::Result<UdpSocket> {
    // Determine the socket family based on the source address or interface
    // logic:
    // - If family_hint is provided, use it.
    // - If src is provided and is IPv6, use IPv6.
    // - If iface is provided and is IPv6, use IPv6.
    // - Otherwise, default to IPv4.
    let (socket, family) = match (family_hint, src, iface) {
        (Some(family_hint), ..) => {
            let domain = socket2::Domain::for_address(family_hint);
            (
                socket2::Socket::new(domain, socket2::Type::DGRAM, None)?,
                domain,
            )
        }
        (None, Some(src), _) if src.is_ipv6() => (
            try_create_dualstack_socket(src, socket2::Type::DGRAM)?.0,
            socket2::Domain::IPV6,
        ),
        (None, _, Some(iface)) if iface.addr_v6.is_some() => (
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV6,
        ),
        _ => (
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV4,
        ),
    };
    debug!("created udp socket");

    if !cfg!(target_os = "android") {
        // Skip interface binding for loopback destinations; binding to a
        // physical outbound interface prevents localhost routes from working.
        let dst_is_loopback = family_hint
            .map(|addr| addr.ip().is_loopback())
            .unwrap_or(false);
        match (src, iface) {
            (_, Some(iface)) if !dst_is_loopback => {
                must_bind_socket_on_interface(&socket, iface, family).inspect_err(
                    |x| {
                        error!("failed to bind socket to interface: {}", x);
                    },
                )?;
                // binding is not necessary for linux but is required on windows
                // Without binding local_addr can't be obtained by system call
                // which is required on quinn.
                #[cfg(target_os = "windows")]
                {
                    let bind_addr =
                        src.or_else(|| bind_addr_for_iface(iface, family));
                    if let Some(addr) = bind_addr {
                        socket.bind(&socket2::SockAddr::from(addr))?;
                    }
                }

                trace!(iface = ?iface, "udp socket bound: {socket:?}");
            }
            (Some(src), _) => {
                socket.bind(&src.into())?;
                trace!(src = ?src, "udp socket bound: {socket:?}");
            }
            (None, _) => {
                // On Windows, UDP sockets must be bound to get a valid local_addr
                // which is required for some operations (e.g., quinn/QUIC)
                #[cfg(target_os = "windows")]
                {
                    let bind_addr = match family {
                        socket2::Domain::IPV4 => {
                            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
                        }
                        socket2::Domain::IPV6 => {
                            "[::]:0".parse::<SocketAddr>().unwrap()
                        }
                        _ => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
                    };
                    socket.bind(&socket2::SockAddr::from(bind_addr))?;
                    trace!(addr = ?bind_addr, "udp socket bound to default address on Windows: {socket:?}");
                }
                #[cfg(not(target_os = "windows"))]
                trace!("udp socket not bound to any specific address: {socket:?}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    #[cfg(target_os = "android")]
    maybe_protect_socket(&socket)?;
    #[cfg(not(target_os = "android"))]
    if iface.is_none() {
        maybe_protect_socket(&socket)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

/// Create an outbound UDP socket protected from being routed back into TUN.
pub async fn new_protected_udp_socket(
    src: Option<SocketAddr>,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
    family_hint: Option<std::net::SocketAddr>,
) -> std::io::Result<UdpSocket> {
    #[cfg(feature = "tun")]
    {
        let effective_iface = effective_interface_for_destination(
            family_hint.map(|address| address.ip()),
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await?;
        return new_udp_socket(
            src,
            effective_iface.as_ref(),
            #[cfg(target_os = "linux")]
            so_mark,
            family_hint,
        )
        .await;
    }

    #[cfg(not(feature = "tun"))]
    {
        new_udp_socket(
            src,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            family_hint,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV6},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio::net::UdpSocket;

    #[cfg(feature = "tun")]
    use super::select_effective_iface;
    #[cfg(all(
        feature = "tun",
        any(target_os = "linux", target_os = "windows")
    ))]
    use super::should_auto_bind_destination;
    use super::{
        new_dual_stack_udp_socket, new_udp_socket, should_prefer_ipv4_udp_socket,
    };
    use crate::app::net::OutboundInterface;
    use crate::proxy::utils::{
        SocketProtector, clear_socket_protector, set_socket_protector,
    };

    struct CountingProtector {
        calls: Arc<AtomicUsize>,
    }

    #[cfg(feature = "tun")]
    #[test]
    fn protected_socket_prefers_explicit_interface_over_default() {
        let explicit = OutboundInterface {
            name: "explicit".to_owned(),
            addr_v4: Some(Ipv4Addr::LOCALHOST),
            addr_v6: None,
            index: 1,
            netmask_v4: None,
            broadcast_v4: None,
            netmask_v6: None,
            broadcast_v6: None,
            mac_addr: None,
        };
        let default = Some(OutboundInterface {
            name: "default".to_owned(),
            addr_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            addr_v6: None,
            index: 2,
            netmask_v4: None,
            broadcast_v4: None,
            netmask_v6: None,
            broadcast_v6: None,
            mac_addr: None,
        });

        let effective = select_effective_iface(Some(&explicit), &default)
            .expect("explicit interface should win");

        assert_eq!(effective.name, "explicit");
    }

    #[cfg(feature = "tun")]
    #[test]
    fn protected_socket_uses_default_interface_without_explicit_iface() {
        let default = Some(OutboundInterface {
            name: "default".to_owned(),
            addr_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            addr_v6: None,
            index: 2,
            netmask_v4: None,
            broadcast_v4: None,
            netmask_v6: None,
            broadcast_v6: None,
            mac_addr: None,
        });

        let effective = select_effective_iface(None, &default)
            .expect("default interface should be used");

        assert_eq!(effective.name, "default");
    }

    #[cfg(all(feature = "tun", any(target_os = "linux", target_os = "windows")))]
    #[test]
    fn automatic_interface_binding_requires_runtime_tun() {
        let destination = Ipv4Addr::new(1, 1, 1, 1).into();
        let loopback = Ipv4Addr::LOCALHOST.into();

        assert!(!should_auto_bind_destination(destination, false, false));
        assert!(!should_auto_bind_destination(destination, true, true));
        assert!(!should_auto_bind_destination(loopback, false, true));
        assert!(should_auto_bind_destination(destination, false, true));
    }

    #[test]
    fn dual_stack_udp_prefers_ipv4_for_ipv4_only_interface() {
        let iface = OutboundInterface {
            name: "ipv4-only".to_owned(),
            addr_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            addr_v6: None,
            index: 2,
            netmask_v4: None,
            broadcast_v4: None,
            netmask_v6: None,
            broadcast_v6: None,
            mac_addr: None,
        };

        assert!(should_prefer_ipv4_udp_socket(Some(&iface)));
        assert!(!should_prefer_ipv4_udp_socket(None));
    }

    impl SocketProtector for CountingProtector {
        fn protect_socket_handle(&self, _handle: usize) -> std::io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn udp_socket_invokes_socket_protector() {
        let calls = Arc::new(AtomicUsize::new(0));
        set_socket_protector(Arc::new(CountingProtector {
            calls: calls.clone(),
        }));

        let family_hint = Some("127.0.0.1:0".parse().expect("valid socket addr"));

        #[cfg(target_os = "linux")]
        let _socket = new_udp_socket(None, None, None, family_hint)
            .await
            .expect("udp socket should be created");

        #[cfg(not(target_os = "linux"))]
        let _socket = new_udp_socket(None, None, family_hint)
            .await
            .expect("udp socket should be created");

        clear_socket_protector();
        assert!(calls.load(Ordering::SeqCst) >= 1);
    }

    fn find_loopback_iface() -> Option<OutboundInterface> {
        use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};

        let iface = NetworkInterface::show().ok()?.into_iter().find(|iface| {
            iface.addr.iter().any(|addr| match addr {
                Addr::V4(v4) => v4.ip.is_loopback(),
                _ => false,
            })
        })?;

        Some(OutboundInterface {
            name: iface.name,
            addr_v4: Some(Ipv4Addr::LOCALHOST),
            addr_v6: Some(Ipv4Addr::LOCALHOST.to_ipv6_mapped().into()),
            index: iface.index,
            netmask_v4: None,
            broadcast_v4: None,
            netmask_v6: None,
            broadcast_v6: None,
            mac_addr: None,
        })
    }

    #[tokio::test]
    async fn dual_stack_no_iface_is_bound_and_sends_ipv4_mapped() {
        let sock = new_dual_stack_udp_socket(
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .expect("failed to create dual-stack socket");

        let local = sock.local_addr().expect("local_addr failed");
        assert_ne!(local.port(), 0, "socket must have a non-zero local port");

        // Hosts without IPv6 support fall back to an IPv4-only socket.
        if !local.is_ipv6() {
            return;
        }

        let echo = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind echo server");
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        let dst = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            echo_port,
            0,
            0,
        ));
        sock.send_to(b"ping", dst).await.expect("send_to failed");

        let mut buf = vec![0u8; 64];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
                .await
                .expect("timed out")
                .expect("recv_from failed");
        assert_eq!(&buf[..n], b"ping");
    }

    #[tokio::test]
    async fn dual_stack_with_iface_is_bound() {
        let Some(iface) = find_loopback_iface() else {
            eprintln!("skipping: loopback interface not found");
            return;
        };

        let result = new_dual_stack_udp_socket(
            Some(&iface),
            #[cfg(target_os = "linux")]
            None,
        );

        #[cfg(target_os = "linux")]
        if result.is_err() {
            eprintln!("skipping: SO_BINDTODEVICE requires elevated privileges");
            return;
        }

        let sock = result.expect("failed to create dual-stack socket with iface");
        let local = sock.local_addr().expect("local_addr failed");
        assert_ne!(
            local.port(),
            0,
            "socket must have a non-zero local port even when iface is set"
        );
    }
}
