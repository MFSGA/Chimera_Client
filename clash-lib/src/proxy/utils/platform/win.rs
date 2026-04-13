use std::{io, os::windows::io::AsRawSocket, sync::Arc};
use tracing::{error, trace};
use windows::{
    Win32::{
        Foundation::GetLastError,
        Networking::WinSock::{
            ADDRESS_FAMILY, AF_INET, AF_INET6, IP_MULTICAST_IF, IP_UNICAST_IF,
            IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_IF, IPV6_UNICAST_IF, SO_TYPE,
            SOCK_DGRAM, SOCKADDR, SOCKADDR_INET, SOCKET, SOL_SOCKET,
            WINSOCK_SOCKET_TYPE, getsockname, getsockopt, setsockopt,
        },
    },
    core::PSTR,
};

use super::SocketProtector;
use crate::{
    app::net::{DEFAULT_OUTBOUND_INTERFACE, OutboundInterface},
    common::errors::new_io_error,
};

pub(crate) fn default_socket_protector() -> Arc<dyn SocketProtector> {
    Arc::new(DefaultSocketProtector)
}

struct DefaultSocketProtector;

impl SocketProtector for DefaultSocketProtector {
    fn protect_socket_handle(&self, handle: usize) -> io::Result<()> {
        let Some(iface) = DEFAULT_OUTBOUND_INTERFACE
            .try_read()
            .ok()
            .and_then(|guard| guard.clone())
        else {
            return Ok(());
        };

        let handle = SOCKET(handle.try_into().map_err(|_| {
            io::Error::other("invalid socket handle for Windows protector")
        })?);
        let family = match socket_family(handle) {
            Ok(family) => family,
            Err(err) => {
                trace!(
                    iface = %iface.name,
                    index = iface.index,
                    err = ?err,
                    "skipping Windows default socket protection because socket family is not available yet"
                );
                return Ok(());
            }
        };
        trace!(
            iface = %iface.name,
            index = iface.index,
            "protecting socket with default outbound interface"
        );
        bind_socket_to_interface(handle, &iface, family)
    }
}

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    let handle = SOCKET(socket.as_raw_socket().try_into().unwrap());
    bind_socket_to_interface(handle, iface, family)
}

/// Return true if it's a udp socket
fn is_udp_socket(socket: SOCKET) -> io::Result<bool> {
    let mut optval = [0u8; 4];
    let mut optlen: i32 = 4;
    let ret = unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_TYPE,
            PSTR::from_raw(optval.as_mut_ptr()),
            &mut optlen,
        )
    };
    if ret != 0 {
        let last_err = io::Error::last_os_error();
        tracing::warn!(
            "getsockopt failed when determining socket type: {:?}",
            last_err
        );
        return Err(last_err);
    }
    Ok(WINSOCK_SOCKET_TYPE(i32::from_ne_bytes(optval)) == SOCK_DGRAM)
}

fn socket_family(socket: SOCKET) -> io::Result<socket2::Domain> {
    let mut addr = SOCKADDR_INET::default();
    let mut addr_len = std::mem::size_of::<SOCKADDR_INET>() as i32;
    let ret = unsafe {
        getsockname(socket, &mut addr as *mut _ as *mut SOCKADDR, &mut addr_len)
    };
    if ret != 0 {
        let last_err = io::Error::last_os_error();
        trace!(err = ?last_err, "getsockname failed when determining socket family");
        return Err(last_err);
    }

    let family: ADDRESS_FAMILY = unsafe { addr.Ipv4.sin_family };
    if family == AF_INET {
        Ok(socket2::Domain::IPV4)
    } else if family == AF_INET6 {
        Ok(socket2::Domain::IPV6)
    } else {
        Err(io::Error::other(format!(
            "unsupported socket family: {}",
            family.0
        )))
    }
}

fn bind_socket_to_interface(
    handle: SOCKET,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    let is_udp = is_udp_socket(handle)?;
    let idx = iface.index;

    let errno = match family {
        socket2::Domain::IPV4 => unsafe {
            setsockopt(
                handle,
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                Some(idx.to_be_bytes().as_ref()),
            )
        },
        socket2::Domain::IPV6 => unsafe {
            setsockopt(
                handle,
                IPPROTO_IPV6.0,
                IPV6_UNICAST_IF,
                Some(idx.to_ne_bytes().as_ref()),
            )
        },
        _ => return Err(io::Error::other("unsupported socket family")),
    };

    if errno != 0 {
        let err = unsafe { GetLastError().to_hresult().message() };
        error!("bind socket to interface failed: {}, errno: {}", err, errno);
        return Err(new_io_error(err));
    }

    if is_udp {
        let errno = match family {
            socket2::Domain::IPV4 => unsafe {
                setsockopt(
                    handle,
                    IPPROTO_IP.0,
                    IP_MULTICAST_IF,
                    Some(idx.to_be_bytes().as_ref()),
                )
            },
            socket2::Domain::IPV6 => unsafe {
                setsockopt(
                    handle,
                    IPPROTO_IPV6.0,
                    IPV6_MULTICAST_IF,
                    Some(idx.to_ne_bytes().as_ref()),
                )
            },
            _ => return Err(io::Error::other("unsupported socket family")),
        };

        if errno != 0 {
            let err = unsafe { GetLastError().to_hresult().message() };
            error!("bind socket to interface failed: {}, errno: {}", err, errno);
            return Err(new_io_error(err));
        }
    }

    Ok(())
}
