use std::{
    io,
    mem::{size_of, size_of_val},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    sync::Arc,
};

use tokio::io::unix::AsyncFd;
use tracing::{trace, warn};

use crate::{
    app::dispatcher::Dispatcher,
    proxy::{
        datagram::UdpPacket,
        tun::TunDatagram,
        utils::{ToCanonical, try_create_dualstack_socket},
    },
    session::{Network, Session, Type},
};

struct ReceivedDatagram {
    len: usize,
    source: SocketAddr,
    destination: SocketAddr,
}

pub(super) async fn listen(
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
) -> io::Result<()> {
    let socket = Arc::new(AsyncFd::new(create_listener(addr)?)?);
    let (response_tx, response_rx) = tokio::sync::mpsc::channel(32);
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(32);
    let datagram = TunDatagram::new(response_tx, request_rx);
    let closer = dispatcher
        .dispatch_datagram(
            Session {
                network: Network::Udp,
                typ: Type::Tproxy,
                so_mark: fw_mark,
                ..Default::default()
            },
            Box::new(datagram),
        )
        .await;

    let result = tokio::select! {
        result = receive_loop(socket, request_tx) => result,
        result = send_loop(response_rx, fw_mark) => result,
    };
    let _ = closer.send(0);
    result
}

fn create_listener(addr: SocketAddr) -> io::Result<socket2::Socket> {
    let (socket, dual_stack) =
        try_create_dualstack_socket(addr, socket2::Type::DGRAM)?;
    if dual_stack || addr.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
        set_receive_original_destination(&socket, libc::IPPROTO_IP)?;
    }
    if addr.is_ipv6() {
        set_socket_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)?;
        set_receive_original_destination(&socket, libc::IPPROTO_IPV6)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

async fn receive_loop(
    socket: Arc<AsyncFd<socket2::Socket>>,
    request_tx: tokio::sync::mpsc::Sender<UdpPacket>,
) -> io::Result<()> {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let meta = recv_original(&socket, &mut buffer).await?;
        if meta.destination.ip().is_multicast()
            || matches!(meta.destination.ip(), IpAddr::V4(ip) if ip.is_broadcast())
        {
            continue;
        }
        trace!(source = %meta.source, destination = %meta.destination, "tproxy UDP packet");
        request_tx
            .send(UdpPacket {
                data: buffer[..meta.len].to_vec(),
                src_addr: meta.source.to_canonical().into(),
                dst_addr: meta.destination.to_canonical().into(),
                inbound_user: None,
            })
            .await
            .map_err(|_| io::Error::other("tproxy dispatcher channel closed"))?;
    }
}

async fn send_loop(
    mut response_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    fw_mark: Option<u32>,
) -> io::Result<()> {
    while let Some(packet) = response_rx.recv().await {
        if let Err(err) = send_transparent(packet, fw_mark).await {
            warn!(%err, "failed to send tproxy UDP response");
        }
    }
    Ok(())
}

async fn send_transparent(
    packet: UdpPacket,
    fw_mark: Option<u32>,
) -> io::Result<()> {
    let source = packet
        .src_addr
        .try_into_socket_addr()
        .ok_or_else(|| io::Error::other("tproxy response source is not an IP"))?
        .to_canonical();
    let destination = packet
        .dst_addr
        .try_into_socket_addr()
        .ok_or_else(|| io::Error::other("tproxy response destination is not an IP"))?
        .to_canonical();
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tproxy response address families do not match",
        ));
    }

    let socket = socket2::Socket::new(
        socket2::Domain::for_address(source),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if source.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
        socket.set_broadcast(true)?;
    } else {
        set_socket_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    if let Some(mark) = fw_mark {
        socket.set_mark(mark)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&source.into())?;
    let socket = tokio::net::UdpSocket::from_std(socket.into())?;
    socket.send_to(&packet.data, destination).await?;
    Ok(())
}

async fn recv_original(
    socket: &AsyncFd<socket2::Socket>,
    buffer: &mut [u8],
) -> io::Result<ReceivedDatagram> {
    loop {
        let mut guard = socket.readable().await?;
        match guard.try_io(|inner| recv_original_once(inner.get_ref(), buffer)) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

fn recv_original_once(
    socket: &socket2::Socket,
    buffer: &mut [u8],
) -> io::Result<ReceivedDatagram> {
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut control = [0usize; 32];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = (&mut peer as *mut libc::sockaddr_storage).cast();
    message.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control);

    let len = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other(
            "tproxy original destination was truncated",
        ));
    }
    Ok(ReceivedDatagram {
        len: len as usize,
        source: storage_to_socket_addr(&peer)?,
        destination: original_destination(&message)?,
    })
}

fn original_destination(message: &libc::msghdr) -> io::Result<SocketAddr> {
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let current = unsafe { &*header };
        if current.cmsg_level == libc::IPPROTO_IP
            && current.cmsg_type == libc::IP_RECVORIGDSTADDR
        {
            return Ok(sockaddr_v4(unsafe {
                &*libc::CMSG_DATA(header).cast::<libc::sockaddr_in>()
            }));
        }
        if current.cmsg_level == libc::IPPROTO_IPV6
            && current.cmsg_type == libc::IPV6_RECVORIGDSTADDR
        {
            return Ok(sockaddr_v6(unsafe {
                &*libc::CMSG_DATA(header).cast::<libc::sockaddr_in6>()
            }));
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    Err(io::Error::other(
        "tproxy packet is missing its original destination",
    ))
}

fn storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
) -> io::Result<SocketAddr> {
    match i32::from(storage.ss_family) {
        libc::AF_INET => Ok(sockaddr_v4(unsafe {
            &*(storage as *const _ as *const libc::sockaddr_in)
        })),
        libc::AF_INET6 => Ok(sockaddr_v6(unsafe {
            &*(storage as *const _ as *const libc::sockaddr_in6)
        })),
        family => Err(io::Error::other(format!(
            "unsupported tproxy source address family {family}"
        ))),
    }
}

fn sockaddr_v4(address: &libc::sockaddr_in) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))),
        u16::from_be(address.sin_port),
    )
}

fn sockaddr_v6(address: &libc::sockaddr_in6) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
        u16::from_be(address.sin6_port),
    )
}

fn set_receive_original_destination(
    socket: &socket2::Socket,
    level: libc::c_int,
) -> io::Result<()> {
    let option = match level {
        libc::IPPROTO_IP => libc::IP_RECVORIGDSTADDR,
        libc::IPPROTO_IPV6 => libc::IPV6_RECVORIGDSTADDR,
        _ => return Err(io::Error::other("invalid original destination level")),
    };
    set_socket_option(socket, level, option)
}

fn set_socket_option(
    socket: &socket2::Socket,
    level: libc::c_int,
    option: libc::c_int,
) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&enabled as *const libc::c_int).cast(),
            size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ipv4_sockaddr_from_network_byte_order() {
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 12_345u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([192, 0, 2, 10]),
            },
            sin_zero: [0; 8],
        };

        assert_eq!(
            sockaddr_v4(&address),
            SocketAddr::from(([192, 0, 2, 10], 12_345))
        );
    }

    #[test]
    fn converts_ipv6_sockaddr_from_network_byte_order() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 2, 3, 4, 5);
        let address = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 53u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: ip.octets(),
            },
            sin6_scope_id: 0,
        };

        assert_eq!(sockaddr_v6(&address), SocketAddr::new(ip.into(), 53));
    }

    #[test]
    fn rejects_unsupported_sockaddr_family() {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        storage.ss_family = libc::AF_UNSPEC as libc::sa_family_t;

        let error = storage_to_socket_addr(&storage).unwrap_err();
        assert!(error.to_string().contains("unsupported tproxy source"));
    }
}
