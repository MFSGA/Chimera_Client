use std::{
    io,
    os::fd::AsRawFd,
    sync::{Arc, LazyLock, RwLock},
};

use tracing::trace;

use crate::app::net::OutboundInterface;

pub trait SocketProtector: Send + Sync {
    fn protect_socket_fd(&self, fd: i32) -> io::Result<()>;
}

static SOCKET_PROTECTOR: LazyLock<RwLock<Option<Arc<dyn SocketProtector>>>> =
    LazyLock::new(|| RwLock::new(None));

pub fn set_socket_protector(protector: Arc<dyn SocketProtector>) {
    if let Ok(mut guard) = SOCKET_PROTECTOR.write() {
        *guard = Some(protector);
    }
}

pub fn clear_socket_protector() {
    if let Ok(mut guard) = SOCKET_PROTECTOR.write() {
        *guard = None;
    }
}

pub(crate) fn maybe_protect_socket(socket: &socket2::Socket) -> io::Result<()> {
    let protector = SOCKET_PROTECTOR
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().cloned());

    let Some(protector) = protector else {
        return Ok(());
    };

    let fd = socket.as_raw_fd();
    trace!(fd, "protecting android socket before connect");
    protector.protect_socket_fd(fd)
}

pub(crate) fn must_bind_socket_on_interface(
    _socket: &socket2::Socket,
    iface: &OutboundInterface,
    _family: socket2::Domain,
) -> io::Result<()> {
    trace!(
        iface = %iface.name,
        "android outbound interface binding is handled by socket protection"
    );
    Ok(())
}
