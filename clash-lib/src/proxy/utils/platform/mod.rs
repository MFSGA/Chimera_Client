#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::{SocketProtector, clear_socket_protector, set_socket_protector};
#[cfg(target_os = "android")]
pub(crate) use android::{maybe_protect_socket, must_bind_socket_on_interface};

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(target_vendor = "apple")]
pub(crate) use apple::must_bind_socket_on_interface;
#[cfg(any(target_os = "fuchsia", target_os = "linux", target_os = "freebsd"))]
pub(crate) mod unix;
#[cfg(any(target_os = "fuchsia", target_os = "linux", target_os = "freebsd"))]
pub(crate) use unix::must_bind_socket_on_interface;
#[cfg(windows)]
pub(crate) mod win;
#[cfg(windows)]
pub(crate) use win::must_bind_socket_on_interface;

#[cfg(not(target_os = "android"))]
use std::{
    io,
    sync::{Arc, LazyLock, RwLock},
};

#[cfg(all(
    not(target_os = "android"),
    any(
        target_vendor = "apple",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "freebsd"
    )
))]
use std::os::fd::AsRawFd;
#[cfg(all(not(target_os = "android"), windows))]
use std::os::windows::io::AsRawSocket;

#[cfg(not(target_os = "android"))]
use tracing::trace;

#[cfg(not(target_os = "android"))]
static SOCKET_PROTECTOR: LazyLock<RwLock<Option<Arc<dyn SocketProtector>>>> =
    LazyLock::new(|| RwLock::new(None));

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub trait SocketProtector: Send + Sync {
    fn protect_socket_handle(&self, handle: usize) -> io::Result<()>;
}

#[cfg(not(target_os = "android"))]
pub fn set_socket_protector(protector: Arc<dyn SocketProtector>) {
    if let Ok(mut guard) = SOCKET_PROTECTOR.write() {
        *guard = Some(protector);
    }
}

#[cfg(not(target_os = "android"))]
pub fn clear_socket_protector() {
    if let Ok(mut guard) = SOCKET_PROTECTOR.write() {
        *guard = None;
    }
}

#[cfg(not(target_os = "android"))]
pub(crate) fn maybe_protect_socket(socket: &socket2::Socket) -> io::Result<()> {
    let protector = SOCKET_PROTECTOR
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().cloned());

    let Some(protector) = protector else {
        return Ok(());
    };

    #[cfg(windows)]
    let handle = socket.as_raw_socket() as usize;
    #[cfg(not(windows))]
    let handle = socket.as_raw_fd() as usize;

    trace!(handle, "protecting socket before connect");
    protector.protect_socket_handle(handle)?;
    Ok(())
}
