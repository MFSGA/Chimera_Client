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
use std::{io, sync::Arc};

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub trait SocketProtector: Send + Sync {
    fn protect_socket_fd(&self, fd: i32) -> io::Result<()>;
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub fn set_socket_protector(_protector: Arc<dyn SocketProtector>) {}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub fn clear_socket_protector() {}

#[cfg(not(target_os = "android"))]
pub(crate) fn maybe_protect_socket(_socket: &socket2::Socket) -> io::Result<()> {
    Ok(())
}
