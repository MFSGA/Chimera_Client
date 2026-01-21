use std::{io, os::windows::io::AsRawSocket};
use tracing::error;
use windows::Win32::Networking::WinSock::SOCKET;

use crate::app::net::OutboundInterface;

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    let handle = SOCKET(socket.as_raw_socket().try_into().unwrap());
    todo!()
}
