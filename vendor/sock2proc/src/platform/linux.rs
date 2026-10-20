// SPDX-License-Identifier: MIT

use std::{
    fs, io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

use crate::{utils::pre_condition, NetworkProtocol};

/// Dump responses are not guaranteed to be filtered by the socket-id
/// fields of an INET_DIAG request. Never attribute an arbitrary first socket.
fn socket_id_matches(
    id: &SocketId,
    src: Option<std::net::SocketAddr>,
    dst: Option<std::net::SocketAddr>,
) -> bool {
    let local_matches = src.is_none_or(|addr| {
        addr.port() == id.source_port
            && (addr.ip() == id.source_address
                || (id.source_address.is_unspecified()
                    && addr.is_ipv4() == id.source_address.is_ipv4()))
    });
    let remote_matches = dst.is_none_or(|addr| {
        addr.port() == id.destination_port && addr.ip() == id.destination_address
    });
    local_matches && remote_matches
}

/// Netlink frames are 4-byte aligned; the header length excludes padding.
fn aligned_message_len(len: usize) -> Option<usize> {
    len.checked_add(3).map(|len| len & !3)
}

/// Reject malformed Netlink envelopes before decoding kernel input.
fn decode_sock_diag_message(
    bytes: &[u8],
) -> Option<NetlinkMessage<SockDiagMessage>> {
    let length = u32::from_ne_bytes(bytes.get(0..4)?.try_into().ok()?) as usize;
    if length < 16 || length > bytes.len() {
        return None;
    }
    NetlinkMessage::<SockDiagMessage>::deserialize(&bytes[..length]).ok()
}

pub fn find_process_name(
    src: Option<std::net::SocketAddr>,
    dst: Option<std::net::SocketAddr>,
    proto: NetworkProtocol,
) -> Option<String> {
    if !pre_condition(src, dst) {
        return None;
    }

    let (uid, inode) = resolve_uid_inode(src, dst, proto)?;
    resolve_process_name_by_proc_search(uid, inode).ok()
}

fn resolve_uid_inode(
    src: Option<std::net::SocketAddr>,
    dst: Option<std::net::SocketAddr>,
    proto: NetworkProtocol,
) -> Option<(u32, u32)> {
    // A missing NETLINK_SOCK_DIAG protocol or insufficient privileges must
    // never crash a forwarding task (release builds use panic = "abort").
    let mut socket = Socket::new(NETLINK_SOCK_DIAG).ok()?;
    socket.bind_auto().ok()?;
    socket.connect(&SocketAddr::new(0, 0)).ok()?;

    let mut nl_hdr = NetlinkHeader::default();
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let (mut socket_id, family) = if crate::utils::is_ipv6(src, dst) {
        (SocketId::new_v6(), AF_INET6)
    } else {
        (SocketId::new_v4(), AF_INET)
    };
    if let Some(addr) = src {
        socket_id.source_address = addr.ip();
        socket_id.source_port = addr.port();
    }
    if let Some(addr) = dst {
        socket_id.destination_address = addr.ip();
        socket_id.destination_port = addr.port();
    }

    let mut packet = NetlinkMessage::new(
        nl_hdr,
        SockDiagMessage::InetRequest(InetRequest {
            family,
            protocol: proto as _,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id,
        })
        .into(),
    );

    packet.finalize();

    let mut buf = vec![0; packet.buffer_len()];

    packet.serialize(&mut buf[..]);

    socket.send(&buf, 0).ok()?;

    let mut receive_buffer = vec![0u8; 4096];
    while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        if size == 0 || size > receive_buffer.len() {
            return None;
        }
        let mut offset = 0usize;
        while offset < size {
            let bytes = &receive_buffer[offset..size];
            let rx_packet = decode_sock_diag_message(bytes)?;
            let message_len = rx_packet.header.length as usize;
            if message_len == 0 || message_len > bytes.len() {
                return None;
            }
            match rx_packet.payload {
                NetlinkPayload::Noop => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(
                    response,
                )) => {
                    if socket_id_matches(&response.header.socket_id, src, dst) {
                        return Some((response.header.uid, response.header.inode));
                    }
                }
                NetlinkPayload::Done(_) => return None,
                _ => return None,
            }
            offset = offset.checked_add(aligned_message_len(message_len)?)?;
        }
    }
    None
}

#[cfg(test)]
mod malformed_tests {
    use super::*;

    #[test]
    fn short_and_untrusted_netlink_frames_fail_closed() {
        assert!(decode_sock_diag_message(&[]).is_none());
        assert!(decode_sock_diag_message(&[0u8; 2]).is_none());
        let mut truncated = vec![0u8; 16];
        truncated[..4].copy_from_slice(&128u32.to_ne_bytes());
        assert!(decode_sock_diag_message(&truncated).is_none());
        truncated[..4].copy_from_slice(&0u32.to_ne_bytes());
        assert!(decode_sock_diag_message(&truncated).is_none());
    }

    #[test]
    fn netlink_offsets_account_for_padding_and_overflow() {
        assert_eq!(aligned_message_len(16), Some(16));
        assert_eq!(aligned_message_len(17), Some(20));
        assert_eq!(aligned_message_len(19), Some(20));
        assert_eq!(aligned_message_len(usize::MAX), None);
    }

    #[test]
    fn socket_dump_requires_matching_source_and_destination() {
        let mut id = SocketId::new_v4();
        id.source_port = 51820;
        id.source_address = "127.0.0.1".parse().unwrap();
        id.destination_port = 53;
        id.destination_address = "127.0.0.2".parse().unwrap();
        let src = "127.0.0.1:51820".parse().unwrap();
        let dst = "127.0.0.2:53".parse().unwrap();
        assert!(socket_id_matches(&id, Some(src), Some(dst)));
        assert!(!socket_id_matches(
            &id,
            Some("127.0.0.1:51821".parse().unwrap()),
            Some(dst)
        ));
        assert!(!socket_id_matches(
            &id,
            Some(src),
            Some("127.0.0.2:54".parse().unwrap())
        ));

        id.source_address = "0.0.0.0".parse().unwrap();
        assert!(socket_id_matches(&id, Some(src), Some(dst)));
        id.source_port = 1;
        assert!(!socket_id_matches(&id, Some(src), Some(dst)));
    }
}

fn resolve_process_name_by_proc_search(
    uid: u32,
    inode: u32,
) -> Result<String, io::Error> {
    let files = fs::read_dir("/proc")?;

    let socket = format!("socket:[{}]", inode);
    tracing::trace!("expected: {socket}");

    for file in files {
        let file = match file {
            Ok(file) => file,
            Err(_) => continue, // /proc entries can disappear at any time
        };
        let file_name = file.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Ok(metadata) = file.metadata() else {
            continue;
        };
        if !metadata.is_dir() || !file_name.chars().all(char::is_numeric) {
            continue;
        }

        let uid_match = metadata.uid() == uid;
        if !uid_match {
            continue;
        }

        let process_path = format!("/proc/{}", file_name);
        let fd_path = format!("{}/fd", process_path);

        let Ok(fds) = fs::read_dir(fd_path) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            if link.as_os_str().as_bytes() == socket.as_bytes() {
                let cmdline = fs::read(Path::new(&process_path).join("cmdline"))?;
                let first = cmdline.split(|&b| b == 0).next().unwrap_or_default();
                return Ok(String::from_utf8_lossy(first).into_owned());
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Process of uid({}), inode({}) not found", uid, inode),
    ))
}
