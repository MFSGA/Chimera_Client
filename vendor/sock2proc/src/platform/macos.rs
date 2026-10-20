use sysctl::Sysctl;

use crate::utils::{is_ipv6, pre_condition};
use crate::NetworkProtocol;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

const SYS_PROC_INFO: i32 = 336;
const PROCPIDPATHINFO: i32 = 0xb;
const PROCPIDPATHINFOSIZE: usize = 1024;
const PROCCALLNUMPIDINFO: i32 = 0x2;

static STRUCT_SIZE: OnceLock<Option<usize>> = OnceLock::new();

fn pcb_struct_size() -> io::Result<usize> {
    // No fallback layout: guessing the wrong kernel structure can produce
    // incorrect process attribution. A lookup failure must be non-fatal.
    (*STRUCT_SIZE.get_or_init(|| {
        let ctl = sysctl::Ctl::new("kern.osrelease").ok()?;
        let version = ctl.value().ok()?;
        let major = version
            .as_string()?
            .split('.')
            .next()?
            .parse::<i32>()
            .ok()?;
        Some(if major >= 22 { 408 } else { 384 })
    }))
    .ok_or_else(|| io::Error::other("unable to determine macOS PCB layout"))
}

/// Parse the kernel-reported PCB list conservatively. Invalid or truncated
/// records must not panic or be mistaken for another process.
fn find_pid_in_pcb_records(
    bytes: &[u8],
    item_size: usize,
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
    ipv4: bool,
) -> Option<u32> {
    if item_size < 176 {
        return None;
    }
    // pcblist_n starts with a 24-byte generation header.
    for record in bytes.get(24..)?.chunks_exact(item_size) {
        let dst_port = u16::from_be_bytes(record.get(16..18)?.try_into().ok()?);
        let src_port = u16::from_be_bytes(record.get(18..20)?.try_into().ok()?);
        let (dst_ip, src_ip) = match (record.get(44).copied()?, ipv4) {
            (0x1, true) => (
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(record.get(60..64)?).ok()?,
                )),
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(record.get(76..80)?).ok()?,
                )),
            ),
            (0x2, false) => (
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(record.get(48..64)?).ok()?,
                )),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(record.get(64..80)?).ok()?,
                )),
            ),
            _ => continue,
        };
        if src.is_some_and(|addr| addr.port() != src_port || addr.ip() != src_ip)
            || dst.is_some_and(|addr| addr.port() != dst_port || addr.ip() != dst_ip)
        {
            continue;
        }
        let pid_bytes: [u8; 4] = record.get(172..176)?.try_into().ok()?;
        return Some(u32::from_ne_bytes(pid_bytes));
    }
    None
}

pub fn find_process_name(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
    proto: NetworkProtocol,
) -> Option<String> {
    find_process_name_inner(src, dst, proto).ok()
}

fn find_process_name_inner(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
    proto: NetworkProtocol,
) -> io::Result<String> {
    if !pre_condition(src, dst) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid input"));
    }
    let struct_size = pcb_struct_size()?;
    let spath = match proto {
        NetworkProtocol::TCP => "net.inet.tcp.pcblist_n",
        NetworkProtocol::UDP => "net.inet.udp.pcblist_n",
    };
    let ctl =
        sysctl::Ctl::new(spath).map_err(|e| io::Error::other(e.to_string()))?;
    let value = ctl.value().map_err(|e| io::Error::other(e.to_string()))?;
    let bytes = value.as_struct().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid macOS PCB payload")
    })?;
    let item_size = struct_size
        + if proto == NetworkProtocol::TCP {
            208
        } else {
            0
        };
    let pid =
        find_pid_in_pcb_records(bytes, item_size, src, dst, !is_ipv6(src, dst))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Process not found")
            })?;
    get_exec_path_from_pid(pid)
}

fn get_exec_path_from_pid(pid: u32) -> io::Result<String> {
    let mut buf = vec![0u8; PROCPIDPATHINFOSIZE];
    // SAFETY: kernel writes at most PROCPIDPATHINFOSIZE bytes into our owned
    // buffer. No pointer is retained by the system call.
    let ret = unsafe {
        libc::syscall(
            SYS_PROC_INFO,
            PROCCALLNUMPIDINFO,
            pid as usize,
            PROCPIDPATHINFO,
            0,
            buf.as_mut_ptr() as usize,
            PROCPIDPATHINFOSIZE,
        )
    };
    // The proc_info syscall may return zero on success; the path buffer
    // itself is checked below. Only negative return values signal failure.
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = buf.iter().position(|&x| x == 0).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "unterminated process path")
    })?;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "empty process path",
        ));
    }
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_or_unknown_pcb_layout_is_not_fatal() {
        assert_eq!(find_pid_in_pcb_records(&[], 408, None, None, true), None);
        assert_eq!(
            find_pid_in_pcb_records(&[0u8; 24], 0, None, None, true),
            None
        );
        assert_eq!(
            find_pid_in_pcb_records(&[0u8; 120], 408, None, None, true),
            None
        );
    }

    #[test]
    fn match_valid_record_only_when_endpoints_agree() {
        let mut payload = vec![0u8; 24 + 408];
        let rec = &mut payload[24..];
        rec[44] = 0x1;
        rec[16..18].copy_from_slice(&443u16.to_be_bytes());
        rec[18..20].copy_from_slice(&50000u16.to_be_bytes());
        rec[60..64].copy_from_slice(&[127, 0, 0, 2]);
        rec[76..80].copy_from_slice(&[127, 0, 0, 1]);
        rec[172..176].copy_from_slice(&42u32.to_ne_bytes());
        let source: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let dest: SocketAddr = "127.0.0.2:443".parse().unwrap();
        assert_eq!(
            find_pid_in_pcb_records(&payload, 408, Some(source), Some(dest), true),
            Some(42)
        );
        let other: SocketAddr = "127.0.0.2:444".parse().unwrap();
        assert_eq!(
            find_pid_in_pcb_records(&payload, 408, Some(source), Some(other), true),
            None
        );
    }
}
