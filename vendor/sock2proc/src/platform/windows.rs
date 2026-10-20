// SPDX-License-Identifier: MIT

use std::io;
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;

use crate::utils::{is_ipv6, pre_condition};
use crate::NetworkProtocol;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

const MAX_PATH: usize = 260;

/// Walk an untrusted Windows IP Helper table without creating potentially
/// unaligned references or reading beyond the actual kernel-returned bytes.
fn valid_table_buffer(buffer: &[u8], reported_size: u32) -> io::Result<&[u8]> {
    buffer.get(..reported_size as usize).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid IP Helper table size")
    })
}

fn table_rows<T: Copy>(
    buffer: &[u8],
    table_offset: usize,
) -> io::Result<impl Iterator<Item = T> + '_> {
    let entries = buffer.get(0..4).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated table header")
    })?;
    let count = u32::from_ne_bytes(entries.try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid table header")
    })?) as usize;
    let data_len = count.checked_mul(size_of::<T>()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "table too large")
    })?;
    let end = table_offset.checked_add(data_len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid table size")
    })?;
    let data = buffer.get(table_offset..end).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated table data")
    })?;
    Ok(data.chunks_exact(size_of::<T>()).map(|row| {
        // SAFETY: the slice was bounds-checked and has size_of::<T>() bytes;
        // Windows API structs consist of plain integer/byte fields.
        unsafe { ptr::read_unaligned(row.as_ptr().cast::<T>()) }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_ip_helper_table_is_rejected() {
        assert!(table_rows::<MIB_TCPROW_OWNER_PID>(&[], 4).is_err());
        assert!(table_rows::<MIB_TCPROW_OWNER_PID>(&1u32.to_ne_bytes(), 4).is_err());
        assert!(valid_table_buffer(&[0; 4], 8).is_err());
    }
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
) -> Result<String, io::Error> {
    if !pre_condition(src, dst) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid input"));
    }

    let is_ipv4 = !is_ipv6(src, dst);
    let pid = match proto {
        NetworkProtocol::TCP => {
            if is_ipv4 {
                find_tcp_v4_pid(src, dst)?
            } else {
                find_tcp_v6_pid(src, dst)?
            }
        }
        NetworkProtocol::UDP => {
            if is_ipv4 {
                find_udp_v4_pid(src, dst)?
            } else {
                find_udp_v6_pid(src, dst)?
            }
        }
    };

    get_process_path(pid)
}

fn find_tcp_v4_pid(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<u32, io::Error> {
    let mut size: u32 = 0;

    // First call to get the size
    let result = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }

    // Allocate buffer and get the table
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Parse the table
    for row in table_rows::<MIB_TCPROW_OWNER_PID>(
        valid_table_buffer(&buffer, size)?,
        offset_of!(MIB_TCPTABLE_OWNER_PID, table),
    )? {
        if let Some(addr) = src {
            let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
            let local_port = u16::from_be(row.dwLocalPort as u16);

            if addr.ip() != IpAddr::V4(local_addr) || addr.port() != local_port {
                continue;
            }
        }

        if let Some(addr) = dst {
            let remote_addr = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
            let remote_port = u16::from_be(row.dwRemotePort as u16);

            if addr.ip() != IpAddr::V4(remote_addr) || addr.port() != remote_port {
                continue;
            }
        }

        return Ok(row.dwOwningPid);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Process not found for TCP connection",
    ))
}

fn find_tcp_v6_pid(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<u32, io::Error> {
    let mut size: u32 = 0;

    // First call to get the size
    let result = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }

    // Allocate buffer and get the table
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Parse the table
    for row in table_rows::<MIB_TCP6ROW_OWNER_PID>(
        valid_table_buffer(&buffer, size)?,
        offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
    )? {
        if let Some(addr) = src {
            let local_addr = Ipv6Addr::from(row.ucLocalAddr);
            let local_port = u16::from_be(row.dwLocalPort as u16);

            if addr.ip() != IpAddr::V6(local_addr) || addr.port() != local_port {
                continue;
            }
        }

        if let Some(addr) = dst {
            let remote_addr = Ipv6Addr::from(row.ucRemoteAddr);
            let remote_port = u16::from_be(row.dwRemotePort as u16);

            if addr.ip() != IpAddr::V6(remote_addr) || addr.port() != remote_port {
                continue;
            }
        }

        return Ok(row.dwOwningPid);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Process not found for TCP connection",
    ))
}

fn find_udp_v4_pid(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<u32, io::Error> {
    let mut size: u32 = 0;

    // First call to get the size
    let result = unsafe {
        GetExtendedUdpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }

    // Allocate buffer and get the table
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let result = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Parse the table
    for row in table_rows::<MIB_UDPROW_OWNER_PID>(
        valid_table_buffer(&buffer, size)?,
        offset_of!(MIB_UDPTABLE_OWNER_PID, table),
    )? {
        if let Some(addr) = src {
            let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
            let local_port = u16::from_be(row.dwLocalPort as u16);

            if addr.ip() != IpAddr::V4(local_addr) || addr.port() != local_port {
                continue;
            }
        }

        // UDP doesn't have remote address for listeners, so we only check if dst is None
        if dst.is_some() {
            // UDP rows don't have remote address/port, so we can't match destination
            continue;
        }

        return Ok(row.dwOwningPid);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Process not found for UDP socket",
    ))
}

fn find_udp_v6_pid(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<u32, io::Error> {
    let mut size: u32 = 0;

    // First call to get the size
    let result = unsafe {
        GetExtendedUdpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }

    // Allocate buffer and get the table
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let result = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Parse the table
    for row in table_rows::<MIB_UDP6ROW_OWNER_PID>(
        valid_table_buffer(&buffer, size)?,
        offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
    )? {
        if let Some(addr) = src {
            let local_addr = Ipv6Addr::from(row.ucLocalAddr);
            let local_port = u16::from_be(row.dwLocalPort as u16);

            if addr.ip() != IpAddr::V6(local_addr) || addr.port() != local_port {
                continue;
            }
        }

        // UDP doesn't have remote address for listeners, so we only check if dst is None
        if dst.is_some() {
            // UDP rows don't have remote address/port, so we can't match destination
            continue;
        }

        return Ok(row.dwOwningPid);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Process not found for UDP socket",
    ))
}

fn get_process_path(pid: u32) -> Result<String, io::Error> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buffer: Vec<u16> = vec![0; MAX_PATH];
        let mut size = buffer.len() as u32;

        let result =
            QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);

        // Close handle
        CloseHandle(handle);

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        // Convert UTF-16 to String
        let path_bytes = buffer.get(..size as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid process image size")
        })?;
        Ok(String::from_utf16_lossy(path_bytes))
    }
}
