#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::find_process_name;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::find_process_name;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::find_process_name;

#[cfg(test)]
mod tests {

    use std::net::TcpListener;

    #[test]
    fn test_get_find_tcp_socket() {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let path =
            super::find_process_name(Some(addr), None, crate::NetworkProtocol::TCP);

        assert!(path.is_some());

        let current_exe = std::env::current_exe().unwrap();
        assert_eq!(path.unwrap(), current_exe.to_str().unwrap());
    }

    #[test]
    fn test_get_find_udp_socket() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let path =
            super::find_process_name(Some(addr), None, crate::NetworkProtocol::UDP);

        assert!(path.is_some());

        let current_exe = std::env::current_exe().unwrap();
        assert_eq!(path.unwrap(), current_exe.to_str().unwrap());
    }
}
