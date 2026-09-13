use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::sync::oneshot;

pub(crate) fn is_inbound_client_allowed(
    allow_lan: bool,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
) -> bool {
    allow_lan || peer_addr.ip().to_canonical() == local_addr.ip().to_canonical()
}

pub(crate) type InboundReady = oneshot::Sender<Result<(), String>>;

pub(crate) fn report_listener_ready<T>(
    ready: InboundReady,
    result: std::io::Result<T>,
) -> std::io::Result<T> {
    match result {
        Ok(value) => {
            let _ = ready.send(Ok(()));
            Ok(value)
        }
        Err(err) => {
            let _ = ready.send(Err(err.to_string()));
            Err(err)
        }
    }
}

#[async_trait]
pub trait InboundHandlerTrait: Sync + Send {
    /// support tcp or not
    fn handle_tcp(&self) -> bool;
    /// support udp or not
    fn handle_udp(&self) -> bool;
    async fn listen_tcp(&self, ready: InboundReady) -> std::io::Result<()>;
    async fn listen_udp(&self, ready: InboundReady) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::is_inbound_client_allowed;

    #[test]
    fn allow_lan_accepts_a_different_client_address() {
        assert!(is_inbound_client_allowed(
            true,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 50000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 7891),
        ));
    }

    #[test]
    fn disabled_lan_rejects_a_different_client_address() {
        assert!(!is_inbound_client_allowed(
            false,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 50000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 7891),
        ));
    }

    #[test]
    fn disabled_lan_keeps_same_host_access() {
        assert!(is_inbound_client_allowed(
            false,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7891),
        ));
    }

    #[test]
    fn ipv4_mapped_ipv6_addresses_are_compared_canonically() {
        assert!(is_inbound_client_allowed(
            false,
            SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 50000,),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7891),
        ));
        assert!(!is_inbound_client_allowed(
            false,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 50000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7891),
        ));
    }
}
