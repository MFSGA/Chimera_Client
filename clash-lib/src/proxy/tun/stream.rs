use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
    },
    config::internal::config::DnsHijackRule,
    session::{Network, Session, Type, find_process_name},
};

fn should_hijack_tcp_dns(
    enabled: bool,
    rules: &[DnsHijackRule],
    destination: std::net::SocketAddr,
) -> bool {
    enabled
        && if rules.is_empty() {
            destination.port() == 53
        } else {
            rules.iter().any(|rule| rule.matches_tcp(destination))
        }
}

async fn handle_tcp_dns(
    mut stream: watfaq_netstack::TcpStream,
    resolver: ThreadSafeDNSResolver,
) {
    loop {
        let mut length_prefix = [0; 2];
        match stream.read_exact(&mut length_prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                warn!("failed to read TCP DNS message length: {error}");
                break;
            }
        }

        let message_length = u16::from_be_bytes(length_prefix) as usize;
        if message_length == 0 {
            warn!("received an empty TCP DNS message");
            break;
        }

        let mut request_bytes = vec![0; message_length];
        if let Err(error) = stream.read_exact(&mut request_bytes).await {
            warn!("failed to read TCP DNS message: {error}");
            break;
        }

        let request = match hickory_proto::op::Message::from_vec(&request_bytes) {
            Ok(request) => request,
            Err(error) => {
                warn!("failed to parse TCP DNS message: {error}");
                break;
            }
        };
        let request_id = request.metadata.id;
        let mut response =
            match exchange_with_resolver(&resolver, &request, true).await {
                Ok(response) => response,
                Err(error) => {
                    warn!("failed to exchange TCP DNS message: {error}");
                    break;
                }
            };
        response.metadata.id = request_id;

        let response_bytes = match response.to_vec() {
            Ok(response) => response,
            Err(error) => {
                warn!("failed to serialize TCP DNS response: {error}");
                break;
            }
        };
        let response_length = match u16::try_from(response_bytes.len()) {
            Ok(length) => length,
            Err(_) => {
                warn!("TCP DNS response exceeds the protocol message limit");
                break;
            }
        };

        if let Err(error) = stream.write_all(&response_length.to_be_bytes()).await {
            warn!("failed to write TCP DNS response length: {error}");
            break;
        }
        if let Err(error) = stream.write_all(&response_bytes).await {
            warn!("failed to write TCP DNS response: {error}");
            break;
        }
    }
}

pub(crate) async fn handle_inbound_stream(
    stream: watfaq_netstack::TcpStream,

    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: bool,
    dns_hijack_rules: Vec<DnsHijackRule>,
) {
    let source = stream.local_addr();
    let destination = stream.remote_addr();

    if should_hijack_tcp_dns(dns_hijack, &dns_hijack_rules, destination) {
        debug!("hijacking TCP DNS connection: {source} -> {destination}");
        handle_tcp_dns(stream, resolver).await;
        return;
    }

    let process_name = find_process_name(source, Some(destination), Network::Tcp);

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source,
        destination: destination.into(),
        iface: None,
        so_mark,
        process_name,
        ..Default::default()
    };

    debug!("new tun TCP session assigned: {}", sess);
    dispatcher.dispatch_stream(sess, Box::new(stream)).await;
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::config::internal::config::{
        DnsHijackAddress, DnsHijackProtocol, DnsHijackRule,
    };

    use super::should_hijack_tcp_dns;

    #[test]
    fn tcp_dns_hijack_uses_rules_and_preserves_empty_list_compatibility() {
        let destination = SocketAddr::from(([192, 0, 2, 53], 5353));
        let tcp_rule = DnsHijackRule {
            protocol: DnsHijackProtocol::Tcp,
            address: DnsHijackAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
            port: 5353,
        };
        let udp_rule = DnsHijackRule {
            protocol: DnsHijackProtocol::Udp,
            ..tcp_rule
        };

        assert!(should_hijack_tcp_dns(
            true,
            &[],
            "192.0.2.53:53".parse().unwrap()
        ));
        assert!(should_hijack_tcp_dns(true, &[tcp_rule], destination));
        assert!(!should_hijack_tcp_dns(true, &[udp_rule], destination));
        assert!(!should_hijack_tcp_dns(false, &[tcp_rule], destination));
        assert!(!should_hijack_tcp_dns(
            true,
            &[tcp_rule],
            "192.0.2.54:5353".parse().unwrap()
        ));
    }
}
