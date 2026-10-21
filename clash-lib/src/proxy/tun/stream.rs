use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, dns_error_response, exchange_with_resolver},
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

// Accept any Tokio duplex stream so offline framing tests can run the
// production TCP DNS hijack loop without allocating a kernel TUN device.
async fn handle_tcp_dns<S>(mut stream: S, resolver: ThreadSafeDNSResolver)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
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
                    dns_error_response(
                        &request,
                        hickory_proto::op::ResponseCode::ServFail,
                    )
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
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use crate::{
        app::dns::{MockClashResolver, ThreadSafeDNSResolver},
        config::internal::config::{
            DnsHijackAddress, DnsHijackProtocol, DnsHijackRule,
        },
    };
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RecordType},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::{handle_tcp_dns, should_hijack_tcp_dns};

    fn dns_query(name: &str, typ: RecordType, id: u16) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), typ));
        query
    }

    async fn tcp_roundtrip(peer: &mut DuplexStream, message: &Message) -> Message {
        let wire = message.to_vec().unwrap();
        peer.write_all(&(wire.len() as u16).to_be_bytes())
            .await
            .unwrap();
        peer.write_all(&wire).await.unwrap();
        let mut length = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut length))
            .await
            .unwrap()
            .unwrap();
        let mut response = vec![0; u16::from_be_bytes(length) as usize];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        Message::from_vec(&response).unwrap()
    }

    #[tokio::test]
    async fn ipv4_tun_tcp_fake_a_and_multi_question_on_same_connection() {
        let mut mock = MockClashResolver::new();
        mock.expect_ipv6().return_const(false);
        mock.expect_fake_ip_enabled().return_const(true);
        mock.expect_fake_ip_v6_enabled().return_const(false);
        mock.expect_exchange().never();
        mock.expect_resolve_v4()
            .once()
            .returning(|_, _| Ok(Some("198.18.0.15".parse().unwrap())));
        let resolver: ThreadSafeDNSResolver = Arc::new(mock);

        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(handle_tcp_dns(server, resolver));

        let answer = tcp_roundtrip(
            &mut client,
            &dns_query("fake.example.", RecordType::A, 0x1701),
        )
        .await;
        assert_eq!(answer.metadata.id, 0x1701);
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert_eq!(answer.answers[0].data.to_string(), "198.18.0.15");

        let mut multi = dns_query("first.example.", RecordType::A, 0x1702);
        multi.add_query(Query::query(
            Name::from_ascii("second.example.").unwrap(),
            RecordType::HTTPS,
        ));
        let answer = tcp_roundtrip(&mut client, &multi).await;
        assert_eq!(answer.metadata.id, 0x1702);
        assert_eq!(answer.metadata.response_code, ResponseCode::FormErr);
        assert!(answer.queries.is_empty());

        drop(client);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn ipv4_tun_tcp_servfail_is_framed_and_session_keeps_working() {
        let mut mock = MockClashResolver::new();
        mock.expect_ipv6().return_const(false);
        mock.expect_fake_ip_enabled().return_const(false);
        mock.expect_fake_ip_v6_enabled().return_const(false);
        mock.expect_exchange()
            .once()
            .returning(|_| Err(anyhow::anyhow!("all upstreams unavailable")));
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(handle_tcp_dns(server, Arc::new(mock)));

        let answer = tcp_roundtrip(
            &mut client,
            &dns_query("down.example.", RecordType::A, 0x1a02),
        )
        .await;
        assert_eq!(answer.metadata.id, 0x1a02);
        assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);

        // A second malformed multi-question query must receive a response
        // on the existing TCP connection, not an unexpected EOF.
        let mut multi = dns_query("one.example.", RecordType::A, 0x1a03);
        multi.add_query(Query::query(
            Name::from_ascii("two.example.").unwrap(),
            RecordType::TXT,
        ));
        let next = tcp_roundtrip(&mut client, &multi).await;
        assert_eq!(next.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(next.metadata.id, 0x1a03);

        drop(client);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

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
