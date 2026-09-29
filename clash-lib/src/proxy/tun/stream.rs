use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
        net::DEFAULT_OUTBOUND_INTERFACE,
    },
    config::internal::config::DnsHijackRule,
    session::{Network, Session, Type, find_process_name},
};

const TLS_SNIFF_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_TLS_RECORD_LENGTH: usize = 16 * 1024;

fn should_sniff_tls(port: u16) -> bool {
    matches!(
        port,
        443 | 465
            | 853
            | 993
            | 995
            | 2053
            | 2083
            | 2087
            | 2096
            | 5228
            | 8443
            | 8888
            | 9443
            | 10443
            | 10444
    )
}

struct ReplayedTcpStream {
    inner: watfaq_netstack::TcpStream,
    buffered: Vec<u8>,
    offset: usize,
}

impl AsyncRead for ReplayedTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.buffered.len() {
            let count = buffer.remaining().min(this.buffered.len() - this.offset);
            buffer.put_slice(&this.buffered[this.offset..this.offset + count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for ReplayedTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn read_tls_prefix(
    stream: &mut watfaq_netstack::TcpStream,
    buffered: &mut Vec<u8>,
    target_len: usize,
) -> std::io::Result<bool> {
    while buffered.len() < target_len {
        let mut chunk = [0; 1024];
        let count = (target_len - buffered.len()).min(chunk.len());
        let read = stream.read(&mut chunk[..count]).await?;
        if read == 0 {
            return Ok(false);
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
    Ok(true)
}

async fn sniff_tls_server_name(
    mut stream: watfaq_netstack::TcpStream,
    destination_port: u16,
) -> (ReplayedTcpStream, Option<String>) {
    let mut buffered = Vec::new();
    if !should_sniff_tls(destination_port) {
        return (
            ReplayedTcpStream {
                inner: stream,
                buffered,
                offset: 0,
            },
            None,
        );
    }

    let sniffed = tokio::time::timeout(TLS_SNIFF_TIMEOUT, async {
        if !read_tls_prefix(&mut stream, &mut buffered, 5).await.ok()? {
            return None;
        }

        if buffered[0] != 0x16 || buffered[1] != 0x03 {
            return None;
        }

        let record_length = u16::from_be_bytes([buffered[3], buffered[4]]) as usize;
        if !(4..=MAX_TLS_RECORD_LENGTH).contains(&record_length) {
            return None;
        }

        let record_end = 5 + record_length;
        if !read_tls_prefix(&mut stream, &mut buffered, record_end)
            .await
            .ok()?
        {
            return None;
        }

        parse_tls_server_name(&buffered)
    })
    .await
    .unwrap_or(None);

    (
        ReplayedTcpStream {
            inner: stream,
            buffered,
            offset: 0,
        },
        sniffed,
    )
}

fn parse_tls_server_name(record: &[u8]) -> Option<String> {
    if record.len() < 9 || record[0] != 0x16 || record[1] != 0x03 {
        return None;
    }

    let record_length = u16::from_be_bytes([record[3], record[4]]) as usize;
    let handshake = record.get(5..5 + record_length)?;
    if handshake.first() != Some(&0x01) {
        return None;
    }

    let hello_length = read_u24(handshake, 1)?;
    let hello_end = 4_usize.checked_add(hello_length)?;
    let hello = handshake.get(4..hello_end)?;
    let mut offset = 0;

    take_bytes(hello, &mut offset, 2 + 32)?;
    let session_id_length = read_u8(hello, &mut offset)? as usize;
    take_bytes(hello, &mut offset, session_id_length)?;
    let cipher_suites_length = read_u16(hello, &mut offset)? as usize;
    take_bytes(hello, &mut offset, cipher_suites_length)?;
    let compression_methods_length = read_u8(hello, &mut offset)? as usize;
    take_bytes(hello, &mut offset, compression_methods_length)?;
    let extensions_length = read_u16(hello, &mut offset)? as usize;
    let extensions = take_bytes(hello, &mut offset, extensions_length)?;

    let mut offset = 0;
    while offset < extensions.len() {
        let extension_type = read_u16(extensions, &mut offset)?;
        let extension_length = read_u16(extensions, &mut offset)? as usize;
        let extension = take_bytes(extensions, &mut offset, extension_length)?;
        if extension_type == 0 {
            return parse_sni_extension(extension);
        }
    }

    None
}

fn parse_sni_extension(extension: &[u8]) -> Option<String> {
    let mut offset = 0;
    let names_length = read_u16(extension, &mut offset)? as usize;
    let names = take_bytes(extension, &mut offset, names_length)?;

    let mut offset = 0;
    while offset < names.len() {
        let name_type = read_u8(names, &mut offset)?;
        let name_length = read_u16(names, &mut offset)? as usize;
        let name = take_bytes(names, &mut offset, name_length)?;
        if name_type == 0 {
            let host = std::str::from_utf8(name).ok()?.trim_end_matches('.');
            if host.is_empty()
                || !host.is_ascii()
                || host.chars().any(char::is_whitespace)
                || host.parse::<std::net::IpAddr>().is_ok()
            {
                return None;
            }
            return Some(host.to_ascii_lowercase());
        }
    }

    None
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Option<&'a [u8]> {
    let end = offset.checked_add(length)?;
    let value = bytes.get(*offset..end)?;
    *offset = end;
    Some(value)
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Option<u8> {
    Some(*take_bytes(bytes, offset, 1)?.first()?)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let value = take_bytes(bytes, offset, 2)?;
    Some(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u24(bytes: &[u8], offset: usize) -> Option<usize> {
    let value = bytes.get(offset..offset + 3)?;
    Some(
        ((value[0] as usize) << 16) | ((value[1] as usize) << 8) | value[2] as usize,
    )
}

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

    let (stream, sniff_host) =
        sniff_tls_server_name(stream, destination.port()).await;

    let process_name = find_process_name(source, Some(destination), Network::Tcp);

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source,
        destination: destination.into(),
        iface: DEFAULT_OUTBOUND_INTERFACE
            .read()
            .await
            .clone()
            .inspect(|x| {
                debug!(
                    "selecting outbound interface: {:?} for tun TCP connection",
                    x
                );
            }),
        so_mark,
        process_name,
        sniff_host,
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
