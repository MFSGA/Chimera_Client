use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::{Network, Session, SocksAddr},
};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEPALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;
const MAX_METADATA_LENGTH: usize = 512;
// Xray's XUDP PacketReader reads each packet into an 8 KiB fixed buffer.
const MAX_PACKET_LENGTH: usize = 8192;
const READ_CHUNK_LENGTH: usize = 8192;

/// Single-subconnection XUDP framing over the VLESS Mux command.
///
/// The address in each UDP frame is the packet destination. A bounded metadata
/// length prevents a peer from causing an unbounded allocation while reading.
pub struct OutboundDatagramXudp {
    inner: AnyStream,
    remote_addr: SocksAddr,
    global_id: [u8; 8],
    first_packet: bool,
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,
    flushed: bool,
    read_buf: BytesMut,
    read_terminated: bool,
}

impl OutboundDatagramXudp {
    pub fn new(
        inner: AnyStream,
        remote_addr: SocksAddr,
        global_id: [u8; 8],
    ) -> Self {
        Self {
            inner,
            remote_addr,
            global_id,
            first_packet: true,
            write_buf: BytesMut::new(),
            pending_packet: None,
            flushed: true,
            read_buf: BytesMut::new(),
            read_terminated: false,
        }
    }

    fn destination_for(&self, packet: &UdpPacket) -> SocksAddr {
        match &packet.dst_addr {
            SocksAddr::Ip(addr)
                if addr.ip().is_unspecified() && addr.port() == 0 =>
            {
                self.remote_addr.clone()
            }
            _ => packet.dst_addr.clone(),
        }
    }

    fn write_packet(&mut self, packet: &UdpPacket) -> io::Result<()> {
        if packet.data.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "XUDP packet too large: {} > {MAX_PACKET_LENGTH}",
                    packet.data.len()
                ),
            ));
        }

        let destination = self.destination_for(packet);
        self.write_buf.clear();
        encode_frame(
            if self.first_packet {
                STATUS_NEW
            } else {
                STATUS_KEEP
            },
            Some(&destination),
            self.global_id,
            &packet.data,
            &mut self.write_buf,
        )?;
        self.first_packet = false;
        trace!(
            destination = %destination,
            data_len = packet.data.len(),
            "encoded VLESS XUDP packet"
        );
        Ok(())
    }
}

/// Build a per-process opaque identifier for an inbound UDP source tuple.
///
/// XUDP peers use this value to retain source-port affinity when the reliable
/// stream reconnects. `RandomState` supplies a process-random keyed hasher, so
/// the identifier is stable for the same source during this process without
/// exposing the source address on the wire.
pub(crate) fn global_id_for_session(session: &Session) -> [u8; 8] {
    static HASHER: OnceLock<RandomState> = OnceLock::new();

    if session.network != Network::Udp
        || session.source.ip().is_unspecified()
        || session.source.port() == 0
    {
        return [0; 8];
    }

    HASHER
        .get_or_init(RandomState::new)
        .hash_one(session.source)
        .to_be_bytes()
}

fn encode_frame(
    status: u8,
    destination: Option<&SocksAddr>,
    global_id: [u8; 8],
    payload: &[u8],
    out: &mut BytesMut,
) -> io::Result<()> {
    if payload.len() > MAX_PACKET_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "XUDP packet too large: {} > {MAX_PACKET_LENGTH}",
                payload.len()
            ),
        ));
    }

    let mut metadata = BytesMut::with_capacity(32);
    metadata.put_u16(0); // Single XUDP always uses mux session ID zero.
    metadata.put_u8(status);
    metadata.put_u8(OPTION_DATA);

    if matches!(status, STATUS_NEW | STATUS_KEEP) {
        metadata.put_u8(NETWORK_UDP);
        let destination = destination.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "XUDP data frame requires a destination",
            )
        })?;
        write_port_then_address(destination, &mut metadata)?;
        if status == STATUS_NEW {
            metadata.put_slice(&global_id);
        }
    }

    if metadata.len() > MAX_METADATA_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP metadata exceeds the supported limit",
        ));
    }

    out.clear();
    out.reserve(2 + metadata.len() + 2 + payload.len());
    out.put_u16(metadata.len() as u16);
    out.put_slice(&metadata);
    out.put_u16(payload.len() as u16);
    out.put_slice(payload);
    Ok(())
}

fn write_port_then_address(
    address: &SocksAddr,
    out: &mut BytesMut,
) -> io::Result<()> {
    match address {
        SocksAddr::Ip(SocketAddr::V4(addr)) => {
            out.put_u16(addr.port());
            out.put_u8(ADDRESS_IPV4);
            out.put_slice(&addr.ip().octets());
        }
        SocksAddr::Ip(SocketAddr::V6(addr)) => {
            out.put_u16(addr.port());
            out.put_u8(ADDRESS_IPV6);
            out.put_slice(&addr.ip().octets());
        }
        SocksAddr::Domain(domain, port) => {
            let domain = domain.as_bytes();
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "XUDP domain must contain between 1 and 255 bytes",
                ));
            }
            out.put_u16(*port);
            out.put_u8(ADDRESS_DOMAIN);
            out.put_u8(domain.len() as u8);
            out.put_slice(domain);
        }
    }
    Ok(())
}

fn frame_length(input: &[u8]) -> io::Result<Option<usize>> {
    if input.len() < 2 {
        return Ok(None);
    }
    let metadata_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if !(4..=MAX_METADATA_LENGTH).contains(&metadata_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid XUDP metadata length: {metadata_len}"),
        ));
    }

    let metadata_end = 2 + metadata_len;
    if input.len() < metadata_end {
        return Ok(None);
    }
    let option = input[2 + 3];
    match option {
        0 => Ok(Some(metadata_end)),
        OPTION_DATA => {
            if input.len() < metadata_end + 2 {
                return Ok(None);
            }
            let payload_len =
                u16::from_be_bytes([input[metadata_end], input[metadata_end + 1]])
                    as usize;
            let frame_end = metadata_end + 2 + payload_len;
            if input.len() < frame_end {
                Ok(None)
            } else {
                Ok(Some(frame_end))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported XUDP option: {option}"),
        )),
    }
}

enum DecodedFrame {
    Packet(UdpPacket),
    Skip,
    End,
}

fn decode_frame(frame: &[u8], remote_addr: &SocksAddr) -> io::Result<DecodedFrame> {
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let metadata_end = 2 + metadata_len;
    let metadata = &frame[2..metadata_end];
    let status = metadata[2];
    let option = metadata[3];

    if status == STATUS_END {
        return Ok(DecodedFrame::End);
    }
    if status == STATUS_KEEPALIVE {
        return Ok(DecodedFrame::Skip);
    }
    if status != STATUS_KEEP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected XUDP response status: {status}"),
        ));
    }
    if option == 0 {
        return Ok(DecodedFrame::Skip);
    }

    let address = if metadata.len() == 4 {
        remote_addr.clone()
    } else {
        if metadata[4] != NETWORK_UDP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected XUDP response network: {}", metadata[4]),
            ));
        }
        let (address, _) = read_port_then_address(metadata, 5)?;
        address
    };

    let payload_start = metadata_end + 2;
    let payload_len =
        u16::from_be_bytes([frame[metadata_end], frame[metadata_end + 1]]) as usize;
    if payload_len == 0 {
        return Ok(DecodedFrame::Skip);
    }
    let data = frame[payload_start..payload_start + payload_len].to_vec();
    Ok(DecodedFrame::Packet(UdpPacket {
        data,
        src_addr: address.clone(),
        dst_addr: address,
        inbound_user: None,
    }))
}

fn read_port_then_address(
    input: &[u8],
    start: usize,
) -> io::Result<(SocksAddr, usize)> {
    let port_bytes = input.get(start..start + 2).ok_or_else(invalid_address)?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    let atyp = *input.get(start + 2).ok_or_else(invalid_address)?;
    let address_start = start + 3;

    match atyp {
        ADDRESS_IPV4 => {
            let bytes = input
                .get(address_start..address_start + 4)
                .ok_or_else(invalid_address)?;
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Ok((SocksAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7))
        }
        ADDRESS_DOMAIN => {
            let len =
                *input.get(address_start).ok_or_else(invalid_address)? as usize;
            if len == 0 {
                return Err(invalid_address());
            }
            let domain_start = address_start + 1;
            let domain_bytes = input
                .get(domain_start..domain_start + len)
                .ok_or_else(invalid_address)?;
            let domain = std::str::from_utf8(domain_bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid XUDP domain")
            })?;
            Ok((SocksAddr::Domain(domain.to_owned(), port), len + 4))
        }
        ADDRESS_IPV6 => {
            let bytes = input
                .get(address_start..address_start + 16)
                .ok_or_else(invalid_address)?;
            let octets: [u8; 16] =
                bytes.try_into().map_err(|_| invalid_address())?;
            let ip = Ipv6Addr::from(octets);
            Ok((SocksAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port)), 19))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported XUDP address type: {atyp}"),
        )),
    }
}

fn invalid_address() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "truncated XUDP address")
}

impl Sink<UdpPacket> for OutboundDatagramXudp {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            ready!(self.poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if this.pending_packet.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous XUDP packet not yet sent",
            ));
        }
        if item.data.is_empty() {
            return Ok(());
        }

        this.write_packet(&item)?;
        this.pending_packet = Some(item);
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.flushed {
            return Poll::Ready(Ok(()));
        }

        while !this.write_buf.is_empty() {
            let n =
                ready!(Pin::new(&mut this.inner).poll_write(cx, &this.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write XUDP frame",
                )));
            }
            this.write_buf.advance(n);
        }

        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        if let Some(packet) = &this.pending_packet {
            debug!(data_len = packet.data.len(), "sent VLESS XUDP packet");
        }
        this.pending_packet = None;
        this.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramXudp {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.read_terminated {
            return Poll::Ready(None);
        }

        loop {
            match frame_length(&this.read_buf) {
                Ok(Some(length)) => {
                    let frame = this.read_buf.split_to(length);
                    match decode_frame(&frame, &this.remote_addr) {
                        Ok(DecodedFrame::Packet(packet)) => {
                            trace!(
                                source = %packet.src_addr,
                                data_len = packet.data.len(),
                                "received VLESS XUDP packet"
                            );
                            return Poll::Ready(Some(packet));
                        }
                        Ok(DecodedFrame::Skip) => continue,
                        Ok(DecodedFrame::End) => {
                            this.read_terminated = true;
                            return Poll::Ready(None);
                        }
                        Err(error) => {
                            debug!(%error, "invalid VLESS XUDP response frame");
                            this.read_terminated = true;
                            return Poll::Ready(None);
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    debug!(%error, "invalid VLESS XUDP response framing");
                    this.read_terminated = true;
                    return Poll::Ready(None);
                }
            }

            let mut scratch = [0u8; READ_CHUNK_LENGTH];
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes = read_buf.filled();
                    if bytes.is_empty() {
                        this.read_terminated = true;
                        return Poll::Ready(None);
                    }
                    this.read_buf.extend_from_slice(bytes);
                }
                Poll::Ready(Err(error)) => {
                    debug!(%error, "failed to read VLESS XUDP frame");
                    this.read_terminated = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use bytes::BytesMut;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        MAX_METADATA_LENGTH, MAX_PACKET_LENGTH, OutboundDatagramXudp, STATUS_KEEP,
        STATUS_KEEPALIVE, decode_frame, encode_frame, frame_length,
    };
    use crate::{proxy::datagram::UdpPacket, session::SocksAddr};

    fn packet(data: &[u8], destination: SocksAddr) -> UdpPacket {
        UdpPacket::new(data.to_vec(), SocksAddr::any_ipv4(), destination)
    }

    fn encode_test_frame(
        status: u8,
        destination: Option<&SocksAddr>,
        data: &[u8],
    ) -> BytesMut {
        let mut frame = BytesMut::new();
        encode_frame(status, destination, [0x44; 8], data, &mut frame)
            .expect("valid test frame");
        frame
    }

    #[test]
    fn first_and_followup_frames_match_single_xudp_layout() {
        let destination: SocksAddr = "203.0.113.7:53".parse().expect("address");
        let mut datagram = OutboundDatagramXudp::new(
            Box::new(tokio::io::duplex(64).0),
            destination.clone(),
            [0xaa; 8],
        );
        let mut first = BytesMut::new();
        datagram
            .write_packet(&packet(b"dns", destination.clone()))
            .expect("first frame");
        first.extend_from_slice(&datagram.write_buf);

        let mut followup = BytesMut::new();
        datagram
            .write_packet(&packet(b"next", destination))
            .expect("follow-up frame");
        followup.extend_from_slice(&datagram.write_buf);

        assert_eq!(
            &first[..],
            &[
                0, 20, // metadata length
                0, 0, // single XUDP session ID
                1, 1, 2, // New, data, UDP
                0, 53, 1, 203, 0, 113, 7, // port and IPv4 destination
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // Global ID
                0, 3, b'd', b'n', b's',
            ]
        );
        assert_eq!(
            &followup[..],
            &[
                0,
                12, // metadata length
                0,
                0, // single XUDP session ID
                STATUS_KEEP,
                1,
                2, // Keep, data, UDP
                0,
                53,
                1,
                203,
                0,
                113,
                7,
                0,
                4,
                b'n',
                b'e',
                b'x',
                b't',
            ]
        );
    }

    #[test]
    fn xudp_addresses_round_trip_for_ipv4_domain_and_ipv6() {
        for destination in [
            SocksAddr::Ip(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 8), 53))),
            SocksAddr::Domain("dns.example".to_owned(), 5353),
            SocksAddr::Ip(SocketAddr::from((Ipv6Addr::LOCALHOST, 853))),
        ] {
            let frame = encode_test_frame(STATUS_KEEP, Some(&destination), b"reply");
            let length = frame_length(&frame)
                .expect("frame length should parse")
                .expect("complete frame");
            assert_eq!(length, frame.len());
            match decode_frame(&frame, &destination).expect("response frame") {
                super::DecodedFrame::Packet(decoded) => {
                    assert_eq!(decoded.src_addr, destination);
                    assert_eq!(decoded.data, b"reply");
                }
                _ => panic!("expected a UDP response packet"),
            }
        }
    }

    #[tokio::test]
    async fn fragmented_response_and_keepalive_are_handled() {
        let (client, mut server) = tokio::io::duplex(1);
        let destination: SocksAddr = "198.51.100.4:1234".parse().expect("address");
        let mut keepalive = BytesMut::new();
        encode_frame(STATUS_KEEPALIVE, None, [0; 8], b"discard", &mut keepalive)
            .expect("keepalive frame");
        let response = encode_test_frame(STATUS_KEEP, Some(&destination), b"reply");
        let mut frames = keepalive.to_vec();
        frames.extend_from_slice(&response);

        let writer = tokio::spawn(async move {
            for byte in frames {
                server.write_all(&[byte]).await.expect("fragmented write");
            }
        });
        let mut datagram =
            OutboundDatagramXudp::new(Box::new(client), destination.clone(), [0; 8]);
        let decoded = datagram.next().await.expect("UDP response");
        assert_eq!(decoded.src_addr, destination);
        assert_eq!(decoded.data, b"reply");
        writer.await.expect("writer task");
    }

    #[tokio::test]
    async fn truncated_response_payload_never_emits_a_partial_packet() {
        let (client, mut server) = tokio::io::duplex(64);
        let destination: SocksAddr = "198.51.100.7:443".parse().expect("address");
        let mut response =
            encode_test_frame(STATUS_KEEP, Some(&destination), b"reply");
        response.truncate(response.len() - 1);
        server.write_all(&response).await.expect("partial response");
        server.shutdown().await.expect("close response stream");

        let mut datagram =
            OutboundDatagramXudp::new(Box::new(client), destination, [0; 8]);
        assert!(datagram.next().await.is_none());
        assert!(datagram.next().await.is_none(), "EOF remains terminal");
    }

    #[tokio::test]
    async fn cancelled_partial_write_resumes_without_duplicate_frame_bytes() {
        let (client, mut server) = tokio::io::duplex(1);
        let destination: SocksAddr = "192.0.2.12:53".parse().expect("address");
        let mut datagram = OutboundDatagramXudp::new(
            Box::new(client),
            destination.clone(),
            [0x33; 8],
        );
        let mut expected = BytesMut::new();
        encode_frame(1, Some(&destination), [0x33; 8], b"dns", &mut expected)
            .expect("expected frame");

        {
            let send = datagram.send(packet(b"dns", destination));
            tokio::pin!(send);
            assert!(futures::poll!(send.as_mut()).is_pending());
        }

        let expected = expected.to_vec();
        let reader = tokio::spawn(async move {
            let mut actual = vec![0; expected.len()];
            server
                .read_exact(&mut actual)
                .await
                .expect("complete frame");
            (actual, expected)
        });
        datagram.flush().await.expect("resume pending frame");
        let (actual, expected) = reader.await.expect("reader task");
        assert_eq!(actual, expected);
        assert!(!datagram.first_packet);
    }

    #[tokio::test]
    async fn sink_frames_are_written_once_and_oversized_packets_rejected() {
        let (client, mut server) = tokio::io::duplex(1);
        let destination: SocksAddr = "192.0.2.9:443".parse().expect("address");
        let mut datagram = OutboundDatagramXudp::new(
            Box::new(client),
            destination.clone(),
            [0x22; 8],
        );
        let mut expected = BytesMut::new();
        encode_frame(1, Some(&destination), [0x22; 8], b"body", &mut expected)
            .expect("expected frame");
        let send = tokio::spawn(async move {
            datagram
                .send(packet(b"body", destination))
                .await
                .expect("send XUDP packet");
        });
        let mut actual = vec![0; expected.len()];
        server
            .read_exact(&mut actual)
            .await
            .expect("complete frame");
        send.await.expect("send task");

        let (client, _server) = tokio::io::duplex(1);
        let mut oversized = OutboundDatagramXudp::new(
            Box::new(client),
            "192.0.2.9:443".parse().expect("address"),
            [0; 8],
        );
        let err = oversized
            .send(packet(
                &vec![0; MAX_PACKET_LENGTH + 1],
                "192.0.2.9:443".parse().expect("address"),
            ))
            .await
            .expect_err("oversized packet must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(actual, expected);
    }

    #[test]
    fn outbound_packet_limit_matches_xray_eight_kib_buffer() {
        let destination: SocksAddr = "192.0.2.10:443".parse().expect("address");
        let mut datagram = OutboundDatagramXudp::new(
            Box::new(tokio::io::duplex(64).0),
            destination.clone(),
            [0; 8],
        );
        let max_packet = vec![0; MAX_PACKET_LENGTH];
        datagram
            .write_packet(&packet(&max_packet, destination.clone()))
            .expect("8 KiB packet is accepted");
        assert_eq!(
            u16::from_be_bytes([
                datagram.write_buf[datagram.write_buf.len() - MAX_PACKET_LENGTH - 2],
                datagram.write_buf[datagram.write_buf.len() - MAX_PACKET_LENGTH - 1],
            ]) as usize,
            MAX_PACKET_LENGTH
        );

        let too_large = vec![0; MAX_PACKET_LENGTH + 1];
        let err = datagram
            .write_packet(&packet(&too_large, destination))
            .expect_err("one byte above the Xray reader limit is rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn xudp_metadata_length_is_bounded() {
        let bytes = ((MAX_METADATA_LENGTH + 1) as u16).to_be_bytes();
        let err = frame_length(&bytes).expect_err("oversized metadata rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
