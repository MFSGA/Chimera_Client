use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const MAX_PACKET_LENGTH: usize = u16::MAX as usize;

pub struct OutboundDatagramVless {
    inner: AnyStream,
    remote_addr: SocksAddr,
    xudp: bool,
    xudp_request_written: bool,
    xudp_read_buf: BytesMut,

    // Write state
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,

    // Read state
    packet_buf: BytesMut,
    remaining_bytes: usize,
    length_buf: [u8; 2],
    header_read: usize,

    // State tracking
    flushed: bool,
}

impl OutboundDatagramVless {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr, xudp: bool) -> Self {
        Self {
            inner,
            remote_addr,
            xudp,
            xudp_request_written: false,
            xudp_read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
            pending_packet: None,
            packet_buf: BytesMut::new(),
            remaining_bytes: 0,
            length_buf: [0; 2],
            header_read: 0,
            flushed: true,
        }
    }

    fn write_packet(
        &mut self,
        payload: &[u8],
        destination: &SocksAddr,
    ) -> Result<(), io::Error> {
        self.write_buf.clear();

        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet too large: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        if self.xudp {
            // Xray-compatible XUDP packet encoding. The two zero bytes after
            // the frame length are the mux session id; the remaining frame
            // metadata is status, option, network, and destination address.
            let frame_len =
                5usize.checked_add(destination.size()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "XUDP destination is too large",
                    )
                })?;
            if frame_len > u16::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "XUDP destination frame is too large",
                ));
            }

            self.write_buf.put_u16(frame_len as u16);
            self.write_buf.put_u16(0); // mux session id
            self.write_buf
                .put_u8(if self.xudp_request_written { 2 } else { 1 });
            self.write_buf.put_u8(1); // option data
            self.write_buf.put_u8(2); // UDP
            destination.write_to_buf_vmess(&mut self.write_buf);
            self.write_buf.put_u16(payload.len() as u16);
            self.write_buf.put_slice(payload);
        } else {
            // Raw VLESS UDP packet encoding: 2-byte length + payload.
            self.write_buf.put_u16(payload.len() as u16);
            self.write_buf.put_slice(payload);
        }

        trace!(
            "encoded VLESS UDP packet: len={}, xudp={}",
            payload.len(),
            self.xudp
        );
        Ok(())
    }

    fn try_decode_xudp_frame(&mut self) -> io::Result<XudpDecode> {
        if self.xudp_read_buf.len() < 6 {
            return Ok(XudpDecode::Incomplete);
        }

        let frame_len =
            u16::from_be_bytes([self.xudp_read_buf[0], self.xudp_read_buf[1]])
                as usize;
        if frame_len < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid XUDP frame length: {frame_len}"),
            ));
        }

        let meta_end = 2 + frame_len;
        if self.xudp_read_buf.len() < meta_end {
            return Ok(XudpDecode::Incomplete);
        }

        let status = self.xudp_read_buf[4];
        let options = self.xudp_read_buf[5];
        if status == 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected XUDP new frame from server",
            ));
        }
        if status == 3 {
            self.xudp_read_buf.advance(meta_end);
            return Ok(XudpDecode::End);
        }
        if status != 2 && status != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected XUDP frame type: {status}"),
            ));
        }
        if options & 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "remote closed XUDP session",
            ));
        }

        let destination = if frame_len == 4 {
            self.remote_addr.clone()
        } else {
            if self.xudp_read_buf[6] != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XUDP frame is not UDP",
                ));
            }
            parse_xudp_address(&self.xudp_read_buf[7..meta_end])?
        };

        if options & 1 == 0 {
            self.xudp_read_buf.advance(meta_end);
            return Ok(XudpDecode::Skip);
        }

        let payload_len = u16::from_be_bytes([
            self.xudp_read_buf[meta_end],
            self.xudp_read_buf[meta_end + 1],
        ]) as usize;
        let total_len = meta_end + 2 + payload_len;
        if self.xudp_read_buf.len() < total_len {
            return Ok(XudpDecode::Incomplete);
        }

        let payload_start = meta_end + 2;
        let data = self.xudp_read_buf[payload_start..total_len].to_vec();
        self.xudp_read_buf.advance(total_len);
        if data.is_empty() {
            return Ok(XudpDecode::Skip);
        }

        Ok(XudpDecode::Packet(UdpPacket {
            data,
            src_addr: destination.clone(),
            dst_addr: destination,
            inbound_user: None,
        }))
    }

    fn poll_next_xudp(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        loop {
            match self.try_decode_xudp_frame() {
                Ok(XudpDecode::Packet(packet)) => {
                    return Poll::Ready(Some(packet));
                }
                Ok(XudpDecode::End) => return Poll::Ready(None),
                Ok(XudpDecode::Skip) => continue,
                Ok(XudpDecode::Incomplete) => {}
                Err(err) => {
                    debug!("failed to decode XUDP frame: {err}");
                    return Poll::Ready(None);
                }
            }

            let mut scratch = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(None);
                    }
                    self.xudp_read_buf.extend_from_slice(&scratch[..n]);
                }
                Poll::Ready(Err(err)) => {
                    debug!("failed to read XUDP frame: {err}");
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

enum XudpDecode {
    Incomplete,
    Skip,
    Packet(UdpPacket),
    End,
}

fn parse_xudp_address(buf: &[u8]) -> io::Result<SocksAddr> {
    if buf.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated XUDP destination",
        ));
    }

    let port = u16::from_be_bytes([buf[0], buf[1]]);
    match buf[2] {
        0x01 => {
            if buf.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated XUDP IPv4 destination",
                ));
            }
            Ok(SocksAddr::from((
                std::net::Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]),
                port,
            )))
        }
        0x02 => {
            let len = buf[3] as usize;
            if buf.len() < 4 + len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated XUDP domain destination",
                ));
            }
            let domain = std::str::from_utf8(&buf[4..4 + len])
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid XUDP domain")
                })?
                .to_owned();
            Ok(SocksAddr::Domain(domain, port))
        }
        0x03 => {
            if buf.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated XUDP IPv6 destination",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[3..19]);
            Ok(SocksAddr::from((std::net::Ipv6Addr::from(octets), port)))
        }
        atyp => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown XUDP address type: {atyp}"),
        )),
    }
}

impl Sink<UdpPacket> for OutboundDatagramVless {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();

        if this.pending_packet.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous packet not yet sent",
            ));
        }

        let total_len = item.data.len();
        if total_len == 0 {
            return Ok(()); // Skip empty packets
        }
        if total_len > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "VLESS UDP packet too large: {total_len} > {MAX_PACKET_LENGTH}"
                ),
            ));
        }

        // A UDP datagram is atomic. Splitting it into multiple VLESS frames
        // would change packet boundaries, so encode the whole datagram once.
        this.write_packet(&item.data, &item.dst_addr)?;
        this.pending_packet = Some(item);
        this.flushed = false;

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();

        if this.write_buf.is_empty() {
            this.flushed = true;
            this.pending_packet = None;
            return Poll::Ready(Ok(()));
        }

        let mut inner = Pin::new(&mut this.inner);

        // Write the encoded packet
        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write packet data",
                )));
            }
            this.write_buf.advance(n);
        }

        // Flush the underlying stream
        ready!(inner.poll_flush(cx))?;

        if let Some(packet) = &this.pending_packet {
            debug!("sent VLESS UDP packet, data_len={}", packet.data.len());
        }

        this.flushed = true;
        this.pending_packet = None;
        if this.xudp {
            this.xudp_request_written = true;
        }

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

impl Stream for OutboundDatagramVless {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.xudp {
            return this.poll_next_xudp(cx);
        }

        let mut inner = Pin::new(&mut this.inner);

        loop {
            // Phase 1: read the 2-byte length header.  TCP may deliver a
            // single byte at a time, so we must accumulate until both bytes
            // are available.  The previous code treated a 1-byte read as
            // "incomplete" and returned EOF, prematurely closing the stream.
            if this.remaining_bytes == 0 && this.header_read < 2 {
                let mut header_read_buf =
                    ReadBuf::new(&mut this.length_buf[this.header_read..]);
                match ready!(inner.as_mut().poll_read(cx, &mut header_read_buf)) {
                    Ok(()) => {
                        let n = header_read_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(None); // connection closed
                        }
                        this.header_read += n;
                        if this.header_read < 2 {
                            continue; // need the second header byte
                        }

                        let packet_len =
                            u16::from_be_bytes(this.length_buf) as usize;
                        this.header_read = 0;

                        if packet_len == 0 {
                            trace!("received empty packet");
                            continue; // skip empty packets
                        }

                        if packet_len > MAX_PACKET_LENGTH {
                            debug!("packet too large: {} bytes", packet_len);
                            return Poll::Ready(None);
                        }

                        this.remaining_bytes = packet_len;
                        this.packet_buf.clear();
                        this.packet_buf.reserve(packet_len);
                        trace!("expecting VLESS UDP packet of {} bytes", packet_len);
                    }
                    Err(e) => {
                        debug!("failed to read length header: {}", e);
                        return Poll::Ready(None);
                    }
                }
            }

            // Phase 2: read the packet payload.  TCP may deliver it in
            // multiple chunks; we must accumulate until the full packet is
            // received before returning it.  The previous code returned a
            // UdpPacket for every poll_read call, splitting a single VLESS
            // UDP packet into multiple items and corrupting the data stream.
            if this.remaining_bytes > 0 {
                let remaining = this.remaining_bytes - this.packet_buf.len();
                let n = {
                    let spare = this.packet_buf.spare_capacity_mut();
                    let mut read_buf = ReadBuf::uninit(&mut spare[..remaining]);
                    match inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            debug!("failed to read packet data: {}", e);
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(())) => read_buf.filled().len(),
                    }
                };
                if n == 0 {
                    return Poll::Ready(None); // connection closed
                }
                // SAFETY: poll_read initialized exactly n bytes starting at
                // the beginning of the spare capacity.
                unsafe { this.packet_buf.advance_mut(n) };

                if this.packet_buf.len() == this.remaining_bytes {
                    let data =
                        this.packet_buf.split_to(this.remaining_bytes).to_vec();
                    this.remaining_bytes = 0;
                    trace!("received complete VLESS UDP packet, len={}", data.len());
                    return Poll::Ready(Some(UdpPacket {
                        data,
                        src_addr: this.remote_addr.clone(),
                        dst_addr: this.remote_addr.clone(),
                        inbound_user: None,
                    }));
                }
                // Partial read: loop and continue accumulating.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{MAX_PACKET_LENGTH, OutboundDatagramVless};
    use crate::{proxy::datagram::UdpPacket, session::SocksAddr};

    fn packet(data: Vec<u8>) -> UdpPacket {
        let addr: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        UdpPacket {
            data,
            src_addr: addr.clone(),
            dst_addr: addr,
            inbound_user: None,
        }
    }

    #[tokio::test]
    async fn udp_datagram_larger_than_8k_is_not_truncated() {
        let (client, mut server) = tokio::io::duplex(128 * 1024);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram =
            OutboundDatagramVless::new(Box::new(client), remote, false);
        let payload = vec![0x5a; 9 * 1024];

        datagram
            .send(packet(payload.clone()))
            .await
            .expect("large valid datagram should send");

        let mut length = [0u8; 2];
        server.read_exact(&mut length).await.expect("length header");
        assert_eq!(u16::from_be_bytes(length) as usize, payload.len());

        let mut received = vec![0u8; payload.len()];
        server
            .read_exact(&mut received)
            .await
            .expect("full datagram");
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn xudp_encodes_vmess_address_order_and_session_frames() {
        let (client, mut server) = tokio::io::duplex(4096);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram =
            OutboundDatagramVless::new(Box::new(client), remote, true);

        datagram
            .send(packet(b"abc".to_vec()))
            .await
            .expect("first XUDP packet");
        let mut first = vec![0u8; 19];
        server
            .read_exact(&mut first)
            .await
            .expect("first XUDP frame");
        assert_eq!(
            &first[..],
            &[
                0, 12, // metadata length
                0, 0, // mux session id
                1, 1, 2, // new, data, UDP
                0, 53, 1, 1, 1, 1, 1, // port, IPv4 address
                0, 3, b'a', b'b', b'c',
            ]
        );

        datagram
            .send(packet(b"def".to_vec()))
            .await
            .expect("keep XUDP packet");
        let mut second = vec![0u8; 19];
        server
            .read_exact(&mut second)
            .await
            .expect("keep XUDP frame");
        assert_eq!(
            &second[..],
            &[
                0, 12, 0, 0, 2, 1, 2, 0, 53, 1, 1, 1, 1, 1, 0, 3, b'd', b'e', b'f',
            ]
        );
    }

    #[tokio::test]
    async fn xudp_decodes_keep_frame_destination() {
        let (client, mut server) = tokio::io::duplex(4096);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram =
            OutboundDatagramVless::new(Box::new(client), remote, true);

        let frame = [
            0, 12, 0, 0, 2, 1, 2, 0, 53, 1, 8, 8, 8, 8, 0, 3, b'x', b'y', b'z',
        ];
        tokio::spawn(async move {
            server.write_all(&frame).await.expect("write XUDP frame");
        });

        let packet = datagram.next().await.expect("XUDP packet");
        assert_eq!(packet.data, b"xyz");
        assert_eq!(packet.dst_addr, "8.8.8.8:53".parse().unwrap());
    }

    #[tokio::test]
    async fn udp_datagram_above_u16_frame_limit_is_rejected() {
        let (client, _server) = tokio::io::duplex(1024);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram =
            OutboundDatagramVless::new(Box::new(client), remote, false);

        let err = datagram
            .send(packet(vec![0u8; MAX_PACKET_LENGTH + 1]))
            .await
            .expect_err("oversized datagram must fail instead of truncating");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("VLESS UDP packet too large"));
    }
}
