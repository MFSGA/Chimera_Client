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

    // Write state
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,

    // Read state
    packet_buf: BytesMut,
    remaining_bytes: usize,
    length_buf: [u8; 2],
    header_read: usize,
    read_terminated: bool,

    // State tracking
    flushed: bool,
}

impl OutboundDatagramVless {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            write_buf: BytesMut::new(),
            pending_packet: None,
            packet_buf: BytesMut::new(),
            remaining_bytes: 0,
            length_buf: [0; 2],
            header_read: 0,
            read_terminated: false,
            flushed: true,
        }
    }

    fn write_packet(&mut self, payload: &[u8]) -> Result<(), io::Error> {
        self.write_buf.clear();

        // VLESS UDP packet format is simpler than expected:
        // Just 2-byte length + payload data
        // No address encoding in the packet data phase!

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

        // Write length header (big-endian)
        self.write_buf.put_u16(payload.len() as u16);

        // Write payload
        self.write_buf.put_slice(payload);

        trace!("encoded VLESS UDP packet: len={}", payload.len());
        Ok(())
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
        this.write_packet(&item.data)?;
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
        if this.read_terminated {
            return Poll::Ready(None);
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
                            this.read_terminated = true;
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
                            this.read_terminated = true;
                            return Poll::Ready(None);
                        }

                        this.remaining_bytes = packet_len;
                        this.packet_buf.clear();
                        this.packet_buf.reserve(packet_len);
                        trace!("expecting VLESS UDP packet of {} bytes", packet_len);
                    }
                    Err(e) => {
                        debug!("failed to read length header: {}", e);
                        this.read_terminated = true;
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
                            this.read_terminated = true;
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(())) => read_buf.filled().len(),
                    }
                };
                if n == 0 {
                    this.read_terminated = true;
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
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::{MAX_PACKET_LENGTH, OutboundDatagramVless};
    use crate::{proxy::datagram::UdpPacket, session::SocksAddr};

    struct FailNthRead {
        inner: tokio::io::DuplexStream,
        fail_on_read: usize,
        read_calls: usize,
        max_read_bytes: usize,
    }

    impl AsyncRead for FailNthRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let call = self.read_calls;
            self.read_calls += 1;
            if call == self.fail_on_read {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "simulated read failure",
                )));
            }

            // Bound each successful read so an injected failure reliably lands
            // after a partial header or payload, independent of duplex batching.
            let mut bytes = [0u8; 8];
            let len = buf.remaining().min(self.max_read_bytes).min(bytes.len());
            let mut bounded = ReadBuf::new(&mut bytes[..len]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut bounded) {
                Poll::Ready(Ok(())) => {
                    buf.put_slice(bounded.filled());
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for FailNthRead {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

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
        let mut datagram = OutboundDatagramVless::new(Box::new(client), remote);
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
    async fn truncated_udp_payload_never_emits_a_partial_datagram() {
        let (client, mut server) = tokio::io::duplex(64);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram = OutboundDatagramVless::new(Box::new(client), remote);
        server
            .write_all(&[0, 4, 0x11, 0x22])
            .await
            .expect("truncated datagram");
        drop(server);

        assert!(
            datagram.next().await.is_none(),
            "a partial UDP datagram must not be forwarded after EOF"
        );
        assert!(datagram.next().await.is_none(), "EOF must remain terminal");
    }

    #[tokio::test]
    async fn cancelled_partial_udp_length_read_resumes_complete_packet() {
        let (client, mut server) = tokio::io::duplex(64);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram = OutboundDatagramVless::new(Box::new(client), remote);

        server.write_all(&[0]).await.expect("first length byte");
        assert!(
            futures::poll!(datagram.next()).is_pending(),
            "a partial length header must remain pending"
        );

        // The pending next() future was cancelled; retain the first byte.
        server
            .write_all(&[3, 0x11, 0x22, 0x33])
            .await
            .expect("complete header and payload");
        let received = datagram.next().await.expect("complete UDP packet");
        assert_eq!(received.data, vec![0x11, 0x22, 0x33]);
    }

    #[tokio::test]
    async fn truncated_udp_length_header_never_emits_a_packet() {
        let (client, mut server) = tokio::io::duplex(64);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram = OutboundDatagramVless::new(Box::new(client), remote);

        server.write_all(&[0]).await.expect("partial length header");
        drop(server);
        assert!(
            datagram.next().await.is_none(),
            "EOF mid-header must not emit a UDP packet"
        );
        assert!(datagram.next().await.is_none(), "EOF must remain terminal");
    }

    #[tokio::test]
    async fn cancelled_pending_udp_send_releases_the_owned_stream() {
        let (client, mut server) = tokio::io::duplex(32);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram = OutboundDatagramVless::new(Box::new(client), remote);
        let send = tokio::spawn(async move {
            // Without a reader this send cannot finish. Aborting the task
            // must drop the datagram and its owned transport promptly.
            datagram.send(packet(vec![0x35; 9 * 1024])).await
        });
        tokio::task::yield_now().await;
        send.abort();
        let _ = send.await;

        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.read_to_end(&mut received),
        )
        .await
        .expect("cancelled transport must close without hanging")
        .expect("read remaining pending bytes");
        assert!(received.len() < 9 * 1024);
    }

    #[tokio::test]
    async fn udp_read_errors_are_terminal_for_header_and_partial_frames() {
        let cases: &[(&str, &[u8], usize, usize)] = &[
            ("before header", &[0, 1, 0x42], 0, 2),
            ("after one header byte", &[0, 1, 0x42], 1, 1),
            (
                "after two payload bytes",
                &[0, 4, 0x11, 0x22, 0x33, 0x44],
                2,
                2,
            ),
        ];
        for &(phase, wire, fail_on_read, max_read_bytes) in cases {
            let (client, mut server) = tokio::io::duplex(64);
            server.write_all(wire).await.expect("synthetic UDP frame");
            let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
            let stream = FailNthRead {
                inner: client,
                fail_on_read,
                read_calls: 0,
                max_read_bytes,
            };
            let mut datagram = OutboundDatagramVless::new(Box::new(stream), remote);

            assert!(
                datagram.next().await.is_none(),
                "read failure {phase} must terminate the stream"
            );
            assert!(
                datagram.next().await.is_none(),
                "read failure {phase} must not resume decoding"
            );
        }
    }

    #[tokio::test]
    async fn udp_read_error_after_complete_packet_is_terminal() {
        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[0, 1, 0x42, 0, 1, 0x43])
            .await
            .expect("two complete UDP frames");
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let stream = FailNthRead {
            inner: client,
            fail_on_read: 2, // First packet's header and payload were read successfully.
            read_calls: 0,
            max_read_bytes: 2,
        };
        let mut datagram = OutboundDatagramVless::new(Box::new(stream), remote);

        assert_eq!(datagram.next().await.expect("first packet").data, [0x42]);
        assert!(
            datagram.next().await.is_none(),
            "next header read must fail"
        );
        assert!(
            datagram.next().await.is_none(),
            "failure must stay terminal"
        );
    }

    #[tokio::test]
    async fn udp_eof_after_complete_packet_is_terminal() {
        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[0, 1, 0x42])
            .await
            .expect("one complete UDP frame");
        drop(server);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram = OutboundDatagramVless::new(Box::new(client), remote);

        assert_eq!(datagram.next().await.expect("first packet").data, [0x42]);
        assert!(datagram.next().await.is_none(), "EOF after frame");
        assert!(datagram.next().await.is_none(), "EOF must stay terminal");
    }

    #[tokio::test]
    async fn udp_datagram_above_u16_frame_limit_is_rejected() {
        let (client, _server) = tokio::io::duplex(1024);
        let remote: SocksAddr = "1.1.1.1:53".parse().expect("test address");
        let mut datagram = OutboundDatagramVless::new(Box::new(client), remote);

        let err = datagram
            .send(packet(vec![0u8; MAX_PACKET_LENGTH + 1]))
            .await
            .expect_err("oversized datagram must fail instead of truncating");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("VLESS UDP packet too large"));
    }
}
