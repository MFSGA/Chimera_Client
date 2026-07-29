use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::{proxy::AnyStream, session::SocksAddr};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;
const XTLS_VISION_FLOW: &str = "xtls-rprx-vision";

struct PendingWrite {
    data: BytesMut,
    written: usize,
    user_len: usize,
}

pub struct VlessStream {
    inner: AnyStream,
    handshake_done: bool,
    handshake_sent: bool,
    response_received: bool,
    pending_write: Option<PendingWrite>,
    response_header: [u8; 2],
    response_header_read: usize,
    response_additional_remaining: Option<usize>,
    uuid: uuid::Uuid,
    destination: SocksAddr,
    is_udp: bool,
    flow: Option<String>,
}

impl VlessStream {
    pub fn new(
        stream: AnyStream,
        uuid: &str,
        destination: &SocksAddr,
        is_udp: bool,
        flow: Option<String>,
    ) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID format")
        })?;

        debug!("VLESS stream created for destination: {}", destination);

        Ok(Self {
            inner: stream,
            handshake_done: false,
            handshake_sent: false,
            response_received: false,
            pending_write: None,
            response_header: [0; 2],
            response_header_read: 0,
            response_additional_remaining: None,
            uuid,
            destination: destination.clone(),
            is_udp,
            flow,
        })
    }

    fn build_handshake_header(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        let addons = self.encode_request_addons();

        // VLESS request header:
        // Version (1 byte) + UUID (16 bytes) + Additional info length (1 byte)
        // + Command (1 byte) + Port (2 bytes) + Address type + Address + Additional
        //   info
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.uuid.as_bytes());
        buf.put_u8(addons.len() as u8);
        buf.put_slice(&addons);

        if self.is_udp {
            buf.put_u8(VLESS_COMMAND_UDP);
        } else {
            buf.put_u8(VLESS_COMMAND_TCP);
        }

        self.destination.write_to_buf_vmess(&mut buf);
        buf
    }

    fn encode_request_addons(&self) -> Vec<u8> {
        match self.flow.as_deref() {
            Some(XTLS_VISION_FLOW) => encode_flow_addon(XTLS_VISION_FLOW),
            _ => Vec::new(),
        }
    }

    fn prepare_handshake_with_data(&mut self, data: &[u8]) {
        debug!(
            "VLESS handshake starting for destination: {}",
            self.destination
        );

        let mut out = self.build_handshake_header();
        out.put_slice(data);
        self.pending_write = Some(PendingWrite {
            data: out,
            written: 0,
            user_len: data.len(),
        });
    }

    fn poll_send_pending_handshake(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let Some(mut pending) = self.pending_write.take() else {
            return Poll::Ready(Ok(0));
        };

        while pending.written < pending.data.len() {
            match Pin::new(&mut self.inner)
                .poll_write(cx, &pending.data[pending.written..])
            {
                Poll::Ready(Ok(0)) => {
                    self.pending_write = Some(pending);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write VLESS handshake",
                    )));
                }
                Poll::Ready(Ok(n)) => pending.written += n,
                Poll::Ready(Err(e)) => {
                    self.pending_write = Some(pending);
                    error!("Failed to send VLESS handshake: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }

        self.handshake_sent = true;
        debug!(
            "VLESS handshake sent with {} bytes of data",
            pending.user_len
        );
        Poll::Ready(Ok(pending.user_len))
    }

    fn poll_receive_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.response_received {
            return Poll::Ready(Ok(()));
        }

        debug!("VLESS waiting for response");

        while self.response_header_read < self.response_header.len() {
            let mut read_buf =
                ReadBuf::new(&mut self.response_header[self.response_header_read..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF while reading VLESS response header",
                        )));
                    }
                    self.response_header_read += n;
                }
                Poll::Ready(Err(e)) => {
                    error!("Failed to read VLESS response: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.response_header[0] != VLESS_VERSION {
            error!(
                "Invalid VLESS response version: {}",
                self.response_header[0]
            );
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid VLESS response version: {}",
                    self.response_header[0]
                ),
            )));
        }

        let mut remaining = self
            .response_additional_remaining
            .get_or_insert(self.response_header[1] as usize)
            .to_owned();
        let original_additional_len = self.response_header[1] as usize;

        while remaining > 0 {
            let mut discard = [0u8; 256];
            let len = remaining.min(discard.len());
            let mut read_buf = ReadBuf::new(&mut discard[..len]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF while reading VLESS additional info",
                        )));
                    }
                    remaining -= n;
                    self.response_additional_remaining = Some(remaining);
                }
                Poll::Ready(Err(e)) => {
                    error!("Failed to read VLESS additional info: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if original_additional_len > 0 {
            debug!(
                "VLESS additional info received: {} bytes",
                original_additional_len
            );
        }

        self.response_received = true;
        self.handshake_done = true;
        debug!("VLESS handshake completed successfully");

        Poll::Ready(Ok(()))
    }
}

fn encode_flow_addon(flow: &str) -> Vec<u8> {
    let flow_bytes = flow.as_bytes();
    let flow_len = flow_bytes.len();
    assert!(
        flow_len < 128,
        "xtls vision flow string must fit in a single-byte protobuf varint"
    );

    let mut result = Vec::with_capacity(2 + flow_len);
    result.push(0x0a);
    result.push(flow_len as u8);
    result.extend_from_slice(flow_bytes);
    result
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Vision handles the response header itself because the first response
        // bytes are followed by Vision-framed body data in the same stream.
        let vision_flow = self.flow.as_deref() == Some(XTLS_VISION_FLOW);

        // Must receive response before reading for non-Vision flows.
        if self.handshake_sent && !self.response_received && !vision_flow {
            match self.poll_receive_response(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        // Send handshake with first write. Keep the composed handshake buffer in
        // the stream state so retries after Pending do not duplicate or lose the
        // VLESS header / first payload bytes.
        if !self.handshake_sent {
            if self.pending_write.is_none() {
                self.prepare_handshake_with_data(buf);
            }
            return self.poll_send_pending_handshake(cx);
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{VlessStream, XTLS_VISION_FLOW};
    use crate::session::SocksAddr;

    const TEST_UUID: &str = "5415d8e0-df92-3655-afa4-b79de66413f5";

    fn test_stream(
        io: tokio::io::DuplexStream,
        flow: Option<String>,
    ) -> VlessStream {
        VlessStream::new(
            Box::new(io),
            TEST_UUID,
            &SocksAddr::Domain("example.com".to_owned(), 443),
            false,
            flow,
        )
        .expect("stream should build")
    }

    #[test]
    fn vless_vision_flow_addon_is_encoded_into_request_header() {
        let (io, _) = tokio::io::duplex(1);
        let stream = test_stream(io, Some(XTLS_VISION_FLOW.to_owned()));

        let header = stream.build_handshake_header();

        assert_eq!(header[17], 18, "vision flow protobuf should be 18 bytes");
        assert_eq!(&header[18..20], &[0x0a, 16]);
        assert_eq!(&header[20..36], XTLS_VISION_FLOW.as_bytes());
    }

    #[tokio::test]
    async fn pending_first_write_sends_handshake_and_payload_once() {
        let (client, mut server) = tokio::io::duplex(1);
        let mut stream = test_stream(client, Some(XTLS_VISION_FLOW.to_owned()));
        let expected_header = stream.build_handshake_header().to_vec();
        let payload = b"first application payload";
        let expected_len = expected_header.len() + payload.len();

        let server_task = tokio::spawn(async move {
            let mut received = vec![0; expected_len];
            server
                .read_exact(&mut received)
                .await
                .expect("complete request");
            received
        });

        stream.write_all(payload).await.expect("first write");
        stream.flush().await.expect("flush");
        let received = server_task.await.expect("server task");

        assert_eq!(&received[..expected_header.len()], expected_header);
        assert_eq!(&received[expected_header.len()..], payload);
    }

    #[tokio::test]
    async fn fragmented_response_header_is_resumed_without_losing_state() {
        let (client, mut server) = tokio::io::duplex(1);
        let mut stream = test_stream(client, None);
        let payload = b"request";
        let request_len = stream.build_handshake_header().len() + payload.len();

        let server_task = tokio::spawn(async move {
            let mut request = vec![0; request_len];
            server.read_exact(&mut request).await.expect("request");
            server.write_all(&[0]).await.expect("response version");
            server.write_all(&[2]).await.expect("addon length");
            server.write_all(&[0xaa]).await.expect("first addon byte");
            server.write_all(&[0xbb]).await.expect("second addon byte");
            server.write_all(b"response").await.expect("response body");
        });

        stream.write_all(payload).await.expect("request write");
        let mut response = [0; 8];
        stream
            .read_exact(&mut response)
            .await
            .expect("response body");
        assert_eq!(&response, b"response");
        server_task.await.expect("server task");
    }
}
