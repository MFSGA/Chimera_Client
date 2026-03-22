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

pub struct VlessStream {
    inner: AnyStream,
    handshake_done: bool,
    handshake_sent: bool,
    response_received: bool,
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

    async fn send_handshake_with_data(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.handshake_sent {
            return Ok(0);
        }

        debug!(
            "VLESS handshake starting for destination: {}",
            self.destination
        );

        let mut buf = self.build_handshake_header();
        buf.put_slice(data);

        // Send handshake + first data
        tokio::io::AsyncWriteExt::write_all(&mut self.inner, &buf)
            .await
            .map_err(|e| {
                error!("Failed to send VLESS handshake: {}", e);
                e
            })?;

        self.handshake_sent = true;
        debug!("VLESS handshake sent with {} bytes of data", data.len());

        Ok(data.len())
    }

    async fn receive_response(&mut self) -> io::Result<()> {
        if self.response_received {
            return Ok(());
        }

        debug!("VLESS waiting for response");

        // Read response (VLESS response is just version + additional info length +
        // additional info)
        let mut response = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut self.inner, &mut response)
            .await
            .map_err(|e| {
                error!("Failed to read VLESS response: {}", e);
                e
            })?;

        if response[0] != VLESS_VERSION {
            error!("Invalid VLESS response version: {}", response[0]);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid VLESS response version: {}", response[0]),
            ));
        }

        let additional_info_len = response[1];

        if additional_info_len > 0 {
            let mut additional_info = vec![0u8; additional_info_len as usize];
            tokio::io::AsyncReadExt::read_exact(
                &mut self.inner,
                &mut additional_info,
            )
            .await
            .map_err(|e| {
                error!("Failed to read VLESS additional info: {}", e);
                e
            })?;
            debug!(
                "VLESS additional info received: {} bytes",
                additional_info_len
            );
        }

        self.response_received = true;
        self.handshake_done = true;
        debug!("VLESS handshake completed successfully");

        Ok(())
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
            let fut = self.receive_response();
            tokio::pin!(fut);
            match fut.poll(cx) {
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
        // Send handshake with first write
        if !self.handshake_sent {
            let fut = self.send_handshake_with_data(buf);
            tokio::pin!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
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
    use super::{VlessStream, XTLS_VISION_FLOW};
    use crate::session::SocksAddr;

    #[test]
    fn vless_vision_flow_addon_is_encoded_into_request_header() {
        let (io, _) = tokio::io::duplex(1);
        let stream = VlessStream::new(
            Box::new(io),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &SocksAddr::Domain("example.com".to_owned(), 443),
            false,
            Some(XTLS_VISION_FLOW.to_owned()),
        )
        .expect("stream should build");

        let header = stream.build_handshake_header();

        assert_eq!(header[17], 18, "vision flow protobuf should be 18 bytes");
        assert_eq!(&header[18..20], &[0x0a, 16]);
        assert_eq!(&header[20..36], XTLS_VISION_FLOW.as_bytes());
    }
}
