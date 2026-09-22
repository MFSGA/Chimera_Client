use bytes::{BufMut, BytesMut};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    prelude::{APPLICATION_DATA, TLS_HEADER_SIZE, TLS_MAJOR, TLS_MINOR},
    stream::{ReadState, WriteState},
    utils::Hmac,
};
use crate::common::io::{ReadExactBase, ReadExt};

const V2_AUTH_SIZE: usize = 8;
const MAX_TLS_PAYLOAD: usize = 16 * 1024;

pub(super) struct HandshakeStream<S> {
    raw: S,
    challenge: Hmac,
}

impl<S> HandshakeStream<S> {
    pub(super) fn new(raw: S, challenge: Hmac) -> Self {
        Self { raw, challenge }
    }

    pub(super) fn into_parts(self) -> (S, Hmac) {
        (self.raw, self.challenge)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HandshakeStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = ready!(Pin::new(&mut this.raw).poll_read(cx, buf));
        if result.is_ok() {
            this.challenge.update(&buf.filled()[before..]);
        }
        Poll::Ready(result)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HandshakeStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().raw).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().raw).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().raw).poll_shutdown(cx)
    }
}

pub(super) struct Stream<S> {
    raw: S,
    first_auth: Option<[u8; V2_AUTH_SIZE]>,
    read_buf: BytesMut,
    read_pos: usize,
    read_state: ReadState,
    write_buf: BytesMut,
    write_state: WriteState,
}

impl<S> Stream<S> {
    pub(super) fn new(raw: S, first_auth: [u8; V2_AUTH_SIZE]) -> Self {
        Self {
            raw,
            first_auth: Some(first_auth),
            read_buf: BytesMut::new(),
            read_pos: 0,
            read_state: ReadState::WaitingHeader,
            write_buf: BytesMut::new(),
            write_state: WriteState::BuildingData,
        }
    }
}

impl<S: AsyncRead + Unpin> ReadExactBase for Stream<S> {
    type I = S;

    fn decompose(&mut self) -> (&mut Self::I, &mut BytesMut, &mut usize) {
        (&mut self.raw, &mut self.read_buf, &mut self.read_pos)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_state {
                ReadState::WaitingHeader => {
                    ready!(this.poll_read_exact(cx, TLS_HEADER_SIZE))?;
                    let header_bytes = this.read_buf.split().freeze();
                    let size = u16::from_be_bytes([header_bytes[3], header_bytes[4]])
                        as usize;
                    let mut header = [0u8; TLS_HEADER_SIZE];
                    header.copy_from_slice(&header_bytes);
                    this.read_state = ReadState::WaitingData(size, header);
                }
                ReadState::WaitingData(size, header) => {
                    ready!(this.poll_read_exact(cx, size))?;
                    let data = this.read_buf.split().freeze();
                    if header[0] != APPLICATION_DATA {
                        this.read_state = ReadState::WaitingHeader;
                        continue;
                    }
                    this.read_buf.put(data);
                    this.read_state = ReadState::FlushingData;
                }
                ReadState::FlushingData => {
                    let available = this.read_buf.len();
                    let to_read = available.min(buf.remaining());
                    let payload = this.read_buf.split_to(to_read);
                    buf.put_slice(&payload);
                    this.read_state = if to_read < available {
                        ReadState::FlushingData
                    } else {
                        ReadState::WaitingHeader
                    };
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            match this.write_state {
                WriteState::BuildingData => {
                    let auth_len = if this.first_auth.is_some() {
                        V2_AUTH_SIZE
                    } else {
                        0
                    };
                    let consume = buf.len().min(MAX_TLS_PAYLOAD - auth_len);
                    let payload_len = consume + auth_len;

                    this.write_buf.reserve(TLS_HEADER_SIZE + payload_len);
                    this.write_buf.put_u8(APPLICATION_DATA);
                    this.write_buf.put_u8(TLS_MAJOR);
                    this.write_buf.put_u8(TLS_MINOR.0);
                    this.write_buf
                        .put_slice(&(payload_len as u16).to_be_bytes());
                    if let Some(auth) = this.first_auth.take() {
                        this.write_buf.put_slice(&auth);
                    }
                    this.write_buf.put_slice(&buf[..consume]);
                    let total = this.write_buf.len();
                    this.write_state = WriteState::FlushingData(consume, total, 0);
                }
                WriteState::FlushingData(consume, total, written) => {
                    let nw = ready!(tokio_util::io::poll_write_buf(
                        Pin::new(&mut this.raw),
                        cx,
                        &mut this.write_buf
                    ))?;
                    if nw == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to write shadow-tls v2 application data",
                        )));
                    }
                    if written + nw >= total {
                        debug_assert_eq!(written + nw, total);
                        this.write_state = WriteState::BuildingData;
                        return Poll::Ready(Ok(consume));
                    }
                    this.write_state =
                        WriteState::FlushingData(consume, total, written + nw);
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().raw).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().raw).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn v2_first_write_prefixes_auth_and_frames_application_data() {
        let (client, mut peer) = tokio::io::duplex(1024);
        let auth = [0x5a; V2_AUTH_SIZE];
        let mut stream = Stream::new(client, auth);

        stream.write_all(b"hello").await.unwrap();

        let mut wire = [0u8; TLS_HEADER_SIZE + V2_AUTH_SIZE + 5];
        peer.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire[0], APPLICATION_DATA);
        assert_eq!(
            u16::from_be_bytes([wire[3], wire[4]]) as usize,
            V2_AUTH_SIZE + 5
        );
        assert_eq!(
            &wire[TLS_HEADER_SIZE..TLS_HEADER_SIZE + V2_AUTH_SIZE],
            &auth
        );
        assert_eq!(&wire[TLS_HEADER_SIZE + V2_AUTH_SIZE..], b"hello");

        stream.write_all(b"next").await.unwrap();
        let mut second = [0u8; TLS_HEADER_SIZE + 4];
        peer.read_exact(&mut second).await.unwrap();
        assert_eq!(u16::from_be_bytes([second[3], second[4]]), 4);
        assert_eq!(&second[TLS_HEADER_SIZE..], b"next");
    }

    #[tokio::test]
    async fn v2_read_strips_tls_application_data_headers() {
        let (mut peer, client) = tokio::io::duplex(1024);
        let mut stream = Stream::new(client, [0; V2_AUTH_SIZE]);

        peer.write_all(&[APPLICATION_DATA, TLS_MAJOR, TLS_MINOR.0, 0, 5])
            .await
            .unwrap();
        peer.write_all(b"hello").await.unwrap();

        let mut plain = [0u8; 5];
        stream.read_exact(&mut plain).await.unwrap();
        assert_eq!(&plain, b"hello");
    }

    #[tokio::test]
    async fn handshake_stream_hashes_only_server_bytes() {
        let (client, mut peer) = tokio::io::duplex(1024);
        let challenge = Hmac::new("password", (&[], &[]));
        let mut stream = HandshakeStream::new(client, challenge);

        peer.write_all(b"server-handshake").await.unwrap();
        let mut buf = [0u8; 16];
        stream.read_exact(&mut buf).await.unwrap();

        let (_raw, challenge) = stream.into_parts();
        let mut expected = Hmac::new("password", (&[], &[]));
        expected.update(b"server-handshake");
        assert_eq!(challenge.finalize_v2(), expected.finalize_v2());
    }
}
