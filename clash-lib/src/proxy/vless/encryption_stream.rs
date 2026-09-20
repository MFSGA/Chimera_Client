#![allow(dead_code)]

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::encryption::{
    EncryptionRecordCodec, PreparedCrypto, PreparedOneRttSession,
};
use crate::proxy::AnyStream;

const SERVER_PFS_RESPONSE_LEN: usize = 1088 + 32 + 16;
const ENCRYPTED_TICKET_LEN: usize = 16 + 16;
const ENCRYPTED_LENGTH_LEN: usize = 2 + 16;
const RECORD_HEADER_LEN: usize = 5;
const MAX_RECORD_PLAINTEXT_LEN: usize = 8192;
const MAX_RECORD_CIPHERTEXT_LEN: usize = 16640;

struct PendingIo {
    data: Vec<u8>,
    offset: usize,
}

impl PendingIo {
    fn with_len(len: usize) -> Self {
        Self {
            data: vec![0; len],
            offset: 0,
        }
    }

    fn from_data(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }

    fn complete(&self) -> bool {
        self.offset == self.data.len()
    }
}

struct PendingRecordWrite {
    wire: PendingIo,
    user_len: usize,
}

pub(crate) struct EncryptionStream {
    inner: AnyStream,
    prepared: Option<PreparedCrypto>,
    session: Option<PreparedOneRttSession>,
    hello: PendingIo,
    server_pfs: PendingIo,
    server_ticket: PendingIo,
    server_padding_len: PendingIo,
    write_codec: Option<EncryptionRecordCodec>,
    read_codec: Option<EncryptionRecordCodec>,
    peer_padding: Option<PendingIo>,
    handshake_done: bool,
    pending_write: Option<PendingRecordWrite>,
    read_header: PendingIo,
    read_ciphertext: Option<PendingIo>,
    read_plaintext: Vec<u8>,
    read_plaintext_offset: usize,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn poll_write_pending(
    inner: &mut AnyStream,
    cx: &mut Context<'_>,
    pending: &mut PendingIo,
) -> Poll<io::Result<()>> {
    while !pending.complete() {
        match Pin::new(&mut **inner).poll_write(cx, &pending.data[pending.offset..])
        {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write VLESS encryption frame",
                )));
            }
            Poll::Ready(Ok(n)) => pending.offset += n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

fn poll_read_pending(
    inner: &mut AnyStream,
    cx: &mut Context<'_>,
    pending: &mut PendingIo,
    eof_message: &'static str,
) -> Poll<io::Result<()>> {
    while !pending.complete() {
        let mut read_buf = ReadBuf::new(&mut pending.data[pending.offset..]);
        match Pin::new(&mut **inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        eof_message,
                    )));
                }
                pending.offset += n;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

fn decode_record_len(header: &[u8]) -> io::Result<usize> {
    if header.len() != RECORD_HEADER_LEN
        || header[0] != 23
        || header[1] != 3
        || header[2] != 3
    {
        return Err(invalid("invalid VLESS encryption record header"));
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if !(17..=MAX_RECORD_CIPHERTEXT_LEN).contains(&len) {
        return Err(invalid(format!(
            "invalid VLESS encryption record ciphertext length: {len}"
        )));
    }
    Ok(len)
}

impl EncryptionStream {
    pub(crate) fn new(
        inner: AnyStream,
        prepared: PreparedCrypto,
    ) -> io::Result<Self> {
        if prepared.xor_mode != 0 {
            return Err(invalid(
                "VLESS encryption runtime MVP currently supports only native appearance",
            ));
        }
        let hello = prepared.one_rtt_hello.as_ref().ok_or_else(|| {
            invalid("VLESS encryption runtime MVP currently supports only 1rtt")
        })?;

        // TODO: preserve hello_write_lengths/padding_gaps_ms timing. Sending the
        // exact prepared hello in one logical write is wire-compatible; only the
        // traffic-shaping cadence is deferred.
        Ok(Self {
            inner,
            hello: PendingIo::from_data(hello.bytes.clone()),
            prepared: Some(prepared),
            session: None,
            server_pfs: PendingIo::with_len(SERVER_PFS_RESPONSE_LEN),
            server_ticket: PendingIo::with_len(ENCRYPTED_TICKET_LEN),
            server_padding_len: PendingIo::with_len(ENCRYPTED_LENGTH_LEN),
            write_codec: None,
            read_codec: None,
            peer_padding: None,
            handshake_done: false,
            pending_write: None,
            read_header: PendingIo::with_len(RECORD_HEADER_LEN),
            read_ciphertext: None,
            read_plaintext: Vec::new(),
            read_plaintext_offset: 0,
        })
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.handshake_done {
            return Poll::Ready(Ok(()));
        }

        match poll_write_pending(&mut self.inner, cx, &mut self.hello) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        match poll_read_pending(
            &mut self.inner,
            cx,
            &mut self.server_pfs,
            "unexpected EOF while reading VLESS encryption server PFS",
        ) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }

        if self.session.is_none() {
            let prepared = self.prepared.as_ref().ok_or_else(|| {
                io::Error::other("VLESS encryption runtime lost prepared crypto")
            })?;
            let hello = prepared.one_rtt_hello.as_ref().ok_or_else(|| {
                io::Error::other("VLESS encryption runtime lost 1rtt hello")
            })?;
            self.session = Some(hello.derive_server_session(
                &prepared.nfs_aead_key,
                &prepared.nfs_relays.nfs_key,
                &self.server_pfs.data,
            )?);
        }

        match poll_read_pending(
            &mut self.inner,
            cx,
            &mut self.server_ticket,
            "unexpected EOF while reading VLESS encryption server ticket",
        ) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        match poll_read_pending(
            &mut self.inner,
            cx,
            &mut self.server_padding_len,
            "unexpected EOF while reading VLESS encryption server padding length",
        ) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }

        let session = self.session.as_ref().ok_or_else(|| {
            io::Error::other("VLESS encryption runtime lost server session")
        })?;
        let tail = session.decrypt_server_tail(
            &self.server_ticket.data,
            &self.server_padding_len.data,
        )?;
        let (write_codec, read_codec) = session.record_codecs(&tail)?;

        self.peer_padding =
            Some(PendingIo::with_len(tail.peer_padding_ciphertext_len));
        self.write_codec = Some(write_codec);
        self.read_codec = Some(read_codec);
        self.prepared = None;
        self.session = None;
        self.handshake_done = true;
        Poll::Ready(Ok(()))
    }

    fn poll_peer_padding(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(mut padding) = self.peer_padding.take() else {
            return Poll::Ready(Ok(()));
        };
        if padding.data.is_empty() {
            return Poll::Ready(Ok(()));
        }

        match poll_read_pending(
            &mut self.inner,
            cx,
            &mut padding,
            "unexpected EOF while reading VLESS encryption peer padding",
        ) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => {
                self.peer_padding = Some(padding);
                return Poll::Pending;
            }
        }

        self.read_codec
            .as_mut()
            .ok_or_else(|| {
                io::Error::other("VLESS encryption read codec is not initialized")
            })?
            .open_peer_padding(&padding.data)?;
        Poll::Ready(Ok(()))
    }

    fn copy_plaintext(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_plaintext_offset >= self.read_plaintext.len() {
            self.read_plaintext.clear();
            self.read_plaintext_offset = 0;
            return false;
        }

        let remaining = &self.read_plaintext[self.read_plaintext_offset..];
        let count = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..count]);
        self.read_plaintext_offset += count;
        true
    }
}

impl AsyncWrite for EncryptionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.poll_handshake(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        if self.pending_write.is_none() {
            let count = buf.len().min(MAX_RECORD_PLAINTEXT_LEN);
            if count == 0 {
                return Poll::Ready(Ok(0));
            }
            let wire = match self
                .write_codec
                .as_mut()
                .ok_or_else(|| {
                    io::Error::other(
                        "VLESS encryption write codec is not initialized",
                    )
                })
                .and_then(|codec| codec.seal_record(&buf[..count]))
            {
                Ok(wire) => wire,
                Err(err) => return Poll::Ready(Err(err)),
            };
            self.pending_write = Some(PendingRecordWrite {
                wire: PendingIo::from_data(wire),
                user_len: count,
            });
        }

        let mut pending = self.pending_write.take().expect("pending write exists");
        match poll_write_pending(&mut self.inner, cx, &mut pending.wire) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(pending.user_len)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                self.pending_write = Some(pending);
                Poll::Pending
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut pending) = self.pending_write.take() {
            match poll_write_pending(&mut self.inner, cx, &mut pending.wire) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for EncryptionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        match self.poll_handshake(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        match self.poll_peer_padding(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        if self.copy_plaintext(buf) {
            return Poll::Ready(Ok(()));
        }

        while !self.read_header.complete() {
            let this = self.as_mut().get_mut();
            let offset = this.read_header.offset;
            let inner = &mut this.inner;
            let header = &mut this.read_header.data;
            let mut read_buf = ReadBuf::new(&mut header[offset..]);
            match Pin::new(&mut **inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if offset == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF while reading VLESS encryption record header",
                        )));
                    }
                    this.read_header.offset += n;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.read_ciphertext.is_none() {
            let len = match decode_record_len(&self.read_header.data) {
                Ok(len) => len,
                Err(err) => return Poll::Ready(Err(err)),
            };
            self.read_ciphertext = Some(PendingIo::with_len(len));
        }

        let mut ciphertext = self.read_ciphertext.take().expect("ciphertext exists");
        match poll_read_pending(
            &mut self.inner,
            cx,
            &mut ciphertext,
            "unexpected EOF while reading VLESS encryption record body",
        ) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => {
                self.read_ciphertext = Some(ciphertext);
                return Poll::Pending;
            }
        }

        let mut record =
            Vec::with_capacity(RECORD_HEADER_LEN + ciphertext.data.len());
        record.extend_from_slice(&self.read_header.data);
        record.extend_from_slice(&ciphertext.data);
        self.read_header = PendingIo::with_len(RECORD_HEADER_LEN);

        self.read_plaintext = match self
            .read_codec
            .as_mut()
            .ok_or_else(|| {
                io::Error::other("VLESS encryption read codec is not initialized")
            })
            .and_then(|codec| codec.open_record(&record))
        {
            Ok(plaintext) => plaintext,
            Err(err) => return Poll::Ready(Err(err)),
        };
        self.read_plaintext_offset = 0;
        self.copy_plaintext(buf);
        Poll::Ready(Ok(()))
    }
}
