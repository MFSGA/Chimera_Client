use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Sleep, sleep},
};

use super::encryption::{
    EncryptionRecordCodec, PreparedCrypto, PreparedOneRttSession, xor_vless_ctr,
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

struct PendingHelloWrite {
    data: Vec<u8>,
    write_lengths: Vec<usize>,
    gaps_ms: Vec<u64>,
    offset: usize,
    segment_index: usize,
    segment_written: usize,
    gap_sleep: Option<Pin<Box<Sleep>>>,
}

impl PendingHelloWrite {
    fn new(
        data: Vec<u8>,
        write_lengths: Vec<usize>,
        gaps_ms: Vec<u64>,
    ) -> io::Result<Self> {
        if write_lengths.is_empty() {
            return Err(invalid("VLESS encryption hello has no write segments"));
        }
        let scheduled_len =
            write_lengths.iter().try_fold(0usize, |total, len| {
                total.checked_add(*len).ok_or_else(|| {
                    invalid("VLESS encryption hello write schedule overflow")
                })
            })?;
        if scheduled_len != data.len() {
            return Err(invalid(format!(
                "VLESS encryption hello write schedule length mismatch: expected {}, got {scheduled_len}",
                data.len()
            )));
        }
        if gaps_ms.len() > write_lengths.len() {
            return Err(invalid(
                "VLESS encryption hello has more gaps than write segments",
            ));
        }

        Ok(Self {
            data,
            write_lengths,
            gaps_ms,
            offset: 0,
            segment_index: 0,
            segment_written: 0,
            gap_sleep: None,
        })
    }

    fn poll_write(
        &mut self,
        inner: &mut AnyStream,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(gap_sleep) = self.gap_sleep.as_mut() {
                match gap_sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => self.gap_sleep = None,
                    Poll::Pending => return Poll::Pending,
                }
            }

            let Some(&segment_len) = self.write_lengths.get(self.segment_index)
            else {
                return Poll::Ready(Ok(()));
            };
            while self.segment_written < segment_len {
                let remaining = segment_len - self.segment_written;
                let segment_end =
                    self.offset.checked_add(remaining).ok_or_else(|| {
                        invalid("VLESS encryption hello segment length overflow")
                    })?;
                match Pin::new(&mut **inner)
                    .poll_write(cx, &self.data[self.offset..segment_end])
                {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to write VLESS encryption hello segment",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        self.offset += n;
                        self.segment_written += n;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let completed_index = self.segment_index;
            self.segment_index += 1;
            self.segment_written = 0;
            if let Some(&gap_ms) = self.gaps_ms.get(completed_index)
                && gap_ms > 0
            {
                self.gap_sleep =
                    Some(Box::pin(sleep(Duration::from_millis(gap_ms))));
            }
        }
    }
}

struct PendingRecordWrite {
    wire: PendingIo,
    user_len: usize,
}

// Xray's random appearance masks only TLS-shaped record headers, not their
// authenticated ciphertext bodies. Preserve AES-CTR byte position across
// records, and never wrap/reuse a key stream block after counter exhaustion.
struct RecordHeaderMask {
    united_key: Vec<u8>,
    counter: [u8; 16],
    keystream: [u8; 16],
    next_byte: usize,
    counter_exhausted: bool,
}

impl RecordHeaderMask {
    fn new(united_key: &[u8], iv: [u8; 16]) -> Self {
        Self {
            united_key: united_key.to_vec(),
            counter: iv,
            keystream: [0; 16],
            next_byte: 16,
            counter_exhausted: false,
        }
    }

    fn apply(&mut self, header: &mut [u8]) -> io::Result<()> {
        if header.len() != RECORD_HEADER_LEN {
            return Err(invalid("invalid VLESS random record header length"));
        }
        // Reject a whole header without modifying it if it needs a block
        // past the final counter. This also keeps repeated errors fail-closed.
        if self.counter_exhausted
            && self.keystream.len() - self.next_byte < header.len()
        {
            return Err(invalid("VLESS random header CTR counter exhausted"));
        }
        for byte in header {
            if self.next_byte == self.keystream.len() {
                self.keystream.fill(0);
                xor_vless_ctr(&self.united_key, &self.counter, &mut self.keystream)?;
                match u128::from_be_bytes(self.counter).checked_add(1) {
                    Some(next) => self.counter = next.to_be_bytes(),
                    None => self.counter_exhausted = true,
                }
                self.next_byte = 0;
            }
            *byte ^= self.keystream[self.next_byte];
            self.next_byte += 1;
        }
        Ok(())
    }
}

pub(crate) struct EncryptionStream {
    inner: AnyStream,
    prepared: Option<PreparedCrypto>,
    session: Option<PreparedOneRttSession>,
    hello: PendingHelloWrite,
    server_pfs: PendingIo,
    server_ticket: PendingIo,
    server_padding_len: PendingIo,
    write_codec: Option<EncryptionRecordCodec>,
    read_codec: Option<EncryptionRecordCodec>,
    write_header_mask: Option<RecordHeaderMask>,
    read_header_mask: Option<RecordHeaderMask>,
    peer_padding: Option<PendingIo>,
    handshake_done: bool,
    pending_write: Option<PendingRecordWrite>,
    read_header: PendingIo,
    read_ciphertext: Option<PendingIo>,
    read_plaintext: Vec<u8>,
    read_plaintext_offset: usize,
    // Framing/authentication errors must permanently terminate the read side.
    read_terminal_error: Option<(io::ErrorKind, String)>,
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
        let hello = prepared.one_rtt_hello.as_ref().ok_or_else(|| {
            invalid("VLESS encryption runtime MVP currently supports only 1rtt")
        })?;
        let pending_hello = PendingHelloWrite::new(
            hello.bytes.clone(),
            prepared.hello_write_lengths.clone(),
            prepared.padding_gaps_ms.clone(),
        )?;

        Ok(Self {
            inner,
            hello: pending_hello,
            prepared: Some(prepared),
            session: None,
            server_pfs: PendingIo::with_len(SERVER_PFS_RESPONSE_LEN),
            server_ticket: PendingIo::with_len(ENCRYPTED_TICKET_LEN),
            server_padding_len: PendingIo::with_len(ENCRYPTED_LENGTH_LEN),
            write_codec: None,
            read_codec: None,
            write_header_mask: None,
            read_header_mask: None,
            peer_padding: None,
            handshake_done: false,
            pending_write: None,
            read_header: PendingIo::with_len(RECORD_HEADER_LEN),
            read_ciphertext: None,
            read_plaintext: Vec::new(),
            read_plaintext_offset: 0,
            read_terminal_error: None,
        })
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.handshake_done {
            return Poll::Ready(Ok(()));
        }

        match self.hello.poll_write(&mut self.inner, cx) {
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
        // Only mask records, after the authenticated 1-RTT server padding.
        // Upload uses ClientHello's IV; download uses the server ticket.
        if self.prepared.as_ref().is_some_and(|p| p.xor_mode == 2) {
            let iv = self
                .prepared
                .as_ref()
                .expect("prepared crypto remains present until handshake completion")
                .nfs_relays
                .iv;
            self.write_header_mask =
                Some(RecordHeaderMask::new(&session.united_key, iv));
            self.read_header_mask =
                Some(RecordHeaderMask::new(&session.united_key, tail.ticket));
        }

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

    fn poll_read_inner(
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
            let this = self.as_mut().get_mut();
            if let Some(mask) = this.read_header_mask.as_mut()
                && let Err(err) = mask.apply(&mut this.read_header.data)
            {
                return Poll::Ready(Err(err));
            }
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
            let mut wire = wire;
            if let Some(mask) = self.write_header_mask.as_mut()
                && let Err(err) = mask.apply(&mut wire[..RECORD_HEADER_LEN])
            {
                return Poll::Ready(Err(err));
            }
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
        if let Some((kind, message)) = &self.read_terminal_error {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }

        let result = self.as_mut().poll_read_inner(cx, buf);
        if let Poll::Ready(Err(ref err)) = result {
            self.read_terminal_error = Some((err.kind(), err.to_string()));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        task::Context,
    };

    use futures::task::noop_waker_ref;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    fn handshaken_read_stream(
        inner: AnyStream,
        peer_padding_len: usize,
    ) -> EncryptionStream {
        EncryptionStream {
            inner,
            prepared: None,
            session: None,
            hello: PendingHelloWrite::new(Vec::new(), vec![0], Vec::new())
                .expect("empty hello schedule"),
            server_pfs: PendingIo::with_len(SERVER_PFS_RESPONSE_LEN),
            server_ticket: PendingIo::with_len(ENCRYPTED_TICKET_LEN),
            server_padding_len: PendingIo::with_len(ENCRYPTED_LENGTH_LEN),
            write_codec: None,
            read_codec: None,
            write_header_mask: None,
            read_header_mask: None,
            peer_padding: Some(PendingIo::with_len(peer_padding_len)),
            handshake_done: true,
            pending_write: None,
            read_header: PendingIo::with_len(RECORD_HEADER_LEN),
            read_ciphertext: None,
            read_plaintext: Vec::new(),
            read_plaintext_offset: 0,
            read_terminal_error: None,
        }
    }

    #[tokio::test]
    async fn partial_peer_padding_eof_remains_terminal_on_repeated_read() {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[0x42])
            .await
            .expect("write partial padding");
        drop(server);
        let mut stream = handshaken_read_stream(Box::new(client), 2);
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut output = [0u8; 8];
        for attempt in 0..2 {
            let mut buf = ReadBuf::new(&mut output);
            let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
            let Poll::Ready(Err(err)) = result else {
                panic!("read {attempt} must fail after truncated peer padding");
            };
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert!(buf.filled().is_empty());
        }
    }

    #[tokio::test]
    async fn invalid_record_header_remains_terminal_on_repeated_read() {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[22, 3, 3, 0, 17])
            .await
            .expect("write invalid header");
        drop(server);
        let mut stream = handshaken_read_stream(Box::new(client), 0);
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut output = [0u8; 8];
        for attempt in 0..2 {
            let mut buf = ReadBuf::new(&mut output);
            let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
            let Poll::Ready(Err(err)) = result else {
                panic!("read {attempt} must fail after invalid record header");
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(
                err.to_string()
                    .contains("invalid VLESS encryption record header")
            );
            assert!(buf.filled().is_empty());
        }
    }

    #[tokio::test]
    async fn truncated_record_body_remains_terminal_on_repeated_read() {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[23, 3, 3, 0, 17, 0x42])
            .await
            .expect("write incomplete encrypted record");
        drop(server);

        let mut stream = handshaken_read_stream(Box::new(client), 0);
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut output = [0u8; 8];
        for attempt in 0..2 {
            let mut buf = ReadBuf::new(&mut output);
            let Poll::Ready(Err(err)) =
                Pin::new(&mut stream).poll_read(&mut cx, &mut buf)
            else {
                panic!("read {attempt} must fail after truncated record body");
            };
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert!(buf.filled().is_empty());
        }
    }

    #[tokio::test]
    async fn cancelled_partial_record_header_read_resumes_without_losing_bytes() {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[23, 3])
            .await
            .expect("write partial record header");
        let mut stream = handshaken_read_stream(Box::new(client), 0);
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut output = [0u8; 8];
        {
            let mut buf = ReadBuf::new(&mut output);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
                Poll::Pending
            ));
            assert_eq!(stream.read_header.offset, 2);
        } // Cancel the pending read without losing the buffered header.

        server
            .write_all(&[3, 0, 0])
            .await
            .expect("finish invalid-length record header");
        let mut buf = ReadBuf::new(&mut output);
        let Poll::Ready(Err(err)) =
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf)
        else {
            panic!("resumed read must reject the completed zero-length record");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("ciphertext length: 0"));
        assert!(buf.filled().is_empty());
    }

    #[tokio::test]
    async fn dropping_pending_encryption_read_closes_underlying_transport() {
        use tokio::io::AsyncReadExt;

        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = handshaken_read_stream(Box::new(client), 0);
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut output = [0u8; 8];
        let mut buf = ReadBuf::new(&mut output);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Pending
        ));
        drop(stream);

        let count = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.read(&mut output),
        )
        .await
        .expect("dropped encryption stream must close promptly")
        .expect("read from closed transport");
        assert_eq!(count, 0);
    }

    struct RecordingStream {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncRead for RecordingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn recording_stream() -> (AnyStream, Arc<Mutex<Vec<Vec<u8>>>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingStream {
            writes: Arc::clone(&writes),
        };
        (Box::new(stream), writes)
    }

    #[test]
    fn random_header_mask_matches_continuous_ctr_across_record_boundaries() {
        let key = [0x39u8; 64];
        let iv = [0x57u8; 16];
        let mut mask = RecordHeaderMask::new(&key, iv);
        let mut expected = [0u8; 35];
        xor_vless_ctr(&key, &iv, &mut expected).expect("reference CTR stream");

        let mut actual = [0u8; 35];
        for header in actual.as_chunks_mut::<RECORD_HEADER_LEN>().0 {
            mask.apply(header).expect("mask header");
        }
        assert_eq!(actual, expected);
        assert_eq!(mask.next_byte, 3); // seven 5-byte headers span three blocks
    }

    #[test]
    fn random_header_mask_rejects_ctr_wrap_without_modifying_a_header() {
        let key = [0x29u8; 64];
        let iv = u128::MAX.to_be_bytes();
        let mut mask = RecordHeaderMask::new(&key, iv);
        let mut expected = [0u8; 15];
        xor_vless_ctr(&key, &iv, &mut expected).expect("last CTR block");
        let mut actual = [0u8; 15];
        for header in actual.as_chunks_mut::<RECORD_HEADER_LEN>().0 {
            mask.apply(header).expect("remaining final block");
        }
        assert_eq!(actual, expected);
        assert!(mask.counter_exhausted);
        assert_eq!(mask.counter, iv);
        assert_eq!(mask.next_byte, 15);

        for _ in 0..2 {
            let mut header = [0x42; RECORD_HEADER_LEN];
            let err = mask.apply(&mut header).expect_err("CTR wrap must fail");
            assert!(err.to_string().contains("CTR counter exhausted"));
            assert_eq!(header, [0x42; RECORD_HEADER_LEN]);
            assert_eq!(mask.next_byte, 15);
        }
    }

    #[test]
    fn random_header_mask_preserves_final_two_ctr_blocks() {
        let key = [0x63u8; 64];
        let iv = (u128::MAX - 1).to_be_bytes();
        let mut mask = RecordHeaderMask::new(&key, iv);
        let mut expected = [0u8; 30];
        xor_vless_ctr(&key, &iv, &mut expected).expect("last two CTR blocks");
        let mut actual = [0u8; 30];
        for header in actual.as_chunks_mut::<RECORD_HEADER_LEN>().0 {
            mask.apply(header).expect("header in final two blocks");
        }
        assert_eq!(actual, expected);
        assert!(mask.counter_exhausted);
        assert_eq!(mask.counter, u128::MAX.to_be_bytes());
        assert_eq!(mask.next_byte, 14);

        let mut header = [0x7f; RECORD_HEADER_LEN];
        assert!(mask.apply(&mut header).is_err());
        assert_eq!(header, [0x7f; RECORD_HEADER_LEN]);
    }

    #[test]
    fn random_header_mask_rejects_non_header_lengths() {
        let mut mask = RecordHeaderMask::new(&[0x25; 64], [0x35; 16]);
        let mut invalid = [0u8; 4];
        assert!(mask.apply(&mut invalid).is_err());
        assert_eq!(invalid, [0; 4]);
        assert_eq!(mask.next_byte, 16);
    }

    #[test]
    fn hello_schedule_preserves_write_segments_and_skips_zero_length_writes() {
        let mut hello =
            PendingHelloWrite::new(b"abcdef".to_vec(), vec![3, 0, 3], vec![0, 0])
                .expect("hello schedule should build");
        let (mut stream, writes) = recording_stream();
        let mut cx = Context::from_waker(noop_waker_ref());

        assert!(matches!(
            hello.poll_write(&mut stream, &mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            *writes.lock().unwrap(),
            vec![b"abc".to_vec(), b"def".to_vec()]
        );
    }

    #[tokio::test]
    async fn hello_schedule_waits_at_gap_before_next_segment() {
        let mut hello =
            PendingHelloWrite::new(b"abcdef".to_vec(), vec![3, 3], vec![50])
                .expect("hello schedule should build");
        let (mut stream, writes) = recording_stream();
        let mut cx = Context::from_waker(noop_waker_ref());

        assert!(matches!(
            hello.poll_write(&mut stream, &mut cx),
            Poll::Pending
        ));
        assert_eq!(*writes.lock().unwrap(), vec![b"abc".to_vec()]);
        assert_eq!(hello.segment_index, 1);
        assert!(hello.gap_sleep.is_some());

        hello.gap_sleep = None;
        assert!(matches!(
            hello.poll_write(&mut stream, &mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            *writes.lock().unwrap(),
            vec![b"abc".to_vec(), b"def".to_vec()]
        );
    }

    #[test]
    fn hello_schedule_rejects_length_mismatch() {
        let err = match PendingHelloWrite::new(b"abcd".to_vec(), vec![2, 1], vec![])
        {
            Ok(_) => panic!("mismatched hello schedule must fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("length mismatch"));
    }
}
