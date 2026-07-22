use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::proxy::{AnyStream, transport::VisionOptions};

use super::{
    tls_fuzzy_deframer::{DeframeResult, FuzzyTlsDeframer},
    vision_filter::VisionFilter,
    vision_unpad::{UnpadCommand, VisionUnpadder},
};

const CMD_PADDING_CONTINUE: u8 = 0x00;
const CMD_PADDING_END: u8 = 0x01;
const CMD_PADDING_DIRECT: u8 = 0x02;
const TLS_APPLICATION_DATA: u8 = 0x17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadMode {
    Framed,
    DirectTls,
    DirectRaw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteMode {
    Framed,
    DirectTls,
    DirectRaw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingWriteSwitch {
    None,
    Tls,
    Raw,
}

pub struct VisionStream {
    inner: AnyStream,
    user_uuid: Option<[u8; 16]>,
    write_mode: WriteMode,
    pending_write_switch: PendingWriteSwitch,
    write_shutdown_queued: bool,
    write_buf: BytesMut,
    write_deframer: FuzzyTlsDeframer,
    read_deframer: FuzzyTlsDeframer,
    traffic_filter: VisionFilter,
    read_mode: ReadMode,
    decoded: BytesMut,
    raw: BytesMut,
    vless_response_pending: bool,
    read_unpadder: VisionUnpadder,
    read_splice_flag: Option<Arc<AtomicBool>>,
    write_splice_flag: Option<Arc<AtomicBool>>,
}

impl VisionStream {
    pub fn new(
        inner: AnyStream,
        uuid: String,
        opts: Option<VisionOptions>,
    ) -> io::Result<Self> {
        let uuid_bytes = uuid::Uuid::parse_str(&uuid)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID")
            })?
            .into_bytes();
        let (read_splice_flag, write_splice_flag) = opts
            .map(|o| (Some(o.read_flag), Some(o.write_flag)))
            .unwrap_or((None, None));

        Ok(Self {
            inner,
            user_uuid: Some(uuid_bytes),
            write_mode: WriteMode::Framed,
            pending_write_switch: PendingWriteSwitch::None,
            write_shutdown_queued: false,
            write_buf: BytesMut::new(),
            write_deframer: FuzzyTlsDeframer::new(),
            read_deframer: FuzzyTlsDeframer::new(),
            traffic_filter: VisionFilter::new(),
            read_mode: ReadMode::Framed,
            decoded: BytesMut::new(),
            raw: BytesMut::new(),
            vless_response_pending: true,
            read_unpadder: VisionUnpadder::new(uuid_bytes),
            read_splice_flag,
            write_splice_flag,
        })
    }

    fn pad_frame(&mut self, data: &[u8], command: u8, is_tls: bool) {
        let frame = if let Some(uuid) = self.user_uuid.take() {
            super::vision_pad::pad_with_uuid_and_command(
                data, &uuid, command, is_tls,
            )
        } else {
            super::vision_pad::pad_with_command(data, command, is_tls)
        };
        self.write_buf.extend_from_slice(&frame);
    }

    fn queue_write_data(&mut self, buf: &[u8]) -> io::Result<usize> {
        let existing_inner_len = self.write_deframer.pending_bytes();
        self.write_deframer.feed(buf);
        let mut processed_len = 0usize;

        loop {
            match self.write_deframer.next_record()? {
                DeframeResult::TlsRecord(record) => {
                    processed_len += record.len();
                    self.traffic_filter.filter_record(&record);

                    let is_app_data = self.traffic_filter.is_tls()
                        && record.len() >= 3
                        && record[0] == TLS_APPLICATION_DATA
                        && record[1] == 0x03;
                    let non_tls_filtering_ended = !is_app_data
                        && !self.traffic_filter.is_filtering()
                        && !self.traffic_filter.is_tls12_or_above();
                    let finish_padding_for_legacy_compat =
                        !self.traffic_filter.is_tls12_or_above()
                            && self.traffic_filter.remaining_filter_count() <= 1;

                    if is_app_data
                        || non_tls_filtering_ended
                        || finish_padding_for_legacy_compat
                    {
                        let command = if self.traffic_filter.supports_xtls() {
                            self.pending_write_switch = PendingWriteSwitch::Raw;
                            CMD_PADDING_DIRECT
                        } else {
                            self.pending_write_switch = PendingWriteSwitch::Tls;
                            CMD_PADDING_END
                        };
                        self.pad_frame(&record, command, true);
                        self.write_deframer.clear();
                        return Ok(processed_len.saturating_sub(existing_inner_len));
                    }

                    self.pad_frame(
                        &record,
                        CMD_PADDING_CONTINUE,
                        self.traffic_filter.is_tls(),
                    );
                }
                DeframeResult::UnknownPrefix(prefix) => {
                    processed_len += prefix.len();
                    self.traffic_filter.decrement_filter_count();

                    if !self.traffic_filter.is_tls()
                        || self.traffic_filter.remaining_filter_count() <= 1
                    {
                        self.pending_write_switch = PendingWriteSwitch::Tls;
                        self.pad_frame(
                            &prefix,
                            CMD_PADDING_END,
                            self.traffic_filter.is_tls(),
                        );
                        self.write_deframer.clear();
                        return Ok(processed_len.saturating_sub(existing_inner_len));
                    }

                    self.pad_frame(
                        &prefix,
                        CMD_PADDING_CONTINUE,
                        self.traffic_filter.is_tls(),
                    );
                }
                DeframeResult::NeedData => break,
            }
        }

        Ok(buf.len())
    }

    fn flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_buf.advance(n);
        }

        match self.pending_write_switch {
            PendingWriteSwitch::None => {}
            PendingWriteSwitch::Tls => {
                debug!("VISION WRITE: switching to direct TLS mode");
                self.write_mode = WriteMode::DirectTls;
                self.pending_write_switch = PendingWriteSwitch::None;
            }
            PendingWriteSwitch::Raw => {
                debug!("VISION WRITE: switching to raw splice mode");
                self.write_mode = WriteMode::DirectRaw;
                self.pending_write_switch = PendingWriteSwitch::None;
                if let Some(flag) = &self.write_splice_flag {
                    flag.store(true, Ordering::Release);
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    fn queue_shutdown_frame(&mut self) {
        if self.write_shutdown_queued || self.write_mode != WriteMode::Framed {
            return;
        }

        let remaining = self.write_deframer.remaining_data().to_vec();
        self.write_deframer.clear();
        self.pad_frame(&remaining, CMD_PADDING_END, self.traffic_filter.is_tls());
        self.write_shutdown_queued = true;
        self.pending_write_switch = PendingWriteSwitch::Tls;
    }

    fn process_raw_read(&mut self) -> io::Result<bool> {
        if self.read_unpadder.is_waiting_for_uuid() && self.raw.len() < 16 {
            return Ok(false);
        }

        let result = self.read_unpadder.unpad(&self.raw)?;
        let changed = !result.content.is_empty() || result.command.is_some();

        self.raw.clear();
        self.observe_read_content(&result.content)?;
        self.decoded.extend_from_slice(&result.content);

        match result.command {
            Some(UnpadCommand::Direct) => {
                debug!("VISION READ: switching to raw splice mode");
                self.read_mode = ReadMode::DirectRaw;
                if let Some(flag) = &self.read_splice_flag {
                    flag.store(true, Ordering::Release);
                }
            }
            Some(UnpadCommand::End) => {
                debug!("VISION READ: switching to direct TLS mode");
                self.read_mode = ReadMode::DirectTls;
            }
            Some(UnpadCommand::Continue) | None => {}
        }

        Ok(changed)
    }

    /// Feed downlink TLS records into the same traffic filter used by the
    /// uplink writer. xray-core shares one TrafficState between VisionReader
    /// and VisionWriter; without this, the client never learns the negotiated
    /// TLS version/cipher from ServerHello and cannot select Direct upstream.
    fn observe_read_content(&mut self, content: &[u8]) -> io::Result<()> {
        if content.is_empty() || !self.traffic_filter.is_filtering() {
            return Ok(());
        }

        self.read_deframer.feed(content);
        loop {
            match self.read_deframer.next_record()? {
                DeframeResult::TlsRecord(record) => {
                    self.traffic_filter.filter_record(&record);
                }
                DeframeResult::UnknownPrefix(_) => {
                    self.traffic_filter.decrement_filter_count();
                }
                DeframeResult::NeedData => return Ok(()),
            }
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.decoded.is_empty() {
                let amt = this.decoded.len().min(buf.remaining());
                buf.put_slice(&this.decoded[..amt]);
                this.decoded.advance(amt);
                return Poll::Ready(Ok(()));
            }

            if this.vless_response_pending {
                if let Some(consumed) = consume_vless_response_header(&mut this.raw)?
                {
                    debug!(
                        "VISION READ: consumed {consumed} bytes of VLESS response header"
                    );
                    this.vless_response_pending = false;
                    continue;
                }
            }

            if this.read_mode != ReadMode::Framed {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            if this.process_raw_read()? || this.read_mode != ReadMode::Framed {
                continue;
            }

            let mut tmp = [0u8; 8192];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = tmp_buf.filled();
                    if filled.is_empty() {
                        if !this.raw.is_empty() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "connection closed with incomplete Vision frame",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    this.raw.extend_from_slice(filled);
                }
            }
        }
    }
}

fn consume_vless_response_header(raw: &mut BytesMut) -> io::Result<Option<usize>> {
    if raw.len() < 2 {
        return Ok(None);
    }

    let version = raw[0];
    if version != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid VLESS response version: {version}"),
        ));
    }

    let addon_len = raw[1] as usize;
    let total = 2 + addon_len;
    if raw.len() < total {
        return Ok(None);
    }

    raw.advance(total);
    Ok(Some(total))
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match this.write_mode {
            WriteMode::DirectTls | WriteMode::DirectRaw => {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            WriteMode::Framed => {}
        }

        ready!(this.flush_write_buf(cx))?;
        if this.write_mode != WriteMode::Framed {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        let consumed = match this.queue_write_data(buf) {
            Ok(consumed) => consumed,
            Err(err) => {
                error!(
                    "VISION WRITE: TLS deframing failed, ending Vision framing: {err}"
                );
                this.traffic_filter.stop_filtering("write invalid TLS data");
                let remaining = this.write_deframer.remaining_data().to_vec();
                this.write_deframer.clear();
                this.pending_write_switch = PendingWriteSwitch::Tls;
                this.pad_frame(
                    &remaining,
                    CMD_PADDING_END,
                    this.traffic_filter.is_tls(),
                );
                buf.len()
            }
        };

        ready!(this.flush_write_buf(cx))?;
        Poll::Ready(Ok(consumed))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_mode == WriteMode::Framed {
            ready!(this.flush_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.write_mode == WriteMode::Framed {
            ready!(this.flush_write_buf(cx))?;
            if this.write_mode == WriteMode::Framed {
                this.queue_shutdown_frame();
                ready!(this.flush_write_buf(cx))?;
            }
        }

        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_UUID_STR: &str = "5415d8e0-df92-3655-afa4-b79de66413f5";
    const TEST_UUID: [u8; 16] = [
        0x54, 0x15, 0xd8, 0xe0, 0xdf, 0x92, 0x36, 0x55, 0xaf, 0xa4, 0xb7, 0x9d,
        0xe6, 0x64, 0x13, 0xf5,
    ];

    fn make_vision_pair() -> (VisionStream, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(65536);
        (
            VisionStream::new(Box::new(client), TEST_UUID_STR.to_owned(), None)
                .unwrap(),
            server,
        )
    }

    fn parse_frame(buf: &[u8], offset: usize) -> (u8, Vec<u8>, u16, usize) {
        let cmd = buf[offset];
        let content_len =
            u16::from_be_bytes([buf[offset + 1], buf[offset + 2]]) as usize;
        let padding_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]);
        let content = buf[offset + 5..offset + 5 + content_len].to_vec();
        let next = offset + 5 + content_len + padding_len as usize;
        (cmd, content, padding_len, next)
    }

    fn tls_record(
        content_type: u8,
        handshake_type: Option<u8>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        if let Some(handshake_type) = handshake_type {
            body.push(handshake_type);
            body.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        }
        body.extend_from_slice(payload);

        let mut record = vec![content_type, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    fn tls13_server_hello() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&[0x11; 32]);
        payload.push(0);
        payload.extend_from_slice(&[0x13, 0x01]);
        payload.push(0);
        payload.extend_from_slice(&[0x00, 0x06]);
        payload.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        tls_record(0x16, Some(0x02), &payload)
    }

    fn server_first_frame(
        uuid: &[u8; 16],
        command: u8,
        content: &[u8],
        padding_len: u16,
    ) -> Vec<u8> {
        let mut v = uuid.to_vec();
        v.push(command);
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
        v.extend_from_slice(&padding_len.to_be_bytes());
        v.extend_from_slice(content);
        v.resize(v.len() + padding_len as usize, 0);
        v
    }

    fn server_frame(command: u8, content: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + content.len());
        v.push(command);
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(content);
        v
    }

    #[tokio::test]
    async fn test_write_plaintext_first_frame_ends_padding() {
        let (mut vs, mut server) = make_vision_pair();
        let payload = b"hello";

        vs.write_all(payload).await.unwrap();
        vs.flush().await.unwrap();

        let mut received = vec![0u8; 65536];
        let n = server.read(&mut received).await.unwrap();
        let received = &received[..n];

        assert_eq!(&received[..16], &TEST_UUID);
        let (cmd, content, padding_len, _) = parse_frame(received, 16);
        assert_eq!(cmd, CMD_PADDING_END);
        assert_eq!(content, payload);
        assert!(padding_len > 0);
    }

    #[tokio::test]
    async fn test_write_direct_after_tls13_server_hello_and_app_data() {
        let (mut vs, mut server) = make_vision_pair();
        let client_hello = tls_record(0x16, Some(0x01), &[0; 32]);
        let server_hello = tls13_server_hello();
        let app_data = tls_record(TLS_APPLICATION_DATA, None, b"hello");

        vs.write_all(&client_hello).await.unwrap();
        vs.write_all(&server_hello).await.unwrap();
        vs.write_all(&app_data).await.unwrap();
        vs.flush().await.unwrap();

        let mut buf = vec![0u8; 65536];
        let n = server.read(&mut buf).await.unwrap();
        let received = &buf[..n];
        let (_, _, _, next) = parse_frame(received, 16);
        let (_, _, _, next) = parse_frame(received, next);
        let (cmd, content, _, _) = parse_frame(received, next);

        assert_eq!(cmd, CMD_PADDING_DIRECT);
        assert_eq!(content, app_data);

        let raw_payload = b"raw bytes after splice";
        vs.write_all(raw_payload).await.unwrap();
        vs.flush().await.unwrap();

        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], raw_payload);
    }

    #[tokio::test]
    async fn test_downlink_server_hello_enables_uplink_direct() {
        let (mut vs, mut server) = make_vision_pair();
        let client_hello = tls_record(0x16, Some(0x01), &[0; 32]);
        let server_hello = tls13_server_hello();
        let app_data = tls_record(TLS_APPLICATION_DATA, None, b"request");

        vs.write_all(&client_hello).await.unwrap();
        vs.flush().await.unwrap();

        let mut uplink = vec![0u8; 65536];
        let _ = server.read(&mut uplink).await.unwrap();

        let mut downlink = vec![0, 0];
        downlink.extend(server_first_frame(
            &TEST_UUID,
            CMD_PADDING_CONTINUE,
            &server_hello,
            0,
        ));
        server.write_all(&downlink).await.unwrap();

        let mut observed_server_hello = vec![0u8; server_hello.len()];
        vs.read_exact(&mut observed_server_hello).await.unwrap();
        assert_eq!(observed_server_hello, server_hello);

        vs.write_all(&app_data).await.unwrap();
        vs.flush().await.unwrap();

        let n = server.read(&mut uplink).await.unwrap();
        let (cmd, content, _, _) = parse_frame(&uplink[..n], 0);
        assert_eq!(cmd, CMD_PADDING_DIRECT);
        assert_eq!(content, app_data);
    }

    #[tokio::test]
    async fn test_read_switches_to_direct_on_cmd_direct() {
        let (mut vs, mut server) = make_vision_pair();
        let raw_after = b"\x17\x03\x03\x00\x05hello";
        let mut msg = vec![0, 0];
        msg.extend(server_first_frame(
            &TEST_UUID,
            CMD_PADDING_CONTINUE,
            b"finished",
            0,
        ));
        msg.extend(server_frame(CMD_PADDING_DIRECT, b"last-vision"));
        msg.extend_from_slice(raw_after);
        server.write_all(&msg).await.unwrap();
        drop(server);

        let mut out = Vec::new();
        vs.read_to_end(&mut out).await.unwrap();

        let mut expected = b"finishedlast-vision".to_vec();
        expected.extend_from_slice(raw_after);
        assert_eq!(out, expected);
    }

    #[tokio::test]
    async fn test_read_incomplete_padding_returns_content() {
        let (mut vs, mut server) = make_vision_pair();
        let mut msg = vec![0, 0];
        msg.extend(server_first_frame(
            &TEST_UUID,
            CMD_PADDING_END,
            b"payload",
            5,
        ));
        msg.truncate(msg.len() - 3);
        server.write_all(&msg).await.unwrap();

        let mut out = [0u8; 16];
        let n = vs.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"payload");
    }

    #[test]
    fn test_empty_raw_after_continue_frame_makes_no_progress() {
        let (mut vs, _) = make_vision_pair();

        vs.raw.extend(server_first_frame(
            &TEST_UUID,
            CMD_PADDING_CONTINUE,
            b"payload",
            0,
        ));

        assert!(vs.process_raw_read().unwrap());
        assert_eq!(&vs.decoded[..], b"payload");
        vs.decoded.clear();

        assert!(!vs.process_raw_read().unwrap());
        assert_eq!(vs.read_mode, ReadMode::Framed);
    }

    #[test]
    fn test_fragmented_downlink_server_hello_enables_direct() {
        let (mut vs, _) = make_vision_pair();
        let server_hello = tls13_server_hello();
        let split = server_hello.len() / 2;

        vs.raw.extend(server_first_frame(
            &TEST_UUID,
            CMD_PADDING_CONTINUE,
            &server_hello[..split],
            0,
        ));
        assert!(vs.process_raw_read().unwrap());
        assert!(!vs.traffic_filter.supports_xtls());
        vs.decoded.clear();

        vs.raw
            .extend(server_frame(CMD_PADDING_CONTINUE, &server_hello[split..]));
        assert!(vs.process_raw_read().unwrap());
        assert!(vs.traffic_filter.supports_xtls());
    }

    #[tokio::test]
    async fn test_shutdown_sends_padding_end_frame() {
        let (mut vs, mut server) = make_vision_pair();

        vs.shutdown().await.unwrap();

        let mut received = vec![0u8; 65536];
        let n = server.read(&mut received).await.unwrap();
        let received = &received[..n];

        assert_eq!(&received[..16], &TEST_UUID);
        let (cmd, content, _, _) = parse_frame(received, 16);
        assert_eq!(cmd, CMD_PADDING_END);
        assert!(content.is_empty());
    }

    #[tokio::test]
    async fn test_shutdown_flushes_pending_deframer_bytes_with_padding_end() {
        let (mut vs, mut server) = make_vision_pair();
        let partial_tls_record = [0x16, 0x03, 0x03];

        vs.write_all(&partial_tls_record).await.unwrap();
        vs.shutdown().await.unwrap();

        let mut received = vec![0u8; 65536];
        let n = server.read(&mut received).await.unwrap();
        let received = &received[..n];

        assert_eq!(&received[..16], &TEST_UUID);
        let (cmd, content, _, _) = parse_frame(received, 16);
        assert_eq!(cmd, CMD_PADDING_END);
        assert_eq!(content, partial_tls_record);
    }

    #[test]
    fn test_split_uuid_prefix_is_retained() {
        let (mut vs, _) = make_vision_pair();

        vs.raw.extend_from_slice(&TEST_UUID[..8]);
        assert!(!vs.process_raw_read().unwrap());
        assert_eq!(&vs.raw[..], &TEST_UUID[..8]);

        vs.raw.extend_from_slice(&TEST_UUID[8..]);
        vs.raw.extend_from_slice(&[
            CMD_PADDING_DIRECT,
            0,
            3,
            0,
            0,
            b'f',
            b'o',
            b'o',
        ]);

        assert!(vs.process_raw_read().unwrap());
        assert_eq!(&vs.decoded[..], b"foo");
        assert_eq!(vs.read_mode, ReadMode::DirectRaw);
    }
}
