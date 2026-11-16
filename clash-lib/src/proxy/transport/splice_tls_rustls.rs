use std::{
    io::{self, Read},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::proxy::{AnyStream, transport::VisionOptions};

const TLS_RECORD_HEADER_LEN: usize = 5;

/// Limits each read passed into rustls to one complete TLS record.
///
/// Vision may switch the connection to raw TCP after a TLS record containing
/// `CMD_DIRECT`. Keeping record boundaries here prevents rustls from reading
/// the raw bytes that follow that record into its private ciphertext buffer.
pub(super) struct TlsRecordBoundaryIo {
    inner: AnyStream,
    header: [u8; TLS_RECORD_HEADER_LEN],
    header_len: usize,
    header_emitted: usize,
    record_remaining: Option<usize>,
    raw_read: bool,
}

impl TlsRecordBoundaryIo {
    pub(super) fn new(inner: AnyStream) -> Self {
        Self {
            inner,
            header: [0; TLS_RECORD_HEADER_LEN],
            header_len: 0,
            header_emitted: 0,
            record_remaining: None,
            raw_read: false,
        }
    }

    fn activate_raw_read(&mut self) {
        debug!("SplicableRustlsStream: activating raw TCP read");
        debug_assert_eq!(self.header_len, self.header_emitted);
        debug_assert_eq!(self.record_remaining, Some(0));
        self.header_len = 0;
        self.header_emitted = 0;
        self.record_remaining = None;
        self.raw_read = true;
    }
}

impl AsyncRead for TlsRecordBoundaryIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.raw_read {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.header_emitted < this.header_len {
                let amount =
                    (this.header_len - this.header_emitted).min(buf.remaining());
                let end = this.header_emitted + amount;
                buf.put_slice(&this.header[this.header_emitted..end]);
                this.header_emitted = end;
                return Poll::Ready(Ok(()));
            }

            if let Some(remaining) = this.record_remaining {
                if remaining == 0 {
                    this.header_len = 0;
                    this.header_emitted = 0;
                    this.record_remaining = None;
                    continue;
                }

                let amount = remaining.min(buf.remaining());
                let read = {
                    let unfilled = buf.initialize_unfilled_to(amount);
                    let mut limited = ReadBuf::new(&mut unfilled[..amount]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
                    limited.filled().len()
                };
                buf.advance(read);
                this.record_remaining = Some(remaining - read);
                return Poll::Ready(Ok(()));
            }

            while this.header_len < TLS_RECORD_HEADER_LEN {
                let start = this.header_len;
                let read = {
                    let (inner, header) = (&mut this.inner, &mut this.header);
                    let mut header_buf = ReadBuf::new(&mut header[start..]);
                    ready!(Pin::new(inner).poll_read(cx, &mut header_buf))?;
                    header_buf.filled().len()
                };
                if read == 0 {
                    if this.header_len == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed during TLS record header",
                    )));
                }
                this.header_len += read;
            }

            let body_len =
                u16::from_be_bytes([this.header[3], this.header[4]]) as usize;
            this.record_remaining = Some(body_len);
        }
    }
}

impl AsyncWrite for TlsRecordBoundaryIo {
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

pub(super) struct SplicableRustlsStream {
    tls: tokio_rustls::client::TlsStream<TlsRecordBoundaryIo>,
    leftover: BytesMut,
    read_flag: Arc<AtomicBool>,
    read_spliced: bool,
    write_flag: Arc<AtomicBool>,
    write_spliced: bool,
}

impl SplicableRustlsStream {
    pub(super) fn new(
        tls: tokio_rustls::client::TlsStream<TlsRecordBoundaryIo>,
        options: &VisionOptions,
    ) -> Self {
        Self {
            tls,
            leftover: BytesMut::new(),
            read_flag: Arc::clone(&options.read_flag),
            read_spliced: false,
            write_flag: Arc::clone(&options.write_flag),
            write_spliced: false,
        }
    }

    fn activate_read_splice(&mut self) {
        debug!("SplicableRustlsStream: draining pending TLS plaintext");
        let (io, conn) = self.tls.get_mut();
        let mut tmp = [0u8; 4096];
        loop {
            match conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => self.leftover.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        io.activate_raw_read();
        self.read_spliced = true;
    }

    fn poll_activate_write_splice(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.write_spliced || !self.write_flag.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }

        ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
        debug!("SplicableRustlsStream: activating raw TCP write");
        self.write_spliced = true;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SplicableRustlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.read_spliced && this.read_flag.load(Ordering::Acquire) {
            this.activate_read_splice();
        }

        if !this.leftover.is_empty() {
            let amount = this.leftover.len().min(buf.remaining());
            buf.put_slice(&this.leftover[..amount]);
            this.leftover.advance(amount);
            return Poll::Ready(Ok(()));
        }

        if this.read_spliced {
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_read(cx, buf)
        } else {
            Pin::new(&mut this.tls).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for SplicableRustlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_activate_write_splice(cx))?;
        if this.write_spliced {
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_write(cx, buf)
        } else {
            Pin::new(&mut this.tls).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_activate_write_splice(cx))?;
        if this.write_spliced {
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_flush(cx)
        } else {
            Pin::new(&mut this.tls).poll_flush(cx)
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_activate_write_splice(cx))?;
        if this.write_spliced {
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_shutdown(cx)
        } else {
            Pin::new(&mut this.tls).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{SplicableRustlsStream, TlsRecordBoundaryIo};
    use crate::proxy::transport::tls::ensure_vision_tls13;
    use crate::proxy::{AnyStream, transport::VisionOptions};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    async fn connected_tls_pair(
        tls12_only: bool,
    ) -> (
        SplicableRustlsStream,
        tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
        VisionOptions,
    ) {
        crate::setup_default_crypto_provider();

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![
                "vision.example.com".to_owned(),
            ])
            .expect("test certificate should generate");
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
                .expect("test private key should serialize");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("test TLS server config should build");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(cert_der)
            .expect("test certificate should be trusted");
        let client_builder = if tls12_only {
            rustls::ClientConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS12,
            ])
        } else {
            rustls::ClientConfig::builder()
        };
        let client_config = client_builder
            .with_root_certificates(roots)
            .with_no_client_auth();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let boundary_io = TlsRecordBoundaryIo::new(Box::new(client_io) as AnyStream);
        let client_fut = TlsConnector::from(Arc::new(client_config)).connect(
            rustls::pki_types::ServerName::try_from("vision.example.com".to_owned())
                .expect("test server name should parse"),
            boundary_io,
        );
        let server_fut =
            TlsAcceptor::from(Arc::new(server_config)).accept(server_io);
        let (client, server) = tokio::join!(client_fut, server_fut);
        let client = client.expect("TLS client handshake should complete");
        let server = server.expect("TLS server handshake should complete");
        let options = VisionOptions::default();

        (
            SplicableRustlsStream::new(client, &options),
            server,
            options,
        )
    }

    #[tokio::test]
    async fn raw_bytes_after_tls_record_remain_available_for_splice() {
        let (client, mut peer) = tokio::io::duplex(128);
        let mut stream = TlsRecordBoundaryIo::new(Box::new(client) as _);
        peer.write_all(b"\x17\x03\x03\x00\x03abcraw-tail")
            .await
            .unwrap();

        let mut tls_record = [0u8; 8];
        stream.read_exact(&mut tls_record).await.unwrap();
        assert_eq!(&tls_record, b"\x17\x03\x03\x00\x03abc");

        stream.activate_raw_read();
        let mut raw = [0u8; 8];
        stream.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw-tail");
    }

    #[tokio::test]
    async fn rustls_read_splice_preserves_raw_bytes_after_tls_record() {
        let (mut client, mut server, options) = connected_tls_pair(false).await;
        server.write_all(b"vision-direct-frame").await.unwrap();
        server.flush().await.unwrap();
        server.get_mut().0.write_all(b"raw-downlink").await.unwrap();

        let mut frame = [0u8; 19];
        client.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"vision-direct-frame");

        options
            .read_flag
            .store(true, std::sync::atomic::Ordering::Release);
        let mut raw = [0u8; 12];
        client.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw-downlink");
    }

    #[tokio::test]
    async fn rustls_write_splice_flushes_tls_before_raw_bytes() {
        let (mut client, mut server, options) = connected_tls_pair(false).await;
        client.write_all(b"vision-direct-frame").await.unwrap();
        client.flush().await.unwrap();
        options
            .write_flag
            .store(true, std::sync::atomic::Ordering::Release);
        client.write_all(b"raw-uplink").await.unwrap();
        client.flush().await.unwrap();

        let server_io = &mut server.get_mut().0;
        let mut header = [0u8; 5];
        server_io.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x17, "expected an outer TLS app-data record");
        let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; body_len];
        server_io.read_exact(&mut body).await.unwrap();

        let mut raw = [0u8; 10];
        server_io.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw-uplink");
    }

    #[tokio::test]
    async fn rustls_tls12_outer_connection_is_rejected_for_vision() {
        let (_, server, _) = connected_tls_pair(true).await;
        assert_eq!(
            server.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
        let err = ensure_vision_tls13(server.get_ref().1.protocol_version())
            .expect_err("Vision must reject outer TLS 1.2");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
