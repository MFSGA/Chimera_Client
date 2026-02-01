use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use aes_gcm::{
    Aes128Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use bytes::BufMut;
use chacha20poly1305::ChaCha20Poly1305;
use rand::{TryRngCore, rngs::OsRng};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

use super::{AnyStream, OutboundHandler, OutboundType};
use crate::{
    app::{
        dispatcher::{BoxedChainedStream, ChainedStream, ChainedStreamWrapper},
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::{
        HandlerCommonOptions,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
        DialWithConnector,
    },
    session::Session,
};

const VERSION_BYTE: u8 = 1;
const CMD_CONNECT: u8 = 1;
const CMD_CONNECT_V2: u8 = 5;
const PAYLOAD_SIZE_LIMIT: usize = 0x3fff;
const SALT_SIZE: usize = 16;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub psk: Vec<u8>,
    pub version: SnellVersion,
    pub obfs: SnellObfs,
    pub obfs_host: String,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snell")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    async fn connect_with_dialer(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let obfs_stream = match self.opts.obfs {
            SnellObfs::None => stream,
            SnellObfs::Tls => wrap_tls(stream, &self.opts.obfs_host).await?,
            SnellObfs::Http => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "snell http obfs is not supported",
                ));
            }
        };

        let cipher = SnellCipher::new(self.opts.version, self.opts.psk.clone());
        let mut snell = SnellStream::handshake(obfs_stream, cipher).await?;
        let host = sess.destination.host();
        write_header(
            &mut snell,
            host.as_str(),
            sess.destination.port(),
            self.opts.version == SnellVersion::V2,
        )
        .await?;

        let chained = ChainedStreamWrapper::new(snell);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Snell
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let connector = self.connector.read().await;
        let dialer = connector
            .as_ref()
            .cloned()
            .unwrap_or_else(|| GLOBAL_DIRECT_CONNECTOR.clone());
        self.connect_with_dialer(sess, resolver, dialer.as_ref())
            .await
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        self.connect_with_dialer(sess, resolver, connector).await
    }
}

impl_default_connector!(Handler);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SnellVersion {
    V1,
    V2,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SnellObfs {
    None,
    Tls,
    Http,
}

impl SnellObfs {
    pub fn from_str(value: Option<&str>) -> io::Result<Self> {
        let normalized = value
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_default();
        match normalized.as_str() {
            "" | "none" | "off" => Ok(SnellObfs::None),
            "tls" => Ok(SnellObfs::Tls),
            "http" => Ok(SnellObfs::Http),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported snell obfs type: {other}"),
            )),
        }
    }
}

struct SnellStream {
    inner: AnyStream,
    reader: SnellReader,
    writer: SnellWriter,
}

impl SnellStream {
    async fn handshake(mut inner: AnyStream, cipher: SnellCipher) -> io::Result<Self> {
        let mut salt_out = vec![0; SALT_SIZE];
        OsRng
            .try_fill_bytes(&mut salt_out)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("snell rng: {e}")))?;
        inner.write_all(&salt_out).await?;
        let writer = SnellWriter::new(cipher.make_encrypter(&salt_out)?);

        let mut salt_in = vec![0; SALT_SIZE];
        inner.read_exact(&mut salt_in).await?;
        let reader = SnellReader::new(cipher.make_decrypter(&salt_in)?);

        Ok(Self {
            inner,
            reader,
            writer,
        })
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.reader.copy_into(buf) {
            return Poll::Ready(Ok(()));
        }
        if this.reader.closed {
            return Poll::Ready(Ok(()));
        }
        match this.reader.poll_fill(cx, Pin::new(&mut this.inner)) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        this.reader.copy_into(buf);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() && this.writer.is_idle() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if this.writer.is_idle() {
                let chunk = buf.len().min(PAYLOAD_SIZE_LIMIT);
                if chunk == 0 {
                    return Poll::Ready(Ok(0));
                }
                this.writer.prepare_chunk(&buf[..chunk])?;
            }

            if let Some(state) = this.writer.state.as_mut() {
                if state.header_pos < state.header.len() {
                    match Pin::new(&mut this.inner)
                        .poll_write(cx, &state.header[state.header_pos..])
                    {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                        Poll::Ready(Ok(n)) => {
                            state.header_pos += n;
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }
                if state.payload_pos < state.payload.len() {
                    match Pin::new(&mut this.inner)
                        .poll_write(cx, &state.payload[state.payload_pos..])
                    {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                        Poll::Ready(Ok(n)) => {
                            state.payload_pos += n;
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }
                let chunk_len = state.chunk_len;
                this.writer.state = None;
                return Poll::Ready(Ok(chunk_len));
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct SnellWriter {
    aead: SnellAead,
    nonce: Vec<u8>,
    state: Option<WriterState>,
    tag_size: usize,
}

impl SnellWriter {
    fn new(aead: SnellAead) -> Self {
        let nonce_len = aead.nonce_len();
        let tag_size = aead.tag_len();
        Self {
            aead,
            nonce: vec![0; nonce_len],
            state: None,
            tag_size,
        }
    }

    fn is_idle(&self) -> bool {
        self.state.is_none()
    }

    fn prepare_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let chunk_len = payload.len();
        let header = self.encrypt_header(chunk_len)?;
        let payload = self.encrypt_payload(payload)?;
        self.state = Some(WriterState {
            header,
            payload,
            header_pos: 0,
            payload_pos: 0,
            chunk_len,
        });
        Ok(())
    }

    fn encrypt_header(&mut self, chunk_len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8, 0u8];
        buf[0] = ((chunk_len >> 8) & 0xff) as u8;
        buf[1] = (chunk_len & 0xff) as u8;
        self.aead.encrypt_in_place(&self.nonce, &mut buf)?;
        increment_nonce(&mut self.nonce);
        Ok(buf)
    }

    fn encrypt_payload(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut buf = payload.to_vec();
        self.aead.encrypt_in_place(&self.nonce, &mut buf)?;
        increment_nonce(&mut self.nonce);
        Ok(buf)
    }
}

struct WriterState {
    header: Vec<u8>,
    payload: Vec<u8>,
    header_pos: usize,
    payload_pos: usize,
    chunk_len: usize,
}

struct SnellReader {
    aead: SnellAead,
    nonce: Vec<u8>,
    phase: ReaderPhase,
    leftover: Vec<u8>,
    leftover_pos: usize,
    closed: bool,
    tag_size: usize,
}

enum ReaderPhase {
    Header {
        buf: Vec<u8>,
        pos: usize,
    },
    Payload {
        buf: Vec<u8>,
        pos: usize,
        chunk_len: usize,
    },
}

impl SnellReader {
    fn new(aead: SnellAead) -> Self {
        let nonce_len = aead.nonce_len();
        let tag_size = aead.tag_len();
        let phase = ReaderPhase::Header {
            buf: vec![0; 2 + tag_size],
            pos: 0,
        };
        Self {
            aead,
            nonce: vec![0; nonce_len],
            phase,
            leftover: Vec::new(),
            leftover_pos: 0,
            closed: false,
            tag_size,
        }
    }

    fn copy_into(&mut self, dst: &mut ReadBuf<'_>) -> bool {
        if self.leftover_pos >= self.leftover.len() {
            self.leftover.clear();
            self.leftover_pos = 0;
            return false;
        }
        let remaining = &self.leftover[self.leftover_pos..];
        let to_copy = remaining.len().min(dst.remaining());
        dst.put_slice(&remaining[..to_copy]);
        self.leftover_pos += to_copy;
        if self.leftover_pos >= self.leftover.len() {
            self.leftover.clear();
            self.leftover_pos = 0;
        }
        true
    }

    fn poll_fill(
        &mut self,
        cx: &mut Context<'_>,
        mut stream: Pin<&mut AnyStream>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut self.phase {
                ReaderPhase::Header { buf, pos } => {
                    if *pos < buf.len() {
                        let mut read_buf = ReadBuf::new(&mut buf[*pos..]);
                        match stream.as_mut().poll_read(cx, &mut read_buf) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    self.closed = true;
                                    return Poll::Ready(Ok(()));
                                }
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }
                    if *pos == buf.len() {
                        Self::decrypt(&self.aead, &mut self.nonce, buf)?;
                        let chunk_len =
                            ((buf[0] as usize) << 8 | buf[1] as usize) & PAYLOAD_SIZE_LIMIT;
                        if chunk_len == 0 {
                            self.closed = true;
                            return Poll::Ready(Ok(()));
                        }
                        let payload_size = chunk_len + self.tag_size;
                        self.phase = ReaderPhase::Payload {
                            buf: vec![0; payload_size],
                            pos: 0,
                            chunk_len,
                        };
                    }
                }
                ReaderPhase::Payload {
                    buf,
                    pos,
                    chunk_len,
                } => {
                    if *pos < buf.len() {
                        let mut read_buf = ReadBuf::new(&mut buf[*pos..]);
                        match stream.as_mut().poll_read(cx, &mut read_buf) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    self.closed = true;
                                    return Poll::Ready(Ok(()));
                                }
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }
                    if *pos == buf.len() {
                        Self::decrypt(&self.aead, &mut self.nonce, buf)?;
                        self.leftover = buf[..*chunk_len].to_vec();
                        self.leftover_pos = 0;
                        self.phase = ReaderPhase::Header {
                            buf: vec![0; 2 + self.tag_size],
                            pos: 0,
                        };
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }

    fn decrypt(aead: &SnellAead, nonce: &mut [u8], buf: &mut Vec<u8>) -> io::Result<()> {
        aead.decrypt_in_place(nonce, buf)?;
        increment_nonce(nonce);
        Ok(())
    }
}

struct SnellCipher {
    version: SnellVersion,
    key: Vec<u8>,
}

impl SnellCipher {
    fn new(version: SnellVersion, psk: Vec<u8>) -> Self {
        Self { version, key: psk }
    }

    fn make_encrypter(&self, salt: &[u8]) -> io::Result<SnellAead> {
        self.make_aead(salt)
    }

    fn make_decrypter(&self, salt: &[u8]) -> io::Result<SnellAead> {
        self.make_aead(salt)
    }

    fn make_aead(&self, salt: &[u8]) -> io::Result<SnellAead> {
        let key = self.derive_key(salt)?;
        match self.version {
            SnellVersion::V2 => {
                let mut key_array = GenericArray::clone_from_slice(&key);
                let cipher = Aes128Gcm::new(&key_array);
                Ok(SnellAead::Aes(cipher))
            }
            SnellVersion::V1 => {
                let mut key_array = GenericArray::clone_from_slice(&key);
                let cipher = ChaCha20Poly1305::new(&key_array);
                Ok(SnellAead::ChaCha(cipher))
            }
        }
    }

    fn derive_key(&self, salt: &[u8]) -> io::Result<Vec<u8>> {
        let key_len = match self.version {
            SnellVersion::V2 => 16,
            SnellVersion::V1 => 32,
        };
        let params = Params::new(8, 3, 1, Some(key_len))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = vec![0u8; key_len];
        argon
            .hash_password_into(&self.key, salt, &mut key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("argon2: {e}")))?;
        Ok(key)
    }
}

enum SnellAead {
    Aes(Aes128Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl SnellAead {
    fn tag_len(&self) -> usize {
        match self {
            SnellAead::Aes(_) => 16,
            SnellAead::ChaCha(_) => 16,
        }
    }

    fn nonce_len(&self) -> usize {
        match self {
            SnellAead::Aes(_) => 12,
            SnellAead::ChaCha(_) => 12,
        }
    }

    fn encrypt_in_place(&self, nonce: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        let tag = self.tag_len();
        let len = buf.len();
        buf.resize(len + tag, 0);
        let nonce = GenericArray::clone_from_slice(nonce);
        match self {
            SnellAead::Aes(cipher) => cipher
                .encrypt_in_place(&nonce, &[], buf)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "snell encrypt"))?,
            SnellAead::ChaCha(cipher) => cipher
                .encrypt_in_place(&nonce, &[], buf)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "snell encrypt"))?,
        }
        Ok(())
    }

    fn decrypt_in_place(&self, nonce: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        let nonce = GenericArray::clone_from_slice(nonce);
        match self {
            SnellAead::Aes(cipher) => cipher
                .decrypt_in_place(&nonce, &[], buf)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "snell decrypt"))?,
            SnellAead::ChaCha(cipher) => cipher
                .decrypt_in_place(&nonce, &[], buf)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "snell decrypt"))?,
        }
        Ok(())
    }
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

async fn wrap_tls(inner: AnyStream, host: &str) -> io::Result<AnyStream> {
    let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid snell tls host for SNI"))?;
    let stream = connector.connect(server_name, inner).await?;
    Ok(Box::new(stream))
}

async fn write_header<S: AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    port: u16,
    use_v2: bool,
) -> io::Result<()> {
    let mut header = Vec::with_capacity(2 + 1 + 1 + host.len() + 2);
    header.push(VERSION_BYTE);
    header.push(if use_v2 { CMD_CONNECT_V2 } else { CMD_CONNECT });
    header.push(0);
    if host.len() > 0xff {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snell host too long",
        ));
    }
    header.push(host.len() as u8);
    header.extend_from_slice(host.as_bytes());
    header.put_u16(port);
    stream.write_all(&header).await
}
