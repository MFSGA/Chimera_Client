use std::{
    collections::HashMap,
    convert::Infallible,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

#[cfg(feature = "xhttp-h3")]
use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
#[cfg(feature = "xhttp-h3")]
use bytes::Buf;
use bytes::Bytes;
use http::{Request, StatusCode, Version};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex, mpsc},
};
use tokio_stream::wrappers::ReceiverStream;

mod meta;
mod padding;
#[cfg(any(feature = "hysteria", feature = "xhttp-h3"))]
pub(crate) mod quinn_datagram;
mod reuse;
mod session;
mod uplink;
pub use meta::{MetadataConfig as XhttpMetadataConfig, MetadataPlacement};
pub use padding::{
    PaddingConfig as XhttpPaddingConfig, PaddingMethod as XhttpPaddingMethod,
    PaddingPlacement as XhttpPaddingPlacement,
};
use reuse::ReuseLimits;
pub use reuse::{
    ReusePolicy as XhttpReusePolicy, ValueRange as XhttpReuseValueRange,
};
pub use session::SessionIdConfig as XhttpSessionIdConfig;
pub use uplink::{
    ChunkSizeRange as XhttpChunkSizeRange, UplinkConfig as XhttpUplinkConfig,
    UplinkDataPlacement,
};

#[cfg(feature = "reality")]
use super::RealityClient;
#[cfg(feature = "tls")]
use super::TlsClient;
use super::Transport;
#[cfg(all(feature = "tun", target_os = "linux"))]
use crate::app::net::TUN_SOMARK;
#[cfg(feature = "xhttp-h3")]
use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::utils::RemoteConnector,
    session::{Session, SocksAddr},
};
use crate::{
    common::errors::map_io_error,
    proxy::{
        AnyStream,
        utils::{NetworkPoolContext, new_protected_tcp_stream},
    },
};
#[cfg(feature = "xhttp-h3")]
use quinn::{
    Endpoint, EndpointConfig, TokioRuntime, TransportConfig,
    crypto::rustls::QuicClientConfig,
};

#[cfg(feature = "xhttp-h3")]
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;
const FRAME_CHANNEL_CAPACITY: usize = 32;
const READ_CHUNK_SIZE: usize = 8 * 1024;
#[allow(dead_code)]
const DEFAULT_XHTTP_ALPN: [&str; 1] = ["h2"];
const DEFAULT_XHTTP_USER_AGENT: &str = "Mozilla/5.0";

type H1SendRequest =
    hyper::client::conn::http1::SendRequest<BoxBody<Bytes, Infallible>>;
type H2SendRequest =
    hyper::client::conn::http2::SendRequest<BoxBody<Bytes, Infallible>>;

struct ReusableH2 {
    sender: H2SendRequest,
    created_at: Instant,
    active: Arc<AtomicU64>,
    reuse_count: u64,
    request_count: Arc<AtomicU64>,
    limits: ReuseLimits,
    network_generation: Option<u64>,
    path_id: Option<crate::app::flow::NetworkPathId>,
}

impl ReusableH2 {
    fn retired(&self) -> bool {
        if self.sender.is_closed() {
            return true;
        }
        if self.limits.c_max_reuse_times != 0
            && self.reuse_count >= self.limits.c_max_reuse_times
        {
            return true;
        }
        if self.limits.h_max_request_times != 0
            && self.request_count.load(Ordering::Acquire)
                >= self.limits.h_max_request_times
        {
            return true;
        }
        self.limits.h_max_reusable_secs != 0
            && self.created_at.elapsed().as_secs() >= self.limits.h_max_reusable_secs
    }

    fn has_capacity(&self) -> bool {
        self.limits.max_concurrency == 0
            || self.active.load(Ordering::Acquire) < self.limits.max_concurrency
    }
}

/// A pooled HTTP/3 connection is retired when its last pool entry is
/// removed. Existing application streams remain usable until their own Drop;
/// after the last stream leaves, explicitly close the QUIC socket so a
/// long-lived downlink task cannot keep its driver alive indefinitely.
#[cfg(feature = "xhttp-h3")]
struct H3PooledSocket {
    endpoint: Endpoint,
    connection: quinn::Connection,
    active: Arc<AtomicU64>,
    retired: AtomicBool,
    driver_finished: AtomicBool,
}

#[cfg(feature = "xhttp-h3")]
impl H3PooledSocket {
    fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.close_if_idle();
    }

    fn close_if_idle(&self) {
        if self.retired.load(Ordering::Acquire)
            && self.active.load(Ordering::Acquire) == 0
        {
            self.connection.close(
                quinn::VarInt::from_u32(0),
                b"retired HTTP/3 connection has no active streams",
            );
            self.endpoint
                .close(quinn::VarInt::from_u32(0), b"retired HTTP/3 endpoint");
        }
    }
}

/// Prevent cancellation while waiting for a reuse-pool lock from leaving
/// an unregistered QUIC driver and UDP socket running.
#[cfg(feature = "xhttp-h3")]
struct H3PoolRegistration(Option<Arc<H3PooledSocket>>);

#[cfg(feature = "xhttp-h3")]
impl H3PoolRegistration {
    fn complete(mut self) {
        self.0.take();
    }
}

#[cfg(feature = "xhttp-h3")]
impl Drop for H3PoolRegistration {
    fn drop(&mut self) {
        if let Some(socket) = self.0.take() {
            socket.retire();
        }
    }
}

#[cfg(feature = "xhttp-h3")]
struct ReusableH3 {
    sender: H3SendRequest,
    socket: Arc<H3PooledSocket>,
    created_at: Instant,
    active: Arc<AtomicU64>,
    reuse_count: u64,
    request_count: Arc<AtomicU64>,
    limits: ReuseLimits,
    network_generation: Option<u64>,
    path_id: Option<crate::app::flow::NetworkPathId>,
}

#[cfg(feature = "xhttp-h3")]
impl Drop for ReusableH3 {
    fn drop(&mut self) {
        self.socket.retire();
    }
}

#[cfg(feature = "xhttp-h3")]
impl ReusableH3 {
    fn retired(&self) -> bool {
        if self.socket.retired.load(Ordering::Acquire) {
            return true;
        }
        if self.limits.c_max_reuse_times != 0
            && self.reuse_count >= self.limits.c_max_reuse_times
        {
            return true;
        }
        if self.limits.h_max_request_times != 0
            && self.request_count.load(Ordering::Acquire)
                >= self.limits.h_max_request_times
        {
            return true;
        }
        self.limits.h_max_reusable_secs != 0
            && self.created_at.elapsed().as_secs() >= self.limits.h_max_reusable_secs
    }

    fn has_capacity(&self) -> bool {
        self.limits.max_concurrency == 0
            || self.active.load(Ordering::Acquire) < self.limits.max_concurrency
    }
}

#[cfg(feature = "xhttp-h3")]
struct H3UploadSender {
    sender: H3SendRequest,
    /// Owned until handoff to the returned application stream. Dropping this
    /// sender during downstream dial / HTTP request creation frees capacity.
    active: H3ActiveLease,
    request_count: Option<Arc<AtomicU64>>,
    network_path_ids: Vec<crate::app::flow::NetworkPathId>,
}

#[cfg(feature = "xhttp-h3")]
struct H3DownlinkSender {
    sender: H3SendRequest,
    /// Owned across all awaits before the downlink is handed to the caller.
    active: H3ActiveLease,
    request_count: Option<Arc<AtomicU64>>,
    network_path_ids: Vec<crate::app::flow::NetworkPathId>,
}

#[cfg(feature = "xhttp-h3")]
struct H3ActiveLease {
    active: Option<Arc<AtomicU64>>,
    socket: Option<Arc<H3PooledSocket>>,
}

#[cfg(feature = "xhttp-h3")]
impl H3ActiveLease {
    fn none() -> Self {
        Self {
            active: None,
            socket: None,
        }
    }

    fn pooled(socket: Arc<H3PooledSocket>) -> Self {
        Self {
            active: Some(socket.active.clone()),
            socket: Some(socket),
        }
    }

    /// Unlike a pooled sender, an unpooled sender owns the physical QUIC
    /// connection itself. Its Drop must close the driver even without an
    /// active counter or pool entry.
    fn unpooled(socket: Arc<H3PooledSocket>) -> Self {
        Self {
            active: None,
            socket: Some(socket),
        }
    }

    fn into_stream(mut self, stream: AnyStream) -> AnyStream {
        if self.active.is_some() || self.socket.is_some() {
            Box::new(ReuseLeaseStream {
                inner: stream,
                active: self.active.take(),
                h3_socket: self.socket.take(),
            })
        } else {
            stream
        }
    }
}

#[cfg(feature = "xhttp-h3")]
impl Drop for H3ActiveLease {
    fn drop(&mut self) {
        let counted = if let Some(active) = self.active.take() {
            active.fetch_sub(1, Ordering::AcqRel);
            true
        } else {
            false
        };
        if let Some(socket) = self.socket.take() {
            if counted {
                socket.close_if_idle();
            } else {
                // No pool owns this sender: cancel setup / failed response
                // creation must retire its QUIC driver and UDP endpoint.
                socket.retire();
            }
        }
    }
}

struct ReuseLeaseStream {
    inner: AnyStream,
    active: Option<Arc<AtomicU64>>,
    #[cfg(feature = "xhttp-h3")]
    h3_socket: Option<Arc<H3PooledSocket>>,
}

impl AsyncRead for ReuseLeaseStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReuseLeaseStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl Drop for ReuseLeaseStream {
    fn drop(&mut self) {
        let counted = if let Some(active) = self.active.take() {
            active.fetch_sub(1, Ordering::AcqRel);
            true
        } else {
            false
        };
        #[cfg(not(feature = "xhttp-h3"))]
        let _ = counted;
        #[cfg(feature = "xhttp-h3")]
        if let Some(socket) = self.h3_socket.take() {
            if counted {
                socket.close_if_idle();
            } else {
                socket.retire();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XhttpMode {
    Auto,
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum XhttpHttpVersion {
    Http1,
    #[default]
    Http2,
    #[cfg_attr(not(feature = "xhttp-h3"), allow(dead_code))]
    Http3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XhttpSecurity {
    None,
    Tls,
    Reality,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct XhttpRealityConfig {
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub server_name: String,
    pub alpn_protocols: Vec<String>,
    pub support_x25519mlkem768: bool,
}

#[derive(Clone, Debug)]
pub struct XhttpEndpointConfig {
    pub server: String,
    pub port: u16,
    pub security: XhttpSecurity,
    pub server_name: String,
    pub alpn_protocols: Vec<String>,
    pub skip_cert_verify: bool,
    pub fingerprint: Option<String>,
    pub verify_name: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    #[cfg_attr(not(feature = "reality"), allow(dead_code))]
    pub reality: Option<XhttpRealityConfig>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct XhttpDownloadConfig {
    pub server: String,
    pub port: u16,
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub security: XhttpSecurity,
    pub server_name: String,
    pub alpn_protocols: Vec<String>,
    pub skip_cert_verify: bool,
    pub fingerprint: Option<String>,
    pub verify_name: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub reality: Option<XhttpRealityConfig>,
    pub reuse_policy: Option<XhttpReusePolicy>,
}

pub struct Client {
    server: String,
    port: u16,
    path: String,
    host: Option<String>,
    headers: HashMap<String, String>,
    use_tls: bool,
    mode: XhttpMode,
    http_version: XhttpHttpVersion,
    max_each_post_bytes: usize,
    no_grpc_header: bool,
    min_posts_interval_ms: Option<u64>,
    download: Option<XhttpDownloadConfig>,
    upload_endpoint: Option<XhttpEndpointConfig>,
    auto_reality: bool,
    metadata: XhttpMetadataConfig,
    uplink: XhttpUplinkConfig,
    padding: XhttpPaddingConfig,
    session: XhttpSessionIdConfig,
    reuse_policy: Option<XhttpReusePolicy>,
    reuse_max_connections: Option<u64>,
    recovery_gate: tokio::sync::RwLock<()>,
    recovery_cancellation: Mutex<tokio_util::sync::CancellationToken>,
    reuse_pool: Mutex<Vec<ReusableH2>>,
    #[cfg(feature = "xhttp-h3")]
    h3_reuse_pool: Mutex<Vec<ReusableH3>>,
    download_reuse_max_connections: Option<u64>,
    #[cfg(feature = "xhttp-h3")]
    h3_download_reuse_pool: Mutex<Vec<ReusableH3>>,
    download_reuse_pool: Mutex<Vec<ReusableH2>>,
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        path: String,
        host: Option<String>,
        headers: HashMap<String, String>,
        use_tls: bool,
        mode: XhttpMode,
        max_each_post_bytes: usize,
        no_grpc_header: bool,
        min_posts_interval_ms: Option<u64>,
        download: Option<XhttpDownloadConfig>,
    ) -> Self {
        let download_reuse_max_connections = download
            .as_ref()
            .and_then(|config| config.reuse_policy.as_ref())
            .and_then(XhttpReusePolicy::sample_max_connections);

        Self {
            server,
            port,
            path,
            host,
            headers,
            use_tls,
            mode,
            http_version: XhttpHttpVersion::Http2,
            max_each_post_bytes,
            no_grpc_header,
            min_posts_interval_ms,
            download,
            upload_endpoint: None,
            auto_reality: false,
            metadata: XhttpMetadataConfig::default(),
            uplink: XhttpUplinkConfig::default(),
            padding: XhttpPaddingConfig::default(),
            session: XhttpSessionIdConfig::default(),
            reuse_policy: None,
            reuse_max_connections: None,
            recovery_gate: tokio::sync::RwLock::new(()),
            recovery_cancellation: Mutex::new(
                tokio_util::sync::CancellationToken::new(),
            ),
            reuse_pool: Mutex::new(Vec::new()),
            #[cfg(feature = "xhttp-h3")]
            h3_reuse_pool: Mutex::new(Vec::new()),
            download_reuse_max_connections,
            download_reuse_pool: Mutex::new(Vec::new()),
            #[cfg(feature = "xhttp-h3")]
            h3_download_reuse_pool: Mutex::new(Vec::new()),
        }
    }

    pub fn with_upload_endpoint(
        mut self,
        upload_endpoint: Option<XhttpEndpointConfig>,
    ) -> Self {
        self.upload_endpoint = upload_endpoint;
        self
    }

    pub fn with_auto_reality(mut self, auto_reality: bool) -> Self {
        self.auto_reality = auto_reality;
        self
    }

    pub fn with_http_version(mut self, http_version: XhttpHttpVersion) -> Self {
        self.http_version = http_version;
        self
    }

    pub fn with_metadata(mut self, metadata: XhttpMetadataConfig) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_uplink(mut self, uplink: XhttpUplinkConfig) -> Self {
        self.uplink = uplink;
        self
    }

    pub fn with_padding(mut self, padding: XhttpPaddingConfig) -> Self {
        self.padding = padding;
        self
    }

    pub fn with_session(mut self, session: XhttpSessionIdConfig) -> Self {
        self.session = session;
        self
    }

    pub fn with_reuse_policy(
        mut self,
        reuse_policy: Option<XhttpReusePolicy>,
    ) -> Self {
        self.reuse_max_connections = reuse_policy
            .as_ref()
            .and_then(XhttpReusePolicy::sample_max_connections);
        self.reuse_policy = reuse_policy;
        self
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: BoxBody<Bytes, Infallible>,
    ) -> io::Result<Request<BoxBody<Bytes, Infallible>>> {
        build_request(
            &self.server,
            self.port,
            path,
            self.host.as_deref(),
            &self.headers,
            self.use_tls,
            self.request_content_type(method),
            method,
            body,
            &self.padding,
        )
    }

    fn effective_mode(&self) -> XhttpMode {
        match self.mode {
            XhttpMode::Auto
                if matches!(self.http_version, XhttpHttpVersion::Http1) =>
            {
                XhttpMode::PacketUp
            }
            XhttpMode::Auto if self.download.is_some() => XhttpMode::StreamUp,
            XhttpMode::Auto if self.auto_reality => XhttpMode::StreamOne,
            XhttpMode::Auto => XhttpMode::StreamUp,
            mode => mode,
        }
    }

    fn request_content_type(&self, method: &str) -> Option<&'static str> {
        if method != "POST" {
            return None;
        }

        if matches!(
            self.effective_mode(),
            XhttpMode::StreamOne | XhttpMode::StreamUp
        ) && !self.no_grpc_header
        {
            return Some("application/grpc");
        }

        Some("application/octet-stream")
    }
}

async fn handshake_http1(stream: AnyStream) -> io::Result<H1SendRequest> {
    let io = TokioIo::new(stream);
    let (sender, conn) =
        hyper::client::conn::http1::handshake::<_, BoxBody<Bytes, Infallible>>(io)
            .await
            .map_err(map_io_error)?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    Ok(sender)
}

async fn handshake_http2(
    stream: AnyStream,
    keep_alive_period: Option<i64>,
) -> io::Result<H2SendRequest> {
    let io = TokioIo::new(stream);
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());

    match keep_alive_period {
        None => {}
        Some(-1) => {
            builder.keep_alive_interval(None);
        }
        Some(0) => {
            builder
                .keep_alive_interval(Duration::from_secs(45))
                .keep_alive_while_idle(true);
        }
        Some(period) if period > 0 => {
            builder
                .keep_alive_interval(Duration::from_secs(period as u64))
                .keep_alive_while_idle(true);
        }
        Some(period) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "xhttp h-keep-alive-period must be -1, 0, or a positive number, got {period}"
                ),
            ));
        }
    }

    let (sender, conn) = builder
        .handshake::<_, BoxBody<Bytes, Infallible>>(io)
        .await
        .map_err(map_io_error)?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    Ok(sender)
}

async fn send_h2_request(
    sender: &mut H2SendRequest,
    request: Request<BoxBody<Bytes, Infallible>>,
    request_count: Option<&Arc<AtomicU64>>,
) -> io::Result<http::Response<Incoming>> {
    if let Some(request_count) = request_count {
        request_count.fetch_add(1, Ordering::AcqRel);
    }
    sender.send_request(request).await.map_err(map_io_error)
}

impl From<&XhttpDownloadConfig> for XhttpEndpointConfig {
    fn from(config: &XhttpDownloadConfig) -> Self {
        Self {
            server: config.server.clone(),
            port: config.port,
            security: config.security,
            server_name: config.server_name.clone(),
            alpn_protocols: config.alpn_protocols.clone(),
            skip_cert_verify: config.skip_cert_verify,
            fingerprint: config.fingerprint.clone(),
            verify_name: config.verify_name.clone(),
            tls_cert: config.tls_cert.clone(),
            tls_key: config.tls_key.clone(),
            reality: config.reality.clone(),
        }
    }
}

async fn secure_endpoint_stream(
    config: &XhttpEndpointConfig,
    stream: AnyStream,
) -> io::Result<AnyStream> {
    match config.security {
        XhttpSecurity::None => Ok(stream),
        XhttpSecurity::Tls => {
            #[cfg(feature = "tls")]
            {
                let tls = TlsClient::new_with_fingerprint(
                    config.skip_cert_verify,
                    config.server_name.clone(),
                    Some(config.alpn_protocols.clone()),
                    None,
                    config.fingerprint.clone(),
                )
                .with_verify_name(config.verify_name.clone())
                .with_client_auth(config.tls_cert.clone(), config.tls_key.clone())?;
                tls.proxy_stream(stream).await
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = stream;
                Err(io::Error::other(
                    "xhttp download_settings tls requires tls feature",
                ))
            }
        }
        XhttpSecurity::Reality => {
            #[cfg(feature = "reality")]
            {
                let reality = config.reality.as_ref().ok_or_else(|| {
                    io::Error::other(
                        "xhttp download_settings reality requires reality config",
                    )
                })?;
                let client = RealityClient::new_with_alpn(
                    reality.public_key,
                    reality.short_id.clone(),
                    reality.server_name.clone(),
                    Vec::new(),
                    reality.alpn_protocols.clone(),
                )
                .with_x25519mlkem768(reality.support_x25519mlkem768);
                client.proxy_stream(stream).await
            }
            #[cfg(not(feature = "reality"))]
            {
                let _ = stream;
                Err(io::Error::other(
                    "xhttp download_settings reality requires reality feature",
                ))
            }
        }
    }
}

async fn connect_endpoint_stream(
    config: &XhttpEndpointConfig,
) -> io::Result<AnyStream> {
    let endpoint = tokio::net::lookup_host((config.server.as_str(), config.port))
        .await?
        .next()
        .ok_or_else(|| io::Error::other("xhttp endpoint resolved no addresses"))?;
    #[cfg(all(feature = "tun", target_os = "linux"))]
    let so_mark = *TUN_SOMARK.read().await;
    #[cfg(all(not(feature = "tun"), target_os = "linux"))]
    let so_mark = None;
    let tcp = new_protected_tcp_stream(
        endpoint,
        None,
        #[cfg(target_os = "linux")]
        so_mark,
    )
    .await?;
    secure_endpoint_stream(config, Box::new(tcp)).await
}

async fn connect_download_stream(
    config: &XhttpDownloadConfig,
) -> io::Result<AnyStream> {
    connect_endpoint_stream(&XhttpEndpointConfig::from(config)).await
}

async fn connect_plain_stream(server: &str, port: u16) -> io::Result<AnyStream> {
    let endpoint = XhttpEndpointConfig {
        server: server.to_owned(),
        port,
        security: XhttpSecurity::None,
        server_name: server.to_owned(),
        alpn_protocols: vec!["http/1.1".to_owned()],
        skip_cert_verify: false,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
    };
    connect_endpoint_stream(&endpoint).await
}

async fn acquire_download_sender(
    client: &Client,
    download: &XhttpDownloadConfig,
    network_generation: Option<u64>,
) -> io::Result<(
    H2SendRequest,
    Option<Arc<AtomicU64>>,
    Option<Arc<AtomicU64>>,
)> {
    let Some(reuse_policy) = download.reuse_policy.as_ref() else {
        let stream = connect_download_stream(download).await?;
        let sender = handshake_http2(stream, None).await?;
        return Ok((sender, None, None));
    };

    let mut pool = client.download_reuse_pool.lock().await;
    pool.retain(|connection| {
        !connection.retired() && connection.network_generation == network_generation
    });

    let should_open_fresh = match client.download_reuse_max_connections {
        Some(0) => true,
        Some(max_connections) => (pool.len() as u64) < max_connections,
        None => !pool.iter().any(ReusableH2::has_capacity),
    };

    if !should_open_fresh
        && let Some(connection) =
            pool.iter_mut().find(|connection| connection.has_capacity())
    {
        connection.reuse_count += 1;
        connection.active.fetch_add(1, Ordering::AcqRel);
        return Ok((
            connection.sender.clone(),
            Some(connection.active.clone()),
            Some(connection.request_count.clone()),
        ));
    }

    let stream = connect_download_stream(download).await?;
    let sender =
        handshake_http2(stream, Some(reuse_policy.h_keep_alive_period)).await?;

    if client.download_reuse_max_connections == Some(0) {
        return Ok((sender, None, None));
    }

    let active = Arc::new(AtomicU64::new(1));
    let request_count = Arc::new(AtomicU64::new(0));
    pool.push(ReusableH2 {
        sender: sender.clone(),
        created_at: Instant::now(),
        active: active.clone(),
        reuse_count: 0,
        request_count: request_count.clone(),
        limits: reuse_policy.sample_limits(),
        network_generation,
        path_id: None,
    });

    Ok((sender, Some(active), Some(request_count)))
}

async fn open_separate_downlink_response(
    client: &Client,
    download: &XhttpDownloadConfig,
    session_id: &str,
    network_generation: Option<u64>,
) -> io::Result<(Incoming, Option<Arc<AtomicU64>>)> {
    let mut headers = download.headers.clone();
    let path =
        client
            .metadata
            .apply(&download.path, &mut headers, session_id, None)?;
    let request = build_request(
        &download.server,
        download.port,
        &path,
        download.host.as_deref(),
        &headers,
        matches!(
            download.security,
            XhttpSecurity::Tls | XhttpSecurity::Reality
        ),
        None,
        "GET",
        http_body_util::Empty::<Bytes>::new().boxed(),
        &client.padding,
    )?;

    let (mut downlink_sender, active, request_count) =
        acquire_download_sender(client, download, network_generation).await?;
    let result =
        send_h2_request(&mut downlink_sender, request, request_count.as_ref())
            .await
            .and_then(validate_response_status);

    match result {
        Ok(body) => Ok((body, active)),
        Err(err) => {
            if let Some(active) = active {
                active.fetch_sub(1, Ordering::AcqRel);
            }
            Err(err)
        }
    }
}

async fn open_downlink_response(
    client: &Client,
    sender: &mut H2SendRequest,
    session_id: &str,
    request_count: Option<&Arc<AtomicU64>>,
    network_generation: Option<u64>,
) -> io::Result<(Incoming, Option<Arc<AtomicU64>>)> {
    if let Some(download) = client.download.as_ref() {
        open_separate_downlink_response(
            client,
            download,
            session_id,
            network_generation,
        )
        .await
    } else {
        let mut headers = client.headers.clone();
        let path =
            client
                .metadata
                .apply(&client.path, &mut headers, session_id, None)?;
        let request = build_request(
            &client.server,
            client.port,
            &path,
            client.host.as_deref(),
            &headers,
            client.use_tls,
            None,
            "GET",
            http_body_util::Empty::<Bytes>::new().boxed(),
            &client.padding,
        )?;
        let response = send_h2_request(sender, request, request_count).await?;
        validate_response_status(response).map(|body| (body, None))
    }
}

fn validate_response_status(
    response: http::Response<Incoming>,
) -> io::Result<Incoming> {
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected xhttp response status: {}", response.status()),
        ));
    }

    Ok(response.into_body())
}

#[allow(clippy::too_many_arguments)]
fn build_request(
    server: &str,
    port: u16,
    path: &str,
    host: Option<&str>,
    headers: &HashMap<String, String>,
    use_tls: bool,
    content_type: Option<&str>,
    method: &str,
    body: BoxBody<Bytes, Infallible>,
    padding: &XhttpPaddingConfig,
) -> io::Result<Request<BoxBody<Bytes, Infallible>>> {
    build_request_for_version(
        server,
        port,
        path,
        host,
        headers,
        use_tls,
        content_type,
        method,
        body,
        padding,
        XhttpHttpVersion::Http2,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_request_for_version<B>(
    server: &str,
    port: u16,
    path: &str,
    host: Option<&str>,
    headers: &HashMap<String, String>,
    use_tls: bool,
    content_type: Option<&str>,
    method: &str,
    body: B,
    padding: &XhttpPaddingConfig,
    http_version: XhttpHttpVersion,
) -> io::Result<Request<B>> {
    let scheme = if use_tls { "https" } else { "http" };
    let mut uri = format!("{scheme}://{server}:{port}{path}");
    let mut headers = headers.clone();
    padding.apply(&mut uri, &mut headers)?;

    let parsed_uri: http::Uri = uri.parse().map_err(map_io_error)?;
    let request_uri = match http_version {
        XhttpHttpVersion::Http1 => parsed_uri
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned()),
        XhttpHttpVersion::Http2 | XhttpHttpVersion::Http3 => uri,
    };
    let version = match http_version {
        XhttpHttpVersion::Http1 => Version::HTTP_11,
        XhttpHttpVersion::Http2 => Version::HTTP_2,
        XhttpHttpVersion::Http3 => Version::HTTP_3,
    };

    let mut request = Request::builder()
        .method(method)
        .uri(request_uri)
        .version(version)
        .header("cache-control", "no-store");

    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }

    if !headers
        .keys()
        .any(|key| key.eq_ignore_ascii_case("user-agent"))
    {
        request = request.header("user-agent", DEFAULT_XHTTP_USER_AGENT);
    }

    if !headers.keys().any(|key| key.eq_ignore_ascii_case("host")) {
        if let Some(host) = host {
            request = request.header("Host", host);
        } else if matches!(http_version, XhttpHttpVersion::Http1) {
            let default_port = if use_tls { 443 } else { 80 };
            let authority = if port == default_port {
                server.to_owned()
            } else {
                format!("{server}:{port}")
            };
            request = request.header("Host", authority);
        }
    }

    for (key, value) in headers {
        request = request.header(key, value);
    }

    request.body(body).map_err(map_io_error)
}

async fn open_xhttp_logical_stream(
    client: &Client,
    sender: H2SendRequest,
    request_count: Option<Arc<AtomicU64>>,
    network_generation: Option<u64>,
) -> io::Result<AnyStream> {
    match client.effective_mode() {
        XhttpMode::StreamOne => {
            proxy_stream_one(client, sender, request_count).await
        }
        XhttpMode::StreamUp => {
            proxy_stream_up(client, sender, request_count, network_generation).await
        }
        XhttpMode::PacketUp => {
            proxy_packet_up(client, sender, request_count, network_generation).await
        }
        XhttpMode::Auto => unreachable!("effective_mode resolves auto"),
    }
}

fn leased_stream(stream: AnyStream, active: Arc<AtomicU64>) -> AnyStream {
    Box::new(ReuseLeaseStream {
        inner: stream,
        active: Some(active),
        #[cfg(feature = "xhttp-h3")]
        h3_socket: None,
    })
}

#[cfg(feature = "xhttp-h3")]
fn count_h3_request(request_count: Option<&Arc<AtomicU64>>) {
    if let Some(request_count) = request_count {
        request_count.fetch_add(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "xhttp-h3")]
async fn proxy_stream_one_h3(
    client: &Client,
    mut sender: H3SendRequest,
    request_count: Option<Arc<AtomicU64>>,
) -> io::Result<AnyStream> {
    let request = build_request_for_version(
        &client.server,
        client.port,
        &client.path,
        client.host.as_deref(),
        &client.headers,
        true,
        client.request_content_type("POST"),
        "POST",
        (),
        &client.padding,
        XhttpHttpVersion::Http3,
    )?;
    count_h3_request(request_count.as_ref());
    let request_stream = sender.send_request(request).await.map_err(|err| {
        io::Error::other(format!("xhttp HTTP/3 request failed: {err}"))
    })?;
    let (mut request_sender, mut response_receiver) = request_stream.split();
    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);

    tokio::spawn(async move {
        let mut buf = vec![0; READ_CHUNK_SIZE];
        loop {
            match transport_reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = request_sender.finish().await;
                    break;
                }
                Ok(n) => {
                    if request_sender
                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        let _sender = sender;
        let response = match response_receiver.recv_response().await {
            Ok(response) if response.status() == StatusCode::OK => response,
            Ok(response) => {
                tracing::debug!(
                    status = %response.status(),
                    "xhttp HTTP/3 returned non-success response"
                );
                let _ = transport_writer.shutdown().await;
                return;
            }
            Err(err) => {
                tracing::debug!(error = %err, "xhttp HTTP/3 response failed");
                let _ = transport_writer.shutdown().await;
                return;
            }
        };
        let _ = response;

        loop {
            match response_receiver.recv_data().await {
                Ok(Some(mut data)) => {
                    while data.has_remaining() {
                        let bytes = data.copy_to_bytes(data.remaining());
                        if transport_writer.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let _ = transport_writer.shutdown().await;
    });

    Ok(Box::new(app_stream))
}

#[cfg(feature = "xhttp-h3")]
async fn proxy_stream_up_h3(
    client: &Client,
    mut sender: H3SendRequest,
    downlink_sender: Option<H3DownlinkSender>,
    request_count: Option<Arc<AtomicU64>>,
) -> io::Result<AnyStream> {
    let session_id = client.session.generate();

    let (mut downlink_sender, downlink_active, downlink_request_count) =
        match downlink_sender {
            Some(downlink) => {
                (downlink.sender, downlink.active, downlink.request_count)
            }
            None => (sender.clone(), H3ActiveLease::none(), request_count.clone()),
        };
    let (
        downlink_server,
        downlink_port,
        downlink_base_path,
        downlink_host,
        mut downlink_headers,
    ) = if let Some(download) = client.download.as_ref() {
        (
            download.server.as_str(),
            download.port,
            download.path.as_str(),
            download.host.as_deref(),
            download.headers.clone(),
        )
    } else {
        (
            client.server.as_str(),
            client.port,
            client.path.as_str(),
            client.host.as_deref(),
            client.headers.clone(),
        )
    };
    let downlink_path = client.metadata.apply(
        downlink_base_path,
        &mut downlink_headers,
        &session_id,
        None,
    )?;
    let downlink_request = build_request_for_version(
        downlink_server,
        downlink_port,
        &downlink_path,
        downlink_host,
        &downlink_headers,
        true,
        None,
        "GET",
        (),
        &client.padding,
        XhttpHttpVersion::Http3,
    )?;
    count_h3_request(downlink_request_count.as_ref());
    let mut downlink = downlink_sender
        .send_request(downlink_request)
        .await
        .map_err(|err| {
            io::Error::other(format!("xhttp HTTP/3 downlink request failed: {err}"))
        })?;
    downlink.finish().await.map_err(|err| {
        io::Error::other(format!("xhttp HTTP/3 downlink finish failed: {err}"))
    })?;
    let response = downlink.recv_response().await.map_err(|err| {
        io::Error::other(format!("xhttp HTTP/3 downlink response failed: {err}"))
    })?;
    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected xhttp HTTP/3 response status: {}",
                response.status()
            ),
        ));
    }

    let mut upload_headers = client.headers.clone();
    let upload_path = client.metadata.apply(
        &client.path,
        &mut upload_headers,
        &session_id,
        None,
    )?;
    let upload_request = build_request_for_version(
        &client.server,
        client.port,
        &upload_path,
        client.host.as_deref(),
        &upload_headers,
        true,
        client.request_content_type("POST"),
        "POST",
        (),
        &client.padding,
        XhttpHttpVersion::Http3,
    )?;
    count_h3_request(request_count.as_ref());
    let upload = sender.send_request(upload_request).await.map_err(|err| {
        io::Error::other(format!("xhttp HTTP/3 stream-up request failed: {err}"))
    })?;
    let (mut upload_sender, mut upload_receiver) = upload.split();

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);

    tokio::spawn(async move {
        let mut buf = vec![0; READ_CHUNK_SIZE];
        loop {
            match transport_reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = upload_sender.finish().await;
                    break;
                }
                Ok(n) => {
                    if upload_sender
                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        let _sender = sender;
        match upload_receiver.recv_response().await {
            Ok(response) if response.status().is_success() => {
                while let Ok(Some(_)) = upload_receiver.recv_data().await {}
            }
            _ => {}
        }
    });

    tokio::spawn(async move {
        let _downlink_sender = downlink_sender;
        loop {
            match downlink.recv_data().await {
                Ok(Some(mut data)) => {
                    while data.has_remaining() {
                        let bytes = data.copy_to_bytes(data.remaining());
                        if transport_writer.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let _ = transport_writer.shutdown().await;
    });

    Ok(downlink_active.into_stream(Box::new(app_stream)))
}

#[cfg(feature = "xhttp-h3")]
async fn proxy_packet_up_h3(
    client: &Client,
    mut sender: H3SendRequest,
    downlink_sender: Option<H3DownlinkSender>,
    request_count: Option<Arc<AtomicU64>>,
) -> io::Result<AnyStream> {
    let session_id = client.session.generate();
    let (mut downlink_sender, downlink_active, downlink_request_count) =
        match downlink_sender {
            Some(downlink) => {
                (downlink.sender, downlink.active, downlink.request_count)
            }
            None => (sender.clone(), H3ActiveLease::none(), request_count.clone()),
        };
    let (
        downlink_server,
        downlink_port,
        downlink_base_path,
        downlink_host,
        mut downlink_headers,
    ) = if let Some(download) = client.download.as_ref() {
        (
            download.server.as_str(),
            download.port,
            download.path.as_str(),
            download.host.as_deref(),
            download.headers.clone(),
        )
    } else {
        (
            client.server.as_str(),
            client.port,
            client.path.as_str(),
            client.host.as_deref(),
            client.headers.clone(),
        )
    };
    let downlink_path = client.metadata.apply(
        downlink_base_path,
        &mut downlink_headers,
        &session_id,
        None,
    )?;
    let downlink_request = build_request_for_version(
        downlink_server,
        downlink_port,
        &downlink_path,
        downlink_host,
        &downlink_headers,
        true,
        None,
        "GET",
        (),
        &client.padding,
        XhttpHttpVersion::Http3,
    )?;
    count_h3_request(downlink_request_count.as_ref());
    let mut downlink = downlink_sender
        .send_request(downlink_request)
        .await
        .map_err(|err| {
            io::Error::other(format!("xhttp HTTP/3 downlink request failed: {err}"))
        })?;
    downlink.finish().await.map_err(|err| {
        io::Error::other(format!("xhttp HTTP/3 downlink finish failed: {err}"))
    })?;
    let response = downlink.recv_response().await.map_err(|err| {
        io::Error::other(format!("xhttp HTTP/3 downlink response failed: {err}"))
    })?;
    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected xhttp HTTP/3 response status: {}",
                response.status()
            ),
        ));
    }

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);
    let base_path = client.path.clone();
    let max_each_post_bytes = client.max_each_post_bytes;
    let server = client.server.clone();
    let port = client.port;
    let host = client.host.clone();
    let headers = client.headers.clone();
    let metadata = client.metadata.clone();
    let uplink = client.uplink.clone();
    let padding = client.padding.clone();
    let min_posts_interval_ms = client.min_posts_interval_ms;

    tokio::spawn(async move {
        let mut seq: u64 = 0;
        let mut last_write_at: Option<Instant> = None;
        let mut buf = vec![0; READ_CHUNK_SIZE];
        loop {
            match transport_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk_size = max_each_post_bytes.max(1);
                    for chunk in buf[..n].chunks(chunk_size) {
                        let mut request_headers = headers.clone();
                        let request_path = match metadata.apply(
                            &base_path,
                            &mut request_headers,
                            &session_id,
                            Some(seq),
                        ) {
                            Ok(path) => path,
                            Err(_) => return,
                        };
                        let payload =
                            uplink.apply_payload(chunk, &mut request_headers);
                        let request = match build_request_for_version(
                            &server,
                            port,
                            &request_path,
                            host.as_deref(),
                            &request_headers,
                            true,
                            uplink.content_type(),
                            uplink.method(),
                            (),
                            &padding,
                            XhttpHttpVersion::Http3,
                        ) {
                            Ok(request) => request,
                            Err(_) => return,
                        };

                        if let Some(delay) = remaining_post_interval(
                            min_posts_interval_ms,
                            last_write_at.map(|instant| instant.elapsed()),
                        ) {
                            tokio::time::sleep(delay).await;
                        }
                        last_write_at = Some(Instant::now());

                        count_h3_request(request_count.as_ref());
                        let mut upload = match sender.send_request(request).await {
                            Ok(upload) => upload,
                            Err(_) => return,
                        };
                        if !payload.is_empty()
                            && upload.send_data(payload).await.is_err()
                        {
                            return;
                        }
                        if upload.finish().await.is_err() {
                            return;
                        }
                        match upload.recv_response().await {
                            Ok(response) if response.status().is_success() => {
                                seq += 1;
                            }
                            _ => return,
                        }
                        while let Ok(Some(_)) = upload.recv_data().await {}
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        let _downlink_sender = downlink_sender;
        loop {
            match downlink.recv_data().await {
                Ok(Some(mut data)) => {
                    while data.has_remaining() {
                        let bytes = data.copy_to_bytes(data.remaining());
                        if transport_writer.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let _ = transport_writer.shutdown().await;
    });

    Ok(downlink_active.into_stream(Box::new(app_stream)))
}

#[cfg(feature = "xhttp-h3")]
fn h3_keep_alive_interval(period: Option<i64>) -> io::Result<Option<Duration>> {
    match period {
        None | Some(-1) => Ok(None),
        Some(0) => Ok(Some(Duration::from_secs(10))),
        Some(period) if period > 0 => Ok(Some(Duration::from_secs(period as u64))),
        Some(period) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "xhttp h-keep-alive-period must be -1, 0, or a positive number, got {period}"
            ),
        )),
    }
}

/// Own the freshly handshaken QUIC socket until the HTTP/3 driver takes it.
/// A cancelled future or H3 setup error must not leave a live socket that is
/// untracked by either a returned sender or its background driver.
#[cfg(feature = "xhttp-h3")]
struct PendingH3Socket {
    endpoint: Option<Endpoint>,
    connection: Option<quinn::Connection>,
}

#[cfg(feature = "xhttp-h3")]
impl PendingH3Socket {
    fn new(endpoint: Endpoint, connection: quinn::Connection) -> Self {
        Self {
            endpoint: Some(endpoint),
            connection: Some(connection),
        }
    }

    fn connection(&self) -> &quinn::Connection {
        self.connection.as_ref().expect("uncommitted HTTP/3 socket")
    }

    fn handoff(mut self) -> (Endpoint, quinn::Connection) {
        let endpoint = self
            .endpoint
            .take()
            .expect("HTTP/3 endpoint not handed off twice");
        let connection = self
            .connection
            .take()
            .expect("HTTP/3 connection not handed off twice");
        (endpoint, connection)
    }
}

#[cfg(feature = "xhttp-h3")]
impl Drop for PendingH3Socket {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(
                quinn::VarInt::from_u32(0),
                b"HTTP/3 setup cancelled before driver handoff",
            );
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(quinn::VarInt::from_u32(0), b"HTTP/3 setup cancelled");
        }
    }
}

#[cfg(feature = "xhttp-h3")]
async fn connect_h3_sender(
    endpoint_config: &XhttpEndpointConfig,
    sess: &Session,
    resolver: ThreadSafeDNSResolver,
    connector: &dyn RemoteConnector,
    keep_alive_period: Option<i64>,
    pool_context: NetworkPoolContext,
) -> io::Result<(H3SendRequest, NetworkPoolContext, Arc<H3PooledSocket>)> {
    if !matches!(endpoint_config.security, XhttpSecurity::Tls) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xhttp HTTP/3 currently supports standard TLS security only",
        ));
    }

    let tls = TlsClient::new_with_fingerprint(
        endpoint_config.skip_cert_verify,
        endpoint_config.server_name.clone(),
        Some(vec!["h3".to_owned()]),
        Some("h3".to_owned()),
        endpoint_config.fingerprint.clone(),
    )
    .with_verify_name(endpoint_config.verify_name.clone())
    .with_client_auth(
        endpoint_config.tls_cert.clone(),
        endpoint_config.tls_key.clone(),
    )?;
    let mut tls_config = tls.rustls_client_config()?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(tls_config).map_err(|err| {
        io::Error::other(format!("invalid QUIC TLS config: {err}"))
    })?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    if keep_alive_period.is_some() {
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(h3_keep_alive_interval(keep_alive_period)?);
        client_config.transport_config(Arc::new(transport));
    }

    let peer_addrs = if let Ok(ip) = endpoint_config.server.parse() {
        vec![std::net::SocketAddr::new(ip, endpoint_config.port)]
    } else {
        resolver
            .resolve_all(&endpoint_config.server, false)
            .await
            .map_err(|err| {
                io::Error::other(format!("xhttp HTTP/3 DNS failed: {err}"))
            })?
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, endpoint_config.port))
            .collect::<Vec<_>>()
    };
    if peer_addrs.is_empty() {
        return Err(io::Error::other(
            "xhttp HTTP/3 endpoint resolved no addresses",
        ));
    }

    let mut errors = Vec::new();
    for peer_addr in peer_addrs {
        let (datagram, connected_context) = match connector
            .connect_datagram_with_pool_context(
                resolver.clone(),
                None,
                SocksAddr::Ip(peer_addr),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                pool_context.clone(),
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                errors.push(format!("{peer_addr}: UDP dial failed: {err}"));
                continue;
            }
        };
        let socket = quinn_datagram::ConnectorUdpSocket::new(datagram, peer_addr);
        let mut endpoint = match Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        ) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                errors.push(format!("{peer_addr}: QUIC endpoint failed: {err}"));
                continue;
            }
        };
        endpoint.set_default_client_config(client_config.clone());
        let connecting = match endpoint
            .connect(peer_addr, &endpoint_config.server_name)
        {
            Ok(connecting) => connecting,
            Err(err) => {
                errors
                    .push(format!("{peer_addr}: QUIC connect setup failed: {err}"));
                continue;
            }
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(err) => {
                errors.push(format!("{peer_addr}: QUIC handshake failed: {err}"));
                continue;
            }
        };
        let pending = PendingH3Socket::new(endpoint, connection);
        let current_context =
            connector.connection_pool_context(sess.iface.as_ref()).await;
        if !current_context.permits(
            connected_context.network_generation,
            connected_context.path_id.as_ref(),
        ) {
            // The PendingH3Socket Drop closes both handles, even when the
            // connector supplies an unlabelled path but eligible NICs exist.
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "network path changed during HTTP/3 handshake",
            ));
        }
        let h3_connection = h3_quinn::Connection::new(pending.connection().clone());
        let (mut driver, sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_connection)
            .await
            .map_err(|err| {
                io::Error::other(format!("HTTP/3 setup failed: {err}"))
            })?;
        let (endpoint, connection) = pending.handoff();
        let socket = Arc::new(H3PooledSocket {
            endpoint,
            connection,
            active: Arc::new(AtomicU64::new(0)),
            retired: AtomicBool::new(false),
            driver_finished: AtomicBool::new(false),
        });
        let driver_socket = socket.clone();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                result = driver.wait_idle() => {
                    tracing::debug!(error = %result, "xhttp HTTP/3 driver ended");
                }
                _ = driver_socket.connection.closed() => {
                    tracing::debug!("xhttp HTTP/3 connection closed; driver stopping");
                }
            }
            // A finished driver must never be reused, even if its sender is
            // still held by an old pool entry.
            driver_socket.driver_finished.store(true, Ordering::Release);
            driver_socket.retire();
        });
        let mut connected_context = connected_context;
        connected_context.network_generation = connected_context
            .path_id
            .as_ref()
            .map(|path| path.network_generation)
            .or(connected_context.network_generation)
            .or(current_context.network_generation);
        return Ok((sender, connected_context, socket));
    }

    Err(io::Error::other(format!(
        "all xhttp HTTP/3 endpoints failed: {}",
        errors.join("; ")
    )))
}

#[cfg(feature = "xhttp-h3")]
async fn acquire_h3_upload_sender(
    client: &Client,
    endpoint_config: &XhttpEndpointConfig,
    sess: &Session,
    resolver: ThreadSafeDNSResolver,
    connector: &dyn RemoteConnector,
    pool_context: NetworkPoolContext,
) -> io::Result<H3UploadSender> {
    let Some(reuse_policy) = client.reuse_policy.as_ref() else {
        let (sender, connected_context, socket) = connect_h3_sender(
            endpoint_config,
            sess,
            resolver,
            connector,
            None,
            pool_context,
        )
        .await?;
        // The sender lease owns this QUIC connection until app-stream handoff.
        return Ok(H3UploadSender {
            sender,
            active: H3ActiveLease::unpooled(socket),
            request_count: None,
            network_path_ids: connected_context.path_id.into_iter().collect(),
        });
    };

    {
        let mut pool = client.h3_reuse_pool.lock().await;
        pool.retain(|connection| {
            !connection.retired()
                && pool_context.permits(
                    connection.network_generation,
                    connection.path_id.as_ref(),
                )
        });
        let should_open_fresh = match client.reuse_max_connections {
            Some(0) => true,
            Some(max_connections) => (pool.len() as u64) < max_connections,
            None => !pool.iter().any(ReusableH3::has_capacity),
        };
        if !should_open_fresh
            && let Some(connection) =
                pool.iter_mut().find(|connection| connection.has_capacity())
        {
            connection.reuse_count += 1;
            connection.active.fetch_add(1, Ordering::AcqRel);
            return Ok(H3UploadSender {
                sender: connection.sender.clone(),
                active: H3ActiveLease::pooled(connection.socket.clone()),
                request_count: Some(connection.request_count.clone()),
                network_path_ids: connection.path_id.clone().into_iter().collect(),
            });
        }
    }

    let (sender, connected_context, socket) = connect_h3_sender(
        endpoint_config,
        sess,
        resolver,
        connector,
        Some(reuse_policy.h_keep_alive_period),
        pool_context,
    )
    .await?;
    let registration = H3PoolRegistration(Some(socket.clone()));
    if client.reuse_max_connections == Some(0)
        || !connected_context.can_pool_connected_path()
    {
        registration.complete(); // This unpooled sender is not a pool entry.
        return Ok(H3UploadSender {
            sender,
            active: H3ActiveLease::unpooled(socket.clone()),
            request_count: None,
            network_path_ids: connected_context
                .path_id
                .clone()
                .into_iter()
                .collect(),
        });
    }

    let active = socket.active.clone();
    let request_count = Arc::new(AtomicU64::new(0));
    let mut pool = client.h3_reuse_pool.lock().await;
    socket.active.fetch_add(1, Ordering::AcqRel);
    pool.push(ReusableH3 {
        sender: sender.clone(),
        socket: socket.clone(),
        created_at: Instant::now(),
        active: active.clone(),
        reuse_count: 0,
        request_count: request_count.clone(),
        limits: reuse_policy.sample_limits(),
        network_generation: connected_context.network_generation,
        path_id: connected_context.path_id.clone(),
    });
    registration.complete();
    Ok(H3UploadSender {
        sender,
        active: H3ActiveLease::pooled(socket.clone()),
        request_count: Some(request_count),
        network_path_ids: connected_context.path_id.clone().into_iter().collect(),
    })
}

#[cfg(feature = "xhttp-h3")]
async fn acquire_h3_download_sender(
    client: &Client,
    download: &XhttpDownloadConfig,
    sess: &Session,
    resolver: ThreadSafeDNSResolver,
    connector: &dyn RemoteConnector,
    pool_context: NetworkPoolContext,
) -> io::Result<H3DownlinkSender> {
    let Some(reuse_policy) = download.reuse_policy.as_ref() else {
        let (sender, connected_context, socket) = connect_h3_sender(
            &XhttpEndpointConfig::from(download),
            sess,
            resolver,
            connector,
            None,
            pool_context,
        )
        .await?;
        // The sender lease owns this QUIC connection until app-stream handoff.
        return Ok(H3DownlinkSender {
            sender,
            active: H3ActiveLease::unpooled(socket),
            request_count: None,
            network_path_ids: connected_context.path_id.into_iter().collect(),
        });
    };

    {
        let mut pool = client.h3_download_reuse_pool.lock().await;
        pool.retain(|connection| {
            !connection.retired()
                && pool_context.permits(
                    connection.network_generation,
                    connection.path_id.as_ref(),
                )
        });
        let should_open_fresh = match client.download_reuse_max_connections {
            Some(0) => true,
            Some(max_connections) => (pool.len() as u64) < max_connections,
            None => !pool.iter().any(ReusableH3::has_capacity),
        };

        if !should_open_fresh
            && let Some(connection) =
                pool.iter_mut().find(|connection| connection.has_capacity())
        {
            connection.reuse_count += 1;
            connection.active.fetch_add(1, Ordering::AcqRel);
            return Ok(H3DownlinkSender {
                sender: connection.sender.clone(),
                active: H3ActiveLease::pooled(connection.socket.clone()),
                request_count: Some(connection.request_count.clone()),
                network_path_ids: connection.path_id.clone().into_iter().collect(),
            });
        }
    }

    let (sender, connected_context, socket) = connect_h3_sender(
        &XhttpEndpointConfig::from(download),
        sess,
        resolver,
        connector,
        Some(reuse_policy.h_keep_alive_period),
        pool_context,
    )
    .await?;
    let registration = H3PoolRegistration(Some(socket.clone()));
    if client.download_reuse_max_connections == Some(0)
        || !connected_context.can_pool_connected_path()
    {
        registration.complete(); // This unpooled sender is not a pool entry.
        return Ok(H3DownlinkSender {
            sender,
            active: H3ActiveLease::unpooled(socket.clone()),
            request_count: None,
            network_path_ids: connected_context
                .path_id
                .clone()
                .into_iter()
                .collect(),
        });
    }

    let active = socket.active.clone();
    let request_count = Arc::new(AtomicU64::new(0));
    let mut pool = client.h3_download_reuse_pool.lock().await;
    socket.active.fetch_add(1, Ordering::AcqRel);
    pool.push(ReusableH3 {
        sender: sender.clone(),
        socket: socket.clone(),
        created_at: Instant::now(),
        active: active.clone(),
        reuse_count: 0,
        request_count: request_count.clone(),
        limits: reuse_policy.sample_limits(),
        network_generation: connected_context.network_generation,
        path_id: connected_context.path_id.clone(),
    });
    registration.complete();
    Ok(H3DownlinkSender {
        sender,
        active: H3ActiveLease::pooled(socket.clone()),
        request_count: Some(request_count),
        network_path_ids: connected_context.path_id.clone().into_iter().collect(),
    })
}

#[cfg(feature = "xhttp-h3")]
async fn open_h3_logical_stream(
    client: &Client,
    sender: H3SendRequest,
    downlink_sender: Option<H3DownlinkSender>,
    request_count: Option<Arc<AtomicU64>>,
) -> io::Result<AnyStream> {
    match client.effective_mode() {
        XhttpMode::StreamOne => {
            proxy_stream_one_h3(client, sender, request_count).await
        }
        XhttpMode::PacketUp => {
            proxy_packet_up_h3(client, sender, downlink_sender, request_count).await
        }
        XhttpMode::StreamUp => {
            proxy_stream_up_h3(client, sender, downlink_sender, request_count).await
        }
        XhttpMode::Auto => unreachable!("effective_mode resolves auto"),
    }
}

#[cfg(feature = "xhttp-h3")]
async fn try_reuse_h3_stream(
    client: &Client,
    pool_context: NetworkPoolContext,
) -> io::Result<Option<(AnyStream, NetworkPoolContext)>> {
    if client.reuse_policy.is_none() || client.download.is_some() {
        return Ok(None);
    }

    let selected = {
        let mut pool = client.h3_reuse_pool.lock().await;
        pool.retain(|connection| {
            !connection.retired()
                && pool_context.permits(
                    connection.network_generation,
                    connection.path_id.as_ref(),
                )
        });

        if let Some(max_connections) = client.reuse_max_connections
            && (max_connections == 0 || (pool.len() as u64) < max_connections)
        {
            return Ok(None);
        }

        let Some(connection) =
            pool.iter_mut().find(|connection| connection.has_capacity())
        else {
            return Ok(None);
        };
        connection.reuse_count += 1;
        connection.active.fetch_add(1, Ordering::AcqRel);
        Some((
            connection.sender.clone(),
            connection.socket.clone(),
            connection.request_count.clone(),
            connection.network_generation,
            connection.path_id.clone(),
        ))
    };

    let Some((sender, socket, request_count, network_generation, path_id)) =
        selected
    else {
        return Ok(None);
    };
    let reservation = H3ActiveLease::pooled(socket);
    match open_h3_logical_stream(client, sender, None, Some(request_count)).await {
        Ok(stream) => {
            let stream = reservation.into_stream(stream);
            Ok(Some((
                stream,
                NetworkPoolContext {
                    network_generation,
                    path_id,
                    ..pool_context
                },
            )))
        }
        Err(err) => {
            // Reservation releases the counter, including on cancellation.
            client.h3_reuse_pool.lock().await.clear();
            Err(err)
        }
    }
}

#[cfg(feature = "xhttp-h3")]
async fn connect_h3_stream(
    client: &Client,
    sess: &Session,
    resolver: ThreadSafeDNSResolver,
    connector: &dyn RemoteConnector,
) -> io::Result<(AnyStream, Vec<crate::app::flow::NetworkPathId>)> {
    let pool_context = connector.connection_pool_context(sess.iface.as_ref()).await;
    for pool in [&client.h3_reuse_pool, &client.h3_download_reuse_pool] {
        pool.lock().await.retain(|connection| {
            !connection.retired()
                && pool_context.permits(
                    connection.network_generation,
                    connection.path_id.as_ref(),
                )
        });
    }
    let endpoint_config = client.upload_endpoint.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "xhttp HTTP/3 requires transport-owned TLS endpoint security",
        )
    })?;
    let upload = acquire_h3_upload_sender(
        client,
        endpoint_config,
        sess,
        resolver.clone(),
        connector,
        pool_context.clone(),
    )
    .await?;
    let mut network_path_ids = upload.network_path_ids.clone();
    let downlink_sender = if let Some(download) = client.download.as_ref() {
        let downlink = acquire_h3_download_sender(
            client,
            download,
            sess,
            resolver,
            connector,
            pool_context,
        )
        .await?;
        for path_id in &downlink.network_path_ids {
            if !network_path_ids.contains(path_id) {
                network_path_ids.push(path_id.clone());
            }
        }
        Some(downlink)
    } else {
        None
    };

    let logical = match open_h3_logical_stream(
        client,
        upload.sender,
        downlink_sender,
        upload.request_count,
    )
    .await
    {
        Ok(logical) => logical,
        Err(err) => {
            // Upload/downlink sender leases release their own reservations,
            // even when cancelled before the error branch can execute.
            if upload.active.active.is_some() {
                client.h3_reuse_pool.lock().await.clear();
            }
            return Err(err);
        }
    };
    let stream = upload.active.into_stream(logical);
    Ok((stream, network_path_ids))
}

#[async_trait]
impl Transport for Client {
    async fn reset_connection_pool(&self) -> io::Result<u32> {
        let mut cancellation = self.recovery_cancellation.lock().await;
        cancellation.cancel();
        let _recovery = self.recovery_gate.write().await;
        let mut count = 0_u32;
        for pool in [&self.reuse_pool, &self.download_reuse_pool] {
            let mut pool = pool.lock().await;
            count = count.saturating_add(pool.len().min(u32::MAX as usize) as u32);
            pool.clear();
        }
        #[cfg(feature = "xhttp-h3")]
        for pool in [&self.h3_reuse_pool, &self.h3_download_reuse_pool] {
            let mut pool = pool.lock().await;
            count = count.saturating_add(pool.len().min(u32::MAX as usize) as u32);
            pool.clear();
        }
        *cancellation = tokio_util::sync::CancellationToken::new();
        Ok(count)
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &crate::session::Session,
        resolver: crate::app::dns::ThreadSafeDNSResolver,
        connector: &dyn crate::proxy::utils::RemoteConnector,
    ) -> io::Result<Option<AnyStream>> {
        Ok(self
            .connect_stream_with_connector_and_path_ids(sess, resolver, connector)
            .await?
            .map(|(stream, _)| stream))
    }

    async fn connect_stream_with_connector_and_path_ids(
        &self,
        sess: &crate::session::Session,
        resolver: crate::app::dns::ThreadSafeDNSResolver,
        connector: &dyn crate::proxy::utils::RemoteConnector,
    ) -> io::Result<Option<(AnyStream, Vec<crate::app::flow::NetworkPathId>)>> {
        let cancellation = self.recovery_cancellation.lock().await.clone();
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "network changed during transport construction")),
            result = async {
                let _recovery = self.recovery_gate.read().await;
                if !matches!(self.http_version, XhttpHttpVersion::Http3) {
                    return Ok(None);
                }
                #[cfg(feature = "xhttp-h3")]
                {
                    return connect_h3_stream(self, sess, resolver, connector)
                        .await
                        .map(Some);
                }
                #[cfg(not(feature = "xhttp-h3"))]
                {
                    let _ = sess;
                    let _ = resolver;
                    let _ = connector;
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "xhttp HTTP/3 requires xhttp-h3 feature",
                    ))
                }
            } => result,
        };
        super::finish_pool_delivery(&cancellation, outcome)
    }

    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        self.proxy_stream_for_network_generation(stream, None).await
    }

    async fn proxy_stream_for_network_generation(
        &self,
        stream: AnyStream,
        network_generation: Option<u64>,
    ) -> io::Result<AnyStream> {
        self.proxy_stream_with_pool_context(
            stream,
            NetworkPoolContext::for_generation(network_generation),
        )
        .await
    }

    async fn proxy_stream_with_pool_context(
        &self,
        stream: AnyStream,
        pool_context: NetworkPoolContext,
    ) -> io::Result<AnyStream> {
        let network_generation = pool_context.network_generation;
        let cancellation = self.recovery_cancellation.lock().await.clone();
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "network changed during transport construction")),
            result = async {
                let _recovery = self.recovery_gate.read().await;
                if matches!(self.http_version, XhttpHttpVersion::Http3) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "xhttp HTTP/3 must use the transport-owned QUIC dial path",
                    ));
                }
                if matches!(self.http_version, XhttpHttpVersion::Http1) {
                    if self.reuse_policy.is_some()
                        || self
                            .download
                            .as_ref()
                            .and_then(|download| download.reuse_policy.as_ref())
                            .is_some()
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "xhttp HTTP/1.1 currently does not support reuse settings",
                        ));
                    }
                    if !matches!(self.effective_mode(), XhttpMode::PacketUp) {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "xhttp HTTP/1.1 currently supports only packet-up mode",
                        ));
                    }
                    let stream = if let Some(endpoint) = self.upload_endpoint.as_ref() {
                        secure_endpoint_stream(endpoint, stream).await?
                    } else {
                        stream
                    };
                    return proxy_packet_up_http1(self, stream).await;
                }

                let stream = if let Some(endpoint) = self.upload_endpoint.as_ref() {
                    secure_endpoint_stream(endpoint, stream).await?
                } else {
                    stream
                };
                let sender = handshake_http2(
                    stream,
                    self.reuse_policy
                        .as_ref()
                        .map(|policy| policy.h_keep_alive_period),
                )
                .await?;

                let Some(reuse_policy) = self.reuse_policy.as_ref() else {
                    return open_xhttp_logical_stream(
                        self,
                        sender,
                        None,
                        network_generation,
                    )
                    .await;
                };

                let request_count = Arc::new(AtomicU64::new(0));
                let logical = open_xhttp_logical_stream(
                    self,
                    sender.clone(),
                    Some(request_count.clone()),
                    network_generation,
                )
                .await?;

                if self.reuse_max_connections == Some(0)
                    || !pool_context.can_pool_connected_path()
                {
                    return Ok(logical);
                }

                let active = Arc::new(AtomicU64::new(1));
                self.reuse_pool.lock().await.push(ReusableH2 {
                    sender,
                    created_at: Instant::now(),
                    active: active.clone(),
                    reuse_count: 0,
                    request_count,
                    limits: reuse_policy.sample_limits(),
                    network_generation,
                    path_id: pool_context.path_id.clone(),
                });

                Ok(leased_stream(logical, active))
            } => result,
        };
        super::finish_pool_delivery(&cancellation, outcome)
    }

    async fn try_reuse_stream(&self) -> io::Result<Option<AnyStream>> {
        self.try_reuse_stream_for_network_generation(None).await
    }

    async fn try_reuse_stream_for_network_generation(
        &self,
        network_generation: Option<u64>,
    ) -> io::Result<Option<AnyStream>> {
        self.try_reuse_stream_with_pool_context(NetworkPoolContext::for_generation(
            network_generation,
        ))
        .await
    }

    async fn try_reuse_stream_with_pool_context(
        &self,
        pool_context: NetworkPoolContext,
    ) -> io::Result<Option<AnyStream>> {
        Ok(self
            .try_reuse_stream_with_pool_metadata(pool_context)
            .await?
            .map(|(stream, _)| stream))
    }

    async fn try_reuse_stream_with_pool_metadata(
        &self,
        pool_context: NetworkPoolContext,
    ) -> io::Result<Option<(AnyStream, NetworkPoolContext)>> {
        let network_generation = pool_context.network_generation;
        let cancellation = self.recovery_cancellation.lock().await.clone();
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "network changed during transport construction")),
            result = async {
                let _recovery = self.recovery_gate.read().await;
                if self.reuse_policy.is_none() {
                    return Ok(None);
                }
                if matches!(self.http_version, XhttpHttpVersion::Http1) {
                    return Ok(None);
                }
                if matches!(self.http_version, XhttpHttpVersion::Http3) {
                    #[cfg(feature = "xhttp-h3")]
                    {
                        return try_reuse_h3_stream(self, pool_context).await;
                    }
                    #[cfg(not(feature = "xhttp-h3"))]
                    {
                        return Ok(None);
                    }
                }

                let selected = {
                    let mut pool = self.reuse_pool.lock().await;
                    pool.retain(|connection| {
                        !connection.retired()
                            && pool_context.permits(
                                connection.network_generation,
                                connection.path_id.as_ref(),
                            )
                    });

                    if let Some(max_connections) = self.reuse_max_connections
                        && (max_connections == 0 || (pool.len() as u64) < max_connections)
                    {
                        return Ok(None);
                    }

                    let Some(connection) =
                        pool.iter_mut().find(|connection| connection.has_capacity())
                    else {
                        return Ok(None);
                    };

                    connection.reuse_count += 1;
                    connection.active.fetch_add(1, Ordering::AcqRel);
                    Some((
                        connection.sender.clone(),
                        connection.active.clone(),
                        connection.request_count.clone(),
                        connection.network_generation,
                        connection.path_id.clone(),
                    ))
                };

                let Some((sender, active, request_count, stored_generation, path_id)) =
                    selected
                else {
                    return Ok(None);
                };

                let reservation = super::PoolActiveReservation::new(active.clone());
                match open_xhttp_logical_stream(
                    self,
                    sender,
                    Some(request_count),
                    network_generation,
                )
                .await
                {
                    Ok(stream) => {
                        let stream = leased_stream(stream, active);
                        reservation.transfer();
                        let mut connected_context = pool_context;
                        connected_context.network_generation = stored_generation;
                        connected_context.path_id = path_id;
                        Ok(Some((stream, connected_context)))
                    }
                    Err(err) => Err(err)
                }
            } => result,
        };
        super::finish_pool_delivery(&cancellation, outcome)
    }
}

async fn proxy_stream_one(
    client: &Client,
    mut sender: H2SendRequest,
    request_count: Option<Arc<AtomicU64>>,
) -> io::Result<AnyStream> {
    let (tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Infallible>>(FRAME_CHANNEL_CAPACITY);
    let request_body = StreamBody::new(ReceiverStream::new(rx)).boxed();
    let request = client.request("POST", &client.path, request_body)?;
    let response = validate_response_status(
        send_h2_request(&mut sender, request, request_count.as_ref()).await?,
    )?;

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);

    tokio::spawn(async move {
        let mut buf = vec![0; READ_CHUNK_SIZE];
        loop {
            match transport_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..n]))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        forward_response_body(response, &mut transport_writer).await;
        let _ = transport_writer.shutdown().await;
    });

    Ok(Box::new(app_stream))
}

async fn proxy_stream_up(
    client: &Client,
    mut sender: H2SendRequest,
    request_count: Option<Arc<AtomicU64>>,
    network_generation: Option<u64>,
) -> io::Result<AnyStream> {
    let session_id = client.session.generate();
    let (response, downlink_active) = open_downlink_response(
        client,
        &mut sender,
        &session_id,
        request_count.as_ref(),
        network_generation,
    )
    .await?;

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);
    let base_path = client.path.clone();
    let server = client.server.clone();
    let port = client.port;
    let host = client.host.clone();
    let headers = client.headers.clone();
    let metadata = client.metadata.clone();
    let padding = client.padding.clone();
    let use_tls = client.use_tls;
    let content_type = client.request_content_type("POST");
    let request_count_for_uplink = request_count.clone();

    tokio::spawn(async move {
        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(
            FRAME_CHANNEL_CAPACITY,
        );
        let mut request_headers = headers.clone();
        let request_path = match metadata.apply(
            &base_path,
            &mut request_headers,
            &session_id,
            None,
        ) {
            Ok(path) => path,
            Err(_) => return,
        };
        let request_body = StreamBody::new(ReceiverStream::new(rx)).boxed();
        let request = match build_request(
            &server,
            port,
            &request_path,
            host.as_deref(),
            &request_headers,
            use_tls,
            content_type,
            "POST",
            request_body,
            &padding,
        ) {
            Ok(request) => request,
            Err(_) => return,
        };

        tokio::spawn(async move {
            let mut buf = vec![0; READ_CHUNK_SIZE];
            loop {
                match transport_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx
                            .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..n]))))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        match send_h2_request(
            &mut sender,
            request,
            request_count_for_uplink.as_ref(),
        )
        .await
        {
            Ok(response) if response.status().is_success() => {}
            _ => {}
        }
    });

    tokio::spawn(async move {
        forward_response_body(response, &mut transport_writer).await;
        let _ = transport_writer.shutdown().await;
        if let Some(active) = downlink_active {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    });

    Ok(Box::new(app_stream))
}

async fn proxy_packet_up_http1(
    client: &Client,
    stream: AnyStream,
) -> io::Result<AnyStream> {
    let session_id = client.session.generate();
    let mut initial_upload_stream = Some(stream);

    let response = if let Some(download) = client.download.as_ref() {
        let mut downlink_headers = download.headers.clone();
        let downlink_path = client.metadata.apply(
            &download.path,
            &mut downlink_headers,
            &session_id,
            None,
        )?;
        let downlink_request = build_request_for_version(
            &download.server,
            download.port,
            &downlink_path,
            download.host.as_deref(),
            &downlink_headers,
            matches!(
                download.security,
                XhttpSecurity::Tls | XhttpSecurity::Reality
            ),
            None,
            "GET",
            http_body_util::Empty::<Bytes>::new().boxed(),
            &client.padding,
            XhttpHttpVersion::Http1,
        )?;
        let downlink_stream =
            connect_endpoint_stream(&XhttpEndpointConfig::from(download)).await?;
        let mut downlink_sender = handshake_http1(downlink_stream).await?;
        downlink_sender
            .send_request(downlink_request)
            .await
            .map_err(map_io_error)
            .and_then(validate_response_status)?
    } else {
        let mut downlink_headers = client.headers.clone();
        let downlink_path = client.metadata.apply(
            &client.path,
            &mut downlink_headers,
            &session_id,
            None,
        )?;
        let downlink_request = build_request_for_version(
            &client.server,
            client.port,
            &downlink_path,
            client.host.as_deref(),
            &downlink_headers,
            client.use_tls,
            None,
            "GET",
            http_body_util::Empty::<Bytes>::new().boxed(),
            &client.padding,
            XhttpHttpVersion::Http1,
        )?;
        let initial_stream = initial_upload_stream.take().ok_or_else(|| {
            io::Error::other("initial HTTP/1.1 stream is unavailable")
        })?;
        let mut downlink_sender = handshake_http1(initial_stream).await?;
        downlink_sender
            .send_request(downlink_request)
            .await
            .map_err(map_io_error)
            .and_then(validate_response_status)?
    };

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);

    let base_path = client.path.clone();
    let max_each_post_bytes = client.max_each_post_bytes;
    let server = client.server.clone();
    let port = client.port;
    let host = client.host.clone();
    let headers = client.headers.clone();
    let metadata = client.metadata.clone();
    let uplink = client.uplink.clone();
    let padding = client.padding.clone();
    let min_posts_interval_ms = client.min_posts_interval_ms;
    let upload_endpoint = client.upload_endpoint.clone();
    let use_tls = client.use_tls;

    tokio::spawn(async move {
        let mut seq: u64 = 0;
        let mut last_write_at: Option<Instant> = None;
        let mut initial_upload_stream = initial_upload_stream;
        let mut buf = vec![0; READ_CHUNK_SIZE];

        loop {
            match transport_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk_size = max_each_post_bytes.max(1);
                    for chunk in buf[..n].chunks(chunk_size) {
                        let mut request_headers = headers.clone();
                        let request_path = match metadata.apply(
                            &base_path,
                            &mut request_headers,
                            &session_id,
                            Some(seq),
                        ) {
                            Ok(path) => path,
                            Err(_) => return,
                        };
                        let body = Full::new(
                            uplink.apply_payload(chunk, &mut request_headers),
                        )
                        .boxed();
                        let request = match build_request_for_version(
                            &server,
                            port,
                            &request_path,
                            host.as_deref(),
                            &request_headers,
                            use_tls,
                            uplink.content_type(),
                            uplink.method(),
                            body,
                            &padding,
                            XhttpHttpVersion::Http1,
                        ) {
                            Ok(request) => request,
                            Err(_) => return,
                        };

                        if let Some(delay) = remaining_post_interval(
                            min_posts_interval_ms,
                            last_write_at.map(|instant| instant.elapsed()),
                        ) {
                            tokio::time::sleep(delay).await;
                        }
                        last_write_at = Some(Instant::now());

                        let upload_stream = if let Some(stream) =
                            initial_upload_stream.take()
                        {
                            stream
                        } else {
                            match upload_endpoint.as_ref() {
                                Some(endpoint) => {
                                    match connect_endpoint_stream(endpoint).await {
                                        Ok(stream) => stream,
                                        Err(_) => return,
                                    }
                                }
                                None => {
                                    match connect_plain_stream(&server, port).await {
                                        Ok(stream) => stream,
                                        Err(_) => return,
                                    }
                                }
                            }
                        };
                        let mut sender = match handshake_http1(upload_stream).await {
                            Ok(sender) => sender,
                            Err(_) => return,
                        };
                        match sender.send_request(request).await {
                            Ok(response) if response.status().is_success() => {
                                seq += 1;
                            }
                            _ => return,
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        forward_response_body(response, &mut transport_writer).await;
        let _ = transport_writer.shutdown().await;
    });

    Ok(Box::new(app_stream))
}

fn remaining_post_interval(
    interval_ms: Option<u64>,
    elapsed_since_last_write: Option<Duration>,
) -> Option<Duration> {
    let interval = Duration::from_millis(interval_ms?);
    let elapsed = elapsed_since_last_write?;
    (elapsed < interval).then(|| interval - elapsed)
}

async fn proxy_packet_up(
    client: &Client,
    mut sender: H2SendRequest,
    request_count: Option<Arc<AtomicU64>>,
    network_generation: Option<u64>,
) -> io::Result<AnyStream> {
    let session_id = client.session.generate();
    let (response, downlink_active) = open_downlink_response(
        client,
        &mut sender,
        &session_id,
        request_count.as_ref(),
        network_generation,
    )
    .await?;

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);
    let base_path = client.path.clone();
    let max_each_post_bytes = client.max_each_post_bytes;
    let server = client.server.clone();
    let port = client.port;
    let host = client.host.clone();
    let headers = client.headers.clone();
    let metadata = client.metadata.clone();
    let uplink = client.uplink.clone();
    let padding = client.padding.clone();
    let use_tls = client.use_tls;
    let min_posts_interval_ms = client.min_posts_interval_ms;
    let request_count_for_uplink = request_count.clone();

    tokio::spawn(async move {
        let mut seq: u64 = 0;
        let mut last_write_at: Option<Instant> = None;
        let mut buf = vec![0; READ_CHUNK_SIZE];
        loop {
            match transport_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk_size = max_each_post_bytes.max(1);
                    for chunk in buf[..n].chunks(chunk_size) {
                        let mut request_headers = headers.clone();
                        let request_path = match metadata.apply(
                            &base_path,
                            &mut request_headers,
                            &session_id,
                            Some(seq),
                        ) {
                            Ok(path) => path,
                            Err(_) => return,
                        };
                        let body = Full::new(
                            uplink.apply_payload(chunk, &mut request_headers),
                        )
                        .boxed();
                        let request = match build_request(
                            &server,
                            port,
                            &request_path,
                            host.as_deref(),
                            &request_headers,
                            use_tls,
                            uplink.content_type(),
                            uplink.method(),
                            body,
                            &padding,
                        ) {
                            Ok(request) => request,
                            Err(_) => return,
                        };

                        if let Some(delay) = remaining_post_interval(
                            min_posts_interval_ms,
                            last_write_at.map(|instant| instant.elapsed()),
                        ) {
                            tokio::time::sleep(delay).await;
                        }
                        last_write_at = Some(Instant::now());

                        match send_h2_request(
                            &mut sender,
                            request,
                            request_count_for_uplink.as_ref(),
                        )
                        .await
                        {
                            Ok(response) if response.status().is_success() => {
                                seq += 1;
                            }
                            _ => return,
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        forward_response_body(response, &mut transport_writer).await;
        let _ = transport_writer.shutdown().await;
        if let Some(active) = downlink_active {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    });

    Ok(Box::new(app_stream))
}

async fn forward_response_body(
    mut body: Incoming,
    writer: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
) {
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Some(data) = frame.data_ref()
                    && writer.write_all(data).await.is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests;
