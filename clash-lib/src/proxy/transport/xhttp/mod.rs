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

use async_trait::async_trait;
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
use crate::{
    common::errors::map_io_error,
    proxy::{AnyStream, utils::new_protected_tcp_stream},
};

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

struct ReuseLeaseStream {
    inner: AnyStream,
    active: Arc<AtomicU64>,
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
        self.active.fetch_sub(1, Ordering::AcqRel);
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
    reuse_pool: Mutex<Vec<ReusableH2>>,
    download_reuse_max_connections: Option<u64>,
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
            reuse_pool: Mutex::new(Vec::new()),
            download_reuse_max_connections,
            download_reuse_pool: Mutex::new(Vec::new()),
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
                );
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
    pool.retain(|connection| !connection.retired());

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
    });

    Ok((sender, Some(active), Some(request_count)))
}

async fn open_separate_downlink_response(
    client: &Client,
    download: &XhttpDownloadConfig,
    session_id: &str,
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
        acquire_download_sender(client, download).await?;
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
) -> io::Result<(Incoming, Option<Arc<AtomicU64>>)> {
    if let Some(download) = client.download.as_ref() {
        open_separate_downlink_response(client, download, session_id).await
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
fn build_request_for_version(
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
    http_version: XhttpHttpVersion,
) -> io::Result<Request<BoxBody<Bytes, Infallible>>> {
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
        XhttpHttpVersion::Http2 => uri,
    };
    let version = match http_version {
        XhttpHttpVersion::Http1 => Version::HTTP_11,
        XhttpHttpVersion::Http2 => Version::HTTP_2,
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
) -> io::Result<AnyStream> {
    match client.effective_mode() {
        XhttpMode::StreamOne => {
            proxy_stream_one(client, sender, request_count).await
        }
        XhttpMode::StreamUp => proxy_stream_up(client, sender, request_count).await,
        XhttpMode::PacketUp => proxy_packet_up(client, sender, request_count).await,
        XhttpMode::Auto => unreachable!("effective_mode resolves auto"),
    }
}

fn leased_stream(stream: AnyStream, active: Arc<AtomicU64>) -> AnyStream {
    Box::new(ReuseLeaseStream {
        inner: stream,
        active,
    })
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
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
            return open_xhttp_logical_stream(self, sender, None).await;
        };

        let request_count = Arc::new(AtomicU64::new(0));
        let logical = open_xhttp_logical_stream(
            self,
            sender.clone(),
            Some(request_count.clone()),
        )
        .await?;

        if self.reuse_max_connections == Some(0) {
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
        });

        Ok(leased_stream(logical, active))
    }

    async fn try_reuse_stream(&self) -> io::Result<Option<AnyStream>> {
        if matches!(self.http_version, XhttpHttpVersion::Http1)
            || self.reuse_policy.is_none()
        {
            return Ok(None);
        }

        let selected = {
            let mut pool = self.reuse_pool.lock().await;
            pool.retain(|connection| !connection.retired());

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
            ))
        };

        let Some((sender, active, request_count)) = selected else {
            return Ok(None);
        };

        match open_xhttp_logical_stream(self, sender, Some(request_count)).await {
            Ok(stream) => Ok(Some(leased_stream(stream, active))),
            Err(err) => {
                active.fetch_sub(1, Ordering::AcqRel);
                Err(err)
            }
        }
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
) -> io::Result<AnyStream> {
    let session_id = client.session.generate();
    let (response, downlink_active) = open_downlink_response(
        client,
        &mut sender,
        &session_id,
        request_count.as_ref(),
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
) -> io::Result<AnyStream> {
    let session_id = client.session.generate();
    let (response, downlink_active) = open_downlink_response(
        client,
        &mut sender,
        &session_id,
        request_count.as_ref(),
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
mod tests {
    use super::{
        Client, MetadataPlacement, UplinkDataPlacement, XhttpChunkSizeRange,
        XhttpDownloadConfig, XhttpEndpointConfig, XhttpHttpVersion,
        XhttpMetadataConfig, XhttpMode, XhttpPaddingConfig, XhttpReusePolicy,
        XhttpReuseValueRange, XhttpSecurity, XhttpUplinkConfig, build_request,
        connect_download_stream, open_separate_downlink_response,
        remaining_post_interval,
    };
    use crate::{
        common::utils::{encode_hex, sha256},
        proxy::transport::Transport,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use bytes::Bytes;
    use http::{Method, Request, Response, StatusCode, Version};
    use http_body_util::{BodyExt, Empty, StreamBody, combinators::BoxBody};
    use hyper::body::{Frame, Incoming};
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        server::conn::auto,
    };
    use std::convert::Infallible;
    use std::{collections::HashMap, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex, mpsc},
        time::{Duration, timeout},
    };
    use tokio_rustls::TlsAcceptor;
    use tokio_stream::wrappers::ReceiverStream;

    type TestSessions =
        Arc<Mutex<HashMap<String, mpsc::Sender<Result<Frame<Bytes>, Infallible>>>>>;

    fn auto_client(
        auto_reality: bool,
        download: Option<XhttpDownloadConfig>,
    ) -> Client {
        Client::new(
            "example.com".to_owned(),
            443,
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            true,
            XhttpMode::Auto,
            1_000_000,
            false,
            None,
            download,
        )
        .with_auto_reality(auto_reality)
    }

    async fn spawn_tls_h2_download_server() -> (std::net::SocketAddr, String) {
        crate::setup_default_crypto_provider();

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![
                "download.example.com".to_owned(),
            ])
            .expect("test certificate should generate");
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let fingerprint = encode_hex(&sha256(cert_der.as_ref()));
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
                .expect("test private key should serialize");

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("test TLS config should build");
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test TLS listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            let (tcp, _) =
                listener.accept().await.expect("TLS accept should succeed");
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let io = TokioIo::new(tls);
            let service =
                hyper::service::service_fn(|req: Request<Incoming>| async move {
                    assert_eq!(req.method(), Method::GET);
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Empty::<Bytes>::new().boxed())
                            .expect("response should build"),
                    )
                });
            let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
            builder
                .serve_connection(io, service)
                .await
                .expect("TLS H2 server connection should succeed");
        });

        (addr, fingerprint)
    }

    async fn spawn_tls_h1_xhttp_server(
        sessions: TestSessions,
    ) -> std::net::SocketAddr {
        crate::setup_default_crypto_provider();

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["xhttp.example.com".to_owned()])
                .expect("test certificate should generate");
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
                .expect("test private key should serialize");
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("test TLS config should build");
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test TLS listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let io = TokioIo::new(tls);
                    let service = hyper::service::service_fn(move |req| {
                        let sessions = sessions.clone();
                        async move {
                            assert_eq!(req.version(), Version::HTTP_11);
                            handle_split_modes(req, sessions).await
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        addr
    }

    fn pinned_tls_download(
        addr: std::net::SocketAddr,
        fingerprint: String,
    ) -> XhttpDownloadConfig {
        XhttpDownloadConfig {
            server: addr.ip().to_string(),
            port: addr.port(),
            path: "/xhttp/".to_owned(),
            host: None,
            headers: HashMap::new(),
            security: XhttpSecurity::Tls,
            server_name: "download.example.com".to_owned(),
            alpn_protocols: vec!["h2".to_owned()],
            skip_cert_verify: true,
            fingerprint: Some(fingerprint),
            verify_name: None,
            tls_cert: None,
            tls_key: None,
            reality: None,
            reuse_policy: None,
        }
    }

    #[tokio::test]
    async fn xhttp_upload_endpoint_secures_connector_owned_stream() {
        let (addr, fingerprint) = spawn_tls_h2_download_server().await;
        let endpoint =
            XhttpEndpointConfig::from(&pinned_tls_download(addr, fingerprint));
        let client = Client::new(
            addr.ip().to_string(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            true,
            XhttpMode::StreamUp,
            1_000_000,
            false,
            None,
            None,
        )
        .with_upload_endpoint(Some(endpoint));

        let raw = TcpStream::connect(addr)
            .await
            .expect("connector-owned raw TCP should connect");
        let logical = client
            .proxy_stream(Box::new(raw))
            .await
            .expect("xhttp should apply upload TLS before H2");

        drop(logical);
    }

    #[tokio::test]
    async fn xhttp_download_tls_uses_certificate_fingerprint_pin() {
        let (addr, fingerprint) = spawn_tls_h2_download_server().await;
        let download = pinned_tls_download(addr, fingerprint);

        let stream = connect_download_stream(&download)
            .await
            .expect("matching certificate fingerprint should complete TLS");
        let _sender = super::handshake_http2(stream, None)
            .await
            .expect("download TLS stream should negotiate h2");
    }

    #[tokio::test]
    async fn xhttp_download_tls_rejects_wrong_certificate_fingerprint() {
        let (addr, _fingerprint) = spawn_tls_h2_download_server().await;
        let download = pinned_tls_download(addr, "00".repeat(32));

        let err = match connect_download_stream(&download).await {
            Ok(_) => panic!("wrong certificate fingerprint must fail TLS"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("cert hash mismatch")
                || err.to_string().contains("certificate"),
            "unexpected TLS pinning error: {err}"
        );
    }

    #[test]
    fn xhttp_auto_reality_resolves_to_stream_one() {
        let client = auto_client(true, None);
        assert_eq!(client.effective_mode(), XhttpMode::StreamOne);
    }

    #[test]
    fn xhttp_auto_h2_resolves_to_stream_up() {
        let client = auto_client(false, None);
        assert_eq!(client.effective_mode(), XhttpMode::StreamUp);
    }

    #[test]
    fn xhttp_auto_with_separate_download_resolves_to_stream_up() {
        let download = XhttpDownloadConfig {
            server: "download.example.com".to_owned(),
            port: 443,
            path: "/xhttp/".to_owned(),
            host: None,
            headers: HashMap::new(),
            security: XhttpSecurity::Tls,
            server_name: "download.example.com".to_owned(),
            alpn_protocols: vec!["h2".to_owned()],
            skip_cert_verify: false,
            fingerprint: None,
            verify_name: None,
            tls_cert: None,
            tls_key: None,
            reality: None,
            reuse_policy: None,
        };
        let client = auto_client(true, Some(download));
        assert_eq!(client.effective_mode(), XhttpMode::StreamUp);
    }

    #[test]
    fn xhttp_post_interval_only_sleeps_for_remaining_time() {
        assert_eq!(
            remaining_post_interval(Some(30), None),
            None,
            "first post should not be delayed"
        );
        assert_eq!(
            remaining_post_interval(Some(30), Some(Duration::from_millis(10)),),
            Some(Duration::from_millis(20))
        );
        assert_eq!(
            remaining_post_interval(Some(30), Some(Duration::from_millis(30)),),
            None
        );
        assert_eq!(
            remaining_post_interval(Some(30), Some(Duration::from_millis(45)),),
            None
        );
    }

    #[test]
    fn xhttp_request_adds_default_padding_referer() {
        let request = build_request(
            "127.0.0.1",
            8080,
            "/xhttp/",
            None,
            &HashMap::new(),
            false,
            None,
            "GET",
            Empty::<Bytes>::new().boxed(),
            &XhttpPaddingConfig::default(),
        )
        .expect("request should build");

        let referer = request
            .headers()
            .get("referer")
            .and_then(|value| value.to_str().ok())
            .expect("referer should be present");
        assert!(
            referer.starts_with("http://127.0.0.1:8080/xhttp/?x_padding="),
            "unexpected referer: {referer}"
        );
        let padding_len = referer
            .split("x_padding=")
            .nth(1)
            .expect("padding should exist")
            .len();
        assert!(
            (100..=1_000).contains(&padding_len),
            "unexpected default padding length: {padding_len}"
        );
    }

    #[tokio::test]
    async fn xhttp_stream_one_echoes_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
            let io = TokioIo::new(tcp);
            let service = hyper::service::service_fn(handle_stream_one);
            let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
            builder
                .serve_connection(io, service)
                .await
                .expect("server connection should succeed");
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::StreamOne,
            1_000_000,
            false,
            None,
            None,
        );

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("stream-one transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn xhttp_reuses_one_h2_connection_for_multiple_logical_streams() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
            let io = TokioIo::new(tcp);
            let service = hyper::service::service_fn(handle_stream_one);
            let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
            builder
                .serve_connection(io, service)
                .await
                .expect("server connection should succeed");
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::StreamOne,
            1_000_000,
            false,
            None,
            None,
        )
        .with_reuse_policy(Some(XhttpReusePolicy {
            max_concurrency: Some(XhttpReuseValueRange { min: 1, max: 1 }),
            max_connections: None,
            c_max_reuse_times: Some(XhttpReuseValueRange { min: 1, max: 1 }),
            h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
            h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
            h_keep_alive_period: 0,
        }));

        let mut first = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("first logical stream should connect");

        assert!(
            client
                .try_reuse_stream()
                .await
                .expect("reuse lookup should succeed")
                .is_none(),
            "max-concurrency=1 must block reuse while first stream is active"
        );

        first
            .write_all(b"one1")
            .await
            .expect("first write should succeed");
        first.flush().await.expect("first flush should succeed");
        let mut first_buf = [0u8; 4];
        timeout(Duration::from_secs(2), first.read_exact(&mut first_buf))
            .await
            .expect("first read should finish")
            .expect("first read should succeed");
        assert_eq!(&first_buf, b"one1");
        drop(first);

        let mut second = client
            .try_reuse_stream()
            .await
            .expect("second reuse lookup should succeed")
            .expect("same H2 connection should be reusable");
        second
            .write_all(b"two2")
            .await
            .expect("second write should succeed");
        second.flush().await.expect("second flush should succeed");
        let mut second_buf = [0u8; 4];
        timeout(Duration::from_secs(2), second.read_exact(&mut second_buf))
            .await
            .expect("second read should finish")
            .expect("second read should succeed");
        assert_eq!(&second_buf, b"two2");
        drop(second);

        assert!(
            client
                .try_reuse_stream()
                .await
                .expect("third reuse lookup should succeed")
                .is_none(),
            "c-max-reuse-times=1 must retire the connection after one reuse"
        );
    }

    #[tokio::test]
    async fn xhttp_max_connections_opens_fresh_until_limit_then_reuses() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) =
                    listener.accept().await.expect("accept should succeed");
                tokio::spawn(async move {
                    let io = TokioIo::new(tcp);
                    let service = hyper::service::service_fn(handle_stream_one);
                    let builder =
                        auto::Builder::new(TokioExecutor::new()).http2_only();
                    builder
                        .serve_connection(io, service)
                        .await
                        .expect("server connection should succeed");
                });
            }
        });

        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::StreamOne,
            1_000_000,
            false,
            None,
            None,
        )
        .with_reuse_policy(Some(XhttpReusePolicy {
            max_concurrency: None,
            max_connections: Some(XhttpReuseValueRange { min: 2, max: 2 }),
            c_max_reuse_times: None,
            h_max_request_times: None,
            h_max_reusable_secs: None,
            h_keep_alive_period: 0,
        }));

        let first_tcp = TcpStream::connect(addr)
            .await
            .expect("first client connection should succeed");
        let mut first = client
            .proxy_stream(Box::new(first_tcp))
            .await
            .expect("first logical stream should connect");
        first.write_all(b"one1").await.unwrap();
        first.flush().await.unwrap();
        let mut first_buf = [0u8; 4];
        timeout(Duration::from_secs(2), first.read_exact(&mut first_buf))
            .await
            .expect("first read should finish")
            .expect("first read should succeed");
        assert_eq!(&first_buf, b"one1");
        drop(first);

        assert!(
            client
                .try_reuse_stream()
                .await
                .expect("first reuse lookup should succeed")
                .is_none(),
            "pool must request a fresh second connection before max-connections is reached"
        );

        let second_tcp = TcpStream::connect(addr)
            .await
            .expect("second client connection should succeed");
        let mut second = client
            .proxy_stream(Box::new(second_tcp))
            .await
            .expect("second logical stream should connect");
        second.write_all(b"two2").await.unwrap();
        second.flush().await.unwrap();
        let mut second_buf = [0u8; 4];
        timeout(Duration::from_secs(2), second.read_exact(&mut second_buf))
            .await
            .expect("second read should finish")
            .expect("second read should succeed");
        assert_eq!(&second_buf, b"two2");
        drop(second);

        let mut third = client
            .try_reuse_stream()
            .await
            .expect("second reuse lookup should succeed")
            .expect("pool must reuse after max-connections is reached");
        third.write_all(b"tri3").await.unwrap();
        third.flush().await.unwrap();
        let mut third_buf = [0u8; 4];
        timeout(Duration::from_secs(2), third.read_exact(&mut third_buf))
            .await
            .expect("third read should finish")
            .expect("third read should succeed");
        assert_eq!(&third_buf, b"tri3");
    }

    #[tokio::test]
    async fn xhttp_separate_download_reuses_single_h2_connection() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
            let io = TokioIo::new(tcp);
            let service =
                hyper::service::service_fn(|req: Request<Incoming>| async move {
                    assert_eq!(req.method(), Method::GET);
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Empty::<Bytes>::new().boxed())
                            .expect("response should build"),
                    )
                });
            let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
            builder
                .serve_connection(io, service)
                .await
                .expect("download server connection should succeed");
        });

        let reuse_policy = XhttpReusePolicy {
            max_concurrency: None,
            max_connections: Some(XhttpReuseValueRange { min: 1, max: 1 }),
            c_max_reuse_times: None,
            h_max_request_times: None,
            h_max_reusable_secs: None,
            h_keep_alive_period: -1,
        };
        let download = XhttpDownloadConfig {
            server: "127.0.0.1".to_owned(),
            port: addr.port(),
            path: "/xhttp/".to_owned(),
            host: None,
            headers: HashMap::new(),
            security: XhttpSecurity::None,
            server_name: "127.0.0.1".to_owned(),
            alpn_protocols: vec!["h2".to_owned()],
            skip_cert_verify: false,
            fingerprint: None,
            verify_name: None,
            tls_cert: None,
            tls_key: None,
            reality: None,
            reuse_policy: Some(reuse_policy),
        };
        let client = Client::new(
            "upload.invalid".to_owned(),
            443,
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::StreamUp,
            1_000_000,
            false,
            None,
            Some(download),
        );

        for session_id in ["first", "second"] {
            let download = client.download.as_ref().expect("download config");
            let (body, active) = timeout(
                Duration::from_secs(2),
                open_separate_downlink_response(&client, download, session_id),
            )
            .await
            .expect("downlink request should finish")
            .expect("downlink request should succeed");

            body.collect()
                .await
                .expect("downlink response body should collect");

            if let Some(active) = active {
                active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }

        assert_eq!(
            client.download_reuse_pool.lock().await.len(),
            1,
            "both downlink sessions must share one HTTP/2 connection"
        );
    }

    #[tokio::test]
    async fn xhttp_stream_up_echoes_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            async move {
                let (tcp, _) =
                    listener.accept().await.expect("accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    handle_split_modes(req, sessions.clone())
                });
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
                builder
                    .serve_connection(io, service)
                    .await
                    .expect("server connection should succeed");
            }
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::StreamUp,
            1_000_000,
            false,
            None,
            None,
        );

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("stream-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn xhttp_stream_up_uses_grpc_content_type_by_default() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));
        let post_content_types = Arc::new(Mutex::new(Vec::<Option<String>>::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            let post_content_types = post_content_types.clone();
            async move {
                let (tcp, _) =
                    listener.accept().await.expect("accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    handle_split_modes_with_post_content_type(
                        req,
                        sessions.clone(),
                        post_content_types.clone(),
                    )
                });
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
                builder
                    .serve_connection(io, service)
                    .await
                    .expect("server connection should succeed");
            }
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::StreamUp,
            1_000_000,
            false,
            None,
            None,
        );

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("stream-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");

        timeout(Duration::from_secs(2), async {
            loop {
                let values = post_content_types.lock().await;
                if !values.is_empty() {
                    assert_eq!(values[0].as_deref(), Some("application/grpc"));
                    break;
                }
                drop(values);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("content-type should be recorded");
    }

    #[tokio::test]
    async fn xhttp_stream_up_no_grpc_header_uses_octet_stream() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));
        let post_content_types = Arc::new(Mutex::new(Vec::<Option<String>>::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            let post_content_types = post_content_types.clone();
            async move {
                let (tcp, _) =
                    listener.accept().await.expect("accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    handle_split_modes_with_post_content_type(
                        req,
                        sessions.clone(),
                        post_content_types.clone(),
                    )
                });
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
                builder
                    .serve_connection(io, service)
                    .await
                    .expect("server connection should succeed");
            }
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::StreamUp,
            1_000_000,
            true,
            None,
            None,
        );

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("stream-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");

        timeout(Duration::from_secs(2), async {
            loop {
                let values = post_content_types.lock().await;
                if !values.is_empty() {
                    assert_eq!(
                        values[0].as_deref(),
                        Some("application/octet-stream")
                    );
                    break;
                }
                drop(values);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("content-type should be recorded");
    }

    #[tokio::test]
    async fn xhttp_http1_packet_up_echoes_bytes_over_separate_connections() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        return;
                    };
                    let sessions = sessions.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(tcp);
                        let service = hyper::service::service_fn(move |req| {
                            let sessions = sessions.clone();
                            async move {
                                assert_eq!(req.version(), Version::HTTP_11);
                                assert!(req.headers().contains_key("host"));
                                handle_split_modes(req, sessions).await
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    });
                }
            }
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::PacketUp,
            1_000_000,
            false,
            None,
            None,
        )
        .with_http_version(XhttpHttpVersion::Http1);

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("HTTP/1.1 packet-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn xhttp_http1_packet_up_supports_separate_download_settings() {
        let upload_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upload listener should bind");
        let upload_addr = upload_listener
            .local_addr()
            .expect("upload listener should expose addr");
        let download_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("download listener should bind");
        let download_addr = download_listener
            .local_addr()
            .expect("download listener should expose addr");

        let sessions: TestSessions = Arc::new(Mutex::new(HashMap::new()));
        let upload_methods = Arc::new(Mutex::new(Vec::<Method>::new()));
        let download_methods = Arc::new(Mutex::new(Vec::<Method>::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            let upload_methods = upload_methods.clone();
            async move {
                let (tcp, _) = upload_listener
                    .accept()
                    .await
                    .expect("upload accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    let sessions = sessions.clone();
                    let upload_methods = upload_methods.clone();
                    async move {
                        upload_methods.lock().await.push(req.method().clone());
                        handle_split_modes(req, sessions).await
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            }
        });

        tokio::spawn({
            let sessions = sessions.clone();
            let download_methods = download_methods.clone();
            async move {
                let (tcp, _) = download_listener
                    .accept()
                    .await
                    .expect("download accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    let sessions = sessions.clone();
                    let download_methods = download_methods.clone();
                    async move {
                        download_methods.lock().await.push(req.method().clone());
                        handle_split_modes(req, sessions).await
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            }
        });

        let download = XhttpDownloadConfig {
            server: "127.0.0.1".to_owned(),
            port: download_addr.port(),
            path: "/xhttp/".to_owned(),
            host: None,
            headers: HashMap::new(),
            security: XhttpSecurity::None,
            server_name: "127.0.0.1".to_owned(),
            alpn_protocols: vec!["http/1.1".to_owned()],
            skip_cert_verify: false,
            fingerprint: None,
            verify_name: None,
            tls_cert: None,
            tls_key: None,
            reality: None,
            reuse_policy: None,
        };
        let client = Client::new(
            "127.0.0.1".to_owned(),
            upload_addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::PacketUp,
            1_000_000,
            false,
            None,
            Some(download),
        )
        .with_http_version(XhttpHttpVersion::Http1);

        let stream = TcpStream::connect(upload_addr)
            .await
            .expect("upload client should connect");
        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("HTTP/1.1 separate download should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");

        timeout(Duration::from_secs(2), async {
            loop {
                let upload = upload_methods.lock().await;
                let download = download_methods.lock().await;
                if !upload.is_empty() && !download.is_empty() {
                    assert_eq!(upload.as_slice(), [Method::POST]);
                    assert_eq!(download.as_slice(), [Method::GET]);
                    break;
                }
                drop(download);
                drop(upload);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("HTTP/1.1 methods should be observed");
    }

    #[tokio::test]
    async fn xhttp_http1_tls_packet_up_echoes_bytes() {
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));
        let addr = spawn_tls_h1_xhttp_server(sessions).await;

        let endpoint = XhttpEndpointConfig {
            server: "127.0.0.1".to_owned(),
            port: addr.port(),
            security: XhttpSecurity::Tls,
            server_name: "xhttp.example.com".to_owned(),
            alpn_protocols: vec!["http/1.1".to_owned()],
            skip_cert_verify: true,
            fingerprint: None,
            verify_name: None,
            tls_cert: None,
            tls_key: None,
            reality: None,
        };
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            true,
            XhttpMode::PacketUp,
            1_000_000,
            false,
            None,
            None,
        )
        .with_upload_endpoint(Some(endpoint))
        .with_http_version(XhttpHttpVersion::Http1);

        let raw = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let mut proxied = client
            .proxy_stream(Box::new(raw))
            .await
            .expect("TLS HTTP/1.1 packet-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn xhttp_http1_auto_resolves_to_packet_up() {
        let client = Client::new(
            "example.com".to_owned(),
            80,
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::Auto,
            1_000_000,
            false,
            None,
            None,
        )
        .with_http_version(XhttpHttpVersion::Http1);

        assert_eq!(client.effective_mode(), XhttpMode::PacketUp);
    }

    #[tokio::test]
    async fn xhttp_packet_up_echoes_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            async move {
                let (tcp, _) =
                    listener.accept().await.expect("accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    handle_split_modes(req, sessions.clone())
                });
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
                builder
                    .serve_connection(io, service)
                    .await
                    .expect("server connection should succeed");
            }
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::PacketUp,
            1_000_000,
            false,
            None,
            None,
        );

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("packet-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn xhttp_packet_up_applies_query_session_and_header_seq() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            async move {
                let (tcp, _) =
                    listener.accept().await.expect("accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    handle_query_session_header_seq(req, sessions.clone())
                });
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
                builder
                    .serve_connection(io, service)
                    .await
                    .expect("server connection should succeed");
            }
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::PacketUp,
            1_000_000,
            false,
            None,
            None,
        )
        .with_metadata(XhttpMetadataConfig {
            session_placement: MetadataPlacement::Query,
            session_key: Some("auth".to_owned()),
            seq_placement: MetadataPlacement::Header,
            seq_key: Some("X-Seq".to_owned()),
        });

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("packet-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn xhttp_packet_up_places_payload_in_headers() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            async move {
                let (tcp, _) =
                    listener.accept().await.expect("accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    handle_header_uplink(req, sessions.clone())
                });
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
                builder
                    .serve_connection(io, service)
                    .await
                    .expect("server connection should succeed");
            }
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::PacketUp,
            1_000_000,
            false,
            None,
            None,
        )
        .with_uplink(XhttpUplinkConfig {
            method: "PUT".to_owned(),
            placement: UplinkDataPlacement::Header,
            key: Some("X-Payload".to_owned()),
            chunk_size: XhttpChunkSizeRange::fixed(4096),
        });

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("packet-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn xhttp_packet_up_supports_separate_download_settings() {
        let upload_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upload listener should bind");
        let upload_addr = upload_listener
            .local_addr()
            .expect("upload listener should expose addr");
        let download_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("download listener should bind");
        let download_addr = download_listener
            .local_addr()
            .expect("download listener should expose addr");
        let sessions = Arc::new(Mutex::new(HashMap::<
            String,
            mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
        >::new()));

        tokio::spawn({
            let sessions = sessions.clone();
            async move {
                let (tcp, _) = upload_listener
                    .accept()
                    .await
                    .expect("upload accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    handle_split_modes(req, sessions.clone())
                });
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
                builder
                    .serve_connection(io, service)
                    .await
                    .expect("upload server connection should succeed");
            }
        });

        tokio::spawn({
            let sessions = sessions.clone();
            async move {
                let (tcp, _) = download_listener
                    .accept()
                    .await
                    .expect("download accept should succeed");
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(move |req| {
                    handle_split_modes(req, sessions.clone())
                });
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
                builder
                    .serve_connection(io, service)
                    .await
                    .expect("download server connection should succeed");
            }
        });

        let stream = TcpStream::connect(upload_addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "127.0.0.1".to_owned(),
            upload_addr.port(),
            "/xhttp/".to_owned(),
            None,
            HashMap::new(),
            false,
            XhttpMode::PacketUp,
            1_000_000,
            false,
            None,
            Some(XhttpDownloadConfig {
                server: "127.0.0.1".to_owned(),
                port: download_addr.port(),
                path: "/xhttp/".to_owned(),
                host: None,
                headers: HashMap::new(),
                security: XhttpSecurity::None,
                server_name: "127.0.0.1".to_owned(),
                alpn_protocols: vec!["h2".to_owned()],
                skip_cert_verify: false,
                fingerprint: None,
                verify_name: None,
                tls_cert: None,
                tls_key: None,
                reality: None,
                reuse_policy: None,
            }),
        );

        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("packet-up transport should connect");
        proxied
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        proxied.flush().await.expect("flush should succeed");

        let mut buf = [0_u8; 4];
        timeout(Duration::from_secs(2), proxied.read_exact(&mut buf))
            .await
            .expect("read should finish")
            .expect("read should succeed");
        assert_eq!(&buf, b"ping");
    }

    async fn handle_stream_one(
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        if req.method() != Method::POST || req.uri().path() != "/xhttp/" {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Empty::<Bytes>::new().boxed())
                .expect("response should build"));
        }

        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(32);
        let mut body = req.into_body();
        tokio::spawn(async move {
            while let Some(frame_res) = body.frame().await {
                match frame_res {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref()
                            && tx.send(Ok(Frame::data(data.clone()))).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(StreamBody::new(ReceiverStream::new(rx)).boxed())
            .expect("response should build"))
    }

    async fn handle_split_modes(
        req: Request<Incoming>,
        sessions: TestSessions,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let path = req.uri().path().to_owned();
        let parts = path
            .trim_start_matches("/xhttp/")
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();

        match (req.method(), parts.as_slice()) {
            (&Method::GET, [session_id]) => {
                let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(32);
                sessions.lock().await.insert((*session_id).to_owned(), tx);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(StreamBody::new(ReceiverStream::new(rx)).boxed())
                    .expect("response should build"))
            }
            (&Method::POST, [session_id]) => {
                let maybe_sender = sessions.lock().await.get(*session_id).cloned();
                if let Some(sender) = maybe_sender {
                    let mut body = req.into_body();
                    tokio::spawn(async move {
                        while let Some(frame_res) = body.frame().await {
                            match frame_res {
                                Ok(frame) => {
                                    if let Some(data) = frame.data_ref()
                                        && sender
                                            .send(Ok(Frame::data(data.clone())))
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
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"))
                } else {
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"))
                }
            }
            (&Method::POST, [session_id, _seq]) => {
                let payload = req
                    .into_body()
                    .collect()
                    .await
                    .expect("request body should collect")
                    .to_bytes();
                let maybe_sender = sessions.lock().await.get(*session_id).cloned();
                if let Some(sender) = maybe_sender {
                    let _ = sender.send(Ok(Frame::data(payload))).await;
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"))
                } else {
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"))
                }
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Empty::<Bytes>::new().boxed())
                .expect("response should build")),
        }
    }

    async fn handle_header_uplink(
        req: Request<Incoming>,
        sessions: TestSessions,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let path = req.uri().path().to_owned();
        let parts = path
            .trim_start_matches("/xhttp/")
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();

        match (req.method(), parts.as_slice()) {
            (&Method::GET, [session_id]) => {
                let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(32);
                sessions.lock().await.insert((*session_id).to_owned(), tx);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(StreamBody::new(ReceiverStream::new(rx)).boxed())
                    .expect("response should build"))
            }
            (&Method::PUT, [session_id, "0"]) => {
                let encoded = req
                    .headers()
                    .get("X-Payload-0")
                    .and_then(|value| value.to_str().ok())
                    .expect("header payload should be present")
                    .to_owned();
                let body = req
                    .into_body()
                    .collect()
                    .await
                    .expect("request body should collect")
                    .to_bytes();
                assert!(
                    body.is_empty(),
                    "header placement must not use request body"
                );

                let payload = URL_SAFE_NO_PAD
                    .decode(encoded)
                    .expect("header payload should decode");

                let sender = sessions.lock().await.get(*session_id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send(Ok(Frame::data(Bytes::from(payload)))).await;
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"))
                } else {
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"))
                }
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Empty::<Bytes>::new().boxed())
                .expect("response should build")),
        }
    }

    async fn handle_query_session_header_seq(
        req: Request<Incoming>,
        sessions: TestSessions,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let session_id = req.uri().query().and_then(|query| {
            query.split('&').find_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                (key == "auth").then(|| value.to_owned())
            })
        });

        match *req.method() {
            Method::GET => {
                let Some(session_id) = session_id else {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"));
                };
                let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(32);
                sessions.lock().await.insert(session_id, tx);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(StreamBody::new(ReceiverStream::new(rx)).boxed())
                    .expect("response should build"))
            }
            Method::POST => {
                let Some(session_id) = session_id else {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"));
                };
                if req
                    .headers()
                    .get("X-Seq")
                    .and_then(|value| value.to_str().ok())
                    != Some("0")
                {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"));
                }

                let payload = req
                    .into_body()
                    .collect()
                    .await
                    .expect("request body should collect")
                    .to_bytes();
                let sender = sessions.lock().await.get(&session_id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send(Ok(Frame::data(payload))).await;
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"))
                } else {
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Empty::<Bytes>::new().boxed())
                        .expect("response should build"))
                }
            }
            _ => Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Empty::<Bytes>::new().boxed())
                .expect("response should build")),
        }
    }

    async fn handle_split_modes_with_post_content_type(
        req: Request<Incoming>,
        sessions: TestSessions,
        post_content_types: Arc<Mutex<Vec<Option<String>>>>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        if req.method() == Method::POST {
            post_content_types.lock().await.push(
                req.headers()
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned),
            );
        }

        handle_split_modes(req, sessions).await
    }
}
