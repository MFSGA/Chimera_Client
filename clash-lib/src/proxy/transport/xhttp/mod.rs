use std::{collections::HashMap, convert::Infallible, io};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode, Version};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

#[cfg(feature = "tls")]
use super::TlsClient;
#[cfg(feature = "reality")]
use super::RealityClient;
use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;
const FRAME_CHANNEL_CAPACITY: usize = 32;
const READ_CHUNK_SIZE: usize = 8 * 1024;
const DEFAULT_XHTTP_ALPN: [&str; 1] = ["h2"];

type H2SendRequest =
    hyper::client::conn::http2::SendRequest<BoxBody<Bytes, Infallible>>;

#[derive(Clone, Debug)]
pub enum XhttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Clone, Debug)]
pub enum XhttpSecurity {
    None,
    Tls,
    Reality,
}

#[derive(Clone, Debug)]
pub struct XhttpRealityConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: String,
}

#[derive(Clone, Debug)]
pub struct XhttpDownloadConfig {
    pub server: String,
    pub port: u16,
    pub path: String,
    pub host: Option<Vec<String>>,
    pub headers: HashMap<String, String>,
    pub security: XhttpSecurity,
    pub server_name: String,
    pub skip_cert_verify: bool,
    pub reality: Option<XhttpRealityConfig>,
}

pub struct Client {
    server: String,
    port: u16,
    path: String,
    host: Option<Vec<String>>,
    headers: HashMap<String, String>,
    use_tls: bool,
    mode: XhttpMode,
    max_each_post_bytes: usize,
    no_grpc_header: bool,
    min_posts_interval_ms: Option<u64>,
    download: Option<XhttpDownloadConfig>,
}

impl Client {
    pub fn new(
        server: String,
        port: u16,
        path: String,
        host: Option<Vec<String>>,
        headers: HashMap<String, String>,
        use_tls: bool,
        mode: XhttpMode,
        max_each_post_bytes: usize,
        no_grpc_header: bool,
        min_posts_interval_ms: Option<u64>,
        download: Option<XhttpDownloadConfig>,
    ) -> Self {
        Self {
            server,
            port,
            path,
            host,
            headers,
            use_tls,
            mode,
            max_each_post_bytes,
            no_grpc_header,
            min_posts_interval_ms,
            download,
        }
    }

    fn request(
        &self,
        method: &'static str,
        path: &str,
        body: BoxBody<Bytes, Infallible>,
    ) -> io::Result<Request<BoxBody<Bytes, Infallible>>> {
        build_request(
            &self.server,
            self.port,
            path,
            self.host.as_ref(),
            &self.headers,
            self.use_tls,
            self.request_content_type(method),
            method,
            body,
        )
    }

    fn request_content_type(&self, method: &str) -> Option<&'static str> {
        if method != "POST" {
            return None;
        }

        if matches!(self.mode, XhttpMode::StreamOne | XhttpMode::StreamUp)
            && !self.no_grpc_header
        {
            return Some("application/grpc");
        }

        Some("application/octet-stream")
    }
}

async fn handshake_http2(stream: AnyStream) -> io::Result<H2SendRequest> {
    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http2::handshake::<
        _,
        _,
        BoxBody<Bytes, Infallible>,
    >(TokioExecutor::new(), io)
    .await
    .map_err(map_io_error)?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    Ok(sender)
}

async fn connect_download_stream(
    config: &XhttpDownloadConfig,
) -> io::Result<AnyStream> {
    let tcp = TcpStream::connect((config.server.as_str(), config.port)).await?;
    let stream: AnyStream = Box::new(tcp);

    match config.security {
        XhttpSecurity::None => Ok(stream),
        XhttpSecurity::Tls => {
            #[cfg(feature = "tls")]
            {
                let tls = TlsClient::new(
                    config.skip_cert_verify,
                    config.server_name.clone(),
                    Some(
                        DEFAULT_XHTTP_ALPN
                            .iter()
                            .map(|item| (*item).to_owned())
                            .collect(),
                    ),
                    None,
                );
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
                let client = RealityClient::new(
                    reality.public_key,
                    reality.short_id,
                    reality.server_name.clone(),
                    Vec::new(),
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

async fn open_downlink_response(
    client: &Client,
    sender: &mut H2SendRequest,
    session_id: &str,
) -> io::Result<Incoming> {
    if let Some(download) = client.download.as_ref() {
        let stream = connect_download_stream(download).await?;
        let mut downlink_sender = handshake_http2(stream).await?;
        let path = format!("{}{}", download.path, session_id);
        let request = build_request(
            &download.server,
            download.port,
            &path,
            download.host.as_ref(),
            &download.headers,
            matches!(
                download.security,
                XhttpSecurity::Tls | XhttpSecurity::Reality
            ),
            None,
            "GET",
            http_body_util::Empty::<Bytes>::new().boxed(),
        )?;
        let response = downlink_sender
            .send_request(request)
            .await
            .map_err(map_io_error)?;
        validate_response_status(response)
    } else {
        let path = format!("{}{}", client.path, session_id);
        let request = client.request(
            "GET",
            &path,
            http_body_util::Empty::<Bytes>::new().boxed(),
        )?;
        let response = sender.send_request(request).await.map_err(map_io_error)?;
        validate_response_status(response)
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

fn build_request(
    server: &str,
    port: u16,
    path: &str,
    host: Option<&Vec<String>>,
    headers: &HashMap<String, String>,
    use_tls: bool,
    content_type: Option<&str>,
    method: &'static str,
    body: BoxBody<Bytes, Infallible>,
) -> io::Result<Request<BoxBody<Bytes, Infallible>>> {
    let scheme = if use_tls { "https" } else { "http" };
    let uri = format!("{scheme}://{server}:{port}{path}");

    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_2)
        .header("cache-control", "no-store");

    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }

    if !headers.keys().any(|key| key.eq_ignore_ascii_case("host"))
        && let Some(host) = host.and_then(|hosts| hosts.first())
    {
        request = request.header("Host", host);
    }

    for (key, value) in headers {
        request = request.header(key, value);
    }

    request.body(body).map_err(map_io_error)
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        match self.mode {
            XhttpMode::StreamOne => proxy_stream_one(self, stream).await,
            XhttpMode::StreamUp => proxy_stream_up(self, stream).await,
            XhttpMode::PacketUp => proxy_packet_up(self, stream).await,
        }
    }
}

async fn proxy_stream_one(
    client: &Client,
    stream: AnyStream,
) -> io::Result<AnyStream> {
    let mut sender = handshake_http2(stream).await?;
    let (tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Infallible>>(FRAME_CHANNEL_CAPACITY);
    let request_body = StreamBody::new(ReceiverStream::new(rx)).boxed();
    let request = client.request("POST", &client.path, request_body)?;
    let response = validate_response_status(
        sender.send_request(request).await.map_err(map_io_error)?,
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
    stream: AnyStream,
) -> io::Result<AnyStream> {
    let mut sender = handshake_http2(stream).await?;
    let session_id = Uuid::new_v4().to_string();
    let response = open_downlink_response(client, &mut sender, &session_id).await?;

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);
    let base_path = client.path.clone();
    let server = client.server.clone();
    let port = client.port;
    let host = client.host.clone();
    let headers = client.headers.clone();
    let use_tls = client.use_tls;
    let content_type = client.request_content_type("POST");

    tokio::spawn(async move {
        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(
            FRAME_CHANNEL_CAPACITY,
        );
        let request_path = format!("{base_path}{session_id}");
        let request_body = StreamBody::new(ReceiverStream::new(rx)).boxed();
        let request = match build_request(
            &server,
            port,
            &request_path,
            host.as_ref(),
            &headers,
            use_tls,
            content_type,
            "POST",
            request_body,
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

        match sender.send_request(request).await {
            Ok(response) if response.status().is_success() => {}
            _ => {}
        }
    });

    tokio::spawn(async move {
        forward_response_body(response, &mut transport_writer).await;
        let _ = transport_writer.shutdown().await;
    });

    Ok(Box::new(app_stream))
}

async fn proxy_packet_up(
    client: &Client,
    stream: AnyStream,
) -> io::Result<AnyStream> {
    let mut sender = handshake_http2(stream).await?;
    let session_id = Uuid::new_v4().to_string();
    let response = open_downlink_response(client, &mut sender, &session_id).await?;

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);
    let base_path = client.path.clone();
    let max_each_post_bytes = client.max_each_post_bytes;
    let server = client.server.clone();
    let port = client.port;
    let host = client.host.clone();
    let headers = client.headers.clone();
    let use_tls = client.use_tls;
    let content_type = client.request_content_type("POST");
    let min_posts_interval_ms = client.min_posts_interval_ms;

    tokio::spawn(async move {
        let mut seq: u64 = 0;
        let mut buf = vec![0; READ_CHUNK_SIZE];
        loop {
            match transport_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk_size = max_each_post_bytes.max(1);
                    for chunk in buf[..n].chunks(chunk_size) {
                        let request_path = format!("{base_path}{session_id}/{seq}");
                        let body = Full::new(Bytes::copy_from_slice(chunk)).boxed();
                        let request = match build_request(
                            &server,
                            port,
                            &request_path,
                            host.as_ref(),
                            &headers,
                            use_tls,
                            content_type,
                            "POST",
                            body,
                        ) {
                            Ok(request) => request,
                            Err(_) => return,
                        };

                        match sender.send_request(request).await {
                            Ok(response) if response.status().is_success() => {
                                seq += 1;
                                if let Some(interval_ms) = min_posts_interval_ms {
                                    tokio::time::sleep(
                                        tokio::time::Duration::from_millis(
                                            interval_ms,
                                        ),
                                    )
                                    .await;
                                }
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
    use super::{Client, XhttpDownloadConfig, XhttpMode, XhttpSecurity};
    use crate::proxy::transport::Transport;
    use bytes::Bytes;
    use http::{Method, Request, Response, StatusCode};
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
    use tokio_stream::wrappers::ReceiverStream;

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
                skip_cert_verify: false,
                reality: None,
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
                        if let Some(data) = frame.data_ref() {
                            if tx.send(Ok(Frame::data(data.clone()))).await.is_err()
                            {
                                break;
                            }
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
        sessions: Arc<
            Mutex<HashMap<String, mpsc::Sender<Result<Frame<Bytes>, Infallible>>>>,
        >,
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

    async fn handle_split_modes_with_post_content_type(
        req: Request<Incoming>,
        sessions: Arc<
            Mutex<HashMap<String, mpsc::Sender<Result<Frame<Bytes>, Infallible>>>>,
        >,
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
