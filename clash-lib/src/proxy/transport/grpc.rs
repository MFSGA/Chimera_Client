use std::{
    convert::Infallible,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{Request, StatusCode, Uri, Version};
use http_body_util::{BodyExt, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use prost::encoding::{decode_varint, encode_varint};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc},
};
use tokio_stream::wrappers::ReceiverStream;
use tracing::warn;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

const FRAME_CHANNEL_CAPACITY: usize = 32;
const READ_CHUNK_SIZE: usize = 8 * 1024;
const DEFAULT_GRPC_USER_AGENT: &str = "tonic/0.10";

type H2SendRequest =
    hyper::client::conn::http2::SendRequest<BoxBody<Bytes, Infallible>>;

#[derive(Clone)]
struct ReusableGrpc {
    sender: H2SendRequest,
    active: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct Client {
    host: String,
    path: http::uri::PathAndQuery,
    user_agent: String,
    ping_interval_secs: Option<u64>,
    max_connections: u64,
    min_streams: u64,
    max_streams: u64,
    pool: Arc<Mutex<Vec<ReusableGrpc>>>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcClient")
            .field("host", &self.host)
            .field("path", &self.path)
            .field("user_agent", &self.user_agent)
            .field("ping_interval_secs", &self.ping_interval_secs)
            .field("max_connections", &self.max_connections)
            .field("min_streams", &self.min_streams)
            .field("max_streams", &self.max_streams)
            .finish()
    }
}

impl Client {
    pub fn new(host: String, path: http::uri::PathAndQuery) -> Self {
        Self {
            host,
            path,
            user_agent: DEFAULT_GRPC_USER_AGENT.to_owned(),
            ping_interval_secs: None,
            max_connections: 1,
            min_streams: 0,
            max_streams: 0,
            pool: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        if let Some(user_agent) = user_agent.filter(|value| !value.is_empty()) {
            self.user_agent = user_agent;
        }
        self
    }

    pub fn with_ping_interval(mut self, ping_interval_secs: Option<u64>) -> Self {
        self.ping_interval_secs = ping_interval_secs.filter(|value| *value > 0);
        self
    }

    pub fn with_pool_limits(
        mut self,
        max_connections: Option<u64>,
        min_streams: Option<u64>,
        max_streams: Option<u64>,
    ) -> Self {
        if let Some(max_streams) = max_streams.filter(|value| *value > 0) {
            self.max_connections = 0;
            self.min_streams = 0;
            self.max_streams = max_streams;
        } else {
            self.max_connections = max_connections.unwrap_or(1);
            self.min_streams = min_streams.unwrap_or(0);
            self.max_streams = 0;
        }
        self
    }

    fn should_reuse(&self, pool_len: usize, active: u64) -> bool {
        if active == 0 {
            return true;
        }

        if self.max_connections > 0 {
            return pool_len as u64 >= self.max_connections
                || active < self.min_streams;
        }

        if self.max_streams > 0 {
            return active < self.max_streams;
        }

        false
    }

    fn request(
        &self,
        body: BoxBody<Bytes, Infallible>,
    ) -> io::Result<Request<BoxBody<Bytes, Infallible>>> {
        let uri: Uri = Uri::builder()
            .scheme("https")
            .authority(self.host.as_str())
            .path_and_query(format!("{}/Tun", self.path.as_str()))
            .build()
            .map_err(map_io_error)?;

        Request::builder()
            .method("POST")
            .uri(uri)
            .version(Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("user-agent", self.user_agent.as_str())
            .body(body)
            .map_err(map_io_error)
    }
}

fn validate_grpc_status(headers: &http::HeaderMap) -> io::Result<()> {
    let Some(status) = headers.get("grpc-status") else {
        return Ok(());
    };
    let status = status
        .to_str()
        .map_err(|_| io::Error::other("grpc response has invalid grpc-status"))?;
    if status == "0" {
        return Ok(());
    }

    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<no grpc-message>");
    Err(io::Error::other(format!(
        "grpc response status {status}: {message}"
    )))
}

fn validate_grpc_response<B>(response: &http::Response<B>) -> io::Result<()> {
    if response.status() != StatusCode::OK {
        return Err(io::Error::other(format!(
            "grpc handshake bad status: {}",
            response.status()
        )));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .ok_or_else(|| io::Error::other("grpc response missing content-type"))?
        .to_str()
        .map_err(|_| io::Error::other("grpc response has invalid content-type"))?;
    let content_type_lower = content_type.to_ascii_lowercase();
    if content_type_lower != "application/grpc"
        && !content_type_lower.starts_with("application/grpc+")
    {
        return Err(io::Error::other(format!(
            "grpc response has unexpected content-type: {content_type}"
        )));
    }

    validate_grpc_status(response.headers())
}

async fn handshake_http2(
    stream: AnyStream,
    ping_interval_secs: Option<u64>,
) -> io::Result<H2SendRequest> {
    let io = TokioIo::new(stream);
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    if let Some(ping_interval_secs) = ping_interval_secs {
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(Duration::from_secs(ping_interval_secs))
            .keep_alive_while_idle(true);
    }
    let (sender, conn) = builder
        .handshake::<_, BoxBody<Bytes, Infallible>>(io)
        .await
        .map_err(map_io_error)?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!("grpc http2 connection failed: {err}");
        }
    });

    Ok(sender)
}

fn encode_grpc_frame(data: &[u8]) -> Bytes {
    let mut protobuf_header = BytesMut::with_capacity(11);
    protobuf_header.put_u8(0x0a);
    encode_varint(data.len() as u64, &mut protobuf_header);

    let grpc_payload_len = protobuf_header.len() + data.len();
    let mut frame = BytesMut::with_capacity(5 + grpc_payload_len);
    frame.put_u8(0);
    frame.put_u32(grpc_payload_len as u32);
    frame.extend_from_slice(&protobuf_header);
    frame.extend_from_slice(data);
    frame.freeze()
}

fn try_decode_grpc_frame(buffer: &mut BytesMut) -> io::Result<Option<Bytes>> {
    if buffer.len() < 5 {
        return Ok(None);
    }

    if buffer[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed grpc frames are not supported",
        ));
    }

    let grpc_payload_len =
        u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    let total_len = 5usize.checked_add(grpc_payload_len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "grpc frame too large")
    })?;
    if buffer.len() < total_len {
        return Ok(None);
    }

    let mut frame = buffer.split_to(total_len).freeze();
    frame.advance(5);
    if !frame.has_remaining() || frame.get_u8() != 0x0a {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid grpc protobuf payload tag",
        ));
    }

    let payload_len = decode_varint(&mut frame).map_err(map_io_error)? as usize;
    if frame.remaining() < payload_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated grpc protobuf payload",
        ));
    }

    Ok(Some(frame.copy_to_bytes(payload_len)))
}

async fn forward_grpc_response(
    mut body: Incoming,
    writer: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
) -> io::Result<()> {
    let mut buffer = BytesMut::new();

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(map_io_error)?;
        if let Some(trailers) = frame.trailers_ref() {
            validate_grpc_status(trailers)?;
            continue;
        }
        let Some(data) = frame.data_ref() else {
            continue;
        };
        buffer.extend_from_slice(data);

        while let Some(payload) = try_decode_grpc_frame(&mut buffer)? {
            writer.write_all(&payload).await?;
        }
    }

    if !buffer.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "grpc response ended with a partial frame",
        ));
    }

    Ok(())
}

impl Client {
    async fn try_reuse_sender(&self) -> Option<(H2SendRequest, Arc<AtomicU64>)> {
        let mut pool = self.pool.lock().await;
        pool.retain(|connection| !connection.sender.is_closed());

        let (index, active) = pool
            .iter()
            .enumerate()
            .map(|(index, connection)| {
                (index, connection.active.load(Ordering::Acquire))
            })
            .min_by_key(|(_, active)| *active)?;

        if !self.should_reuse(pool.len(), active) {
            return None;
        }

        let connection = &pool[index];
        connection.active.fetch_add(1, Ordering::AcqRel);
        Some((connection.sender.clone(), connection.active.clone()))
    }

    async fn register_fresh_sender(
        &self,
        sender: H2SendRequest,
    ) -> (H2SendRequest, Arc<AtomicU64>) {
        let mut pool = self.pool.lock().await;
        pool.retain(|connection| !connection.sender.is_closed());

        if let Some((index, active)) = pool
            .iter()
            .enumerate()
            .map(|(index, connection)| {
                (index, connection.active.load(Ordering::Acquire))
            })
            .min_by_key(|(_, active)| *active)
            && self.should_reuse(pool.len(), active)
        {
            let connection = &pool[index];
            connection.active.fetch_add(1, Ordering::AcqRel);
            return (connection.sender.clone(), connection.active.clone());
        }

        let active = Arc::new(AtomicU64::new(1));
        pool.push(ReusableGrpc {
            sender: sender.clone(),
            active: active.clone(),
        });
        (sender, active)
    }

    async fn open_logical_stream(
        &self,
        mut sender: H2SendRequest,
        active: Arc<AtomicU64>,
    ) -> io::Result<AnyStream> {
        let (body_tx, body_rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(
            FRAME_CHANNEL_CAPACITY,
        );
        let body = StreamBody::new(ReceiverStream::new(body_rx)).boxed();
        let request = match self.request(body) {
            Ok(request) => request,
            Err(err) => {
                active.fetch_sub(1, Ordering::AcqRel);
                return Err(err);
            }
        };

        let (app_stream, transport_stream) = tokio::io::duplex(64 * 1024);
        let (mut transport_reader, mut transport_writer) =
            tokio::io::split(transport_stream);

        tokio::spawn(async move {
            let mut buf = vec![0; READ_CHUNK_SIZE];
            loop {
                match transport_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if body_tx
                            .send(Ok(Frame::data(encode_grpc_frame(&buf[..n]))))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(err) => {
                        warn!("grpc uplink read failed: {err}");
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            let result = async {
                let response =
                    sender.send_request(request).await.map_err(map_io_error)?;
                validate_grpc_response(&response)?;

                forward_grpc_response(response.into_body(), &mut transport_writer)
                    .await
            }
            .await;

            if let Err(err) = result {
                warn!("grpc downlink failed: {err}");
            }
            let _ = transport_writer.shutdown().await;
            active.fetch_sub(1, Ordering::AcqRel);
        });

        Ok(Box::new(app_stream))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let sender = handshake_http2(stream, self.ping_interval_secs).await?;
        let (sender, active) = self.register_fresh_sender(sender).await;
        self.open_logical_stream(sender, active).await
    }

    async fn try_reuse_stream(&self) -> io::Result<Option<AnyStream>> {
        let Some((sender, active)) = self.try_reuse_sender().await else {
            return Ok(None);
        };
        self.open_logical_stream(sender, active).await.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::server::conn::auto;
    use tokio::{
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };

    async fn grpc_echo_handler(
        request: Request<Incoming>,
    ) -> Result<http::Response<Full<Bytes>>, Infallible> {
        assert_eq!(request.method(), "POST");
        assert_eq!(request.uri().path(), "/service/Tun");
        assert_eq!(
            request.headers().get("content-type").unwrap(),
            "application/grpc"
        );
        assert_eq!(request.headers().get("te").unwrap(), "trailers");

        let body = request
            .into_body()
            .collect()
            .await
            .expect("request body should collect")
            .to_bytes();

        Ok(http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .body(Full::new(body))
            .unwrap())
    }

    #[test]
    fn grpc_request_matches_reference_shape() {
        let client = Client::new(
            "grpc.example.com".to_owned(),
            "/service".try_into().unwrap(),
        );
        let body = http_body_util::Empty::<Bytes>::new().boxed();
        let request = client.request(body).expect("request should build");

        assert_eq!(request.method(), "POST");
        assert_eq!(request.version(), Version::HTTP_2);
        assert_eq!(
            request.uri().to_string(),
            "https://grpc.example.com/service/Tun"
        );
        assert_eq!(
            request.headers().get("content-type").unwrap(),
            "application/grpc"
        );
        assert_eq!(request.headers().get("te").unwrap(), "trailers");
        assert_eq!(request.headers().get("user-agent").unwrap(), "tonic/0.10");
    }

    #[test]
    fn grpc_response_requires_grpc_content_type() {
        for content_type in [
            "application/grpc",
            "application/grpc+proto",
            "Application/GRPC",
        ] {
            let response = http::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", content_type)
                .body(())
                .unwrap();
            validate_grpc_response(&response)
                .expect("valid gRPC content-type should be accepted");
        }

        let missing = http::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        assert!(
            validate_grpc_response(&missing)
                .expect_err("missing content-type must fail")
                .to_string()
                .contains("missing content-type")
        );

        for invalid in ["text/html", "application/grpc-web"] {
            let response = http::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", invalid)
                .body(())
                .unwrap();
            assert!(
                validate_grpc_response(&response)
                    .expect_err("non-native gRPC content-type must fail")
                    .to_string()
                    .contains("unexpected content-type"),
                "unexpectedly accepted {invalid}"
            );
        }
    }

    #[test]
    fn grpc_response_rejects_nonzero_grpc_status() {
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("grpc-status", "7")
            .header("grpc-message", "permission denied")
            .body(())
            .unwrap();

        let err = validate_grpc_response(&response)
            .expect_err("nonzero grpc-status must fail");
        assert!(
            err.to_string()
                .contains("grpc response status 7: permission denied")
        );
    }

    #[test]
    fn grpc_status_zero_is_accepted() {
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "0".parse().unwrap());
        validate_grpc_status(&headers).expect("grpc-status 0 should pass");
    }

    #[test]
    fn grpc_response_rejects_non_ok_status_before_content_type() {
        let response = http::Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();

        let err = validate_grpc_response(&response)
            .expect_err("non-200 response must fail");
        assert!(err.to_string().contains("502 Bad Gateway"));
    }

    #[test]
    fn grpc_request_uses_custom_user_agent_and_ping_interval() {
        let client = Client::new(
            "grpc.example.com".to_owned(),
            "/service".try_into().unwrap(),
        )
        .with_user_agent(Some("mihomo-compatible/1.0".to_owned()))
        .with_ping_interval(Some(30));

        let body = http_body_util::Empty::<Bytes>::new().boxed();
        let request = client.request(body).expect("request should build");

        assert_eq!(
            request.headers().get("user-agent").unwrap(),
            "mihomo-compatible/1.0"
        );
        assert_eq!(client.ping_interval_secs, Some(30));
    }

    #[test]
    fn grpc_zero_ping_interval_disables_keepalive() {
        let client = Client::new(
            "grpc.example.com".to_owned(),
            "/service".try_into().unwrap(),
        )
        .with_ping_interval(Some(0));

        assert_eq!(client.ping_interval_secs, None);
    }

    #[test]
    fn grpc_frame_round_trip() {
        let payload = b"hello grpc tunnel";
        let encoded = encode_grpc_frame(payload);
        let mut buffer = BytesMut::from(encoded.as_ref());

        let decoded = try_decode_grpc_frame(&mut buffer)
            .expect("frame should decode")
            .expect("full frame should produce payload");

        assert_eq!(decoded.as_ref(), payload);
        assert!(buffer.is_empty());
    }

    #[test]
    fn grpc_frame_waits_for_complete_payload() {
        let encoded = encode_grpc_frame(b"fragmented");
        let split = encoded.len() - 2;
        let mut buffer = BytesMut::from(&encoded[..split]);

        assert!(
            try_decode_grpc_frame(&mut buffer)
                .expect("partial frame should not error")
                .is_none()
        );

        buffer.extend_from_slice(&encoded[split..]);
        let decoded = try_decode_grpc_frame(&mut buffer)
            .expect("completed frame should decode")
            .expect("completed frame should produce payload");
        assert_eq!(decoded.as_ref(), b"fragmented");
    }

    #[test]
    fn grpc_pool_policy_matches_mihomo_thresholds() {
        let default = Client::new(
            "grpc.example.com".to_owned(),
            "/service".try_into().unwrap(),
        );
        assert!(default.should_reuse(1, 12));

        let min_streams = Client::new(
            "grpc.example.com".to_owned(),
            "/service".try_into().unwrap(),
        )
        .with_pool_limits(Some(3), Some(4), None);
        assert!(min_streams.should_reuse(1, 3));
        assert!(!min_streams.should_reuse(1, 4));
        assert!(min_streams.should_reuse(3, 100));

        let max_streams = Client::new(
            "grpc.example.com".to_owned(),
            "/service".try_into().unwrap(),
        )
        .with_pool_limits(None, None, Some(8));
        assert!(max_streams.should_reuse(1, 7));
        assert!(!max_streams.should_reuse(1, 8));
    }

    #[tokio::test]
    async fn grpc_transport_reuses_one_h2_connection_for_two_streams() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
            let io = TokioIo::new(tcp);
            let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
            builder
                .serve_connection(io, service_fn(grpc_echo_handler))
                .await
                .expect("grpc server connection should succeed");
        });

        let client = Client::new(
            "grpc.example.com".to_owned(),
            "/service".try_into().unwrap(),
        );

        let raw = TcpStream::connect(addr)
            .await
            .expect("first client should connect");
        let mut first = client
            .proxy_stream(Box::new(raw))
            .await
            .expect("first grpc stream should build");
        first.write_all(b"first").await.unwrap();
        first.shutdown().await.unwrap();
        let mut first_reply = Vec::new();
        timeout(Duration::from_secs(2), first.read_to_end(&mut first_reply))
            .await
            .expect("first reply timeout")
            .expect("first reply read");
        assert_eq!(first_reply, b"first");

        let mut second = client
            .try_reuse_stream()
            .await
            .expect("reuse lookup should succeed")
            .expect("second stream must reuse the first H2 connection");
        second.write_all(b"second").await.unwrap();
        second.shutdown().await.unwrap();
        let mut second_reply = Vec::new();
        timeout(
            Duration::from_secs(2),
            second.read_to_end(&mut second_reply),
        )
        .await
        .expect("second reply timeout")
        .expect("second reply read");
        assert_eq!(second_reply, b"second");

        assert_eq!(client.pool.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn grpc_transport_round_trips_bytes_over_http2() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
            let io = TokioIo::new(tcp);
            let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
            builder
                .serve_connection(io, service_fn(grpc_echo_handler))
                .await
                .expect("grpc echo server should succeed");
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let client = Client::new(
            "grpc.example.com".to_owned(),
            "/service".try_into().unwrap(),
        )
        .with_ping_interval(Some(1));
        let mut proxied = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("grpc transport should build");

        let payload = b"grpc transport payload";
        proxied
            .write_all(payload)
            .await
            .expect("uplink write should succeed");
        proxied
            .shutdown()
            .await
            .expect("uplink shutdown should succeed");

        let mut received = Vec::new();
        timeout(Duration::from_secs(3), proxied.read_to_end(&mut received))
            .await
            .expect("downlink should finish before timeout")
            .expect("downlink read should succeed");

        assert_eq!(received, payload);
    }
}
