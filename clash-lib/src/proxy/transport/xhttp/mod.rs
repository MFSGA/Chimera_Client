use std::{collections::HashMap, convert::Infallible, io};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode, Version};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;
const FRAME_CHANNEL_CAPACITY: usize = 32;
const READ_CHUNK_SIZE: usize = 8 * 1024;

#[derive(Clone, Debug)]
pub enum XhttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
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
            method,
            body,
        )
    }
}

fn build_request(
    server: &str,
    port: u16,
    path: &str,
    host: Option<&Vec<String>>,
    headers: &HashMap<String, String>,
    use_tls: bool,
    method: &'static str,
    body: BoxBody<Bytes, Infallible>,
) -> io::Result<Request<BoxBody<Bytes, Infallible>>> {
    let scheme = if use_tls { "https" } else { "http" };
    let uri = format!("{scheme}://{server}:{port}{path}");

    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_2)
        .header("content-type", "application/octet-stream")
        .header("cache-control", "no-store");

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
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake::<
        _,
        _,
        BoxBody<Bytes, Infallible>,
    >(TokioExecutor::new(), io)
    .await
    .map_err(map_io_error)?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Infallible>>(FRAME_CHANNEL_CAPACITY);
    let request_body = StreamBody::new(ReceiverStream::new(rx)).boxed();
    let request = client.request("POST", &client.path, request_body)?;
    let response = sender.send_request(request).await.map_err(map_io_error)?;

    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected xhttp response status: {}", response.status()),
        ));
    }

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
        forward_response_body(response.into_body(), &mut transport_writer).await;
        let _ = transport_writer.shutdown().await;
    });

    Ok(Box::new(app_stream))
}

async fn proxy_stream_up(
    client: &Client,
    stream: AnyStream,
) -> io::Result<AnyStream> {
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake::<
        _,
        _,
        BoxBody<Bytes, Infallible>,
    >(TokioExecutor::new(), io)
    .await
    .map_err(map_io_error)?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let session_id = Uuid::new_v4().to_string();
    let downlink_path = format!("{}{}", client.path, session_id);
    let get_request = client.request(
        "GET",
        &downlink_path,
        http_body_util::Empty::<Bytes>::new().boxed(),
    )?;
    let response = sender
        .send_request(get_request)
        .await
        .map_err(map_io_error)?;

    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected xhttp response status: {}", response.status()),
        ));
    }

    let (app_stream, transport_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport_stream);
    let base_path = client.path.clone();
    let server = client.server.clone();
    let port = client.port;
    let host = client.host.clone();
    let headers = client.headers.clone();
    let use_tls = client.use_tls;

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
        forward_response_body(response.into_body(), &mut transport_writer).await;
        let _ = transport_writer.shutdown().await;
    });

    Ok(Box::new(app_stream))
}

async fn proxy_packet_up(
    client: &Client,
    stream: AnyStream,
) -> io::Result<AnyStream> {
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake::<
        _,
        _,
        BoxBody<Bytes, Infallible>,
    >(TokioExecutor::new(), io)
    .await
    .map_err(map_io_error)?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let session_id = Uuid::new_v4().to_string();
    let downlink_path = format!("{}{}", client.path, session_id);
    let get_request = client.request(
        "GET",
        &downlink_path,
        http_body_util::Empty::<Bytes>::new().boxed(),
    )?;
    let response = sender
        .send_request(get_request)
        .await
        .map_err(map_io_error)?;

    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected xhttp response status: {}", response.status()),
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
    let use_tls = client.use_tls;

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
                            "POST",
                            body,
                        ) {
                            Ok(request) => request,
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
        forward_response_body(response.into_body(), &mut transport_writer).await;
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
    use super::{Client, XhttpMode};
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
}
