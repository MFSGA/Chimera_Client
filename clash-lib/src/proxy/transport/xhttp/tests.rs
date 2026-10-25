use super::{
    Client, MetadataPlacement, UplinkDataPlacement, XhttpChunkSizeRange,
    XhttpDownloadConfig, XhttpEndpointConfig, XhttpHttpVersion, XhttpMetadataConfig,
    XhttpMode, XhttpPaddingConfig, XhttpReusePolicy, XhttpReuseValueRange,
    XhttpSecurity, XhttpUplinkConfig, build_request, connect_download_stream,
    open_separate_downlink_response, remaining_post_interval,
};
#[cfg(feature = "xhttp-h3")]
use crate::{
    app::dns::MockClashResolver,
    proxy::utils::{DirectConnector, NetworkPoolContext},
    session::Session,
};
use crate::{
    common::utils::{encode_hex, sha256},
    proxy::transport::Transport,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "xhttp-h3")]
use bytes::Buf;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use std::convert::Infallible;
#[cfg(feature = "xhttp-h3")]
use std::sync::atomic::Ordering;
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

#[cfg(feature = "xhttp-h3")]
async fn spawn_h3_packet_up_echo_server() -> std::net::SocketAddr {
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
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .expect("test QUIC TLS config should build");
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("test QUIC endpoint should bind");
    let addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = endpoint
            .accept()
            .await
            .expect("test QUIC connection should arrive");
        let connection = incoming.await.expect("test QUIC handshake should succeed");
        let h3_connection = h3_quinn::Connection::new(connection);
        let mut h3_server = h3::server::builder()
            .build(h3_connection)
            .await
            .expect("test HTTP/3 server should build");

        let resolver = h3_server
            .accept()
            .await
            .expect("test HTTP/3 accept should succeed")
            .expect("test HTTP/3 downlink should arrive");
        let (request, mut downlink) = resolver
            .resolve_request()
            .await
            .expect("test HTTP/3 downlink should resolve");
        assert_eq!(request.version(), Version::HTTP_3);
        assert_eq!(request.method(), Method::GET);
        downlink
            .send_response(
                Response::builder().status(StatusCode::OK).body(()).unwrap(),
            )
            .await
            .expect("test HTTP/3 downlink response should send");

        for seq in 0..3_u64 {
            let resolver = h3_server
                .accept()
                .await
                .expect("test HTTP/3 upload accept should succeed")
                .expect("test HTTP/3 upload should arrive");
            let (request, mut upload) = resolver
                .resolve_request()
                .await
                .expect("test HTTP/3 upload should resolve");
            assert_eq!(request.version(), Version::HTTP_3);
            assert_eq!(request.method(), Method::POST);
            assert!(
                request.uri().path().ends_with(&format!("/{seq}")),
                "unexpected upload path: {}",
                request.uri().path()
            );

            let mut echoed = Vec::new();
            while let Some(mut data) = upload
                .recv_data()
                .await
                .expect("test HTTP/3 upload body should read")
            {
                echoed.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            assert_eq!(
                echoed.len(),
                [4, 4, 1][seq as usize],
                "unexpected upload body length for seq {seq}"
            );
            upload
                .send_response(
                    Response::builder().status(StatusCode::OK).body(()).unwrap(),
                )
                .await
                .expect("test HTTP/3 upload response should send");
            upload
                .finish()
                .await
                .expect("test HTTP/3 upload response should finish");
            downlink
                .send_data(Bytes::from(echoed))
                .await
                .expect("test HTTP/3 downlink echo should send");
        }
        // Keep the QUIC endpoint alive after the final DATA frame. Dropping
        // the endpoint immediately can race the last packet before the test
        // client has consumed it.
        std::future::pending::<()>().await;
    });

    addr
}

#[cfg(feature = "xhttp-h3")]
async fn spawn_h3_stream_up_echo_server() -> std::net::SocketAddr {
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
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .expect("test QUIC TLS config should build");
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("test QUIC endpoint should bind");
    let addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = endpoint
            .accept()
            .await
            .expect("test QUIC connection should arrive");
        let connection = incoming.await.expect("test QUIC handshake should succeed");
        let h3_connection = h3_quinn::Connection::new(connection);
        let mut h3_server = h3::server::builder()
            .build(h3_connection)
            .await
            .expect("test HTTP/3 server should build");

        let resolver = h3_server
            .accept()
            .await
            .expect("test HTTP/3 downlink accept should succeed")
            .expect("test HTTP/3 downlink should arrive");
        let (downlink_request, mut downlink) = resolver
            .resolve_request()
            .await
            .expect("test HTTP/3 downlink should resolve");
        assert_eq!(downlink_request.version(), Version::HTTP_3);
        assert_eq!(downlink_request.method(), Method::GET);
        downlink
            .send_response(
                Response::builder().status(StatusCode::OK).body(()).unwrap(),
            )
            .await
            .expect("test HTTP/3 downlink response should send");

        let resolver = h3_server
            .accept()
            .await
            .expect("test HTTP/3 stream-up accept should succeed")
            .expect("test HTTP/3 stream-up should arrive");
        let (upload_request, mut upload) = resolver
            .resolve_request()
            .await
            .expect("test HTTP/3 stream-up should resolve");
        assert_eq!(upload_request.version(), Version::HTTP_3);
        assert_eq!(upload_request.method(), Method::POST);
        assert_eq!(upload_request.uri().path(), downlink_request.uri().path());
        upload
            .send_response(
                Response::builder().status(StatusCode::OK).body(()).unwrap(),
            )
            .await
            .expect("test HTTP/3 stream-up response should send");

        while let Some(mut data) = upload
            .recv_data()
            .await
            .expect("test HTTP/3 stream-up body should read")
        {
            let bytes = data.copy_to_bytes(data.remaining());
            downlink
                .send_data(bytes)
                .await
                .expect("test HTTP/3 downlink echo should send");
        }
        std::future::pending::<()>().await;
    });

    addr
}

#[cfg(feature = "xhttp-h3")]
async fn spawn_h3_download_settings_servers() -> (
    std::net::SocketAddr,
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<Vec<u8>>,
) {
    crate::setup_default_crypto_provider();

    fn server_config() -> quinn::ServerConfig {
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
        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        let quic_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
                .expect("test QUIC TLS config should build");
        quinn::ServerConfig::with_crypto(Arc::new(quic_crypto))
    }

    let upload_endpoint =
        quinn::Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap())
            .expect("test upload QUIC endpoint should bind");
    let upload_addr = upload_endpoint.local_addr().unwrap();
    let download_endpoint =
        quinn::Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap())
            .expect("test download QUIC endpoint should bind");
    let download_addr = download_endpoint.local_addr().unwrap();
    let (upload_tx, upload_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let incoming = upload_endpoint
            .accept()
            .await
            .expect("test upload QUIC connection should arrive");
        let connection = incoming
            .await
            .expect("test upload QUIC handshake should succeed");
        let h3_connection = h3_quinn::Connection::new(connection);
        let mut h3_server = h3::server::builder()
            .build::<_, Bytes>(h3_connection)
            .await
            .expect("test upload HTTP/3 server should build");
        let resolver = h3_server
            .accept()
            .await
            .expect("test upload HTTP/3 accept should succeed")
            .expect("test upload HTTP/3 request should arrive");
        let (request, mut upload) = resolver
            .resolve_request()
            .await
            .expect("test upload HTTP/3 request should resolve");
        assert_eq!(request.method(), Method::POST);
        assert!(request.uri().path().starts_with("/upload/"));
        upload
            .send_response(
                Response::builder().status(StatusCode::OK).body(()).unwrap(),
            )
            .await
            .expect("test upload HTTP/3 response should send");
        let mut body = Vec::new();
        while let Some(mut data) = upload
            .recv_data()
            .await
            .expect("test upload HTTP/3 body should read")
        {
            body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        let _ = upload_tx.send(body);
        std::future::pending::<()>().await;
    });

    tokio::spawn(async move {
        let incoming = download_endpoint
            .accept()
            .await
            .expect("test download QUIC connection should arrive");
        let connection = incoming
            .await
            .expect("test download QUIC handshake should succeed");
        let h3_connection = h3_quinn::Connection::new(connection);
        let mut h3_server = h3::server::builder()
            .build::<_, Bytes>(h3_connection)
            .await
            .expect("test download HTTP/3 server should build");
        let resolver = h3_server
            .accept()
            .await
            .expect("test download HTTP/3 accept should succeed")
            .expect("test download HTTP/3 request should arrive");
        let (request, mut downlink) = resolver
            .resolve_request()
            .await
            .expect("test download HTTP/3 request should resolve");
        assert_eq!(request.method(), Method::GET);
        assert!(request.uri().path().starts_with("/download/"));
        downlink
            .send_response(
                Response::builder().status(StatusCode::OK).body(()).unwrap(),
            )
            .await
            .expect("test download HTTP/3 response should send");
        downlink
            .send_data(Bytes::from_static(b"down-h3"))
            .await
            .expect("test download HTTP/3 body should send");
        std::future::pending::<()>().await;
    });

    (upload_addr, download_addr, upload_rx)
}

#[cfg(feature = "xhttp-h3")]
async fn spawn_h3_stream_one_echo_server(
    request_count: usize,
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
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .expect("test QUIC TLS config should build");
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("test QUIC endpoint should bind");
    let addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = endpoint
            .accept()
            .await
            .expect("test QUIC connection should arrive");
        let connection = incoming.await.expect("test QUIC handshake should succeed");
        let h3_connection = h3_quinn::Connection::new(connection);
        let mut h3_server = h3::server::builder()
            .build(h3_connection)
            .await
            .expect("test HTTP/3 server should build");
        for _ in 0..request_count {
            let resolver = h3_server
                .accept()
                .await
                .expect("test HTTP/3 accept should succeed")
                .expect("test HTTP/3 request should arrive");
            let (request, mut stream) = resolver
                .resolve_request()
                .await
                .expect("test HTTP/3 request should resolve");
            assert_eq!(request.version(), Version::HTTP_3);
            assert_eq!(request.method(), Method::POST);
            stream
                .send_response(
                    Response::builder().status(StatusCode::OK).body(()).unwrap(),
                )
                .await
                .expect("test HTTP/3 response headers should send");

            while let Some(mut data) = stream
                .recv_data()
                .await
                .expect("test HTTP/3 request body should read")
            {
                let bytes = data.copy_to_bytes(data.remaining());
                stream
                    .send_data(bytes)
                    .await
                    .expect("test HTTP/3 response data should send");
            }
            stream
                .finish()
                .await
                .expect("test HTTP/3 response should finish");
        }
        std::future::pending::<()>().await;
    });

    addr
}

fn auto_client(auto_reality: bool, download: Option<XhttpDownloadConfig>) -> Client {
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
        rcgen::generate_simple_self_signed(vec!["download.example.com".to_owned()])
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
        let (tcp, _) = listener.accept().await.expect("TLS accept should succeed");
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

async fn spawn_tls_h1_xhttp_server(sessions: TestSessions) -> std::net::SocketAddr {
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

#[cfg(feature = "xhttp-h3")]
#[test]
fn xhttp_http3_keepalive_period_maps_to_quic_interval() {
    assert_eq!(super::h3_keep_alive_interval(None).unwrap(), None);
    assert_eq!(super::h3_keep_alive_interval(Some(-1)).unwrap(), None);
    assert_eq!(
        super::h3_keep_alive_interval(Some(0)).unwrap(),
        Some(Duration::from_secs(10))
    );
    assert_eq!(
        super::h3_keep_alive_interval(Some(30)).unwrap(),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        super::h3_keep_alive_interval(Some(-2))
            .expect_err("invalid negative keepalive must fail")
            .kind(),
        std::io::ErrorKind::InvalidInput
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

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn xhttp_http3_stream_one_echoes_bytes_through_connector_udp() {
    let addr = spawn_h3_stream_one_echo_server(1).await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".to_owned(),
        port: addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
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
        XhttpMode::StreamOne,
        1_000_000,
        false,
        None,
        None,
    )
    .with_upload_endpoint(Some(endpoint))
    .with_http_version(XhttpHttpVersion::Http3);
    let resolver = Arc::new(MockClashResolver::new());
    let connector = DirectConnector::new();
    let mut proxied = client
        .connect_stream_with_connector(&Session::default(), resolver, &connector)
        .await
        .expect("HTTP/3 transport-owned dial should succeed")
        .expect("HTTP/3 should return a logical stream");

    proxied.write_all(b"ping-h3").await.expect("HTTP/3 write");
    proxied.flush().await.expect("HTTP/3 flush");
    let mut buf = [0u8; 7];
    timeout(Duration::from_secs(3), proxied.read_exact(&mut buf))
        .await
        .expect("HTTP/3 echo timed out")
        .expect("HTTP/3 read failed");
    assert_eq!(&buf, b"ping-h3");
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn xhttp_http3_reuses_one_quic_connection_for_logical_streams() {
    let addr = spawn_h3_stream_one_echo_server(2).await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".to_owned(),
        port: addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
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
        XhttpMode::StreamOne,
        1_000_000,
        false,
        None,
        None,
    )
    .with_upload_endpoint(Some(endpoint))
    .with_http_version(XhttpHttpVersion::Http3)
    .with_reuse_policy(Some(XhttpReusePolicy {
        max_concurrency: Some(XhttpReuseValueRange { min: 1, max: 1 }),
        max_connections: None,
        c_max_reuse_times: Some(XhttpReuseValueRange { min: 1, max: 1 }),
        h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_keep_alive_period: 0,
    }));
    let resolver = Arc::new(MockClashResolver::new());
    let connector = DirectConnector::new();
    let mut first = client
        .connect_stream_with_connector(&Session::default(), resolver, &connector)
        .await
        .expect("first HTTP/3 pooled dial should succeed")
        .expect("first HTTP/3 pooled stream should exist");

    assert!(
        client
            .try_reuse_stream()
            .await
            .expect("active H3 reuse lookup should succeed")
            .is_none(),
        "max-concurrency=1 must block H3 reuse while active"
    );
    first.write_all(b"one1").await.expect("first H3 write");
    first.flush().await.expect("first H3 flush");
    let mut first_buf = [0u8; 4];
    timeout(Duration::from_secs(3), first.read_exact(&mut first_buf))
        .await
        .expect("first H3 reuse read timed out")
        .expect("first H3 reuse read failed");
    assert_eq!(&first_buf, b"one1");
    drop(first);

    let mut second = client
        .try_reuse_stream()
        .await
        .expect("second H3 reuse lookup should succeed")
        .expect("same QUIC/H3 connection should be reusable");
    second.write_all(b"two2").await.expect("second H3 write");
    second.flush().await.expect("second H3 flush");
    let mut second_buf = [0u8; 4];
    timeout(Duration::from_secs(3), second.read_exact(&mut second_buf))
        .await
        .expect("second H3 reuse read timed out")
        .expect("second H3 reuse read failed");
    assert_eq!(&second_buf, b"two2");
    assert_eq!(client.reset_connection_pool().await.unwrap(), 1);
    // Retiring the pool preserves an existing healthy logical stream.
    second.write_all(b"live").await.unwrap();
    second.flush().await.unwrap();
    let mut live = [0; 4];
    timeout(Duration::from_secs(2), second.read_exact(&mut live))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&live, b"live");
    drop(second);

    assert!(
        client
            .try_reuse_stream()
            .await
            .expect("retired H3 reuse lookup should succeed")
            .is_none(),
        "c-max-reuse-times=1 must retire the H3 connection"
    );
}

#[cfg(feature = "xhttp-h3")]
async fn spawn_s04bv_observed_h3_server() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<quinn::ConnectionError>,
) {
    crate::setup_default_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["xhttp.example.com".to_owned()])
            .unwrap();
    let cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
            .unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let watcher = conn.clone();
        tokio::spawn(async move {
            let _ = closed_tx.send(watcher.closed().await);
        });
        let h3_conn = h3_quinn::Connection::new(conn);
        let mut h3_server = h3::server::builder().build(h3_conn).await.unwrap();
        while let Ok(Some(resolver)) = h3_server.accept().await {
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream
                .send_response(
                    Response::builder().status(StatusCode::OK).body(()).unwrap(),
                )
                .await
                .unwrap();
            while let Ok(Some(mut data)) = stream.recv_data().await {
                if stream
                    .send_data(data.copy_to_bytes(data.remaining()))
                    .await
                    .is_err()
                {
                    break; // a cancelled QUIC stream is expected in teardown tests
                }
            }
            let _ = stream.finish().await;
        }
    });
    (addr, closed_rx)
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bw_unpooled_h3_stream_drop_closes_quic_driver() {
    for explicitly_disabled_pool in [false, true] {
        let (addr, closed_rx) = spawn_s04bv_observed_h3_server().await;
        let endpoint = XhttpEndpointConfig {
            server: "127.0.0.1".into(),
            port: addr.port(),
            security: XhttpSecurity::Tls,
            server_name: "xhttp.example.com".into(),
            alpn_protocols: vec!["h3".into()],
            skip_cert_verify: true,
            fingerprint: None,
            verify_name: None,
            tls_cert: None,
            tls_key: None,
            reality: None,
        };
        let mut client = Client::new(
            "127.0.0.1".into(),
            addr.port(),
            "/xhttp/".into(),
            None,
            HashMap::new(),
            true,
            XhttpMode::StreamOne,
            1_000_000,
            false,
            None,
            None,
        )
        .with_upload_endpoint(Some(endpoint))
        .with_http_version(XhttpHttpVersion::Http3);
        if explicitly_disabled_pool {
            client = client.with_reuse_policy(Some(XhttpReusePolicy {
                // No concurrency policy: max-connections=0 genuinely
                // disables pooling rather than enabling concurrency pooling.
                max_concurrency: None,
                max_connections: Some(XhttpReuseValueRange { min: 0, max: 0 }),
                c_max_reuse_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
                h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
                h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
                h_keep_alive_period: 0,
            }));
        }
        let mut stream = timeout(
            Duration::from_secs(3),
            client.connect_stream_with_connector(
                &Session::default(),
                Arc::new(MockClashResolver::new()),
                &DirectConnector::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        stream.write_all(b"probe").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0; 5];
        timeout(Duration::from_secs(3), stream.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"probe");
        assert!(client.h3_reuse_pool.lock().await.is_empty());
        drop(stream);
        timeout(Duration::from_secs(3), closed_rx)
            .await
            .expect("unpooled QUIC must close on last app stream Drop")
            .expect("server must see QUIC close");
        assert_eq!(client.reset_connection_pool().await.unwrap(), 0);
    }
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bw_cancel_unpooled_h3_after_sender_acquisition_closes_driver() {
    let (addr, remote_closed) = spawn_s04bv_observed_h3_server().await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".into(),
        port: addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".into(),
        alpn_protocols: vec!["h3".into()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
    };
    let client = Client::new(
        "127.0.0.1".into(),
        addr.port(),
        "/xhttp/".into(),
        None,
        HashMap::new(),
        true,
        XhttpMode::StreamOne,
        1_000_000,
        false,
        None,
        None,
    );
    let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let sender = super::acquire_h3_upload_sender(
            &client,
            &endpoint,
            &Session::default(),
            Arc::new(MockClashResolver::new()),
            &DirectConnector::new(),
            NetworkPoolContext::default(),
        )
        .await
        .unwrap();
        let socket = sender.active.socket.as_ref().unwrap().clone();
        assert!(acquired_tx.send(socket).is_ok());
        let _sender = sender;
        std::future::pending::<()>().await;
    });
    let socket = timeout(Duration::from_secs(3), acquired_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(!socket.retired.load(Ordering::Acquire));
    task.abort();
    assert!(
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .expect_err("cancelled H3 sender task must be dropped")
            .is_cancelled()
    );
    assert!(socket.retired.load(Ordering::Acquire));
    assert_eq!(socket.active.load(Ordering::Acquire), 0);
    timeout(Duration::from_secs(3), remote_closed)
        .await
        .expect("unpooled sender cancellation must close real QUIC")
        .expect("server should observe connection close");
    timeout(Duration::from_secs(3), async {
        while !socket.driver_finished.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("unpooled sender cancellation must stop driver");
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bw_unpooled_separate_h3_upload_download_close_after_stream_drop() {
    let (upload_addr, upload_closed) = spawn_s04bv_observed_h3_server().await;
    let (download_addr, download_closed) = spawn_s04bv_observed_h3_server().await;
    let upload = XhttpEndpointConfig {
        server: "127.0.0.1".into(),
        port: upload_addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".into(),
        alpn_protocols: vec!["h3".into()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
    };
    let download = XhttpDownloadConfig {
        server: "127.0.0.1".into(),
        port: download_addr.port(),
        path: "/download/".into(),
        host: None,
        headers: HashMap::new(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".into(),
        alpn_protocols: vec!["h3".into()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
        reuse_policy: None,
    };
    let client = Client::new(
        "127.0.0.1".into(),
        upload_addr.port(),
        "/upload/".into(),
        None,
        HashMap::new(),
        true,
        XhttpMode::StreamUp,
        1_000_000,
        false,
        None,
        Some(download),
    )
    .with_upload_endpoint(Some(upload))
    .with_http_version(XhttpHttpVersion::Http3);
    let stream = timeout(
        Duration::from_secs(3),
        client.connect_stream_with_connector(
            &Session::default(),
            Arc::new(MockClashResolver::new()),
            &DirectConnector::new(),
        ),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert!(client.h3_reuse_pool.lock().await.is_empty());
    assert!(client.h3_download_reuse_pool.lock().await.is_empty());
    drop(stream);
    for closed in [upload_closed, download_closed] {
        timeout(Duration::from_secs(3), closed)
            .await
            .expect("each physical QUIC path must be closed")
            .expect("remote must observe QUIC close");
    }
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bw_unpooled_upload_closes_if_download_endpoint_rejects_tls() {
    let (upload_addr, upload_closed) = spawn_s04bv_observed_h3_server().await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".into(),
        port: upload_addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".into(),
        alpn_protocols: vec!["h3".into()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
    };
    let invalid_download = XhttpDownloadConfig {
        server: "127.0.0.1".into(),
        port: 443,
        path: "/download/".into(),
        host: None,
        headers: HashMap::new(),
        security: XhttpSecurity::None,
        server_name: "xhttp.example.com".into(),
        alpn_protocols: vec!["h3".into()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
        reuse_policy: None,
    };
    let client = Client::new(
        "127.0.0.1".into(),
        upload_addr.port(),
        "/upload/".into(),
        None,
        HashMap::new(),
        true,
        XhttpMode::StreamUp,
        1_000_000,
        false,
        None,
        Some(invalid_download),
    )
    .with_upload_endpoint(Some(endpoint))
    .with_http_version(XhttpHttpVersion::Http3);
    let err = timeout(
        Duration::from_secs(3),
        client.connect_stream_with_connector(
            &Session::default(),
            Arc::new(MockClashResolver::new()),
            &DirectConnector::new(),
        ),
    )
    .await
    .unwrap()
    .err()
    .expect("download setup must fail closed");
    assert!(
        err.to_string().contains("standard TLS security only"),
        "{err}"
    );
    timeout(Duration::from_secs(3), upload_closed)
        .await
        .expect("failed downlink must close already-opened upload QUIC")
        .expect("remote upload must observe QUIC close");
    assert!(client.h3_reuse_pool.lock().await.is_empty());
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bv_h3_pool_registration_abort_closes_unpublished_driver() {
    let (addr, closed_rx) = spawn_s04bv_observed_h3_server().await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".into(),
        port: addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".into(),
        alpn_protocols: vec!["h3".into()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
    };
    let (sender, _, socket) = timeout(
        Duration::from_secs(3),
        super::connect_h3_sender(
            &endpoint,
            &Session::default(),
            Arc::new(MockClashResolver::new()),
            &DirectConnector::new(),
            Some(0),
            NetworkPoolContext::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let socket_state = socket.clone();
    let client = Arc::new(Client::new(
        "127.0.0.1".into(),
        addr.port(),
        "/xhttp/".into(),
        None,
        HashMap::new(),
        true,
        XhttpMode::StreamOne,
        1_000_000,
        false,
        None,
        None,
    ));
    let gate = client.h3_reuse_pool.lock().await;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let pool_owner = client.clone();
    let registration = tokio::spawn(async move {
        let _sender = sender;
        let pending = super::H3PoolRegistration(Some(socket));
        entered_tx.send(()).unwrap();
        let _write = pool_owner.h3_reuse_pool.lock().await;
        pending.complete();
    });
    timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    registration.abort();
    assert!(
        timeout(Duration::from_secs(3), registration)
            .await
            .unwrap()
            .expect_err("pending pool write should be cancelled")
            .is_cancelled()
    );
    drop(gate);
    assert!(client.h3_reuse_pool.lock().await.is_empty());
    assert!(socket_state.retired.load(Ordering::Acquire));
    assert_eq!(socket_state.active.load(Ordering::Acquire), 0);
    timeout(Duration::from_secs(3), closed_rx)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(3), async {
        while !socket_state.driver_finished.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled registration must also stop the HTTP/3 driver");
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bv_h3_pool_retirement_closes_udp_after_last_active_stream() {
    for keep_active_at_reset in [true, false] {
        let (addr, mut remote_closed) = spawn_s04bv_observed_h3_server().await;
        let endpoint = XhttpEndpointConfig {
            server: "127.0.0.1".into(),
            port: addr.port(),
            security: XhttpSecurity::Tls,
            server_name: "xhttp.example.com".into(),
            alpn_protocols: vec!["h3".into()],
            skip_cert_verify: true,
            fingerprint: None,
            verify_name: None,
            tls_cert: None,
            tls_key: None,
            reality: None,
        };
        let client = Client::new(
            "127.0.0.1".into(),
            addr.port(),
            "/xhttp/".into(),
            None,
            HashMap::new(),
            true,
            XhttpMode::StreamOne,
            1_000_000,
            false,
            None,
            None,
        )
        .with_upload_endpoint(Some(endpoint))
        .with_http_version(XhttpHttpVersion::Http3)
        .with_reuse_policy(Some(XhttpReusePolicy {
            max_concurrency: Some(XhttpReuseValueRange { min: 2, max: 2 }),
            max_connections: None,
            c_max_reuse_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
            h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
            h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
            h_keep_alive_period: 0,
        }));
        let mut app = timeout(
            Duration::from_secs(3),
            client.connect_stream_with_connector(
                &Session::default(),
                Arc::new(MockClashResolver::new()),
                &DirectConnector::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        app.write_all(b"start").await.unwrap();
        app.flush().await.unwrap();
        let mut reply = [0; 5];
        timeout(Duration::from_secs(3), app.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"start");
        let socket = client.h3_reuse_pool.lock().await[0].socket.clone();
        assert_eq!(socket.active.load(Ordering::Acquire), 1);
        let mut app = Some(app);
        if !keep_active_at_reset {
            drop(app.take());
            assert_eq!(socket.active.load(Ordering::Acquire), 0);
        }
        assert_eq!(client.reset_connection_pool().await.unwrap(), 1);
        assert!(socket.retired.load(Ordering::Acquire));
        assert!(client.h3_reuse_pool.lock().await.is_empty());
        if keep_active_at_reset {
            // Retirement is only a future-reuse barrier, not permission
            // to break an application stream still in use.
            assert!(
                timeout(Duration::from_millis(50), &mut remote_closed)
                    .await
                    .is_err(),
                "healthy active stream closed during retirement"
            );
            let stream = app.as_mut().expect("active app stream exists");
            stream.write_all(b"live!").await.unwrap();
            stream.flush().await.unwrap();
            let mut next = [0; 5];
            timeout(Duration::from_secs(3), stream.read_exact(&mut next))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&next, b"live!");
            drop(app.take());
        }
        let _closed = timeout(Duration::from_secs(3), remote_closed)
            .await
            .expect("remote QUIC connection must close after retirement")
            .expect("remote closure observer must report");
        timeout(Duration::from_secs(3), async {
            while !socket.driver_finished.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("H3 driver task must finish after idle pool retirement");
        assert_eq!(socket.active.load(Ordering::Acquire), 0);
    }
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bu_abort_after_quic_handshake_closes_uncommitted_socket() {
    use super::{PendingH3Socket, TlsClient};
    use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
    use tokio::sync::oneshot;

    crate::setup_default_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["xhttp.example.com".to_owned()])
            .unwrap();
    let cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
            .unwrap();
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
    ));
    let server =
        Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let remote = server.local_addr().unwrap();
    let (closed_tx, closed_rx) = oneshot::channel();
    tokio::spawn(async move {
        let incoming = server.accept().await.expect("QUIC connection expected");
        let connection = incoming.await.expect("QUIC handshake expected");
        let error = connection.closed().await;
        closed_tx.send(error).ok();
    });

    let tls = TlsClient::new_with_fingerprint(
        true,
        "xhttp.example.com".to_owned(),
        Some(vec!["h3".to_owned()]),
        Some("h3".to_owned()),
        None,
    );
    let mut client_tls = tls.rustls_client_config().unwrap();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(client_tls).unwrap();
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint
        .set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(remote, "xhttp.example.com").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _setup = PendingH3Socket::new(endpoint, connection);
        ready_tx.send(()).unwrap();
        // Simulate HTTP/3 driver construction suspended after TLS/QUIC
        // completed. Cancelling this task must close the real UDP socket.
        std::future::pending::<()>().await;
    });
    timeout(Duration::from_secs(2), ready_rx)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .expect_err("cancelled setup must not finish")
            .is_cancelled()
    );
    let closed = timeout(Duration::from_secs(3), closed_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(
        closed.to_string().contains("closed")
            || closed.to_string().contains("application"),
        "QUIC server should observe cancellation: {closed}"
    );
}

#[cfg(feature = "xhttp-h3")]
#[test]
fn s04bu_h3_unreported_socket_does_not_bypass_explicit_path_candidates() {
    use crate::app::flow::{AddressFamily, InterfaceId, NetworkPathId};
    let path = NetworkPathId {
        interface: InterfaceId {
            name: "expected0".into(),
            index: 7,
        },
        family: AddressFamily::Ipv4,
        source_address: Some("192.0.2.70".parse().unwrap()),
        network_generation: 12,
    };
    let current = NetworkPoolContext {
        network_generation: Some(12),
        eligible_path_ids: Some([path].into_iter().collect()),
        ..Default::default()
    };
    // A QUIC socket without reported network_path_id is not equivalent
    // to a verified candidate, even if the generation number matches.
    assert!(!current.permits(Some(12), None));
    assert!(NetworkPoolContext::for_generation(Some(12)).permits(Some(12), None));
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bt_abort_between_h3_sender_acquisition_and_handoff_releases_both_slots()
{
    let (upload_addr, download_addr, _unused_capture) =
        spawn_h3_download_settings_servers().await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".to_owned(),
        port: upload_addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
    };
    let reuse_policy = XhttpReusePolicy {
        max_concurrency: Some(XhttpReuseValueRange { min: 1, max: 1 }),
        max_connections: None,
        c_max_reuse_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_keep_alive_period: 0,
    };
    let download = XhttpDownloadConfig {
        server: "127.0.0.1".to_owned(),
        port: download_addr.port(),
        path: "/download/".to_owned(),
        host: None,
        headers: HashMap::new(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
        reuse_policy: Some(reuse_policy.clone()),
    };
    let client = Arc::new(
        Client::new(
            "127.0.0.1".to_owned(),
            upload_addr.port(),
            "/upload/".to_owned(),
            None,
            HashMap::new(),
            true,
            XhttpMode::StreamUp,
            1_000_000,
            false,
            None,
            Some(download.clone()),
        )
        .with_upload_endpoint(Some(endpoint.clone()))
        .with_http_version(XhttpHttpVersion::Http3)
        .with_reuse_policy(Some(reuse_policy)),
    );
    let resolver = Arc::new(MockClashResolver::new());
    let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
    let borrower = client.clone();
    let task = tokio::spawn(async move {
        let connector = DirectConnector::new();
        let sess = Session::default();
        let upload = super::acquire_h3_upload_sender(
            &borrower,
            &endpoint,
            &sess,
            resolver.clone(),
            &connector,
            NetworkPoolContext::default(),
        )
        .await
        .unwrap();
        let downlink = super::acquire_h3_download_sender(
            &borrower,
            &download,
            &sess,
            resolver,
            &connector,
            NetworkPoolContext::default(),
        )
        .await
        .unwrap();
        // Both physical QUIC connections are acquired, but neither
        // logical HTTP/3 stream has been delivered to a caller.
        acquired_tx.send(()).unwrap();
        let _upload = upload;
        let _download = downlink;
        std::future::pending::<()>().await;
    });
    timeout(Duration::from_secs(5), acquired_rx)
        .await
        .unwrap()
        .unwrap();
    let upload_active = client.h3_reuse_pool.lock().await[0].active.clone();
    let download_active =
        client.h3_download_reuse_pool.lock().await[0].active.clone();
    assert_eq!(upload_active.load(Ordering::Acquire), 1);
    assert_eq!(download_active.load(Ordering::Acquire), 1);
    task.abort();
    let err = timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .expect_err("borrower must be cancelled");
    assert!(err.is_cancelled());
    assert_eq!(
        upload_active.load(Ordering::Acquire),
        0,
        "abort must release upload slot before logical handoff"
    );
    assert_eq!(
        download_active.load(Ordering::Acquire),
        0,
        "abort must release download slot before logical handoff"
    );
    // Explicit pool retirement still owns socket/driver cleanup.
    assert_eq!(client.reset_connection_pool().await.unwrap(), 2);
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn s04bt_failed_h3_downlink_setup_releases_previously_acquired_upload() {
    let upload_addr = spawn_h3_stream_one_echo_server(0).await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".to_owned(),
        port: upload_addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
    };
    let reuse_policy = XhttpReusePolicy {
        max_concurrency: Some(XhttpReuseValueRange { min: 1, max: 1 }),
        max_connections: None,
        c_max_reuse_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_keep_alive_period: 0,
    };
    let download = XhttpDownloadConfig {
        server: "127.0.0.1".to_owned(),
        port: 443,
        path: "/download/".to_owned(),
        host: None,
        headers: HashMap::new(),
        // Downlink must fail synchronously *after* successful upload dial.
        security: XhttpSecurity::None,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
        reuse_policy: Some(reuse_policy.clone()),
    };
    let client = Client::new(
        "127.0.0.1".to_owned(),
        upload_addr.port(),
        "/upload/".to_owned(),
        None,
        HashMap::new(),
        true,
        XhttpMode::StreamUp,
        1_000_000,
        false,
        None,
        Some(download),
    )
    .with_upload_endpoint(Some(endpoint))
    .with_http_version(XhttpHttpVersion::Http3)
    .with_reuse_policy(Some(reuse_policy));
    let result = timeout(
        Duration::from_secs(5),
        client.connect_stream_with_connector(
            &Session::default(),
            Arc::new(MockClashResolver::new()),
            &DirectConnector::new(),
        ),
    )
    .await
    .unwrap();
    let err = result
        .err()
        .expect("invalid HTTP/3 download must fail closed");
    assert!(
        err.to_string().contains("standard TLS security only"),
        "{err}"
    );
    let pool = client.h3_reuse_pool.lock().await;
    assert_eq!(pool.len(), 1, "upload QUIC sender was actually acquired");
    assert_eq!(
        pool[0].active.load(Ordering::Acquire),
        0,
        "failed second endpoint cannot strand upload capacity"
    );
    drop(pool);
    assert_eq!(client.reset_connection_pool().await.unwrap(), 1);
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn xhttp_http3_reuses_separate_download_connection() {
    let addr = spawn_h3_stream_one_echo_server(2).await;
    let reuse_policy = XhttpReusePolicy {
        max_concurrency: Some(XhttpReuseValueRange { min: 1, max: 1 }),
        max_connections: None,
        c_max_reuse_times: Some(XhttpReuseValueRange { min: 2, max: 2 }),
        h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_keep_alive_period: 0,
    };
    let download = XhttpDownloadConfig {
        server: "127.0.0.1".to_owned(),
        port: addr.port(),
        path: "/xhttp/".to_owned(),
        host: None,
        headers: HashMap::new(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
        skip_cert_verify: true,
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
        "/upload/".to_owned(),
        None,
        HashMap::new(),
        true,
        XhttpMode::StreamUp,
        1_000_000,
        false,
        None,
        Some(download.clone()),
    );
    let resolver = Arc::new(MockClashResolver::new());
    let connector = DirectConnector::new();
    let session = Session::default();

    async fn roundtrip(
        mut lease: super::H3DownlinkSender,
        addr: std::net::SocketAddr,
    ) {
        super::count_h3_request(lease.request_count.as_ref());
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_3)
            .uri(format!("https://127.0.0.1:{}/xhttp/", addr.port()))
            .body(())
            .unwrap();
        let mut stream = lease
            .sender
            .send_request(request)
            .await
            .expect("pooled H3 request should send");
        stream
            .finish()
            .await
            .expect("pooled H3 request should finish");
        let response = stream
            .recv_response()
            .await
            .expect("pooled H3 response should arrive");
        assert_eq!(response.status(), StatusCode::OK);
        while stream
            .recv_data()
            .await
            .expect("pooled H3 response body should drain")
            .is_some()
        {}
        // The sender's H3ActiveLease is released with the sender here.
    }

    let first = super::acquire_h3_download_sender(
        &client,
        &download,
        &session,
        resolver.clone(),
        &connector,
        NetworkPoolContext::default(),
    )
    .await
    .expect("first H3 download sender should connect");
    roundtrip(first, addr).await;

    let second = super::acquire_h3_download_sender(
        &client,
        &download,
        &session,
        resolver,
        &connector,
        NetworkPoolContext::default(),
    )
    .await
    .expect("second H3 download sender should reuse");
    roundtrip(second, addr).await;

    let pool = client.h3_download_reuse_pool.lock().await;
    assert_eq!(pool.len(), 1);
    assert_eq!(pool[0].reuse_count, 1);
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn xhttp_http3_stream_up_uses_separate_download_settings() {
    let (upload_addr, download_addr, upload_body) =
        spawn_h3_download_settings_servers().await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".to_owned(),
        port: upload_addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
    };
    let reuse_policy = XhttpReusePolicy {
        max_concurrency: Some(XhttpReuseValueRange { min: 2, max: 2 }),
        max_connections: None,
        c_max_reuse_times: Some(XhttpReuseValueRange { min: 2, max: 2 }),
        h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_keep_alive_period: 0,
    };
    let download = XhttpDownloadConfig {
        server: "127.0.0.1".to_owned(),
        port: download_addr.port(),
        path: "/download/".to_owned(),
        host: None,
        headers: HashMap::new(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
        skip_cert_verify: true,
        fingerprint: None,
        verify_name: None,
        tls_cert: None,
        tls_key: None,
        reality: None,
        reuse_policy: Some(reuse_policy.clone()),
    };
    let client = Client::new(
        "127.0.0.1".to_owned(),
        upload_addr.port(),
        "/upload/".to_owned(),
        None,
        HashMap::new(),
        true,
        XhttpMode::StreamUp,
        1_000_000,
        false,
        None,
        Some(download),
    )
    .with_upload_endpoint(Some(endpoint))
    .with_http_version(XhttpHttpVersion::Http3)
    .with_reuse_policy(Some(reuse_policy));
    let resolver = Arc::new(MockClashResolver::new());
    let connector = DirectConnector::new();
    let mut proxied = client
        .connect_stream_with_connector(&Session::default(), resolver, &connector)
        .await
        .expect("HTTP/3 split-endpoint dial should succeed")
        .expect("HTTP/3 split-endpoint should return a logical stream");

    proxied
        .write_all(b"up-h3")
        .await
        .expect("HTTP/3 split-endpoint upload should write");
    proxied.flush().await.expect("HTTP/3 upload should flush");
    let mut buf = [0u8; 7];
    timeout(Duration::from_secs(3), proxied.read_exact(&mut buf))
        .await
        .expect("HTTP/3 download-settings read timed out")
        .expect("HTTP/3 download-settings read failed");
    assert_eq!(&buf, b"down-h3");
    assert_eq!(client.h3_reuse_pool.lock().await.len(), 1);
    assert_eq!(client.h3_download_reuse_pool.lock().await.len(), 1);

    proxied
        .shutdown()
        .await
        .expect("HTTP/3 upload should close");
    let uploaded = timeout(Duration::from_secs(3), upload_body)
        .await
        .expect("HTTP/3 upload capture timed out")
        .expect("HTTP/3 upload capture sender dropped");
    assert_eq!(uploaded, b"up-h3");
    assert_eq!(
        client.h3_reuse_pool.lock().await[0]
            .active
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(
        client.h3_download_reuse_pool.lock().await[0]
            .active
            .load(Ordering::Acquire),
        1
    );
    drop(proxied);
    assert_eq!(
        client.h3_reuse_pool.lock().await[0]
            .active
            .load(Ordering::Acquire),
        0,
        "upload reservation must end when application releases stream"
    );
    assert_eq!(
        client.h3_download_reuse_pool.lock().await[0]
            .active
            .load(Ordering::Acquire),
        0,
        "download reservation must not remain owned by a stalled QUIC task"
    );
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn xhttp_http3_stream_up_echoes_streaming_post() {
    let addr = spawn_h3_stream_up_echo_server().await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".to_owned(),
        port: addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
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
        XhttpMode::StreamUp,
        1_000_000,
        false,
        None,
        None,
    )
    .with_upload_endpoint(Some(endpoint))
    .with_http_version(XhttpHttpVersion::Http3);
    let resolver = Arc::new(MockClashResolver::new());
    let connector = DirectConnector::new();
    let mut proxied = client
        .connect_stream_with_connector(&Session::default(), resolver, &connector)
        .await
        .expect("HTTP/3 stream-up dial should succeed")
        .expect("HTTP/3 stream-up should return a logical stream");

    proxied
        .write_all(b"stream-h3")
        .await
        .expect("HTTP/3 stream-up write");
    proxied.flush().await.expect("HTTP/3 stream-up flush");
    let mut buf = [0u8; 9];
    timeout(Duration::from_secs(3), proxied.read_exact(&mut buf))
        .await
        .expect("HTTP/3 stream-up echo timed out")
        .expect("HTTP/3 stream-up read failed");
    assert_eq!(&buf, b"stream-h3");
}

#[cfg(feature = "xhttp-h3")]
#[tokio::test]
async fn xhttp_http3_packet_up_echoes_sequenced_posts() {
    let addr = spawn_h3_packet_up_echo_server().await;
    let endpoint = XhttpEndpointConfig {
        server: "127.0.0.1".to_owned(),
        port: addr.port(),
        security: XhttpSecurity::Tls,
        server_name: "xhttp.example.com".to_owned(),
        alpn_protocols: vec!["h3".to_owned()],
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
        4,
        false,
        None,
        None,
    )
    .with_upload_endpoint(Some(endpoint))
    .with_http_version(XhttpHttpVersion::Http3);
    let resolver = Arc::new(MockClashResolver::new());
    let connector = DirectConnector::new();
    let mut proxied = client
        .connect_stream_with_connector(&Session::default(), resolver, &connector)
        .await
        .expect("HTTP/3 packet-up dial should succeed")
        .expect("HTTP/3 packet-up should return a logical stream");

    proxied
        .write_all(b"packet-h3")
        .await
        .expect("HTTP/3 packet-up write");
    proxied.flush().await.expect("HTTP/3 packet-up flush");
    let mut buf = [0u8; 9];
    timeout(Duration::from_secs(3), proxied.read_exact(&mut buf))
        .await
        .expect("HTTP/3 packet-up echo timed out")
        .expect("HTTP/3 packet-up read failed");
    assert_eq!(&buf, b"packet-h3");
}

#[tokio::test]
async fn s04br_xhttp_pool_waiter_is_cancelled_on_network_reset() {
    let client = Arc::new(Client::new(
        "localhost".into(),
        80,
        "/xhttp/".into(),
        None,
        HashMap::new(),
        false,
        XhttpMode::StreamOne,
        1_000_000,
        false,
        None,
        None,
    ));
    let gate = client.recovery_gate.write().await;
    let old = client.recovery_cancellation.lock().await.clone();
    let borrowing = client.clone();
    let task = tokio::spawn(async move { borrowing.try_reuse_stream().await });
    tokio::task::yield_now().await;
    let resetting = client.clone();
    let reset = tokio::spawn(async move { resetting.reset_connection_pool().await });
    timeout(Duration::from_secs(2), old.cancelled())
        .await
        .expect("reset must cancel outstanding borrows");
    drop(gate);
    let error = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .err()
        .expect("cancelled pool borrow must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    timeout(Duration::from_secs(2), reset)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!client.recovery_cancellation.lock().await.is_cancelled());
}

#[tokio::test]
async fn network_reset_cancels_stalled_xhttp_construction() {
    let client = std::sync::Arc::new(Client::new(
        "localhost".into(),
        80,
        "/xhttp/".into(),
        None,
        HashMap::new(),
        false,
        XhttpMode::StreamOne,
        1_000_000,
        false,
        None,
        None,
    ));
    let (stream, _silent_peer) = tokio::io::duplex(65536);
    let constructing = client.clone();
    let task =
        tokio::spawn(
            async move { constructing.proxy_stream(Box::new(stream)).await },
        );
    timeout(Duration::from_secs(2), async {
        while client.recovery_gate.try_write().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("construction did not start");
    timeout(Duration::from_secs(2), client.reset_connection_pool())
        .await
        .expect("reset must cancel construction before waiting for its lock")
        .unwrap();
    let result = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(result, Err(error) if error.kind() == std::io::ErrorKind::ConnectionAborted)
    );
    assert!(!client.recovery_cancellation.lock().await.is_cancelled());
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
async fn s04bs_xhttp_aborted_h2_reuse_releases_active_capacity() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicU64::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered_tx)));
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let service = hyper::service::service_fn(move |request| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            let entered = entered.clone();
            async move {
                if n == 0 {
                    handle_stream_one(request).await
                } else {
                    if let Some(tx) = entered.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    // Hold the HTTP response open after the client has
                    // already reserved an active pooled stream slot.
                    std::future::pending::<
                        Result<Response<BoxBody<Bytes, Infallible>>, Infallible>,
                    >()
                    .await
                }
            }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .http2_only()
            .serve_connection(TokioIo::new(tcp), service)
            .await;
    });
    let client = Arc::new(
        Client::new(
            "127.0.0.1".into(),
            addr.port(),
            "/xhttp/".into(),
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
            max_concurrency: Some(XhttpReuseValueRange { min: 2, max: 2 }),
            max_connections: None,
            c_max_reuse_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
            h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
            h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
            h_keep_alive_period: 0,
        })),
    );
    let raw = TcpStream::connect(addr).await.unwrap();
    let first = client.proxy_stream(Box::new(raw)).await.unwrap();
    drop(first);
    let active = client.reuse_pool.lock().await[0].active.clone();
    assert_eq!(active.load(Ordering::Acquire), 0);
    let borrower = client.clone();
    let task = tokio::spawn(async move { borrower.try_reuse_stream().await });
    timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.load(Ordering::Acquire), 1);
    task.abort();
    let cancelled = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .err()
        .expect("aborted pool borrow must not return a logical stream");
    assert!(cancelled.is_cancelled());
    assert_eq!(
        active.load(Ordering::Acquire),
        0,
        "cancelled HTTP/2 stream construction must release reserved capacity"
    );
}

#[tokio::test]
async fn xhttp_h2_pool_rejects_a_connection_from_an_older_network_generation() {
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
        c_max_reuse_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_request_times: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_max_reusable_secs: Some(XhttpReuseValueRange { min: 0, max: 0 }),
        h_keep_alive_period: 0,
    }));

    let path_a = crate::app::flow::NetworkPathId {
        interface: crate::app::flow::InterfaceId {
            name: "wifi0".to_owned(),
            index: 4,
        },
        family: crate::app::flow::AddressFamily::Ipv4,
        source_address: Some("192.0.2.10".parse().unwrap()),
        network_generation: 20,
    };
    let path_b = crate::app::flow::NetworkPathId {
        interface: crate::app::flow::InterfaceId {
            name: "eth0".to_owned(),
            index: 5,
        },
        family: crate::app::flow::AddressFamily::Ipv4,
        source_address: Some("198.51.100.10".parse().unwrap()),
        network_generation: 20,
    };
    let both_paths = crate::proxy::utils::NetworkPoolContext {
        network_generation: Some(20),
        path_id: Some(path_a.clone()),
        eligible_path_ids: Some(
            [path_a.clone(), path_b.clone()].into_iter().collect(),
        ),
        reporter: None,
    };

    let raw = TcpStream::connect(addr)
        .await
        .expect("client should connect");
    let mut first = client
        .proxy_stream_with_pool_context(Box::new(raw), both_paths.clone())
        .await
        .expect("first logical stream should connect");
    first
        .write_all(b"epoch")
        .await
        .expect("write should succeed");
    first.flush().await.expect("flush should succeed");
    let mut response = [0u8; 5];
    timeout(Duration::from_secs(2), first.read_exact(&mut response))
        .await
        .expect("response timeout")
        .expect("response should be readable");
    assert_eq!(&response, b"epoch");
    drop(first);

    let (mut same_generation, reused_context) = client
        .try_reuse_stream_with_pool_metadata(both_paths)
        .await
        .expect("same generation lookup should succeed")
        .expect("same generation should reuse the pooled connection");
    assert_eq!(reused_context.path_id.as_ref(), Some(&path_a));
    same_generation
        .write_all(b"epoch2")
        .await
        .expect("same-generation write should succeed");
    same_generation
        .flush()
        .await
        .expect("same-generation flush should succeed");
    let mut same_response = [0u8; 6];
    timeout(
        Duration::from_secs(2),
        same_generation.read_exact(&mut same_response),
    )
    .await
    .expect("same-generation response timeout")
    .expect("same-generation response should be readable");
    assert_eq!(&same_response, b"epoch2");
    drop(same_generation);

    let only_path_b = crate::proxy::utils::NetworkPoolContext {
        network_generation: Some(20),
        path_id: None,
        eligible_path_ids: Some([path_b].into_iter().collect()),
        reporter: None,
    };
    assert!(
        client
            .try_reuse_stream_with_pool_context(only_path_b)
            .await
            .expect("path eligibility lookup should succeed")
            .is_none(),
        "an H2 connection tagged with path A must be retired when only path B remains eligible"
    );
    assert!(client.reuse_pool.lock().await.is_empty());

    assert!(
        client
            .try_reuse_stream_for_network_generation(Some(21))
            .await
            .expect("stale generation lookup should succeed")
            .is_none(),
        "a connection created on generation 20 must not be borrowed on generation 21"
    );
    assert!(client.reuse_pool.lock().await.is_empty());
}

#[tokio::test]
async fn xhttp_max_connections_opens_fresh_until_limit_then_reuses() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener should expose addr");

    tokio::spawn(async move {
        for _ in 0..2 {
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let service = hyper::service::service_fn(handle_stream_one);
                let builder = auto::Builder::new(TokioExecutor::new()).http2_only();
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
            open_separate_downlink_response(&client, download, session_id, None),
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
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
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
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
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
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
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
                assert_eq!(values[0].as_deref(), Some("application/octet-stream"));
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
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
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
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
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
            let (tcp, _) = listener.accept().await.expect("accept should succeed");
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
