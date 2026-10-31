#![cfg(all(feature = "trojan", any(feature = "ring", feature = "aws-lc-rs")))]

use bytes::Bytes;
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use sha2::{Digest, Sha224};
use std::{
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

mod common;

use common::{
    ClashInstance, Socks5UdpSession, send_http_request,
    wait_for_initial_network_recovery,
};

const PASSWORD: &str = "local-trojan-explain-test-password";

fn available_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

async fn socks5_connect(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("failed to connect to SOCKS5 listener");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("failed to send SOCKS5 greeting");
    let mut greeting = [0; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("failed to read SOCKS5 greeting response");
    assert_eq!(greeting, [0x05, 0x00]);

    stream
        .write_all(&[
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            (target_port >> 8) as u8,
            target_port as u8,
        ])
        .await
        .expect("failed to send SOCKS5 CONNECT request");
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .expect("failed to read SOCKS5 CONNECT response");
    assert_eq!(header[1], 0x00, "SOCKS5 CONNECT was rejected");
    let remaining = match header[3] {
        0x01 => 6,
        0x04 => 18,
        atyp => panic!("unexpected SOCKS5 response address type {atyp}"),
    };
    let mut address = vec![0; remaining];
    stream
        .read_exact(&mut address)
        .await
        .expect("failed to read SOCKS5 bound address");
    stream
}

async fn get_api_json(api_port: u16, path: &str) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build API GET request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send API GET request");
    assert_eq!(response.status(), http::StatusCode::OK, "GET {path}");
    let body = response
        .collect()
        .await
        .expect("failed to collect API GET response")
        .to_bytes();
    serde_json::from_slice(&body).expect("failed to parse API GET JSON")
}

async fn trojan_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    target_port: u16,
) {
    let (tcp, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("timed out accepting Trojan TLS connection")
        .expect("failed to accept Trojan TLS connection");
    let mut tls = timeout(Duration::from_secs(5), acceptor.accept(tcp))
        .await
        .expect("timed out completing Trojan TLS handshake")
        .expect("Trojan TLS handshake failed");

    let mut auth = [0; 56];
    tls.read_exact(&mut auth)
        .await
        .expect("failed to read Trojan password hash");
    let expected_auth = Sha224::digest(PASSWORD.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");
    assert_eq!(std::str::from_utf8(&auth).unwrap(), expected_auth);
    let mut separator = [0; 2];
    tls.read_exact(&mut separator)
        .await
        .expect("failed to read Trojan auth separator");
    assert_eq!(&separator, b"\r\n");
    assert_eq!(
        tls.read_u8().await.expect("failed to read Trojan command"),
        0x01
    );
    assert_eq!(
        tls.read_u8()
            .await
            .expect("failed to read Trojan address type"),
        0x01
    );
    let mut destination = [0; 6];
    tls.read_exact(&mut destination)
        .await
        .expect("failed to read Trojan destination");
    assert_eq!(&destination[..4], &[127, 0, 0, 1]);
    assert_eq!(
        u16::from_be_bytes([destination[4], destination[5]]),
        target_port
    );
    tls.read_exact(&mut separator)
        .await
        .expect("failed to read Trojan request separator");
    assert_eq!(&separator, b"\r\n");

    let mut request = Vec::new();
    loop {
        let mut chunk = [0; 512];
        let size = timeout(Duration::from_secs(5), tls.read(&mut chunk))
            .await
            .expect("timed out reading tunneled HTTP request")
            .expect("failed to read tunneled HTTP request");
        assert_ne!(size, 0, "client closed before sending HTTP request");
        request.extend_from_slice(&chunk[..size]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(request.len() < 4096, "HTTP request headers are too large");
    }
    assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
    tls.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\ntrojan-roundtrip",
    )
    .await
    .expect("failed to write tunneled HTTP response");
    tls.flush().await.expect("failed to flush HTTP response");
}

async fn read_trojan_ipv4_addr<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> SocketAddr {
    assert_eq!(stream.read_u8().await.unwrap(), 0x01);
    let mut ip = [0; 4];
    stream.read_exact(&mut ip).await.unwrap();
    let port = stream.read_u16().await.unwrap();
    SocketAddr::from((ip, port))
}

async fn trojan_udp_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    target_addr: SocketAddr,
) {
    let (tcp, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("timed out accepting Trojan UDP connection")
        .expect("failed to accept Trojan UDP connection");
    let mut tls = timeout(Duration::from_secs(5), acceptor.accept(tcp))
        .await
        .expect("timed out completing Trojan UDP TLS handshake")
        .expect("Trojan UDP TLS handshake failed");

    let mut auth = [0; 56];
    tls.read_exact(&mut auth)
        .await
        .expect("failed to read Trojan UDP password hash");
    let expected_auth = Sha224::digest(PASSWORD.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");
    assert_eq!(std::str::from_utf8(&auth).unwrap(), expected_auth);
    let mut separator = [0; 2];
    tls.read_exact(&mut separator).await.unwrap();
    assert_eq!(&separator, b"\r\n");
    assert_eq!(
        tls.read_u8().await.unwrap(),
        0x03,
        "expected Trojan UDP command"
    );
    assert_eq!(read_trojan_ipv4_addr(&mut tls).await, target_addr);
    tls.read_exact(&mut separator).await.unwrap();
    assert_eq!(&separator, b"\r\n");

    let framed_target = read_trojan_ipv4_addr(&mut tls).await;
    assert_eq!(framed_target, target_addr);
    let payload_len = usize::from(tls.read_u16().await.unwrap());
    tls.read_exact(&mut separator).await.unwrap();
    assert_eq!(&separator, b"\r\n");
    let mut payload = vec![0; payload_len];
    tls.read_exact(&mut payload).await.unwrap();

    let relay = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind Trojan UDP relay socket");
    relay
        .send_to(&payload, target_addr)
        .await
        .expect("failed to forward Trojan UDP payload");
    let mut response = [0; 2048];
    let (response_len, source_addr) =
        timeout(Duration::from_secs(5), relay.recv_from(&mut response))
            .await
            .expect("timed out waiting for UDP target response")
            .expect("failed to receive UDP target response");
    assert_eq!(source_addr, target_addr);

    let source_ip = match source_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("expected IPv4 UDP target"),
    };
    let mut frame = Vec::with_capacity(9 + response_len);
    frame.push(0x01);
    frame.extend_from_slice(&source_ip);
    frame.extend_from_slice(&source_addr.port().to_be_bytes());
    frame.extend_from_slice(&(response_len as u16).to_be_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(&response[..response_len]);
    tls.write_all(&frame)
        .await
        .expect("failed to write Trojan UDP response frame");
    tls.flush()
        .await
        .expect("failed to flush Trojan UDP response");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_trojan_tcp_flow_is_queryable_from_path_explain() {
    clash_lib::setup_default_crypto_provider();

    let client_api = available_port();
    let socks_port = available_port();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local Trojan server");
    let trojan_port = listener.local_addr().unwrap().port();
    let target_port = 38_421;

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("test certificate should generate");
    let cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
            .expect("test private key should serialize");
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("test TLS config should build");
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_config));
    let server_task = tokio::spawn(trojan_server(listener, acceptor, target_port));

    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{client_api}
secret: clash-rs
tun:
  enable: false
proxies:
  - name: trojan-out
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: {PASSWORD}
    sni: localhost
    skip-cert-verify: true
rules:
  - MATCH,trojan-out
"#
    );
    let _client = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![client_api, socks_port],
    )
    .expect("failed to start Trojan Explain client");

    let mut stream = socks5_connect(socks_port, target_port).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("failed to send HTTP request through Trojan");
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out reading Trojan response")
        .expect("failed to read Trojan response");
    server_task.await.expect("Trojan server task panicked");

    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("trojan-roundtrip"));

    let (flow, decision) = timeout(Duration::from_secs(5), async {
        loop {
            let flows = get_api_json(client_api, "/flows?include_closed=true").await;
            if let Some(flow) = flows.as_array().and_then(|records| {
                records.iter().find(|flow| {
                    flow["protocol"] == "tcp"
                        && flow["dstPort"].as_u64() == Some(u64::from(target_port))
                        && flow["flowIds"]
                            .as_array()
                            .is_some_and(|ids| !ids.is_empty())
                })
            }) {
                let flow = flow.clone();
                let flow_ids = flow["flowIds"]
                    .as_array()
                    .expect("tracked Trojan flow should expose IDs");
                let decisions =
                    get_api_json(client_api, "/runtime/network/path-decisions")
                        .await;
                if let Some(decision) = decisions.as_array().and_then(|records| {
                    records.iter().find(|decision| {
                        flow_ids.iter().any(|id| id == &decision["flowId"])
                            && decision["outcome"] == "connected"
                            && decision["route"]["outbound"] == "trojan-out"
                    })
                }) {
                    break (flow, decision.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Trojan Flow did not produce a connected Explain record");
    let flow_id = decision["flowId"]
        .as_str()
        .expect("Trojan Explain record should expose a flow ID");
    assert!(
        flow["flowIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == flow_id)
    );
    let detail = get_api_json(
        client_api,
        &format!("/runtime/network/path-decision/{flow_id}"),
    )
    .await;
    assert_eq!(detail, decision);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_trojan_udp_flow_is_queryable_from_path_explain() {
    clash_lib::setup_default_crypto_provider();

    let client_api = available_port();
    let socks_port = available_port();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local Trojan UDP server");
    let trojan_port = listener.local_addr().unwrap().port();
    let echo = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to start local UDP echo target");
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0; 2048];
        let (len, peer) = echo.recv_from(&mut buffer).await.unwrap();
        echo.send_to(&buffer[..len], peer).await.unwrap();
    });

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("test certificate should generate");
    let cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
            .expect("test private key should serialize");
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("test TLS config should build");
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_config));
    let server_task = tokio::spawn(trojan_udp_server(listener, acceptor, echo_addr));

    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{client_api}
secret: clash-rs
tun:
  enable: false
proxies:
  - name: trojan-udp-out
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: {PASSWORD}
    sni: localhost
    skip-cert-verify: true
    udp: true
rules:
  - MATCH,trojan-udp-out
"#
    );
    let _client = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![client_api, socks_port],
    )
    .expect("failed to start Trojan UDP client");

    wait_for_initial_network_recovery(client_api).await;
    let session = Socks5UdpSession::connect(socks_port).await;
    let payload = b"trojan-udp-roundtrip";
    session
        .send_ipv4(payload, [127, 0, 0, 1], echo_addr.port())
        .await;
    let (response, source) = timeout(Duration::from_secs(10), session.recv())
        .await
        .expect("timed out waiting for Trojan UDP response");
    assert_eq!(response, payload);
    assert_eq!(source, echo_addr.to_string());
    echo_task.await.expect("UDP echo task failed");
    server_task.await.expect("Trojan UDP server task failed");

    let (flow, decision) = timeout(Duration::from_secs(5), async {
        loop {
            let flows = get_api_json(client_api, "/flows?include_closed=true").await;
            if let Some(flow) = flows.as_array().and_then(|records| {
                records.iter().find(|flow| {
                    flow["protocol"] == "udp"
                        && flow["dstPort"].as_u64()
                            == Some(u64::from(echo_addr.port()))
                        && flow["flowIds"]
                            .as_array()
                            .is_some_and(|ids| !ids.is_empty())
                })
            }) {
                let flow = flow.clone();
                let flow_ids = flow["flowIds"]
                    .as_array()
                    .expect("tracked Trojan UDP flow should expose IDs");
                let decisions =
                    get_api_json(client_api, "/runtime/network/path-decisions")
                        .await;
                if let Some(decision) = decisions.as_array().and_then(|records| {
                    records.iter().find(|decision| {
                        flow_ids.iter().any(|id| id == &decision["flowId"])
                            && decision["outcome"] == "connected"
                            && decision["route"]["outbound"] == "trojan-udp-out"
                    })
                }) {
                    break (flow, decision.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Trojan UDP flow did not produce a connected Explain record");
    let flow_id = decision["flowId"]
        .as_str()
        .expect("Trojan UDP Explain record should expose a flow ID");
    assert!(
        flow["flowIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == flow_id)
    );
    let detail = get_api_json(
        client_api,
        &format!("/runtime/network/path-decision/{flow_id}"),
    )
    .await;
    assert_eq!(detail, decision);
}
