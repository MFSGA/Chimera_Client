#![cfg(all(feature = "tls", any(feature = "ring", feature = "aws-lc-rs")))]

use bytes::Bytes;
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{net::TcpListener as StdTcpListener, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

mod common;

use common::{ClashInstance, send_http_request};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

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

async fn vless_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    target_port: u16,
) {
    let (tcp, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("timed out accepting VLESS TLS connection")
        .expect("failed to accept VLESS TLS connection");
    let mut tls = timeout(Duration::from_secs(5), acceptor.accept(tcp))
        .await
        .expect("timed out completing VLESS TLS handshake")
        .expect("VLESS TLS handshake failed");

    let mut request_header = [0; 19];
    tls.read_exact(&mut request_header)
        .await
        .expect("failed to read VLESS request header");
    assert_eq!(request_header[0], 0, "VLESS version must be zero");
    assert_eq!(
        &request_header[1..17],
        uuid::Uuid::parse_str(UUID).unwrap().as_bytes()
    );
    assert_eq!(request_header[17], 0, "VLESS request add-ons must be empty");
    assert_eq!(request_header[18], 1, "VLESS command must be TCP");
    let target_port_bytes = tls
        .read_u16()
        .await
        .expect("failed to read VLESS target port")
        .to_be_bytes();
    assert_eq!(
        tls.read_u8()
            .await
            .expect("failed to read VLESS address type"),
        1,
        "VLESS target should use IPv4"
    );
    let mut target_ip = [0; 4];
    tls.read_exact(&mut target_ip)
        .await
        .expect("failed to read VLESS target");
    assert_eq!(&target_ip, &[127, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes(target_port_bytes), target_port);

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

    tls.write_all(&[0, 0])
        .await
        .expect("failed to write VLESS response header");
    tls.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nvless-roundtrip",
    )
    .await
    .expect("failed to write VLESS tunneled HTTP response");
    tls.flush().await.expect("failed to flush VLESS response");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_vless_tls_tcp_flow_is_queryable_from_path_explain() {
    clash_lib::setup_default_crypto_provider();

    let client_api = available_port();
    let socks_port = available_port();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local VLESS server");
    let vless_port = listener.local_addr().unwrap().port();
    let target_port = available_port();

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
    let server_task = tokio::spawn(vless_server(listener, acceptor, target_port));

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
  - name: vless-out
    type: vless
    server: 127.0.0.1
    port: {vless_port}
    uuid: {UUID}
    tls: true
    servername: localhost
    skip-cert-verify: true
rules:
  - MATCH,vless-out
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
    .expect("failed to start VLESS Explain client");

    let mut stream = socks5_connect(socks_port, target_port).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("failed to send HTTP request through VLESS");
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out reading VLESS response")
        .expect("failed to read VLESS response");
    server_task.await.expect("VLESS server task panicked");

    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("vless-roundtrip"));

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
                    .expect("tracked VLESS flow should expose IDs");
                let decisions =
                    get_api_json(client_api, "/runtime/network/path-decisions")
                        .await;
                if let Some(decision) = decisions.as_array().and_then(|records| {
                    records.iter().find(|decision| {
                        flow_ids.iter().any(|id| id == &decision["flowId"])
                            && decision["outcome"] == "connected"
                            && decision["route"]["outbound"] == "vless-out"
                    })
                }) {
                    break (flow, decision.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("VLESS Flow did not produce a connected Explain record");
    let flow_id = decision["flowId"]
        .as_str()
        .expect("VLESS Explain record should expose a flow ID");
    assert!(
        flow["flowIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id.as_str() == Some(flow_id))
    );
    let detail = get_api_json(
        client_api,
        &format!("/runtime/network/path-decision/{flow_id}"),
    )
    .await;
    assert_eq!(detail, decision);
}
