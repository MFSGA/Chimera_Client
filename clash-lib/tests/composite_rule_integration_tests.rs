use std::{net::TcpListener as StdTcpListener, path::PathBuf, time::Duration};

use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod common;

use common::{ClashInstance, Socks5UdpSession, send_http_request};

fn available_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

fn start_client() -> (ClashInstance, u16, u16) {
    let api_port = available_port();
    let socks_port = available_port();
    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: test-secret
tun:
  enable: false
rules:
  - "AND,((IP-CIDR,127.0.0.1/32),(NETWORK,TCP)),DIRECT"
  - "AND,((IP-CIDR,127.0.0.1/32),(NETWORK,UDP)),DIRECT"
  - MATCH,REJECT
"#
    );
    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let client = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start composite-rule client");
    (client, api_port, socks_port)
}

async fn socks5_connect(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("failed to connect to SOCKS5 listener");
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    let [port_hi, port_lo] = target_port.to_be_bytes();
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port_hi, port_lo])
        .await
        .unwrap();
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[1], 0x00, "SOCKS5 CONNECT was rejected");
    let remaining = match header[3] {
        0x01 => 6,
        0x04 => 18,
        atyp => panic!("unexpected SOCKS5 response address type {atyp}"),
    };
    let mut address = vec![0u8; remaining];
    stream.read_exact(&mut address).await.unwrap();
    stream
}

async fn rules(api_port: u16) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}/rules");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build rules request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to query rules API");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect rules response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse rules response")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn composite_rules_are_reported_by_api() {
    let (_client, api_port, _socks_port) = start_client();
    let json = rules(api_port).await;
    let rules = json["rules"].as_array().expect("rules should be an array");
    assert_eq!(rules[0]["type"], "AND");
    assert_eq!(rules[0]["proxy"], "DIRECT");
    assert_eq!(
        rules[0]["payload"],
        "((IP-CIDR,127.0.0.1/32),(NETWORK,TCP))"
    );
    assert_eq!(rules[1]["type"], "AND");
    assert_eq!(rules[1]["proxy"], "DIRECT");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn composite_tcp_rule_routes_matching_traffic() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local TCP target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buf = [0u8; 128];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
    });

    let (_client, _api_port, socks_port) = start_client();
    let mut stream = socks5_connect(socks_port, target_port).await;
    let payload = b"composite-tcp-route";
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("timed out waiting for TCP response")
        .expect("failed to read TCP response");
    assert_eq!(echoed, payload);
    target_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn composite_udp_rule_routes_matching_traffic() {
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local UDP target");
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (len, source) = target.recv_from(&mut buf).await.unwrap();
        target.send_to(&buf[..len], source).await.unwrap();
    });

    let (_client, _api_port, socks_port) = start_client();
    let session = Socks5UdpSession::connect(socks_port).await;
    let payload = b"composite-udp-route";
    session
        .send_ipv4(payload, [127, 0, 0, 1], target_port)
        .await;
    let (echoed, source) =
        tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .expect("timed out waiting for UDP response");
    assert_eq!(echoed, payload);
    assert_eq!(source, format!("127.0.0.1:{target_port}"));
}
