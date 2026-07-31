#![cfg(feature = "shadowsocks")]

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

const SERVER_KEY: &str = "3SYJ/f8nmVuzKvKglykRQDSgg10e/ADilkdRWrrY9HU=";
const USER1_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const USER2_KEY: &str = "AQIDAQIDAQIDAQIDAQIDAQIDAQIDAQIDAQIDAQIDAQID";

fn available_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

fn start_multiuser_pair() -> (ClashInstance, ClashInstance, u16, u16) {
    let server_api = available_port();
    let server_port = available_port();
    let client_api = available_port();
    let socks_port = available_port();
    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");

    let server_config = format!(
        r#"
allow-lan: false
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{server_api}
secret: test-secret
tun:
  enable: false
listeners:
  - name: shadowsocks-multiuser
    type: shadowsocks
    listen: 127.0.0.1
    port: {server_port}
    cipher: 2022-blake3-aes-256-gcm
    password: {SERVER_KEY}
    udp: true
    users:
      - name: user1
        password: {USER1_KEY}
      - name: user2
        password: {USER2_KEY}
rules:
  - MATCH,DIRECT
"#
    );
    let server = ClashInstance::start(
        Options {
            config: Config::Str(server_config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![server_api, server_port],
    )
    .expect("failed to start multi-user Shadowsocks server");

    let client_password = format!("{SERVER_KEY}:{USER1_KEY}");
    let client_config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{client_api}
tun:
  enable: false
proxies:
  - name: shadowsocks-user1
    type: ss
    server: 127.0.0.1
    port: {server_port}
    cipher: 2022-blake3-aes-256-gcm
    password: {client_password}
    udp: true
rules:
  - MATCH,shadowsocks-user1
"#
    );
    let client = ClashInstance::start(
        Options {
            config: Config::Str(client_config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![client_api, socks_port],
    )
    .expect("failed to start user1 Shadowsocks client");

    (server, client, server_api, socks_port)
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

async fn spawn_udp_echo() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind UDP echo target");
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (len, source) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&buf[..len], source).await.unwrap();
    });
    port
}

async fn user_stats(api_port: u16) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}/user-stats");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build user-stats request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to query user stats");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect user-stats response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse user-stats response")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn ss2022_tcp_attributes_traffic_to_authenticated_user() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local TCP target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = [0u8; 128];
        let n = stream.read(&mut request).await.unwrap();
        stream.write_all(&request[..n]).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let (_server, _client, server_api, socks_port) = start_multiuser_pair();
    let mut stream = socks5_connect(socks_port, target_port).await;
    let payload = b"ss2022-user-attribution";
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    stream.shutdown().await.unwrap();
    target_task.await.unwrap();

    for _ in 0..30 {
        let stats = user_stats(server_api).await;
        if let Some(user1) = stats.get("user1") {
            assert!(user1["upload"].as_u64().unwrap_or_default() > 0);
            assert!(user1["download"].as_u64().unwrap_or_default() > 0);
            assert!(stats.get("user2").is_none());
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("user1 traffic was not reported by /user-stats");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn ss2022_udp_attributes_traffic_to_authenticated_user() {
    let target_port = spawn_udp_echo().await;
    let (_server, _client, server_api, socks_port) = start_multiuser_pair();
    let session = Socks5UdpSession::connect(socks_port).await;
    let payload = b"ss2022-udp-user-attribution";

    session
        .send_ipv4(payload, [127, 0, 0, 1], target_port)
        .await;
    let (echoed, source) =
        tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .expect("timed out waiting for SS2022 UDP response");
    assert_eq!(echoed, payload);
    assert_eq!(source, format!("127.0.0.1:{target_port}"));

    for _ in 0..30 {
        let stats = user_stats(server_api).await;
        if let Some(user1) = stats.get("user1") {
            assert!(user1["upload"].as_u64().unwrap_or_default() > 0);
            assert!(user1["download"].as_u64().unwrap_or_default() > 0);
            assert!(stats.get("user2").is_none());
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("user1 UDP traffic was not reported by /user-stats");
}
