#![cfg(feature = "shadowsocks")]

use std::{net::TcpListener as StdTcpListener, path::PathBuf, time::Duration};

use clash_lib::{Config, Options};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod common;

use common::{ClashInstance, Socks5UdpSession};

const PASSWORD: &str = "3SYJ/f8nmVuzKvKglykRQDSgg10e/ADilkdRWrrY9HU=";

fn available_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

fn start_shadowsocks_pair(udp: bool) -> (ClashInstance, ClashInstance, u16) {
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
tun:
  enable: false
listeners:
  - name: shadowsocks-in
    type: shadowsocks
    listen: 127.0.0.1
    port: {server_port}
    cipher: 2022-blake3-aes-256-gcm
    password: {PASSWORD}
    udp: {udp}
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
    .expect("failed to start Shadowsocks server");

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
  - name: shadowsocks-out
    type: ss
    server: 127.0.0.1
    port: {server_port}
    cipher: 2022-blake3-aes-256-gcm
    password: {PASSWORD}
    udp: {udp}
rules:
  - MATCH,shadowsocks-out
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
    .expect("failed to start Shadowsocks client");

    (server, client, socks_port)
}

async fn spawn_udp_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind Shadowsocks UDP echo target");
    let port = socket.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        let (size, source) = socket.recv_from(&mut buffer).await.unwrap();
        socket.send_to(&buffer[..size], source).await.unwrap();
    });
    (port, task)
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

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_shadowsocks_tcp() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to start local HTTP target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\nshadowsocks-roundtrip",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });

    let (_server, _client, socks_port) = start_shadowsocks_pair(false);
    let mut stream = socks5_connect(socks_port, target_port).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("failed to send HTTP request through Shadowsocks");

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out reading Shadowsocks response")
        .expect("failed to read Shadowsocks response");
    target_task.await.expect("HTTP target task failed");

    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("shadowsocks-roundtrip"));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_shadowsocks_udp() {
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind Shadowsocks UDP echo target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        let (size, source) = target.recv_from(&mut buffer).await.unwrap();
        target.send_to(&buffer[..size], source).await.unwrap();
    });

    let (_server, _client, socks_port) = start_shadowsocks_pair(true);
    let session = Socks5UdpSession::connect(socks_port).await;
    session
        .send_ipv4(b"shadowsocks-udp-roundtrip", [127, 0, 0, 1], target_port)
        .await;
    let (response, source) =
        tokio::time::timeout(Duration::from_secs(10), session.recv())
            .await
            .expect("timed out waiting for Shadowsocks UDP response");

    assert_eq!(response, b"shadowsocks-udp-roundtrip");
    assert_eq!(source, format!("127.0.0.1:{target_port}"));
    target_task.await.expect("UDP echo target failed");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_shadowsocks_udp_multi_target() {
    let (first_port, first_task) = spawn_udp_echo().await;
    let (second_port, second_task) = spawn_udp_echo().await;
    let (_server, _client, socks_port) = start_shadowsocks_pair(true);
    let session = Socks5UdpSession::connect(socks_port).await;

    for (payload, port) in [
        (b"first-target".as_slice(), first_port),
        (b"second-target".as_slice(), second_port),
    ] {
        session.send_ipv4(payload, [127, 0, 0, 1], port).await;
        let (response, source) =
            tokio::time::timeout(Duration::from_secs(10), session.recv())
                .await
                .expect("timed out waiting for multi-target response");
        assert_eq!(response, payload);
        assert_eq!(source, format!("127.0.0.1:{port}"));
    }

    first_task.await.expect("first UDP target failed");
    second_task.await.expect("second UDP target failed");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_shadowsocks_udp_session_isolation() {
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind shared Shadowsocks UDP target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        for _ in 0..2 {
            let (size, source) = target.recv_from(&mut buffer).await.unwrap();
            target.send_to(&buffer[..size], source).await.unwrap();
        }
    });

    let (_server, _client, socks_port) = start_shadowsocks_pair(true);
    let first = Socks5UdpSession::connect(socks_port).await;
    let second = Socks5UdpSession::connect(socks_port).await;
    first
        .send_ipv4(b"first-client", [127, 0, 0, 1], target_port)
        .await;
    second
        .send_ipv4(b"second-client", [127, 0, 0, 1], target_port)
        .await;

    let (first_response, _) =
        tokio::time::timeout(Duration::from_secs(10), first.recv())
            .await
            .expect("first Shadowsocks UDP client timed out");
    let (second_response, _) =
        tokio::time::timeout(Duration::from_secs(10), second.recv())
            .await
            .expect("second Shadowsocks UDP client timed out");
    assert_eq!(first_response, b"first-client");
    assert_eq!(second_response, b"second-client");
    target_task.await.expect("shared UDP target failed");
}
