#![cfg(feature = "anytls")]

use clash_lib::{Config, Options};
use std::{
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

mod common;

use common::ClashInstance;

fn available_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

fn start_anytls_pair() -> (ClashInstance, ClashInstance, u16) {
    let server_api = available_port();
    let anytls_port = available_port();
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
  - name: anytls-in
    type: anytls
    listen: 127.0.0.1
    port: {anytls_port}
    password: anytls-smoke-test-password
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
        vec![server_api, anytls_port],
    )
    .expect("failed to start AnyTLS server");

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
  - name: anytls-simple
    type: anytls
    server: 127.0.0.1
    port: {anytls_port}
    password: anytls-smoke-test-password
    skip-cert-verify: true
    udp: true
rules:
  - MATCH,anytls-simple
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
    .expect("failed to start AnyTLS client");

    (server, client, socks_port)
}

async fn socks5_connect(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("failed to connect to SOCKS5 listener");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("failed to send SOCKS5 greeting");
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("failed to read SOCKS5 greeting response");
    assert_eq!(greeting, [0x05, 0x00]);

    let [port_hi, port_lo] = target_port.to_be_bytes();
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port_hi, port_lo])
        .await
        .expect("failed to send SOCKS5 CONNECT request");

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .expect("failed to read SOCKS5 CONNECT response");
    assert_eq!(header[0], 0x05);
    assert_eq!(header[1], 0x00, "SOCKS5 CONNECT was rejected");
    match header[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await.unwrap();
        }
        0x03 => {
            let len = stream.read_u8().await.unwrap() as usize;
            let mut rest = vec![0u8; len + 2];
            stream.read_exact(&mut rest).await.unwrap();
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await.unwrap();
        }
        atyp => panic!("unexpected SOCKS5 response address type {atyp}"),
    }
    stream
}

async fn socks5_udp_associate(proxy_port: u16) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("failed to connect to SOCKS5 listener");
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
        .expect("failed to send SOCKS5 UDP ASSOCIATE request");
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[1], 0x00, "SOCKS5 UDP ASSOCIATE was rejected");
    let relay: SocketAddr = match header[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            let mut port = [0u8; 2];
            stream.read_exact(&mut ip).await.unwrap();
            stream.read_exact(&mut port).await.unwrap();
            (std::net::Ipv4Addr::from(ip), u16::from_be_bytes(port)).into()
        }
        atyp => panic!("unexpected UDP relay address type {atyp}"),
    };
    let relay = if relay.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], relay.port()))
    } else {
        relay
    };
    (stream, relay)
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_anytls_tcp() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to start local HTTP target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = vec![0u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nanytls-roundtrip",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });

    let (_server, _client, socks_port) = start_anytls_pair();
    let mut stream = socks5_connect(socks_port, target_port).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("failed to send HTTP request through AnyTLS");

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out reading AnyTLS response")
        .expect("failed to read AnyTLS response");
    target_task.await.expect("HTTP target task failed");

    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("anytls-roundtrip"));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_anytls_udp() {
    let echo = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to start UDP echo target");
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (len, peer) = echo.recv_from(&mut buf).await.unwrap();
        echo.send_to(&buf[..len], peer).await.unwrap();
    });

    let (_server, _client, socks_port) = start_anytls_pair();
    let (_control, relay_addr) = socks5_udp_associate(socks_port).await;
    let payload = b"anytls-udp-roundtrip";
    let echo_ip = match echo_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => panic!("expected IPv4 UDP echo address"),
    };
    let mut packet = vec![0x00, 0x00, 0x00, 0x01];
    packet.extend_from_slice(&echo_ip);
    packet.extend_from_slice(&echo_addr.port().to_be_bytes());
    packet.extend_from_slice(payload);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&packet, relay_addr).await.unwrap();
    let mut response = [0u8; 2048];
    let (len, _) = tokio::time::timeout(
        Duration::from_secs(10),
        socket.recv_from(&mut response),
    )
    .await
    .expect("timed out waiting for AnyTLS UDP response")
    .expect("failed to receive AnyTLS UDP response");
    echo_task.await.expect("UDP echo task failed");

    assert!(len >= 10, "SOCKS5 UDP response header is truncated");
    assert_eq!(&response[10..len], payload);
}
