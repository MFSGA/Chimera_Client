use clash_lib::{Config, Options};
use std::{net::TcpListener as StdTcpListener, path::PathBuf, time::Duration};
use tokio::net::UdpSocket;

mod common;

use common::{ClashInstance, Socks5UdpSession};

fn available_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

fn start_direct_udp_client() -> (ClashInstance, u16) {
    let api_port = available_port();
    let socks_port = available_port();
    let config = format!(
        r#"allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: direct
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: clash-rs
tun:
  enable: false
proxies:
  - {{name: DIRECT_alias, type: direct}}
rules:
  - MATCH,DIRECT
"#
    );
    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let clash = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start DIRECT UDP client");
    (clash, socks_port)
}

async fn spawn_echo_server() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind UDP echo server");
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if socket.send_to(&buf[..len], peer).await.is_err() {
                break;
            }
        }
    });
    port
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn ref_compat_udp_one_client_preserves_multiple_destinations() {
    let (_clash, socks_port) = start_direct_udp_client();
    let port_a = spawn_echo_server().await;
    let port_b = spawn_echo_server().await;
    let client = Socks5UdpSession::connect(socks_port).await;

    client.send_ipv4(b"to-a", [127, 0, 0, 1], port_a).await;
    client.send_ipv4(b"to-b", [127, 0, 0, 1], port_b).await;

    let timeout = Duration::from_secs(5);
    let first = tokio::time::timeout(timeout, client.recv())
        .await
        .expect("timed out waiting for first UDP response");
    let second = tokio::time::timeout(timeout, client.recv())
        .await
        .expect("timed out waiting for second UDP response");

    let expected_a = format!("127.0.0.1:{port_a}");
    let expected_b = format!("127.0.0.1:{port_b}");
    let replies = [first, second];

    assert!(replies.iter().any(|(data, source)| {
        data.as_slice() == b"to-a" && source == &expected_a
    }));
    assert!(replies.iter().any(|(data, source)| {
        data.as_slice() == b"to-b" && source == &expected_b
    }));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn ref_compat_udp_sessions_are_isolated_by_client() {
    let (_clash, socks_port) = start_direct_udp_client();
    let echo_port = spawn_echo_server().await;
    let client_a = Socks5UdpSession::connect(socks_port).await;
    let client_b = Socks5UdpSession::connect(socks_port).await;

    client_a
        .send_ipv4(b"from-a", [127, 0, 0, 1], echo_port)
        .await;
    client_b
        .send_ipv4(b"from-b", [127, 0, 0, 1], echo_port)
        .await;

    let timeout = Duration::from_secs(5);
    let (data_a, source_a) = tokio::time::timeout(timeout, client_a.recv())
        .await
        .expect("client A timed out");
    let (data_b, source_b) = tokio::time::timeout(timeout, client_b.recv())
        .await
        .expect("client B timed out");

    let expected_source = format!("127.0.0.1:{echo_port}");
    assert_eq!(data_a, b"from-a");
    assert_eq!(data_b, b"from-b");
    assert_eq!(source_a, expected_source);
    assert_eq!(source_b, expected_source);
}
