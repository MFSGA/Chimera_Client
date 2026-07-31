use std::{net::TcpListener as StdTcpListener, path::PathBuf, time::Duration};

use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod common;

use common::{ClashInstance, send_http_request};

fn available_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

fn start_client(strategy: &str) -> (ClashInstance, u16, u16) {
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
proxy-groups:
  - name: balanced
    type: load-balance
    proxies:
      - DIRECT
      - REJECT
    url: http://127.0.0.1/
    interval: 3600
    lazy: true
    strategy: {strategy}
rules:
  - MATCH,balanced
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
    .expect("failed to start load-balance client");
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

async fn get_json(api_port: u16, path: &str) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build API request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to query API");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect API response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse API response")
}

async fn roundtrip(proxy_port: u16, target_port: u16, payload: &[u8]) -> bool {
    let mut stream = socks5_connect(proxy_port, target_port).await;
    if stream.write_all(payload).await.is_err() {
        return false;
    }
    let mut echoed = vec![0u8; payload.len()];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed)).await,
        Ok(Ok(_)) if echoed == payload
    )
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn load_balance_group_is_exposed_by_api() {
    let (_client, api_port, _socks_port) = start_client("round-robin");
    let group = get_json(api_port, "/proxies/balanced").await;
    assert_eq!(group["name"], "balanced");
    assert_eq!(group["type"], "LoadBalance");
    assert_eq!(group["all"], serde_json::json!(["DIRECT", "REJECT"]));
    assert!(group.get("now").is_none());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn load_balance_rotates_real_tcp_connections() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = target.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0u8; 128];
                let len = stream.read(&mut request).await.unwrap();
                stream.write_all(&request[..len]).await.unwrap();
            });
        }
    });

    let (_client, _api_port, socks_port) = start_client("round-robin");
    assert!(roundtrip(socks_port, target_port, b"first-direct").await);
    assert!(!roundtrip(socks_port, target_port, b"second-reject").await);
    assert!(roundtrip(socks_port, target_port, b"third-direct").await);
    target_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn consistent_hash_keeps_real_tcp_target_stable() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = target.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 128];
                let len = stream.read(&mut request).await.unwrap();
                stream.write_all(&request[..len]).await.unwrap();
            });
        }
    });

    let (_client, _api_port, socks_port) = start_client("consistent-hashing");
    let outcomes = [
        roundtrip(socks_port, target_port, b"stable-one").await,
        roundtrip(socks_port, target_port, b"stable-two").await,
        roundtrip(socks_port, target_port, b"stable-three").await,
    ];
    assert!(outcomes.iter().all(|outcome| *outcome == outcomes[0]));
    target_task.abort();
}
