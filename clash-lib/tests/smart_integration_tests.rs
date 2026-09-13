use std::net::TcpListener as StdTcpListener;

use clash_lib::{Config, Options};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod common;

use common::ClashInstance;

fn reserve_ports() -> (StdTcpListener, StdTcpListener) {
    let api =
        StdTcpListener::bind("127.0.0.1:0").expect("failed to reserve API port");
    let socks =
        StdTcpListener::bind("127.0.0.1:0").expect("failed to reserve SOCKS port");
    (api, socks)
}

fn start_smart_client() -> (tempfile::TempDir, ClashInstance, u16) {
    let (api_reservation, socks_reservation) = reserve_ports();
    let api_port = api_reservation.local_addr().unwrap().port();
    let socks_port = socks_reservation.local_addr().unwrap().port();
    let cwd = tempfile::tempdir().expect("failed to create smart test cwd");
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
profile:
  store-selected: false
  store-smart-stats: false
tun:
  enable: false
proxy-groups:
  - name: smart-auto
    type: smart
    proxies:
      - DIRECT
    max-retries: 2
rules:
  - MATCH,smart-auto
"#
    );

    drop(api_reservation);
    drop(socks_reservation);
    let client = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.path().to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start smart proxy client");

    (cwd, client, socks_port)
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
async fn smart_group_routes_real_tcp_traffic() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local TCP target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = [0u8; 128];
        let len = stream.read(&mut request).await.unwrap();
        stream.write_all(&request[..len]).await.unwrap();
    });

    let (_cwd, _client, socks_port) = start_smart_client();
    let mut stream = socks5_connect(socks_port, target_port).await;
    let payload = b"smart-runtime-e2e";
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, payload);
    target_task.await.unwrap();
}
