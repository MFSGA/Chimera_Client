use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
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

fn start_client(target_url: &str) -> (ClashInstance, u16, u16) {
    let api_port = available_port();
    let socks_port = available_port();
    let config = format!(
        r#"allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: clash-rs
tun:
  enable: false
proxies:
  - {{name: DIRECT_alias, type: direct}}
proxy-groups:
  - name: url-test
    type: url-test
    proxies:
      - DIRECT
    url: {target_url}
    interval: 3600
    lazy: true
  - name: selector
    type: select
    proxies:
      - url-test
rules:
  - MATCH,selector
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
    .expect("failed to start connection-chain client");
    (clash, api_port, socks_port)
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
        atyp => panic!("unexpected SOCKS5 address type {atyp}"),
    };
    let mut address = vec![0u8; remaining];
    stream.read_exact(&mut address).await.unwrap();
    stream
}

async fn first_connection(api_port: u16) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}/connections");
    for _ in 0..50 {
        let request = hyper::Request::builder()
            .uri(&url)
            .header(http::header::AUTHORIZATION, "Bearer clash-rs")
            .method(http::Method::GET)
            .body(http_body_util::Empty::<Bytes>::new())
            .expect("failed to build connections request");
        let response = send_http_request(url.parse().unwrap(), request)
            .await
            .expect("failed to query connections");
        let json: serde_json::Value = serde_json::from_reader(
            response
                .collect()
                .await
                .expect("failed to collect connections response")
                .aggregate()
                .reader(),
        )
        .expect("failed to parse connections response");
        if let Some(connection) =
            json["connections"].as_array().and_then(|v| v.first())
        {
            return connection.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no active connection was observed")
}

async fn run_socks5_relay(
    mut stream: TcpStream,
    destinations: mpsc::UnboundedSender<SocketAddr>,
) -> std::io::Result<()> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(std::io::Error::other("invalid SOCKS5 greeting"));
    }
    let mut methods = vec![0; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        return Err(std::io::Error::other("no anonymous SOCKS5 method"));
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 0x05 || request[1] != 0x01 {
        return Err(std::io::Error::other("expected SOCKS5 CONNECT"));
    }
    let host = match request[3] {
        0x01 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut length = [0];
            stream.read_exact(&mut length).await?;
            let mut domain = vec![0; usize::from(length[0])];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(std::io::Error::other)?
        }
        0x04 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        atyp => {
            return Err(std::io::Error::other(format!(
                "unsupported SOCKS5 address type {atyp}"
            )));
        }
    };
    let mut port = [0; 2];
    stream.read_exact(&mut port).await?;
    let target_addr =
        tokio::net::lookup_host((host.as_str(), u16::from_be_bytes(port)))
            .await?
            .next()
            .ok_or_else(|| std::io::Error::other("SOCKS5 target did not resolve"))?;
    destinations
        .send(target_addr)
        .map_err(|_| std::io::Error::other("SOCKS5 target observer stopped"))?;
    let mut target = TcpStream::connect(target_addr).await?;
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
        .await?;
    tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
    Ok(())
}

async fn spawn_socks5_relay() -> (
    u16,
    mpsc::UnboundedReceiver<SocketAddr>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local SOCKS5 relay");
    let port = listener.local_addr().unwrap().port();
    let (destinations_tx, destinations_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let destinations = destinations_tx.clone();
            tokio::spawn(async move {
                let _ = run_socks5_relay(stream, destinations).await;
            });
        }
    });
    (port, destinations_rx, task)
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn ref_compat_connections_report_proxy_chain_names() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local HTTP target");
    let target_addr = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        stream.write_all(b"ok").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let target_url = format!("http://{target_addr}/");
    let (_clash, api_port, socks_port) = start_client(&target_url);
    let request_task = tokio::spawn(async move {
        let mut stream = socks5_connect(socks_port, target_addr.port()).await;
        stream
            .write_all(
                b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("timed out reading local target response")
        .expect("failed to read local target response");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.ends_with(b"ok"));
    });

    let connection = first_connection(api_port).await;
    assert_eq!(
        connection["chains"],
        serde_json::json!(["DIRECT", "url-test", "selector"])
    );

    request_task.await.expect("proxy request task failed");
    target_task.await.expect("HTTP target task failed");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn dialer_proxy_connects_through_a_local_socks5_hop() {
    let (upstream_port, mut upstream_destinations, upstream_task) =
        spawn_socks5_relay().await;
    let (leaf_port, mut leaf_destinations, leaf_task) = spawn_socks5_relay().await;

    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local HTTP target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) =
            tokio::time::timeout(Duration::from_secs(5), target.accept())
                .await
                .expect("timed out waiting for local HTTP target connection")
                .expect("failed to accept local HTTP target connection");
        let request = tokio::time::timeout(Duration::from_secs(5), async {
            let mut request = Vec::new();
            let mut chunk = [0; 512];
            loop {
                let length = stream.read(&mut chunk).await?;
                if length == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..length]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            std::io::Result::Ok(request)
        })
        .await
        .expect("timed out waiting for HTTP request at local target")
        .expect("failed to read HTTP request at local target");
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(request.windows(4).any(|window| window == b"\r\n\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\ndialer-proxy-ok",
            )
            .await
            .unwrap();
    });

    let api_port = available_port();
    let socks_port = available_port();
    let config = format!(
        r#"allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: clash-rs
tun:
  enable: false
proxies:
  - name: upstream-hop
    type: socks5
    server: 127.0.0.1
    port: {upstream_port}
    udp: false
  - name: leaf-proxy
    type: socks5
    server: 127.0.0.1
    port: {leaf_port}
    udp: false
    dialer-proxy: upstream-hop
rules:
  - MATCH,leaf-proxy
"#
    );
    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let _clash = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start dialer-proxy integration client");

    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        socks5_connect(socks_port, target_port),
    )
    .await
    .expect("timed out during client SOCKS5 connection and handshake");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("failed to send request through dialer-proxy chain");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out reading response through dialer-proxy chain")
        .expect("failed to read response through dialer-proxy chain");
    tokio::time::timeout(Duration::from_secs(5), target_task)
        .await
        .expect("timed out waiting for local HTTP target task")
        .expect("HTTP target task failed");

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response.ends_with(b"dialer-proxy-ok"));
    let upstream_target =
        tokio::time::timeout(Duration::from_secs(5), upstream_destinations.recv())
            .await
            .expect("upstream SOCKS5 hop did not receive a CONNECT request")
            .expect("upstream SOCKS5 relay stopped");
    assert_eq!(
        upstream_target,
        SocketAddr::from(([127, 0, 0, 1], leaf_port))
    );
    let leaf_target =
        tokio::time::timeout(Duration::from_secs(5), leaf_destinations.recv())
            .await
            .expect("leaf SOCKS5 proxy did not receive a CONNECT request")
            .expect("leaf SOCKS5 relay stopped");
    assert_eq!(leaf_target, SocketAddr::from(([127, 0, 0, 1], target_port)));

    upstream_task.abort();
    leaf_task.abort();
}
