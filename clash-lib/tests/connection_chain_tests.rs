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
    net::{TcpListener, TcpStream, UdpSocket},
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

fn start_direct_client() -> (ClashInstance, u16, u16) {
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
    .expect("failed to start DIRECT Explain client");
    (clash, api_port, socks_port)
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
    assert!(connection["metadata"]["sourcePort"].is_u64());
    assert!(connection["metadata"]["destinationPort"].is_u64());

    request_task.await.expect("proxy request task failed");
    target_task.await.expect("HTTP target task failed");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn direct_tcp_flow_is_queryable_from_path_explain() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local HTTP target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 512];
        loop {
            let length = stream.read(&mut chunk).await.unwrap();
            if length == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..length]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\ndirect-ok",
            )
            .await
            .unwrap();
    });

    let (_clash, api_port, socks_port) = start_direct_client();
    let mut stream = socks5_connect(socks_port, target_port).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("failed to send request through DIRECT");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("timed out reading DIRECT response")
        .expect("failed to read DIRECT response");
    target_task.await.expect("HTTP target task failed");
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response.ends_with(b"direct-ok"));

    let (tracked_flow, connected_decision) =
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let flows =
                    get_api_json(api_port, "/flows?include_closed=true").await;
                if let Some(flow) = flows.as_array().and_then(|records| {
                    records.iter().find(|flow| {
                        flow["protocol"] == "tcp"
                            && flow["dstPort"].as_u64()
                                == Some(u64::from(target_port))
                            && flow["flowIds"]
                                .as_array()
                                .is_some_and(|ids| !ids.is_empty())
                    })
                }) {
                    let flow = flow.clone();
                    let flow_ids = flow["flowIds"]
                        .as_array()
                        .expect("tracked DIRECT flow should expose IDs");
                    let decisions =
                        get_api_json(api_port, "/runtime/network/path-decisions")
                            .await;
                    if let Some(decision) =
                        decisions.as_array().and_then(|records| {
                            records.iter().find(|decision| {
                                flow_ids.iter().any(|id| id == &decision["flowId"])
                                    && decision["outcome"] == "connected"
                                    && decision["route"]["outbound"] == "DIRECT"
                            })
                        })
                    {
                        break (flow, decision.clone());
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("DIRECT flow did not produce a connected Explain record");
    assert_eq!(
        connected_decision["destination"].as_str(),
        Some(format!("127.0.0.1:{target_port}").as_str())
    );
    let flow_ids = tracked_flow["flowIds"]
        .as_array()
        .expect("tracked DIRECT flow should expose IDs");
    assert!(
        flow_ids
            .iter()
            .any(|flow_id| flow_id == &connected_decision["flowId"])
    );
    let flow_id = connected_decision["flowId"]
        .as_str()
        .expect("DIRECT Explain record should expose a flow ID");
    let detail = get_api_json(
        api_port,
        &format!("/runtime/network/path-decision/{flow_id}"),
    )
    .await;
    assert_eq!(detail, connected_decision);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn direct_tcp_dial_failure_is_queryable_from_path_explain() {
    let (_clash, api_port, socks_port) = start_direct_client();
    let existing_decisions = tokio::time::timeout(
        Duration::from_secs(3),
        get_api_json(api_port, "/runtime/network/path-decisions"),
    )
    .await
    .expect("timed out reading initial path decisions");
    let existing_flow_ids = existing_decisions
        .as_array()
        .expect("initial path decisions should be an array")
        .iter()
        .filter_map(|decision| decision["flowId"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();

    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to reserve a local TCP port");
    let target_port = target.local_addr().unwrap().port();
    drop(target);

    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, target_port),
    )
    .await
    .expect("timed out during the local SOCKS5 connection");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for the refused DIRECT dial to close")
        .expect("failed to read the closed DIRECT stream");
    assert!(response.is_empty(), "refused DIRECT dial returned payload");

    let failed_decision = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let decisions =
                get_api_json(api_port, "/runtime/network/path-decisions").await;
            if let Some(decision) = decisions.as_array().and_then(|records| {
                records.iter().find(|decision| {
                    decision["outcome"] == "dialFailed"
                        && decision["route"]["outbound"] == "DIRECT"
                        && decision["reason"] == "directDialFailed"
                        && decision["flowId"].as_str().is_some_and(|flow_id| {
                            !existing_flow_ids
                                .iter()
                                .any(|existing| existing == flow_id)
                        })
                })
            }) {
                break decision.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("DIRECT refusal did not produce a failed Explain record");
    assert_eq!(
        failed_decision["destination"].as_str(),
        Some(format!("127.0.0.1:{target_port}").as_str())
    );
    assert_eq!(failed_decision["selectedPath"], serde_json::Value::Null);
    assert!(
        failed_decision["failureKind"]
            .as_str()
            .is_some_and(|failure_kind| !failure_kind.is_empty())
    );

    let flow_id = failed_decision["flowId"]
        .as_str()
        .expect("failed DIRECT Explain should expose a flow ID");
    let detail = tokio::time::timeout(
        Duration::from_secs(3),
        get_api_json(
            api_port,
            &format!("/runtime/network/path-decision/{flow_id}"),
        ),
    )
    .await
    .expect("timed out querying the failed DIRECT Explain detail");
    assert_eq!(detail, failed_decision);
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

    let tracked_flow = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let flows_url =
                format!("http://127.0.0.1:{api_port}/flows?include_closed=true");
            let request = hyper::Request::builder()
                .uri(&flows_url)
                .header(http::header::AUTHORIZATION, "Bearer clash-rs")
                .method(http::Method::GET)
                .body(http_body_util::Empty::<Bytes>::new())
                .expect("failed to build closed flow query");
            let response = send_http_request(flows_url.parse().unwrap(), request)
                .await
                .expect("failed to query closed flows");
            assert_eq!(response.status(), http::StatusCode::OK);
            let flows: serde_json::Value = serde_json::from_reader(
                response
                    .collect()
                    .await
                    .expect("failed to collect closed flows")
                    .aggregate()
                    .reader(),
            )
            .expect("failed to parse closed flows");
            if let Some(flow) = flows.as_array().and_then(|records| {
                records.iter().find(|flow| {
                    flow["protocol"] == "tcp"
                        && flow["dstPort"].as_u64() == Some(u64::from(target_port))
                        && flow["flowIds"]
                            .as_array()
                            .is_some_and(|flow_ids| !flow_ids.is_empty())
                })
            }) {
                break flow.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("proxy TCP flow was not recorded in /flows");
    let flow_ids = tracked_flow["flowIds"]
        .as_array()
        .expect("tracked proxy TCP flow should expose flow IDs");
    let decisions: serde_json::Value =
        tokio::time::timeout(Duration::from_secs(3), async {
            let decisions_url = format!(
                "http://127.0.0.1:{api_port}/runtime/network/path-decisions"
            );
            let decisions_request = hyper::Request::builder()
                .uri(&decisions_url)
                .header(http::header::AUTHORIZATION, "Bearer clash-rs")
                .method(http::Method::GET)
                .body(http_body_util::Empty::<Bytes>::new())
                .expect("failed to build path decisions query");
            let decisions_response =
                send_http_request(decisions_url.parse().unwrap(), decisions_request)
                    .await
                    .expect("failed to query path decisions");
            assert_eq!(decisions_response.status(), http::StatusCode::OK);
            serde_json::from_reader(
                decisions_response
                    .collect()
                    .await
                    .expect("failed to collect path decisions")
                    .aggregate()
                    .reader(),
            )
            .expect("failed to parse path decisions")
        })
        .await
        .expect("timed out querying path decisions");
    let connected_proxy_decision = decisions
        .as_array()
        .expect("path decisions should be an array")
        .iter()
        .find(|decision| {
            flow_ids
                .iter()
                .any(|flow_id| flow_id == &decision["flowId"])
                && decision["outcome"] == "connected"
                && decision["route"]["outbound"] == "leaf-proxy"
        })
        .expect("proxy TCP flow should have a connected proxy Explain record");
    let decision_detail: serde_json::Value =
        tokio::time::timeout(Duration::from_secs(3), async {
            let decision_url = format!(
                "http://127.0.0.1:{api_port}/runtime/network/path-decision/{}",
                connected_proxy_decision["flowId"]
                    .as_str()
                    .expect("Explain record should have a flow ID")
            );
            let decision_request = hyper::Request::builder()
                .uri(&decision_url)
                .header(http::header::AUTHORIZATION, "Bearer clash-rs")
                .method(http::Method::GET)
                .body(http_body_util::Empty::<Bytes>::new())
                .expect("failed to build proxy path decision query");
            let decision_response =
                send_http_request(decision_url.parse().unwrap(), decision_request)
                    .await
                    .expect("failed to query proxy path decision");
            assert_eq!(decision_response.status(), http::StatusCode::OK);
            serde_json::from_reader(
                decision_response
                    .collect()
                    .await
                    .expect("failed to collect proxy path decision")
                    .aggregate()
                    .reader(),
            )
            .expect("failed to parse proxy path decision")
        })
        .await
        .expect("timed out querying proxy path decision");
    assert_eq!(
        &decision_detail, connected_proxy_decision,
        "single-flow Explain should match the successful proxy connection record"
    );

    upstream_task.abort();
    leaf_task.abort();
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn proxy_handshake_failure_is_queryable_from_path_explain() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local failing SOCKS5 endpoint");
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) =
            tokio::time::timeout(Duration::from_secs(5), upstream.accept())
                .await
                .expect("timed out waiting for proxy endpoint connection")
                .expect("failed to accept proxy endpoint connection");
        drop(stream);
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
  - name: failing-proxy
    type: socks5
    server: 127.0.0.1
    port: {upstream_port}
    udp: false
rules:
  - MATCH,failing-proxy
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
    .expect("failed to start proxy Explain integration client");

    let _stream =
        tokio::time::timeout(Duration::from_secs(5), socks5_connect(socks_port, 80))
            .await
            .expect("timed out during local SOCKS5 CONNECT");
    upstream_task
        .await
        .expect("local failing SOCKS5 endpoint task failed");

    let failure = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let decisions_url = format!(
                "http://127.0.0.1:{api_port}/runtime/network/path-decisions"
            );
            let request = hyper::Request::builder()
                .uri(&decisions_url)
                .header(http::header::AUTHORIZATION, "Bearer clash-rs")
                .method(http::Method::GET)
                .body(http_body_util::Empty::<Bytes>::new())
                .expect("failed to build failure path decisions query");
            let response =
                send_http_request(decisions_url.parse().unwrap(), request)
                    .await
                    .expect("failed to query failure path decisions");
            assert_eq!(response.status(), http::StatusCode::OK);
            let decisions: serde_json::Value = serde_json::from_reader(
                response
                    .collect()
                    .await
                    .expect("failed to collect failure path decisions")
                    .aggregate()
                    .reader(),
            )
            .expect("failed to parse failure path decisions");
            if let Some(decision) = decisions.as_array().and_then(|records| {
                records.iter().find(|decision| {
                    matches!(
                        decision["outcome"].as_str(),
                        Some("dialFailed" | "staleNetworkDiscarded")
                    ) && decision["route"]["outbound"] == "failing-proxy"
                })
            }) {
                break decision.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("proxy SOCKS handshake failure was not recorded in Explain");
    assert!(
        failure["failureKind"]
            .as_str()
            .is_some_and(|kind| !kind.is_empty())
    );
    assert!(
        failure["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("proxyDialFailed"))
    );

    let detail: serde_json::Value =
        tokio::time::timeout(Duration::from_secs(3), async {
            let decision_url = format!(
                "http://127.0.0.1:{api_port}/runtime/network/path-decision/{}",
                failure["flowId"]
                    .as_str()
                    .expect("failure Explain record should have a flow ID")
            );
            let request = hyper::Request::builder()
                .uri(&decision_url)
                .header(http::header::AUTHORIZATION, "Bearer clash-rs")
                .method(http::Method::GET)
                .body(http_body_util::Empty::<Bytes>::new())
                .expect("failed to build failure path decision detail query");
            let response = send_http_request(decision_url.parse().unwrap(), request)
                .await
                .expect("failed to query failure path decision detail");
            assert_eq!(response.status(), http::StatusCode::OK);
            serde_json::from_reader(
                response
                    .collect()
                    .await
                    .expect("failed to collect failure path decision detail")
                    .aggregate()
                    .reader(),
            )
            .expect("failed to parse failure path decision detail")
        })
        .await
        .expect("timed out querying failure path decision detail");
    assert_eq!(detail, failure);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn http_inbound_forwards_websocket_upgrade_bidirectionally() {
    async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut headers = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream
                .read_exact(&mut byte)
                .await
                .expect("HTTP upgrade headers should be complete");
            headers.push(byte[0]);
            assert!(headers.len() <= 16 * 1024, "HTTP headers exceeded limit");
            if headers.ends_with(b"\r\n\r\n") {
                return headers;
            }
        }
    }

    let origin = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind websocket fixture");
    let origin_port = origin.local_addr().unwrap().port();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin
            .accept()
            .await
            .expect("websocket fixture should accept connection");
        let request = read_headers(&mut stream).await;
        let request = String::from_utf8_lossy(&request);
        let _ = request_tx.send(request.into_owned());

        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade, X-Upstream-Private\r\n\
                  Upgrade: websocket\r\n\
                  X-Upstream-Private: secret\r\n\
                  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                  \r\n\x81\x05hello",
            )
            .await
            .expect("websocket fixture should accept the upgrade");

        let mut client_frame_header = [0u8; 2];
        stream
            .read_exact(&mut client_frame_header)
            .await
            .expect("websocket fixture should receive client data");
        assert_eq!(client_frame_header, [0x81, 0x84]);
        let mut client_masked_frame = [0u8; 8];
        stream
            .read_exact(&mut client_masked_frame)
            .await
            .expect("websocket fixture should receive masked client frame");
        let mask = &client_masked_frame[..4];
        let payload: Vec<u8> = client_masked_frame[4..]
            .iter()
            .enumerate()
            .map(|(index, byte)| *byte ^ mask[index % 4])
            .collect();
        assert_eq!(payload, b"ping");
        stream
            .write_all(b"\x81\x04pong")
            .await
            .expect("websocket fixture should return client data");
    });

    let api_port = available_port();
    let http_port = available_port();
    let config = format!(
        "allow-lan: false\n\
         bind-address: 127.0.0.1\n\
         port: {http_port}\n\
         mode: rule\n\
         log-level: error\n\
         mmdb: null\n\
         external-controller: 127.0.0.1:{api_port}\n\
         secret: clash-rs\n\
         authentication:\n\
           - test-user:test-password\n\
         tun:\n\
           enable: false\n\
         rules:\n\
           - MATCH,DIRECT\n"
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
        vec![api_port, http_port],
    )
    .expect("failed to start HTTP proxy client");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match TcpStream::connect(("127.0.0.1", http_port)).await {
                Ok(stream) => {
                    drop(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }

        let mut client = TcpStream::connect(("127.0.0.1", http_port))
            .await
            .expect("failed to connect to HTTP inbound");
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{origin_port}/socket HTTP/1.1\r\n\
                     Host: wrong.example\r\n\
                     Connection: keep-alive, Upgrade, X-Hop-Private\r\n\
                     X-Hop-Private: secret\r\n\
                     Proxy-Authorization: Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=\r\n\
                     Upgrade: websocket\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\
                     \r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("failed to send websocket upgrade request");

        let request = tokio::time::timeout(Duration::from_secs(2), request_rx)
            .await
            .expect("origin should receive upgrade request")
            .expect("origin request channel should remain open");
        assert!(request.starts_with("GET /socket HTTP/1.1\r\n"));
        let request_lower = request.to_ascii_lowercase();
        let connection = request_lower
            .lines()
            .find_map(|line| line.strip_prefix("connection:"))
            .expect("upgrade request should include Connection header");
        assert_eq!(connection.trim(), "upgrade");
        assert!(request_lower.contains("upgrade: websocket"));
        assert!(request.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(request_lower.contains(&format!("host: 127.0.0.1:{origin_port}")));
        assert!(!request_lower.contains("proxy-authorization:"));
        assert!(!request_lower.contains("x-hop-private:"));

        let response = read_headers(&mut client).await;
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));
        let response_lower = response.to_ascii_lowercase();
        assert!(response_lower.contains("upgrade: websocket"));
        assert!(response_lower.contains("connection: upgrade"));
        assert!(!response_lower.contains("x-upstream-private:"));

        let mut server_frame = [0u8; 7];
        client
            .read_exact(&mut server_frame)
            .await
            .expect("HTTP inbound should forward early upstream upgrade data");
        assert_eq!(&server_frame, b"\x81\x05hello");

        let client_payload = b"ping";
        let mask = [0x13, 0x57, 0x9b, 0xdf];
        let mut client_frame = vec![0x81, 0x80 | client_payload.len() as u8];
        client_frame.extend_from_slice(&mask);
        client_frame.extend(
            client_payload
                .iter()
                .enumerate()
                .map(|(index, byte)| *byte ^ mask[index % mask.len()]),
        );
        client
            .write_all(&client_frame)
            .await
            .expect("HTTP inbound should forward client upgrade data");
        let mut acknowledgement = [0u8; 6];
        client
            .read_exact(&mut acknowledgement)
            .await
            .expect("HTTP inbound should forward upstream upgrade data");
        assert_eq!(&acknowledgement, b"\x81\x04pong");
    })
    .await
    .expect("HTTP websocket upgrade tunnel timed out");
    origin_task
        .await
        .expect("websocket fixture task should complete");

    let refused_port = available_port();
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut client = TcpStream::connect(("127.0.0.1", http_port))
            .await
            .expect("failed to reconnect to HTTP inbound");
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{refused_port}/socket HTTP/1.1\r\n\
                     Host: 127.0.0.1:{refused_port}\r\n\
                     Connection: Upgrade\r\n\
                     Proxy-Authorization: Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=\r\n\
                     Upgrade: websocket\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\
                     \r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("failed to send refused websocket upgrade request");
        let response = read_headers(&mut client).await;
        assert!(
            String::from_utf8_lossy(&response)
                .starts_with("HTTP/1.1 502 Bad Gateway")
        );
    })
    .await
    .expect("HTTP upgrade connection failure response timed out");
}

async fn assert_connected_udp_flow_explain(
    api_port: u16,
    target_port: u16,
    outbound: &str,
) {
    let (flow, decision) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let flows = get_api_json(api_port, "/flows?include_closed=true").await;
            if let Some(flow) = flows.as_array().and_then(|records| {
                records.iter().find(|flow| {
                    flow["protocol"] == "udp"
                        && flow["dstPort"].as_u64() == Some(u64::from(target_port))
                        && flow["flowIds"]
                            .as_array()
                            .is_some_and(|ids| !ids.is_empty())
                })
            }) {
                let flow = flow.clone();
                let flow_ids = flow["flowIds"]
                    .as_array()
                    .expect("tracked UDP flow should expose IDs");
                let decisions =
                    get_api_json(api_port, "/runtime/network/path-decisions").await;
                if let Some(decision) = decisions.as_array().and_then(|records| {
                    records.iter().find(|decision| {
                        flow_ids.iter().any(|id| id == &decision["flowId"])
                            && decision["outcome"] == "connected"
                            && decision["route"]["outbound"] == outbound
                    })
                }) {
                    break (flow, decision.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("SOCKS5 UDP flow did not produce a connected Explain record");

    let flow_ids = flow["flowIds"]
        .as_array()
        .expect("tracked UDP flow should expose IDs");
    assert!(
        flow_ids
            .iter()
            .any(|flow_id| flow_id == &decision["flowId"])
    );
    let flow_id = decision["flowId"]
        .as_str()
        .expect("UDP Explain record should expose a flow ID");
    let detail = get_api_json(
        api_port,
        &format!("/runtime/network/path-decision/{flow_id}"),
    )
    .await;
    assert_eq!(detail, decision);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn socks5_udp_outbound_roundtrip_is_queryable_from_path_explain() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local SOCKS5 UDP upstream");
    let upstream_port = upstream.local_addr().unwrap().port();

    let relay = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local SOCKS5 UDP relay");
    let relay_addr = relay.local_addr().unwrap();
    let target = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local UDP echo target");
    let target_addr = target.local_addr().unwrap();
    let (target_tx, target_rx) = tokio::sync::oneshot::channel();

    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) =
            tokio::time::timeout(Duration::from_secs(5), upstream.accept())
                .await
                .expect("timed out waiting for SOCKS5 UDP association")
                .expect("failed to accept SOCKS5 UDP association");

        let mut greeting = [0u8; 2];
        stream
            .read_exact(&mut greeting)
            .await
            .expect("failed to read SOCKS5 greeting");
        assert_eq!(greeting[0], 0x05);
        let mut methods = vec![0u8; usize::from(greeting[1])];
        stream
            .read_exact(&mut methods)
            .await
            .expect("failed to read SOCKS5 authentication methods");
        assert!(methods.contains(&0x00), "SOCKS5 no-auth was not offered");
        stream
            .write_all(&[0x05, 0x00])
            .await
            .expect("failed to accept SOCKS5 no-auth");

        let mut request = [0u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .expect("failed to read SOCKS5 UDP ASSOCIATE request");
        assert_eq!(request, [0x05, 0x03, 0x00, 0x01]);
        let mut address = [0u8; 6];
        stream
            .read_exact(&mut address)
            .await
            .expect("failed to read SOCKS5 UDP ASSOCIATE address");
        assert_eq!(address, [0u8; 6]);

        let mut response = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
        response.extend_from_slice(&relay_addr.port().to_be_bytes());
        stream
            .write_all(&response)
            .await
            .expect("failed to return SOCKS5 UDP relay address");

        let mut byte = [0u8; 1];
        while stream
            .read(&mut byte)
            .await
            .expect("failed while holding SOCKS5 control connection")
            != 0
        {}
    });

    let relay_task = tokio::spawn(async move {
        let mut packet = vec![0u8; 65_535];
        let (len, client_addr) = tokio::time::timeout(
            Duration::from_secs(5),
            relay.recv_from(&mut packet),
        )
        .await
        .expect("timed out waiting for SOCKS5 UDP datagram")
        .expect("failed to receive SOCKS5 UDP datagram");
        assert!(len >= 10, "SOCKS5 UDP datagram is truncated");
        assert_eq!(
            &packet[..4],
            &[0x00, 0x00, 0x00, 0x01],
            "expected an unfragmented IPv4 SOCKS5 UDP datagram"
        );
        let destination = SocketAddr::from((
            std::net::Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]),
            u16::from_be_bytes([packet[8], packet[9]]),
        ));
        target_tx
            .send(destination)
            .expect("test should still be waiting for the destination");
        target
            .send_to(&packet[10..len], destination)
            .await
            .expect("failed to forward SOCKS5 UDP payload to target");

        let mut echoed = vec![0u8; 65_535];
        let (echoed_len, source) = tokio::time::timeout(
            Duration::from_secs(5),
            target.recv_from(&mut echoed),
        )
        .await
        .expect("timed out waiting for local UDP echo")
        .expect("failed to receive local UDP echo");
        assert_eq!(source, destination);

        let source_ip = match source.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("expected an IPv4 UDP echo source"),
        };
        let mut response = vec![0x00, 0x00, 0x00, 0x01];
        response.extend_from_slice(&source_ip);
        response.extend_from_slice(&source.port().to_be_bytes());
        response.extend_from_slice(&echoed[..echoed_len]);
        relay
            .send_to(&response, client_addr)
            .await
            .expect("failed to return SOCKS5 UDP response");
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
  - name: socks5-udp-out
    type: socks5
    server: 127.0.0.1
    port: {upstream_port}
    udp: true
rules:
  - MATCH,socks5-udp-out
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
    .expect("failed to start SOCKS5 UDP Explain integration client");

    let client = tokio::time::timeout(
        Duration::from_secs(5),
        common::Socks5UdpSession::connect(socks_port),
    )
    .await
    .expect("timed out during local SOCKS5 UDP ASSOCIATE");
    let payload = b"socks5-outbound-udp-roundtrip";
    client
        .send_ipv4(payload, [127, 0, 0, 1], target_addr.port())
        .await;
    let (response, source) =
        tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await
            .expect("timed out waiting for SOCKS5 UDP echo response");
    assert_eq!(response, payload);
    assert_eq!(source, format!("127.0.0.1:{}", target_addr.port()));
    let destination = tokio::time::timeout(Duration::from_secs(1), target_rx)
        .await
        .expect("SOCKS5 UDP relay did not forward the requested destination")
        .expect("SOCKS5 UDP relay task stopped");
    assert_eq!(destination, target_addr);

    assert_connected_udp_flow_explain(
        api_port,
        target_addr.port(),
        "socks5-udp-out",
    )
    .await;

    drop(client);
    relay_task.await.expect("SOCKS5 UDP relay task failed");
    tokio::time::timeout(Duration::from_secs(5), upstream_task)
        .await
        .expect("SOCKS5 control connection stayed open after the UDP session closed")
        .expect("SOCKS5 control-connection task failed");
}
