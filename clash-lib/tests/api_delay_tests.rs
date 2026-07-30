use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{net::TcpListener, path::PathBuf};

mod common;

use common::{ClashInstance, send_http_request};

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

fn start_client(latency_url: &str) -> (ClashInstance, u16) {
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
    url: {latency_url}
    interval: 3600
    lazy: true
rules:
  - MATCH,url-test
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
    .expect("failed to start delay API client");
    (clash, api_port)
}

fn encoded_url(url: &str) -> String {
    url.replace(':', "%3A").replace('/', "%2F")
}

async fn get_json(url: String) -> serde_json::Value {
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build delay request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send delay request");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect delay response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse delay response")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_proxy_delay_direct() {
    let mock_server = httpmock::MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");
        then.status(200).body("ok");
    });
    let (_clash, api_port) = start_client(&mock_server.url("/"));
    let url = format!(
        "http://127.0.0.1:{api_port}/proxies/DIRECT/delay?url={}&timeout=5000",
        encoded_url(&mock_server.url("/"))
    );
    let json = get_json(url).await;
    assert!(json["delay"].is_u64());
    assert!(json["overall"].is_u64());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_group_delay_url_test() {
    let mock_server = httpmock::MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");
        then.status(200).body("ok");
    });
    let (_clash, api_port) = start_client(&mock_server.url("/"));
    let url = format!(
        "http://127.0.0.1:{api_port}/group/url-test/delay?url={}&timeout=5000",
        encoded_url(&mock_server.url("/"))
    );
    let json = get_json(url).await;
    assert!(json["url-test"].is_u64());
}
