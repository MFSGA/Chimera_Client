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

fn start_client(health_url: &str) -> (ClashInstance, u16) {
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
    url: {health_url}
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
    .expect("failed to start provider API client");
    (clash, api_port)
}

async fn request(
    api_port: u16,
    method: http::Method,
    path: &str,
) -> http::Response<hyper::body::Incoming> {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .method(method)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build provider API request");
    send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send provider API request")
}

async fn response_json(
    response: http::Response<hyper::body::Incoming>,
) -> serde_json::Value {
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect provider response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse provider response")
}

fn mock_server() -> httpmock::MockServer {
    let server = httpmock::MockServer::start();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");
        then.status(200).body("ok");
    });
    server
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_provider() {
    let mock = mock_server();
    let (_clash, api_port) = start_client(&mock.url("/"));
    let response =
        request(api_port, http::Method::GET, "/providers/proxies/url-test").await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["name"], "url-test");
    assert!(json["type"].is_string());
    assert!(json["vehicleType"].is_string());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_put_provider() {
    let mock = mock_server();
    let (_clash, api_port) = start_client(&mock.url("/"));
    let response =
        request(api_port, http::Method::PUT, "/providers/proxies/url-test").await;
    assert_eq!(response.status(), http::StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_provider_healthcheck() {
    let mock = mock_server();
    let (_clash, api_port) = start_client(&mock.url("/"));
    let response = request(
        api_port,
        http::Method::GET,
        "/providers/proxies/url-test/healthcheck",
    )
    .await;
    assert_eq!(response.status(), http::StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_proxy_from_provider() {
    let mock = mock_server();
    let (_clash, api_port) = start_client(&mock.url("/"));
    let response = request(
        api_port,
        http::Method::GET,
        "/providers/proxies/url-test/DIRECT",
    )
    .await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["name"], "DIRECT");
    assert_eq!(json["type"], "Direct");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_provider_proxy_healthcheck() {
    let mock = mock_server();
    let (_clash, api_port) = start_client(&mock.url("/"));
    let target = mock.url("/").replace(':', "%3A").replace('/', "%2F");
    let path = format!(
        "/providers/proxies/url-test/DIRECT/healthcheck?url={target}&timeout=5000"
    );
    let response = request(api_port, http::Method::GET, &path).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["delay"].is_u64());
    assert!(json["overall"].is_u64());
}
