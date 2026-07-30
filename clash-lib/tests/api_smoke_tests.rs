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

fn start_client() -> (ClashInstance, u16) {
    let api_port = available_port();
    let socks_port = available_port();
    let config = format!(
        "allow-lan: false\n\
bind-address: 127.0.0.1\n\
socks-port: {socks_port}\n\
mode: direct\n\
log-level: info\n\
mmdb: null\n\
external-controller: 127.0.0.1:{api_port}\n\
secret: clash-rs\n\
tun:\n\
  enable: false\n\
proxies:\n\
  - {{name: DIRECT_alias, type: direct}}\n\
  - {{name: REJECT_alias, type: reject}}\n\
rules:\n\
  - MATCH,DIRECT\n"
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
    .expect("failed to start isolated API client");
    (clash, api_port)
}

async fn get(
    api_port: u16,
    path: &str,
    authenticated: bool,
) -> http::Response<hyper::body::Incoming> {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let mut builder = hyper::Request::builder()
        .uri(&url)
        .method(http::Method::GET);
    if authenticated {
        builder = builder.header(http::header::AUTHORIZATION, "Bearer clash-rs");
    }
    let request = builder
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build API request");
    send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send API request")
}

async fn response_json(
    response: http::Response<hyper::body::Incoming>,
) -> serde_json::Value {
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect API response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse API response JSON")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_hello_endpoint() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response_json(response).await["hello"], "clash-rs");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_version_endpoint() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/version", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(response_json(response).await["version"].is_string());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_memory_endpoint() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/memory", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["inuse"].is_u64());
    assert_eq!(json["oslimit"], 0);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_auth_required() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/", false).await;
    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
}
