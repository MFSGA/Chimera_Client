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
  - {{name: REJECT_alias, type: reject}}
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
    .expect("failed to start isolated API client");
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
async fn test_plain_proxy_api_response_direct_reject() {
    let (_clash, api_port) = start_client();

    let direct = request(api_port, http::Method::GET, "/proxies/DIRECT").await;
    assert_eq!(direct.status(), http::StatusCode::OK);
    let direct = response_json(direct).await;
    assert_eq!(direct["name"], "DIRECT");
    assert_eq!(direct["type"], "Direct");
    assert_eq!(direct["udp"], true);

    let reject = request(api_port, http::Method::GET, "/proxies/REJECT").await;
    assert_eq!(reject.status(), http::StatusCode::OK);
    let reject = response_json(reject).await;
    assert_eq!(reject["name"], "REJECT");
    assert_eq!(reject["type"], "Reject");
    assert_eq!(reject["udp"], false);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_rules_endpoint() {
    let (_clash, api_port) = start_client();
    let response = request(api_port, http::Method::GET, "/rules").await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    let rules = json["rules"].as_array().expect("rules should be an array");
    assert!(!rules.is_empty(), "rules should not be empty");
    assert!(rules.iter().all(|rule| rule.get("type").is_some()));
    assert!(rules.iter().all(|rule| rule.get("payload").is_some()));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_delete_all_connections() {
    let (_clash, api_port) = start_client();
    let response = request(api_port, http::Method::DELETE, "/connections").await;
    assert_eq!(response.status(), http::StatusCode::OK);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_connections_rest() {
    let (_clash, api_port) = start_client();
    let response = request(api_port, http::Method::GET, "/connections").await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["connections"].is_array());
    assert!(json.get("downloadTotal").is_some());
    assert!(json.get("uploadTotal").is_some());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_delete_connection_by_id() {
    let (_clash, api_port) = start_client();
    let response = request(
        api_port,
        http::Method::DELETE,
        "/connections/00000000-0000-0000-0000-000000000000",
    )
    .await;
    assert_eq!(response.status(), http::StatusCode::OK);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_providers_endpoint() {
    let (_clash, api_port) = start_client();
    let response = request(api_port, http::Method::GET, "/providers/proxies").await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["providers"].is_object());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_proxy_not_found() {
    let (_clash, api_port) = start_client();
    let response = request(api_port, http::Method::GET, "/proxies/not-found").await;
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
}
