use clash_lib::{Config, Options};
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
proxy-groups:
  - name: selector
    type: select
    proxies:
      - DIRECT
      - REJECT
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
    .expect("failed to start selector API client");
    (clash, api_port)
}

async fn put_selection(
    api_port: u16,
    proxy: &str,
    selected: &str,
) -> http::StatusCode {
    let url = format!("http://127.0.0.1:{api_port}/proxies/{proxy}");
    let body = serde_json::json!({ "name": selected }).to_string();
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .header(http::header::CONTENT_TYPE, "application/json")
        .method(http::Method::PUT)
        .body(body)
        .expect("failed to build proxy selection request");
    send_http_request::<String>(url.parse().unwrap(), request)
        .await
        .expect("failed to send proxy selection request")
        .status()
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_update_proxy_selector() {
    let (_clash, api_port) = start_client();
    assert_eq!(
        put_selection(api_port, "selector", "REJECT").await,
        http::StatusCode::ACCEPTED
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_update_proxy_selector_invalid() {
    let (_clash, api_port) = start_client();
    assert_eq!(
        put_selection(api_port, "selector", "this-proxy-does-not-exist").await,
        http::StatusCode::BAD_REQUEST
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_update_non_selector_proxy_returns_not_found() {
    let (_clash, api_port) = start_client();
    assert_eq!(
        put_selection(api_port, "DIRECT", "DIRECT").await,
        http::StatusCode::NOT_FOUND
    );
}
