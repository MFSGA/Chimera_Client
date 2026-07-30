use bytes::Bytes;
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
mode: direct
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: clash-rs
dns:
  enable: false
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
    .expect("failed to start isolated API client");
    (clash, api_port)
}

async fn get(api_port: u16, path: &str) -> http::Response<hyper::body::Incoming> {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build API request");
    send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send API request")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_provider_not_found() {
    let (_clash, api_port) = start_client();
    let response =
        get(api_port, "/providers/proxies/nonexistent-provider-xyz").await;
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_dns_query_when_disabled() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/dns/query?name=example.com&type=A").await;
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_dns_query_invalid_hostname() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/dns/query?name=&type=A").await;
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
}
