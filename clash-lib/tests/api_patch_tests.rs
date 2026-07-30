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

fn configs_url(api_port: u16) -> String {
    format!("http://127.0.0.1:{api_port}/configs")
}

fn auth_get(url: &str) -> hyper::Request<http_body_util::Empty<Bytes>> {
    hyper::Request::builder()
        .uri(url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::Method::GET)
        .body(http_body_util::Empty::new())
        .expect("failed to build GET /configs request")
}

async fn get_configs(api_port: u16) -> serde_json::Value {
    let url = configs_url(api_port);
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("failed to send GET /configs request");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect GET /configs response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse GET /configs response")
}

async fn patch_configs(api_port: u16, body: String) -> http::StatusCode {
    let url = configs_url(api_port);
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .header(http::header::CONTENT_TYPE, "application/json")
        .method(http::Method::PATCH)
        .body(body)
        .expect("failed to build PATCH /configs request");
    send_http_request::<String>(url.parse().unwrap(), request)
        .await
        .expect("failed to send PATCH /configs request")
        .status()
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_patch_mode_roundtrip() {
    let (_clash, api_port) = start_client();
    assert_eq!(get_configs(api_port).await["mode"], "rule");

    for mode in ["direct", "global", "rule"] {
        let body = serde_json::json!({ "mode": mode }).to_string();
        assert_eq!(
            patch_configs(api_port, body).await,
            http::StatusCode::ACCEPTED
        );
        assert_eq!(get_configs(api_port).await["mode"], mode);
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_patch_mode_does_not_block_get_configs() {
    let (_clash, api_port) = start_client();
    let url = configs_url(api_port);
    let patch = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .header(http::header::CONTENT_TYPE, "application/json")
        .method(http::Method::PATCH)
        .body(r#"{"mode":"direct"}"#.to_owned())
        .expect("failed to build PATCH /configs request");

    let (patch_response, get_response) = tokio::join!(
        send_http_request::<String>(url.parse().unwrap(), patch),
        send_http_request(url.parse().unwrap(), auth_get(&url)),
    );
    assert_eq!(
        patch_response.expect("PATCH should complete").status(),
        http::StatusCode::ACCEPTED
    );
    assert_eq!(
        get_response.expect("GET should complete").status(),
        http::StatusCode::OK
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_patch_mode_and_log_level_together() {
    let (_clash, api_port) = start_client();
    let body = serde_json::json!({
        "mode": "global",
        "log-level": "warning"
    })
    .to_string();
    assert_eq!(
        patch_configs(api_port, body).await,
        http::StatusCode::ACCEPTED
    );

    let json = get_configs(api_port).await;
    assert_eq!(json["mode"], "global");
    assert_eq!(json["log-level"], "warning");
}
