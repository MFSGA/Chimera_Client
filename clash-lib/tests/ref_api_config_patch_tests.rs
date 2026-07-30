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
        r#"allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: warning
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
    .expect("failed to start log-level patch client");
    (clash, api_port)
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn ref_compat_patch_log_level_is_visible_without_changing_mode() {
    let (_clash, api_port) = start_client();
    let url = format!("http://127.0.0.1:{api_port}/configs");
    let patch = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .header(http::header::CONTENT_TYPE, "application/json")
        .method(http::Method::PATCH)
        .body(r#"{"log-level":"info"}"#.to_owned())
        .expect("failed to build PATCH /configs request");
    let patch_response = send_http_request::<String>(url.parse().unwrap(), patch)
        .await
        .expect("failed to PATCH log-level");
    assert_eq!(patch_response.status(), http::StatusCode::ACCEPTED);

    let get = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build GET /configs request");
    let response = send_http_request(url.parse().unwrap(), get)
        .await
        .expect("failed to GET /configs");
    assert_eq!(response.status(), http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect GET /configs response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse GET /configs response");

    assert_eq!(json["log-level"], "info");
    assert_eq!(json["mode"], "rule");
}
