#![cfg(feature = "anytls")]

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

fn start_multiuser_server() -> (ClashInstance, u16) {
    let api_port = available_port();
    let anytls_port = available_port();
    let config = format!(
        r#"
allow-lan: false
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: test-secret
tun:
  enable: false
listeners:
  - name: anytls-multiuser
    type: anytls
    listen: 127.0.0.1
    port: {anytls_port}
    password: default-password
    users:
      - name: user1
        password: user1-password
      - name: user2
        password: user2-password
rules:
  - MATCH,DIRECT
"#
    );
    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let server = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, anytls_port],
    )
    .expect("failed to start AnyTLS multiuser server");
    (server, api_port)
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_user_stats_endpoint_empty_on_no_traffic() {
    let (_server, api_port) = start_multiuser_server();
    let url = format!("http://127.0.0.1:{api_port}/user-stats");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build user-stats request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send user-stats request");
    assert_eq!(response.status(), http::StatusCode::OK);

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect user-stats response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse user-stats response");
    assert_eq!(json, serde_json::json!({}));
}
