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
mode: direct
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
    .expect("failed to start API compatibility client");
    (clash, api_port)
}

async fn get_json(api_port: u16, path: &str) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build API request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send API request");
    assert_eq!(response.status(), http::StatusCode::OK);
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
async fn ref_compat_version_reports_non_meta_core() {
    let (_clash, api_port) = start_client();
    let json = get_json(api_port, "/version").await;
    assert!(json["version"].is_string());
    assert_eq!(json["meta"], false);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn ref_compat_proxy_collection_exposes_builtin_udp_flags() {
    let (_clash, api_port) = start_client();
    let json = get_json(api_port, "/proxies").await;
    assert_eq!(json["proxies"]["DIRECT"]["udp"], true);
    assert_eq!(json["proxies"]["REJECT"]["udp"], false);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn ref_compat_user_stats_is_empty_without_traffic() {
    let (_clash, api_port) = start_client();
    let first = get_json(api_port, "/user-stats").await;
    assert!(first.as_object().is_some_and(serde_json::Map::is_empty));

    let second = get_json(api_port, "/user-stats").await;
    assert!(second.as_object().is_some_and(serde_json::Map::is_empty));
}
