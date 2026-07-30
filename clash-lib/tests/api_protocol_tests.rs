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

#[cfg(feature = "shadowsocks")]
fn start_shadowsocks_client() -> (ClashInstance, u16) {
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
tun:
  enable: false
proxies:
  - name: ss-simple
    type: ss
    server: 127.0.0.1
    port: 8901
    cipher: 2022-blake3-aes-256-gcm
    password: 3SYJ/f8nmVuzKvKglykRQDSgg10e/ADilkdRWrrY9HU=
    udp: true
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
    .expect("failed to start Shadowsocks API client");
    (clash, api_port)
}

#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_plain_proxy_api_response_shadowsocks() {
    let (_clash, api_port) = start_shadowsocks_client();
    let url = format!("http://127.0.0.1:{api_port}/proxies/ss-simple");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build Shadowsocks API request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send Shadowsocks API request");
    assert_eq!(response.status(), http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect Shadowsocks API response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse Shadowsocks API response");

    assert_eq!(json["name"], "ss-simple");
    assert_eq!(json["type"], "Shadowsocks");
    assert_eq!(json["server"], "127.0.0.1");
    assert_eq!(json["port"], 8901);
    assert_eq!(json["cipher"], "2022-blake3-aes-256-gcm");
    assert!(json.get("password").is_some());
    assert_eq!(json["udp"], true);
}
