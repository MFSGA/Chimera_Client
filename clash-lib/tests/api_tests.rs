use crate::common::{ClashInstance, send_http_request};
use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{net::TcpListener, path::PathBuf, time::Duration};

mod common;

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve test port")
        .local_addr()
        .expect("failed to inspect test port")
        .port()
}

fn isolated_config(api_port: u16) -> (PathBuf, u16) {
    let socks_port = available_port();
    let path = std::env::temp_dir().join(format!(
        "chimera-api-test-{api_port}-{}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!(
            "allow-lan: true\n\
bind-address: 0.0.0.0\n\
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
        ),
    )
    .expect("failed to write isolated test configuration");
    (path, socks_port)
}

async fn get_allow_lan(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/configs", port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect response body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON response");
    json.get("allow-lan")
        .and_then(|v| v.as_bool())
        .expect("'allow-lan' not found or not a bool")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_config_reload_via_payload() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_path = wd.join("rules.yaml");
    assert!(
        config_path.exists(),
        "Config file does not exist at: {}",
        config_path.to_string_lossy()
    );

    let api_port = available_port();
    let reload_api_port = available_port();
    let (isolated_config, socks_port) = isolated_config(api_port);
    let _clash = ClashInstance::start(
        Options {
            config: Config::File(isolated_config.to_string_lossy().to_string()),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(isolated_config.to_string_lossy().to_string()),
        },
        vec![api_port, reload_api_port, socks_port],
    )
    .expect("Failed to start clash");

    assert!(
        get_allow_lan(api_port).await,
        "expected allow-lan=true before reload"
    );

    let new_payload = format!(
        r#"
socks-port: 7892
bind-address: 127.0.0.1
allow-lan: false
mode: direct
log-level: info
mmdb: null
external-controller: 127.0.0.1:{reload_api_port}
secret: clash-rs
tun:
  enable: false
proxies:
  - {{name: DIRECT_alias, type: direct}}
  - {{name: REJECT_alias, type: reject}}
"#
    );
    let body = serde_json::json!({ "payload": new_payload }).to_string();

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /configs request");
    assert_eq!(
        res.status(),
        http::StatusCode::NO_CONTENT,
        "PUT /configs should return 204 No Content"
    );

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        !get_allow_lan(reload_api_port).await,
        "expected allow-lan=false after reload"
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_set_allow_lan() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_path = wd.join("rules.yaml");
    assert!(
        config_path.exists(),
        "Config file does not exist at: {}",
        config_path.to_string_lossy()
    );

    let api_port = available_port();
    let (isolated_config, socks_port) = isolated_config(api_port);
    let _clash = ClashInstance::start(
        Options {
            config: Config::File(isolated_config.to_string_lossy().to_string()),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(isolated_config.to_string_lossy().to_string()),
        },
        vec![api_port, socks_port],
    )
    .expect("Failed to start clash");

    assert!(
        get_allow_lan(api_port).await,
        "'allow_lan' should be true by config"
    );

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body("{\"allow-lan\": false}".into())
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), http::StatusCode::ACCEPTED);

    assert!(
        !get_allow_lan(api_port).await,
        "'allow_lan' should be false after update"
    );
}
