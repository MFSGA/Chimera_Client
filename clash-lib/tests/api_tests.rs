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

fn start_wildcard_cors_client() -> (ClashInstance, u16) {
    let api_port = available_port();
    let (config_path, socks_port) = isolated_config(api_port);
    let config = std::fs::read_to_string(&config_path)
        .expect("failed to read isolated test configuration");
    std::fs::write(
        &config_path,
        format!("{config}cors-allow-origins:\n  - \"*\"\n"),
    )
    .expect("failed to enable wildcard CORS for isolated test configuration");

    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let clash = ClashInstance::start(
        Options {
            config: Config::File(config_path.to_string_lossy().to_string()),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(config_path.to_string_lossy().to_string()),
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start client with wildcard CORS origins");

    (clash, api_port)
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
async fn test_wildcard_cors_returns_any_origin_header() {
    let (_clash, api_port) = start_wildcard_cors_client();
    let version_url = format!("http://127.0.0.1:{api_port}/version");
    let req = hyper::Request::builder()
        .uri(&version_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(http::header::ORIGIN, "https://example.com")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build CORS request");

    let res = send_http_request(version_url.parse().unwrap(), req)
        .await
        .expect("failed to send CORS request");

    assert_eq!(res.status(), http::StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_cors_preflight_without_auth_returns_cors_headers() {
    let (_clash, api_port) = start_wildcard_cors_client();
    let version_url = format!("http://127.0.0.1:{api_port}/version");
    let req = hyper::Request::builder()
        .uri(&version_url)
        .header(http::header::ORIGIN, "https://example.com")
        .header(http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .header(
            http::header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization",
        )
        .method(http::method::Method::OPTIONS)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build CORS preflight request");

    let res = send_http_request(version_url.parse().unwrap(), req)
        .await
        .expect("failed to send CORS preflight request");

    assert_eq!(res.status(), http::StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );
    assert!(
        res.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_METHODS)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("GET")),
        "preflight response should allow GET"
    );
    assert!(
        res.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("authorization")),
        "preflight response should allow Authorization"
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_config_reload_rejects_empty_or_directory_path_without_panicking() {
    let api_port = available_port();
    let (config_path, socks_port) = isolated_config(api_port);
    let config = std::fs::read_to_string(config_path)
        .expect("failed to read isolated test configuration");
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let _clash = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start isolated client");

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    for (body, message) in [
        ("{\"path\":\"\"}", "empty path"),
        ("{\"path\":\".\"}", "directory path"),
    ] {
        let req = hyper::Request::builder()
            .uri(&configs_url)
            .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .method(http::method::Method::PUT)
            .body(body.to_owned())
            .expect("failed to build invalid reload request");
        let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
            .await
            .expect("failed to send invalid reload request");
        assert_eq!(
            res.status(),
            http::StatusCode::BAD_REQUEST,
            "{message} should be rejected"
        );
    }

    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build health check request");
    let res = send_http_request(configs_url.parse().unwrap(), req)
        .await
        .expect("API should remain available after invalid reload requests");
    assert_eq!(res.status(), http::StatusCode::OK);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_config_reload_via_empty_path_uses_stored_config_path() {
    let api_port = available_port();
    let (config_path, socks_port) = isolated_config(api_port);
    let config_path = config_path.to_string_lossy().to_string();
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let _clash = ClashInstance::start(
        Options {
            config: Config::File(config_path.clone()),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(config_path),
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start isolated client with stored config path");

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body("{\"path\":\"\"}".to_owned())
        .expect("failed to build stored-path reload request");
    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("failed to send stored-path reload request");

    assert_eq!(
        res.status(),
        http::StatusCode::NO_CONTENT,
        "empty path should reload the stored config path"
    );
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
async fn network_reset_reports_dns_and_connection_pool_counts() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
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

    let url = format!("http://127.0.0.1:{api_port}/network/reset");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::POST)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build network reset request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("Failed to send POST /network/reset request");

    assert_eq!(response.status(), http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect network reset response")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse network reset response");
    assert_eq!(json["dnsTransportsReset"], 0);
    assert_eq!(json["connectionPoolsReset"], 0);
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
