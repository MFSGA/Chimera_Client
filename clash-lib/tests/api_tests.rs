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

async fn capability_api_request(
    port: u16,
    path: &str,
    method: http::Method,
    body: Option<String>,
) -> (http::StatusCode, Bytes) {
    let url = format!("http://127.0.0.1:{port}{path}");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(method)
        .body(http_body_util::Full::new(Bytes::from(
            body.unwrap_or_default(),
        )))
        .expect("failed to build client capability request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send client capability request");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("failed to collect client capability response")
        .to_bytes();
    (status, body)
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn client_capability_controller_endpoints_expose_validation_and_mode_override()
{
    let api_port = available_port();
    let (config_path, socks_port) = isolated_config(api_port);
    let config_payload = std::fs::read_to_string(&config_path)
        .expect("failed to read isolated test configuration");
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let _clash = ClashInstance::start(
        Options {
            config: Config::File(config_path.to_string_lossy().to_string()),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(config_path.to_string_lossy().to_string()),
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start isolated client");

    let (status, body) =
        capability_api_request(api_port, "/capabilities", http::Method::GET, None)
            .await;
    assert_eq!(status, http::StatusCode::OK);
    let capabilities: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(capabilities["outboundProtocols"].as_array().is_some());

    let (status, body) =
        capability_api_request(api_port, "/runtime", http::Method::GET, None).await;
    assert_eq!(status, http::StatusCode::OK);
    let runtime: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(runtime["application"]["phase"], "running");
    assert_eq!(runtime["application"]["health"], "healthy");
    assert!(
        runtime["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item["name"] == "api" && item["phase"] == "ready" })
    );

    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(serde_json::json!({ "payload": config_payload }).to_string()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], true);
    assert_eq!(
        validation["validationScope"],
        "offline-config-outbound-connector-and-group-validation"
    );

    let valid_connector_payload = r#"
proxies:
  - name: edge-a
    type: socks5
    server: 127.0.0.1
    port: 1080
    dialer-proxy: DIRECT
  - name: edge-b
    type: socks5
    server: 127.0.0.1
    port: 1081
    dialer-proxy: GLOBAL
  - name: edge-c
    type: socks5
    server: 127.0.0.1
    port: 1082
    dialer-proxy: relay-group
proxy-groups:
  - name: relay-group
    type: select
    proxies: [DIRECT]
"#;
    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(serde_json::json!({ "payload": valid_connector_payload }).to_string()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], true);

    let valid_group_payload = r#"
proxy-groups:
  - name: group-a
    type: select
    proxies: [DIRECT, REJECT]
rules:
  - MATCH,group-a
"#;
    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(serde_json::json!({ "payload": valid_group_payload }).to_string()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], true);

    let invalid_payload = "proxies:\n  - name: edge-a\n    type: not-supported\n";
    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(serde_json::json!({ "payload": invalid_payload }).to_string()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], false);
    assert_eq!(validation["errors"][0]["node"], "edge-a");
    assert_eq!(validation["errors"][0]["fieldPath"], "proxies[0].type");

    let missing_connector_payload = r#"
proxies:
  - name: edge-a
    type: socks5
    server: 127.0.0.1
    port: 1080
    dialer-proxy: missing-node
"#;
    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(
            serde_json::json!({ "payload": missing_connector_payload }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], false);
    assert!(
        validation["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| {
                issue["code"] == "outbound_connector_reference"
                    && issue["node"] == "edge-a"
                    && issue["fieldPath"] == "proxies.edge-a.dialer-proxy"
            })
    );

    let reserved_global_payload = r#"
proxies:
  - name: GLOBAL
    type: socks5
    server: 127.0.0.1
    port: 1080
"#;
    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(serde_json::json!({ "payload": reserved_global_payload }).to_string()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], false);
    assert!(
        validation["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| {
                issue["code"] == "proxy_name_reserved" && issue["node"] == "GLOBAL"
            })
    );

    let reserved_global_group_payload = r#"
proxy-groups:
  - name: GLOBAL
    type: select
    proxies: [DIRECT]
"#;
    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(
            serde_json::json!({ "payload": reserved_global_group_payload })
                .to_string(),
        ),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], false);
    assert!(
        validation["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| {
                issue["code"] == "proxy_group_name" && issue["node"] == "GLOBAL"
            })
    );

    let invalid_group_payload = r#"
proxy-groups:
  - name: group-a
    type: select
    proxies: [missing-node]
rules:
  - MATCH,group-a
"#;
    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(serde_json::json!({ "payload": invalid_group_payload }).to_string()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], false);
    assert_eq!(validation["errors"][0]["node"], "group-a");
    assert_eq!(
        validation["errors"][0]["fieldPath"],
        "proxy-groups.group-a.proxies[0]"
    );

    let cyclic_group_payload = r#"
proxy-groups:
  - name: group-a
    type: select
    proxies: [group-b]
  - name: group-b
    type: select
    proxies: [group-a]
rules:
  - MATCH,group-a
"#;
    let (status, body) = capability_api_request(
        api_port,
        "/configs/validate",
        http::Method::POST,
        Some(serde_json::json!({ "payload": cyclic_group_payload }).to_string()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(validation["valid"], false);
    assert!(
        validation["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| {
                error["code"] == "proxy_group_graph"
                    && error["fieldPath"] == "proxy-groups"
            })
    );

    let (status, body) = capability_api_request(
        api_port,
        "/proxies/DIRECT/history?url=https%3A%2F%2Fhealth.example%2Fcheck",
        http::Method::GET,
        None,
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!([])
    );

    let (status, body) =
        capability_api_request(api_port, "/configs/mode", http::Method::GET, None)
            .await;
    assert_eq!(status, http::StatusCode::OK);
    let mode: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(mode["configuredMode"], "direct");
    assert_eq!(mode["overrideMode"], serde_json::Value::Null);

    let (status, _) = capability_api_request(
        api_port,
        "/configs/mode",
        http::Method::PUT,
        Some(serde_json::json!({ "mode": "rule" }).to_string()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);

    let (status, body) = capability_api_request(
        api_port,
        "/configs/mode",
        http::Method::DELETE,
        None,
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let mode: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(mode["effectiveMode"], "direct");
    assert_eq!(mode["overrideMode"], serde_json::Value::Null);
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

    let status = response.status();
    let body = response
        .collect()
        .await
        .expect("Failed to collect network reset response")
        .to_bytes();
    assert_eq!(
        status,
        http::StatusCode::OK,
        "POST /network/reset response: {}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body)
        .expect("Failed to parse network reset response");
    assert_eq!(json["dnsTransportsReset"], 0);
    assert_eq!(json["connectionPoolsReset"], 0);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn runtime_path_preference_updates_are_versioned_and_temporary() {
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

    let get_url =
        format!("http://127.0.0.1:{api_port}/runtime/network/path-preference");
    let get = || {
        hyper::Request::builder()
            .uri(&get_url)
            .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
            .method(http::method::Method::GET)
            .body(http_body_util::Empty::<Bytes>::new())
            .expect("failed to build path preference GET")
    };
    let response = send_http_request(get_url.parse().unwrap(), get())
        .await
        .expect("failed to GET path preference");
    assert_eq!(response.status(), http::StatusCode::OK);
    let initial: serde_json::Value = serde_json::from_reader(
        response.collect().await.unwrap().aggregate().reader(),
    )
    .unwrap();
    assert_eq!(initial["policyVersion"], 0);
    assert_eq!(initial["priority"], serde_json::json!([]));

    let decisions_url =
        format!("http://127.0.0.1:{api_port}/runtime/network/path-decisions");
    let decisions_request = hyper::Request::builder()
        .uri(&decisions_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build path decisions GET");
    let response =
        send_http_request(decisions_url.parse().unwrap(), decisions_request)
            .await
            .expect("failed to GET path decisions");
    assert_eq!(response.status(), http::StatusCode::OK);
    let decisions: serde_json::Value = serde_json::from_reader(
        response.collect().await.unwrap().aggregate().reader(),
    )
    .unwrap();
    assert!(decisions.is_array());

    if initial["automaticSupported"] == false {
        // Platforms without a path observer report the capability explicitly;
        // the runtime preference write is intentionally unavailable there.
        return;
    }

    let put_body = serde_json::json!({
        "priority": [{ "interface": "ethernet", "family": "ipv4" }]
    });
    let put = hyper::Request::builder()
        .uri(&get_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(http_body_util::Full::new(Bytes::from(put_body.to_string())))
        .expect("failed to build path preference PUT");
    let response = send_http_request(get_url.parse().unwrap(), put)
        .await
        .expect("failed to PUT path preference");
    assert_eq!(response.status(), http::StatusCode::OK);
    let configured: serde_json::Value = serde_json::from_reader(
        response.collect().await.unwrap().aggregate().reader(),
    )
    .unwrap();
    assert_eq!(configured["policyVersion"], 1);
    assert_eq!(configured["priority"][0]["interface"], "ethernet");

    let effective_url =
        format!("http://127.0.0.1:{api_port}/runtime/network/effective-paths");
    let effective_request = hyper::Request::builder()
        .uri(&effective_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build effective paths GET");
    let response =
        send_http_request(effective_url.parse().unwrap(), effective_request)
            .await
            .expect("failed to GET effective paths");
    assert_eq!(response.status(), http::StatusCode::OK);
    let effective: serde_json::Value = serde_json::from_reader(
        response.collect().await.unwrap().aggregate().reader(),
    )
    .unwrap();
    assert_eq!(effective["policyVersion"], 1);
    assert_eq!(effective["configuredPriority"][0]["interface"], "ethernet");

    let temporary_body = serde_json::json!({
        "priority": [{ "interface": "wifi", "family": "ipv6" }],
        "ttlMs": 60000
    });
    let temporary = hyper::Request::builder()
        .uri(&get_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(http_body_util::Full::new(Bytes::from(
            temporary_body.to_string(),
        )))
        .expect("failed to build temporary path preference PUT");
    let response = send_http_request(get_url.parse().unwrap(), temporary)
        .await
        .expect("failed to PUT temporary path preference");
    assert_eq!(response.status(), http::StatusCode::OK);
    let temporary: serde_json::Value = serde_json::from_reader(
        response.collect().await.unwrap().aggregate().reader(),
    )
    .unwrap();
    assert_eq!(temporary["policyVersion"], 2);
    assert_eq!(temporary["source"], "temporaryOverride");
    assert!(temporary["expiresAtMs"].as_i64().is_some());

    let clear = hyper::Request::builder()
        .uri(&get_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::DELETE)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build temporary preference DELETE");
    let response = send_http_request(get_url.parse().unwrap(), clear)
        .await
        .expect("failed to clear temporary path preference");
    assert_eq!(response.status(), http::StatusCode::OK);
    let restored: serde_json::Value = serde_json::from_reader(
        response.collect().await.unwrap().aggregate().reader(),
    )
    .unwrap();
    assert_eq!(restored["policyVersion"], 3);
    assert_eq!(restored["source"], "runtime");
    assert_eq!(restored["priority"][0]["interface"], "ethernet");

    let unknown_flow = uuid::Uuid::new_v4();
    let decision_url = format!(
        "http://127.0.0.1:{api_port}/runtime/network/path-decision/{unknown_flow}"
    );
    let decision_request = hyper::Request::builder()
        .uri(&decision_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build path decision GET");
    let response =
        send_http_request(decision_url.parse().unwrap(), decision_request)
            .await
            .expect("failed to GET path decision");
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn connection_summary_avoids_full_connection_payload() {
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

    let url = format!("http://127.0.0.1:{api_port}/connections/summary");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build connection summary request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("Failed to send GET /connections/summary request");

    assert_eq!(response.status(), http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect connection summary response")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse connection summary response");
    assert_eq!(json["downloadTotal"], 0);
    assert_eq!(json["uploadTotal"], 0);
    assert_eq!(json["connectionCount"], 0);
    assert!(json.get("connections").is_none());
    assert!(json.get("memory").is_none());
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
