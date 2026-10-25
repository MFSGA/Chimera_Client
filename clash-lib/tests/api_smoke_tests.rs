use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{net::TcpListener, path::PathBuf};

mod common;

use common::{ClashInstance, send_http_request};

fn available_ports() -> (u16, u16) {
    let api_listener =
        TcpListener::bind("127.0.0.1:0").expect("failed to reserve API test port");
    let socks_listener =
        TcpListener::bind("127.0.0.1:0").expect("failed to reserve SOCKS test port");
    let api_port = api_listener
        .local_addr()
        .expect("failed to inspect API test port")
        .port();
    let socks_port = socks_listener
        .local_addr()
        .expect("failed to inspect SOCKS test port")
        .port();
    (api_port, socks_port)
}

fn start_client() -> (ClashInstance, u16) {
    let (api_port, socks_port) = available_ports();
    let config = format!(
        r#"allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: direct
log-level: info
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: clash-rs
tun:
  enable: false
proxies:
  - {{name: DIRECT_alias, type: direct}}
  - {{name: REJECT_alias, type: reject}}
rule-providers:
  api-contract:
    type: inline
    behavior: domain
    payload:
      - DOMAIN,example.com
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

async fn get(
    api_port: u16,
    path: &str,
    authenticated: bool,
) -> http::Response<hyper::body::Incoming> {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let mut builder = hyper::Request::builder()
        .uri(&url)
        .method(http::Method::GET);
    if authenticated {
        builder = builder.header(http::header::AUTHORIZATION, "Bearer clash-rs");
    }
    let request = builder
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build API request");
    send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send API request")
}

async fn response_json(
    response: http::Response<hyper::body::Incoming>,
) -> serde_json::Value {
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
async fn test_hello_endpoint() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response_json(response).await["hello"], "clash-rs");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_version_endpoint() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/version", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["version"].is_string());
    assert!(json["meta"].is_boolean());
    assert!(json.get("premium").is_none());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_capabilities_endpoint_matches_dashboard_contract() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/capabilities", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["platform"]["os"].is_string());
    assert!(json["platform"]["architecture"].is_string());
    let outbound_protocols = json["outboundProtocols"]
        .as_array()
        .expect("outboundProtocols should be an array");
    assert!(
        outbound_protocols.iter().all(serde_json::Value::is_string),
        "outboundProtocols should contain only strings"
    );
    for protocol in ["direct", "reject", "socks5", "vless"] {
        assert!(
            outbound_protocols.iter().any(|item| item == protocol),
            "outboundProtocols should include {protocol}"
        );
    }
    assert!(
        json["features"]
            .as_array()
            .is_some_and(|items| items.iter().all(serde_json::Value::is_string))
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_memory_endpoint() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/memory", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["inuse"].is_u64());
    assert_eq!(json["oslimit"], 0);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_dashboard_controller_response_shapes() {
    let (_clash, api_port) = start_client();

    let response = get(api_port, "/configs", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let config = response_json(response).await;
    assert!(config["socks-port"].is_u64());
    assert!(config["bind-address"].is_string());
    assert!(config["mode"].is_string());
    assert!(config["log-level"].is_string());
    assert!(config["ipv6"].is_boolean());
    assert!(config["allow-lan"].is_boolean());
    assert!(config["listeners"].is_array());

    let response = get(api_port, "/proxies", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let proxies = response_json(response).await;
    let direct = &proxies["proxies"]["DIRECT"];
    assert!(direct["name"].is_string());
    assert!(direct["type"].is_string());
    assert!(direct["udp"].is_boolean());
    assert!(direct["alive"].is_boolean());
    assert!(direct["history"].is_array());

    let response = get(api_port, "/providers/proxies", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(response_json(response).await["providers"].is_object());

    let response = get(api_port, "/providers/rules", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let rule_providers = response_json(response).await;
    assert!(rule_providers["providers"].is_object());
    let provider = &rule_providers["providers"]["api-contract"];
    assert!(
        provider["name"].is_string(),
        "rule provider response: {rule_providers}"
    );
    assert!(provider["type"].is_string());
    assert!(provider["vehicleType"].is_string());
    assert!(provider["behavior"].is_string());
    assert!(provider["format"].is_string());

    let response = get(api_port, "/rules", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let rules_response = response_json(response).await;
    let rules = rules_response["rules"]
        .as_array()
        .expect("rules should be an array");
    assert!(!rules.is_empty());
    assert!(rules[0]["type"].is_string());
    assert!(rules[0]["payload"].is_string());
    assert!(rules[0]["proxy"].is_string());

    let response = get(api_port, "/connections", true).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let connections = response_json(response).await;
    assert!(connections["connections"].is_array());
    assert!(connections["downloadTotal"].is_u64());
    assert!(connections["uploadTotal"].is_u64());
    assert!(connections["memory"].is_u64());

    let response = get(api_port, "/proxies/missing", true).await;
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("failed to collect error response")
        .to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("not found"));

    let response = get(api_port, "/configs", false).await;
    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_auth_required() {
    let (_clash, api_port) = start_client();
    let response = get(api_port, "/", false).await;
    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
}
