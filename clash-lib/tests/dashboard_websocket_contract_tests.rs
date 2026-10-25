#![cfg(feature = "ws")]

use clash_lib::{Config, Options};
use futures::StreamExt;
use std::{net::TcpListener, path::PathBuf, time::Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};

mod common;

use common::ClashInstance;

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve API test port")
        .local_addr()
        .expect("failed to inspect API test port")
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
    .expect("failed to start isolated WebSocket API client");
    (clash, api_port)
}

async fn first_json_message(api_port: u16, path: &str) -> serde_json::Value {
    let url = format!("ws://127.0.0.1:{api_port}{path}");
    let (mut socket, response) = connect_async(url)
        .await
        .expect("failed to connect to authenticated Dashboard WebSocket");
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);

    let message = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("timed out waiting for Dashboard WebSocket payload")
        .expect("Dashboard WebSocket closed before sending a payload")
        .expect("failed to receive Dashboard WebSocket payload");
    let Message::Text(body) = message else {
        panic!("Dashboard WebSocket should send a text JSON payload");
    };
    serde_json::from_str(body.as_ref()).expect("Dashboard payload should be JSON")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn dashboard_websocket_payloads_match_typescript_models() {
    let (_clash, api_port) = start_client();

    let traffic = first_json_message(api_port, "/ws/traffic?token=clash-rs").await;
    assert!(traffic["up"].is_u64());
    assert!(traffic["down"].is_u64());

    let connections =
        first_json_message(api_port, "/ws/connections?token=clash-rs").await;
    assert!(connections["connections"].is_array());
    assert!(connections["downloadTotal"].is_u64());
    assert!(connections["uploadTotal"].is_u64());
    assert!(connections["memory"].is_u64());

    let flows =
        first_json_message(api_port, "/ws/flows?token=clash-rs&interval=1&top=10")
            .await;
    assert!(flows.is_array());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn dashboard_websocket_rejects_invalid_query_token() {
    let (_clash, api_port) = start_client();
    let url = format!("ws://127.0.0.1:{api_port}/ws/traffic?token=invalid");

    match connect_async(url).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        }
        Err(error) => panic!("unexpected WebSocket handshake error: {error}"),
        Ok(_) => panic!("WebSocket upgrade should reject an invalid token"),
    }
}
