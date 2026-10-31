#![cfg(feature = "ws")]

use clash_lib::{Config, Options};
use futures::StreamExt;
use std::{net::TcpListener, path::PathBuf, time::Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};

mod common;

use common::ClashInstance;

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

#[tokio::test(flavor = "current_thread")]
async fn dashboard_log_websocket_streams_serialized_events() {
    let (api_port, socks_port) = available_ports();
    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: direct
log-level: debug
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
    let _clash = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start isolated Dashboard log API client");

    let url = format!("ws://127.0.0.1:{api_port}/ws/logs?token=clash-rs");
    let (mut socket, response) = connect_async(url)
        .await
        .expect("failed to connect to authenticated Dashboard log WebSocket");
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);

    for _ in 0..20 {
        tracing::warn!(
            target: "clash::dashboard_contract_test",
            "dashboard_contract_log_event"
        );
        match tokio::time::timeout(Duration::from_millis(100), socket.next()).await {
            Err(_) => continue,
            Ok(Some(Ok(Message::Text(body)))) => {
                let event: serde_json::Value = serde_json::from_str(body.as_ref())
                    .expect("Dashboard log event should be JSON");
                assert_eq!(event["type"], "warning");
                assert!(
                    event["payload"]
                        .as_str()
                        .is_some_and(|payload| payload
                            .contains("dashboard_contract_log_event")),
                    "unexpected Dashboard log payload: {event}"
                );
                return;
            }
            Ok(Some(Ok(message))) => {
                panic!(
                    "Dashboard log WebSocket should send text JSON, got {message:?}"
                );
            }
            Ok(Some(Err(error))) => {
                panic!("failed to receive Dashboard log event: {error}");
            }
            Ok(None) => {
                panic!("Dashboard log WebSocket closed before sending an event")
            }
        }
    }
    panic!("timed out waiting for a Dashboard log WebSocket event");
}
