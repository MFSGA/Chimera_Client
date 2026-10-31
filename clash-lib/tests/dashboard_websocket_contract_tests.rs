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

fn start_client() -> (ClashInstance, u16) {
    let (api_port, socks_port) = available_ports();
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

    let traffic = first_json_message(api_port, "/traffic?token=clash-rs").await;
    assert!(traffic["up"].is_u64());
    assert!(traffic["down"].is_u64());

    let connections =
        first_json_message(api_port, "/connections?token=clash-rs").await;
    assert!(connections["connections"].is_array());
    assert!(connections["downloadTotal"].is_u64());
    assert!(connections["uploadTotal"].is_u64());
    assert!(connections["memory"].is_u64());

    let flows =
        first_json_message(api_port, "/flows?token=clash-rs&interval=1&top=10")
            .await;
    assert!(flows.is_array());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn dashboard_websocket_rejects_invalid_query_token() {
    let (_clash, api_port) = start_client();
    let url = format!("ws://127.0.0.1:{api_port}/traffic?token=invalid");

    match connect_async(url).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        }
        Err(error) => panic!("unexpected WebSocket handshake error: {error}"),
        Ok(_) => panic!("WebSocket upgrade should reject an invalid token"),
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn active_dashboard_websocket_closes_when_runtime_stops() {
    let (api_port, socks_port) = available_ports();
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
rules:
  - MATCH,DIRECT
"#
    );
    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let options = Options {
        config: Config::Str(config),
        cwd: Some(cwd.to_string_lossy().to_string()),
        rt: None,
        log_file: None,
        config_path: None,
    };
    let (handle, token) = tokio::task::spawn_blocking(move || {
        clash_lib::start_scaffold_instance(options)
    })
    .await
    .expect("runtime startup worker should not panic")
    .expect("runtime should start before opening the WebSocket");

    let url = format!("ws://127.0.0.1:{api_port}/traffic?token=clash-rs");
    let websocket_result: Result<(), String> = async {
        let (mut socket, response) =
            tokio::time::timeout(Duration::from_secs(5), connect_async(url))
                .await
                .map_err(|_| "WebSocket connect timed out".to_owned())?
                .map_err(|error| format!("WebSocket connect failed: {error}"))?;
        if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
            return Err(format!(
                "unexpected WebSocket status {}",
                response.status()
            ));
        }

        let first_message =
            tokio::time::timeout(Duration::from_secs(3), socket.next())
                .await
                .map_err(|_| "WebSocket payload timed out".to_owned())?
                .ok_or_else(|| {
                    "WebSocket closed before its first payload".to_owned()
                })?
                .map_err(|error| format!("WebSocket receive failed: {error}"))?;
        if !matches!(first_message, Message::Text(_)) {
            return Err(format!(
                "expected a traffic JSON message, received {first_message:?}"
            ));
        }

        token.cancel();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match socket.next().await {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                    Some(_) => continue,
                }
            }
        })
        .await
        .map_err(|_| {
            "active WebSocket stayed open after runtime shutdown".to_owned()
        })?;
        drop(socket);
        Ok(())
    }
    .await;

    token.cancel();
    let join_result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || handle.join()),
    )
    .await
    .expect("runtime thread did not stop after cancellation")
    .expect("runtime join worker should not panic");
    assert!(join_result.is_ok(), "runtime thread should exit cleanly");
    assert!(
        websocket_result.is_ok(),
        "WebSocket shutdown assertion failed: {websocket_result:?}"
    );
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", api_port)).is_err(),
        "API listener should be closed after runtime shutdown"
    );
}
