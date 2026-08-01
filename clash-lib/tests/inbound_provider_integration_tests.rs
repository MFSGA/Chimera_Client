use std::net::TcpListener as StdTcpListener;

use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

mod common;

use common::{ClashInstance, send_http_request, wait_port_ready};

fn available_ports() -> (u16, u16) {
    let api =
        StdTcpListener::bind("127.0.0.1:0").expect("failed to reserve API port");
    let inbound =
        StdTcpListener::bind("127.0.0.1:0").expect("failed to reserve inbound port");
    let ports = (
        api.local_addr().unwrap().port(),
        inbound.local_addr().unwrap().port(),
    );
    drop((api, inbound));
    ports
}

fn start_file_provider_client() -> (tempfile::TempDir, ClashInstance, u16, u16) {
    let (api_port, inbound_port) = available_ports();
    let cwd = tempfile::tempdir().expect("failed to create provider tempdir");
    std::fs::write(
        cwd.path().join("inbound-provider.yaml"),
        format!(
            r#"
listeners:
  - name: provider-socks
    type: socks
    listen: 127.0.0.1
    port: {inbound_port}
    udp: false
"#
        ),
    )
    .expect("failed to write inbound provider file");

    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
mode: direct
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: test-secret
tun:
  enable: false
inbound-providers:
  local:
    type: file
    path: inbound-provider.yaml
    interval: 0
rules:
  - MATCH,DIRECT
"#
    );
    let client = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.path().to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, inbound_port],
    )
    .expect("failed to start file inbound-provider client");
    wait_port_ready(inbound_port).expect("provider SOCKS listener did not start");
    (cwd, client, api_port, inbound_port)
}

async fn get_configs(api_port: u16) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}/configs");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build GET /configs request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to send GET /configs request");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect GET /configs response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse GET /configs response")
}

async fn assert_socks_greeting(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("failed to connect to provider SOCKS listener");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("failed to send SOCKS greeting");
    let mut response = [0u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .expect("failed to read SOCKS greeting response");
    assert_eq!(response, [0x05, 0x00]);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn file_inbound_provider_starts_listener_and_exposes_it_by_api() {
    let (_cwd, _client, api_port, inbound_port) = start_file_provider_client();
    assert_socks_greeting(inbound_port).await;

    let configs = get_configs(api_port).await;
    let listener = configs["listeners"]
        .as_array()
        .expect("listeners should be an array")
        .iter()
        .find(|listener| listener["name"] == "provider-socks")
        .expect("provider listener should be exposed by API");
    assert_eq!(listener["type"], "socks");
    assert_eq!(listener["port"], inbound_port);
    assert_eq!(listener["active"], true);
}
