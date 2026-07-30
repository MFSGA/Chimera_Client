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

fn start_client() -> (ClashInstance, u16, u16) {
    let api_port = available_port();
    let socks_port = available_port();
    let config = format!(
        "allow-lan: true\n\
bind-address: 0.0.0.0\n\
socks-port: {socks_port}\n\
mode: direct\n\
log-level: error\n\
mmdb: null\n\
external-controller: 127.0.0.1:{api_port}\n\
secret: clash-rs\n\
tun:\n\
  enable: false\n\
proxies:\n\
  - {{name: DIRECT_alias, type: direct}}\n\
rules:\n\
  - MATCH,DIRECT\n"
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
    (clash, api_port, socks_port)
}

fn start_dns_client() -> (ClashInstance, u16, u16) {
    let api_port = available_port();
    let socks_port = available_port();
    let dns_port = available_port();
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
dns:
  enable: true
  listen:
    udp: 127.0.0.1:{dns_port}
    tcp: 127.0.0.1:{dns_port}
  default-nameserver:
    - 127.0.0.1
  nameserver:
    - 127.0.0.1
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
    let clash = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port, dns_port],
    )
    .expect("failed to start DNS-enabled API client");
    (clash, api_port, dns_port)
}

async fn get_configs(api_port: u16) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}/configs");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer clash-rs")
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

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_configs_listeners() {
    let (_clash, api_port, socks_port) = start_client();
    let json = get_configs(api_port).await;
    let listeners = json["listeners"]
        .as_array()
        .expect("listeners should be an array");
    assert!(!listeners.is_empty(), "listeners should not be empty");

    let socks = listeners
        .iter()
        .find(|listener| listener["port"] == socks_port)
        .expect("configured SOCKS listener should be reported");
    assert_eq!(socks["name"], "SOCKS-IN");
    assert_eq!(socks["type"], "socks");
    assert_eq!(socks["active"], true);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_configs_dns_listen_when_enabled() {
    let (_clash, api_port, dns_port) = start_dns_client();
    let json = get_configs(api_port).await;
    let dns_listen = json
        .get("dns-listen")
        .expect("dns-listen should be present when DNS is enabled");

    let expected = format!("127.0.0.1:{dns_port}");
    assert_eq!(dns_listen["udp"], expected);
    assert_eq!(dns_listen["tcp"], expected);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_configs_lan_ips_when_allow_lan() {
    let (_clash, api_port, _socks_port) = start_client();
    let json = get_configs(api_port).await;
    let lan_ips = json["lan-ips"]
        .as_array()
        .expect("lan-ips should be present when allow-lan is true");

    for value in lan_ips {
        let ip = value.as_str().expect("lan-ips entries should be strings");
        assert!(
            ip.parse::<std::net::Ipv4Addr>().is_ok(),
            "lan-ips should contain only IPv4 addresses, got {ip}"
        );
    }
}
