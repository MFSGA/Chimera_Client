use std::{fs, net::TcpListener as StdTcpListener, path::PathBuf, time::Duration};

use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod common;

use common::{ClashInstance, send_http_request};

fn available_ports() -> (u16, u16) {
    let first = StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve first test port");
    let second = StdTcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve second test port");
    let first_port = first.local_addr().unwrap().port();
    let second_port = second.local_addr().unwrap().port();
    (first_port, second_port)
}

fn start_client(strategy: &str) -> (ClashInstance, u16, u16) {
    let (api_port, socks_port) = available_ports();
    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: test-secret
tun:
  enable: false
proxy-groups:
  - name: balanced
    type: load-balance
    proxies:
      - DIRECT
      - REJECT
    url: http://127.0.0.1/
    interval: 3600
    lazy: true
    strategy: {strategy}
rules:
  - MATCH,balanced
"#
    );
    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let client = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port],
    )
    .expect("failed to start load-balance client");
    (client, api_port, socks_port)
}

fn start_file_provider_client() -> (tempfile::TempDir, ClashInstance, u16, u16) {
    let (api_port, socks_port) = available_ports();
    let cwd = tempfile::tempdir().expect("failed to create provider tempdir");
    fs::write(
        cwd.path().join("providers.yaml"),
        r#"
proxies:
  - name: provider-direct
    type: direct
  - name: provider-reject
    type: reject
"#,
    )
    .expect("failed to write provider file");
    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: test-secret
tun:
  enable: false
proxy-providers:
  local:
    type: file
    path: providers.yaml
    health-check:
      enable: false
proxy-groups:
  - name: balanced
    type: load-balance
    use:
      - local
    url: http://127.0.0.1/
    interval: 3600
    lazy: true
    strategy: round-robin
rules:
  - MATCH,balanced
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
        vec![api_port, socks_port],
    )
    .expect("failed to start file-provider client");
    (cwd, client, api_port, socks_port)
}

fn start_http_provider_client(
    provider_url: &str,
    interval: u64,
) -> (tempfile::TempDir, ClashInstance, u16, u16) {
    start_http_provider_client_with_cache(provider_url, interval, None)
}

fn start_http_provider_client_with_cache(
    provider_url: &str,
    interval: u64,
    cached_provider: Option<&str>,
) -> (tempfile::TempDir, ClashInstance, u16, u16) {
    let (api_port, socks_port) = available_ports();
    let cwd = tempfile::tempdir().expect("failed to create provider tempdir");
    if let Some(cached_provider) = cached_provider {
        fs::write(cwd.path().join("http-provider.yaml"), cached_provider)
            .expect("failed to write provider cache");
    }
    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: test-secret
tun:
  enable: false
proxy-providers:
  local:
    type: http
    url: {provider_url}
    path: http-provider.yaml
    interval: {interval}
    health-check:
      enable: false
proxy-groups:
  - name: balanced
    type: load-balance
    use:
      - local
    url: http://127.0.0.1/
    interval: 3600
    lazy: true
    strategy: round-robin
rules:
  - MATCH,balanced
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
        vec![api_port, socks_port],
    )
    .expect("failed to start HTTP-provider client");
    (cwd, client, api_port, socks_port)
}

async fn socks5_connect(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("failed to connect to SOCKS5 listener");
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    let [port_hi, port_lo] = target_port.to_be_bytes();
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port_hi, port_lo])
        .await
        .unwrap();
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[1], 0x00, "SOCKS5 CONNECT was rejected");
    let remaining = match header[3] {
        0x01 => 6,
        0x04 => 18,
        atyp => panic!("unexpected SOCKS5 response address type {atyp}"),
    };
    let mut address = vec![0u8; remaining];
    stream.read_exact(&mut address).await.unwrap();
    stream
}

async fn get_json(api_port: u16, path: &str) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build API request");
    let response = send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to query API");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("failed to collect API response")
            .aggregate()
            .reader(),
    )
    .expect("failed to parse API response")
}

async fn provider_update_status(api_port: u16, name: &str) -> http::StatusCode {
    let path = format!("/providers/proxies/{name}");
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let request = hyper::Request::builder()
        .uri(&url)
        .header(http::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::Method::PUT)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build provider update request");
    send_http_request(url.parse().unwrap(), request)
        .await
        .expect("failed to update provider")
        .status()
}

async fn put_provider(api_port: u16, name: &str) {
    assert_eq!(
        provider_update_status(api_port, name).await,
        http::StatusCode::ACCEPTED
    );
}

async fn wait_for_group_proxies(api_port: u16, expected: serde_json::Value) {
    for _ in 0..30 {
        let group = get_json(api_port, "/proxies/balanced").await;
        if group["all"] == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("proxy group did not refresh to {expected}");
}

async fn roundtrip(proxy_port: u16, target_port: u16, payload: &[u8]) -> bool {
    let mut stream = socks5_connect(proxy_port, target_port).await;
    if stream.write_all(payload).await.is_err() {
        return false;
    }
    let mut echoed = vec![0u8; payload.len()];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed)).await,
        Ok(Ok(_)) if echoed == payload
    )
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn load_balance_group_is_exposed_by_api() {
    let (_client, api_port, _socks_port) = start_client("round-robin");
    let group = get_json(api_port, "/proxies/balanced").await;
    assert_eq!(group["name"], "balanced");
    assert_eq!(group["type"], "LoadBalance");
    assert_eq!(group["all"], serde_json::json!(["DIRECT", "REJECT"]));
    assert!(group.get("now").is_none());
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn load_balance_rotates_real_tcp_connections() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = target.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0u8; 128];
                let len = stream.read(&mut request).await.unwrap();
                stream.write_all(&request[..len]).await.unwrap();
            });
        }
    });

    let (_client, _api_port, socks_port) = start_client("round-robin");
    assert!(roundtrip(socks_port, target_port, b"first-direct").await);
    assert!(!roundtrip(socks_port, target_port, b"second-reject").await);
    assert!(roundtrip(socks_port, target_port, b"third-direct").await);
    target_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn file_provider_populates_group_and_routes_real_tcp() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = target.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0u8; 128];
                let len = stream.read(&mut request).await.unwrap();
                stream.write_all(&request[..len]).await.unwrap();
            });
        }
    });

    let (_cwd, _client, api_port, socks_port) = start_file_provider_client();
    let provider = get_json(api_port, "/providers/proxies/local").await;
    assert_eq!(provider["name"], "local");
    let group = get_json(api_port, "/proxies/balanced").await;
    assert_eq!(group["all"], serde_json::json!(["DIRECT", "REJECT"]));

    assert!(roundtrip(socks_port, target_port, b"provider-first").await);
    assert!(!roundtrip(socks_port, target_port, b"provider-second").await);
    assert!(roundtrip(socks_port, target_port, b"provider-third").await);
    target_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn http_provider_downloads_caches_and_routes_real_tcp() {
    let server = httpmock::MockServer::start();
    let provider_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/providers.yaml");
        then.status(200).body(
            r#"
proxies:
  - name: remote-direct
    type: direct
  - name: remote-reject
    type: reject
"#,
        );
    });
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = target.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0u8; 128];
                let len = stream.read(&mut request).await.unwrap();
                stream.write_all(&request[..len]).await.unwrap();
            });
        }
    });

    let (cwd, _client, api_port, socks_port) =
        start_http_provider_client(&server.url("/providers.yaml"), 0);
    provider_mock.assert();
    assert!(cwd.path().join("http-provider.yaml").is_file());
    let provider = get_json(api_port, "/providers/proxies/local").await;
    assert_eq!(provider["name"], "local");
    let group = get_json(api_port, "/proxies/balanced").await;
    assert_eq!(group["all"], serde_json::json!(["DIRECT", "REJECT"]));

    assert!(roundtrip(socks_port, target_port, b"http-first").await);
    assert!(!roundtrip(socks_port, target_port, b"http-second").await);
    assert!(roundtrip(socks_port, target_port, b"http-third").await);
    target_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn http_provider_put_replaces_live_proxy_set() {
    let server = httpmock::MockServer::start();
    let mut direct_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/refresh.yaml");
        then.status(200).body(
            r#"
proxies:
  - name: remote-direct
    type: direct
"#,
        );
    });
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = [0u8; 128];
        let len = stream.read(&mut request).await.unwrap();
        stream.write_all(&request[..len]).await.unwrap();
    });

    let (cwd, _client, api_port, socks_port) =
        start_http_provider_client(&server.url("/refresh.yaml"), 0);
    assert!(roundtrip(socks_port, target_port, b"before-refresh").await);
    target_task.await.unwrap();

    direct_mock.delete();
    let reject_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/refresh.yaml");
        then.status(200).body(
            r#"
proxies:
  - name: remote-reject
    type: reject
"#,
        );
    });
    put_provider(api_port, "local").await;
    reject_mock.assert();

    let group = get_json(api_port, "/proxies/balanced").await;
    assert_eq!(group["all"], serde_json::json!(["REJECT"]));
    assert!(!roundtrip(socks_port, target_port, b"after-refresh").await);
    let cached = fs::read_to_string(cwd.path().join("http-provider.yaml"))
        .expect("failed to read refreshed provider cache");
    assert!(cached.contains("type: reject"));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn http_provider_starts_from_cache_during_remote_outage() {
    let server = httpmock::MockServer::start();
    let unavailable_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/offline.yaml");
        then.status(503).body("provider unavailable");
    });
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = [0u8; 128];
        let len = stream.read(&mut request).await.unwrap();
        stream.write_all(&request[..len]).await.unwrap();
    });
    let cached_provider = r#"
proxies:
  - name: cached-direct
    type: direct
"#;

    let (cwd, _client, api_port, socks_port) = start_http_provider_client_with_cache(
        &server.url("/offline.yaml"),
        1,
        Some(cached_provider),
    );
    wait_for_group_proxies(api_port, serde_json::json!(["DIRECT"])).await;
    for _ in 0..30 {
        if unavailable_mock.calls() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(unavailable_mock.calls() > 0);
    assert!(roundtrip(socks_port, target_port, b"cached-provider").await);
    target_task.await.unwrap();
    let cached = fs::read_to_string(cwd.path().join("http-provider.yaml"))
        .expect("failed to read provider cache after outage");
    assert!(cached.contains("type: direct"));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn failed_http_provider_refresh_keeps_live_proxy_set() {
    let server = httpmock::MockServer::start();
    let mut direct_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/failure.yaml");
        then.status(200).body(
            r#"
proxies:
  - name: stable-direct
    type: direct
"#,
        );
    });
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut request = [0u8; 128];
            let len = stream.read(&mut request).await.unwrap();
            stream.write_all(&request[..len]).await.unwrap();
        }
    });

    let (cwd, _client, api_port, socks_port) =
        start_http_provider_client(&server.url("/failure.yaml"), 0);
    assert!(roundtrip(socks_port, target_port, b"before-failure").await);

    direct_mock.delete();
    let invalid_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/failure.yaml");
        then.status(200).body("proxies: [");
    });
    assert_eq!(
        provider_update_status(api_port, "local").await,
        http::StatusCode::INTERNAL_SERVER_ERROR
    );
    invalid_mock.assert();

    let group = get_json(api_port, "/proxies/balanced").await;
    assert_eq!(group["all"], serde_json::json!(["DIRECT"]));
    assert!(roundtrip(socks_port, target_port, b"after-failure").await);
    target_task.await.unwrap();
    let cached = fs::read_to_string(cwd.path().join("http-provider.yaml"))
        .expect("failed to read provider cache after failed refresh");
    assert!(cached.contains("type: direct"));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn http_provider_interval_refreshes_live_proxy_set() {
    let server = httpmock::MockServer::start();
    let mut direct_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/interval.yaml");
        then.status(200).body(
            r#"
proxies:
  - name: interval-direct
    type: direct
"#,
        );
    });
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = [0u8; 128];
        let len = stream.read(&mut request).await.unwrap();
        stream.write_all(&request[..len]).await.unwrap();
    });

    let (cwd, _client, api_port, socks_port) =
        start_http_provider_client(&server.url("/interval.yaml"), 1);
    assert!(roundtrip(socks_port, target_port, b"before-interval").await);
    target_task.await.unwrap();

    direct_mock.delete();
    let reject_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/interval.yaml");
        then.status(200).body(
            r#"
proxies:
  - name: interval-reject
    type: reject
"#,
        );
    });
    wait_for_group_proxies(api_port, serde_json::json!(["REJECT"])).await;
    assert!(reject_mock.calls() >= 1);
    assert!(!roundtrip(socks_port, target_port, b"after-interval").await);
    let cached = fs::read_to_string(cwd.path().join("http-provider.yaml"))
        .expect("failed to read interval-refreshed cache");
    assert!(cached.contains("type: reject"));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn consistent_hash_keeps_real_tcp_target_stable() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = target.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 128];
                let len = stream.read(&mut request).await.unwrap();
                stream.write_all(&request[..len]).await.unwrap();
            });
        }
    });

    let (_client, _api_port, socks_port) = start_client("consistent-hashing");
    let outcomes = [
        roundtrip(socks_port, target_port, b"stable-one").await,
        roundtrip(socks_port, target_port, b"stable-two").await,
        roundtrip(socks_port, target_port, b"stable-three").await,
    ];
    assert!(outcomes.iter().all(|outcome| *outcome == outcomes[0]));
    target_task.abort();
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn sticky_session_keeps_real_tcp_target_stable() {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local target");
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = target.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 128];
                let len = stream.read(&mut request).await.unwrap();
                stream.write_all(&request[..len]).await.unwrap();
            });
        }
    });

    let (_client, _api_port, socks_port) = start_client("sticky-session");
    let outcomes = [
        roundtrip(socks_port, target_port, b"sticky-one").await,
        roundtrip(socks_port, target_port, b"sticky-two").await,
        roundtrip(socks_port, target_port, b"sticky-three").await,
    ];
    assert!(outcomes.iter().all(|outcome| *outcome == outcomes[0]));
    target_task.abort();
}
