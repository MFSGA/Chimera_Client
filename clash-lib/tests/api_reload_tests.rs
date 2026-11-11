use std::{
    net::{Shutdown, TcpListener, TcpStream},
    path::PathBuf,
    time::Duration,
};

use bytes::Bytes;
use clash_lib::{Config, Options};
use futures::TryFutureExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;

fn wait_port_ready(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..30 {
        if let Ok(stream) = TcpStream::connect(&addr) {
            stream.shutdown(Shutdown::Both).ok();
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    panic!("port {port} did not become ready");
}

async fn send_http_request<T>(
    url: hyper::Uri,
    req: hyper::Request<T>,
) -> std::io::Result<http::Response<Incoming>>
where
    T: hyper::body::Body + Send + 'static,
    <T as hyper::body::Body>::Data: Send,
    <T as hyper::body::Body>::Error: Sync + Send + std::error::Error,
{
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let stream = tokio::net::TcpStream::connect(format!("{host}:{port}")).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .map_err(|err| std::io::Error::other(format!("handshake failed: {err}")))
        .await?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    sender
        .send_request(req)
        .map_err(|err| std::io::Error::other(format!("request failed: {err}")))
        .await
}

fn write_config(path: &PathBuf, api_port: u16, socks_port: u16, mode: &str) {
    write_config_with_extra(path, api_port, socks_port, mode, "");
}

fn write_config_with_extra(
    path: &PathBuf,
    api_port: u16,
    socks_port: u16,
    mode: &str,
    extra: &str,
) {
    std::fs::write(
        path,
        format!(
            "ipv6: false\n\
log_level: info\n\
mode: {mode}\n\
mmdb: null\n\
external-controller: 127.0.0.1:{api_port}\n\
socks-port: {socks_port}\n\
{extra}\
dns:\n\
  enable: false\n\
profile:\n\
  store_selected: false\n\
proxies: []\n\
rules:\n\
- MATCH,DIRECT\n"
        ),
    )
    .expect("failed to write config");
}

// The reload integration tests keep all DNS traffic on loopback. A Fake-IP
// query must be answered locally, without contacting a public resolver.
fn write_loopback_fake_ip_config(
    path: &PathBuf,
    api_port: u16,
    socks_port: u16,
    dns_port: u16,
    mode: &str,
) {
    write_loopback_fake_ip_config_with_range(
        path,
        api_port,
        socks_port,
        dns_port,
        mode,
        "198.18.0.0/24",
    );
}

fn write_loopback_fake_ip_config_with_range(
    path: &PathBuf,
    api_port: u16,
    socks_port: u16,
    dns_port: u16,
    mode: &str,
    fake_ip_range: &str,
) {
    std::fs::write(
        path,
        format!(
            r#"ipv6: false
log_level: error
mode: {mode}
mmdb: null
external-controller: 127.0.0.1:{api_port}
socks-port: {socks_port}
bind-address: 127.0.0.1
tun:
  enable: false
dns:
  enable: true
  ipv6: false
  listen:
    udp: 127.0.0.1:{dns_port}
  enhanced-mode: fake-ip
  fake-ip-range: {fake_ip_range}
  nameserver: ['udp://127.0.0.1:9']
  default-nameserver: [127.0.0.1]
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
rules:
  - MATCH,DIRECT
"#
        ),
    )
    .expect("failed to write loopback Fake-IP config");
}

async fn query_loopback_fake_ip_result(
    port: u16,
    host: &str,
) -> anyhow::Result<std::net::Ipv4Addr> {
    use hickory_proto::{
        op::{Message, Query, ResponseCode},
        rr::{Name, RData, RecordType},
    };

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let mut message = Message::query();
    message.metadata.id = 0x649a;
    message.metadata.recursion_desired = true;
    let mut question = Query::new();
    question.set_name(Name::from_ascii(format!("{host}."))?);
    question.set_query_type(RecordType::A);
    message.add_query(question);
    socket
        .send_to(&message.to_vec()?, format!("127.0.0.1:{port}"))
        .await?;

    let mut buffer = [0_u8; 1500];
    let received =
        tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buffer))
            .await??;
    let reply = Message::from_vec(&buffer[..received])?;
    anyhow::ensure!(
        reply.metadata.id == message.metadata.id,
        "DNS reply ID mismatch"
    );
    anyhow::ensure!(
        reply.queries.len() == 1,
        "DNS reply question count mismatch"
    );
    anyhow::ensure!(
        reply.queries[0].name() == message.queries[0].name(),
        "DNS reply question mismatch"
    );
    anyhow::ensure!(
        reply.metadata.response_code == ResponseCode::NoError,
        "DNS returned {:?} instead of NoError",
        reply.metadata.response_code
    );
    reply
        .answers
        .iter()
        .find_map(|answer| match &answer.data {
            RData::A(addr) => Some(**addr),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("Fake-IP DNS reply contained no A record"))
}

async fn query_loopback_fake_ip(port: u16, host: &str) -> std::net::Ipv4Addr {
    query_loopback_fake_ip_result(port, host)
        .await
        .expect("loopback Fake-IP resolver did not return an A record")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn put_configs_reloads_runtime_from_file() {
    let api_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve port")
        .local_addr()
        .expect("failed to read local addr")
        .port();
    let socks_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve socks port")
        .local_addr()
        .expect("failed to read socks local addr")
        .port();
    let temp_dir =
        std::env::temp_dir().join(format!("chimera-api-reload-{api_port}"));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let initial_config = temp_dir.join("initial.yaml");
    let reload_config = temp_dir.join("reload.yaml");
    write_config(&initial_config, api_port, socks_port, "global");
    write_config(&reload_config, api_port, socks_port, "rule");

    let cwd = temp_dir.clone();
    let runtime = std::thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::File(initial_config.to_string_lossy().to_string()),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(initial_config.to_string_lossy().to_string()),
        })
        .expect("failed to start clash");
    });

    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let get_request = || {
        hyper::Request::builder()
            .uri(&configs_url)
            .method(http::Method::GET)
            .body(http_body_util::Empty::<Bytes>::new())
            .expect("failed to build GET request")
    };

    let initial_response =
        send_http_request(configs_url.parse().unwrap(), get_request())
            .await
            .expect("failed to get configs");
    let initial_body = initial_response
        .collect()
        .await
        .expect("failed to read initial response")
        .to_bytes();
    let initial_json: serde_json::Value = serde_json::from_slice(&initial_body)
        .expect("failed to parse initial response");
    assert_eq!(initial_json["mode"], "global");

    let mode_url = format!("http://127.0.0.1:{api_port}/configs/mode");
    let mode_override_request = hyper::Request::builder()
        .uri(&mode_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(r#"{"mode":"direct"}"#)))
        .expect("failed to build mode override request");
    let mode_override_response =
        send_http_request(mode_url.parse().unwrap(), mode_override_request)
            .await
            .expect("failed to set mode override");
    assert_eq!(mode_override_response.status(), http::StatusCode::OK);
    let mode_override_body = mode_override_response
        .collect()
        .await
        .expect("failed to read mode override response")
        .to_bytes();
    let mode_override_json: serde_json::Value =
        serde_json::from_slice(&mode_override_body)
            .expect("failed to parse mode override response");
    assert_eq!(mode_override_json["configuredMode"], "global");
    assert_eq!(mode_override_json["effectiveMode"], "direct");
    assert_eq!(mode_override_json["overrideMode"], "direct");

    let put_request = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from("{\"path\":\"reload.yaml\"}")))
        .expect("failed to build PUT request");
    let put_response = send_http_request(configs_url.parse().unwrap(), put_request)
        .await
        .expect("failed to reload configs");
    assert_eq!(put_response.status(), http::StatusCode::NO_CONTENT);

    tokio::time::sleep(Duration::from_secs(1)).await;

    let reloaded_response =
        send_http_request(configs_url.parse().unwrap(), get_request())
            .await
            .expect("failed to get configs after reload");
    let reloaded_body = reloaded_response
        .collect()
        .await
        .expect("failed to read reloaded response")
        .to_bytes();
    let reloaded_json: serde_json::Value = serde_json::from_slice(&reloaded_body)
        .expect("failed to parse reloaded response");
    assert_eq!(reloaded_json["mode"], "rule");

    let reloaded_mode_request = hyper::Request::builder()
        .uri(&mode_url)
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build GET mode request after reload");
    let reloaded_mode_response =
        send_http_request(mode_url.parse().unwrap(), reloaded_mode_request)
            .await
            .expect("failed to get mode after reload");
    let reloaded_mode_body = reloaded_mode_response
        .collect()
        .await
        .expect("failed to read mode after reload")
        .to_bytes();
    let reloaded_mode_json: serde_json::Value =
        serde_json::from_slice(&reloaded_mode_body)
            .expect("failed to parse mode after reload");
    assert_eq!(reloaded_mode_json["configuredMode"], "rule");
    assert_eq!(reloaded_mode_json["effectiveMode"], "rule");
    assert_eq!(reloaded_mode_json["overrideMode"], serde_json::Value::Null);

    assert!(clash_lib::shutdown());
    runtime.join().expect("runtime thread panicked");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn controller_bind_failure_restores_existing_runtime() {
    let api_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve API port")
        .local_addr()
        .expect("failed to read API address")
        .port();
    let socks_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve SOCKS port")
        .local_addr()
        .expect("failed to read SOCKS address")
        .port();
    let blocked_api = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve blocked API port");
    let blocked_api_port = blocked_api
        .local_addr()
        .expect("failed to read blocked API address")
        .port();
    let temp_dir = std::env::temp_dir()
        .join(format!("chimera-api-reload-controller-rollback-{api_port}"));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let initial_config = temp_dir.join("initial.yaml");
    let blocked_config = temp_dir.join("blocked-controller.yaml");
    write_config(&initial_config, api_port, socks_port, "global");
    write_config(&blocked_config, blocked_api_port, socks_port, "rule");

    let cwd = temp_dir.clone();
    let runtime = std::thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::File(initial_config.to_string_lossy().to_string()),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(initial_config.to_string_lossy().to_string()),
        })
        .expect("failed to start clash");
    });

    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let put_request = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            "{\"path\":\"blocked-controller.yaml\"}",
        )))
        .expect("failed to build PUT request");
    let put_response = send_http_request(configs_url.parse().unwrap(), put_request)
        .await
        .expect("failed to request reload with blocked controller");
    assert_eq!(
        put_response.status(),
        http::StatusCode::INTERNAL_SERVER_ERROR
    );

    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    let get_request = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build GET request");
    let response = send_http_request(configs_url.parse().unwrap(), get_request)
        .await
        .expect("active API was not restored after controller bind failure");
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response
        .collect()
        .await
        .expect("failed to read restored config response")
        .to_bytes();
    let config: serde_json::Value =
        serde_json::from_slice(&body).expect("failed to parse restored config");
    assert_eq!(config["mode"], "global");

    drop(blocked_api);
    assert!(clash_lib::shutdown());
    runtime.join().expect("runtime thread panicked");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn data_plane_bind_failure_restores_existing_runtime() {
    // verifies rollback restores the live, patched inbound state rather than stale YAML
    let api_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve API port")
        .local_addr()
        .expect("failed to read API address")
        .port();
    let socks_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve SOCKS port")
        .local_addr()
        .expect("failed to read SOCKS address")
        .port();
    let blocked_socks = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve blocked SOCKS port");
    let blocked_socks_port = blocked_socks
        .local_addr()
        .expect("failed to read blocked SOCKS address")
        .port();
    let temp_dir = std::env::temp_dir()
        .join(format!("chimera-api-reload-data-plane-rollback-{api_port}"));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let initial_config = temp_dir.join("initial.yaml");
    let blocked_config = temp_dir.join("blocked-socks.yaml");
    write_config_with_extra(
        &initial_config,
        api_port,
        socks_port,
        "global",
        "bind-address: 127.0.0.1\n",
    );
    write_config_with_extra(
        &blocked_config,
        api_port,
        blocked_socks_port,
        "rule",
        "bind-address: 127.0.0.1\n",
    );

    let cwd = temp_dir.clone();
    let runtime = std::thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::File(initial_config.to_string_lossy().to_string()),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(initial_config.to_string_lossy().to_string()),
        })
        .expect("failed to start clash");
    });

    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    let patched_socks_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve patched SOCKS port")
        .local_addr()
        .expect("failed to read patched SOCKS address")
        .port();
    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let patch_request = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PATCH)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(format!(
            "{{\"socks-port\":{patched_socks_port}}}"
        ))))
        .expect("failed to build PATCH request");
    let patch_response =
        send_http_request(configs_url.parse().unwrap(), patch_request)
            .await
            .expect("failed to patch active SOCKS port");
    assert_eq!(patch_response.status(), http::StatusCode::ACCEPTED);
    wait_port_ready(patched_socks_port);
    assert!(TcpStream::connect(("127.0.0.1", socks_port)).is_err());

    let put_request = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from("{\"path\":\"blocked-socks.yaml\"}")))
        .expect("failed to build PUT request");
    let put_response = send_http_request(configs_url.parse().unwrap(), put_request)
        .await
        .expect("failed to request reload with blocked data plane");
    assert_eq!(
        put_response.status(),
        http::StatusCode::INTERNAL_SERVER_ERROR
    );

    wait_port_ready(api_port);
    wait_port_ready(patched_socks_port);
    assert!(TcpStream::connect(("127.0.0.1", socks_port)).is_err());

    let get_request = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build GET request");
    let response = send_http_request(configs_url.parse().unwrap(), get_request)
        .await
        .expect("active API was not restored after data-plane bind failure");
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response
        .collect()
        .await
        .expect("failed to read restored config response")
        .to_bytes();
    let config: serde_json::Value =
        serde_json::from_slice(&body).expect("failed to parse restored config");
    assert_eq!(config["mode"], "global");
    assert_eq!(config["socks-port"], patched_socks_port);

    drop(blocked_socks);
    assert!(clash_lib::shutdown());
    runtime.join().expect("runtime thread panicked");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn successful_reload_publishes_new_fake_ip_dns_owner() {
    // A successful replacement must publish the new DNS policy rather than
    // continuing to use a retained old resolver from the rollback candidate.
    let api_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let socks_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dns_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let temp = tempfile::tempdir().expect("failed to create reload test directory");
    let initial = temp.path().join("initial.yaml");
    let candidate = temp.path().join("new-dns-range.yaml");
    write_loopback_fake_ip_config(
        &initial, api_port, socks_port, dns_port, "global",
    );
    write_loopback_fake_ip_config_with_range(
        &candidate,
        api_port,
        socks_port,
        dns_port,
        "rule",
        "198.19.0.0/24",
    );

    let cwd = temp.path().to_path_buf();
    let runtime = std::thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::File(initial.to_string_lossy().to_string()),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(initial.to_string_lossy().to_string()),
        })
        .expect("failed starting loopback Fake-IP runtime");
    });
    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    let before = query_loopback_fake_ip(dns_port, "switch.reload.invalid").await;
    assert_eq!(&before.octets()[..2], &[198, 18]);

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let put = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(r#"{"path":"new-dns-range.yaml"}"#)))
        .unwrap();
    let response = send_http_request(configs_url.parse().unwrap(), put)
        .await
        .expect("failed requesting successful DNS policy reload");
    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);

    let after = query_loopback_fake_ip(dns_port, "switch.reload.invalid").await;
    assert_eq!(&after.octets()[..2], &[198, 19]);
    assert_ne!(after, before, "old resolver must not serve the new runtime");

    assert!(clash_lib::shutdown());
    runtime.join().expect("runtime thread panicked");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn failed_controller_reload_preserves_active_fake_ip_dns_owner() {
    // A controller bind failure occurs before the old data plane is stopped.
    // It must not permanently retire the old DNS owner either.
    let api_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let socks_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dns_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let blocked_api = TcpListener::bind("127.0.0.1:0").unwrap();
    let blocked_port = blocked_api.local_addr().unwrap().port();
    let temp = tempfile::tempdir().expect("failed to create reload test directory");
    let initial = temp.path().join("initial.yaml");
    let candidate = temp.path().join("blocked-controller.yaml");
    write_loopback_fake_ip_config(
        &initial, api_port, socks_port, dns_port, "global",
    );
    // A rejected replacement must not leak its different DNS policy into
    // the still-active runtime.
    write_loopback_fake_ip_config_with_range(
        &candidate,
        blocked_port,
        socks_port,
        dns_port,
        "rule",
        "198.19.0.0/24",
    );

    let cwd = temp.path().to_path_buf();
    let runtime = std::thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::File(initial.to_string_lossy().to_string()),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(initial.to_string_lossy().to_string()),
        })
        .expect("failed starting loopback Fake-IP runtime");
    });
    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    let original_ip =
        query_loopback_fake_ip(dns_port, "controller.reload.invalid").await;
    assert_eq!(&original_ip.octets()[..2], &[198, 18]);
    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let put = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            r#"{"path":"blocked-controller.yaml"}"#,
        )))
        .unwrap();
    let response = send_http_request(configs_url.parse().unwrap(), put)
        .await
        .expect("failed requesting controller rollback");
    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    assert_eq!(
        query_loopback_fake_ip(dns_port, "controller.reload.invalid").await,
        original_ip
    );
    let new_ip =
        query_loopback_fake_ip(dns_port, "controller-next.reload.invalid").await;
    assert_ne!(
        new_ip, original_ip,
        "controller rollback must keep the original DNS owner and Fake-IP pool"
    );
    assert_eq!(&new_ip.octets()[..2], &[198, 18]);

    drop(blocked_api);
    assert!(clash_lib::shutdown());
    runtime.join().expect("runtime thread panicked");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn failed_data_plane_reload_preserves_active_fake_ip_dns_owner() {
    // The existing data-plane rollback test has DNS disabled; this test uses
    // the real reload coordinator and a loopback-only DNS listener to prove
    // that the active Fake-IP owner survives a failed replacement.
    let api_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let socks_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dns_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let blocked_socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let blocked_port = blocked_socks.local_addr().unwrap().port();
    let temp = tempfile::tempdir().expect("failed to create reload test directory");
    let initial = temp.path().join("initial.yaml");
    let candidate = temp.path().join("blocked-socks.yaml");
    let recovery = temp.path().join("recovery.yaml");
    write_loopback_fake_ip_config(
        &initial, api_port, socks_port, dns_port, "global",
    );
    write_loopback_fake_ip_config_with_range(
        &candidate,
        api_port,
        blocked_port,
        dns_port,
        "rule",
        "198.19.0.0/24",
    );
    write_loopback_fake_ip_config_with_range(
        &recovery,
        api_port,
        socks_port,
        dns_port,
        "rule",
        "198.19.0.0/24",
    );

    let cwd = temp.path().to_path_buf();
    let runtime = std::thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::File(initial.to_string_lossy().to_string()),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(initial.to_string_lossy().to_string()),
        })
        .expect("failed starting loopback Fake-IP runtime");
    });
    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    let original_ip =
        query_loopback_fake_ip(dns_port, "original.reload.invalid").await;
    assert_eq!(&original_ip.octets()[..2], &[198, 18]);
    assert_eq!(
        original_ip,
        query_loopback_fake_ip(dns_port, "original.reload.invalid").await
    );

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let put = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(r#"{"path":"blocked-socks.yaml"}"#)))
        .unwrap();
    let reload_url: hyper::Uri = configs_url.parse().unwrap();
    let reloading = tokio::spawn(async move {
        send_http_request(reload_url, put)
            .await
            .expect("failed to request data-plane reload")
    });
    // The replacement DNS listener can bind before the failing SOCKS
    // listener completes its readiness timeout. During that window it must
    // never serve the candidate's policy to clients of the old runtime.
    let start = tokio::time::Instant::now();
    let mut probes = 0_usize;
    let mut api_probes = 0_usize;
    let mut leaked_candidate_answer = false;
    let mut leaked_control_answer = false;
    while !reloading.is_finished() && start.elapsed() < Duration::from_secs(3) {
        probes += 1;
        if let Ok(Ok(ip)) = tokio::time::timeout(
            Duration::from_millis(40),
            query_loopback_fake_ip_result(dns_port, "transient.reload.invalid"),
        )
        .await
        {
            leaked_candidate_answer |= ip.octets()[..2] == [198, 19];
        }
        // The replacement controller can be ready *before* the data plane.
        // Its /dns/query route must also reject unpublished resolver policy.
        if probes.is_multiple_of(3) {
            api_probes += 1;
            let control_url: hyper::Uri = format!(
                "http://127.0.0.1:{api_port}/dns/query?name=transient.reload.invalid&type=A"
            )
            .parse()
            .unwrap();
            let request = hyper::Request::builder()
                .uri(&control_url)
                .method(http::Method::GET)
                .body(Full::new(Bytes::new()))
                .unwrap();
            if let Ok(Ok(response)) = tokio::time::timeout(
                Duration::from_millis(40),
                send_http_request(control_url, request),
            )
            .await
                && response.status() == http::StatusCode::OK
                && let Ok(Ok(body)) = tokio::time::timeout(
                    Duration::from_millis(40),
                    response.into_body().collect(),
                )
                .await
            {
                leaked_control_answer |=
                    String::from_utf8_lossy(&body.to_bytes()).contains("198.19.");
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let response = reloading.await.expect("reload HTTP task panicked");
    assert_eq!(
        response.status(),
        http::StatusCode::INTERNAL_SERVER_ERROR,
        "occupied SOCKS port must fail replacement after preparation"
    );
    assert!(probes >= 5, "failed reload was not probed in flight");
    assert!(
        api_probes > 0,
        "candidate controller was not probed in flight"
    );
    assert!(
        !leaked_candidate_answer,
        "candidate Fake-IP policy served a DNS answer before the failed reload rolled back"
    );
    assert!(
        !leaked_control_answer,
        "candidate controller API returned its DNS policy before the failed reload rolled back"
    );
    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    // A retired resolver would reject this query; a fresh replacement might
    // recycle the first Fake-IP allocation, so also check a *new* hostname.
    assert_eq!(
        query_loopback_fake_ip(dns_port, "original.reload.invalid").await,
        original_ip,
        "old mapping must survive failed reload"
    );
    let next_ip = query_loopback_fake_ip(dns_port, "next.reload.invalid").await;
    assert_ne!(
        next_ip, original_ip,
        "rollback must keep the old Fake-IP owner and allocation history"
    );
    assert_eq!(&next_ip.octets()[..2], &[198, 18]);

    // Recovering from a failed reload must not permanently retire the owner
    // before the next, genuinely successful replacement is ready.
    drop(blocked_socks);
    let recovery_put = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(r#"{"path":"recovery.yaml"}"#)))
        .unwrap();
    let recovery_response =
        send_http_request(configs_url.parse().unwrap(), recovery_put)
            .await
            .expect("failed to request recovery reload");
    assert_eq!(recovery_response.status(), http::StatusCode::NO_CONTENT);
    let recovered_ip =
        query_loopback_fake_ip(dns_port, "original.reload.invalid").await;
    assert_eq!(
        &recovered_ip.octets()[..2],
        &[198, 19],
        "successful reload after rollback must publish its new DNS owner"
    );
    assert_ne!(recovered_ip, original_ip);

    assert!(clash_lib::shutdown());
    runtime.join().expect("runtime thread panicked");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn failed_reload_keeps_existing_runtime_available() {
    let api_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve API port")
        .local_addr()
        .expect("failed to read API address")
        .port();
    let socks_port = TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve SOCKS port")
        .local_addr()
        .expect("failed to read SOCKS address")
        .port();
    let temp_dir =
        std::env::temp_dir().join(format!("chimera-api-reload-rollback-{api_port}"));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let initial_config = temp_dir.join("initial.yaml");
    let invalid_config = temp_dir.join("invalid-interface.yaml");
    write_config(&initial_config, api_port, socks_port, "global");
    write_config_with_extra(
        &invalid_config,
        api_port,
        socks_port,
        "rule",
        "interface-name: __chimera_missing_interface__\n",
    );

    let cwd = temp_dir.clone();
    let runtime = std::thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::File(initial_config.to_string_lossy().to_string()),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(initial_config.to_string_lossy().to_string()),
        })
        .expect("failed to start clash");
    });

    wait_port_ready(api_port);
    wait_port_ready(socks_port);

    let configs_url = format!("http://127.0.0.1:{api_port}/configs");
    let put_request = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::PUT)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            "{\"path\":\"invalid-interface.yaml\"}",
        )))
        .expect("failed to build PUT request");
    let put_response = send_http_request(configs_url.parse().unwrap(), put_request)
        .await
        .expect("failed to request invalid reload");
    assert_eq!(
        put_response.status(),
        http::StatusCode::INTERNAL_SERVER_ERROR
    );

    let get_request = hyper::Request::builder()
        .uri(&configs_url)
        .method(http::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("failed to build GET request");
    let response = send_http_request(configs_url.parse().unwrap(), get_request)
        .await
        .expect("active API stopped after failed reload");
    assert_eq!(response.status(), http::StatusCode::OK);
    wait_port_ready(socks_port);

    assert!(clash_lib::shutdown());
    runtime.join().expect("runtime thread panicked");
}
