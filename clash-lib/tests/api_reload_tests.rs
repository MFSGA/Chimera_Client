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
    std::fs::write(
        path,
        format!(
            "ipv6: false\n\
log_level: info\n\
mode: {mode}\n\
external-controller: 127.0.0.1:{api_port}\n\
socks-port: {socks_port}\n\
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

#[tokio::test(flavor = "current_thread")]
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
    std::thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::File(initial_config.to_string_lossy().to_string()),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
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
}
