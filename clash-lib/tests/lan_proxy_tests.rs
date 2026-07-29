mod common;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    time::Duration,
};

use clash_lib::{Config, Options};
use common::{ClashInstance, send_http_request};
use http_body_util::BodyExt;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

const TEST_SECRET: &str = "lan-proxy-test";
const IO_TIMEOUT: Duration = Duration::from_secs(3);

fn available_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("failed to reserve a test port")
        .local_addr()
        .expect("failed to inspect reserved test port")
        .port()
}

fn non_loopback_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut addresses = NetworkInterface::show()
        .unwrap_or_default()
        .into_iter()
        .flat_map(|interface| interface.addr)
        .filter_map(|address| match address {
            Addr::V4(address)
                if !address.ip.is_loopback()
                    && !address.ip.is_link_local()
                    && !address.ip.is_unspecified() =>
            {
                Some(address.ip)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    addresses
}

fn write_proxy_config(
    path: &Path,
    api_port: u16,
    socks_port: u16,
    http_port: u16,
    mixed_port: u16,
    allow_lan: bool,
) {
    std::fs::write(
        path,
        format!(
            "ipv6: false\n\
allow-lan: {allow_lan}\n\
bind-address: 0.0.0.0\n\
port: {http_port}\n\
socks-port: {socks_port}\n\
mixed-port: {mixed_port}\n\
mode: direct\n\
log-level: info\n\
mmdb: null\n\
external-controller: 127.0.0.1:{api_port}\n\
secret: {TEST_SECRET}\n\
dns:\n\
  enable: false\n\
profile:\n\
  store-selected: false\n\
proxies: []\n\
rules:\n\
  - MATCH,DIRECT\n"
        ),
    )
    .expect("failed to write LAN proxy test config");
}

async fn spawn_echo_server() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    let count = match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => count,
                    };
                    if stream.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok((address, task))
}

async fn connect_tcp(
    proxy_addr: SocketAddr,
    source_ip: Option<Ipv4Addr>,
) -> io::Result<TcpStream> {
    let connect = async move {
        if let Some(source_ip) = source_ip {
            let socket = TcpSocket::new_v4()?;
            socket.bind(SocketAddr::new(IpAddr::V4(source_ip), 0))?;
            socket.connect(proxy_addr).await
        } else {
            TcpStream::connect(proxy_addr).await
        }
    };

    timeout(IO_TIMEOUT, connect).await.map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "proxy connect timed out")
    })?
}

async fn read_socks_reply(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] != 0 {
        return Err(io::Error::other(format!(
            "SOCKS CONNECT failed: version={}, reply={}",
            header[0], header[1]
        )));
    }

    let address_bytes = match header[3] {
        1 => 4,
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0])
        }
        4 => 16,
        address_type => {
            return Err(io::Error::other(format!(
                "unexpected SOCKS address type {address_type}"
            )));
        }
    };
    let mut remaining = vec![0_u8; address_bytes + 2];
    stream.read_exact(&mut remaining).await?;
    Ok(())
}

async fn open_socks_tunnel(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    source_ip: Option<Ipv4Addr>,
) -> io::Result<TcpStream> {
    let mut stream = connect_tcp(proxy_addr, source_ip).await?;
    timeout(IO_TIMEOUT, async {
        stream.write_all(&[5, 1, 0]).await?;
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting != [5, 0] {
            return Err(io::Error::other(format!(
                "unexpected SOCKS greeting reply {greeting:?}"
            )));
        }

        let IpAddr::V4(target_ip) = target_addr.ip() else {
            return Err(io::Error::other("test target must be IPv4"));
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&target_ip.octets());
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        stream.write_all(&request).await?;
        read_socks_reply(&mut stream).await
    })
    .await
    .map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake timed out")
    })??;
    Ok(stream)
}

async fn open_http_connect_tunnel(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
) -> io::Result<TcpStream> {
    let mut stream = connect_tcp(proxy_addr, None).await?;
    let request = format!(
        "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );

    timeout(IO_TIMEOUT, async {
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::with_capacity(256);
        while !response.ends_with(b"\r\n\r\n") {
            if response.len() >= 8192 {
                return Err(io::Error::other(
                    "HTTP proxy response headers too large",
                ));
            }
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await?;
            response.push(byte[0]);
        }
        let response = String::from_utf8_lossy(&response);
        if !response.starts_with("HTTP/1.1 200")
            && !response.starts_with("HTTP/1.0 200")
        {
            return Err(io::Error::other(format!(
                "HTTP CONNECT failed: {}",
                response.lines().next().unwrap_or_default()
            )));
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "HTTP CONNECT timed out")
    })??;
    Ok(stream)
}

async fn assert_echo(mut stream: TcpStream, payload: &[u8]) -> io::Result<()> {
    timeout(IO_TIMEOUT, async {
        stream.write_all(payload).await?;
        let mut echoed = vec![0_u8; payload.len()];
        stream.read_exact(&mut echoed).await?;
        if echoed != payload {
            return Err(io::Error::other("echo payload did not match"));
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "echo timed out"))?
}

async fn find_reachable_lan_ip(port: u16) -> io::Result<Ipv4Addr> {
    for address in non_loopback_ipv4_addresses() {
        let proxy_addr = SocketAddr::new(IpAddr::V4(address), port);
        if connect_tcp(proxy_addr, None).await.is_ok() {
            return Ok(address);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no reachable non-loopback IPv4 address found for LAN proxy test",
    ))
}

async fn get_runtime_config(api_port: u16) -> io::Result<serde_json::Value> {
    let url = format!("http://127.0.0.1:{api_port}/configs");
    let request = hyper::Request::builder()
        .uri(&url)
        .method(http::Method::GET)
        .header(
            hyper::header::AUTHORIZATION,
            format!("Bearer {TEST_SECRET}"),
        )
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("failed to build GET /configs request");
    let response = send_http_request(url.parse().unwrap(), request).await?;
    let body = response
        .collect()
        .await
        .map_err(|error| {
            io::Error::other(format!("failed to read config response: {error}"))
        })?
        .to_bytes();
    serde_json::from_slice(&body).map_err(|error| {
        io::Error::other(format!("invalid config response JSON: {error}"))
    })
}

async fn patch_allow_lan(api_port: u16, allow_lan: bool) -> io::Result<()> {
    let url = format!("http://127.0.0.1:{api_port}/configs");
    let request = hyper::Request::builder()
        .uri(&url)
        .method(http::Method::PATCH)
        .header(
            hyper::header::AUTHORIZATION,
            format!("Bearer {TEST_SECRET}"),
        )
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(format!("{{\"allow-lan\":{allow_lan}}}"))
        .expect("failed to build PATCH /configs request");
    let response =
        send_http_request::<String>(url.parse().unwrap(), request).await?;
    if response.status() != http::StatusCode::ACCEPTED {
        return Err(io::Error::other(format!(
            "PATCH /configs returned {}",
            response.status()
        )));
    }
    Ok(())
}

async fn wait_for_source_bound_socks(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    source_ip: Ipv4Addr,
) -> io::Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match open_socks_tunnel(proxy_addr, target_addr, Some(source_ip)).await {
            Ok(stream) => return Ok(stream),
            Err(error) if tokio::time::Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn test_config_path(api_port: u16, name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "chimera-{name}-{api_port}-{}.yaml",
        std::process::id()
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn allow_lan_proxies_tcp_through_socks_http_and_mixed() {
    let api_port = available_port();
    let socks_port = available_port();
    let http_port = available_port();
    let mixed_port = available_port();
    let config_path = test_config_path(api_port, "lan-proxy");
    write_proxy_config(
        &config_path,
        api_port,
        socks_port,
        http_port,
        mixed_port,
        true,
    );

    let (echo_addr, echo_task) = spawn_echo_server()
        .await
        .expect("failed to start echo server");
    {
        let _clash = ClashInstance::start(
            Options {
                config: Config::File(config_path.to_string_lossy().to_string()),
                cwd: config_path
                    .parent()
                    .map(|path| path.to_string_lossy().to_string()),
                rt: None,
                log_file: None,
                config_path: Some(config_path.to_string_lossy().to_string()),
            },
            vec![api_port, socks_port, http_port, mixed_port],
        )
        .expect("failed to start Chimera for LAN proxy test");

        let lan_ip = find_reachable_lan_ip(socks_port).await.expect(
            "LAN proxy was not reachable through a non-loopback IPv4 address",
        );
        let runtime_config = get_runtime_config(api_port)
            .await
            .expect("failed to query runtime LAN proxy config");
        assert_eq!(runtime_config["allow-lan"], true);
        assert_eq!(runtime_config["bind-address"], "0.0.0.0");
        assert!(
            runtime_config["lan-ips"]
                .as_array()
                .is_some_and(|addresses| addresses.iter().any(|address| {
                    address.as_str() == Some(lan_ip.to_string().as_str())
                })),
            "runtime config should advertise the tested LAN address {lan_ip}"
        );

        let socks = open_socks_tunnel(
            SocketAddr::new(IpAddr::V4(lan_ip), socks_port),
            echo_addr,
            None,
        )
        .await
        .expect("SOCKS proxy should accept LAN traffic");
        assert_echo(socks, b"lan-socks-echo")
            .await
            .expect("SOCKS LAN proxy did not relay data");

        let http = open_http_connect_tunnel(
            SocketAddr::new(IpAddr::V4(lan_ip), http_port),
            echo_addr,
        )
        .await
        .expect("HTTP proxy should accept LAN traffic");
        assert_echo(http, b"lan-http-connect-echo")
            .await
            .expect("HTTP LAN proxy did not relay data");

        let mixed = open_socks_tunnel(
            SocketAddr::new(IpAddr::V4(lan_ip), mixed_port),
            echo_addr,
            None,
        )
        .await
        .expect("mixed proxy should accept SOCKS traffic from LAN");
        assert_echo(mixed, b"lan-mixed-echo")
            .await
            .expect("mixed LAN proxy did not relay data");
    }

    echo_task.abort();
    let _ = std::fs::remove_file(config_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn runtime_allow_lan_toggle_changes_access_policy() {
    let api_port = available_port();
    let socks_port = available_port();
    let http_port = available_port();
    let mixed_port = available_port();
    let config_path = test_config_path(api_port, "lan-toggle");
    write_proxy_config(
        &config_path,
        api_port,
        socks_port,
        http_port,
        mixed_port,
        false,
    );

    let (echo_addr, echo_task) = spawn_echo_server()
        .await
        .expect("failed to start echo server");
    {
        let _clash = ClashInstance::start(
            Options {
                config: Config::File(config_path.to_string_lossy().to_string()),
                cwd: config_path
                    .parent()
                    .map(|path| path.to_string_lossy().to_string()),
                rt: None,
                log_file: None,
                config_path: Some(config_path.to_string_lossy().to_string()),
            },
            vec![api_port, socks_port, http_port, mixed_port],
        )
        .expect("failed to start Chimera for LAN toggle test");

        let proxy_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks_port);
        let simulated_remote = Ipv4Addr::new(127, 0, 0, 2);
        let denied =
            open_socks_tunnel(proxy_addr, echo_addr, Some(simulated_remote)).await;
        assert!(
            denied.is_err(),
            "allow-lan=false must reject a client whose source differs from the accepted local address"
        );

        patch_allow_lan(api_port, true)
            .await
            .expect("failed to enable allow-lan through the control API");
        let allowed = wait_for_source_bound_socks(
            proxy_addr,
            echo_addr,
            simulated_remote,
        )
        .await
        .expect(
            "allow-lan=true should admit the same source after listener restart",
        );
        assert_echo(allowed, b"runtime-lan-toggle")
            .await
            .expect("runtime-enabled LAN proxy did not relay data");
    }

    echo_task.abort();
    let _ = std::fs::remove_file(config_path);
}
