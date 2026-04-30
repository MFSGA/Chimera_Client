use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use clash_lib::{Config, Options, TokioRuntime, shutdown, start_scaffold};

const REAL_TRAFFIC_ENV: &str = "CHIMERA_REAL_DNS_TEST";
const TEST_HOST: &str = "www.cloudflare.com";

#[test]
#[ignore = "requires CHIMERA_REAL_DNS_TEST=1 and public DNS connectivity"]
fn local_dns_listener_resolves_real_udp_and_tcp_traffic() {
    if !real_traffic_enabled() {
        return;
    }

    let udp_port = unused_local_port();
    let tcp_port = unused_local_port();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let cwd = temp_dir.path().to_string_lossy().to_string();
    let config = real_dns_config(udp_port, tcp_port);

    let handle = std::thread::spawn(move || {
        start_scaffold(Options {
            config: Config::Str(config),
            cwd: Some(cwd),
            rt: Some(TokioRuntime::MultiThread),
            log_file: None,
        })
    });

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = runtime.block_on(async {
        let udp_ips =
            wait_for_udp_answers(udp_port, TEST_HOST, RecordType::A).await?;
        assert_has_public_ipv4(&udp_ips);

        let tcp_ips =
            wait_for_tcp_answers(tcp_port, TEST_HOST, RecordType::A).await?;
        assert_has_public_ipv4(&tcp_ips);
        anyhow::Ok(())
    });

    assert!(shutdown(), "runtime should have a shutdown token");
    let joined = handle.join().expect("runtime thread should not panic");
    joined.expect("runtime should stop cleanly");
    result.expect("udp/tcp dns queries should resolve through Chimera")
}

#[test]
#[ignore = "requires CHIMERA_REAL_DNS_TEST=1 and public DNS connectivity"]
fn local_dns_listener_handles_concurrent_real_udp_queries() {
    if !real_traffic_enabled() {
        return;
    }

    let udp_port = unused_local_port();
    let tcp_port = unused_local_port();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let cwd = temp_dir.path().to_string_lossy().to_string();
    let config = real_dns_config(udp_port, tcp_port);

    let handle = std::thread::spawn(move || {
        start_scaffold(Options {
            config: Config::Str(config),
            cwd: Some(cwd),
            rt: Some(TokioRuntime::MultiThread),
            log_file: None,
        })
    });

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = runtime.block_on(async {
        wait_for_udp_answers(udp_port, TEST_HOST, RecordType::A).await?;

        let mut tasks = Vec::new();
        for index in 0..20 {
            let host = if index % 2 == 0 {
                "www.cloudflare.com"
            } else {
                "www.google.com"
            };
            tasks.push(tokio::spawn(async move {
                query_udp(udp_port, host, RecordType::A).await
            }));
        }

        for task in tasks {
            let ips = task.await.expect("query task should not panic")?;
            assert_has_public_ipv4(&ips);
        }
        anyhow::Ok(())
    });

    assert!(shutdown(), "runtime should have a shutdown token");
    let joined = handle.join().expect("runtime thread should not panic");
    joined.expect("runtime should stop cleanly");
    result.expect("concurrent udp queries should resolve through Chimera")
}

fn real_traffic_enabled() -> bool {
    if std::env::var(REAL_TRAFFIC_ENV).as_deref() == Ok("1") {
        true
    } else {
        eprintln!(
            "skipping real DNS traffic test; set {REAL_TRAFFIC_ENV}=1 to enable"
        );
        false
    }
}

fn unused_local_port() -> u16 {
    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn real_dns_config(udp_port: u16, tcp_port: u16) -> String {
    format!(
        r#"
mixed-port: 0
bind-address: '*'
allow-lan: false
mode: rule
log-level: info
ipv6: true
mmdb: null

dns:
  enable: true
  ipv6: true
  listen:
    udp: 127.0.0.1:{udp_port}
    tcp: 127.0.0.1:{tcp_port}
  enhanced-mode: normal
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8

profile:
  store-selected: false
  store-fake-ip: false

proxies: []

rules:
  - MATCH,DIRECT
"#
    )
}

async fn wait_for_udp_answers(
    port: u16,
    host: &str,
    record_type: RecordType,
) -> anyhow::Result<Vec<IpAddr>> {
    wait_for_answers(|| query_udp(port, host, record_type)).await
}

async fn wait_for_tcp_answers(
    port: u16,
    host: &str,
    record_type: RecordType,
) -> anyhow::Result<Vec<IpAddr>> {
    wait_for_answers(|| query_tcp(port, host, record_type)).await
}

async fn wait_for_answers<F, Fut>(mut query: F) -> anyhow::Result<Vec<IpAddr>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<IpAddr>>>,
{
    let started = Instant::now();
    let mut last_error = None;

    while started.elapsed() < Duration::from_secs(15) {
        match query().await {
            Ok(ips) if !ips.is_empty() => return Ok(ips),
            Ok(_) => last_error = Some(anyhow::anyhow!("empty answer")),
            Err(err) => last_error = Some(err),
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("dns query timed out")))
}

async fn query_udp(
    port: u16,
    host: &str,
    record_type: RecordType,
) -> anyhow::Result<Vec<IpAddr>> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let query = build_query(host, record_type)?;
    let packet = query.to_vec()?;
    socket
        .send_to(&packet, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await?;

    let mut buf = vec![0_u8; 1500];
    let len = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await??;
    let response = Message::from_vec(&buf[..len])?;
    Ok(answer_ips(&response))
}

async fn query_tcp(
    port: u16,
    host: &str,
    record_type: RecordType,
) -> anyhow::Result<Vec<IpAddr>> {
    let mut stream =
        TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
    let query = build_query(host, record_type)?;
    let packet = query.to_vec()?;
    let len = u16::try_from(packet.len())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&packet).await?;

    let mut len_buf = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await??;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0_u8; response_len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await??;

    let response = Message::from_vec(&response)?;
    Ok(answer_ips(&response))
}

fn build_query(host: &str, record_type: RecordType) -> anyhow::Result<Message> {
    let mut message = Message::new();
    message.set_id(rand::random::<u16>());
    message.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(Name::from_ascii(host)?);
    query.set_query_type(record_type);
    message.add_query(query);

    Ok(message)
}

fn answer_ips(message: &Message) -> Vec<IpAddr> {
    message
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            RData::A(ip) => Some(IpAddr::V4(**ip)),
            RData::AAAA(ip) => Some(IpAddr::V6(**ip)),
            _ => None,
        })
        .collect()
}

fn assert_has_public_ipv4(ips: &[IpAddr]) {
    assert!(
        ips.iter()
            .any(|ip| matches!(ip, IpAddr::V4(ip) if !ip.is_private()
            && !ip.is_loopback()
            && !ip.is_link_local()
            && !ip.is_unspecified())),
        "expected at least one public IPv4 address, got {ips:?}"
    );
}
