#![allow(dead_code)]

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

use std::{sync::Arc, time::Duration};

use futures::{SinkExt, StreamExt};
use network_interface::NetworkInterfaceConfig as _;
use sysinfo::Networks;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    proxy::{OutboundHandler, datagram::UdpPacket},
    session::{Session, SocksAddr},
};

use tracing::{debug, trace};

#[allow(unused_imports)]
pub use docker_runner::{
    DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup, alloc_docker_port,
};

#[cfg(throughput_test)]
pub fn alloc_port() -> u16 {
    alloc_docker_port()
}

#[cfg(docker_test)]
pub fn use_ci_host_network() -> bool {
    cfg!(target_os = "linux")
        && std::env::var("CLASH_RS_CI")
            .is_ok_and(|value| value.eq_ignore_ascii_case("true"))
}

#[cfg(throughput_test)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ThroughputResult {
    pub label: String,
    pub upload_mbps: f64,
    pub download_mbps: f64,
    pub upload_stdev_mbps: f64,
    pub download_stdev_mbps: f64,
    pub runs: usize,
    pub total_bytes: usize,
    pub netem: Option<String>,
}

#[cfg(all(docker_test, throughput_test))]
pub fn write_throughput_result(result: &ThroughputResult) {
    let Some(path) = std::env::var_os("THROUGHPUT_RESULTS_FILE") else {
        return;
    };

    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("THROUGHPUT_RESULTS_FILE: cannot open for append");
    let mut line = serde_json::to_string(result)
        .expect("ThroughputResult serialization failed");
    line.push('\n');
    file.write_all(line.as_bytes())
        .expect("THROUGHPUT_RESULTS_FILE: write failed");
}

#[cfg(throughput_test)]
pub fn find_clash_rs_binary() -> std::path::PathBuf {
    let binary_name = if cfg!(windows) {
        "clash-rs.exe"
    } else {
        "clash-rs"
    };
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(profile_dir) =
            current_exe.parent().and_then(|deps| deps.parent())
    {
        let sibling = profile_dir.join(binary_name);
        if sibling.exists() {
            return sibling;
        }
    }

    let root = config_helper::root_dir();
    let debug = root.join("target").join("debug").join(binary_name);
    let release = root.join("target").join("release").join(binary_name);

    if debug.exists() {
        debug
    } else if release.exists() {
        release
    } else {
        panic!("clash-rs binary not found; run `cargo build -p clash-rs` first")
    }
}

#[cfg(all(docker_test, throughput_test))]
fn median_mbps(samples: &[std::time::Duration], mb: f64) -> f64 {
    let mut mbps: Vec<f64> =
        samples.iter().map(|d| mb * 8.0 / d.as_secs_f64()).collect();
    mbps.sort_by(|a, b| a.partial_cmp(b).unwrap());
    mbps[mbps.len() / 2]
}

#[cfg(all(docker_test, throughput_test))]
fn stdev_mbps(samples: &[std::time::Duration], mb: f64) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let mbps: Vec<f64> =
        samples.iter().map(|d| mb * 8.0 / d.as_secs_f64()).collect();
    let mean = mbps.iter().sum::<f64>() / mbps.len() as f64;
    let var = mbps.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
        / (mbps.len() - 1) as f64;
    var.sqrt()
}

#[cfg(all(docker_test, throughput_test))]
async fn socks5_connect(
    proxy_addr: std::net::SocketAddr,
    target_host: &str,
    target_port: u16,
) -> std::io::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::other("SOCKS5 auth negotiation failed"));
    }

    let mut req = Vec::with_capacity(10 + target_host.len());
    if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
        req.extend_from_slice(&ip.octets());
    } else {
        let host_bytes = target_host.as_bytes();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 CONNECT failed: REP={}",
            hdr[1]
        )));
    }
    match hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        _ => {}
    }
    Ok(stream)
}

#[cfg(all(docker_test, throughput_test))]
async fn wait_for_port(port: u16, timeout_secs: u64) -> anyhow::Result<()> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("port {} not ready after {}s", port, timeout_secs);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

#[cfg(all(docker_test, throughput_test))]
pub async fn clash_process_e2e_throughput(
    binary: &std::path::Path,
    config_yaml: &str,
    label: &str,
    socks_port: u16,
    echo_port: u16,
    gateway_ip: Option<String>,
    payload_bytes: usize,
) -> anyhow::Result<ThroughputResult> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut cfg_file = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut cfg_file, config_yaml.as_bytes())?;
    let cfg_path = cfg_file.path().to_owned();

    let mut child = tokio::process::Command::new(binary)
        .arg("-c")
        .arg(&cfg_path)
        .arg("--compatibility=false")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn clash-rs: {e}"))?;
    let _cfg_file = cfg_file;

    let echo_listener = std::sync::Arc::new(
        tokio::net::TcpListener::bind(format!("0.0.0.0:{echo_port}")).await?,
    );

    wait_for_port(socks_port, 90).await.map_err(|e| {
        match child.try_wait() {
            Ok(Some(status)) => {
                eprintln!(
                    "[clash-rs/{label}] exited early (status: {status}) before \
                     SOCKS port {socks_port} became ready"
                );
            }
            Ok(None) => {
                eprintln!(
                    "[clash-rs/{label}] still running after 90s but SOCKS port \
                     {socks_port} never became ready; killing"
                );
            }
            Err(ref err) => {
                eprintln!("[clash-rs/{label}] try_wait failed: {err}");
            }
        }
        child.start_kill().ok();
        e
    })?;

    let destinations = destination_list(gateway_ip);
    let mut last_err = anyhow::anyhow!("no destinations");
    const RUNS: usize = 3;

    for dest in &destinations {
        let mut upload_samples = Vec::with_capacity(RUNS);
        let mut download_samples = Vec::with_capacity(RUNS);
        let mut dest_ok = true;

        for _run in 0..RUNS {
            let listener_clone = echo_listener.clone();
            let pbe = payload_bytes;
            let echo_task = tokio::spawn(async move {
                let chunk_size = 64 * 1024_usize;
                let mut buf = vec![0u8; chunk_size];
                let (mut stream, _) = listener_clone.accept().await?;
                let mut received = 0usize;
                while received < pbe {
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        anyhow::bail!("echo: premature EOF on receive");
                    }
                    received += n;
                }

                stream.write_all(&[0xACu8]).await?;
                stream.flush().await?;
                let mut ack = [0u8; 1];
                stream.read_exact(&mut ack).await?;
                if ack != [0xCAu8] {
                    anyhow::bail!("echo server: invalid barrier ACK {ack:?}");
                }

                let data = vec![0x42u8; chunk_size];
                let mut sent = 0usize;
                while sent < pbe {
                    let to_send = chunk_size.min(pbe - sent);
                    stream.write_all(&data[..to_send]).await?;
                    sent += to_send;
                }
                stream.flush().await?;
                anyhow::Ok(())
            });

            let proxy_addr: std::net::SocketAddr =
                format!("127.0.0.1:{socks_port}").parse().unwrap();
            let mut conn = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                socks5_connect(proxy_addr, dest, echo_port),
            )
            .await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(err)) => {
                    last_err = err.into();
                    echo_task.abort();
                    dest_ok = false;
                    break;
                }
                Err(_) => {
                    last_err = anyhow::anyhow!("socks5_connect timeout");
                    echo_task.abort();
                    dest_ok = false;
                    break;
                }
            };

            let upload_start = std::time::Instant::now();
            let chunk_size = 64 * 1024_usize;
            let upload_data = vec![0x42u8; chunk_size];
            let mut sent = 0usize;
            while sent < payload_bytes {
                let to_send = chunk_size.min(payload_bytes - sent);
                if let Err(err) = conn.write_all(&upload_data[..to_send]).await {
                    last_err = err.into();
                    echo_task.abort();
                    dest_ok = false;
                    break;
                }
                sent += to_send;
            }
            if !dest_ok {
                break;
            }
            if let Err(err) = conn.flush().await {
                last_err = err.into();
                echo_task.abort();
                dest_ok = false;
                break;
            }

            let mut sync = [0u8; 1];
            if let Err(err) = conn.read_exact(&mut sync).await {
                last_err = err.into();
                echo_task.abort();
                dest_ok = false;
                break;
            }
            if sync != [0xACu8] {
                last_err = anyhow::anyhow!("invalid sync marker: {sync:?}");
                echo_task.abort();
                dest_ok = false;
                break;
            }
            let upload_elapsed = upload_start.elapsed();

            if let Err(err) = conn.write_all(&[0xCAu8]).await {
                last_err = err.into();
                echo_task.abort();
                dest_ok = false;
                break;
            }
            if let Err(err) = conn.flush().await {
                last_err = err.into();
                echo_task.abort();
                dest_ok = false;
                break;
            }

            let mut read_buf = vec![0u8; chunk_size];
            let download_start = std::time::Instant::now();
            let mut received = 0usize;
            loop {
                match conn.read(&mut read_buf).await {
                    Ok(0) => {
                        last_err = anyhow::anyhow!("premature EOF on download");
                        echo_task.abort();
                        dest_ok = false;
                        break;
                    }
                    Ok(n) => {
                        received += n;
                        if received >= payload_bytes {
                            break;
                        }
                    }
                    Err(err) => {
                        last_err = err.into();
                        echo_task.abort();
                        dest_ok = false;
                        break;
                    }
                }
            }
            if !dest_ok {
                break;
            }
            let download_elapsed = download_start.elapsed();

            echo_task.await??;
            upload_samples.push(upload_elapsed);
            download_samples.push(download_elapsed);
        }

        if dest_ok {
            let mb = payload_bytes as f64 / 1024.0 / 1024.0;
            let result = ThroughputResult {
                label: label.to_owned(),
                upload_mbps: median_mbps(&upload_samples, mb),
                download_mbps: median_mbps(&download_samples, mb),
                upload_stdev_mbps: stdev_mbps(&upload_samples, mb),
                download_stdev_mbps: stdev_mbps(&download_samples, mb),
                runs: RUNS,
                total_bytes: payload_bytes,
                netem: None,
            };
            tracing::info!(
                "e2e throughput [{}] ({} MB, {} runs): upload={:.1}+/-{:.1} Mbps \
                 download={:.1}+/-{:.1} Mbps",
                label,
                payload_bytes / 1024 / 1024,
                RUNS,
                result.upload_mbps,
                result.upload_stdev_mbps,
                result.download_mbps,
                result.download_stdev_mbps,
            );
            child.start_kill().ok();
            write_throughput_result(&result);
            return Ok(result);
        }
    }

    child.start_kill().ok();
    Err(last_err)
}

const DOCKER_TARGET_TCP_PORT: u16 = 18080;
const DOCKER_TARGET_UDP_PORT: u16 = 18081;
const DOCKER_TARGET_DNS_PORT: u16 = 18082;

const DOCKER_TARGET_CMD: &str = r#"
nc -lk -p 18080 -e sh -c 'dd bs=5 count=1 >/dev/null 2>/dev/null; printf world' &
nc -u -lk -p 18081 -e sh -c 'dd bs=5 count=1 >/dev/null 2>/dev/null; printf world' &
nc -u -lk -p 18082 -e sh -c 'printf \\022\\064\\201\\200' &
wait
"#;

async fn docker_test_target() -> anyhow::Result<(DockerTestRunner, String)> {
    let runner = DockerTestRunnerBuilder::new()
        .image(consts::IMAGE_DOCKER_TEST_TARGET)
        .no_port()
        .cmd(&["sh", "-c", DOCKER_TARGET_CMD])
        .build()
        .await?;
    let ip = runner
        .container_ip()
        .ok_or_else(|| anyhow::anyhow!("docker test target has no container IP"))?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok((runner, ip))
}

#[derive(Clone, Copy, Debug)]
pub enum Suite {
    PingPongTcp,
    PingPongUdp,
    LatencyTcp,
    DnsUdp,
}

impl Suite {
    pub const fn all() -> &'static [Suite] {
        &[
            Suite::PingPongTcp,
            Suite::PingPongUdp,
            Suite::LatencyTcp,
            Suite::DnsUdp,
        ]
    }

    pub const fn tcp_tests() -> &'static [Suite] {
        &[Suite::PingPongTcp, Suite::LatencyTcp]
    }
}

pub async fn run_test_suites_and_cleanup(
    handler: Arc<dyn OutboundHandler>,
    docker_test_runner: impl RunAndCleanup,
    suites: &[Suite],
) -> anyhow::Result<()> {
    let suites = suites.to_vec();
    let (target_runner, target_ip) = docker_test_target().await?;

    docker_test_runner
        .run_and_cleanup(async move {
            let suite_result = async {
                for suite in suites {
                    tracing::info!(?suite, %target_ip, "running docker test suite");
                    let result = match suite {
                        Suite::PingPongTcp => {
                            ping_pong_tcp_test(handler.clone(), &target_ip).await
                        }
                        Suite::PingPongUdp => {
                            ping_pong_udp_test(handler.clone(), &target_ip).await
                        }
                        Suite::LatencyTcp => {
                            latency_tcp_test(handler.clone(), &target_ip).await.map(
                                |latency| {
                                    tracing::info!(
                                        ?latency,
                                        "docker tcp latency test passed"
                                    );
                                },
                            )
                        }
                        Suite::DnsUdp => {
                            dns_udp_test(handler.clone(), &target_ip).await
                        }
                    };
                    result.map_err(|err| {
                        anyhow::anyhow!("docker suite {suite:?} failed: {err}")
                    })?;
                }
                Ok(())
            }
            .await;

            let cleanup_result = target_runner.cleanup().await;
            match (suite_result, cleanup_result) {
                (Err(err), _) => Err(err),
                (Ok(()), Err(err)) => Err(err),
                (Ok(()), Ok(())) => Ok(()),
            }
        })
        .await
}

fn destination_list(gateway_ip: Option<String>) -> Vec<String> {
    let mut destination_list = vec!["host.docker.internal".to_owned()];
    if let Some(ip) = gateway_ip {
        debug!("gateway_ip Ip: {}", ip);
        destination_list.push(ip);
    }
    if let Some(ip) = std::env::var("CLIENT_IP").ok() {
        debug!("client Ip: {}", &ip);
        destination_list.insert(0, ip);
    } else {
        debug!("CLIENT_IP env not set, ");
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh(true);

        trace!("networks: {:?}", networks);
        // 收集所有有流量的网卡的 IPv4 地址
        let mut active_interfaces = networks
            .iter()
            .filter(|(_, data)| {
                data.mac_address().to_string() != "00:00:00:00:00:00"
            })
            .collect::<Vec<_>>();

        // 按流量排序：优先按发送流量降序，其次按接收流量降序
        active_interfaces.sort_by(|a, b| {
            b.1.total_transmitted()
                .cmp(&a.1.total_transmitted())
                .then_with(|| b.1.total_received().cmp(&a.1.total_received()))
        });
        for (iface_name, data) in active_interfaces {
            trace!("Processing interface: {}, {:#?}", iface_name, data);

            // 获取该网卡的所有 IP 地址
            for ip_network in data.ip_networks() {
                let addr = ip_network.addr;
                // 只添加 IPv4 地址，排除 loopback
                if addr.is_ipv4() && !addr.is_loopback() {
                    let ip_str = addr.to_string();
                    // 跳过已存在的 IP
                    if !destination_list.contains(&ip_str) {
                        debug!("Found IPv4 address on {}: {}", iface_name, ip_str);
                        destination_list.push(ip_str);
                    }
                }
            }
        }

        if let Ok(interfaces) = network_interface::NetworkInterface::show() {
            for iface in interfaces {
                for addr in iface.addr {
                    if let network_interface::Addr::V4(v4) = addr
                        && !v4.ip.is_loopback()
                        && !v4.ip.is_link_local()
                    {
                        let ip_str = v4.ip.to_string();
                        if !destination_list.contains(&ip_str) {
                            debug!(
                                "Found IPv4 address via network-interface on {}: {}",
                                iface.name, ip_str
                            );
                            destination_list.push(ip_str);
                        }
                    }
                }
            }
        }
    }
    destination_list
}

async fn ping_pong_tcp_test(
    handler: Arc<dyn OutboundHandler>,
    target_ip: &str,
) -> anyhow::Result<()> {
    let resolver = config_helper::build_dns_resolver().await?;
    let dst: SocksAddr =
        (target_ip.to_owned(), DOCKER_TARGET_TCP_PORT).try_into()?;
    let sess = Session {
        destination: dst.clone(),
        ..Default::default()
    };

    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        handler.connect_stream(&sess, resolver),
    )
    .await
    .map_err(|_| anyhow::anyhow!("tcp ping-pong connect timed out for {dst:?}"))??;

    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(b"hello").await?;
        stream.flush().await?;
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await?;
        anyhow::ensure!(&response == b"world", "unexpected tcp response payload");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("tcp ping-pong roundtrip timed out for {dst:?}")
    })??;

    Ok(())
}

async fn ping_pong_udp_test(
    handler: Arc<dyn OutboundHandler>,
    target_ip: &str,
) -> anyhow::Result<()> {
    let resolver = config_helper::build_dns_resolver().await?;
    let dst: SocksAddr =
        (target_ip.to_owned(), DOCKER_TARGET_UDP_PORT).try_into()?;
    let sess = Session {
        destination: dst.clone(),
        ..Default::default()
    };
    let datagram = tokio::time::timeout(
        Duration::from_secs(5),
        handler.connect_datagram(&sess, resolver),
    )
    .await
    .map_err(|_| anyhow::anyhow!("udp ping-pong connect timed out for {dst:?}"))??;
    let (mut sink, mut stream) = datagram.split();

    sink.send(UdpPacket::new(
        b"hello".to_vec(),
        SocksAddr::Ip("127.0.0.1:0".parse()?),
        dst.clone(),
    ))
    .await?;

    let response = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .map_err(|_| {
            anyhow::anyhow!("udp ping-pong roundtrip timed out for {dst:?}")
        })?
        .ok_or_else(|| anyhow::anyhow!("udp ping-pong stream closed for {dst:?}"))?;
    anyhow::ensure!(response.data == b"world", "unexpected udp response payload");
    Ok(())
}

async fn latency_tcp_test(
    handler: Arc<dyn OutboundHandler>,
    target_ip: &str,
) -> anyhow::Result<Duration> {
    let resolver = config_helper::build_dns_resolver().await?;
    let dst: SocksAddr =
        (target_ip.to_owned(), DOCKER_TARGET_TCP_PORT).try_into()?;
    let sess = Session {
        destination: dst.clone(),
        ..Default::default()
    };
    let started = std::time::Instant::now();
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        handler.connect_stream(&sess, resolver),
    )
    .await
    .map_err(|_| anyhow::anyhow!("tcp latency connect timed out for {dst:?}"))??;

    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(b"hello").await?;
        stream.flush().await?;
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await?;
        anyhow::ensure!(&response == b"world", "unexpected tcp latency response");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("tcp latency roundtrip timed out for {dst:?}"))??;

    Ok(started.elapsed())
}

async fn dns_udp_test(
    handler: Arc<dyn OutboundHandler>,
    target_ip: &str,
) -> anyhow::Result<()> {
    let resolver = config_helper::build_dns_resolver().await?;
    let dst: SocksAddr =
        (target_ip.to_owned(), DOCKER_TARGET_DNS_PORT).try_into()?;
    let sess = Session {
        destination: dst.clone(),
        ..Default::default()
    };
    let datagram = tokio::time::timeout(
        Duration::from_secs(5),
        handler.connect_datagram(&sess, resolver),
    )
    .await
    .map_err(|_| anyhow::anyhow!("dns udp connect timed out for {dst:?}"))??;
    let (mut sink, mut stream) = datagram.split();
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01";

    sink.send(UdpPacket::new(
        query.to_vec(),
        SocksAddr::Ip("127.0.0.1:0".parse()?),
        dst.clone(),
    ))
    .await?;

    let response = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .map_err(|_| anyhow::anyhow!("dns udp roundtrip timed out for {dst:?}"))?
        .ok_or_else(|| anyhow::anyhow!("dns udp stream closed for {dst:?}"))?;
    anyhow::ensure!(
        response.data.len() >= 4
            && response.data[..2] == [0x12, 0x34]
            && response.data[2] & 0x80 != 0,
        "unexpected dns udp response: {:?}",
        response.data
    );
    Ok(())
}

#[cfg(test)]
mod suite_tests {
    use std::{future::Future, sync::Arc};

    use super::*;
    use crate::proxy::direct;

    struct LocalRunner;

    #[async_trait::async_trait]
    impl RunAndCleanup for LocalRunner {
        fn docker_gateway_ip(&self) -> Option<String> {
            Some("127.0.0.1".to_owned())
        }

        async fn run_and_cleanup(
            self,
            f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
        ) -> anyhow::Result<()> {
            f.await
        }
    }

    #[tokio::test]
    async fn formerly_placeholder_suites_execute_real_roundtrips() {
        let handler: Arc<dyn OutboundHandler> =
            Arc::new(direct::Handler::new("test-direct"));
        run_test_suites_and_cleanup(handler, LocalRunner, Suite::all())
            .await
            .expect("restored docker suites must execute real local roundtrips");
    }
}
