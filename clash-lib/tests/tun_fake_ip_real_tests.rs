#![cfg(feature = "tun")]

use std::{
    fs,
    io::{Read, Write},
    net::{
        IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
    },
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clash_lib::{Config, Options};
use serial_test::serial;

mod common;

const DIRECT_DOMAIN: &str = "direct.tun-fake-ip.test";
const PROXY_DOMAIN: &str = "proxy.tun-fake-ip.test";
const FAKE_IP_PREFIX: [u8; 2] = [198, 18];
const TUN_GATEWAY_PREFIX: [u8; 3] = [192, 0, 2];

/// Real cross-platform TUN test; run explicitly with
/// `cargo test -p clash-lib --features tun --test tun_fake_ip_real_tests -- --ignored --test-threads=1`.
/// It requires administrator/root permission and a working platform TUN driver.
#[test]
#[ignore = "requires administrator/root permission and a working TUN driver"]
#[serial]
fn tun_fake_ip_answers_without_upstream_and_routes_direct_and_proxy() {
    // This ignored diagnostic test owns process-global logging while it runs.
    unsafe {
        std::env::set_var("RUST_LOG", "warn,clash_lib=debug");
    }

    let api_port = pick_free_port();
    let dns_port = pick_free_port();
    let upstream_dns_port = pick_free_port();
    let http_port = pick_free_port();
    let socks_port = pick_free_port();

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let log_path = temp_dir.path().join("tun-fake-ip.log");
    fs::File::create(&log_path).expect("create log file");

    let upstream_queries = spawn_fixed_a_dns(upstream_dns_port, Ipv4Addr::LOCALHOST);
    spawn_http_echo(http_port);
    let proxy_connects = spawn_recording_socks5_proxy(socks_port, http_port);

    let device_id = unique_device_id();
    let subnet_octet = test_subnet_octet();
    let gateway_octet = ((std::process::id() % 64) * 4 + 1) as u8;
    let fake_ip_range = format!(
        "{}.{}.{}.0/24",
        FAKE_IP_PREFIX[0], FAKE_IP_PREFIX[1], subnet_octet
    );
    let tun_gateway = format!(
        "{}.{}.{}.{}/30",
        TUN_GATEWAY_PREFIX[0],
        TUN_GATEWAY_PREFIX[1],
        TUN_GATEWAY_PREFIX[2],
        gateway_octet
    );

    let conf = format!(
        r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: debug
external-controller: 127.0.0.1:{api_port}
secret: clash-rs
mmdb: null

tun:
  enable: true
  device-id: "{device_id}"
  route-all: false
  gateway: "{tun_gateway}"
  dns-hijack: false

dns:
  enable: true
  listen:
    udp: 127.0.0.1:{dns_port}
    tcp: 127.0.0.1:{dns_port}
  enhanced-mode: fake-ip
  fake-ip-range: {fake_ip_range}
  nameserver:
    - udp://127.0.0.1:{upstream_dns_port}
  default-nameserver:
    - udp://127.0.0.1:{upstream_dns_port}

profile:
  store-selected: false
  store-fake-ip: false

proxies:
  - name: local-socks
    type: socks5
    server: 127.0.0.1
    port: {socks_port}
    udp: false

rules:
  - DOMAIN,{PROXY_DOMAIN},local-socks
  - DOMAIN,{DIRECT_DOMAIN},DIRECT
  - MATCH,DIRECT
"#
    );

    let cwd = temp_dir.path().to_string_lossy().to_string();
    let log_file = log_path.to_string_lossy().to_string();
    let (handle, cancellation_token) = clash_lib::start_scaffold_instance(Options {
        config: Config::Str(conf),
        cwd: Some(cwd),
        rt: None,
        log_file: Some(log_file),
        config_path: None,
    })
    .expect("start clash with tun");
    let runtime = RuntimeGuard::new(handle, cancellation_token);

    common::wait_port_ready(api_port).expect("api port ready");
    wait_for_dns(dns_port);

    let upstream_queries_before_fake_ip = upstream_queries.load(Ordering::SeqCst);
    let direct_fake_ip = query_a(("127.0.0.1", dns_port), DIRECT_DOMAIN);
    let direct_fake_ip_tcp = query_a_tcp(("127.0.0.1", dns_port), DIRECT_DOMAIN);
    let proxy_fake_ip = query_a(("127.0.0.1", dns_port), PROXY_DOMAIN);
    assert_eq!(
        direct_fake_ip, direct_fake_ip_tcp,
        "UDP and TCP DNS queries should reuse the same fake-IP mapping"
    );
    assert_ne!(
        direct_fake_ip, proxy_fake_ip,
        "different domains should receive different fake-IP addresses"
    );
    assert_fake_ip_in_test_range(direct_fake_ip, subnet_octet);
    assert_fake_ip_in_test_range(proxy_fake_ip, subnet_octet);
    assert_eq!(
        upstream_queries.load(Ordering::SeqCst),
        upstream_queries_before_fake_ip,
        "fake-IP DNS answers should not query the real DNS upstream"
    );

    let direct_body =
        http_get((direct_fake_ip, http_port), DIRECT_DOMAIN, "direct-marker");
    assert!(
        direct_body.contains("direct-marker"),
        "direct response should come from the real 127.0.0.1 echo server: {direct_body}"
    );
    assert_eq!(
        proxy_connects.load(Ordering::SeqCst),
        0,
        "DIRECT rule must not touch the proxy"
    );

    let proxy_body =
        http_get((proxy_fake_ip, http_port), PROXY_DOMAIN, "proxy-marker");
    assert!(
        proxy_body.contains("proxy-marker"),
        "proxy response should pass through local SOCKS5 proxy: {proxy_body}"
    );
    let proxy_deadline = Instant::now() + Duration::from_secs(2);
    while proxy_connects.load(Ordering::SeqCst) != 1
        && Instant::now() < proxy_deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        proxy_connects.load(Ordering::SeqCst),
        1,
        "proxy rule should connect exactly once to the local SOCKS5 proxy"
    );

    // Reset through the production coordinator while retaining the fake-IP
    // addresses already handed to applications. No physical NIC is changed.
    for round in 0..3 {
        let mut control =
            TcpStream::connect((Ipv4Addr::LOCALHOST, api_port)).unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        control.write_all(b"POST /network/reset HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer clash-rs\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        control.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "reset failed: {response}"
        );
        assert_eq!(
            query_a(("127.0.0.1", dns_port), DIRECT_DOMAIN),
            direct_fake_ip
        );
        assert_eq!(
            query_a(("127.0.0.1", dns_port), PROXY_DOMAIN),
            proxy_fake_ip
        );
        let marker = format!("recovered-{round}");
        assert!(
            http_get((direct_fake_ip, http_port), DIRECT_DOMAIN, &marker)
                .contains(&marker)
        );
        assert!(
            http_get((proxy_fake_ip, http_port), PROXY_DOMAIN, &marker)
                .contains(&marker)
        );
    }

    runtime.stop();

    let logs = fs::read_to_string(&log_path).expect("read log file");
    assert!(
        logs.contains("dispatching")
            && logs.contains(DIRECT_DOMAIN)
            && logs.contains("DIRECT"),
        "missing direct dispatch log:\n{logs}"
    );
    assert!(
        logs.contains("dispatching")
            && logs.contains(PROXY_DOMAIN)
            && logs.contains("local-socks"),
        "missing proxy dispatch log:\n{logs}"
    );
}

fn pick_free_port() -> u16 {
    loop {
        let tcp =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind free TCP port");
        let port = tcp.local_addr().expect("local addr").port();
        if let Ok(udp) = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            drop(udp);
            drop(tcp);
            return port;
        }
    }
}

fn unique_device_id() -> String {
    let _pid = std::process::id();
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ifconfig")
            .arg("-l")
            .output()
            .expect("list macOS interfaces");
        assert!(output.status.success(), "ifconfig -l failed");
        let interfaces = String::from_utf8_lossy(&output.stdout);
        let name = (0..4096)
            .map(|index| format!("utun{index}"))
            .find(|candidate| !interfaces.split_whitespace().any(|x| x == candidate))
            .expect("find an unused macOS utun name");
        format!("dev://{name}")
    }
    #[cfg(windows)]
    {
        format!("dev://chimera-test-{_pid}")
    }
    #[cfg(target_os = "linux")]
    {
        let interfaces = std::fs::read_dir("/sys/class/net")
            .expect("list Linux interfaces")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect::<Vec<_>>();
        let name = (0..1000)
            .map(|suffix| format!("ct{}", (_pid + suffix) % 1_000_000_000))
            .find(|candidate| !interfaces.iter().any(|x| x == candidate))
            .expect("find an unused Linux TUN name");
        format!("dev://{name}")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        format!("dev://chimera-test-{_pid}")
    }
}

fn test_subnet_octet() -> u8 {
    (std::process::id() % 200 + 20) as u8
}

fn assert_fake_ip_in_test_range(ip: Ipv4Addr, subnet_octet: u8) {
    let octets = ip.octets();
    assert_eq!(
        &octets[..3],
        &[FAKE_IP_PREFIX[0], FAKE_IP_PREFIX[1], subnet_octet],
        "fake-IP should come from the isolated test subnet"
    );
}

struct RuntimeGuard {
    handle: Option<thread::JoinHandle<()>>,
    cancellation_token: tokio_util::sync::CancellationToken,
}

impl RuntimeGuard {
    fn new(
        handle: thread::JoinHandle<()>,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            handle: Some(handle),
            cancellation_token,
        }
    }

    fn stop(mut self) {
        self.cancellation_token.cancel();
        if let Some(handle) = self.handle.take() {
            handle.join().expect("clash runtime thread joined");
        }
    }
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        self.cancellation_token.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_fixed_a_dns(port: u16, ip: Ipv4Addr) -> Arc<AtomicUsize> {
    let upstream_queries = Arc::new(AtomicUsize::new(0));
    let query_counter = upstream_queries.clone();
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).expect("dns bind");
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((len, peer)) = socket.recv_from(&mut buf) {
            query_counter.fetch_add(1, Ordering::SeqCst);
            if let Some(response) = build_a_response(&buf[..len], ip) {
                let _ = socket.send_to(&response, peer);
            }
        }
    });
    upstream_queries
}

fn wait_for_dns(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| {
                socket.set_read_timeout(Some(Duration::from_millis(200)))?;
                let query = build_a_query(0x1234, "ready.test");
                socket.send_to(&query, (Ipv4Addr::LOCALHOST, port))?;
                let mut buf = [0u8; 512];
                socket.recv_from(&mut buf).map(|_| ())
            })
            .is_ok()
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("DNS listener on 127.0.0.1:{port} did not become ready");
}

fn query_a(addr: (&str, u16), domain: &str) -> Ipv4Addr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("query bind");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set timeout");
    let query = build_a_query(0x4321, domain);
    socket.send_to(&query, addr).expect("send dns query");
    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf).expect("recv dns response");
    parse_first_a(&buf[..len]).expect("A response")
}

fn query_a_tcp(addr: (&str, u16), domain: &str) -> Ipv4Addr {
    let mut stream = TcpStream::connect((addr.0, addr.1)).expect("DNS TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set DNS TCP read timeout");
    let query = build_a_query(0x4322, domain);
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .expect("write DNS TCP length");
    stream.write_all(&query).expect("write DNS TCP query");
    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .expect("read DNS TCP response length");
    let mut response = vec![0u8; u16::from_be_bytes(length) as usize];
    stream
        .read_exact(&mut response)
        .expect("read DNS TCP response");
    parse_first_a(&response).expect("A response over TCP")
}

fn build_a_query(id: u16, domain: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    push_qname(&mut out, domain);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let question_end = skip_question(query, 12)?;
    let mut out = Vec::with_capacity(question_end + 32);
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..question_end]);
    out.extend_from_slice(&0xC00Cu16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
    Some(out)
}

fn push_qname(out: &mut Vec<u8>, domain: &str) {
    for label in domain.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn skip_question(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *packet.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        offset += len;
        if offset > packet.len() {
            return None;
        }
    }
    offset.checked_add(4).filter(|end| *end <= packet.len())
}

fn parse_first_a(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 12 || u16::from_be_bytes([packet[6], packet[7]]) == 0 {
        return None;
    }
    let mut offset = skip_question(packet, 12)?;
    loop {
        if offset + 12 > packet.len() {
            return None;
        }
        offset = skip_name(packet, offset)?;
        let typ = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let rdlen =
            u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if typ == 1 && class == 1 && rdlen == 4 && offset + 4 <= packet.len() {
            return Some(Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ));
        }
        offset += rdlen;
    }
}

fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *packet.get(offset)?;
        offset += 1;
        if len & 0xC0 == 0xC0 {
            return offset.checked_add(1).filter(|end| *end <= packet.len());
        }
        if len == 0 {
            return Some(offset);
        }
        offset += len as usize;
        if offset > packet.len() {
            return None;
        }
    }
}

fn spawn_http_echo(port: u16) {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("http bind");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || handle_http_echo(stream));
        }
    });
}

fn handle_http_echo(mut stream: TcpStream) {
    let mut buf = [0u8; 2048];
    let Ok(n) = stream.read(&mut buf) else {
        return;
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let body = req
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .trim_start_matches('/');
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn spawn_recording_socks5_proxy(port: u16, forward_port: u16) -> Arc<AtomicUsize> {
    let connects = Arc::new(AtomicUsize::new(0));
    let connects_cloned = connects.clone();
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("socks bind");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let connects = connects_cloned.clone();
            thread::spawn(move || {
                if handle_socks5_connect(stream, forward_port).is_ok() {
                    connects.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    connects
}

fn handle_socks5_connect(
    mut client: TcpStream,
    forward_port: u16,
) -> std::io::Result<()> {
    let mut header = [0u8; 2];
    client.read_exact(&mut header)?;
    let mut methods = vec![0u8; header[1] as usize];
    client.read_exact(&mut methods)?;
    client.write_all(&[0x05, 0x00])?;

    let mut req = [0u8; 4];
    client.read_exact(&mut req)?;
    if req != [0x05, 0x01, 0x00, 0x03] {
        return Err(std::io::Error::other("expected domain CONNECT"));
    }
    let mut len = [0u8; 1];
    client.read_exact(&mut len)?;
    let mut domain = vec![0u8; len[0] as usize];
    client.read_exact(&mut domain)?;
    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    let _requested = (
        String::from_utf8_lossy(&domain).to_string(),
        u16::from_be_bytes(port),
    );

    let mut remote = TcpStream::connect((Ipv4Addr::LOCALHOST, forward_port))?;
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])?;

    let mut client_to_remote = client.try_clone()?;
    let mut remote_to_client = remote.try_clone()?;
    let up = thread::spawn(move || {
        let _ = std::io::copy(&mut client_to_remote, &mut remote);
    });
    let _ = std::io::copy(&mut remote_to_client, &mut client);
    client.shutdown(Shutdown::Write)?;
    let _ = up.join();
    Ok(())
}

fn http_get(addr: (Ipv4Addr, u16), host: &str, marker: &str) -> String {
    let destination = SocketAddr::new(IpAddr::V4(addr.0), addr.1);
    let mut stream =
        TcpStream::connect_timeout(&destination, Duration::from_secs(5))
            .expect("connect fake-ip through tun");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let request = format!(
        "GET /{marker} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .expect("write http request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read http response");
    response
}
