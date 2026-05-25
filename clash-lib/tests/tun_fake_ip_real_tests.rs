#![cfg(feature = "tun")]

use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::PathBuf,
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

#[test]
#[ignore = "requires administrator/root permission and a working TUN driver"]
#[serial]
fn tun_fake_ip_routes_direct_and_proxy_with_real_network() {
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

    spawn_fixed_a_dns(upstream_dns_port, Ipv4Addr::LOCALHOST);
    spawn_http_echo(http_port);
    let proxy_connects = spawn_recording_socks5_proxy(socks_port, http_port);

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
  device-id: "dev://chimera-test-tun"
  route-all: false
  routes:
    - 198.18.0.0/16
  gateway: "198.18.0.1/24"
  dns-hijack: false

dns:
  enable: true
  listen:
    udp: 127.0.0.1:{dns_port}
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/16
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
    let handle = thread::spawn(move || {
        clash_lib::start_scaffold(Options {
            config: Config::Str(conf),
            cwd: Some(cwd),
            rt: None,
            log_file: Some(log_file),
            config_path: None,
        })
        .expect("start clash with tun")
    });

    common::wait_port_ready(api_port).expect("api port ready");
    wait_for_dns(dns_port);
    assert_tun_did_not_fail(&log_path);

    let direct_fake_ip = query_a(("127.0.0.1", dns_port), DIRECT_DOMAIN);
    let proxy_fake_ip = query_a(("127.0.0.1", dns_port), PROXY_DOMAIN);
    assert!(direct_fake_ip.octets().starts_with(&[198, 18]));
    assert!(proxy_fake_ip.octets().starts_with(&[198, 18]));

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
    assert_eq!(
        proxy_connects.load(Ordering::SeqCst),
        1,
        "proxy rule should connect exactly once to the local SOCKS5 proxy"
    );

    assert!(clash_lib::shutdown());
    handle.join().expect("clash thread joined");

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
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind free port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn assert_tun_did_not_fail(log_path: &PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let logs = fs::read_to_string(log_path).unwrap_or_default();
        assert!(
            !logs.contains("tun initialization failed"),
            "TUN failed to initialize. Re-run this ignored test from an elevated terminal and ensure the TUN/Wintun driver is available.\n{logs}"
        );
        if logs.contains("tun device") || logs.contains("tun started") {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_fixed_a_dns(port: u16, ip: Ipv4Addr) {
    thread::spawn(move || {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).expect("dns bind");
        let mut buf = [0u8; 512];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf) else {
                break;
            };
            if let Some(response) = build_a_response(&buf[..len], ip) {
                let _ = socket.send_to(&response, peer);
            }
        }
    });
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
    thread::spawn(move || {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("http bind");
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
    let body = if req.contains("proxy-marker") {
        "proxy-marker"
    } else {
        "direct-marker"
    };
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
    thread::spawn(move || {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("socks bind");
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
    let _ = up.join();
    Ok(())
}

fn http_get(addr: (Ipv4Addr, u16), host: &str, marker: &str) -> String {
    let mut stream = TcpStream::connect(SocketAddr::new(IpAddr::V4(addr.0), addr.1))
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
