use clash_lib::{
    Config, Options, TokioRuntime,
    app::dns::{Config as DnsConfig, config::DNSNetMode},
};

fn parse_dns(yaml: &str) -> DnsConfig {
    Config::Str(yaml.to_owned())
        .try_parse()
        .expect("config should parse")
        .dns
}

fn parse_error(yaml: String) -> clash_lib::Error {
    match Config::Str(yaml).try_parse() {
        Ok(_) => panic!("config should fail"),
        Err(err) => err,
    }
}

fn base_config(dns_yaml: &str) -> String {
    format!(
        r#"
mixed-port: 0
bind-address: '*'
allow-lan: false
mode: rule
log-level: info
ipv6: true

dns:
{dns_yaml}

profile:
  store-selected: false
  store-fake-ip: false

proxies: []

rules:
  - MATCH,DIRECT
"#
    )
}

#[test]
#[serial_test::serial]
fn occupied_dns_listeners_fail_runtime_startup() {
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve TCP DNS port");
    let addr = tcp.local_addr().expect("failed to read DNS address");
    let udp =
        std::net::UdpSocket::bind(addr).expect("failed to reserve UDP DNS port");
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let yaml = format!(
        r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
mmdb: null
tun:
  enable: false
dns:
  enable: true
  ipv6: false
  listen:
    udp: {addr}
    tcp: {addr}
  enhanced-mode: normal
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 1.1.1.1
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
rules:
  - MATCH,DIRECT
"#
    );

    let err = clash_lib::start_scaffold(Options {
        config: Config::Str(yaml),
        cwd: Some(temp.path().to_string_lossy().to_string()),
        rt: Some(TokioRuntime::SingleThread),
        log_file: None,
        config_path: None,
    })
    .expect_err("runtime startup must fail when every DNS listener is occupied");

    assert!(err.to_string().contains("no listener started"));
    assert!(!clash_lib::shutdown());
    drop(udp);
    drop(tcp);
}

#[test]
#[serial_test::serial]
fn missing_dhcp_interface_fails_runtime_startup() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let yaml = r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
mmdb: null
tun:
  enable: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: normal
  nameserver:
    - dhcp://__chimera_missing_interface__
  default-nameserver:
    - 1.1.1.1
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
rules:
  - MATCH,DIRECT
"#;

    let err = clash_lib::start_scaffold(Options {
        config: Config::Str(yaml.to_owned()),
        cwd: Some(temp.path().to_string_lossy().to_string()),
        rt: Some(TokioRuntime::SingleThread),
        log_file: None,
        config_path: None,
    })
    .expect_err("missing DHCP interface must fail runtime startup");

    assert!(
        err.to_string().contains("__chimera_missing_interface__"),
        "unexpected error: {err}"
    );
    assert!(!clash_lib::shutdown());
}

#[test]
#[serial_test::serial]
fn invalid_fake_ip_ranges_fail_runtime_startup() {
    for (range, expected) in [
        ("2001:db8::/64", "IPv4 subnet"),
        ("198.18.0.0/31", "at least one allocatable address"),
    ] {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let yaml = format!(
            r#"
mixed-port: 0
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
mmdb: null
tun:
  enable: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: {range}
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 1.1.1.1
profile:
  store-selected: false
  store-fake-ip: false
proxies: []
rules:
  - MATCH,DIRECT
"#
        );

        let err = clash_lib::start_scaffold(Options {
            config: Config::Str(yaml),
            cwd: Some(temp.path().to_string_lossy().to_string()),
            rt: Some(TokioRuntime::SingleThread),
            log_file: None,
            config_path: None,
        })
        .expect_err("invalid fake IP range must fail runtime startup");

        assert!(
            err.to_string().contains(expected),
            "unexpected error for {range}: {err}"
        );
        assert!(!clash_lib::shutdown());
    }
}

#[test]
fn full_dns_fixture_parses_expected_runtime_shape() {
    let yaml = include_str!("data/config/dns/full_dns.yaml");
    let dns = parse_dns(yaml);

    assert!(dns.enable);
    assert!(dns.ipv6);
    assert_eq!(dns.listen.udp.unwrap().to_string(), "127.0.0.1:0");
    assert_eq!(dns.listen.tcp.unwrap().to_string(), "127.0.0.1:0");
    assert_eq!(dns.nameserver.len(), 4);
    assert_eq!(dns.nameserver[0].net, DNSNetMode::Udp);
    assert_eq!(dns.nameserver[0].host.to_string(), "1.1.1.1");
    assert_eq!(dns.nameserver[0].port, 53);
    assert_eq!(dns.nameserver[1].net, DNSNetMode::Tcp);
    assert_eq!(dns.nameserver[1].port, 5353);
    assert_eq!(dns.nameserver[2].net, DNSNetMode::DoT);
    assert_eq!(dns.nameserver[2].port, 853);
    assert_eq!(dns.nameserver[3].net, DNSNetMode::DoH);
    assert_eq!(dns.nameserver[3].port, 443);
    assert_eq!(dns.nameserver[3].proxy.as_deref(), Some("DIRECT"));
    assert_eq!(dns.default_nameserver.len(), 2);
    assert_eq!(dns.proxy_server_nameserver.as_ref().unwrap().len(), 1);
    assert_eq!(dns.fallback.len(), 1);
    assert!(dns.nameserver_policy.contains_key("example.com"));
    assert_eq!(dns.fallback_filter.geo_ip_code, "CN");
    assert_eq!(dns.fallback_filter.ip_cidr.as_ref().unwrap().len(), 1);
    assert_eq!(dns.fake_ip_range.to_string(), "198.18.0.1/16");
    assert_eq!(dns.fake_ip_filter, vec!["*.lan", "+.local"]);
    assert_eq!(
        dns.edns_client_subnet.unwrap().ipv4.unwrap().to_string(),
        "1.2.3.0/24"
    );
}

#[test]
fn dns_enabled_requires_at_least_one_nameserver() {
    let yaml = base_config(
        r#"
  enable: true
  default-nameserver:
    - 223.5.5.5
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string()
            .contains("dns enabled, no nameserver specified"),
        "unexpected error: {err}"
    );
}

#[test]
fn default_nameserver_must_be_ip_address() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - dns.google
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("default dns must be ip address"),
        "unexpected error: {err}"
    );
}

#[test]
fn unsupported_nameserver_scheme_is_rejected() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - quic://1.1.1.1
  default-nameserver:
    - 223.5.5.5
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string().contains("unsupported scheme"),
        "unexpected error: {err}"
    );
}

#[test]
fn edns_client_subnet_requires_at_least_one_family() {
    let yaml = base_config(
        r#"
  enable: true
  nameserver:
    - 1.1.1.1
  default-nameserver:
    - 223.5.5.5
  edns-client-subnet: {}
"#,
    );

    let err = parse_error(yaml);
    assert!(
        err.to_string()
            .contains("edns-client-subnet requires at least one"),
        "unexpected error: {err}"
    );
}
