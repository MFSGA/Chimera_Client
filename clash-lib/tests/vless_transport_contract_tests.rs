use clash_lib::{
    Config,
    config::internal::proxy::{OutboundProxy, OutboundProxyProtocol},
};

fn parse_with_proxy(proxy_yaml: &str) -> clash_lib::config::RuntimeConfig {
    let yaml = format!(
        r#"
mixed-port: 0
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: error
ipv6: false
mmdb: null
tun:
  enable: false
dns:
  enable: false
proxies:
{proxy_yaml}
rules: []
"#
    );

    Config::Str(yaml)
        .try_parse()
        .expect("Mihomo-style VLESS config should parse")
}

fn vless<'a>(
    config: &'a clash_lib::config::RuntimeConfig,
    name: &str,
) -> &'a clash_lib::config::internal::proxy::OutboundVless {
    let proxy = config
        .proxies
        .get(name)
        .unwrap_or_else(|| panic!("missing proxy {name}"));

    match proxy {
        OutboundProxy::ProxyServer(OutboundProxyProtocol::Vless(vless)) => vless,
        _ => panic!("proxy {name} is not VLESS"),
    }
}

#[cfg(feature = "ws")]
#[test]
fn mihomo_vless_ws_upgrade_schema_contract_parses() {
    let config = parse_with_proxy(
        r#"  - name: mihomo-ws
    type: vless
    server: ws.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: ws-host.example.com
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
      v2ray-http-upgrade: true
      v2ray-http-upgrade-fast-open: true
"#,
    );

    let vless = vless(&config, "mihomo-ws");
    assert_eq!(vless.network.as_deref(), Some("ws"));

    let ws = vless.ws_opts.as_ref().expect("ws opts");
    assert_eq!(ws.path.as_deref(), Some("/ws"));
    assert_eq!(ws.max_early_data, Some(2048));
    assert_eq!(
        ws.early_data_header_name.as_deref(),
        Some("Sec-WebSocket-Protocol")
    );
    assert_eq!(ws.v2ray_http_upgrade, Some(true));
    assert_eq!(ws.v2ray_http_upgrade_fast_open, Some(true));
    assert_eq!(
        ws.headers
            .as_ref()
            .and_then(|headers| headers.get("Host"))
            .map(String::as_str),
        Some("ws-host.example.com")
    );
}

#[test]
fn mihomo_vless_grpc_schema_contract_parses() {
    let config = parse_with_proxy(
        r#"  - name: mihomo-grpc
    type: vless
    server: grpc.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    alpn:
      - h2
    network: grpc
    grpc-opts:
      grpc-service-name: grpc-service
      grpc-user-agent: grpc-go/1.65
      ping-interval: 30
      max-connections: 4
      min-streams: 8
"#,
    );

    let vless = vless(&config, "mihomo-grpc");
    assert_eq!(vless.network.as_deref(), Some("grpc"));
    assert_eq!(vless.alpn.as_deref(), Some(["h2".to_owned()].as_slice()));

    let grpc = vless.grpc_opts.as_ref().expect("grpc opts");
    assert_eq!(grpc.grpc_service_name.as_deref(), Some("grpc-service"));
    assert_eq!(grpc.grpc_user_agent.as_deref(), Some("grpc-go/1.65"));
    assert_eq!(grpc.ping_interval, Some(30));
    assert_eq!(grpc.max_connections, Some(4));
    assert_eq!(grpc.min_streams, Some(8));
    assert_eq!(grpc.max_streams, None);
}

#[test]
fn mihomo_vless_tls_verify_name_and_mtls_schema_contract_parses() {
    let config = parse_with_proxy(
        r#"  - name: mihomo-mtls
    type: vless
    server: edge.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: front.example.com
    name-cert-verify: verify.example.com
    fingerprint: 0123456789abcdef
    certificate: client-cert.pem
    private-key: client-key.pem
    alpn:
      - h2
      - http/1.1
"#,
    );

    let vless = vless(&config, "mihomo-mtls");
    assert_eq!(vless.tls, Some(true));
    assert_eq!(vless.server_name.as_deref(), Some("front.example.com"));
    assert_eq!(
        vless.name_cert_verify.as_deref(),
        Some("verify.example.com")
    );
    assert_eq!(vless.fingerprint.as_deref(), Some("0123456789abcdef"));
    assert_eq!(vless.certificate.as_deref(), Some("client-cert.pem"));
    assert_eq!(vless.private_key.as_deref(), Some("client-key.pem"));
    assert_eq!(
        vless.alpn.as_deref(),
        Some(["h2".to_owned(), "http/1.1".to_owned()].as_slice())
    );
}
