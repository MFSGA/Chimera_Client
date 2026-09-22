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
fn mihomo_vless_xhttp_schema_contract_parses() {
    let config = parse_with_proxy(
        r#"  - name: mihomo-xhttp
    type: vless
    server: upload.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    alpn:
      - h2
    servername: upload.example.com
    network: xhttp
    xhttp-opts:
      path: /api?ed=2048
      host: upload-host.example.com
      mode: auto
      session-placement: query
      session-key: x_session
      session-table: Base62
      session-length: 10
      seq-placement: header
      seq-key: X-Seq
      x-padding-bytes: 100-1000
      x-padding-obfs-mode: true
      x-padding-key: x_padding
      x-padding-header: X-Padding
      x-padding-placement: queryInHeader
      x-padding-method: tokenish
      uplink-http-method: POST
      uplink-data-placement: body
      uplink-chunk-size: 100-200
      reuse-settings:
        max-concurrency: 16-32
        c-max-reuse-times: 0
        h-max-request-times: 600-900
        h-max-reusable-secs: 1800-3000
        h-keep-alive-period: -1
      download-settings:
        address: download.example.com
        port: 8443
        network: xhttp
        security: tls
        server-name: download.example.com
        skip-cert-verify: true
        fingerprint: 0123456789abcdef
        path: /download?token=1
        host: download-host.example.com
        headers:
          X-Download: enabled
        reuse-settings:
          max-connections: 4
"#,
    );

    let vless = vless(&config, "mihomo-xhttp");
    assert_eq!(vless.network.as_deref(), Some("xhttp"));
    assert_eq!(vless.alpn.as_deref(), Some(["h2".to_owned()].as_slice()));

    let xhttp = vless.xhttp_opts.as_ref().expect("xhttp opts");
    assert_eq!(xhttp.path.as_deref(), Some("/api?ed=2048"));
    assert_eq!(xhttp.host.as_deref(), Some("upload-host.example.com"));
    assert_eq!(xhttp.mode.as_deref(), Some("auto"));
    assert_eq!(xhttp.session_placement.as_deref(), Some("query"));
    assert_eq!(xhttp.session_key.as_deref(), Some("x_session"));
    assert_eq!(xhttp.session_table.as_deref(), Some("Base62"));
    assert_eq!(xhttp.session_length.as_deref(), Some("10"));
    assert_eq!(xhttp.seq_placement.as_deref(), Some("header"));
    assert_eq!(xhttp.seq_key.as_deref(), Some("X-Seq"));
    assert_eq!(xhttp.x_padding_bytes.as_deref(), Some("100-1000"));
    assert_eq!(xhttp.x_padding_obfs_mode, Some(true));
    assert_eq!(xhttp.x_padding_key.as_deref(), Some("x_padding"));
    assert_eq!(xhttp.x_padding_header.as_deref(), Some("X-Padding"));
    assert_eq!(xhttp.x_padding_placement.as_deref(), Some("queryInHeader"));
    assert_eq!(xhttp.x_padding_method.as_deref(), Some("tokenish"));
    assert_eq!(xhttp.uplink_http_method.as_deref(), Some("POST"));
    assert_eq!(xhttp.uplink_data_placement.as_deref(), Some("body"));
    assert_eq!(xhttp.uplink_chunk_size.as_deref(), Some("100-200"));

    let reuse = xhttp.reuse_settings.as_ref().expect("reuse settings");
    assert_eq!(reuse.max_concurrency.as_deref(), Some("16-32"));
    assert_eq!(reuse.c_max_reuse_times.as_deref(), Some("0"));
    assert_eq!(reuse.h_max_request_times.as_deref(), Some("600-900"));
    assert_eq!(reuse.h_max_reusable_secs.as_deref(), Some("1800-3000"));
    assert_eq!(reuse.h_keep_alive_period.as_deref(), Some("-1"));

    let download = xhttp.download_settings.as_ref().expect("download settings");
    assert_eq!(download.address, "download.example.com");
    assert_eq!(download.port, 8443);
    assert_eq!(download.network, "xhttp");
    assert_eq!(download.security.as_deref(), Some("tls"));
    assert_eq!(
        download.server_name.as_deref(),
        Some("download.example.com")
    );
    assert_eq!(download.skip_cert_verify, Some(true));
    assert_eq!(download.fingerprint.as_deref(), Some("0123456789abcdef"));
    assert_eq!(download.path.as_deref(), Some("/download?token=1"));
    assert_eq!(download.host.as_deref(), Some("download-host.example.com"));
    assert_eq!(
        download
            .headers
            .as_ref()
            .and_then(|headers| headers.get("X-Download"))
            .map(String::as_str),
        Some("enabled")
    );
    assert_eq!(
        download
            .reuse_settings
            .as_ref()
            .and_then(|reuse| reuse.max_connections.as_deref()),
        Some("4")
    );
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
