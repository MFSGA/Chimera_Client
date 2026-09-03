use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
};

use serde::{Deserialize, de::value::MapDeserializer};
use serde_yaml::Value;

use crate::{Error, common::utils::default_bool_true, config::utils};

pub const PROXY_DIRECT: &str = "DIRECT";
pub const PROXY_REJECT: &str = "REJECT";
pub const PROXY_GLOBAL: &str = "GLOBAL";

#[allow(clippy::large_enum_variant)]
pub enum OutboundProxy {
    ProxyServer(OutboundProxyProtocol),
    ProxyGroup(OutboundGroupProtocol),
}

impl OutboundProxy {
    pub(crate) fn name(&self) -> String {
        match self {
            OutboundProxy::ProxyServer(s) => s.name().to_string(),
            OutboundProxy::ProxyGroup(g) => g.name().to_string(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum OutboundProxyProtocol {
    #[serde(rename = "direct")]
    Direct(OutboundDirect),
    #[serde(rename = "reject")]
    Reject(OutboundReject),
    #[cfg(feature = "shadowsocks")]
    #[serde(rename = "ss")]
    Ss(OutboundShadowsocks),
    #[serde(rename = "socks5")]
    Socks5(OutboundSocks5),
    #[cfg(feature = "anytls")]
    #[serde(rename = "anytls")]
    Anytls(OutboundAnytls),

    #[serde(rename = "vless")]
    Vless(OutboundVless),
    #[cfg(feature = "wireguard")]
    #[serde(rename = "wireguard")]
    Wireguard(OutboundWireguard),
    #[cfg(feature = "trojan")]
    #[serde(rename = "trojan")]
    Trojan(OutboundTrojan),
    #[cfg(feature = "hysteria")]
    #[serde(rename = "hysteria2")]
    Hysteria2(OutboundHysteria2),
}

impl OutboundProxyProtocol {
    pub(crate) fn name(&self) -> &str {
        match &self {
            OutboundProxyProtocol::Direct(direct) => &direct.name,
            OutboundProxyProtocol::Reject(reject) => &reject.name,
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ss(ss) => &ss.common_opts.name,
            OutboundProxyProtocol::Socks5(socks5) => &socks5.common_opts.name,
            #[cfg(feature = "anytls")]
            OutboundProxyProtocol::Anytls(anytls) => &anytls.common_opts.name,
            OutboundProxyProtocol::Vless(vless) => &vless.common_opts.name,
            #[cfg(feature = "wireguard")]
            OutboundProxyProtocol::Wireguard(wireguard) => {
                &wireguard.common_opts.name
            }
            #[cfg(feature = "trojan")]
            OutboundProxyProtocol::Trojan(trojan) => &trojan.common_opts.name,
            #[cfg(feature = "hysteria")]
            OutboundProxyProtocol::Hysteria2(hysteria2) => &hysteria2.name,
        }
    }
}

impl TryFrom<HashMap<String, Value>> for OutboundProxyProtocol {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy protocol".to_owned(),
            ))?
            .to_owned();
        OutboundProxyProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}

impl Display for OutboundProxyProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundProxyProtocol::Direct(_) => write!(f, "{PROXY_DIRECT}"),
            OutboundProxyProtocol::Reject(_) => write!(f, "{PROXY_REJECT}"),
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ss(_) => write!(f, "Shadowsocks"),
            OutboundProxyProtocol::Socks5(_) => write!(f, "Socks5"),
            #[cfg(feature = "anytls")]
            OutboundProxyProtocol::Anytls(_) => write!(f, "AnyTLS"),
            OutboundProxyProtocol::Vless(_) => write!(f, "Vless"),
            #[cfg(feature = "wireguard")]
            OutboundProxyProtocol::Wireguard(_) => write!(f, "Wireguard"),
            #[cfg(feature = "trojan")]
            OutboundProxyProtocol::Trojan(_) => write!(f, "Trojan"),
            #[cfg(feature = "hysteria")]
            OutboundProxyProtocol::Hysteria2(_) => write!(f, "Hysteria2"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundDirect {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundReject {
    pub name: String,
}

#[cfg(feature = "shadowsocks")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundShadowsocks {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub cipher: String,
    pub password: String,
    #[serde(default = "default_bool_true")]
    pub udp: bool,
    pub plugin: Option<String>,
    pub plugin_opts: Option<HashMap<String, serde_yaml::Value>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSocks5 {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub username: Option<String>,
    pub password: Option<String>,
    #[cfg(feature = "tls")]
    #[serde(default = "Default::default")]
    pub tls: bool,
    #[cfg(feature = "tls")]
    pub sni: Option<String>,
    #[cfg(feature = "tls")]
    #[serde(default = "Default::default")]
    pub skip_cert_verify: bool,
    #[serde(default = "default_bool_true")]
    pub udp: bool,
}

#[cfg(feature = "anytls")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundAnytls {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub skip_cert_verify: Option<bool>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub fingerprint: Option<String>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub client_fingerprint: Option<String>,
    pub udp: Option<bool>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub idle_session_check_interval: Option<u64>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub idle_session_timeout: Option<u64>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub min_idle_session: Option<u64>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    pub tls_key: Option<String>,
}

pub fn map_serde_error(
    name: String,
) -> impl FnOnce(serde_yaml::Error) -> crate::Error {
    move |x| {
        if let Some(loc) = x.location() {
            Error::InvalidConfig(format!(
                "invalid config for {} at line {}, column {} while parsing {}",
                name,
                loc.line(),
                loc.column(),
                name
            ))
        } else {
            Error::InvalidConfig(format!("error while parsing  {name}: {x}"))
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CommonConfigOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// this can be a proxy name or a group name
    /// can't be a name in a proxy provider
    /// only applies to raw proxy, i.e. applying this to a proxy group does
    /// nothing
    #[serde(alias = "dialer-proxy")]
    pub connect_via: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub struct WsOpt {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub max_early_data: Option<i32>,
    pub early_data_header_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub struct H2Opt {
    pub host: Option<Vec<String>>,
    pub path: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub struct GrpcOpt {
    pub grpc_service_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct XhttpDownloadTlsSettings {
    #[serde(alias = "serverName")]
    pub server_name: Option<String>,
    #[serde(alias = "allowInsecure")]
    pub insecure: Option<bool>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct XhttpDownloadXhttpSettings {
    pub path: Option<String>,
    pub host: Option<Vec<String>>,
    pub headers: Option<HashMap<String, String>>,
    pub mode: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct XhttpExtra {
    pub headers: Option<HashMap<String, String>>,
    #[serde(alias = "downloadSettings")]
    pub download_settings: Option<XhttpDownloadSettings>,
    #[serde(alias = "noGRPCHeader")]
    pub no_grpc_header: Option<bool>,
    #[serde(alias = "scMaxEachPostBytes")]
    pub sc_max_each_post_bytes: Option<usize>,
    #[serde(alias = "scMinPostsIntervalMs")]
    pub sc_min_posts_interval_ms: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct XhttpDownloadSettings {
    pub address: String,
    pub port: u16,
    pub network: String,
    pub security: Option<String>,
    #[serde(alias = "servername", alias = "serverName")]
    pub server_name: Option<String>,
    pub sni: Option<String>,
    #[serde(alias = "tlsSettings")]
    pub tls_settings: Option<XhttpDownloadTlsSettings>,
    #[serde(alias = "xhttpSettings")]
    pub xhttp_settings: Option<XhttpDownloadXhttpSettings>,
}

pub type XhttpUploadSettings = XhttpDownloadSettings;

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct XhttpOpt {
    pub path: Option<String>,
    pub mode: Option<String>,
    pub host: Option<Vec<String>>,
    pub headers: Option<HashMap<String, String>>,
    pub extra: Option<XhttpExtra>,
    #[serde(alias = "uploadSettings")]
    pub upload_settings: Option<XhttpUploadSettings>,
    #[serde(alias = "downloadSettings")]
    pub download_settings: Option<XhttpDownloadSettings>,
    pub download_mode: Option<String>,
    pub upload_mode: Option<String>,
    pub max_each_post_bytes: Option<usize>,
    pub max_buffered_posts: Option<usize>,
    pub session_ttl: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundVless {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub uuid: String,
    pub udp: Option<bool>,
    pub tls: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    #[serde(alias = "servername", alias = "serverName")]
    pub server_name: Option<String>,
    pub sni: Option<String>,
    pub network: Option<String>,
    #[serde(alias = "xhttpOpts")]
    pub xhttp_opts: Option<XhttpOpt>,
    #[cfg(feature = "ws")]
    pub ws_opts: Option<WsOpt>,
    #[serde(alias = "realityOpts")]
    pub reality_opts: Option<OutboundTrojanRealityOpts>,
    pub flow: Option<String>,
    #[serde(alias = "fingerprint")]
    pub client_fingerprint: Option<String>,
}

#[cfg(feature = "wireguard")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundWireguard {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub private_key: String,
    pub public_key: String,
    #[serde(alias = "preshared-key")]
    pub pre_shared_key: Option<String>,
    pub mtu: Option<u16>,
    pub udp: Option<bool>,
    pub ip: String,
    pub ipv6: Option<String>,
    pub remote_dns_resolve: Option<bool>,
    pub dns: Option<Vec<String>>,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum OutboundGroupProtocol {
    #[serde(rename = "url-test")]
    UrlTest(OutboundGroupUrlTest),
    #[serde(rename = "fallback")]
    Fallback(OutboundGroupFallback),
    #[serde(rename = "relay")]
    Relay(OutboundGroupRelay),
    #[serde(rename = "select")]
    Select(OutboundGroupSelect),
}

/// Only used statically in config parsing.
/// Runtime access is done via the `try_as_group_handler`.
impl OutboundGroupProtocol {
    /// Returns the name of the group.
    pub fn name(&self) -> &str {
        match &self {
            OutboundGroupProtocol::UrlTest(g) => &g.name,
            OutboundGroupProtocol::Fallback(g) => &g.name,
            OutboundGroupProtocol::Relay(g) => &g.name,
            /* OutboundGroupProtocol::LoadBalance(g) => &g.name,
            OutboundGroupProtocol::Smart(g) => &g.name, */
            OutboundGroupProtocol::Select(g) => &g.name,
        }
    }

    /// Returns the proxies in the group, if any.
    pub fn proxies(&self) -> Option<&Vec<String>> {
        match &self {
            OutboundGroupProtocol::Relay(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Select(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::UrlTest(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Fallback(g) => g.proxies.as_ref(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupUrlTest {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub tolerance: Option<u16>,
    pub icon: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupFallback {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub icon: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupSelect {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,
    pub udp: Option<bool>,

    pub url: Option<String>,
    pub icon: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupRelay {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: Option<String>,
    pub icon: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum OutboundProxyProviderDef {
    Http(OutboundHttpProvider),
    File(OutboundFileProvider),
}

impl OutboundProxyProviderDef {
    pub fn set_name(&mut self, name: String) {
        match self {
            OutboundProxyProviderDef::Http(p) => p.name = name,
            OutboundProxyProviderDef::File(p) => p.name = name,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHttpProvider {
    #[serde(skip)]
    pub name: String,
    pub url: String,
    pub interval: u64,
    pub path: String,
    pub health_check: HealthCheck,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundFileProvider {
    #[serde(skip)]
    pub name: String,
    pub path: String,
    pub interval: Option<u64>,
    #[serde(default)]
    pub health_check: HealthCheck,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct HealthCheck {
    pub enable: Option<bool>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub lazy: Option<bool>,
    #[serde(rename = "type", default)]
    pub probe: HealthCheckProbe,
    pub minimum_bytes: Option<usize>,
    pub minimum_events: Option<usize>,
    pub maximum_first_byte_ms: Option<u64>,
    pub expect_echo: Option<String>,
    pub timeout: Option<u64>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq,
)]
#[serde(rename_all = "kebab-case")]
pub enum HealthCheckProbe {
    #[default]
    Http,
    Download,
    Sse,
    Websocket,
}

#[cfg(feature = "trojan")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTrojan {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub udp: Option<bool>,
    pub network: Option<String>,
    // pub grpc_opts: Option<GrpcOpt>,
    #[cfg(feature = "ws")]
    pub ws_opts: Option<WsOpt>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTrojanRealityOpts {
    #[serde(alias = "publicKey")]
    pub public_key: String,
    #[serde(alias = "shortId")]
    pub short_id: Option<String>,
}

#[cfg(feature = "hysteria")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHysteria2 {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub ports: Option<String>,
    pub password: String,
    pub obfs: Option<Hysteria2Obfs>,
    pub obfs_password: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub up: Option<u64>,
    pub down: Option<u64>,
    pub sni: Option<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    pub ca: Option<String>,
    pub ca_str: Option<String>,
    pub fingerprint: Option<String>,
    pub udp_mtu: Option<u32>,
    pub disable_mtu_discovery: Option<bool>,
    pub cwnd: Option<u64>,
}

#[cfg(feature = "hysteria")]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Hysteria2Obfs {
    Salamander,
}

#[cfg(test)]
mod tests {
    use super::{HealthCheck, HealthCheckProbe, OutboundProxyProtocol};

    #[test]
    fn download_health_check_config_parses() {
        let health: HealthCheck = serde_yaml::from_str(
            r#"
enable: true
url: https://probe.example/64k.bin
interval: 300
timeout: 10
type: download
minimum-bytes: 65536
"#,
        )
        .expect("health check config should parse");

        assert_eq!(health.probe, HealthCheckProbe::Download);
        assert_eq!(health.minimum_bytes, Some(65_536));
        assert_eq!(health.timeout, Some(10));
    }

    #[test]
    fn streaming_health_check_configs_parse() {
        let sse: HealthCheck = serde_yaml::from_str(
            "type: sse\nminimum-events: 3\nmaximum-first-byte-ms: 3000",
        )
        .unwrap();
        assert_eq!(sse.probe, HealthCheckProbe::Sse);
        assert_eq!(sse.minimum_events, Some(3));
        assert_eq!(sse.maximum_first_byte_ms, Some(3000));

        let websocket: HealthCheck =
            serde_yaml::from_str("type: websocket\nexpect-echo: chimera-health")
                .unwrap();
        assert_eq!(websocket.probe, HealthCheckProbe::Websocket);
        assert_eq!(websocket.expect_echo.as_deref(), Some("chimera-health"));
    }

    #[test]
    fn outbound_vless_parses_xhttp_opts() {
        let config = r#"
name: xhttp-demo
type: vless
server: 127.0.0.1
port: 3000
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
network: xhttp
xhttp-opts:
  path: /xhttp/
  mode: split
  extra:
    headers:
      X-Test-Extra: enabled
    no-grpc-header: true
    sc-max-each-post-bytes: 2048
    download-settings:
      address: extra-download.example.com
      port: 7443
      network: xhttp
      security: tls
      xhttp-settings:
        path: /extra-download/
  upload-settings:
    address: upload.example.com
    port: 9443
    network: xhttp
    security: tls
    xhttp-settings:
      path: /upload/
  download-settings:
    address: download.example.com
    port: 8443
    network: xhttp
    security: tls
    xhttp-settings:
      path: /download/
  download-mode: stream-down
  upload-mode: packet-up
  max-each-post-bytes: 1000000
  max-buffered-posts: 30
  session-ttl: 30
"#;

        let parsed: OutboundProxyProtocol =
            serde_yaml::from_str(config).expect("xhttp config should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };

        assert_eq!(vless.network.as_deref(), Some("xhttp"));
        let opts = vless.xhttp_opts.expect("xhttp_opts should be present");
        assert_eq!(opts.path.as_deref(), Some("/xhttp/"));
        let extra = opts.extra.expect("xhttp extra should be present");
        assert_eq!(
            extra
                .headers
                .as_ref()
                .and_then(|headers| headers.get("X-Test-Extra")),
            Some(&"enabled".to_owned())
        );
        assert_eq!(extra.no_grpc_header, Some(true));
        assert_eq!(extra.sc_max_each_post_bytes, Some(2048));
        assert_eq!(
            extra
                .download_settings
                .as_ref()
                .map(|settings| settings.address.as_str()),
            Some("extra-download.example.com")
        );
        let upload = opts
            .upload_settings
            .expect("upload_settings should be present");
        assert_eq!(upload.address, "upload.example.com");
        assert_eq!(upload.port, 9443);
        assert_eq!(upload.network, "xhttp");
        assert_eq!(upload.security.as_deref(), Some("tls"));
        assert_eq!(
            upload
                .xhttp_settings
                .and_then(|settings| settings.path)
                .as_deref(),
            Some("/upload/")
        );
        let download = opts
            .download_settings
            .expect("download_settings should be present");
        assert_eq!(download.address, "download.example.com");
        assert_eq!(download.port, 8443);
        assert_eq!(download.network, "xhttp");
        assert_eq!(download.security.as_deref(), Some("tls"));
        assert_eq!(
            download
                .xhttp_settings
                .and_then(|settings| settings.path)
                .as_deref(),
            Some("/download/")
        );
        assert_eq!(opts.mode.as_deref(), Some("split"));
        assert_eq!(opts.download_mode.as_deref(), Some("stream-down"));
        assert_eq!(opts.upload_mode.as_deref(), Some("packet-up"));
        assert_eq!(opts.max_each_post_bytes, Some(1_000_000));
        assert_eq!(opts.max_buffered_posts, Some(30));
        assert_eq!(opts.session_ttl, Some(30));
    }
}

#[cfg(all(test, feature = "wireguard"))]
mod wireguard_tests {
    use super::{
        OutboundProxyProtocol, OutboundProxyProviderDef, OutboundWireguard,
    };

    const PRE_SHARED_KEY: &str = "+JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc=";

    fn wireguard_yaml(pre_shared_key_field: Option<&str>) -> String {
        let pre_shared_key = pre_shared_key_field
            .map(|field| format!("{field}: {PRE_SHARED_KEY}\n"))
            .unwrap_or_default();
        format!(
            r#"
name: wg-test
type: wireguard
server: example.com
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
{pre_shared_key}ip: 10.0.0.2/32
"#
        )
    }

    #[test]
    fn wireguard_file_provider_accepts_clash_type_tag() {
        let provider: OutboundProxyProviderDef =
            serde_yaml::from_str("type: file\npath: wireguard-proxies.yaml\n")
                .expect("wireguard file provider should parse with type: file");

        assert!(matches!(provider, OutboundProxyProviderDef::File(_)));
    }

    #[test]
    fn wireguard_parses_standard_pre_shared_key() {
        let config: OutboundWireguard =
            serde_yaml::from_str(&wireguard_yaml(Some("pre-shared-key")))
                .expect("should parse with pre-shared-key");
        assert_eq!(config.pre_shared_key.as_deref(), Some(PRE_SHARED_KEY));
    }

    #[test]
    fn wireguard_parses_legacy_preshared_key_alias() {
        let config: OutboundWireguard =
            serde_yaml::from_str(&wireguard_yaml(Some("preshared-key")))
                .expect("should parse with preshared-key legacy alias");
        assert_eq!(config.pre_shared_key.as_deref(), Some(PRE_SHARED_KEY));
    }

    #[test]
    fn wireguard_pre_shared_key_is_optional() {
        let config: OutboundWireguard = serde_yaml::from_str(&wireguard_yaml(None))
            .expect("should parse without pre-shared-key");
        assert!(config.pre_shared_key.is_none());
    }

    #[test]
    fn wireguard_protocol_variant_exposes_name() {
        let config: OutboundProxyProtocol =
            serde_yaml::from_str(&wireguard_yaml(None))
                .expect("should parse wireguard");
        assert_eq!(config.name(), "wg-test");
        assert_eq!(config.to_string(), "Wireguard");
        assert!(matches!(config, OutboundProxyProtocol::Wireguard(_)));
    }
}

#[cfg(all(test, feature = "anytls"))]
mod anytls_tests {
    use super::{OutboundProxyProtocol, OutboundProxyProtocol::Anytls};

    #[test]
    fn test_anytls_deserialize() {
        let yaml = r#"
            name: anytls-test
            type: anytls
            server: example.com
            port: 443
            password: example-password
            sni: sni.example.com
            skip-cert-verify: true
            udp: true
            idle-session-check-interval: 30
            idle-session-timeout: 300
            min-idle-session: 2
        "#;

        let config: OutboundProxyProtocol =
            serde_yaml::from_str(yaml).expect("should parse anytls");

        let Anytls(config) = config else {
            panic!("expected anytls config");
        };

        assert_eq!(config.common_opts.name, "anytls-test");
        assert_eq!(config.common_opts.server, "example.com");
        assert_eq!(config.common_opts.port, 443);
        assert_eq!(config.password, "example-password");
        assert_eq!(config.sni.as_deref(), Some("sni.example.com"));
        assert_eq!(config.skip_cert_verify, Some(true));
        assert_eq!(config.udp, Some(true));
        assert_eq!(config.idle_session_check_interval, Some(30));
        assert_eq!(config.idle_session_timeout, Some(300));
        assert_eq!(config.min_idle_session, Some(2));
    }
}
