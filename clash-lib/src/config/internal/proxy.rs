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

fn deserialize_optional_string_or_integer<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum StringOrInteger {
        String(String),
        Integer(u64),
    }

    Ok(Option::<StringOrInteger>::deserialize(deserializer)?.map(
        |value| match value {
            StringOrInteger::String(value) => value,
            StringOrInteger::Integer(value) => value.to_string(),
        },
    ))
}

fn deserialize_optional_string_or_signed_integer<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum StringOrInteger {
        String(String),
        Integer(i64),
    }

    Ok(Option::<StringOrInteger>::deserialize(deserializer)?.map(
        |value| match value {
            StringOrInteger::String(value) => value,
            StringOrInteger::Integer(value) => value.to_string(),
        },
    ))
}

fn deserialize_optional_string_or_singleton_vec<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    match Option::<StringOrVec>::deserialize(deserializer)? {
        None => Ok(None),
        Some(StringOrVec::String(value)) => Ok(Some(value)),
        Some(StringOrVec::Vec(values)) => match values.as_slice() {
            [] => Ok(None),
            [value] => Ok(Some(value.clone())),
            _ => Err(serde::de::Error::custom(
                "xhttp host accepts a string or a single-element sequence",
            )),
        },
    }
}

#[cfg(feature = "wireguard")]
fn deserialize_optional_wireguard_reserved<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum ReservedValue {
        Bytes(Vec<u8>),
        Base64(String),
    }

    let value = Option::<ReservedValue>::deserialize(deserializer)?;
    let bytes = match value {
        None => return Ok(None),
        Some(ReservedValue::Bytes(bytes)) => bytes,
        Some(ReservedValue::Base64(value)) => {
            STANDARD.decode(value.trim()).map_err(|err| {
                serde::de::Error::custom(format!(
                    "invalid WireGuard reserved base64: {err}"
                ))
            })?
        }
    };

    if bytes.len() != 3 {
        return Err(serde::de::Error::custom(format!(
            "WireGuard reserved must contain exactly 3 bytes, got {}",
            bytes.len()
        )));
    }

    Ok(Some(bytes))
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
    pub v2ray_http_upgrade: Option<bool>,
    pub v2ray_http_upgrade_fast_open: Option<bool>,
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
    pub grpc_user_agent: Option<String>,
    pub ping_interval: Option<u64>,
    pub max_connections: Option<u64>,
    pub min_streams: Option<u64>,
    pub max_streams: Option<u64>,
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
pub struct XhttpReuseSettings {
    #[serde(default, deserialize_with = "deserialize_optional_string_or_integer")]
    pub max_concurrency: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_integer")]
    pub max_connections: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_integer")]
    pub c_max_reuse_times: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_integer")]
    pub h_max_request_times: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_integer")]
    pub h_max_reusable_secs: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_signed_integer"
    )]
    pub h_keep_alive_period: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct XhttpDownloadXhttpSettings {
    pub path: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_singleton_vec"
    )]
    pub host: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub mode: Option<String>,
    pub reuse_settings: Option<XhttpReuseSettings>,
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

fn default_xhttp_network() -> String {
    "xhttp".to_owned()
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct XhttpDownloadSettings {
    #[serde(default, alias = "server")]
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default = "default_xhttp_network")]
    pub network: String,
    pub security: Option<String>,
    pub tls: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: Option<bool>,
    pub name_cert_verify: Option<String>,
    pub fingerprint: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub client_fingerprint: Option<String>,
    #[serde(alias = "echOpts")]
    pub ech_opts: Option<EchOptions>,
    pub reality_opts: Option<OutboundTrojanRealityOpts>,
    #[serde(alias = "servername", alias = "serverName")]
    pub server_name: Option<String>,
    pub sni: Option<String>,
    pub path: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_singleton_vec"
    )]
    pub host: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub reuse_settings: Option<XhttpReuseSettings>,
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
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_singleton_vec"
    )]
    pub host: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    #[serde(alias = "noGRPCHeader")]
    pub no_grpc_header: Option<bool>,
    pub sc_max_each_post_bytes: Option<usize>,
    pub sc_min_posts_interval_ms: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_integer")]
    pub x_padding_bytes: Option<String>,
    pub x_padding_obfs_mode: Option<bool>,
    pub x_padding_key: Option<String>,
    pub x_padding_header: Option<String>,
    pub x_padding_placement: Option<String>,
    pub x_padding_method: Option<String>,
    pub reuse_settings: Option<XhttpReuseSettings>,
    pub extra: Option<XhttpExtra>,
    #[serde(alias = "uploadSettings")]
    pub upload_settings: Option<XhttpUploadSettings>,
    #[serde(alias = "downloadSettings")]
    pub download_settings: Option<XhttpDownloadSettings>,
    pub download_mode: Option<String>,
    pub upload_mode: Option<String>,
    pub session_placement: Option<String>,
    pub session_key: Option<String>,
    pub session_table: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_integer")]
    pub session_length: Option<String>,
    pub seq_placement: Option<String>,
    pub seq_key: Option<String>,
    pub uplink_http_method: Option<String>,
    pub uplink_data_placement: Option<String>,
    pub uplink_data_key: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_integer")]
    pub uplink_chunk_size: Option<String>,
    pub max_each_post_bytes: Option<usize>,
    pub max_buffered_posts: Option<usize>,
    pub session_ttl: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct EchOptions {
    pub enable: Option<bool>,
    pub config: Option<String>,
    pub query_server_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ShadowTlsOptions {
    pub version: Option<u8>,
    pub password: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RestlsOptions {
    pub password: Option<String>,
    pub version_hint: Option<String>,
    pub restls_script: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct JlsOptions {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundVless {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub uuid: String,
    pub udp: Option<bool>,
    pub tls: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: Option<bool>,
    pub name_cert_verify: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    #[serde(alias = "servername", alias = "serverName")]
    pub server_name: Option<String>,
    pub sni: Option<String>,
    pub network: Option<String>,
    #[serde(alias = "xhttpOpts")]
    pub xhttp_opts: Option<XhttpOpt>,
    #[cfg(feature = "ws")]
    pub ws_opts: Option<WsOpt>,
    pub grpc_opts: Option<GrpcOpt>,
    #[serde(alias = "realityOpts")]
    pub reality_opts: Option<OutboundTrojanRealityOpts>,
    pub flow: Option<String>,
    pub encryption: Option<String>,
    /// TLS certificate SHA-256 fingerprint pin.
    pub fingerprint: Option<String>,
    /// TLS ClientHello/uTLS-style fingerprint selection.
    pub client_fingerprint: Option<String>,
    #[serde(alias = "echOpts")]
    pub ech_opts: Option<EchOptions>,
    #[serde(alias = "shadowTlsOpts")]
    pub shadow_tls_opts: Option<ShadowTlsOptions>,
    #[serde(alias = "restlsOpts")]
    pub restls_opts: Option<RestlsOptions>,
    #[serde(alias = "jlsOpts")]
    pub jls_opts: Option<JlsOptions>,
}

#[cfg(feature = "wireguard")]
#[derive(serde::Serialize, Debug, Default, Clone)]
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
    #[serde(
        rename = "reserved",
        alias = "reserved-bits",
        default,
        deserialize_with = "deserialize_optional_wireguard_reserved"
    )]
    pub reserved_bits: Option<Vec<u8>>,
    pub persistent_keepalive: Option<u16>,
}

#[cfg(feature = "wireguard")]
impl<'de> serde::Deserialize<'de> for OutboundWireguard {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct RawWireguard {
            name: Option<String>,
            server: Option<String>,
            port: Option<u16>,
            #[serde(alias = "dialer-proxy")]
            connect_via: Option<String>,
            private_key: Option<String>,
            public_key: Option<String>,
            #[serde(alias = "preshared-key")]
            pre_shared_key: Option<String>,
            mtu: Option<u16>,
            udp: Option<bool>,
            ip: Option<String>,
            ipv6: Option<String>,
            remote_dns_resolve: Option<bool>,
            dns: Option<Vec<String>>,
            allowed_ips: Option<Vec<String>>,
            #[serde(
                rename = "reserved",
                alias = "reserved-bits",
                default,
                deserialize_with = "deserialize_optional_wireguard_reserved"
            )]
            reserved_bits: Option<Vec<u8>>,
            persistent_keepalive: Option<u16>,
            #[serde(flatten)]
            extra: HashMap<String, Value>,
        }

        let raw = RawWireguard::deserialize(deserializer)?;
        for (field, message) in [
            (
                "peers",
                "WireGuard multi-peer configuration (peers) is not supported",
            ),
            (
                "ip-stack",
                "WireGuard ip-stack is not supported; Chimera uses its built-in WireGuard IP stack",
            ),
            (
                "amnezia-wg-option",
                "AmneziaWG (amnezia-wg-option) is not supported",
            ),
        ] {
            if raw.extra.contains_key(field) {
                return Err(serde::de::Error::custom(message));
            }
        }

        let required = |value: Option<String>, field: &str| {
            value.ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "missing required WireGuard field `{field}`"
                ))
            })
        };

        Ok(Self {
            common_opts: CommonConfigOptions {
                name: required(raw.name, "name")?,
                server: required(raw.server, "server")?,
                port: raw.port.ok_or_else(|| {
                    serde::de::Error::custom(
                        "missing required WireGuard field `port`",
                    )
                })?,
                connect_via: raw.connect_via,
            },
            private_key: required(raw.private_key, "private-key")?,
            public_key: required(raw.public_key, "public-key")?,
            pre_shared_key: raw.pre_shared_key,
            mtu: raw.mtu,
            udp: raw.udp,
            ip: required(raw.ip, "ip")?,
            ipv6: raw.ipv6,
            remote_dns_resolve: raw.remote_dns_resolve,
            dns: raw.dns,
            allowed_ips: raw.allowed_ips,
            reserved_bits: raw.reserved_bits,
            persistent_keepalive: raw.persistent_keepalive,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum OutboundGroupProtocol {
    #[serde(rename = "url-test")]
    UrlTest(OutboundGroupUrlTest),
    #[serde(rename = "fallback")]
    Fallback(OutboundGroupFallback),
    #[serde(rename = "load-balance")]
    LoadBalance(OutboundGroupLoadBalance),
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
            OutboundGroupProtocol::LoadBalance(g) => &g.name,
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
            OutboundGroupProtocol::LoadBalance(g) => g.proxies.as_ref(),
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
pub struct OutboundGroupLoadBalance {
    pub name: String,
    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,
    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub udp: Option<bool>,
    #[serde(default)]
    pub strategy: LoadBalanceStrategy,
    pub icon: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, Default)]
pub enum LoadBalanceStrategy {
    #[default]
    #[serde(rename = "round-robin")]
    RoundRobin,
    #[serde(rename = "consistent-hashing")]
    ConsistentHashing,
    #[serde(rename = "sticky-session")]
    StickySession,
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
    pub name_cert_verify: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    /// TLS certificate SHA-256 fingerprint pin.
    pub fingerprint: Option<String>,
    /// TLS ClientHello/uTLS-style fingerprint selection.
    pub client_fingerprint: Option<String>,
    pub udp: Option<bool>,
    pub network: Option<String>,
    pub grpc_opts: Option<GrpcOpt>,
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
    #[serde(alias = "supportX25519MLKEM768")]
    pub support_x25519mlkem768: Option<bool>,
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
  no-grpc-header: false
  sc-max-each-post-bytes: 4096
  sc-min-posts-interval-ms: 45
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
    ech-opts:
      enable: true
      config: upload-ech
    xhttp-settings:
      path: /upload/
  download-settings:
    address: download.example.com
    port: 8443
    network: xhttp
    security: tls
    ech-opts:
      enable: false
    xhttp-settings:
      path: /download/
  download-mode: stream-down
  upload-mode: packet-up
  session-placement: query
  session-key: auth
  session-table: Base62
  session-length: "10"
  seq-placement: header
  seq-key: X-Seq
  x-padding-bytes: "120-180"
  x-padding-obfs-mode: true
  x-padding-key: pad
  x-padding-header: X-Pad
  x-padding-placement: header
  x-padding-method: tokenish
  uplink-http-method: PUT
  uplink-data-placement: header
  uplink-data-key: X-Payload
  uplink-chunk-size: "128-256"
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
        assert_eq!(opts.no_grpc_header, Some(false));
        assert_eq!(opts.sc_max_each_post_bytes, Some(4096));
        assert_eq!(opts.sc_min_posts_interval_ms, Some(45));
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
            upload.ech_opts.as_ref().and_then(|opts| opts.enable),
            Some(true)
        );
        assert_eq!(
            upload
                .ech_opts
                .as_ref()
                .and_then(|opts| opts.config.as_deref()),
            Some("upload-ech")
        );
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
            download.ech_opts.as_ref().and_then(|opts| opts.enable),
            Some(false)
        );
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
        assert_eq!(opts.session_placement.as_deref(), Some("query"));
        assert_eq!(opts.session_key.as_deref(), Some("auth"));
        assert_eq!(opts.session_table.as_deref(), Some("Base62"));
        assert_eq!(opts.session_length.as_deref(), Some("10"));
        assert_eq!(opts.seq_placement.as_deref(), Some("header"));
        assert_eq!(opts.seq_key.as_deref(), Some("X-Seq"));
        assert_eq!(opts.x_padding_bytes.as_deref(), Some("120-180"));
        assert_eq!(opts.x_padding_obfs_mode, Some(true));
        assert_eq!(opts.x_padding_key.as_deref(), Some("pad"));
        assert_eq!(opts.x_padding_header.as_deref(), Some("X-Pad"));
        assert_eq!(opts.x_padding_placement.as_deref(), Some("header"));
        assert_eq!(opts.x_padding_method.as_deref(), Some("tokenish"));
        assert_eq!(opts.uplink_http_method.as_deref(), Some("PUT"));
        assert_eq!(opts.uplink_data_placement.as_deref(), Some("header"));
        assert_eq!(opts.uplink_data_key.as_deref(), Some("X-Payload"));
        assert_eq!(opts.uplink_chunk_size.as_deref(), Some("128-256"));
        assert_eq!(opts.max_each_post_bytes, Some(1_000_000));
        assert_eq!(opts.max_buffered_posts, Some(30));
        assert_eq!(opts.session_ttl, Some(30));
    }

    #[test]
    fn outbound_vless_xhttp_parses_reuse_settings() {
        let config = r#"
name: xhttp-reuse
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
network: xhttp
xhttp-opts:
  reuse-settings:
    max-concurrency: "16-32"
    c-max-reuse-times: 0
    h-max-request-times: "600-900"
    h-max-reusable-secs: "1800-3000"
    h-keep-alive-period: -1
  download-settings:
    address: download.example.com
    port: 443
    network: xhttp
    security: tls
    xhttp-settings:
      reuse-settings:
        max-connections: 4
"#;

        let parsed: OutboundProxyProtocol =
            serde_yaml::from_str(config).expect("xhttp reuse settings should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };
        let opts = vless.xhttp_opts.expect("xhttp opts should be present");
        let reuse = opts
            .reuse_settings
            .expect("uplink reuse settings should be present");
        assert_eq!(reuse.max_concurrency.as_deref(), Some("16-32"));
        assert_eq!(reuse.c_max_reuse_times.as_deref(), Some("0"));
        assert_eq!(reuse.h_max_request_times.as_deref(), Some("600-900"));
        assert_eq!(reuse.h_max_reusable_secs.as_deref(), Some("1800-3000"));
        assert_eq!(reuse.h_keep_alive_period.as_deref(), Some("-1"));

        let download_reuse = opts
            .download_settings
            .and_then(|settings| settings.xhttp_settings)
            .and_then(|settings| settings.reuse_settings)
            .expect("download reuse settings should be present");
        assert_eq!(download_reuse.max_connections.as_deref(), Some("4"));
    }

    #[test]
    fn outbound_vless_xhttp_accepts_integer_session_length() {
        let config = r#"
name: xhttp-session
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
network: xhttp
xhttp-opts:
  session-table: Base62
  session-length: 10
"#;

        let parsed: OutboundProxyProtocol = serde_yaml::from_str(config)
            .expect("numeric session-length should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };

        assert_eq!(
            vless
                .xhttp_opts
                .and_then(|opts| opts.session_length)
                .as_deref(),
            Some("10")
        );
    }

    #[test]
    fn outbound_vless_xhttp_accepts_integer_padding_bytes() {
        let config = r#"
name: xhttp-padding
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
network: xhttp
xhttp-opts:
  x-padding-bytes: 256
"#;

        let parsed: OutboundProxyProtocol = serde_yaml::from_str(config)
            .expect("numeric x-padding-bytes should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };

        assert_eq!(
            vless
                .xhttp_opts
                .and_then(|opts| opts.x_padding_bytes)
                .as_deref(),
            Some("256")
        );
    }

    #[test]
    fn outbound_vless_xhttp_accepts_integer_uplink_chunk_size() {
        let config = r#"
name: xhttp-uplink
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
network: xhttp
xhttp-opts:
  mode: packet-up
  uplink-data-placement: cookie
  uplink-chunk-size: 3072
"#;

        let parsed: OutboundProxyProtocol = serde_yaml::from_str(config)
            .expect("numeric uplink chunk size should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };

        assert_eq!(
            vless
                .xhttp_opts
                .and_then(|opts| opts.uplink_chunk_size)
                .as_deref(),
            Some("3072")
        );
    }

    #[test]
    fn outbound_vless_parses_grpc_opts() {
        let config = r#"
name: grpc-demo
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
network: grpc
grpc-opts:
  grpc-service-name: grpc-service
  grpc-user-agent: chimera-test/1.0
  ping-interval: 30
  max-connections: 2
  min-streams: 4
"#;

        let parsed: OutboundProxyProtocol =
            serde_yaml::from_str(config).expect("grpc vless config should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };

        assert_eq!(vless.network.as_deref(), Some("grpc"));
        let grpc = vless.grpc_opts.expect("grpc opts should be present");
        assert_eq!(grpc.grpc_service_name.as_deref(), Some("grpc-service"));
        assert_eq!(grpc.grpc_user_agent.as_deref(), Some("chimera-test/1.0"));
        assert_eq!(grpc.ping_interval, Some(30));
        assert_eq!(grpc.max_connections, Some(2));
        assert_eq!(grpc.min_streams, Some(4));
        assert_eq!(grpc.max_streams, None);
    }

    #[test]
    fn outbound_vless_keeps_certificate_and_client_fingerprints_separate() {
        let config = r#"
name: vless-fingerprint
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
fingerprint: 0123456789abcdef
client-fingerprint: chrome
name-cert-verify: verify.example.com
certificate: client-cert.pem
private-key: client-key.pem
alpn:
  - h2
  - http/1.1
"#;

        let parsed: OutboundProxyProtocol = serde_yaml::from_str(config)
            .expect("vless fingerprint config should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };

        assert_eq!(vless.fingerprint.as_deref(), Some("0123456789abcdef"));
        assert_eq!(vless.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(
            vless.name_cert_verify.as_deref(),
            Some("verify.example.com")
        );
        assert_eq!(vless.certificate.as_deref(), Some("client-cert.pem"));
        assert_eq!(vless.private_key.as_deref(), Some("client-key.pem"));
        assert_eq!(
            vless.alpn,
            Some(vec!["h2".to_owned(), "http/1.1".to_owned()])
        );
    }

    #[test]
    fn outbound_vless_parses_extended_tls_option_blocks() {
        let config = r#"
name: vless-tls-options
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
tls: true
ech-opts:
  enable: true
  config: ech-config
  query-server-name: ech.example.com
shadow-tls-opts:
  version: 3
  password: shadow-secret
restls-opts:
  password: restls-secret
  version-hint: tls13
  restls-script: script-data
jls-opts:
  username: jls-user
  password: jls-secret
"#;

        let parsed: OutboundProxyProtocol = serde_yaml::from_str(config)
            .expect("extended TLS option blocks should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };
        let ech = vless.ech_opts.expect("ech opts should be present");
        assert_eq!(ech.enable, Some(true));
        assert_eq!(ech.config.as_deref(), Some("ech-config"));
        assert_eq!(ech.query_server_name.as_deref(), Some("ech.example.com"));
        let shadow = vless
            .shadow_tls_opts
            .expect("shadow tls opts should be present");
        assert_eq!(shadow.version, Some(3));
        assert_eq!(shadow.password.as_deref(), Some("shadow-secret"));
        let restls = vless.restls_opts.expect("restls opts should be present");
        assert_eq!(restls.password.as_deref(), Some("restls-secret"));
        assert_eq!(restls.version_hint.as_deref(), Some("tls13"));
        assert_eq!(restls.restls_script.as_deref(), Some("script-data"));
        let jls = vless.jls_opts.expect("jls opts should be present");
        assert_eq!(jls.username.as_deref(), Some("jls-user"));
        assert_eq!(jls.password.as_deref(), Some("jls-secret"));
    }

    #[test]
    fn outbound_vless_parses_encryption_and_reality_hybrid_flag() {
        let config = r#"
name: vless-reality-options
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
encryption: ""
reality-opts:
  public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
  short-id: ""
  support-x25519mlkem768: false
"#;

        let parsed: OutboundProxyProtocol = serde_yaml::from_str(config)
            .expect("vless encryption/reality options should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };

        assert_eq!(vless.encryption.as_deref(), Some(""));
        let reality = vless.reality_opts.expect("reality opts should be present");
        assert_eq!(reality.short_id.as_deref(), Some(""));
        assert_eq!(reality.support_x25519mlkem768, Some(false));
    }

    #[test]
    fn outbound_vless_xhttp_accepts_scalar_host() {
        let config = r#"
name: xhttp-host
type: vless
server: upload.example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
network: xhttp
xhttp-opts:
  host: upload-host.example.com
  download-settings:
    address: download.example.com
    port: 443
    network: xhttp
    xhttp-settings:
      host: download-host.example.com
"#;

        let parsed: OutboundProxyProtocol =
            serde_yaml::from_str(config).expect("scalar xhttp host should parse");

        let OutboundProxyProtocol::Vless(vless) = parsed else {
            panic!("expected vless proxy");
        };
        let opts = vless.xhttp_opts.expect("xhttp opts should be present");

        assert_eq!(opts.host.as_deref(), Some("upload-host.example.com"));
        assert_eq!(
            opts.download_settings
                .and_then(|settings| settings.xhttp_settings)
                .and_then(|settings| settings.host),
            Some("download-host.example.com".to_owned())
        );
    }

    #[test]
    fn outbound_vless_xhttp_rejects_multiple_host_values() {
        let config = r#"
name: xhttp-host-list
type: vless
server: upload.example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
network: xhttp
xhttp-opts:
  host:
    - upload-a.example.com
    - upload-b.example.com
"#;

        let err = serde_yaml::from_str::<OutboundProxyProtocol>(config)
            .expect_err("multiple xhttp host values must be rejected");
        assert!(err.to_string().contains("single-element sequence"));
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
{pre_shared_key}ip: 10.0.0.2
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
    fn wireguard_parses_reserved_array_and_keepalive() {
        let yaml = format!(
            "{}reserved: [209, 98, 59]\npersistent-keepalive: 25\n",
            wireguard_yaml(None)
        );
        let config: OutboundWireguard = serde_yaml::from_str(&yaml)
            .expect("WireGuard reserved array should parse");

        assert_eq!(config.reserved_bits.as_deref(), Some(&[209, 98, 59][..]));
        assert_eq!(config.persistent_keepalive, Some(25));
    }

    #[test]
    fn wireguard_parses_reserved_base64_and_legacy_alias() {
        let base64_yaml = format!("{}reserved: U4An\n", wireguard_yaml(None));
        let base64_config: OutboundWireguard = serde_yaml::from_str(&base64_yaml)
            .expect("WireGuard reserved base64 should parse");
        assert_eq!(
            base64_config.reserved_bits.as_deref(),
            Some(&[83, 128, 39][..])
        );

        let legacy_yaml =
            format!("{}reserved-bits: [1, 2, 3]\n", wireguard_yaml(None));
        let legacy_config: OutboundWireguard = serde_yaml::from_str(&legacy_yaml)
            .expect("legacy reserved-bits alias should parse");
        assert_eq!(legacy_config.reserved_bits.as_deref(), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn wireguard_rejects_invalid_reserved_values() {
        for suffix in ["reserved: [1, 2]\n", "reserved: not-base64!\n"] {
            let yaml = format!("{}{suffix}", wireguard_yaml(None));
            let err = serde_yaml::from_str::<OutboundWireguard>(&yaml)
                .expect_err("invalid reserved value must fail parsing");
            assert!(err.to_string().contains("reserved"));
        }
    }

    #[test]
    fn wireguard_rejects_multi_peer_with_explicit_error() {
        let err = serde_yaml::from_str::<OutboundWireguard>(
            r#"
name: wg-multi
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
ip: 10.0.0.2
peers:
  - server: 198.51.100.10
    port: 51820
    public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
    allowed-ips: [0.0.0.0/0]
"#,
        )
        .expect_err("multi-peer WireGuard must fail explicitly");

        assert!(err.to_string().contains("multi-peer"));
        assert!(
            !err.to_string()
                .contains("missing required WireGuard field `server`")
        );
    }

    #[test]
    fn wireguard_rejects_unsupported_ip_stack() {
        let yaml = format!(
            "{}ip-stack:\n  mode: mips\n  congestion-controller: cubic\n",
            wireguard_yaml(None)
        );
        let err = serde_yaml::from_str::<OutboundWireguard>(&yaml)
            .expect_err("ip-stack must fail explicitly");
        assert!(err.to_string().contains("ip-stack is not supported"));
    }

    #[test]
    fn wireguard_rejects_amnezia_options_explicitly() {
        let yaml = format!(
            "{}amnezia-wg-option:\n  version: 3\n  jc: 4\n",
            wireguard_yaml(None)
        );
        let err = serde_yaml::from_str::<OutboundWireguard>(&yaml)
            .expect_err("AmneziaWG options must fail explicitly");
        assert!(err.to_string().contains("AmneziaWG"));
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
