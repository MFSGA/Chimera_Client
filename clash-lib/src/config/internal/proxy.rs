use std::collections::HashMap;

use serde::{de::value::MapDeserializer, Deserialize};
use serde_yaml::Value;

use crate::Error;

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
            OutboundProxy::ProxyGroup(g) => todo!(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum OutboundProxyProtocol {
    #[serde(rename = "direct")]
    Direct(OutboundDirect),
    #[serde(rename = "reject")]
    Reject(OutboundReject),
    #[serde(rename = "socks5")]
    Socks5(OutboundSocks5),

    #[serde(rename = "vless")]
    Vless(OutboundVless),
    #[cfg(feature = "trojan")]
    #[serde(rename = "trojan")]
    Trojan(OutboundTrojan),
    #[cfg(feature = "hysteria")]
    #[serde(rename = "hysteria2")]
    Hysteria2(OutboundHysteria2),
}

impl OutboundProxyProtocol {
    fn name(&self) -> &str {
        match &self {
            OutboundProxyProtocol::Direct(direct) => &direct.name,
            OutboundProxyProtocol::Reject(reject) => &reject.name,
            OutboundProxyProtocol::Socks5(socks5) => {
                todo!()
            }
            OutboundProxyProtocol::Vless(vless) => &vless.common_opts.name,
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
        println!("parsing proxy protocol for {name}");
        OutboundProxyProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
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

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSocks5 {
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
}

pub fn map_serde_error(name: String) -> impl FnOnce(serde_yaml::Error) -> crate::Error {
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
pub struct WsOpt {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub max_early_data: Option<i32>,
    pub early_data_header_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct H2Opt {
    pub host: Option<Vec<String>>,
    pub path: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcOpt {
    pub grpc_service_name: Option<String>,
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
    #[serde(alias = "servername", alias = "serverName", alias = "sni")]
    pub server_name: Option<String>,
    #[serde(alias = "fingerprint")]
    pub client_fingerprint: Option<String>,
    pub network: Option<String>,
    pub ws_opts: Option<WsOpt>,
    pub h2_opts: Option<H2Opt>,
    pub grpc_opts: Option<GrpcOpt>,
    #[serde(alias = "realityOpts")]
    pub reality_opts: Option<OutboundTrojanRealityOpts>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum OutboundGroupProtocol {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum OutboundProxyProviderDef {}

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

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
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
