use std::collections::HashMap;

use serde::{Deserialize, de::value::MapDeserializer};
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
}

impl OutboundProxyProtocol {
    fn name(&self) -> &str {
        match &self {
            OutboundProxyProtocol::Direct(direct) => &direct.name,
            OutboundProxyProtocol::Reject(reject) => &reject.name,
            OutboundProxyProtocol::Socks5(socks5) => {
                todo!()
            }
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
    #[serde(default = "Default::default")]
    pub tls: bool,
    pub sni: Option<String>,
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
            Error::InvalidConfig(format!("error while parsing {name}: {x}"))
        }
    }
}


#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum OutboundGroupProtocol {}