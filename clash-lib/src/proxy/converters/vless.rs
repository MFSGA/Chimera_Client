#[cfg(feature = "ws")]
use std::vec;

#[cfg(feature = "ws")]
use crate::proxy::transport::{RealityClient, WsClient, reality};
use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::{
        HandlerCommonOptions,
        transport::{TlsClient, Transport},
        vless::{Handler, HandlerOptions},
    },
};
use tracing::warn;

use base64::{Engine as _, engine::general_purpose};

impl TryFrom<OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVless) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVless) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let network = s.network.as_deref();
        let transport = build_transport(network, s)?;
        /* let tls: Option<Box<dyn Transport>> = if s.tls.unwrap_or_default() {
            let client = TlsClient::new(
                skip_cert_verify,
                tls_server_name(s),
                tls_alpn(network)?,
                None,
            );
            Some(Box::new(client))
        } else {
            None
        }; */

        let tls = None;
        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
            udp: s.udp.unwrap_or(true),
            transport,
            tls,
        }))
    }
}

fn build_transport(
    network: Option<&str>,
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    match network {
        Some("ws") => build_ws_transport(s),
        Some("tcp") => build_tcp_transport(s),
        Some(other) => Err(Error::InvalidConfig(format!(
            "unsupported network222: {other}"
        ))),
        None => Ok(None),
    }
}

#[cfg(feature = "ws")]
fn build_ws_transport(s: &OutboundVless) -> Result<Option<Box<dyn Transport>>, Error> {
    let opts = s.ws_opts.as_ref().ok_or(Error::InvalidConfig(
        "ws_opts is required for ws".to_owned(),
    ))?;
    let client = WsClient::new(
        s.common_opts.server.clone(),
        s.common_opts.port,
        opts.path.clone().unwrap_or_default(),
        opts.headers.clone().unwrap_or_default(),
        None,
        opts.max_early_data.unwrap_or_default() as usize,
        opts.early_data_header_name.clone().unwrap_or_default(),
    );
    Ok(Some(Box::new(client)))
}

#[cfg(feature = "ws")]
fn build_tcp_transport(s: &OutboundVless) -> Result<Option<Box<dyn Transport>>, Error> {
    tracing::debug!("todo must");
    let client = RealityClient::new(
        // s.reality_opts.unwrap().public_key,
        // s.reality_opts.unwrap().short_id,
        reality_public_key_to_u8_32(&s.reality_opts.as_ref().unwrap().public_key.clone()).unwrap(),
        // string_to_ascii_array::<32>().unwrap(),
        hex_pairs_to_u8x8(&s.reality_opts.as_ref().unwrap().short_id.clone().unwrap()).unwrap(),
        s.server_name.clone().unwrap_or_default(),
        vec![],
    );
    Ok(Some(Box::new(client)))
}

fn reality_public_key_to_u8_32(s: &str) -> Result<[u8; 32], String> {
    // 先按 xray x25519 默认的 base64url(no pad) 解；失败再尝试标准 base64
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| general_purpose::STANDARD.decode(s))
        .map_err(|e| format!("base64 decode failed: {e}"))?;

    if bytes.len() != 32 {
        return Err(format!(
            "decoded length must be 32 bytes, got {}",
            bytes.len()
        ));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairToByteError {
    InvalidLength { expected: usize, got: usize },
    InvalidHexChar(char),
}

pub fn hex_pairs_to_u8x8(input: &str) -> Result<[u8; 8], PairToByteError> {
    // 允许 0x 前缀与常见分隔符
    let s = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);

    let filtered: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' ' | '\t' | '\n' | '\r'))
        .collect();

    // 8 bytes = 16 hex chars
    if filtered.len() != 16 {
        return Err(PairToByteError::InvalidLength {
            expected: 16,
            got: filtered.len(),
        });
    }

    fn hex_nibble(c: char) -> Option<u8> {
        match c {
            '0'..='9' => Some((c as u8) - b'0'),
            'a'..='f' => Some((c as u8) - b'a' + 10),
            'A'..='F' => Some((c as u8) - b'A' + 10),
            _ => None,
        }
    }

    let mut out = [0u8; 8];
    let mut it = filtered.chars();

    for i in 0..8 {
        let hi_c = it.next().unwrap();
        let lo_c = it.next().unwrap();

        let hi = hex_nibble(hi_c).ok_or(PairToByteError::InvalidHexChar(hi_c))?;
        let lo = hex_nibble(lo_c).ok_or(PairToByteError::InvalidHexChar(lo_c))?;

        out[i] = (hi << 4) | lo;
    }

    Ok(out)
}

#[cfg(not(feature = "ws"))]
fn build_ws_transport(_: &OutboundVless) -> Result<Option<Box<dyn Transport>>, Error> {
    Err(Error::InvalidConfig(
        "ws network unsupported in this build".to_owned(),
    ))
}

fn tls_server_name(s: &OutboundVless) -> String {
    s.server_name
        .as_ref()
        .cloned()
        .or_else(|| {
            s.ws_opts.as_ref().and_then(|opts| {
                opts.headers
                    .as_ref()
                    .and_then(|headers| headers.get("Host").cloned())
            })
        })
        .unwrap_or_else(|| s.common_opts.server.clone())
}

fn tls_alpn(network: Option<&str>) -> Result<Option<Vec<String>>, Error> {
    match network {
        Some("ws") => Ok(Some(vec!["http/1.1".to_owned()])),
        Some("http") => Ok(Some(Vec::new())),
        Some("h2") | Some("grpc") => Ok(Some(vec!["h2".to_owned()])),
        Some(other) => Err(Error::InvalidConfig(format!(
            "unsupported network: {other}"
        ))),
        None => Ok(Some(vec!["http/1.1".to_owned()])),
    }
}
