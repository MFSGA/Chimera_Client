use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::{
        HandlerCommonOptions,
        transport::Transport,
        vless::{Handler, HandlerOptions},
    },
};
#[cfg(feature = "aws-lc-rs")]
use base64::{Engine as _, engine::general_purpose};
use tracing::warn;

#[cfg(feature = "aws-lc-rs")]
use crate::proxy::transport::{
    DEFAULT_REALITY_SHORT_ID, RealityClient, decode_public_key, decode_short_id,
};

impl TryFrom<OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVless) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVless) -> Result<Self, Self::Error> {
        let network = s.network.as_deref();
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let transport = build_transport(network, s)?;

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
            tls: None,
        }))
    }
}

fn build_transport(
    network: Option<&str>,
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    match network.unwrap_or("tcp") {
        "tcp" => build_tcp_transport(s),
        // "ws" => build_ws_transport(s),
        other => Err(Error::InvalidConfig(format!(
            "unsupported vless network: {other}"
        ))),
    }
}

fn build_tcp_transport(s: &OutboundVless) -> Result<Option<Box<dyn Transport>>, Error> {
    if s.reality_opts.is_none() {
        return Ok(None);
    }

    #[cfg(not(feature = "aws-lc-rs"))]
    {
        return Err(Error::InvalidConfig(
            "vless reality requires aws-lc-rs feature".to_owned(),
        ));
    }

    #[cfg(feature = "aws-lc-rs")]
    let reality_opts = s.reality_opts.as_ref().expect("checked is_some above");
    #[cfg(feature = "aws-lc-rs")]
    let public_key = decode_reality_public_key(&reality_opts.public_key)?;
    #[cfg(feature = "aws-lc-rs")]
    let short_id = decode_reality_short_id(reality_opts.short_id.as_deref())?;
    #[cfg(feature = "aws-lc-rs")]
    let server_name = s
        .server_name
        .clone()
        .unwrap_or("wwww.apple.com".to_string());

    let client = RealityClient::new(public_key, short_id, server_name, Vec::new());

    Ok(Some(Box::new(client)))
}

#[cfg(feature = "aws-lc-rs")]
fn decode_reality_public_key(input: &str) -> Result<[u8; 32], Error> {
    if let Ok(public_key) = decode_public_key(input) {
        return Ok(public_key);
    }

    let bytes = general_purpose::STANDARD.decode(input).map_err(|err| {
        Error::InvalidConfig(format!("invalid reality public-key '{}': {err}", input))
    })?;

    if bytes.len() != 32 {
        return Err(Error::InvalidConfig(format!(
            "invalid reality public-key length: expected 32, got {}",
            bytes.len()
        )));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(feature = "aws-lc-rs")]
fn decode_reality_short_id(short_id: Option<&str>) -> Result<[u8; 8], Error> {
    let candidate = short_id.map(str::trim).unwrap_or(DEFAULT_REALITY_SHORT_ID);
    let normalized = if candidate.is_empty() {
        DEFAULT_REALITY_SHORT_ID
    } else {
        candidate
    };

    decode_short_id(normalized).map_err(|err| {
        Error::InvalidConfig(format!("invalid reality short-id '{}': {err}", normalized))
    })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aws-lc-rs")]
    use super::decode_reality_short_id;
    use super::tls_server_name;
    use crate::config::internal::proxy::{CommonConfigOptions, OutboundVless, WsOpt};
    use std::collections::HashMap;

    #[test]
    fn tls_server_name_prefers_servername_field() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test".into(),
                server: "fallback.example.com".into(),
                port: 443,
                connect_via: None,
            },
            server_name: Some("sni.example.com".into()),
            ..Default::default()
        };

        assert_eq!(tls_server_name(&outbound), "sni.example.com");
    }

    #[test]
    fn tls_server_name_uses_ws_host_header_when_servername_missing() {
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), "ws-host.example.com".to_string());
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test".into(),
                server: "fallback.example.com".into(),
                port: 443,
                connect_via: None,
            },

            ..Default::default()
        };

        assert_eq!(tls_server_name(&outbound), "ws-host.example.com");
    }

    #[cfg(feature = "aws-lc-rs")]
    #[test]
    fn reality_short_id_accepts_empty_as_zero_short_id() {
        let decoded = decode_reality_short_id(Some("")).expect("empty short-id should decode");
        assert_eq!(decoded, [0; 8]);
    }
}
