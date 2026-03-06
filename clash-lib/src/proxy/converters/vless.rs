use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::{
        HandlerCommonOptions,
        transport::{TlsClient, Transport},
        vless::{Handler, HandlerOptions},
    },
};
#[cfg(feature = "reality")]
use base64::{Engine as _, engine::general_purpose};
use tracing::warn;

#[cfg(feature = "ws")]
use crate::proxy::transport::WsClient;

const DEFAULT_WS_ALPN: [&str; 1] = ["http/1.1"];

#[cfg(feature = "reality")]
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
            tls: build_tls_transport(network, s, skip_cert_verify)?,
        }))
    }
}

fn build_transport(
    network: Option<&str>,
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    match network.unwrap_or("tcp") {
        "tcp" => {
            #[cfg(feature = "reality")]
            return build_tcp_transport(s);
            #[cfg(not(feature = "reality"))]
            {
                Ok(None)
            }
        }
        "ws" => build_ws_transport(s),
        other => Err(Error::InvalidConfig(format!(
            "unsupported vless network: {other}"
        ))),
    }
}

fn build_tls_transport(
    network: Option<&str>,
    s: &OutboundVless,
    skip_cert_verify: bool,
) -> Result<Option<Box<dyn Transport>>, Error> {
    if !s.tls.unwrap_or_default() {
        return Ok(None);
    }

    if s.reality_opts.is_some() {
        return Ok(None);
    }

    let server_name = s
        .sni
        .clone()
        .or_else(|| s.server_name.clone())
        .unwrap_or_else(|| s.common_opts.server.clone());
    let alpn = match network {
        Some("ws") => Some(
            DEFAULT_WS_ALPN
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>(),
        ),
        _ => None,
    };

    Ok(Some(Box::new(TlsClient::new(
        skip_cert_verify,
        server_name,
        alpn,
        None,
    ))))
}

fn build_ws_transport(
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    #[cfg(feature = "ws")]
    {
        s.ws_opts
            .as_ref()
            .map(|opts| {
                let client: WsClient =
                    (opts, &s.common_opts).try_into().map_err(|err| {
                        Error::InvalidConfig(format!(
                            "invalid ws_opts for {}: {err}",
                            s.common_opts.name
                        ))
                    })?;
                Ok(Box::new(client) as Box<dyn Transport>)
            })
            .transpose()
            .and_then(|transport| {
                transport.ok_or_else(|| {
                    Error::InvalidConfig(
                        "ws_opts is required for vless ws".to_owned(),
                    )
                })
            })
            .map(Some)
    }
    #[cfg(not(feature = "ws"))]
    {
        let _ = s;
        Err(Error::InvalidConfig(
            "vless ws network requires ws feature".to_owned(),
        ))
    }
}

#[cfg(feature = "reality")]
fn build_tcp_transport(
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    if s.reality_opts.is_none() {
        return Ok(None);
    }

    #[cfg(not(feature = "aws-lc-rs"))]
    {
        return Err(Error::InvalidConfig(
            "vless reality requires aws-lc-rs feature".to_owned(),
        ));
    }

    let reality_opts = s.reality_opts.as_ref().expect("checked is_some above");
    let public_key = decode_reality_public_key(&reality_opts.public_key)?;
    let short_id = decode_reality_short_id(reality_opts.short_id.as_deref())?;

    let server_name = s
        .server_name
        .clone()
        .unwrap_or("wwww.apple.com".to_string());

    let client = RealityClient::new(public_key, short_id, server_name, Vec::new());

    Ok(Some(Box::new(client)))
}

#[cfg(feature = "reality")]
fn decode_reality_public_key(input: &str) -> Result<[u8; 32], Error> {
    if let Ok(public_key) = decode_public_key(input) {
        return Ok(public_key);
    }

    let bytes = general_purpose::STANDARD.decode(input).map_err(|err| {
        Error::InvalidConfig(format!(
            "invalid reality public-key '{}': {err}",
            input
        ))
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

#[cfg(feature = "reality")]
fn decode_reality_short_id(short_id: Option<&str>) -> Result<[u8; 8], Error> {
    let candidate = short_id.map(str::trim).unwrap_or(DEFAULT_REALITY_SHORT_ID);
    let normalized = if candidate.is_empty() {
        DEFAULT_REALITY_SHORT_ID
    } else {
        candidate
    };

    decode_short_id(normalized).map_err(|err| {
        Error::InvalidConfig(format!(
            "invalid reality short-id '{}': {err}",
            normalized
        ))
    })
}

#[cfg(test)]
mod tests {
    use crate::config::internal::proxy::CommonConfigOptions;

    use super::{OutboundVless, build_tls_transport};

    #[cfg(feature = "ws")]
    use crate::config::internal::proxy::WsOpt;

    #[cfg(feature = "ws")]
    use super::build_transport;

    #[cfg(feature = "reality")]
    use super::decode_reality_short_id;

    #[cfg(feature = "reality")]
    #[test]
    fn reality_short_id_accepts_empty_as_zero_short_id() {
        let decoded =
            decode_reality_short_id(Some("")).expect("empty short-id should decode");
        assert_eq!(decoded, [0; 8]);
    }

    #[cfg(feature = "ws")]
    #[test]
    fn vless_ws_requires_ws_opts() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "ws".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("ws".to_owned()),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("missing ws_opts must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("ws_opts is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_ws_tls_uses_http11_alpn() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "ws-tls".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            network: Some("ws".to_owned()),
            ..Default::default()
        };

        let tls = build_tls_transport(outbound.network.as_deref(), &outbound, false)
            .expect("tls build should succeed");
        assert!(tls.is_some(), "tls transport should be present");
    }

    #[cfg(feature = "ws")]
    #[test]
    fn vless_ws_transport_builds_with_ws_opts() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "ws".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("ws".to_owned()),
            ws_opts: Some(WsOpt {
                path: Some("/websocket".to_owned()),
                headers: None,
                max_early_data: None,
                early_data_header_name: None,
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("ws transport should build");
        assert!(transport.is_some(), "ws transport should be present");
    }
}
