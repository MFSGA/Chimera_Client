use crate::{
    Error,
    config::internal::proxy::{OutboundVless, XhttpDownloadSettings, XhttpOpt},
    proxy::{
        HandlerCommonOptions,
        transport::{
            TlsClient, Transport, XhttpClient, XhttpDownloadConfig, XhttpMode,
            XhttpSecurity,
        },
        vless::{Handler, HandlerOptions},
    },
};
#[cfg(feature = "reality")]
use base64::{Engine as _, engine::general_purpose};
use tracing::warn;

#[cfg(feature = "ws")]
use crate::proxy::transport::WsClient;

const DEFAULT_WS_ALPN: [&str; 1] = ["http/1.1"];
const DEFAULT_XHTTP_ALPN: [&str; 1] = ["h2"];

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
        "xhttp" => build_xhttp_transport(s),
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
        Some("xhttp") => Some(
            DEFAULT_XHTTP_ALPN
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

fn build_xhttp_transport(
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    if s.reality_opts.is_some() {
        return Err(Error::InvalidConfig(
            "vless xhttp with reality is not implemented yet".to_owned(),
        ));
    }

    let xhttp_opts = s.xhttp_opts.as_ref().ok_or_else(|| {
        Error::InvalidConfig("xhttp_opts is required for vless xhttp".to_owned())
    })?;

    validate_xhttp_opts(xhttp_opts)?;
    let mode = parse_xhttp_mode(xhttp_opts)?;

    Ok(Some(Box::new(XhttpClient::new(
        s.common_opts.server.clone(),
        s.common_opts.port,
        normalized_xhttp_path(xhttp_opts.path.as_deref()),
        xhttp_opts.host.clone(),
        xhttp_opts.headers.clone().unwrap_or_default(),
        s.tls.unwrap_or_default(),
        mode,
        xhttp_opts.max_each_post_bytes.unwrap_or(1_000_000),
        build_xhttp_download_config(xhttp_opts)?,
    ))))
}

fn build_xhttp_download_config(
    xhttp_opts: &XhttpOpt,
) -> Result<Option<XhttpDownloadConfig>, Error> {
    let Some(download_settings) = xhttp_opts.download_settings.as_ref() else {
        return Ok(None);
    };

    validate_xhttp_download_settings(download_settings)?;

    let xhttp_settings = download_settings.xhttp_settings.as_ref();
    let host = xhttp_settings.and_then(|settings| settings.host.clone());
    let security = match download_settings.security.as_deref().unwrap_or("none") {
        "none" => XhttpSecurity::None,
        "tls" => XhttpSecurity::Tls,
        other => {
            return Err(Error::InvalidConfig(format!(
                "unsupported xhttp download_settings security: {other}"
            )));
        }
    };

    let server_name = download_settings
        .sni
        .clone()
        .or_else(|| download_settings.server_name.clone())
        .or_else(|| {
            download_settings
                .tls_settings
                .as_ref()
                .and_then(|settings| settings.server_name.clone())
        })
        .or_else(|| host.as_ref().and_then(|hosts| hosts.first().cloned()))
        .unwrap_or_else(|| download_settings.address.clone());

    let skip_cert_verify = download_settings
        .tls_settings
        .as_ref()
        .and_then(|settings| settings.insecure)
        .unwrap_or(false);

    Ok(Some(XhttpDownloadConfig {
        server: download_settings.address.clone(),
        port: download_settings.port,
        path: normalized_xhttp_path(
            xhttp_settings.and_then(|settings| settings.path.as_deref()),
        ),
        host,
        headers: xhttp_settings
            .and_then(|settings| settings.headers.clone())
            .unwrap_or_default(),
        security,
        server_name,
        skip_cert_verify,
    }))
}

fn validate_xhttp_opts(xhttp_opts: &XhttpOpt) -> Result<(), Error> {
    if matches!(xhttp_opts.path.as_deref(), Some("")) {
        return Err(Error::InvalidConfig(
            "xhttp path must not be empty".to_owned(),
        ));
    }

    for (name, value) in [
        ("max_each_post_bytes", xhttp_opts.max_each_post_bytes),
        ("max_buffered_posts", xhttp_opts.max_buffered_posts),
    ] {
        if matches!(value, Some(0)) {
            return Err(Error::InvalidConfig(format!(
                "xhttp {name} must be greater than zero"
            )));
        }
    }

    if matches!(xhttp_opts.session_ttl, Some(0)) {
        return Err(Error::InvalidConfig(
            "xhttp session_ttl must be greater than zero".to_owned(),
        ));
    }

    Ok(())
}

fn validate_xhttp_download_settings(
    download_settings: &XhttpDownloadSettings,
) -> Result<(), Error> {
    if download_settings.address.is_empty() {
        return Err(Error::InvalidConfig(
            "xhttp download_settings address must not be empty".to_owned(),
        ));
    }

    if download_settings.port == 0 {
        return Err(Error::InvalidConfig(
            "xhttp download_settings port must be greater than zero".to_owned(),
        ));
    }

    if download_settings.network != "xhttp" {
        return Err(Error::InvalidConfig(format!(
            "xhttp download_settings network must be xhttp, got {}",
            download_settings.network
        )));
    }

    if let Some(security) = download_settings.security.as_deref()
        && !matches!(security, "none" | "tls")
    {
        return Err(Error::InvalidConfig(format!(
            "unsupported xhttp download_settings security: {security}"
        )));
    }

    if matches!(
        download_settings
            .xhttp_settings
            .as_ref()
            .and_then(|settings| settings.path.as_deref()),
        Some("")
    ) {
        return Err(Error::InvalidConfig(
            "xhttp download_settings path must not be empty".to_owned(),
        ));
    }

    #[cfg(not(feature = "tls"))]
    if matches!(download_settings.security.as_deref(), Some("tls")) {
        return Err(Error::InvalidConfig(
            "xhttp download_settings tls requires tls feature".to_owned(),
        ));
    }

    Ok(())
}

fn parse_xhttp_mode(xhttp_opts: &XhttpOpt) -> Result<XhttpMode, Error> {
    let mode = xhttp_opts.mode.as_deref().unwrap_or("auto");
    match mode {
        "stream-one" => Ok(XhttpMode::StreamOne),
        "stream-up" => Ok(XhttpMode::StreamUp),
        "packet-up" | "split" => Ok(XhttpMode::PacketUp),
        "auto" => Ok(XhttpMode::PacketUp),
        other => Err(Error::InvalidConfig(format!(
            "unsupported xhttp mode: {other}"
        ))),
    }
}

fn normalized_xhttp_path(path: Option<&str>) -> String {
    let raw = path.unwrap_or("/");
    let mut normalized = if raw.starts_with('/') {
        raw.to_owned()
    } else {
        format!("/{raw}")
    };

    if !normalized.ends_with('/') {
        normalized.push('/');
    }

    normalized
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
    #[cfg(feature = "reality")]
    use crate::config::internal::proxy::OutboundTrojanRealityOpts;
    use crate::config::internal::proxy::{
        CommonConfigOptions, XhttpDownloadSettings, XhttpDownloadXhttpSettings,
        XhttpOpt,
    };

    use super::{OutboundVless, build_tls_transport};

    #[cfg(feature = "ws")]
    use crate::config::internal::proxy::WsOpt;

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

    #[test]
    fn vless_xhttp_requires_xhttp_opts() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("missing xhttp_opts must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("xhttp_opts is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_stream_one_transport_builds() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                mode: Some("stream-one".to_owned()),
                max_each_post_bytes: Some(1_000_000),
                max_buffered_posts: Some(30),
                session_ttl: Some(30),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("xhttp stream-one should build");
        assert!(transport.is_some(), "xhttp transport should be present");
    }

    #[test]
    fn vless_xhttp_rejects_zero_limits() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                max_buffered_posts: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("zero xhttp limits must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("must be greater than zero"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_stream_up_transport_builds() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                mode: Some("stream-up".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("stream-up mode should build");
        assert!(
            transport.is_some(),
            "xhttp stream-up transport should be present"
        );
    }

    #[test]
    fn vless_xhttp_packet_up_transport_builds() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                mode: Some("split".to_owned()),
                upload_mode: Some("packet-up".to_owned()),
                download_mode: Some("stream-down".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("split mode should build");
        assert!(
            transport.is_some(),
            "xhttp packet-up transport should be present"
        );
    }

    #[test]
    fn vless_xhttp_auto_defaults_to_packet_up() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("auto mode should build");
        assert!(
            transport.is_some(),
            "xhttp auto transport should be present"
        );
    }

    #[test]
    fn vless_xhttp_download_settings_transport_builds() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "upload.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/upload/".to_owned()),
                mode: Some("packet-up".to_owned()),
                download_settings: Some(XhttpDownloadSettings {
                    address: "download.example.com".to_owned(),
                    port: 8443,
                    network: "xhttp".to_owned(),
                    security: Some("tls".to_owned()),
                    xhttp_settings: Some(XhttpDownloadXhttpSettings {
                        path: Some("/download/".to_owned()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("download settings transport should build");
        assert!(
            transport.is_some(),
            "xhttp transport with download settings should be present"
        );
    }

    #[test]
    fn vless_xhttp_rejects_non_xhttp_download_network() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "upload.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/upload/".to_owned()),
                download_settings: Some(XhttpDownloadSettings {
                    address: "download.example.com".to_owned(),
                    port: 8443,
                    network: "ws".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("non-xhttp download network should fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("download_settings network must be xhttp"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_xhttp_rejects_reality() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                ..Default::default()
            }),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: "a".repeat(43),
                short_id: None,
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("xhttp reality should be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("reality is not implemented"),
            "unexpected error: {err}"
        );
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
