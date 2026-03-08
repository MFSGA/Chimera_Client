use crate::{
    Error,
    config::internal::proxy::{
        OutboundTrojanRealityOpts, OutboundVless, XhttpDownloadSettings,
        XhttpOpt, XhttpUploadSettings,
    },
    proxy::{
        HandlerCommonOptions,
        transport::{
            TlsClient, Transport, XhttpClient, XhttpDownloadConfig, XhttpMode,
            XhttpRealityConfig, XhttpSecurity,
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
        let (server, port) = xhttp_upload_server_port(s);
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
            server,
            port,
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
    if matches!(network, Some("xhttp")) && s.reality_opts.is_some() {
        return build_xhttp_reality_transport(s);
    }

    if matches!(network, Some("xhttp"))
        && let Some(upload_settings) = s
            .xhttp_opts
            .as_ref()
            .and_then(|opts| opts.upload_settings.as_ref())
    {
        return build_xhttp_upload_tls_transport(upload_settings);
    }

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

fn build_xhttp_reality_transport(
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    #[cfg(feature = "reality")]
    {
        let server_name = resolve_xhttp_upload_server_name(s);
        let client = build_reality_transport_from_opts(
            s.reality_opts
                .as_ref()
                .expect("xhttp reality transport requires reality_opts"),
            server_name,
        )?;
        Ok(Some(Box::new(client)))
    }
    #[cfg(not(feature = "reality"))]
    {
        let _ = s;
        Err(Error::InvalidConfig(
            "vless xhttp reality requires reality feature".to_owned(),
        ))
    }
}

fn build_xhttp_upload_tls_transport(
    upload_settings: &XhttpUploadSettings,
) -> Result<Option<Box<dyn Transport>>, Error> {
    match upload_settings.security.as_deref().unwrap_or("none") {
        "none" => Ok(None),
        "tls" => {
            let xhttp_settings = upload_settings.xhttp_settings.as_ref();
            let server_name = upload_settings
                .sni
                .clone()
                .or_else(|| upload_settings.server_name.clone())
                .or_else(|| {
                    upload_settings
                        .tls_settings
                        .as_ref()
                        .and_then(|settings| settings.server_name.clone())
                })
                .or_else(|| {
                    xhttp_settings
                        .and_then(|settings| settings.host.as_ref())
                        .and_then(|hosts| hosts.first().cloned())
                })
                .unwrap_or_else(|| upload_settings.address.clone());
            let skip_cert_verify = upload_settings
                .tls_settings
                .as_ref()
                .and_then(|settings| settings.insecure)
                .unwrap_or(false);
            let alpn = Some(
                DEFAULT_XHTTP_ALPN
                    .iter()
                    .map(|item| (*item).to_owned())
                    .collect(),
            );

            Ok(Some(Box::new(TlsClient::new(
                skip_cert_verify,
                server_name,
                alpn,
                None,
            ))))
        }
        other => Err(Error::InvalidConfig(format!(
            "unsupported xhttp upload_settings security: {other}"
        ))),
    }
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
    let xhttp_opts = s.xhttp_opts.as_ref().ok_or_else(|| {
        Error::InvalidConfig("xhttp_opts is required for vless xhttp".to_owned())
    })?;

    validate_xhttp_opts(xhttp_opts)?;
    let mode = parse_xhttp_mode(xhttp_opts)?;
    let extra = xhttp_opts.extra.as_ref();
    let upload_settings = xhttp_opts.upload_settings.as_ref();
    let upload_xhttp_settings =
        upload_settings.and_then(|settings| settings.xhttp_settings.as_ref());
    let upload_security =
        upload_settings.and_then(|settings| settings.security.as_deref());

    Ok(Some(Box::new(XhttpClient::new(
        upload_settings
            .map(|settings| settings.address.clone())
            .unwrap_or_else(|| s.common_opts.server.clone()),
        upload_settings
            .map(|settings| settings.port)
            .unwrap_or(s.common_opts.port),
        normalized_xhttp_path(
            upload_xhttp_settings
                .and_then(|settings| settings.path.as_deref())
                .or(xhttp_opts.path.as_deref()),
        ),
        upload_xhttp_settings
            .and_then(|settings| settings.host.clone())
            .or_else(|| xhttp_opts.host.clone()),
        merged_xhttp_headers(
            xhttp_opts.headers.clone(),
            extra.and_then(|value| value.headers.clone()),
            upload_xhttp_settings.and_then(|settings| settings.headers.clone()),
        ),
        matches!(upload_security, Some("tls" | "reality"))
            || s.tls.unwrap_or_default()
            || s.reality_opts.is_some(),
        mode,
        resolve_xhttp_max_each_post_bytes(xhttp_opts),
        resolve_xhttp_no_grpc_header(xhttp_opts),
        resolve_xhttp_min_posts_interval_ms(xhttp_opts),
        build_xhttp_download_config(s, xhttp_opts)?,
    ))))
}

fn build_xhttp_download_config(
    s: &OutboundVless,
    xhttp_opts: &XhttpOpt,
) -> Result<Option<XhttpDownloadConfig>, Error> {
    let Some(download_settings) = resolve_xhttp_download_settings(xhttp_opts) else {
        return Ok(None);
    };

    validate_xhttp_download_settings(download_settings)?;

    let xhttp_settings = download_settings.xhttp_settings.as_ref();
    let host = xhttp_settings.and_then(|settings| settings.host.clone());
    let security = match download_settings.security.as_deref().unwrap_or_else(|| {
        if s.reality_opts.is_some() {
            "reality"
        } else {
            "none"
        }
    }) {
        "none" => XhttpSecurity::None,
        "tls" => XhttpSecurity::Tls,
        "reality" => XhttpSecurity::Reality,
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

    let reality =
        build_xhttp_download_reality_config(
            s.reality_opts.as_ref(),
            &security,
            &server_name,
        )?;

    Ok(Some(XhttpDownloadConfig {
        server: download_settings.address.clone(),
        port: download_settings.port,
        path: normalized_xhttp_path(
            xhttp_settings.and_then(|settings| settings.path.as_deref()),
        ),
        host,
        headers: merged_xhttp_headers(
            None,
            xhttp_opts
                .extra
                .as_ref()
                .and_then(|extra| extra.headers.clone()),
            xhttp_settings.and_then(|settings| settings.headers.clone()),
        ),
        security,
        server_name,
        skip_cert_verify,
        reality,
    }))
}

fn xhttp_upload_server_port(s: &OutboundVless) -> (String, u16) {
    let upload_settings = s
        .xhttp_opts
        .as_ref()
        .and_then(|opts| opts.upload_settings.as_ref());
    upload_settings
        .map(|settings| (settings.address.clone(), settings.port))
        .unwrap_or_else(|| (s.common_opts.server.clone(), s.common_opts.port))
}

fn resolve_xhttp_download_settings(
    xhttp_opts: &XhttpOpt,
) -> Option<&XhttpDownloadSettings> {
    xhttp_opts
        .extra
        .as_ref()
        .and_then(|extra| extra.download_settings.as_ref())
        .or(xhttp_opts.download_settings.as_ref())
}

fn resolve_xhttp_max_each_post_bytes(xhttp_opts: &XhttpOpt) -> usize {
    xhttp_opts
        .extra
        .as_ref()
        .and_then(|extra| extra.sc_max_each_post_bytes)
        .or(xhttp_opts.max_each_post_bytes)
        .unwrap_or(1_000_000)
}

fn resolve_xhttp_no_grpc_header(xhttp_opts: &XhttpOpt) -> bool {
    xhttp_opts
        .extra
        .as_ref()
        .and_then(|extra| extra.no_grpc_header)
        .unwrap_or(false)
}

fn resolve_xhttp_min_posts_interval_ms(xhttp_opts: &XhttpOpt) -> Option<u64> {
    xhttp_opts
        .extra
        .as_ref()
        .and_then(|extra| extra.sc_min_posts_interval_ms)
}

fn resolve_xhttp_upload_server_name(s: &OutboundVless) -> String {
    s.xhttp_opts
        .as_ref()
        .and_then(|opts| opts.upload_settings.as_ref())
        .and_then(|settings| {
            settings
                .sni
                .clone()
                .or_else(|| settings.server_name.clone())
                .or_else(|| {
                    settings
                        .tls_settings
                        .as_ref()
                        .and_then(|value| value.server_name.clone())
                })
                .or_else(|| {
                    settings
                        .xhttp_settings
                        .as_ref()
                        .and_then(|value| value.host.as_ref())
                        .and_then(|hosts| hosts.first().cloned())
                })
        })
        .or_else(|| s.sni.clone())
        .or_else(|| s.server_name.clone())
        .unwrap_or_else(|| xhttp_upload_server_port(s).0)
}

#[cfg(feature = "reality")]
fn build_reality_transport_from_opts(
    reality_opts: &OutboundTrojanRealityOpts,
    server_name: String,
) -> Result<RealityClient, Error> {
    let public_key = decode_reality_public_key(&reality_opts.public_key)?;
    let short_id = decode_reality_short_id(reality_opts.short_id.as_deref())?;
    Ok(RealityClient::new(
        public_key,
        short_id,
        server_name,
        Vec::new(),
    ))
}

fn build_xhttp_download_reality_config(
    reality_opts: Option<&OutboundTrojanRealityOpts>,
    security: &XhttpSecurity,
    server_name: &str,
) -> Result<Option<XhttpRealityConfig>, Error> {
    if !matches!(security, XhttpSecurity::Reality) {
        return Ok(None);
    }

    #[cfg(feature = "reality")]
    {
        let reality_opts = reality_opts.ok_or_else(|| {
            Error::InvalidConfig(
                "xhttp download_settings security reality requires reality_opts"
                    .to_owned(),
            )
        })?;
        let public_key = decode_reality_public_key(&reality_opts.public_key)?;
        let short_id = decode_reality_short_id(reality_opts.short_id.as_deref())?;
        Ok(Some(XhttpRealityConfig {
            public_key,
            short_id,
            server_name: server_name.to_owned(),
        }))
    }
    #[cfg(not(feature = "reality"))]
    {
        let _ = reality_opts;
        let _ = server_name;
        Err(Error::InvalidConfig(
            "xhttp download_settings reality requires reality feature".to_owned(),
        ))
    }
}

fn merged_xhttp_headers(
    base: Option<std::collections::HashMap<String, String>>,
    extra: Option<std::collections::HashMap<String, String>>,
    override_headers: Option<std::collections::HashMap<String, String>>,
) -> std::collections::HashMap<String, String> {
    let mut merged = base.unwrap_or_default();
    if let Some(extra) = extra {
        merged.extend(extra);
    }
    if let Some(override_headers) = override_headers {
        merged.extend(override_headers);
    }
    merged
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

    if matches!(
        xhttp_opts
            .extra
            .as_ref()
            .and_then(|extra| extra.sc_max_each_post_bytes),
        Some(0)
    ) {
        return Err(Error::InvalidConfig(
            "xhttp extra sc_max_each_post_bytes must be greater than zero"
                .to_owned(),
        ));
    }

    if matches!(
        xhttp_opts
            .extra
            .as_ref()
            .and_then(|extra| extra.sc_min_posts_interval_ms),
        Some(0)
    ) {
        return Err(Error::InvalidConfig(
            "xhttp extra sc_min_posts_interval_ms must be greater than zero"
                .to_owned(),
        ));
    }

    if let Some(upload_settings) = xhttp_opts.upload_settings.as_ref() {
        validate_xhttp_upload_settings(upload_settings)?;
    }

    if let Some(download_settings) = resolve_xhttp_download_settings(xhttp_opts) {
        validate_xhttp_download_settings(download_settings)?;
    }

    Ok(())
}

fn validate_xhttp_upload_settings(
    upload_settings: &XhttpUploadSettings,
) -> Result<(), Error> {
    validate_xhttp_endpoint_settings(upload_settings, "upload_settings")
}

fn validate_xhttp_download_settings(
    download_settings: &XhttpDownloadSettings,
) -> Result<(), Error> {
    validate_xhttp_endpoint_settings(download_settings, "download_settings")
}

fn validate_xhttp_endpoint_settings(
    settings: &XhttpDownloadSettings,
    label: &str,
) -> Result<(), Error> {
    if settings.address.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} address must not be empty"
        )));
    }

    if settings.port == 0 {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} port must be greater than zero"
        )));
    }

    if settings.network != "xhttp" {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} network must be xhttp, got {}",
            settings.network
        )));
    }

    if let Some(security) = settings.security.as_deref()
        && !matches!(security, "none" | "tls" | "reality")
    {
        return Err(Error::InvalidConfig(format!(
            "unsupported xhttp {label} security: {security}"
        )));
    }

    if matches!(
        settings
            .xhttp_settings
            .as_ref()
            .and_then(|settings| settings.path.as_deref()),
        Some("")
    ) {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} path must not be empty"
        )));
    }

    #[cfg(not(feature = "tls"))]
    if matches!(settings.security.as_deref(), Some("tls")) {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} tls requires tls feature"
        )));
    }

    #[cfg(not(feature = "reality"))]
    if matches!(settings.security.as_deref(), Some("reality")) {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} reality requires reality feature"
        )));
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

    let server_name = s
        .server_name
        .clone()
        .unwrap_or("wwww.apple.com".to_string());
    let reality_opts = s.reality_opts.as_ref().expect("checked is_some above");
    let client = build_reality_transport_from_opts(reality_opts, server_name)?;

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
        XhttpExtra, XhttpOpt, XhttpUploadSettings,
    };

    use super::{OutboundVless, build_tls_transport};

    #[cfg(feature = "ws")]
    use crate::config::internal::proxy::WsOpt;

    use super::build_transport;

    #[cfg(feature = "reality")]
    use super::decode_reality_short_id;

    #[cfg(feature = "reality")]
    const TEST_REALITY_PUBLIC_KEY: &str =
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

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
    fn vless_xhttp_rejects_zero_extra_limits() {
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
                extra: Some(XhttpExtra {
                    sc_max_each_post_bytes: Some(0),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("zero xhttp extra limits must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("sc_max_each_post_bytes"),
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
                server: "legacy-upload.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/upload/".to_owned()),
                mode: Some("packet-up".to_owned()),
                extra: Some(XhttpExtra {
                    headers: Some(
                        [("X-Extra".to_owned(), "enabled".to_owned())]
                            .into_iter()
                            .collect(),
                    ),
                    sc_max_each_post_bytes: Some(512),
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
                upload_settings: Some(XhttpUploadSettings {
                    address: "upload.example.com".to_owned(),
                    port: 9443,
                    network: "xhttp".to_owned(),
                    security: Some("tls".to_owned()),
                    xhttp_settings: Some(XhttpDownloadXhttpSettings {
                        path: Some("/upload/".to_owned()),
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

        let tls = build_tls_transport(outbound.network.as_deref(), &outbound, false)
            .expect("upload settings tls should build");
        assert!(
            tls.is_some(),
            "xhttp upload settings should create a tls transport"
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

    #[test]
    fn vless_xhttp_rejects_non_xhttp_upload_network() {
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
                upload_settings: Some(XhttpUploadSettings {
                    address: "upload.example.com".to_owned(),
                    port: 9443,
                    network: "ws".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("non-xhttp upload network should fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("upload_settings network must be xhttp"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_xhttp_supports_reality() {
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
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: None,
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("xhttp reality transport should build");
        assert!(transport.is_some(), "xhttp reality transport should be present");

        let tls = build_tls_transport(outbound.network.as_deref(), &outbound, false)
            .expect("xhttp reality tls transport should build");
        assert!(
            tls.is_some(),
            "xhttp reality should create a handshake transport"
        );
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_xhttp_download_settings_support_reality() {
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
                extra: Some(XhttpExtra {
                    download_settings: Some(XhttpDownloadSettings {
                        address: "download.example.com".to_owned(),
                        port: 8443,
                        network: "xhttp".to_owned(),
                        security: Some("reality".to_owned()),
                        xhttp_settings: Some(XhttpDownloadXhttpSettings {
                            path: Some("/download/".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: None,
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("xhttp download reality transport should build");
        assert!(
            transport.is_some(),
            "xhttp transport with reality download settings should be present"
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
