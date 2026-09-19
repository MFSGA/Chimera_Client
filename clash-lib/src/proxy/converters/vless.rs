use crate::{
    Error,
    config::internal::proxy::{
        OutboundTrojanRealityOpts, OutboundVless, XhttpDownloadSettings, XhttpOpt,
        XhttpReuseSettings, XhttpUploadSettings,
    },
    proxy::{
        HandlerCommonOptions,
        transport::{
            GrpcClient, TlsClient, Transport, XhttpChunkSizeRange, XhttpClient,
            XhttpDownloadConfig, XhttpEndpointConfig, XhttpHttpVersion,
            XhttpMetadataConfig, XhttpMetadataPlacement, XhttpMode,
            XhttpPaddingConfig, XhttpPaddingMethod, XhttpPaddingPlacement,
            XhttpRealityConfig, XhttpReusePolicy, XhttpReuseValueRange,
            XhttpSecurity, XhttpSessionIdConfig, XhttpUplinkConfig,
            XhttpUplinkDataPlacement,
        },
        vless::{
            Handler, HandlerOptions, encryption::Config as VlessEncryptionConfig,
        },
    },
};
#[cfg(feature = "reality")]
use base64::{Engine as _, engine::general_purpose};
use tracing::warn;

#[cfg(feature = "ws")]
use super::utils::build_ws_client;
#[cfg(feature = "ws")]
use crate::proxy::transport::WsClient;

const DEFAULT_WS_ALPN: [&str; 1] = ["http/1.1"];
const DEFAULT_H2_ALPN: [&str; 1] = ["h2"];

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
        validate_vless_config(s)?;
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
            flow: s.flow.clone(),
        }))
    }
}

fn validate_vless_config(s: &OutboundVless) -> Result<(), Error> {
    match s.flow.as_deref() {
        None | Some("") | Some("xtls-rprx-vision") => {}
        Some(flow) => {
            return Err(Error::InvalidConfig(format!(
                "unsupported vless flow: {flow}"
            )));
        }
    }

    if let Some(encryption) = s.encryption.as_deref() {
        let encryption = encryption.trim();
        if !encryption.is_empty() && encryption != "none" {
            let parsed =
                VlessEncryptionConfig::parse(encryption).map_err(|err| {
                    Error::InvalidConfig(format!(
                        "invalid vless encryption config: {err}"
                    ))
                })?;
            #[cfg(feature = "vless-encryption")]
            {
                let prepared = parsed.prepare_crypto().map_err(|err| {
                    Error::InvalidConfig(format!(
                        "invalid vless encryption crypto key: {err}"
                    ))
                })?;
                return Err(Error::InvalidConfig(format!(
                    "vless encryption config is valid ({}; {}) but runtime handshake support is not implemented yet",
                    parsed.summary(),
                    prepared.summary()
                )));
            }
            #[cfg(not(feature = "vless-encryption"))]
            {
                let _ = parsed;
                return Err(Error::InvalidConfig(
                    "vless encryption requires vless-encryption feature".to_owned(),
                ));
            }
        }
    }

    match (&s.certificate, &s.private_key) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(Error::InvalidConfig(
                "vless certificate and private-key must both be set or both omitted"
                    .to_owned(),
            ));
        }
    }

    if s.certificate.is_some() {
        if s.reality_opts.is_some() {
            return Err(Error::InvalidConfig(
                "vless certificate/private-key client auth is not supported with reality"
                    .to_owned(),
            ));
        }
        if !vless_standard_tls_enabled(s) {
            return Err(Error::InvalidConfig(
                "vless certificate/private-key requires standard TLS".to_owned(),
            ));
        }
    }

    if let Some(client_fingerprint) = s.client_fingerprint.as_deref()
        && client_fingerprint != "none"
    {
        warn!(
            "vless client-fingerprint '{client_fingerprint}' is not supported yet, ignoring it"
        );
    }

    if matches!(s.network.as_deref(), Some("xhttp")) {
        resolve_xhttp_http_version(s)?;
    }

    if matches!(s.network.as_deref(), Some("grpc"))
        && let Some(alpn) = s.alpn.as_ref()
        && alpn.as_slice() != ["h2"]
    {
        return Err(Error::InvalidConfig(
            "vless grpc requires alpn: [h2]".to_owned(),
        ));
    }

    #[cfg(feature = "ws")]
    if matches!(s.network.as_deref(), Some("ws"))
        && let Some(ws_opts) = s.ws_opts.as_ref()
    {
        if ws_opts.max_early_data.is_some_and(|value| value < 0) {
            return Err(Error::InvalidConfig(
                "vless ws max-early-data must not be negative".to_owned(),
            ));
        }

        let http_upgrade = ws_opts.v2ray_http_upgrade.unwrap_or(false);
        let fast_open = ws_opts.v2ray_http_upgrade_fast_open.unwrap_or(false);
        if fast_open && !http_upgrade {
            return Err(Error::InvalidConfig(
                "vless ws v2ray-http-upgrade-fast-open requires v2ray-http-upgrade"
                    .to_owned(),
            ));
        }
    }

    Ok(())
}

fn vless_standard_tls_enabled(s: &OutboundVless) -> bool {
    if matches!(s.network.as_deref(), Some("xhttp"))
        && let Some(upload_settings) = s
            .xhttp_opts
            .as_ref()
            .and_then(|opts| opts.upload_settings.as_ref())
    {
        return matches!(upload_settings.security.as_deref(), Some("tls"));
    }

    s.tls.unwrap_or_default() && s.reality_opts.is_none()
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
        "grpc" => build_grpc_transport(s),
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
    if matches!(network, Some("xhttp")) {
        if matches!(
            resolve_xhttp_http_version(s)?,
            XhttpHttpVersion::Http1 | XhttpHttpVersion::Http3
        ) {
            // HTTP/1.1 packet-up opens more than one TCP connection, while
            // HTTP/3 owns a UDP/QUIC endpoint. In both cases XHTTP must own
            // endpoint security rather than wrapping a pre-dialed TCP stream.
            return Ok(None);
        }
        if s.xhttp_opts
            .as_ref()
            .and_then(|opts| opts.upload_settings.as_ref())
            .is_some()
        {
            // Explicit XHTTP upload-settings own their endpoint security inside
            // the transport so the raw socket can still be created by the normal
            // RemoteConnector path.
            return Ok(None);
        }
    }

    if matches!(network, Some("xhttp")) && s.reality_opts.is_some() {
        return build_xhttp_reality_transport(s);
    }

    if matches!(network, Some("grpc")) && s.reality_opts.is_some() {
        return build_grpc_reality_transport(s);
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
    let alpn = resolve_vless_alpn(s, network);

    let client = TlsClient::new_with_fingerprint(
        skip_cert_verify,
        server_name,
        alpn,
        None,
        s.fingerprint.clone(),
    )
    .with_verify_name(s.name_cert_verify.clone())
    .with_client_auth(s.certificate.clone(), s.private_key.clone())?;

    Ok(Some(Box::new(client)))
}

fn resolve_vless_alpn(
    s: &OutboundVless,
    network: Option<&str>,
) -> Option<Vec<String>> {
    s.alpn.clone().or_else(|| match network {
        Some("ws") => Some(
            DEFAULT_WS_ALPN
                .iter()
                .map(|item| (*item).to_owned())
                .collect(),
        ),
        Some("grpc" | "xhttp") => Some(
            DEFAULT_H2_ALPN
                .iter()
                .map(|item| (*item).to_owned())
                .collect(),
        ),
        _ => None,
    })
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
            resolve_vless_alpn(s, Some("xhttp")),
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

fn build_grpc_reality_transport(
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    #[cfg(feature = "reality")]
    {
        let reality_opts = s.reality_opts.as_ref().ok_or_else(|| {
            Error::InvalidConfig(
                "vless grpc reality requires reality_opts".to_owned(),
            )
        })?;
        let client = build_reality_transport_from_opts(
            reality_opts,
            resolve_reality_server_name(s),
            resolve_vless_alpn(s, Some("grpc")),
        )?;
        Ok(Some(Box::new(client)))
    }
    #[cfg(not(feature = "reality"))]
    {
        let _ = s;
        Err(Error::InvalidConfig(
            "vless grpc reality requires reality feature".to_owned(),
        ))
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
                let client: WsClient = build_ws_client(
                    opts,
                    &s.common_opts,
                    s.sni.as_deref().or(s.server_name.as_deref()),
                );
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

fn build_grpc_transport(
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    let grpc_opts = s.grpc_opts.as_ref().ok_or_else(|| {
        Error::InvalidConfig("grpc_opts is required for vless grpc".to_owned())
    })?;
    validate_grpc_opts(grpc_opts)?;

    let authority = s
        .sni
        .clone()
        .or_else(|| s.server_name.clone())
        .unwrap_or_else(|| s.common_opts.server.clone());
    let path = format!(
        "/{}",
        grpc_opts.grpc_service_name.as_deref().unwrap_or_default()
    )
    .try_into()
    .map_err(|err| {
        Error::InvalidConfig(format!("invalid vless grpc service path: {err}"))
    })?;

    let client = GrpcClient::new(authority, path)
        .with_user_agent(grpc_opts.grpc_user_agent.clone())
        .with_ping_interval(grpc_opts.ping_interval)
        .with_pool_limits(
            grpc_opts.max_connections,
            grpc_opts.min_streams,
            grpc_opts.max_streams,
        );

    Ok(Some(Box::new(client)))
}

fn validate_grpc_opts(
    grpc_opts: &crate::config::internal::proxy::GrpcOpt,
) -> Result<(), Error> {
    if grpc_opts.max_streams.is_some()
        && (grpc_opts.max_connections.is_some() || grpc_opts.min_streams.is_some())
    {
        return Err(Error::InvalidConfig(
            "vless grpc max-streams conflicts with max-connections and min-streams"
                .to_owned(),
        ));
    }

    Ok(())
}

fn resolve_xhttp_http_version(s: &OutboundVless) -> Result<XhttpHttpVersion, Error> {
    match s.alpn.as_deref() {
        None => Ok(XhttpHttpVersion::Http2),
        Some([value]) if value == "h2" => Ok(XhttpHttpVersion::Http2),
        Some([value]) if value == "h3" => {
            #[cfg(not(feature = "xhttp-h3"))]
            {
                Err(Error::InvalidConfig(
                    "vless xhttp HTTP/3 requires xhttp-h3 feature".to_owned(),
                ))
            }
            #[cfg(feature = "xhttp-h3")]
            {
                let opts = s.xhttp_opts.as_ref().ok_or_else(|| {
                    Error::InvalidConfig(
                        "xhttp_opts is required for vless xhttp".to_owned(),
                    )
                })?;
                if let Some(download) = resolve_xhttp_download_settings(opts) {
                    if matches!(parse_xhttp_mode(opts)?, XhttpMode::StreamOne) {
                        return Err(Error::InvalidConfig(
                            "vless xhttp HTTP/3 stream-one does not support download-settings"
                                .to_owned(),
                        ));
                    }
                    let download_reuse =
                        download.reuse_settings.as_ref().or_else(|| {
                            download.xhttp_settings.as_ref().and_then(|settings| {
                                settings.reuse_settings.as_ref()
                            })
                        });
                    build_xhttp_reuse_policy(download_reuse)?;
                }
                build_xhttp_reuse_policy(opts.reuse_settings.as_ref())?;
                if s.reality_opts.is_some() {
                    return Err(Error::InvalidConfig(
                        "vless xhttp HTTP/3 currently supports standard TLS only"
                            .to_owned(),
                    ));
                }
                let tls_enabled = opts
                    .upload_settings
                    .as_ref()
                    .and_then(|settings| settings.tls)
                    .or(s.tls)
                    .unwrap_or(false);
                let upload_security = opts
                    .upload_settings
                    .as_ref()
                    .and_then(|settings| settings.security.as_deref());
                if !tls_enabled && !matches!(upload_security, Some("tls")) {
                    return Err(Error::InvalidConfig(
                        "vless xhttp HTTP/3 requires TLS".to_owned(),
                    ));
                }
                Ok(XhttpHttpVersion::Http3)
            }
        }
        Some([value]) if value == "http/1.1" => {
            let opts = s.xhttp_opts.as_ref().ok_or_else(|| {
                Error::InvalidConfig(
                    "xhttp_opts is required for vless xhttp".to_owned(),
                )
            })?;
            if opts.upload_settings.is_some() || opts.reuse_settings.is_some() {
                return Err(Error::InvalidConfig(
                    "vless xhttp HTTP/1.1 currently does not support upload-settings or reuse-settings"
                        .to_owned(),
                ));
            }
            if let Some(download) = resolve_xhttp_download_settings(opts)
                && (download.reuse_settings.is_some()
                    || download
                        .xhttp_settings
                        .as_ref()
                        .and_then(|settings| settings.reuse_settings.as_ref())
                        .is_some())
            {
                return Err(Error::InvalidConfig(
                    "vless xhttp HTTP/1.1 download-settings currently does not support reuse-settings"
                        .to_owned(),
                ));
            }
            if !matches!(
                parse_xhttp_mode(opts)?,
                XhttpMode::Auto | XhttpMode::PacketUp
            ) {
                return Err(Error::InvalidConfig(
                    "vless xhttp HTTP/1.1 currently supports only mode: auto or packet-up"
                        .to_owned(),
                ));
            }
            Ok(XhttpHttpVersion::Http1)
        }
        _ => Err(Error::InvalidConfig(
            "vless xhttp currently supports alpn: [h2], [h3], or [http/1.1]"
                .to_owned(),
        )),
    }
}

fn build_xhttp_transport(
    s: &OutboundVless,
) -> Result<Option<Box<dyn Transport>>, Error> {
    let xhttp_opts = s.xhttp_opts.as_ref().ok_or_else(|| {
        Error::InvalidConfig("xhttp_opts is required for vless xhttp".to_owned())
    })?;

    validate_xhttp_opts(xhttp_opts)?;
    let http_version = resolve_xhttp_http_version(s)?;
    let reuse_policy = build_xhttp_reuse_policy(xhttp_opts.reuse_settings.as_ref())?;
    validate_xhttp_runtime_reuse_support(reuse_policy.as_ref())?;
    let mode = parse_xhttp_mode(xhttp_opts)?;
    let metadata = build_xhttp_metadata_config(xhttp_opts)?;
    let uplink = build_xhttp_uplink_config(xhttp_opts, mode)?;
    let padding = build_xhttp_padding_config(xhttp_opts)?;
    let session = build_xhttp_session_config(xhttp_opts)?;
    let extra = xhttp_opts.extra.as_ref();
    let upload_settings = xhttp_opts.upload_settings.as_ref();
    let upload_xhttp_settings =
        upload_settings.and_then(|settings| settings.xhttp_settings.as_ref());
    let upload_security =
        upload_settings.and_then(|settings| settings.security.as_deref());
    let own_primary_security = matches!(
        http_version,
        XhttpHttpVersion::Http1 | XhttpHttpVersion::Http3
    ) && (s.tls.unwrap_or(false)
        || s.reality_opts.is_some());
    let upload_endpoint =
        build_xhttp_upload_endpoint_config(s, own_primary_security)?;
    let upload_uses_security = upload_endpoint
        .as_ref()
        .is_some_and(|endpoint| !matches!(endpoint.security, XhttpSecurity::None));
    let auto_reality = upload_endpoint
        .as_ref()
        .is_some_and(|endpoint| matches!(endpoint.security, XhttpSecurity::Reality))
        || (upload_endpoint.is_none() && s.reality_opts.is_some());

    Ok(Some(Box::new(
        XhttpClient::new(
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
                &metadata,
            ),
            upload_xhttp_settings
                .and_then(|settings| settings.host.clone())
                .or_else(|| xhttp_opts.host.clone()),
            merged_xhttp_headers(
                xhttp_opts.headers.clone(),
                extra.and_then(|value| value.headers.clone()),
                upload_xhttp_settings.and_then(|settings| settings.headers.clone()),
            ),
            if upload_endpoint.is_some() {
                upload_uses_security
            } else {
                matches!(upload_security, Some("tls" | "reality"))
                    || s.tls.unwrap_or_default()
                    || s.reality_opts.is_some()
            },
            mode,
            resolve_xhttp_max_each_post_bytes(xhttp_opts),
            resolve_xhttp_no_grpc_header(xhttp_opts),
            resolve_xhttp_min_posts_interval_ms(xhttp_opts),
            build_xhttp_download_config(s, xhttp_opts, &metadata, http_version)?,
        )
        .with_upload_endpoint(upload_endpoint)
        .with_http_version(http_version)
        .with_auto_reality(auto_reality)
        .with_metadata(metadata)
        .with_uplink(uplink)
        .with_padding(padding)
        .with_session(session)
        .with_reuse_policy(reuse_policy),
    )))
}

fn build_xhttp_upload_endpoint_config(
    s: &OutboundVless,
    own_primary_security: bool,
) -> Result<Option<XhttpEndpointConfig>, Error> {
    let xhttp_opts = s.xhttp_opts.as_ref().ok_or_else(|| {
        Error::InvalidConfig("xhttp_opts is required for vless xhttp".to_owned())
    })?;
    let upload = xhttp_opts.upload_settings.as_ref();
    if upload.is_none() && !own_primary_security {
        return Ok(None);
    }
    let nested = upload.and_then(|settings| settings.xhttp_settings.as_ref());
    let (server, port) = xhttp_upload_server_port(s);

    let upload_reality_opts =
        match upload.and_then(|settings| settings.reality_opts.as_ref()) {
            Some(opts) if opts.public_key.trim().is_empty() => None,
            Some(opts) => Some(opts),
            None => s.reality_opts.as_ref(),
        };
    let tls_enabled = upload
        .and_then(|settings| settings.tls)
        .or(s.tls)
        .unwrap_or(false);
    let security_name = upload
        .and_then(|settings| settings.security.as_deref())
        .unwrap_or_else(|| {
            if upload_reality_opts.is_some() {
                "reality"
            } else if tls_enabled {
                "tls"
            } else {
                "none"
            }
        });
    let security = match security_name {
        "none" => XhttpSecurity::None,
        "tls" => XhttpSecurity::Tls,
        "reality" => XhttpSecurity::Reality,
        other => {
            return Err(Error::InvalidConfig(format!(
                "unsupported xhttp upload_settings security: {other}"
            )));
        }
    };

    let host = upload
        .and_then(|settings| settings.host.clone())
        .or_else(|| nested.and_then(|settings| settings.host.clone()))
        .or_else(|| xhttp_opts.host.clone());
    let server_name = upload
        .and_then(|settings| settings.sni.clone())
        .or_else(|| upload.and_then(|settings| settings.server_name.clone()))
        .or_else(|| {
            upload
                .and_then(|settings| settings.tls_settings.as_ref())
                .and_then(|settings| settings.server_name.clone())
        })
        .or_else(|| s.sni.clone())
        .or_else(|| s.server_name.clone())
        .or_else(|| host.clone())
        .unwrap_or_else(|| server.clone());
    let alpn_protocols = upload
        .and_then(|settings| settings.alpn.clone())
        .or_else(|| s.alpn.clone())
        .unwrap_or_else(|| vec!["h2".to_owned()]);
    let expected_alpn = match s.alpn.as_deref() {
        Some([value]) if value == "h3" => "h3",
        _ if own_primary_security => "http/1.1",
        _ => "h2",
    };
    if alpn_protocols.as_slice() != [expected_alpn] {
        return Err(Error::InvalidConfig(format!(
            "xhttp upload endpoint currently requires alpn: [{expected_alpn}]"
        )));
    }

    let skip_cert_verify = upload
        .and_then(|settings| settings.skip_cert_verify)
        .or_else(|| {
            upload
                .and_then(|settings| settings.tls_settings.as_ref())
                .and_then(|settings| settings.insecure)
        })
        .or(s.skip_cert_verify)
        .unwrap_or(false);
    let fingerprint = upload
        .and_then(|settings| settings.fingerprint.clone())
        .or_else(|| s.fingerprint.clone());
    let verify_name = upload
        .and_then(|settings| settings.name_cert_verify.clone())
        .or_else(|| s.name_cert_verify.clone());
    let tls_cert = upload
        .and_then(|settings| settings.certificate.clone())
        .or_else(|| s.certificate.clone());
    let tls_key = upload
        .and_then(|settings| settings.private_key.clone())
        .or_else(|| s.private_key.clone());
    match (&tls_cert, &tls_key) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(Error::InvalidConfig(
                "xhttp upload endpoint certificate and private-key must both be set or both omitted".to_owned(),
            ));
        }
    }

    let client_fingerprint = upload
        .and_then(|settings| settings.client_fingerprint.as_deref())
        .or(s.client_fingerprint.as_deref());
    if let Some(client_fingerprint) = client_fingerprint
        && !matches!(
            &security,
            XhttpSecurity::Reality if client_fingerprint == "chrome"
        )
        && client_fingerprint != "none"
    {
        warn!(
            "xhttp upload endpoint client-fingerprint '{client_fingerprint}' is not supported yet, ignoring it"
        );
    }

    let reality = build_xhttp_reality_config(
        upload_reality_opts,
        &security,
        &server_name,
        Some(alpn_protocols.as_slice()),
        "upload endpoint",
    )?;

    Ok(Some(XhttpEndpointConfig {
        server,
        port,
        security,
        server_name,
        alpn_protocols,
        skip_cert_verify,
        fingerprint,
        verify_name,
        tls_cert,
        tls_key,
        reality,
    }))
}

fn build_xhttp_download_config(
    s: &OutboundVless,
    xhttp_opts: &XhttpOpt,
    metadata: &XhttpMetadataConfig,
    http_version: XhttpHttpVersion,
) -> Result<Option<XhttpDownloadConfig>, Error> {
    let Some(download_settings) = resolve_xhttp_download_settings(xhttp_opts) else {
        return Ok(None);
    };

    validate_xhttp_download_settings(download_settings)?;

    let xhttp_settings = download_settings.xhttp_settings.as_ref();
    let download_server = if download_settings.address.is_empty() {
        s.common_opts.server.clone()
    } else {
        download_settings.address.clone()
    };
    let download_port = if download_settings.port == 0 {
        s.common_opts.port
    } else {
        download_settings.port
    };
    let reuse_policy = build_xhttp_reuse_policy(
        download_settings
            .reuse_settings
            .as_ref()
            .or_else(|| {
                xhttp_settings.and_then(|settings| settings.reuse_settings.as_ref())
            })
            .or(xhttp_opts.reuse_settings.as_ref()),
    )?;
    validate_xhttp_runtime_reuse_support(reuse_policy.as_ref())?;
    let host = download_settings
        .host
        .clone()
        .or_else(|| xhttp_settings.and_then(|settings| settings.host.clone()))
        .or_else(|| xhttp_opts.host.clone());
    let download_reality_opts = match download_settings.reality_opts.as_ref() {
        Some(opts) if opts.public_key.trim().is_empty() => None,
        Some(opts) => Some(opts),
        None => s.reality_opts.as_ref(),
    };
    let download_tls = download_settings.tls.or(s.tls).unwrap_or(false);
    let security_name = download_settings.security.as_deref().unwrap_or_else(|| {
        if download_reality_opts.is_some() {
            "reality"
        } else if download_tls {
            "tls"
        } else {
            "none"
        }
    });
    let security = match security_name {
        "none" => XhttpSecurity::None,
        "tls" => XhttpSecurity::Tls,
        "reality" => XhttpSecurity::Reality,
        other => {
            return Err(Error::InvalidConfig(format!(
                "unsupported xhttp download_settings security: {other}"
            )));
        }
    };
    if matches!(http_version, XhttpHttpVersion::Http3)
        && !matches!(security, XhttpSecurity::Tls)
    {
        return Err(Error::InvalidConfig(
            "xhttp HTTP/3 download-settings currently supports standard TLS only"
                .to_owned(),
        ));
    }

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
        .or_else(|| s.sni.clone())
        .or_else(|| s.server_name.clone())
        .or_else(|| host.clone())
        .unwrap_or_else(|| download_server.clone());

    let skip_cert_verify = download_settings
        .skip_cert_verify
        .or_else(|| {
            download_settings
                .tls_settings
                .as_ref()
                .and_then(|settings| settings.insecure)
        })
        .or(s.skip_cert_verify)
        .unwrap_or(false);
    let expected_alpn = match http_version {
        XhttpHttpVersion::Http1 => "http/1.1",
        XhttpHttpVersion::Http2 => "h2",
        XhttpHttpVersion::Http3 => "h3",
    };
    let alpn_protocols = download_settings
        .alpn
        .clone()
        .or_else(|| s.alpn.clone())
        .unwrap_or_else(|| vec![expected_alpn.to_owned()]);
    if alpn_protocols.as_slice() != [expected_alpn] {
        return Err(Error::InvalidConfig(format!(
            "xhttp download-settings currently requires alpn: [{expected_alpn}]"
        )));
    }

    let tls_cert = download_settings
        .certificate
        .clone()
        .or_else(|| s.certificate.clone());
    let tls_key = download_settings
        .private_key
        .clone()
        .or_else(|| s.private_key.clone());
    match (&tls_cert, &tls_key) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(Error::InvalidConfig(
                "xhttp download-settings certificate and private-key must both be set or both omitted".to_owned(),
            ));
        }
    }

    let client_fingerprint = download_settings
        .client_fingerprint
        .as_deref()
        .or(s.client_fingerprint.as_deref());
    if let Some(client_fingerprint) = client_fingerprint
        && !matches!(
            &security,
            XhttpSecurity::Reality if client_fingerprint == "chrome"
        )
        && client_fingerprint != "none"
    {
        warn!(
            "xhttp download-settings client-fingerprint '{client_fingerprint}' is not supported yet, ignoring it"
        );
    }

    let reality = build_xhttp_reality_config(
        download_reality_opts,
        &security,
        &server_name,
        Some(alpn_protocols.as_slice()),
        "download-settings",
    )?;

    let inherited_headers = merged_xhttp_headers(
        xhttp_opts.headers.clone(),
        xhttp_opts
            .extra
            .as_ref()
            .and_then(|extra| extra.headers.clone()),
        xhttp_settings.and_then(|settings| settings.headers.clone()),
    );

    Ok(Some(XhttpDownloadConfig {
        server: download_server,
        port: download_port,
        path: normalized_xhttp_path(
            download_settings
                .path
                .as_deref()
                .or_else(|| {
                    xhttp_settings.and_then(|settings| settings.path.as_deref())
                })
                .or(xhttp_opts.path.as_deref()),
            metadata,
        ),
        host,
        headers: merged_xhttp_headers(
            Some(inherited_headers),
            None,
            download_settings.headers.clone(),
        ),
        security,
        server_name,
        alpn_protocols,
        skip_cert_verify,
        fingerprint: download_settings
            .fingerprint
            .clone()
            .or_else(|| s.fingerprint.clone()),
        verify_name: download_settings
            .name_cert_verify
            .clone()
            .or_else(|| s.name_cert_verify.clone()),
        tls_cert,
        tls_key,
        reality,
        reuse_policy,
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
        .sc_max_each_post_bytes
        .or_else(|| {
            xhttp_opts
                .extra
                .as_ref()
                .and_then(|extra| extra.sc_max_each_post_bytes)
        })
        .or(xhttp_opts.max_each_post_bytes)
        .unwrap_or(1_000_000)
}

fn resolve_xhttp_no_grpc_header(xhttp_opts: &XhttpOpt) -> bool {
    xhttp_opts
        .no_grpc_header
        .or_else(|| {
            xhttp_opts
                .extra
                .as_ref()
                .and_then(|extra| extra.no_grpc_header)
        })
        .unwrap_or(false)
}

fn resolve_xhttp_min_posts_interval_ms(xhttp_opts: &XhttpOpt) -> Option<u64> {
    Some(
        xhttp_opts
            .sc_min_posts_interval_ms
            .or_else(|| {
                xhttp_opts
                    .extra
                    .as_ref()
                    .and_then(|extra| extra.sc_min_posts_interval_ms)
            })
            .unwrap_or(30),
    )
}

#[cfg(feature = "reality")]
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
                        .cloned()
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
    alpn_protocols: Option<Vec<String>>,
) -> Result<RealityClient, Error> {
    let public_key = decode_reality_public_key(&reality_opts.public_key)?;
    let short_id = decode_reality_short_id(reality_opts.short_id.as_deref())?;
    Ok(RealityClient::new_with_alpn(
        public_key,
        short_id,
        server_name,
        Vec::new(),
        alpn_protocols.unwrap_or_default(),
    ))
}

fn build_xhttp_reality_config(
    reality_opts: Option<&OutboundTrojanRealityOpts>,
    security: &XhttpSecurity,
    server_name: &str,
    alpn_protocols: Option<&[String]>,
    label: &str,
) -> Result<Option<XhttpRealityConfig>, Error> {
    if !matches!(security, XhttpSecurity::Reality) {
        return Ok(None);
    }

    #[cfg(feature = "reality")]
    {
        let reality_opts = reality_opts.ok_or_else(|| {
            Error::InvalidConfig(format!(
                "xhttp {label} security reality requires reality-opts"
            ))
        })?;
        let public_key = decode_reality_public_key(&reality_opts.public_key)?;
        let short_id = decode_reality_short_id(reality_opts.short_id.as_deref())?;
        Ok(Some(XhttpRealityConfig {
            public_key,
            short_id,
            server_name: server_name.to_owned(),
            alpn_protocols: alpn_protocols
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| vec!["h2".to_owned()]),
        }))
    }
    #[cfg(not(feature = "reality"))]
    {
        let _ = reality_opts;
        let _ = server_name;
        let _ = alpn_protocols;
        Err(Error::InvalidConfig(format!(
            "xhttp {label} reality requires reality feature"
        )))
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

fn validate_xhttp_headers(
    headers: Option<&std::collections::HashMap<String, String>>,
    label: &str,
) -> Result<(), Error> {
    if headers
        .into_iter()
        .flat_map(|headers| headers.keys())
        .any(|key| key.eq_ignore_ascii_case("host"))
    {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} headers must not contain Host; use the host field instead"
        )));
    }

    Ok(())
}

fn validate_xhttp_opts(xhttp_opts: &XhttpOpt) -> Result<(), Error> {
    validate_xhttp_headers(xhttp_opts.headers.as_ref(), "xhttp-opts")?;
    validate_xhttp_headers(
        xhttp_opts
            .extra
            .as_ref()
            .and_then(|extra| extra.headers.as_ref()),
        "extra",
    )?;

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

    if matches!(xhttp_opts.sc_max_each_post_bytes, Some(0)) {
        return Err(Error::InvalidConfig(
            "xhttp sc_max_each_post_bytes must be greater than zero".to_owned(),
        ));
    }

    if matches!(xhttp_opts.sc_min_posts_interval_ms, Some(0)) {
        return Err(Error::InvalidConfig(
            "xhttp sc_min_posts_interval_ms must be greater than zero".to_owned(),
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
    validate_xhttp_endpoint_settings(upload_settings, "upload_settings", true)
}

fn validate_xhttp_download_settings(
    download_settings: &XhttpDownloadSettings,
) -> Result<(), Error> {
    validate_xhttp_endpoint_settings(download_settings, "download_settings", false)
}

fn validate_xhttp_endpoint_settings(
    settings: &XhttpDownloadSettings,
    label: &str,
    require_endpoint: bool,
) -> Result<(), Error> {
    if require_endpoint && settings.address.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} address must not be empty"
        )));
    }

    if require_endpoint && settings.port == 0 {
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

    validate_xhttp_headers(settings.headers.as_ref(), label)?;
    validate_xhttp_headers(
        settings
            .xhttp_settings
            .as_ref()
            .and_then(|settings| settings.headers.as_ref()),
        label,
    )?;

    if matches!(settings.path.as_deref(), Some(""))
        || matches!(
            settings
                .xhttp_settings
                .as_ref()
                .and_then(|settings| settings.path.as_deref()),
            Some("")
        )
    {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} path must not be empty"
        )));
    }

    #[cfg(not(feature = "tls"))]
    if matches!(settings.security.as_deref(), Some("tls"))
        || settings.tls.unwrap_or(false)
    {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} tls requires tls feature"
        )));
    }

    #[cfg(not(feature = "reality"))]
    if matches!(settings.security.as_deref(), Some("reality"))
        || settings.reality_opts.is_some()
    {
        return Err(Error::InvalidConfig(format!(
            "xhttp {label} reality requires reality feature"
        )));
    }

    Ok(())
}

fn build_xhttp_reuse_policy(
    settings: Option<&XhttpReuseSettings>,
) -> Result<Option<XhttpReusePolicy>, Error> {
    let Some(settings) = settings else {
        return Ok(None);
    };

    let parse_range = |value: Option<&str>, field: &str| {
        value
            .map(|raw| {
                XhttpReuseValueRange::parse(raw, field)
                    .map_err(|err| Error::InvalidConfig(err.to_string()))
            })
            .transpose()
    };

    let h_keep_alive_period = settings
        .h_keep_alive_period
        .as_deref()
        .unwrap_or("0")
        .trim()
        .parse::<i64>()
        .map_err(|err| {
            Error::InvalidConfig(format!("invalid xhttp h-keep-alive-period: {err}"))
        })?;

    let policy = XhttpReusePolicy {
        max_concurrency: parse_range(
            settings.max_concurrency.as_deref(),
            "max-concurrency",
        )?,
        max_connections: parse_range(
            settings.max_connections.as_deref(),
            "max-connections",
        )?,
        c_max_reuse_times: parse_range(
            settings.c_max_reuse_times.as_deref(),
            "c-max-reuse-times",
        )?,
        h_max_request_times: parse_range(
            settings.h_max_request_times.as_deref(),
            "h-max-request-times",
        )?,
        h_max_reusable_secs: parse_range(
            settings.h_max_reusable_secs.as_deref(),
            "h-max-reusable-secs",
        )?,
        h_keep_alive_period,
    };

    policy
        .validate()
        .map_err(|err| Error::InvalidConfig(err.to_string()))?;
    Ok(Some(policy))
}

fn validate_xhttp_runtime_reuse_support(
    policy: Option<&XhttpReusePolicy>,
) -> Result<(), Error> {
    let Some(policy) = policy else {
        return Ok(());
    };

    if policy.h_keep_alive_period < -1 {
        return Err(Error::InvalidConfig(
            "xhttp reuse-settings h-keep-alive-period must be -1, 0, or a positive number"
                .to_owned(),
        ));
    }

    Ok(())
}

fn build_xhttp_session_config(
    xhttp_opts: &XhttpOpt,
) -> Result<XhttpSessionIdConfig, Error> {
    let table = xhttp_opts.session_table.as_deref().unwrap_or("");
    if table.is_empty() || table == "uuid" {
        return Ok(XhttpSessionIdConfig::default());
    }

    let length = parse_xhttp_session_length(xhttp_opts.session_length.as_deref())?;
    XhttpSessionIdConfig::from_table(table, length).map_err(|err| {
        Error::InvalidConfig(format!("invalid xhttp session config: {err}"))
    })
}

fn parse_xhttp_session_length(
    value: Option<&str>,
) -> Result<XhttpChunkSizeRange, Error> {
    let raw = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("16-32");

    let parse_number = |part: &str| {
        part.trim().parse::<usize>().map_err(|err| {
            Error::InvalidConfig(format!(
                "invalid xhttp session-length '{raw}': {err}"
            ))
        })
    };

    let (min, max) = if let Some((min, max)) = raw.split_once('-') {
        (parse_number(min)?, parse_number(max)?)
    } else {
        let value = parse_number(raw)?;
        (value, value)
    };

    if min == 0 || min > max {
        return Err(Error::InvalidConfig(format!(
            "invalid xhttp session-length range: {raw}"
        )));
    }

    Ok(XhttpChunkSizeRange { min, max })
}

fn build_xhttp_padding_config(
    xhttp_opts: &XhttpOpt,
) -> Result<XhttpPaddingConfig, Error> {
    let defaults = XhttpPaddingConfig::default();
    let bytes = parse_xhttp_padding_bytes(
        xhttp_opts.x_padding_bytes.as_deref(),
        defaults.bytes,
    )?;
    let placement = match xhttp_opts
        .x_padding_placement
        .as_deref()
        .unwrap_or("queryInHeader")
    {
        "cookie" => XhttpPaddingPlacement::Cookie,
        "header" => XhttpPaddingPlacement::Header,
        "query" => XhttpPaddingPlacement::Query,
        "queryInHeader" | "query-in-header" => XhttpPaddingPlacement::QueryInHeader,
        other => {
            return Err(Error::InvalidConfig(format!(
                "unsupported xhttp x-padding-placement: {other}"
            )));
        }
    };
    let method = match xhttp_opts.x_padding_method.as_deref().unwrap_or("repeat-x") {
        "repeat-x" => XhttpPaddingMethod::RepeatX,
        "tokenish" => XhttpPaddingMethod::Tokenish,
        other => {
            return Err(Error::InvalidConfig(format!(
                "unsupported xhttp x-padding-method: {other}"
            )));
        }
    };

    Ok(XhttpPaddingConfig {
        bytes,
        obfs_mode: xhttp_opts.x_padding_obfs_mode.unwrap_or(false),
        key: xhttp_opts
            .x_padding_key
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(defaults.key.as_str())
            .to_owned(),
        header: xhttp_opts
            .x_padding_header
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(defaults.header.as_str())
            .to_owned(),
        placement,
        method,
    })
}

fn parse_xhttp_padding_bytes(
    value: Option<&str>,
    default: XhttpChunkSizeRange,
) -> Result<XhttpChunkSizeRange, Error> {
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };

    let parse_number = |part: &str| {
        part.trim().parse::<usize>().map_err(|err| {
            Error::InvalidConfig(format!(
                "invalid xhttp x-padding-bytes '{raw}': {err}"
            ))
        })
    };

    let (min, max) = if let Some((min, max)) = raw.split_once('-') {
        (parse_number(min)?, parse_number(max)?)
    } else {
        let value = parse_number(raw)?;
        (value, value)
    };

    if min == 0 || max == 0 || min > max {
        return Err(Error::InvalidConfig(format!(
            "invalid xhttp x-padding-bytes range: {raw}; values must be greater than zero"
        )));
    }

    Ok(XhttpChunkSizeRange { min, max })
}

fn build_xhttp_uplink_config(
    xhttp_opts: &XhttpOpt,
    mode: XhttpMode,
) -> Result<XhttpUplinkConfig, Error> {
    let method = xhttp_opts
        .uplink_http_method
        .as_deref()
        .unwrap_or("POST")
        .trim()
        .to_ascii_uppercase();
    if !matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(Error::InvalidConfig(format!(
            "unsupported xhttp uplink-http-method: {method}"
        )));
    }

    let placement = match xhttp_opts
        .uplink_data_placement
        .as_deref()
        .unwrap_or("body")
    {
        "body" => XhttpUplinkDataPlacement::Body,
        "header" => XhttpUplinkDataPlacement::Header,
        "cookie" => XhttpUplinkDataPlacement::Cookie,
        other => {
            return Err(Error::InvalidConfig(format!(
                "unsupported xhttp uplink-data-placement: {other}"
            )));
        }
    };

    if !matches!(placement, XhttpUplinkDataPlacement::Body)
        && !matches!(mode, XhttpMode::PacketUp)
    {
        return Err(Error::InvalidConfig(
            "xhttp header/cookie uplink-data-placement requires packet-up mode"
                .to_owned(),
        ));
    }

    let key = match placement {
        XhttpUplinkDataPlacement::Body => None,
        XhttpUplinkDataPlacement::Header => Some(
            xhttp_opts
                .uplink_data_key
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("X-Data")
                .to_owned(),
        ),
        XhttpUplinkDataPlacement::Cookie => Some(
            xhttp_opts
                .uplink_data_key
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("x_data")
                .to_owned(),
        ),
    };

    let chunk_size = parse_xhttp_uplink_chunk_size(
        xhttp_opts.uplink_chunk_size.as_deref(),
        placement,
    )?;

    Ok(XhttpUplinkConfig {
        method,
        placement,
        key,
        chunk_size,
    })
}

fn parse_xhttp_uplink_chunk_size(
    value: Option<&str>,
    placement: XhttpUplinkDataPlacement,
) -> Result<XhttpChunkSizeRange, Error> {
    let default = match placement {
        XhttpUplinkDataPlacement::Body => XhttpChunkSizeRange::fixed(1),
        XhttpUplinkDataPlacement::Header => XhttpChunkSizeRange {
            min: 3_000,
            max: 4_000,
        },
        XhttpUplinkDataPlacement::Cookie => XhttpChunkSizeRange {
            min: 2 * 1024,
            max: 3 * 1024,
        },
    };

    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };

    let parse_number = |part: &str| {
        part.trim().parse::<usize>().map_err(|err| {
            Error::InvalidConfig(format!(
                "invalid xhttp uplink-chunk-size '{raw}': {err}"
            ))
        })
    };

    let (mut min, mut max) = if let Some((min, max)) = raw.split_once('-') {
        (parse_number(min)?, parse_number(max)?)
    } else {
        let value = parse_number(raw)?;
        (value, value)
    };

    if min == 0 && max == 0 {
        return Ok(default);
    }
    if min > max {
        return Err(Error::InvalidConfig(format!(
            "invalid xhttp uplink-chunk-size range: {raw}"
        )));
    }

    if !matches!(placement, XhttpUplinkDataPlacement::Body) {
        min = min.max(64);
        max = max.max(min);
    } else {
        min = min.max(1);
        max = max.max(min);
    }

    Ok(XhttpChunkSizeRange { min, max })
}

fn build_xhttp_metadata_config(
    xhttp_opts: &XhttpOpt,
) -> Result<XhttpMetadataConfig, Error> {
    let session_placement = parse_xhttp_metadata_placement(
        xhttp_opts.session_placement.as_deref(),
        "session-placement",
    )?;
    let seq_placement = parse_xhttp_metadata_placement(
        xhttp_opts.seq_placement.as_deref(),
        "seq-placement",
    )?;

    if matches!(session_placement, XhttpMetadataPlacement::Path)
        && !matches!(seq_placement, XhttpMetadataPlacement::Path)
    {
        return Err(Error::InvalidConfig(
            "xhttp seq-placement must be path when session-placement is path"
                .to_owned(),
        ));
    }

    Ok(XhttpMetadataConfig {
        session_placement,
        session_key: normalize_xhttp_metadata_key(
            session_placement,
            xhttp_opts.session_key.as_deref(),
            "X-Session",
            "x_session",
        ),
        seq_placement,
        seq_key: normalize_xhttp_metadata_key(
            seq_placement,
            xhttp_opts.seq_key.as_deref(),
            "X-Seq",
            "x_seq",
        ),
    })
}

fn normalize_xhttp_metadata_key(
    placement: XhttpMetadataPlacement,
    configured: Option<&str>,
    header_default: &str,
    other_default: &str,
) -> Option<String> {
    if let Some(configured) = configured.filter(|value| !value.is_empty()) {
        return Some(configured.to_owned());
    }

    match placement {
        XhttpMetadataPlacement::Path => None,
        XhttpMetadataPlacement::Header => Some(header_default.to_owned()),
        XhttpMetadataPlacement::Query | XhttpMetadataPlacement::Cookie => {
            Some(other_default.to_owned())
        }
    }
}

fn parse_xhttp_metadata_placement(
    value: Option<&str>,
    field: &str,
) -> Result<XhttpMetadataPlacement, Error> {
    match value.unwrap_or("path") {
        "path" => Ok(XhttpMetadataPlacement::Path),
        "query" => Ok(XhttpMetadataPlacement::Query),
        "cookie" => Ok(XhttpMetadataPlacement::Cookie),
        "header" => Ok(XhttpMetadataPlacement::Header),
        other => Err(Error::InvalidConfig(format!(
            "unsupported xhttp {field}: {other}"
        ))),
    }
}

fn parse_xhttp_mode(xhttp_opts: &XhttpOpt) -> Result<XhttpMode, Error> {
    let mode = xhttp_opts.mode.as_deref().unwrap_or("auto");
    match mode {
        "stream-one" => Ok(XhttpMode::StreamOne),
        "stream-up" => Ok(XhttpMode::StreamUp),
        "packet-up" | "split" => Ok(XhttpMode::PacketUp),
        "auto" => Ok(XhttpMode::Auto),
        other => Err(Error::InvalidConfig(format!(
            "unsupported xhttp mode: {other}"
        ))),
    }
}

fn normalized_xhttp_path(
    path: Option<&str>,
    metadata: &XhttpMetadataConfig,
) -> String {
    let raw = path.unwrap_or("/");
    let (raw_path, raw_query) = raw
        .split_once('?')
        .map_or((raw, None), |(path, query)| (path, Some(query)));

    let mut normalized = if raw_path.starts_with('/') {
        raw_path.to_owned()
    } else {
        format!("/{raw_path}")
    };

    let needs_path_suffix =
        matches!(metadata.session_placement, XhttpMetadataPlacement::Path)
            || matches!(metadata.seq_placement, XhttpMetadataPlacement::Path);
    if needs_path_suffix && !normalized.ends_with('/') {
        normalized.push('/');
    }

    if let Some(query) = raw_query.filter(|query| !query.is_empty()) {
        normalized.push('?');
        normalized.push_str(query);
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

    let server_name = resolve_reality_server_name(s);
    let reality_opts = s.reality_opts.as_ref().expect("checked is_some above");
    let client = build_reality_transport_from_opts(
        reality_opts,
        server_name,
        s.alpn.clone(),
    )?;

    Ok(Some(Box::new(client)))
}

#[cfg(feature = "reality")]
fn resolve_reality_server_name(s: &OutboundVless) -> String {
    s.sni
        .clone()
        .or_else(|| s.server_name.clone())
        .unwrap_or_else(|| s.common_opts.server.clone())
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
fn decode_reality_short_id(short_id: Option<&str>) -> Result<Vec<u8>, Error> {
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
    use crate::config::internal::proxy::{
        CommonConfigOptions, GrpcOpt, OutboundTrojanRealityOpts,
        XhttpDownloadSettings, XhttpDownloadXhttpSettings, XhttpExtra, XhttpOpt,
        XhttpReuseSettings, XhttpUploadSettings,
    };

    use super::{
        OutboundVless, XhttpHttpVersion, XhttpMetadataConfig,
        XhttpMetadataPlacement, XhttpMode, XhttpPaddingMethod,
        XhttpPaddingPlacement, XhttpUplinkDataPlacement, build_tls_transport,
        build_xhttp_download_config, build_xhttp_metadata_config,
        build_xhttp_padding_config, build_xhttp_reuse_policy,
        build_xhttp_session_config, build_xhttp_uplink_config,
        build_xhttp_upload_endpoint_config, normalized_xhttp_path, parse_xhttp_mode,
        resolve_vless_alpn, resolve_xhttp_http_version,
        resolve_xhttp_max_each_post_bytes, resolve_xhttp_min_posts_interval_ms,
        resolve_xhttp_no_grpc_header, validate_vless_config,
    };

    #[cfg(feature = "ws")]
    use crate::config::internal::proxy::WsOpt;

    use super::build_transport;

    #[cfg(feature = "reality")]
    use super::{decode_reality_short_id, resolve_reality_server_name};

    #[cfg(feature = "reality")]
    const TEST_REALITY_PUBLIC_KEY: &str =
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    #[cfg(feature = "reality")]
    #[test]
    fn reality_short_id_accepts_empty_as_empty_short_id() {
        let decoded =
            decode_reality_short_id(Some("")).expect("empty short-id should decode");
        assert!(decoded.is_empty());
    }

    #[cfg(feature = "reality")]
    #[test]
    fn reality_short_id_preserves_variable_length_bytes() {
        let decoded = decode_reality_short_id(Some("85144f63"))
            .expect("short-id should decode");
        assert_eq!(decoded, vec![0x85, 0x14, 0x4f, 0x63]);
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_reality_prefers_sni_for_server_name() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "reality".to_owned(),
                server: "edge.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            server_name: Some("www.apple.com".to_owned()),
            sni: Some("www.amd.com".to_owned()),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: Some("85144f63".to_owned()),
            }),
            ..Default::default()
        };

        assert_eq!(resolve_reality_server_name(&outbound), "www.amd.com");
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_reality_accepts_explicit_alpn_and_chrome_fingerprint() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "reality-alpn".to_owned(),
                server: "edge.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            alpn: Some(vec!["h2".to_owned()]),
            client_fingerprint: Some("chrome".to_owned()),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: None,
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound).expect(
            "reality should accept explicit h2 ALPN with chrome fingerprint",
        );
        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("reality transport should build");
        assert!(
            transport.is_some(),
            "reality handshake transport should be present"
        );
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_reality_allows_client_fingerprint_configuration_with_warning() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "reality-firefox".to_owned(),
                server: "edge.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            client_fingerprint: Some("firefox".to_owned()),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: None,
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound).expect(
            "Reality client-fingerprint should be accepted for config compatibility",
        );
    }

    #[test]
    fn vless_non_reality_allows_client_fingerprint_configuration() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "tls-firefox".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            client_fingerprint: Some("firefox".to_owned()),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("non-Reality TLS client-fingerprint should be accepted for config compatibility");
    }

    #[test]
    fn vless_accepts_default_encryption_values() {
        for encryption in ["", "none"] {
            let outbound = OutboundVless {
                common_opts: CommonConfigOptions {
                    name: "encryption-default".to_owned(),
                    server: "example.com".to_owned(),
                    port: 443,
                    connect_via: None,
                },
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
                encryption: Some(encryption.to_owned()),
                ..Default::default()
            };

            validate_vless_config(&outbound).unwrap_or_else(|err| {
                panic!("default encryption '{encryption}' should pass: {err}")
            });
        }
    }

    #[test]
    fn vless_rejects_malformed_encryption_before_runtime_check() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "encrypted-vless".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            encryption: Some("mlkem768x25519plus.native".to_owned()),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("malformed VLESS Encryption must be rejected");
        assert!(
            err.to_string().contains("invalid vless encryption config"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_recognizes_valid_encryption_before_runtime_rejection() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "encrypted-vless".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            encryption: Some(format!(
                "mlkem768x25519plus.native.1rtt.100-200-300.{key}"
            )),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("runtime handshake is not implemented yet");
        assert!(
            err.to_string().contains(
                "vless encryption config is valid (native.1rtt; padding-blocks=1; x25519-keys=1; mlkem768-keys=0; xor-mode=0; relay-bytes=32; key-hashes=1; padding-bytes=200-300; hello-bytes=1498-1598; write-segments=1; gap-segments=0)"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_rejects_unknown_flow() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "bad-flow".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            flow: Some("xtls-rprx-unknown".to_owned()),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("unknown vless flow must be rejected");
        assert!(
            err.to_string().contains("unsupported vless flow"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_accepts_vision_flow() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "vision".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            flow: Some("xtls-rprx-vision".to_owned()),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("vision flow should remain supported");
    }

    #[test]
    fn vless_explicit_alpn_overrides_transport_default() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "alpn".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            alpn: Some(vec!["h2".to_owned(), "http/1.1".to_owned()]),
            network: Some("tcp".to_owned()),
            ..Default::default()
        };

        assert_eq!(
            resolve_vless_alpn(&outbound, outbound.network.as_deref()),
            Some(vec!["h2".to_owned(), "http/1.1".to_owned()])
        );
    }

    #[test]
    fn vless_xhttp_accepts_plain_http1_packet_up() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-http1".to_owned(),
                server: "example.com".to_owned(),
                port: 80,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            alpn: Some(vec!["http/1.1".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                mode: Some("packet-up".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("plaintext HTTP/1.1 packet-up should validate");
        assert_eq!(
            resolve_xhttp_http_version(&outbound).expect("HTTP version"),
            XhttpHttpVersion::Http1
        );
        assert!(
            build_transport(outbound.network.as_deref(), &outbound)
                .expect("HTTP/1.1 transport should build")
                .is_some()
        );
    }

    #[test]
    fn vless_xhttp_http1_tls_is_owned_by_xhttp_transport() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-http1-tls".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            server_name: Some("example.com".to_owned()),
            alpn: Some(vec!["http/1.1".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                mode: Some("packet-up".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("HTTP/1.1 TLS config should validate");
        let outer =
            build_tls_transport(outbound.network.as_deref(), &outbound, false)
                .expect("outer security decision");
        assert!(
            outer.is_none(),
            "HTTP/1.1 XHTTP must own TLS for every underlying connection"
        );

        let endpoint = build_xhttp_upload_endpoint_config(&outbound, true)
            .expect("primary TLS endpoint should build")
            .expect("HTTP/1.1 TLS should create an endpoint");
        assert!(matches!(
            endpoint.security,
            crate::proxy::transport::XhttpSecurity::Tls
        ));
        assert_eq!(endpoint.alpn_protocols, vec!["http/1.1".to_owned()]);
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_xhttp_http1_reality_is_owned_by_xhttp_transport() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-http1-reality".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            server_name: Some("www.example.com".to_owned()),
            alpn: Some(vec!["http/1.1".to_owned()]),
            network: Some("xhttp".to_owned()),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: Some("85144f63".to_owned()),
            }),
            xhttp_opts: Some(XhttpOpt {
                mode: Some("packet-up".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("HTTP/1.1 Reality config should validate");
        assert_eq!(
            resolve_xhttp_http_version(&outbound).expect("HTTP version"),
            XhttpHttpVersion::Http1
        );

        let outer =
            build_tls_transport(outbound.network.as_deref(), &outbound, false)
                .expect("outer security decision");
        assert!(
            outer.is_none(),
            "HTTP/1.1 XHTTP must own Reality for every underlying connection"
        );

        let endpoint = build_xhttp_upload_endpoint_config(&outbound, true)
            .expect("primary Reality endpoint should build")
            .expect("HTTP/1.1 Reality should create an endpoint");
        assert!(matches!(
            endpoint.security,
            crate::proxy::transport::XhttpSecurity::Reality
        ));
        assert_eq!(endpoint.alpn_protocols, vec!["http/1.1".to_owned()]);
        assert!(endpoint.reality.is_some());

        crate::proxy::vless::Handler::try_from(&outbound)
            .expect("HTTP/1.1 Reality handler should build");
    }

    #[cfg(feature = "xhttp-h3")]
    #[test]
    fn vless_xhttp_accepts_http3_stream_one_tls() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-h3".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h3".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                mode: Some("stream-one".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound).expect("xhttp h3 should validate");
        assert_eq!(
            resolve_xhttp_http_version(&outbound).expect("HTTP version"),
            XhttpHttpVersion::Http3
        );
        let endpoint = build_xhttp_upload_endpoint_config(&outbound, true)
            .expect("HTTP/3 TLS endpoint should build")
            .expect("HTTP/3 should own TLS security");
        assert!(matches!(
            endpoint.security,
            crate::proxy::transport::XhttpSecurity::Tls
        ));
        assert_eq!(endpoint.alpn_protocols, vec!["h3".to_owned()]);
        crate::proxy::vless::Handler::try_from(&outbound)
            .expect("HTTP/3 VLESS handler should build");
    }

    #[cfg(feature = "xhttp-h3")]
    #[test]
    fn vless_xhttp_accepts_http3_packet_up_tls() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-h3-packet-up".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h3".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                mode: Some("packet-up".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound).expect("HTTP/3 packet-up should validate");
        crate::proxy::vless::Handler::try_from(&outbound)
            .expect("HTTP/3 packet-up handler should build");
    }

    #[cfg(feature = "xhttp-h3")]
    #[test]
    fn vless_xhttp_accepts_http3_stream_up_tls() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-h3-stream-up".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h3".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                mode: Some("stream-up".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound).expect("HTTP/3 stream-up should validate");
        crate::proxy::vless::Handler::try_from(&outbound)
            .expect("HTTP/3 stream-up handler should build");
    }

    #[cfg(feature = "xhttp-h3")]
    #[test]
    fn vless_xhttp_http3_accepts_upload_reuse() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-h3-reuse".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h3".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                mode: Some("stream-one".to_owned()),
                reuse_settings: Some(XhttpReuseSettings {
                    max_concurrency: Some("2".to_owned()),
                    c_max_reuse_times: Some("4".to_owned()),
                    h_max_request_times: Some("8".to_owned()),
                    h_max_reusable_secs: Some("60".to_owned()),
                    h_keep_alive_period: Some("0".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound).expect("HTTP/3 reuse should validate");
        crate::proxy::vless::Handler::try_from(&outbound)
            .expect("HTTP/3 reuse handler should build");
    }

    #[cfg(feature = "xhttp-h3")]
    #[test]
    fn vless_xhttp_http3_accepts_nonzero_keepalive_period() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-h3-keepalive".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h3".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                mode: Some("stream-one".to_owned()),
                reuse_settings: Some(XhttpReuseSettings {
                    h_keep_alive_period: Some("10".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("HTTP/3 nonzero keepalive should validate");
        crate::proxy::vless::Handler::try_from(&outbound)
            .expect("HTTP/3 nonzero keepalive handler should build");
    }

    #[cfg(feature = "xhttp-h3")]
    #[test]
    fn vless_xhttp_http3_accepts_download_settings_for_split_modes() {
        for mode in ["stream-up", "packet-up"] {
            let outbound = OutboundVless {
                common_opts: CommonConfigOptions {
                    name: format!("xhttp-h3-download-{mode}"),
                    server: "upload.example.com".to_owned(),
                    port: 443,
                    connect_via: None,
                },
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
                tls: Some(true),
                alpn: Some(vec!["h3".to_owned()]),
                network: Some("xhttp".to_owned()),
                xhttp_opts: Some(XhttpOpt {
                    path: Some("/upload/".to_owned()),
                    mode: Some(mode.to_owned()),
                    reuse_settings: Some(XhttpReuseSettings {
                        max_concurrency: Some("2".to_owned()),
                        c_max_reuse_times: Some("2".to_owned()),
                        h_keep_alive_period: Some("0".to_owned()),
                        ..Default::default()
                    }),
                    download_settings: Some(XhttpDownloadSettings {
                        address: "download.example.com".to_owned(),
                        port: 8443,
                        network: "xhttp".to_owned(),
                        tls: Some(true),
                        alpn: Some(vec!["h3".to_owned()]),
                        path: Some("/download/".to_owned()),
                        reuse_settings: Some(XhttpReuseSettings {
                            max_concurrency: Some("1".to_owned()),
                            c_max_reuse_times: Some("2".to_owned()),
                            h_keep_alive_period: Some("0".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };

            validate_vless_config(&outbound)
                .expect("HTTP/3 split-mode download-settings should validate");
            crate::proxy::vless::Handler::try_from(&outbound)
                .expect("HTTP/3 split-mode download-settings handler should build");
        }
    }

    #[cfg(feature = "xhttp-h3")]
    #[test]
    fn vless_xhttp_http3_stream_one_rejects_download_settings() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-h3-download-stream-one".to_owned(),
                server: "upload.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h3".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                mode: Some("stream-one".to_owned()),
                download_settings: Some(XhttpDownloadSettings {
                    address: "download.example.com".to_owned(),
                    port: 8443,
                    network: "xhttp".to_owned(),
                    tls: Some(true),
                    alpn: Some(vec!["h3".to_owned()]),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("HTTP/3 stream-one must reject separate download-settings");
        assert!(
            err.to_string()
                .contains("stream-one does not support download-settings")
        );
    }

    #[cfg(all(feature = "xhttp-h3", feature = "reality"))]
    #[test]
    fn vless_xhttp_http3_rejects_reality() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-h3-reality".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h3".to_owned()]),
            network: Some("xhttp".to_owned()),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: None,
            }),
            xhttp_opts: Some(XhttpOpt {
                mode: Some("stream-one".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("HTTP/3 Reality is not implemented");
        assert!(err.to_string().contains("standard TLS only"));
    }

    #[cfg(not(feature = "xhttp-h3"))]
    #[test]
    fn vless_xhttp_http3_requires_feature() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-h3-disabled".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h3".to_owned()]),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                mode: Some("stream-one".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("HTTP/3 feature must fail explicitly when disabled");
        assert!(err.to_string().contains("requires xhttp-h3 feature"));
    }

    #[test]
    fn vless_transport_default_alpn_is_preserved_without_override() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "alpn-default".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            ..Default::default()
        };

        assert_eq!(
            resolve_vless_alpn(&outbound, outbound.network.as_deref()),
            Some(vec!["h2".to_owned()])
        );
    }

    #[test]
    fn vless_mtls_requires_certificate_and_private_key_pair() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "mtls-missing-key".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            certificate: Some("client-cert.pem".to_owned()),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("mTLS must require a certificate/private-key pair");
        assert!(
            err.to_string()
                .contains("certificate and private-key must both be set"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_mtls_requires_standard_tls() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "mtls-no-tls".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            certificate: Some("client-cert.pem".to_owned()),
            private_key: Some("client-key.pem".to_owned()),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("mTLS without TLS must fail");
        assert!(
            err.to_string().contains("requires standard TLS"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_mtls_builds_with_standard_tls() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "mtls".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            certificate: Some("client-cert.pem".to_owned()),
            private_key: Some("client-key.pem".to_owned()),
            name_cert_verify: Some("verify.example.com".to_owned()),
            ..Default::default()
        };

        validate_vless_config(&outbound).expect("valid mTLS config should pass");
        let tls = build_tls_transport(outbound.network.as_deref(), &outbound, false)
            .expect("mTLS transport should build");
        assert!(tls.is_some(), "mTLS transport should be present");
    }

    #[test]
    fn vless_mtls_rejects_reality_combination() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "mtls-reality".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            certificate: Some("client-cert.pem".to_owned()),
            private_key: Some("client-key.pem".to_owned()),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
                    .to_owned(),
                short_id: None,
            }),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("mTLS with Reality must not be silently ignored");
        assert!(
            err.to_string()
                .contains("client auth is not supported with reality"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_tls_accepts_certificate_fingerprint_pinning() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "fingerprint".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            fingerprint: Some("0123456789abcdef".to_owned()),
            ..Default::default()
        };

        validate_vless_config(&outbound).expect(
            "certificate fingerprint should be a supported vless TLS option",
        );
        let tls = build_tls_transport(outbound.network.as_deref(), &outbound, false)
            .expect("vless tls with certificate pinning should build");
        assert!(tls.is_some(), "tls transport should be present");
    }

    #[cfg(feature = "ws")]
    #[test]
    fn vless_ws_http_upgrade_and_fast_open_build() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "ws-upgrade".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("ws".to_owned()),
            ws_opts: Some(WsOpt {
                path: Some("/upgrade".to_owned()),
                v2ray_http_upgrade: Some(true),
                v2ray_http_upgrade_fast_open: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("http upgrade fast-open config should validate");
        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("http upgrade transport should build");
        assert!(transport.is_some());
    }

    #[cfg(feature = "ws")]
    #[test]
    fn vless_ws_fast_open_requires_http_upgrade() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "ws-fast-open".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("ws".to_owned()),
            ws_opts: Some(WsOpt {
                v2ray_http_upgrade_fast_open: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("fast-open without HTTP upgrade must fail");
        assert!(
            err.to_string()
                .contains("fast-open requires v2ray-http-upgrade"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "ws")]
    #[test]
    fn vless_ws_http_upgrade_accepts_early_data() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "ws-upgrade-early".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("ws".to_owned()),
            ws_opts: Some(WsOpt {
                max_early_data: Some(2048),
                early_data_header_name: Some("Sec-WebSocket-Protocol".to_owned()),
                v2ray_http_upgrade: Some(true),
                v2ray_http_upgrade_fast_open: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("HTTP upgrade early-data config should validate");
        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("HTTP upgrade early-data transport should build");
        assert!(transport.is_some());
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
    fn vless_grpc_requires_grpc_opts() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "grpc".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("grpc".to_owned()),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("missing grpc_opts must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("grpc_opts is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_grpc_transport_builds_with_h2_alpn() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "grpc".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            network: Some("grpc".to_owned()),
            grpc_opts: Some(GrpcOpt {
                grpc_service_name: Some("grpc-service".to_owned()),
                grpc_user_agent: Some("chimera-grpc/1.0".to_owned()),
                ping_interval: Some(30),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            resolve_vless_alpn(&outbound, outbound.network.as_deref()),
            Some(vec!["h2".to_owned()])
        );
        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("grpc transport should build");
        assert!(transport.is_some(), "grpc transport should be present");

        let tls = build_tls_transport(outbound.network.as_deref(), &outbound, false)
            .expect("grpc tls should build");
        assert!(tls.is_some(), "grpc tls transport should be present");
    }

    #[test]
    fn vless_grpc_accepts_connection_pool_settings() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "grpc-pool".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("grpc".to_owned()),
            grpc_opts: Some(GrpcOpt {
                grpc_service_name: Some("grpc-service".to_owned()),
                max_connections: Some(2),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("grpc connection pool settings should build");
        assert!(transport.is_some());
    }

    #[test]
    fn vless_grpc_accepts_max_streams_pool_mode() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "grpc-max-streams".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("grpc".to_owned()),
            grpc_opts: Some(GrpcOpt {
                grpc_service_name: Some("grpc-service".to_owned()),
                max_streams: Some(16),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("grpc max-streams pool mode should build");
        assert!(transport.is_some());
    }

    #[test]
    fn vless_grpc_rejects_conflicting_stream_pool_settings() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "grpc-pool-conflict".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("grpc".to_owned()),
            grpc_opts: Some(GrpcOpt {
                grpc_service_name: Some("grpc-service".to_owned()),
                max_connections: Some(2),
                max_streams: Some(16),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("conflicting grpc pool settings must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("max-streams conflicts"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_grpc_rejects_non_h2_alpn() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "grpc-http11".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("grpc".to_owned()),
            alpn: Some(vec!["http/1.1".to_owned()]),
            grpc_opts: Some(GrpcOpt {
                grpc_service_name: Some("grpc-service".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = validate_vless_config(&outbound)
            .expect_err("grpc with non-h2 ALPN must fail");
        assert!(
            err.to_string().contains("vless grpc requires alpn: [h2]"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_grpc_reality_builds_security_and_transport_layers() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "grpc-reality".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("grpc".to_owned()),
            client_fingerprint: Some("chrome".to_owned()),
            grpc_opts: Some(GrpcOpt {
                grpc_service_name: Some("grpc-service".to_owned()),
                ..Default::default()
            }),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: None,
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("grpc Reality config should be supported");
        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("grpc transport should build");
        assert!(transport.is_some(), "grpc transport should be present");

        let security =
            build_tls_transport(outbound.network.as_deref(), &outbound, false)
                .expect("grpc Reality security should build");
        assert!(
            security.is_some(),
            "Reality security layer should be present"
        );
    }

    #[test]
    fn vless_xhttp_normalizes_path_and_preserves_raw_query() {
        let metadata = XhttpMetadataConfig::default();

        assert_eq!(
            normalized_xhttp_path(Some("api?ed=2048"), &metadata),
            "/api/?ed=2048"
        );
        assert_eq!(
            normalized_xhttp_path(Some("/api?ed=2048"), &metadata),
            "/api/?ed=2048"
        );
    }

    #[test]
    fn vless_xhttp_non_path_metadata_does_not_force_trailing_slash() {
        let metadata = XhttpMetadataConfig {
            session_placement: XhttpMetadataPlacement::Query,
            session_key: Some("x_session".to_owned()),
            seq_placement: XhttpMetadataPlacement::Header,
            seq_key: Some("X-Seq".to_owned()),
        };

        assert_eq!(
            normalized_xhttp_path(Some("api?ed=2048"), &metadata),
            "/api?ed=2048"
        );
    }

    #[test]
    fn vless_xhttp_metadata_config_defaults_to_path() {
        let opts = XhttpOpt::default();

        let metadata = build_xhttp_metadata_config(&opts)
            .expect("default metadata should parse");

        assert_eq!(metadata.session_placement, XhttpMetadataPlacement::Path);
        assert_eq!(metadata.seq_placement, XhttpMetadataPlacement::Path);
    }

    #[test]
    fn vless_xhttp_metadata_config_accepts_query_and_header() {
        let opts = XhttpOpt {
            session_placement: Some("query".to_owned()),
            session_key: Some("auth".to_owned()),
            seq_placement: Some("header".to_owned()),
            seq_key: Some("X-Seq".to_owned()),
            ..Default::default()
        };

        let metadata =
            build_xhttp_metadata_config(&opts).expect("metadata should parse");

        assert_eq!(metadata.session_placement, XhttpMetadataPlacement::Query);
        assert_eq!(metadata.session_key.as_deref(), Some("auth"));
        assert_eq!(metadata.seq_placement, XhttpMetadataPlacement::Header);
        assert_eq!(metadata.seq_key.as_deref(), Some("X-Seq"));
    }

    #[test]
    fn vless_xhttp_metadata_applies_default_non_path_keys() {
        let query = XhttpOpt {
            session_placement: Some("query".to_owned()),
            seq_placement: Some("header".to_owned()),
            ..Default::default()
        };
        let query_metadata =
            build_xhttp_metadata_config(&query).expect("default keys should apply");
        assert_eq!(query_metadata.session_key.as_deref(), Some("x_session"));
        assert_eq!(query_metadata.seq_key.as_deref(), Some("X-Seq"));

        let cookie = XhttpOpt {
            session_placement: Some("cookie".to_owned()),
            seq_placement: Some("cookie".to_owned()),
            ..Default::default()
        };
        let cookie_metadata = build_xhttp_metadata_config(&cookie)
            .expect("cookie defaults should apply");
        assert_eq!(cookie_metadata.session_key.as_deref(), Some("x_session"));
        assert_eq!(cookie_metadata.seq_key.as_deref(), Some("x_seq"));
    }

    #[test]
    fn vless_xhttp_metadata_requires_path_seq_when_session_is_path() {
        let opts = XhttpOpt {
            session_placement: Some("path".to_owned()),
            seq_placement: Some("query".to_owned()),
            seq_key: Some("seq".to_owned()),
            ..Default::default()
        };

        let err = build_xhttp_metadata_config(&opts)
            .expect_err("path session with non-path seq must fail");

        assert!(
            err.to_string().contains(
                "seq-placement must be path when session-placement is path"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_reuse_policy_parses_ranges_and_negative_keepalive() {
        let settings = XhttpReuseSettings {
            max_concurrency: Some("16-32".to_owned()),
            max_connections: None,
            c_max_reuse_times: Some("0".to_owned()),
            h_max_request_times: Some("600-900".to_owned()),
            h_max_reusable_secs: Some("1800-3000".to_owned()),
            h_keep_alive_period: Some("-1".to_owned()),
        };

        let policy = build_xhttp_reuse_policy(Some(&settings))
            .expect("reuse policy should parse")
            .expect("reuse policy should be present");

        assert_eq!(
            policy.max_concurrency,
            Some(crate::proxy::transport::XhttpReuseValueRange { min: 16, max: 32 })
        );
        assert_eq!(
            policy.c_max_reuse_times,
            Some(crate::proxy::transport::XhttpReuseValueRange { min: 0, max: 0 })
        );
        assert_eq!(policy.h_keep_alive_period, -1);
    }

    #[test]
    fn vless_xhttp_reuse_policy_rejects_conflicting_limits() {
        let settings = XhttpReuseSettings {
            max_concurrency: Some("16".to_owned()),
            max_connections: Some("4".to_owned()),
            ..Default::default()
        };

        let err = build_xhttp_reuse_policy(Some(&settings))
            .expect_err("max-concurrency and max-connections must conflict");

        assert!(
            err.to_string()
                .contains("max-concurrency conflicts with max-connections"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_reuse_settings_build_with_supported_runtime_limits() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-reuse".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                reuse_settings: Some(XhttpReuseSettings {
                    max_concurrency: Some("16-32".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("supported reuse-settings should build");
        assert!(transport.is_some(), "xhttp transport should be present");
    }

    #[test]
    fn vless_xhttp_reuse_builds_with_max_connections() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-max-connections".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                reuse_settings: Some(XhttpReuseSettings {
                    max_connections: Some("4".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("max-connections reuse policy should build");
        assert!(transport.is_some(), "xhttp transport should be present");
    }

    #[test]
    fn vless_xhttp_reuse_accepts_supported_keep_alive_periods() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-keepalive".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                reuse_settings: Some(XhttpReuseSettings {
                    h_keep_alive_period: Some("-1".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("-1 keepalive should build");
        assert!(transport.is_some(), "xhttp transport should be present");

        let positive = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-keepalive-positive".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                reuse_settings: Some(XhttpReuseSettings {
                    h_keep_alive_period: Some("30".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(positive.network.as_deref(), &positive)
            .expect("positive keepalive should build");
        assert!(transport.is_some(), "xhttp transport should be present");
    }

    #[test]
    fn vless_xhttp_reuse_rejects_keep_alive_below_minus_one() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-keepalive-invalid".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                reuse_settings: Some(XhttpReuseSettings {
                    h_keep_alive_period: Some("-2".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("keepalive below -1 must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("must be -1, 0, or a positive number"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_download_reuse_settings_build_runtime_policy() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-download-reuse".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                download_settings: Some(XhttpDownloadSettings {
                    address: "download.example.com".to_owned(),
                    port: 443,
                    network: "xhttp".to_owned(),
                    security: Some("tls".to_owned()),
                    xhttp_settings: Some(XhttpDownloadXhttpSettings {
                        reuse_settings: Some(XhttpReuseSettings {
                            max_concurrency: Some("8-16".to_owned()),
                            h_keep_alive_period: Some("30".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("download reuse-settings should build");
        assert!(transport.is_some());
    }

    #[test]
    fn vless_xhttp_session_defaults_to_uuid() {
        let opts = XhttpOpt::default();

        let session =
            build_xhttp_session_config(&opts).expect("default session should parse");

        assert!(uuid::Uuid::parse_str(&session.generate()).is_ok());
    }

    #[test]
    fn vless_xhttp_session_base62_length_10_is_valid() {
        let opts = XhttpOpt {
            session_table: Some("Base62".to_owned()),
            session_length: Some("10".to_owned()),
            ..Default::default()
        };

        let session = build_xhttp_session_config(&opts)
            .expect("Base62 length 10 should have sufficient entropy");
        let generated = session.generate();

        assert_eq!(generated.len(), 10);
        assert!(generated.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    }

    #[test]
    fn vless_xhttp_session_rejects_small_id_space() {
        let opts = XhttpOpt {
            session_table: Some("number".to_owned()),
            session_length: Some("4".to_owned()),
            ..Default::default()
        };

        let err = build_xhttp_session_config(&opts)
            .expect_err("small session space must be rejected");

        assert!(
            err.to_string()
                .contains("session-table or session-length is too small"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_session_rejects_zero_or_reversed_length() {
        for value in ["0", "16-8"] {
            let opts = XhttpOpt {
                session_table: Some("Base62".to_owned()),
                session_length: Some(value.to_owned()),
                ..Default::default()
            };

            let err = build_xhttp_session_config(&opts)
                .expect_err("invalid session length must fail");
            assert!(
                err.to_string().contains("session-length"),
                "unexpected error for {value}: {err}"
            );
        }
    }

    #[test]
    fn vless_xhttp_padding_defaults_match_legacy_behavior() {
        let opts = XhttpOpt::default();

        let padding =
            build_xhttp_padding_config(&opts).expect("default padding should parse");

        assert_eq!(padding.bytes.min, 100);
        assert_eq!(padding.bytes.max, 1_000);
        assert!(!padding.obfs_mode);
        assert_eq!(padding.key, "x_padding");
        assert_eq!(padding.header, "Referer");
        assert_eq!(padding.placement, XhttpPaddingPlacement::QueryInHeader);
        assert_eq!(padding.method, XhttpPaddingMethod::RepeatX);
    }

    #[test]
    fn vless_xhttp_padding_accepts_obfs_fields() {
        let opts = XhttpOpt {
            x_padding_bytes: Some("128-256".to_owned()),
            x_padding_obfs_mode: Some(true),
            x_padding_key: Some("pad".to_owned()),
            x_padding_header: Some("X-Pad".to_owned()),
            x_padding_placement: Some("header".to_owned()),
            x_padding_method: Some("tokenish".to_owned()),
            ..Default::default()
        };

        let padding =
            build_xhttp_padding_config(&opts).expect("obfs padding should parse");

        assert_eq!(padding.bytes.min, 128);
        assert_eq!(padding.bytes.max, 256);
        assert!(padding.obfs_mode);
        assert_eq!(padding.key, "pad");
        assert_eq!(padding.header, "X-Pad");
        assert_eq!(padding.placement, XhttpPaddingPlacement::Header);
        assert_eq!(padding.method, XhttpPaddingMethod::Tokenish);
    }

    #[test]
    fn vless_xhttp_padding_accepts_mihomo_query_in_header_name() {
        let opts = XhttpOpt {
            x_padding_obfs_mode: Some(true),
            x_padding_placement: Some("queryInHeader".to_owned()),
            ..Default::default()
        };

        let padding = build_xhttp_padding_config(&opts)
            .expect("Mihomo queryInHeader placement should parse");

        assert_eq!(padding.placement, XhttpPaddingPlacement::QueryInHeader);
        assert_eq!(padding.key, "x_padding");
        assert_eq!(padding.header, "Referer");
    }

    #[test]
    fn vless_xhttp_padding_rejects_reversed_range() {
        let opts = XhttpOpt {
            x_padding_bytes: Some("512-128".to_owned()),
            ..Default::default()
        };

        let err = build_xhttp_padding_config(&opts)
            .expect_err("reversed padding range must fail");

        assert!(
            err.to_string()
                .contains("invalid xhttp x-padding-bytes range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_padding_rejects_zero_range() {
        for value in ["0", "0-0", "0-128"] {
            let opts = XhttpOpt {
                x_padding_bytes: Some(value.to_owned()),
                ..Default::default()
            };

            let err = build_xhttp_padding_config(&opts)
                .expect_err("zero padding range must fail");

            assert!(
                err.to_string().contains("values must be greater than zero"),
                "unexpected error for {value}: {err}"
            );
        }
    }

    #[test]
    fn vless_xhttp_padding_rejects_unknown_placement_and_method() {
        let bad_placement = XhttpOpt {
            x_padding_placement: Some("path".to_owned()),
            ..Default::default()
        };
        let err = build_xhttp_padding_config(&bad_placement)
            .expect_err("unsupported padding placement must fail");
        assert!(
            err.to_string()
                .contains("unsupported xhttp x-padding-placement"),
            "unexpected error: {err}"
        );

        let bad_method = XhttpOpt {
            x_padding_method: Some("random".to_owned()),
            ..Default::default()
        };
        let err = build_xhttp_padding_config(&bad_method)
            .expect_err("unsupported padding method must fail");
        assert!(
            err.to_string()
                .contains("unsupported xhttp x-padding-method"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_packet_up_defaults_to_30ms_post_interval() {
        let opts = XhttpOpt::default();

        assert_eq!(resolve_xhttp_min_posts_interval_ms(&opts), Some(30));
    }

    #[test]
    fn vless_xhttp_flat_packet_tuning_overrides_legacy_values() {
        let opts = XhttpOpt {
            no_grpc_header: Some(false),
            sc_max_each_post_bytes: Some(2048),
            sc_min_posts_interval_ms: Some(45),
            max_each_post_bytes: Some(8192),
            extra: Some(XhttpExtra {
                no_grpc_header: Some(true),
                sc_max_each_post_bytes: Some(4096),
                sc_min_posts_interval_ms: Some(60),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(resolve_xhttp_max_each_post_bytes(&opts), 2048);
        assert!(!resolve_xhttp_no_grpc_header(&opts));
        assert_eq!(resolve_xhttp_min_posts_interval_ms(&opts), Some(45));
    }

    #[test]
    fn vless_xhttp_uplink_defaults_to_post_body() {
        let opts = XhttpOpt {
            mode: Some("packet-up".to_owned()),
            ..Default::default()
        };

        let uplink = build_xhttp_uplink_config(&opts, XhttpMode::PacketUp)
            .expect("default uplink should parse");

        assert_eq!(uplink.method, "POST");
        assert_eq!(uplink.placement, XhttpUplinkDataPlacement::Body);
        assert_eq!(uplink.key, None);
    }

    #[test]
    fn vless_xhttp_uplink_header_applies_defaults() {
        let opts = XhttpOpt {
            mode: Some("packet-up".to_owned()),
            uplink_data_placement: Some("header".to_owned()),
            ..Default::default()
        };

        let uplink = build_xhttp_uplink_config(&opts, XhttpMode::PacketUp)
            .expect("header uplink should parse");

        assert_eq!(uplink.placement, XhttpUplinkDataPlacement::Header);
        assert_eq!(uplink.key.as_deref(), Some("X-Data"));
        assert_eq!(uplink.chunk_size.min, 3_000);
        assert_eq!(uplink.chunk_size.max, 4_000);
    }

    #[test]
    fn vless_xhttp_uplink_cookie_clamps_small_chunk_range() {
        let opts = XhttpOpt {
            mode: Some("packet-up".to_owned()),
            uplink_data_placement: Some("cookie".to_owned()),
            uplink_chunk_size: Some("1-32".to_owned()),
            ..Default::default()
        };

        let uplink = build_xhttp_uplink_config(&opts, XhttpMode::PacketUp)
            .expect("cookie uplink should parse");

        assert_eq!(uplink.placement, XhttpUplinkDataPlacement::Cookie);
        assert_eq!(uplink.key.as_deref(), Some("x_data"));
        assert_eq!(uplink.chunk_size.min, 64);
        assert_eq!(uplink.chunk_size.max, 64);
    }

    #[test]
    fn vless_xhttp_uplink_rejects_nonbody_outside_packet_up() {
        let opts = XhttpOpt {
            mode: Some("stream-up".to_owned()),
            uplink_data_placement: Some("header".to_owned()),
            ..Default::default()
        };

        let err = build_xhttp_uplink_config(&opts, XhttpMode::StreamUp)
            .expect_err("header uplink must require packet-up");

        assert!(
            err.to_string().contains("requires packet-up mode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_uplink_rejects_unsupported_http_method() {
        let opts = XhttpOpt {
            mode: Some("packet-up".to_owned()),
            uplink_http_method: Some("GET".to_owned()),
            ..Default::default()
        };

        let err = build_xhttp_uplink_config(&opts, XhttpMode::PacketUp)
            .expect_err("GET is not supported by current Mihomo xhttp config");

        assert!(
            err.to_string()
                .contains("unsupported xhttp uplink-http-method"),
            "unexpected error: {err}"
        );
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
    fn vless_xhttp_rejects_host_header_case_insensitively() {
        for key in ["Host", "host", "HOST"] {
            let outbound = OutboundVless {
                common_opts: CommonConfigOptions {
                    name: "xhttp-host-header".to_owned(),
                    server: "example.com".to_owned(),
                    port: 443,
                    connect_via: None,
                },
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
                network: Some("xhttp".to_owned()),
                xhttp_opts: Some(XhttpOpt {
                    headers: Some(std::collections::HashMap::from([(
                        key.to_owned(),
                        "other.example.com".to_owned(),
                    )])),
                    ..Default::default()
                }),
                ..Default::default()
            };

            let err = match build_transport(outbound.network.as_deref(), &outbound) {
                Ok(_) => panic!("Host header must be rejected"),
                Err(err) => err,
            };
            assert!(
                err.to_string().contains("must not contain Host"),
                "unexpected error for {key}: {err}"
            );
        }
    }

    #[test]
    fn vless_xhttp_allows_non_host_headers() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-header".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                headers: Some(std::collections::HashMap::from([(
                    "X-Forwarded-For".to_owned(),
                    "203.0.113.10".to_owned(),
                )])),
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("ordinary xhttp headers should remain valid");
        assert!(transport.is_some());
    }

    #[test]
    fn vless_xhttp_rejects_nested_download_host_header() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-download-host-header".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                download_settings: Some(XhttpDownloadSettings {
                    address: "download.example.com".to_owned(),
                    port: 443,
                    network: "xhttp".to_owned(),
                    xhttp_settings: Some(XhttpDownloadXhttpSettings {
                        headers: Some(std::collections::HashMap::from([(
                            "Host".to_owned(),
                            "wrong.example.com".to_owned(),
                        )])),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("nested Host header must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("must not contain Host"),
            "unexpected error: {err}"
        );
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
    fn vless_xhttp_rejects_zero_flat_packet_limit() {
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
                sc_max_each_post_bytes: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("zero flat xhttp packet limit must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("sc_max_each_post_bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vless_xhttp_rejects_zero_flat_post_interval() {
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
                sc_min_posts_interval_ms: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = match build_transport(outbound.network.as_deref(), &outbound) {
            Ok(_) => panic!("zero flat xhttp post interval must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("sc_min_posts_interval_ms"),
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
    fn vless_xhttp_auto_is_preserved_for_runtime_resolution() {
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

        let opts = outbound
            .xhttp_opts
            .as_ref()
            .expect("xhttp options should be present");
        assert_eq!(
            parse_xhttp_mode(opts).expect("auto mode should parse"),
            XhttpMode::Auto
        );

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
            .expect("upload settings security should be owned by xhttp");
        assert!(
            tls.is_none(),
            "explicit xhttp upload settings must not double-wrap TLS outside xhttp"
        );
    }

    #[test]
    fn vless_xhttp_mihomo_flat_download_settings_reach_runtime_config() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-flat-download".to_owned(),
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
                    network: "xhttp".to_owned(),
                    tls: Some(true),
                    alpn: Some(vec!["h2".to_owned()]),
                    skip_cert_verify: Some(true),
                    name_cert_verify: Some("cert.example.com".to_owned()),
                    fingerprint: Some("0123456789abcdef".to_owned()),
                    certificate: Some("client-cert.pem".to_owned()),
                    private_key: Some("client-key.pem".to_owned()),
                    client_fingerprint: Some("none".to_owned()),
                    server_name: Some("sni.example.com".to_owned()),
                    path: Some("/download/".to_owned()),
                    host: Some("download-host.example.com".to_owned()),
                    headers: Some(std::collections::HashMap::from([(
                        "X-Download".to_owned(),
                        "yes".to_owned(),
                    )])),
                    reuse_settings: Some(XhttpReuseSettings {
                        max_connections: Some("2".to_owned()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let xhttp_opts = outbound
            .xhttp_opts
            .as_ref()
            .expect("xhttp options should be present");
        let metadata =
            build_xhttp_metadata_config(xhttp_opts).expect("metadata should build");
        let download = build_xhttp_download_config(
            &outbound,
            xhttp_opts,
            &metadata,
            XhttpHttpVersion::Http2,
        )
        .expect("flat download settings should build")
        .expect("download config should be present");

        assert_eq!(download.server, "download.example.com");
        assert_eq!(download.port, 8443);
        assert_eq!(download.path, "/download/");
        assert_eq!(download.host, Some("download-host.example.com".to_owned()));
        assert_eq!(
            download.headers.get("X-Download").map(String::as_str),
            Some("yes")
        );
        assert!(matches!(
            download.security,
            crate::proxy::transport::XhttpSecurity::Tls
        ));
        assert_eq!(download.server_name, "sni.example.com");
        assert_eq!(download.alpn_protocols, vec!["h2".to_owned()]);
        assert!(download.skip_cert_verify);
        assert_eq!(download.verify_name.as_deref(), Some("cert.example.com"));
        assert_eq!(download.fingerprint.as_deref(), Some("0123456789abcdef"));
        assert_eq!(download.tls_cert.as_deref(), Some("client-cert.pem"));
        assert_eq!(download.tls_key.as_deref(), Some("client-key.pem"));
        assert!(download.reuse_policy.is_some());
    }

    #[test]
    fn vless_xhttp_http1_download_settings_use_http11_alpn() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-http1-download".to_owned(),
                server: "upload.example.com".to_owned(),
                port: 80,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            alpn: Some(vec!["http/1.1".to_owned()]),
            xhttp_opts: Some(XhttpOpt {
                download_settings: Some(XhttpDownloadSettings {
                    address: "download.example.com".to_owned(),
                    port: 80,
                    network: "xhttp".to_owned(),
                    alpn: Some(vec!["http/1.1".to_owned()]),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        validate_vless_config(&outbound)
            .expect("HTTP/1.1 download-settings should validate");
        crate::proxy::vless::Handler::try_from(&outbound)
            .expect("HTTP/1.1 download-settings handler should build");

        let xhttp_opts = outbound.xhttp_opts.as_ref().expect("xhttp opts");
        let metadata =
            build_xhttp_metadata_config(xhttp_opts).expect("metadata should build");
        let download = build_xhttp_download_config(
            &outbound,
            xhttp_opts,
            &metadata,
            XhttpHttpVersion::Http1,
        )
        .expect("HTTP/1.1 download settings should build")
        .expect("download config should be present");

        assert_eq!(download.alpn_protocols, vec!["http/1.1".to_owned()]);
    }

    #[test]
    fn vless_xhttp_download_settings_inherit_unset_uplink_fields() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-inherit".to_owned(),
                server: "upload.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h2".to_owned()]),
            skip_cert_verify: Some(true),
            name_cert_verify: Some("verify.example.com".to_owned()),
            certificate: Some("client-cert.pem".to_owned()),
            private_key: Some("client-key.pem".to_owned()),
            server_name: Some("sni.example.com".to_owned()),
            network: Some("xhttp".to_owned()),
            fingerprint: Some("0123456789abcdef".to_owned()),
            client_fingerprint: Some("none".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/shared/".to_owned()),
                host: Some("shared-host.example.com".to_owned()),
                headers: Some(std::collections::HashMap::from([(
                    "X-Shared".to_owned(),
                    "yes".to_owned(),
                )])),
                reuse_settings: Some(XhttpReuseSettings {
                    max_connections: Some("2".to_owned()),
                    ..Default::default()
                }),
                download_settings: Some(XhttpDownloadSettings {
                    network: "xhttp".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let xhttp_opts = outbound
            .xhttp_opts
            .as_ref()
            .expect("xhttp options should be present");
        let metadata =
            build_xhttp_metadata_config(xhttp_opts).expect("metadata should build");
        let download = build_xhttp_download_config(
            &outbound,
            xhttp_opts,
            &metadata,
            XhttpHttpVersion::Http2,
        )
        .expect("inherited download settings should build")
        .expect("download config should be present");

        assert_eq!(download.server, "upload.example.com");
        assert_eq!(download.port, 443);
        assert_eq!(download.path, "/shared/");
        assert_eq!(download.host, Some("shared-host.example.com".to_owned()));
        assert_eq!(
            download.headers.get("X-Shared").map(String::as_str),
            Some("yes")
        );
        assert!(matches!(
            download.security,
            crate::proxy::transport::XhttpSecurity::Tls
        ));
        assert_eq!(download.server_name, "sni.example.com");
        assert_eq!(download.alpn_protocols, vec!["h2".to_owned()]);
        assert!(download.skip_cert_verify);
        assert_eq!(download.verify_name.as_deref(), Some("verify.example.com"));
        assert_eq!(download.fingerprint.as_deref(), Some("0123456789abcdef"));
        assert_eq!(download.tls_cert.as_deref(), Some("client-cert.pem"));
        assert_eq!(download.tls_key.as_deref(), Some("client-key.pem"));
        assert!(download.reuse_policy.is_some());
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_xhttp_download_empty_reality_key_clears_inherited_reality() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-clear-reality".to_owned(),
                server: "upload.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            alpn: Some(vec!["h2".to_owned()]),
            network: Some("xhttp".to_owned()),
            client_fingerprint: Some("chrome".to_owned()),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: None,
            }),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/xhttp/".to_owned()),
                download_settings: Some(XhttpDownloadSettings {
                    network: "xhttp".to_owned(),
                    client_fingerprint: Some("none".to_owned()),
                    reality_opts: Some(OutboundTrojanRealityOpts {
                        public_key: String::new(),
                        short_id: None,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let xhttp_opts = outbound
            .xhttp_opts
            .as_ref()
            .expect("xhttp options should be present");
        let metadata =
            build_xhttp_metadata_config(xhttp_opts).expect("metadata should build");
        let download = build_xhttp_download_config(
            &outbound,
            xhttp_opts,
            &metadata,
            XhttpHttpVersion::Http2,
        )
        .expect("empty download reality key should clear inherited Reality")
        .expect("download config should be present");

        assert!(matches!(
            download.security,
            crate::proxy::transport::XhttpSecurity::Tls
        ));
        assert!(download.reality.is_none());
        assert_eq!(download.server, "upload.example.com");
        assert_eq!(download.port, 443);
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_xhttp_download_tls_requires_fingerprint_override_when_reality_is_cleared()
     {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-clear-reality-fingerprint".to_owned(),
                server: "upload.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            tls: Some(true),
            network: Some("xhttp".to_owned()),
            client_fingerprint: Some("chrome".to_owned()),
            reality_opts: Some(OutboundTrojanRealityOpts {
                public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                short_id: None,
            }),
            xhttp_opts: Some(XhttpOpt {
                download_settings: Some(XhttpDownloadSettings {
                    network: "xhttp".to_owned(),
                    reality_opts: Some(OutboundTrojanRealityOpts {
                        public_key: String::new(),
                        short_id: None,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let xhttp_opts = outbound
            .xhttp_opts
            .as_ref()
            .expect("xhttp options should be present");
        let metadata =
            build_xhttp_metadata_config(xhttp_opts).expect("metadata should build");
        build_xhttp_download_config(
            &outbound,
            xhttp_opts,
            &metadata,
            XhttpHttpVersion::Http2,
        )
        .expect("non-Reality TLS fingerprint should only warn for compatibility");
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
            alpn: Some(vec!["h2".to_owned()]),
            client_fingerprint: Some("chrome".to_owned()),
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
        assert!(
            transport.is_some(),
            "xhttp reality transport should be present"
        );

        let tls = build_tls_transport(outbound.network.as_deref(), &outbound, false)
            .expect("xhttp reality tls transport should build");
        assert!(
            tls.is_some(),
            "xhttp reality should create a handshake transport"
        );
    }

    #[cfg(feature = "reality")]
    #[test]
    fn vless_xhttp_explicit_upload_reality_is_owned_by_transport() {
        let outbound = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "xhttp-upload-reality".to_owned(),
                server: "legacy-upload.example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            network: Some("xhttp".to_owned()),
            client_fingerprint: Some("chrome".to_owned()),
            xhttp_opts: Some(XhttpOpt {
                upload_settings: Some(XhttpUploadSettings {
                    address: "upload.example.com".to_owned(),
                    port: 9443,
                    network: "xhttp".to_owned(),
                    security: Some("reality".to_owned()),
                    reality_opts: Some(OutboundTrojanRealityOpts {
                        public_key: TEST_REALITY_PUBLIC_KEY.to_owned(),
                        short_id: None,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let endpoint = build_xhttp_upload_endpoint_config(&outbound, false)
            .expect("upload Reality endpoint should build")
            .expect("explicit upload-settings should create an endpoint");
        assert_eq!(endpoint.server, "upload.example.com");
        assert_eq!(endpoint.port, 9443);
        assert!(matches!(
            endpoint.security,
            crate::proxy::transport::XhttpSecurity::Reality
        ));
        assert!(endpoint.reality.is_some());

        let outer_security =
            build_tls_transport(outbound.network.as_deref(), &outbound, false)
                .expect("outer security decision should succeed");
        assert!(
            outer_security.is_none(),
            "explicit upload Reality must not also wrap the VLESS socket outside xhttp"
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
            alpn: Some(vec!["h2".to_owned()]),
            client_fingerprint: Some("chrome".to_owned()),
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

        let xhttp_opts = outbound
            .xhttp_opts
            .as_ref()
            .expect("xhttp options should be present");
        let metadata = build_xhttp_metadata_config(xhttp_opts)
            .expect("metadata config should build");
        let download = build_xhttp_download_config(
            &outbound,
            xhttp_opts,
            &metadata,
            XhttpHttpVersion::Http2,
        )
        .expect("download config should build")
        .expect("download config should be present");
        assert_eq!(
            download
                .reality
                .expect("reality config should be present")
                .alpn_protocols,
            vec!["h2".to_owned()]
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
                ..Default::default()
            }),
            ..Default::default()
        };

        let transport = build_transport(outbound.network.as_deref(), &outbound)
            .expect("ws transport should build");
        assert!(transport.is_some(), "ws transport should be present");
    }
}
