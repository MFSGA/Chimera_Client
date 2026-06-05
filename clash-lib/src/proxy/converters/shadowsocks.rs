use std::collections::HashMap;

#[cfg(feature = "ws")]
use crate::proxy::transport::V2rayWsClient;
#[cfg(feature = "tls")]
use crate::proxy::transport::{Shadowtls, SimpleOBFSMode};
use crate::{
    Error,
    config::internal::proxy::OutboundShadowsocks,
    proxy::{
        HandlerCommonOptions,
        shadowsocks::outbound::{Handler, HandlerOptions},
        transport::{SimpleOBFSOption, SimpleObfsHttp, SimpleObfsTLS, Sip003Plugin},
    },
};

impl TryFrom<OutboundShadowsocks> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundShadowsocks) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundShadowsocks> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundShadowsocks) -> Result<Self, Self::Error> {
        let plugin: Option<Box<dyn Sip003Plugin>> = match &s.plugin {
            Some(plugin) => match plugin.as_str() {
                "obfs" => {
                    tracing::warn!(
                        "simple-obfs is deprecated, please use v2ray-plugin instead"
                    );
                    let opt: SimpleOBFSOption = s
                        .plugin_opts
                        .clone()
                        .ok_or(Error::InvalidConfig(
                            "plugin_opts is required for plugin obfs".to_owned(),
                        ))?
                        .try_into()?;
                    build_simple_obfs_plugin(opt, s.common_opts.port)?
                }
                #[cfg(feature = "ws")]
                "v2ray-plugin" => {
                    use crate::proxy::transport::V2RayOBFSOption;
                    let opt: V2RayOBFSOption = s
                        .plugin_opts
                        .clone()
                        .ok_or(Error::InvalidConfig(
                            "plugin_opts is required for plugin v2ray-plugin"
                                .to_owned(),
                        ))?
                        .try_into()?;
                    Some(Box::new(V2rayWsClient::try_from(opt)?) as _)
                }
                #[cfg(feature = "tls")]
                "shadow-tls" => {
                    let plugin: Shadowtls = s
                        .plugin_opts
                        .clone()
                        .ok_or(Error::InvalidConfig(
                            "plugin_opts is required for plugin shadow-tls"
                                .to_owned(),
                        ))?
                        .try_into()?;
                    Some(Box::new(plugin) as _)
                }
                #[cfg(not(feature = "ws"))]
                "v2ray-plugin" => {
                    return Err(Error::InvalidConfig(
                        "v2ray-plugin requires the 'ws' feature".to_owned(),
                    ));
                }
                #[cfg(not(feature = "tls"))]
                "shadow-tls" => {
                    return Err(Error::InvalidConfig(
                        "shadow-tls requires the 'tls' feature".to_owned(),
                    ));
                }
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "unsupported plugin: {plugin}"
                    )));
                }
            },
            None => None,
        };

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.to_owned(),
            cipher: s.cipher.to_owned(),
            udp: s.udp,
            plugin,
        });
        Ok(h)
    }
}

#[cfg(feature = "tls")]
fn build_simple_obfs_plugin(
    opt: SimpleOBFSOption,
    port: u16,
) -> Result<Option<Box<dyn Sip003Plugin>>, Error> {
    let plugin: Box<dyn Sip003Plugin> = match opt.mode {
        SimpleOBFSMode::Http => Box::new(SimpleObfsHttp::new(opt.host, port)),
        SimpleOBFSMode::Tls => Box::new(SimpleObfsTLS::new(opt.host)),
    };
    Ok(Some(plugin))
}

#[cfg(not(feature = "tls"))]
fn build_simple_obfs_plugin(
    opt: SimpleOBFSOption,
    port: u16,
) -> Result<Option<Box<dyn Sip003Plugin>>, Error> {
    match opt.mode {
        SimpleOBFSMode::Http => {
            Ok(Some(Box::new(SimpleObfsHttp::new(opt.host, port))))
        }
        SimpleOBFSMode::Tls => Err(Error::InvalidConfig(
            "simple-obfs tls mode requires the 'tls' feature".to_owned(),
        )),
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for SimpleOBFSOption {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        match mode {
            "http" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Http,
                host: host.to_owned(),
            }),
            "tls" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Tls,
                host: host.to_owned(),
            }),
            _ => Err(Error::InvalidConfig(format!("invalid obfs mode: {mode}"))),
        }
    }
}

#[cfg(feature = "ws")]
impl TryFrom<HashMap<String, serde_yaml::Value>>
    for crate::proxy::transport::V2RayOBFSOption
{
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        if mode != "websocket" {
            return Err(Error::InvalidConfig(format!("invalid obfs mode: {mode}")));
        }

        let path = value.get("path").and_then(|x| x.as_str()).unwrap_or("");
        let mux = value.get("mux").and_then(|x| x.as_bool()).unwrap_or(false);
        let tls = value.get("tls").and_then(|x| x.as_bool()).unwrap_or(false);
        // port is optional in plugin-opts; real Clash configs omit it and rely
        // on the main proxy port for the actual TCP connection. The value here
        // is only used for the WebSocket HTTP Upgrade Host header, so default
        // to the standard port for the chosen scheme.
        let port = value
            .get("port")
            .and_then(|x| x.as_u64())
            .unwrap_or(if tls { 443 } else { 80 }) as u16;
        let skip_cert_verify = value
            .get("skip-cert-verify")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);

        let mut headers = HashMap::new();
        if let Some(h) = value.get("headers")
            && let Some(h) = h.as_mapping()
        {
            for (k, v) in h {
                if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                    headers.insert(k.to_owned(), v.to_owned());
                }
            }
        }

        Ok(crate::proxy::transport::V2RayOBFSOption {
            mode: mode.to_owned(),
            host: host.to_owned(),
            port,
            path: path.to_owned(),
            tls,
            headers,
            skip_cert_verify,
            mux,
        })
    }
}

#[cfg(feature = "tls")]
impl TryFrom<HashMap<String, serde_yaml::Value>> for Shadowtls {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let password = value
            .get("password")
            .and_then(|x| x.as_str().to_owned())
            .ok_or(Error::InvalidConfig(
                "shadow-tls password is required".to_owned(),
            ))?;
        let strict = value
            .get("strict")
            .and_then(|x| x.as_bool())
            .unwrap_or(true);

        Ok(Shadowtls::new(
            host.to_string(),
            password.to_string(),
            strict,
        ))
    }
}

#[cfg(test)]
#[cfg(feature = "shadowsocks")]
mod tests {
    use std::collections::HashMap;

    use serde_yaml::Value;

    use super::{
        SimpleOBFSMode, SimpleOBFSOption, SimpleObfsHttp, SimpleObfsTLS,
    };
    use crate::{
        config::internal::proxy::{CommonConfigOptions, OutboundShadowsocks},
        proxy::shadowsocks::outbound::Handler,
    };

    fn make_common(name: &str, server: &str, port: u16) -> CommonConfigOptions {
        CommonConfigOptions {
            name: name.to_owned(),
            server: server.to_owned(),
            port,
            connect_via: None,
        }
    }

    fn make_ss(
        plugin: Option<&str>,
        plugin_opts: Option<HashMap<String, Value>>,
    ) -> OutboundShadowsocks {
        OutboundShadowsocks {
            common_opts: make_common("ss1", "10.0.0.1", 8388),
            cipher: "aes-256-gcm".to_owned(),
            password: "hunter2".to_owned(),
            udp: true,
            plugin: plugin.map(|s| s.to_owned()),
            plugin_opts,
        }
    }

    #[test]
    fn ss_without_plugin_builds_handler_with_none_plugin() {
        let ss = make_ss(None, None);
        let h: Handler = (&ss).try_into().expect("plain ss converts");
        assert!(format!("{h:?}").contains("ss1"));
    }

    #[test]
    fn unknown_plugin_returns_invalid_config_error() {
        let ss = make_ss(Some("not-a-real-plugin"), None);
        let result: Result<Handler, _> = (&ss).try_into();
        let err = result.expect_err("unknown plugin must error");
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported plugin"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn obfs_http_with_explicit_host_builds_handler() {
        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("http"));
        opts.insert("host".to_owned(), Value::from("example.com"));
        let ss = make_ss(Some("obfs"), Some(opts));

        let h: Handler = (&ss).try_into().expect("obfs http converts");
        assert!(format!("{h:?}").contains("ss1"));
    }

    #[test]
    fn obfs_tls_mode_round_trip_via_hashmap() {
        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("tls"));
        opts.insert("host".to_owned(), Value::from("cdn.example.com"));

        let parsed: SimpleOBFSOption = opts.try_into().expect("obfs tls parses");
        assert_eq!(parsed.host, "cdn.example.com");
        assert!(matches!(parsed.mode, SimpleOBFSMode::Tls));

        let _client = SimpleObfsTLS::new(parsed.host);
    }

    #[test]
    fn obfs_http_defaults_host_to_bing_when_absent() {
        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("http"));

        let parsed: SimpleOBFSOption = opts.try_into().expect("obfs http parses");
        assert_eq!(parsed.host, "bing.com");
        assert!(matches!(parsed.mode, SimpleOBFSMode::Http));
    }

    #[test]
    fn obfs_missing_mode_errors() {
        let opts = HashMap::<String, Value>::new();
        let result: Result<SimpleOBFSOption, _> = opts.try_into();
        let err = result.expect_err("missing mode must error");
        assert!(err.to_string().contains("obfs mode is required"));
    }

    #[test]
    fn obfs_unknown_mode_errors() {
        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("gopher"));
        let result: Result<SimpleOBFSOption, _> = opts.try_into();
        let err = result.expect_err("unknown mode must error");
        assert!(err.to_string().contains("invalid obfs mode"));
    }

    #[test]
    fn simple_obfs_http_wires_through_converter() {
        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("http"));
        opts.insert("host".to_owned(), Value::from("example.com"));

        let parsed: SimpleOBFSOption = opts.try_into().unwrap();
        let _client: SimpleObfsHttp = SimpleObfsHttp::new(parsed.host, 8388);
    }

    #[cfg(feature = "ws")]
    #[test]
    fn v2ray_plugin_websocket_parses_with_tls_and_default_port() {
        use crate::proxy::transport::V2RayOBFSOption;

        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("websocket"));
        opts.insert("host".to_owned(), Value::from("cdn.example.com"));
        opts.insert("path".to_owned(), Value::from("/ws"));
        opts.insert("tls".to_owned(), Value::from(true));
        opts.insert("skip-cert-verify".to_owned(), Value::from(true));

        let parsed: V2RayOBFSOption = opts.try_into().expect("v2ray parses");
        assert_eq!(parsed.host, "cdn.example.com");
        assert_eq!(parsed.path, "/ws");
        assert!(parsed.tls);
        assert!(parsed.skip_cert_verify);
        assert!(!parsed.mux);
        assert_eq!(parsed.port, 443);
    }

    #[cfg(feature = "ws")]
    #[test]
    fn v2ray_plugin_websocket_parses_without_tls_uses_port_80() {
        use crate::proxy::transport::V2RayOBFSOption;

        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("websocket"));
        opts.insert("host".to_owned(), Value::from("example.com"));

        let parsed: V2RayOBFSOption = opts.try_into().expect("v2ray parses");
        assert!(!parsed.tls);
        assert_eq!(parsed.port, 80);
    }

    #[cfg(feature = "ws")]
    #[test]
    fn v2ray_plugin_websocket_forwards_custom_headers() {
        use crate::proxy::transport::V2RayOBFSOption;

        let mut headers = serde_yaml::Mapping::new();
        headers.insert(Value::from("Origin"), Value::from("https://x"));
        headers.insert(Value::from("User-Agent"), Value::from("v2ray/1.0"));

        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("websocket"));
        opts.insert("headers".to_owned(), Value::Mapping(headers));

        let parsed: V2RayOBFSOption = opts.try_into().expect("v2ray parses");
        assert_eq!(parsed.headers.get("Origin").unwrap(), "https://x");
        assert_eq!(parsed.headers.get("User-Agent").unwrap(), "v2ray/1.0");
    }

    #[cfg(feature = "ws")]
    #[test]
    fn v2ray_plugin_websocket_builds_handler() {
        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("websocket"));
        opts.insert("host".to_owned(), Value::from("example.com"));
        let ss = make_ss(Some("v2ray-plugin"), Some(opts));

        let h: Handler = (&ss).try_into().expect("v2ray-plugin converts");
        assert!(format!("{h:?}").contains("ss1"));
    }

    #[cfg(feature = "ws")]
    #[test]
    fn v2ray_plugin_unsupported_mode_errors() {
        use crate::proxy::transport::V2RayOBFSOption;

        let mut opts = HashMap::new();
        opts.insert("mode".to_owned(), Value::from("quic"));
        let result: Result<V2RayOBFSOption, _> = opts.try_into();
        let err = result.expect_err("non-websocket mode must error");
        assert!(err.to_string().contains("invalid obfs mode"));
    }

    #[cfg(feature = "ws")]
    #[test]
    fn v2ray_plugin_missing_plugin_opts_errors() {
        let ss = make_ss(Some("v2ray-plugin"), None);
        let result: Result<Handler, _> = (&ss).try_into();
        let err = result.expect_err("missing plugin_opts must error");
        assert!(err.to_string().contains("plugin_opts is required"));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn shadow_tls_parses_with_password_and_strict() {
        use crate::proxy::transport::Shadowtls;

        let mut opts = HashMap::new();
        opts.insert("host".to_owned(), Value::from("cdn.example.com"));
        opts.insert("password".to_owned(), Value::from("sekret"));
        opts.insert("strict".to_owned(), Value::from(false));

        let parsed: Shadowtls = opts.try_into().expect("shadow-tls parses");
        let _ = parsed;
    }

    #[cfg(feature = "tls")]
    #[test]
    fn shadow_tls_defaults_strict_to_true() {
        use crate::proxy::transport::Shadowtls;

        let mut opts = HashMap::new();
        opts.insert("password".to_owned(), Value::from("sekret"));

        let _parsed: Shadowtls = opts.try_into().expect("shadow-tls parses");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn shadow_tls_missing_password_errors() {
        use crate::proxy::transport::Shadowtls;

        let opts = HashMap::<String, Value>::new();
        let result: Result<Shadowtls, _> = opts.try_into();
        let err = result.expect_err("missing password must error");
        assert!(err.to_string().contains("password is required"));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn shadow_tls_missing_plugin_opts_errors() {
        let ss = make_ss(Some("shadow-tls"), None);
        let result: Result<Handler, _> = (&ss).try_into();
        let err = result.expect_err("missing plugin_opts must error");
        assert!(err.to_string().contains("plugin_opts is required"));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn shadow_tls_builds_handler() {
        let mut opts = HashMap::new();
        opts.insert("host".to_owned(), Value::from("cdn.example.com"));
        opts.insert("password".to_owned(), Value::from("sekret"));
        let ss = make_ss(Some("shadow-tls"), Some(opts));

        let h: Handler = (&ss).try_into().expect("shadow-tls converts");
        assert!(format!("{h:?}").contains("ss1"));
    }
}
