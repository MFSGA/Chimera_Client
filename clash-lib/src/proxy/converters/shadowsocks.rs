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
