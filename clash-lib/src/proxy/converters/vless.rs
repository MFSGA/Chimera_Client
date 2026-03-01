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
        let tls: Option<Box<dyn Transport>> = if s.tls.unwrap_or_default() {
            let client = TlsClient::new(
                skip_cert_verify,
                tls_server_name(s),
                tls_alpn(network)?,
                None,
            );
            Some(Box::new(client))
        } else {
            None
        };

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
            "unsupported network: {other}"
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
        convert_u8_32(),
        convert_u8_8(),
        s.server_name
            .clone()
            .unwrap_or_default(),
        vec![],
    );
    Ok(Some(Box::new(client)))
}

fn convert_u8_32() -> [u8; 32] {
    // let _ = [0u8; 32];
    todo!()
}

fn convert_u8_8() -> [u8; 8] {
    todo!()
    // let _ = [0u8; 32];
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
