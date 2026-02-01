use crate::proxy::HandlerCommonOptions;
use crate::{
    Error,
    config::internal::proxy::OutboundSnell,
    proxy::snell::{Handler, HandlerOptions, SnellObfs, SnellVersion},
};

impl TryFrom<&OutboundSnell> for Handler {
    type Error = Error;

    fn try_from(value: &OutboundSnell) -> Result<Self, Self::Error> {
        let version_raw = value.version.unwrap_or(2);
        let version = match version_raw {
            1 => SnellVersion::V1,
            2 => SnellVersion::V2,
            other => {
                return Err(Error::InvalidConfig(format!(
                    "unsupported snell version: {other}"
                )));
            }
        };

        let obfs = SnellObfs::from_str(value.obfs.as_deref())
            .map_err(|e| Error::InvalidConfig(format!("invalid snell obfs: {e}")))?;

        let obfs_host = value
            .obfs_opts
            .as_ref()
            .and_then(|opts| opts.host.clone())
            .unwrap_or_else(|| value.common_opts.server.clone());

        let handler = Handler::new(HandlerOptions {
            name: value.common_opts.name.clone(),
            common_opts: HandlerCommonOptions {
                connector: value.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: value.common_opts.server.clone(),
            port: value.common_opts.port,
            psk: value.psk.clone().into_bytes(),
            version,
            obfs,
            obfs_host,
        });
        Ok(handler)
    }
}
