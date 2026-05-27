use crate::{
    config::internal::proxy::OutboundShadowsocks,
    proxy::{
        HandlerCommonOptions,
        shadowsocks::outbound::{Handler, HandlerOptions},
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
        // Plugin support (obfs, v2ray-plugin, shadow-tls) is not yet
        // implemented. Configs that specify a plugin will be accepted but
        // the plugin will be ignored.
        if s.plugin.is_some() {
            tracing::warn!(
                "SS plugin '{}' for '{}' is not yet supported, ignoring",
                s.plugin.as_deref().unwrap_or(""),
                s.common_opts.name
            );
        }

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
        });
        Ok(h)
    }
}
