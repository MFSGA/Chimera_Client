use crate::{
    config::internal::proxy::OutboundSocks5,
    proxy::{
        HandlerCommonOptions,
        socks::outbound::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundSocks5> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundSocks5) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundSocks5> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundSocks5) -> Result<Self, Self::Error> {
        #[cfg(feature = "tls")]
        let tls_client = if s.tls {
            Some(Box::new(crate::proxy::transport::TlsClient::new(
                s.skip_cert_verify,
                s.sni
                    .clone()
                    .unwrap_or_else(|| s.common_opts.server.to_owned()),
                None,
                None,
            ))
                as Box<dyn crate::proxy::transport::Transport>)
        } else {
            None
        };
        #[cfg(not(feature = "tls"))]
        let tls_client = None;

        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            user: s.username.clone(),
            password: s.password.clone(),
            udp: s.udp,
            tls_client,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config::internal::proxy::OutboundSocks5,
        proxy::{OutboundHandler, socks::outbound::Handler},
    };

    #[tokio::test]
    async fn converts_socks5_common_fields() {
        let config: OutboundSocks5 = serde_yaml::from_str(
            r#"
name: socks-test
server: 127.0.0.1
port: 1080
username: alice
password: secret
udp: false
"#,
        )
        .expect("parse socks5 config");

        let handler = Handler::try_from(config).expect("convert socks5 handler");
        assert_eq!(handler.name(), "socks-test");
        assert_eq!(handler.server_name(), Some("127.0.0.1"));
        assert!(!handler.support_udp().await);
    }
}
