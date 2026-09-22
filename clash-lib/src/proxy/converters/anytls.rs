use tracing::warn;

use crate::Error;

use crate::{
    config::internal::proxy::OutboundAnytls,
    proxy::{
        HandlerCommonOptions,
        anytls::{Handler, HandlerOptions},
        transport::TlsClient,
    },
};

const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

impl TryFrom<OutboundAnytls> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundAnytls) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundAnytls> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundAnytls) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }
        if let Some(client_fingerprint) = s.client_fingerprint.as_deref()
            && client_fingerprint != "none"
        {
            return Err(Error::InvalidConfig(format!(
                "anytls client-fingerprint is not implemented, got {client_fingerprint}"
            )));
        }
        if s.idle_session_check_interval.is_some()
            || s.idle_session_timeout.is_some()
            || s.min_idle_session.is_some()
        {
            warn!(
                "anytls idle-session fields are parsed but not applied yet for {}",
                s.common_opts.name
            );
        }

        let client = TlsClient::new_with_fingerprint(
            skip_cert_verify,
            s.sni
                .clone()
                .unwrap_or_else(|| s.common_opts.server.clone()),
            s.alpn
                .clone()
                .or_else(|| Some(DEFAULT_ALPN.map(str::to_owned).to_vec())),
            None,
            s.fingerprint.clone(),
        )
        .with_client_auth(s.tls_cert.clone(), s.tls_key.clone())?;

        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            tls: Some(Box::new(client)),
            transport: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &str) -> OutboundAnytls {
        serde_yaml::from_str(&format!(
            r#"
name: anytls-test
server: 198.51.100.10
port: 443
password: secret
sni: example.com
{extra}
"#
        ))
        .expect("AnyTLS test config should parse")
    }

    #[test]
    fn anytls_accepts_certificate_fingerprint_pinning() {
        let config = parse("fingerprint: 0123456789abcdef");
        Handler::try_from(&config)
            .expect("certificate fingerprint should be wired into TLS");
    }

    #[test]
    fn anytls_rejects_unimplemented_client_fingerprint() {
        let config = parse("client-fingerprint: chrome");
        let err = Handler::try_from(&config)
            .expect_err("uTLS fingerprint must not be silently ignored");
        assert!(
            err.to_string()
                .contains("client-fingerprint is not implemented")
        );
    }

    #[test]
    fn anytls_accepts_explicit_no_client_fingerprint() {
        let config = parse("client-fingerprint: none");
        Handler::try_from(&config)
            .expect("client-fingerprint: none should keep standard rustls TLS");
    }
}
