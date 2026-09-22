use async_trait::async_trait;
#[cfg(not(feature = "anytls"))]
use rustls::pki_types::PrivateKeyDer;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::Serialize;
use std::{io, sync::Arc};

use super::Transport;
use crate::{
    common::{errors::map_io_error, tls::DefaultTlsVerifier},
    proxy::AnyStream,
};

#[cfg(feature = "anytls")]
use crate::common::tls::build_tls_client_config;

#[derive(Serialize, Clone)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
}

impl From<TLSOptions> for Client {
    fn from(opt: TLSOptions) -> Self {
        Self::new(opt.skip_cert_verify, opt.sni, opt.alpn, None)
    }
}

#[derive(Debug)]
struct VerifyNameOverride {
    inner: DefaultTlsVerifier,
    verify_name: Option<ServerName<'static>>,
}

impl VerifyNameOverride {
    fn new(
        fingerprint: Option<String>,
        skip: bool,
        verify_name: Option<String>,
    ) -> io::Result<Self> {
        let verify_name = verify_name
            .map(ServerName::try_from)
            .transpose()
            .map_err(map_io_error)?;

        Ok(Self {
            inner: DefaultTlsVerifier::new(fingerprint, skip),
            verify_name,
        })
    }
}

#[cfg(not(feature = "anytls"))]
fn load_client_auth_material(
    cert: &str,
    key: &str,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = if cert.contains("-----BEGIN") {
        cert.to_owned()
    } else {
        std::fs::read_to_string(cert).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to read TLS client certificate '{cert}': {err}"),
            )
        })?
    };
    let key_pem = if key.contains("-----BEGIN") {
        key.to_owned()
    } else {
        std::fs::read_to_string(key).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to read TLS client private key '{key}': {err}"),
            )
        })?
    };

    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to parse TLS client certificate: {err}"),
            )
        })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no valid TLS client certificates found",
        ));
    }

    let private_key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to parse TLS client private key: {err}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no TLS client private key found",
            )
        })?;

    Ok((certs, private_key))
}

impl ServerCertVerifier for VerifyNameOverride {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            self.verify_name.as_ref().unwrap_or(server_name),
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub struct Client {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub expected_alpn: Option<String>,
    pub fingerprint: Option<String>,
    pub verify_name: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

impl Client {
    pub fn new(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
    ) -> Self {
        Self {
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
            fingerprint: None,
            verify_name: None,
            tls_cert: None,
            tls_key: None,
        }
    }

    pub fn new_with_fingerprint(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        Self {
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
            fingerprint,
            verify_name: None,
            tls_cert: None,
            tls_key: None,
        }
    }

    #[cfg(feature = "anytls")]
    pub fn new_with_client_auth(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Self> {
        Self::new(skip_cert_verify, sni, alpn, expected_alpn).with_client_auth(
            tls_cert.map(ToOwned::to_owned),
            tls_key.map(ToOwned::to_owned),
        )
    }

    pub fn with_verify_name(mut self, verify_name: Option<String>) -> Self {
        self.verify_name = verify_name;
        self
    }

    pub fn with_client_auth(
        mut self,
        tls_cert: Option<String>,
        tls_key: Option<String>,
    ) -> io::Result<Self> {
        match (&tls_cert, &tls_key) {
            (Some(_), Some(_)) | (None, None) => {
                self.tls_cert = tls_cert;
                self.tls_key = tls_key;
                Ok(self)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tls certificate and private key must both be set or both omitted",
            )),
        }
    }

    fn certificate_verifier(&self) -> io::Result<Arc<dyn ServerCertVerifier>> {
        Ok(Arc::new(VerifyNameOverride::new(
            self.fingerprint.clone(),
            self.skip_cert_verify,
            self.verify_name.clone(),
        )?))
    }

    pub(crate) fn rustls_client_config(&self) -> io::Result<rustls::ClientConfig> {
        let verifier = self.certificate_verifier()?;

        #[cfg(feature = "anytls")]
        let mut tls_config = build_tls_client_config(
            verifier,
            self.tls_cert.as_deref(),
            self.tls_key.as_deref(),
        )?;

        #[cfg(not(feature = "anytls"))]
        let mut tls_config = match (
            self.tls_cert.as_deref(),
            self.tls_key.as_deref(),
        ) {
            (Some(cert), Some(key)) => {
                let (certs, private_key) = load_client_auth_material(cert, key)?;
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_client_auth_cert(certs, private_key)
                    .map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid TLS client cert/key: {err}"),
                        )
                    })?
            }
            (None, None) => rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tls certificate and private key must both be set or both omitted",
                ));
            }
        };
        tls_config.alpn_protocols = self
            .alpn
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.as_bytes().to_vec())
            .collect();

        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        Ok(tls_config)
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let tls_config = self.rustls_client_config()?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let dns_name =
            rustls::pki_types::ServerName::try_from(self.sni.as_str().to_owned())
                .map_err(map_io_error)?;

        let c = connector.connect(dns_name, stream).await.and_then(|x| {
            if let Some(expected_alpn) = self.expected_alpn.as_ref()
                && x.get_ref().1.alpn_protocol() != Some(expected_alpn.as_bytes())
            {
                return Err(io::Error::other(format!(
                    "unexpected alpn protocol: {:?}, expected: {:?}",
                    x.get_ref().1.alpn_protocol(),
                    expected_alpn
                )));
            }

            Ok(x)
        });
        c.map(|x| Box::new(x) as _)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use rustls::pki_types::ServerName;

    #[cfg(not(feature = "anytls"))]
    use super::load_client_auth_material;
    use super::{Client, VerifyNameOverride};

    #[test]
    fn tls_client_preserves_certificate_fingerprint() {
        let client = Client::new_with_fingerprint(
            false,
            "example.com".to_owned(),
            None,
            None,
            Some("0123456789abcdef".to_owned()),
        );

        assert_eq!(client.fingerprint.as_deref(), Some("0123456789abcdef"));
    }

    #[test]
    fn tls_client_keeps_sni_and_verify_name_separate() {
        crate::setup_default_crypto_provider();
        let client = Client::new_with_fingerprint(
            false,
            "sni.example.com".to_owned(),
            None,
            None,
            None,
        )
        .with_verify_name(Some("verify.example.com".to_owned()));

        assert_eq!(client.sni, "sni.example.com");
        assert_eq!(client.verify_name.as_deref(), Some("verify.example.com"));

        let verifier = VerifyNameOverride::new(None, false, client.verify_name)
            .expect("verify name should parse");

        assert_eq!(
            verifier.verify_name,
            Some(ServerName::try_from("verify.example.com".to_owned()).unwrap())
        );
    }

    #[test]
    fn tls_client_rejects_invalid_verify_name() {
        let client = Client::new(false, "sni.example.com".to_owned(), None, None)
            .with_verify_name(Some("not a valid dns name".to_owned()));

        assert!(
            client.certificate_verifier().is_err(),
            "invalid name-cert-verify must fail before TLS handshake"
        );
    }

    #[test]
    fn tls_client_auth_requires_certificate_and_key_pair() {
        let err = match Client::new(false, "example.com".to_owned(), None, None)
            .with_client_auth(Some("cert.pem".to_owned()), None)
        {
            Ok(_) => {
                panic!("client auth must require both certificate and private key")
            }
            Err(err) => err,
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(not(feature = "anytls"))]
    #[test]
    fn tls_client_auth_parses_inline_pem_material() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![
                "client.example.com".to_owned(),
            ])
            .expect("client certificate should generate");
        let cert_pem = cert.pem();
        let key_pem = signing_key.serialize_pem();

        let (certs, _key) = load_client_auth_material(&cert_pem, &key_pem)
            .expect("inline client certificate and key should parse");

        assert_eq!(certs.len(), 1);
    }
}
