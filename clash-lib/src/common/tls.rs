use std::sync::{Arc, LazyLock};

use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
};

pub static GLOBAL_ROOT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let store = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(store)
});

#[derive(Debug)]
pub struct DefaultTlsVerifier {
    fingerprint: Option<String>,
    skip: bool,
    pki: Arc<WebPkiServerVerifier>,
}

impl DefaultTlsVerifier {
    pub fn new(fingerprint: Option<String>, skip: bool) -> Self {
        Self {
            fingerprint,
            skip,
            pki: WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .unwrap(),
        }
    }
}

impl ServerCertVerifier for DefaultTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(ref fingerprint) = self.fingerprint {
            let cert_hex = super::utils::encode_hex(&super::utils::sha256(end_entity.as_ref()));
            if &cert_hex != fingerprint {
                return Err(rustls::Error::General(format!(
                    "cert hash mismatch: found: {cert_hex}\nexcept: {fingerprint}"
                )));
            }
        }

        if self.skip {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        self.pki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.skip {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }
        self.pki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.skip {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }
        self.pki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.pki.supported_verify_schemes()
    }
}
