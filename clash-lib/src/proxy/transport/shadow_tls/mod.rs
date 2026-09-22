#![allow(dead_code)]

use async_trait::async_trait;
use rand::{RngExt, distr::Distribution};
use std::{io, ptr::copy_nonoverlapping, sync::Arc};
use stream::{ProxyTlsStream, VerifiedStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsConnector, client::TlsStream};
use utils::Hmac;
use v2::{HandshakeStream as V2HandshakeStream, Stream as V2Stream};

mod prelude;
mod stream;
mod utils;
mod v2;

use super::Transport;
use crate::{
    common::{errors::map_io_error, tls::GLOBAL_ROOT_STORE},
    proxy::AnyStream,
};
use prelude::*;

/// Shadow-tls V3 client.
///
/// Wraps an arbitrary `AnyStream` in a TLS 1.3 connection that is
/// indistinguishable from a normal TLS handshake on the wire. The actual
/// application data is XORed / authenticated with an HMAC keyed with
/// `password` and the server random — see the shadow-tls V3 spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShadowtlsVersion {
    V1,
    V2,
    V3,
}

#[derive(Debug)]
pub struct Shadowtls {
    host: String,
    password: String,
    strict: bool,
    version: ShadowtlsVersion,
}

impl Shadowtls {
    pub fn new(host: String, password: String, strict: bool) -> Self {
        Self {
            host,
            password,
            strict,
            version: ShadowtlsVersion::V3,
        }
    }

    pub fn new_v1(host: String) -> Self {
        Self {
            host,
            password: String::new(),
            strict: false,
            version: ShadowtlsVersion::V1,
        }
    }

    pub fn new_v2(host: String, password: String) -> Self {
        Self {
            host,
            password,
            strict: false,
            version: ShadowtlsVersion::V2,
        }
    }

    pub async fn wrap_shadow_tls_stream(
        &self,
        stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        match self.version {
            ShadowtlsVersion::V1 => self.wrap_shadow_tls_v1_stream(stream).await,
            ShadowtlsVersion::V2 => self.wrap_shadow_tls_v2_stream(stream).await,
            ShadowtlsVersion::V3 => self.wrap_shadow_tls_v3_stream(stream).await,
        }
    }

    async fn wrap_shadow_tls_v1_stream(
        &self,
        stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        let sni_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(map_io_error)?;
        let tls = new_v1_connector().connect(sni_name, stream).await?;
        Ok(tls.into_inner().0)
    }

    async fn wrap_shadow_tls_v2_stream(
        &self,
        stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        let challenge = Hmac::new(&self.password, (&[], &[]));
        let handshake_stream = V2HandshakeStream::new(stream, challenge);
        let sni_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(map_io_error)?;
        let tls = new_connector().connect(sni_name, handshake_stream).await?;
        let handshake_stream = tls.into_inner().0;
        let (raw, challenge) = handshake_stream.into_parts();
        Ok(Box::new(V2Stream::new(raw, challenge.finalize_v2())))
    }

    async fn wrap_shadow_tls_v3_stream(
        &self,
        stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        let proxy_stream = ProxyTlsStream::new(stream, &self.password);

        // ShadowTLS V3 authenticates the ClientHello by replacing its
        // compatibility session ID with a password-derived signature. This
        // must happen inside rustls before the ClientHello enters the
        // handshake transcript; rewriting the bytes below rustls would make
        // the client/server transcript hashes diverge.
        let hmac_handshake = Hmac::new(&self.password, (&[], &[]));
        let sni_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(map_io_error)?;
        let session_id_generator =
            move |data: &[u8]| generate_session_id(&hmac_handshake, data);
        let connector = new_connector();
        let mut tls = connector
            .connect_with_session_id_generator(
                sni_name,
                proxy_stream,
                Some(session_id_generator),
                |_| {},
            )
            .await?;

        // check if is authorized
        let authorized = tls.get_mut().0.authorized();
        let maybe_server_random_and_hamc = tls
            .get_mut()
            .0
            .state()
            .as_ref()
            .map(|s| (s.server_random, s.hmac.to_owned()));

        // whatever the fake_request is successful or not, we should return an
        // error when strict mode is enabled
        if (!authorized || maybe_server_random_and_hamc.is_none()) && self.strict {
            tracing::warn!(
                "shadow-tls V3 strict enabled: traffic hijacked or TLS1.3 is not \
                 supported, perform fake request"
            );

            tls.get_mut().0.fake_request = true;
            fake_request(tls).await?;

            return Err(io::Error::other(
                "V3 strict enabled: traffic hijacked or TLS1.3 is not supported, \
                 fake request",
            ));
        }

        let (server_random, hmac_nop) = match maybe_server_random_and_hamc {
            Some(inner) => inner,
            None => {
                return Err(io::Error::other(
                    "server random and hmac not extracted from handshake, fail to \
                     connect",
                ));
            }
        };

        let hmac_client =
            Hmac::new(&self.password, (&server_random, "C".as_bytes()));
        let hmac_server =
            Hmac::new(&self.password, (&server_random, "S".as_bytes()));

        // now the shadow tls stream is connected, we can use it to send data
        let verified_stream = VerifiedStream::new(
            tls.into_inner().0.raw,
            hmac_client,
            hmac_server,
            Some(hmac_nop),
        );

        Ok(Box::new(verified_stream))
    }
}

#[async_trait]
impl Transport for Shadowtls {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        self.wrap_shadow_tls_stream(stream).await
    }
}

fn new_connector() -> TlsConnector {
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
        .with_no_client_auth();

    TlsConnector::from(Arc::new(tls_config))
}

fn new_v1_connector() -> TlsConnector {
    let tls_config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
    ])
    .with_root_certificates(GLOBAL_ROOT_STORE.clone())
    .with_no_client_auth();

    TlsConnector::from(Arc::new(tls_config))
}

/// Take a slice of tls message[5..] and returns signed session id.
///
/// Only used by V3 protocol.
fn generate_session_id(hmac: &Hmac, buf: &[u8]) -> [u8; TLS_SESSION_ID_SIZE] {
    /// Note: SESSION_ID_START does not include 5 TLS_HEADER_SIZE.
    const SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;

    if buf.len() < SESSION_ID_START + TLS_SESSION_ID_SIZE {
        tracing::warn!("unexpected client hello length");
        return [0; TLS_SESSION_ID_SIZE];
    }

    let mut session_id = [0; TLS_SESSION_ID_SIZE];
    rand::fill(&mut session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE]);
    let mut hmac = hmac.to_owned();
    hmac.update(&buf[0..SESSION_ID_START]);
    hmac.update(&session_id);
    hmac.update(&buf[SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
    let hmac_val = hmac.finalize();
    unsafe {
        copy_nonoverlapping(
            hmac_val.as_ptr(),
            session_id.as_mut_ptr().add(TLS_SESSION_ID_SIZE - HMAC_SIZE),
            HMAC_SIZE,
        )
    }
    session_id
}

/// Doing fake request.
///
/// Only used by V3 protocol.
async fn fake_request<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: TlsStream<S>,
) -> std::io::Result<()> {
    const HEADER: &[u8; 207] = b"GET / HTTP/1.1\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\nAccept: gzip, deflate, br\nConnection: Close\nCookie: sessionid=";
    const FAKE_REQUEST_LENGTH_RANGE: (usize, usize) = (16, 64);
    let cnt = rand::rng()
        .random_range(FAKE_REQUEST_LENGTH_RANGE.0..FAKE_REQUEST_LENGTH_RANGE.1);
    let mut buffer = Vec::with_capacity(cnt + HEADER.len() + 1);

    buffer.extend_from_slice(HEADER);
    rand::distr::Alphanumeric
        .sample_iter(rand::rng())
        .take(cnt)
        .for_each(|c| buffer.push(c));
    buffer.push(b'\n');

    stream.write_all(&buffer).await?;
    let _ = stream.shutdown().await;

    // read until eof
    let mut buf = Vec::with_capacity(1024);
    let r = stream.read_to_end(&mut buf).await;
    r.map(|_| ())
}
