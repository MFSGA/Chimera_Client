#![allow(dead_code)]

mod buf_reader;
mod common;
mod crypto_connection;
mod crypto_handshake;
mod crypto_tls_stream;
mod reality_aead;
mod reality_auth;
mod reality_cipher_suite;
mod reality_client_connection;
mod reality_client_verify;
mod reality_hybrid;
mod reality_io_state;
mod reality_reader_writer;
mod reality_records;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;
mod slide_buffer;
#[cfg(feature = "vision")]
mod splice_tls;
mod sync_adapter;
mod util;

pub use crypto_tls_stream::CryptoTlsStream;
pub use reality_cipher_suite::CipherSuite;
pub use reality_util::{decode_public_key, decode_short_id};
#[cfg(feature = "vision")]
pub use splice_tls::SplicableTlsStream;

pub const DEFAULT_REALITY_SHORT_ID: &str = "";

#[derive(Clone, Debug)]
pub struct Client {
    public_key: [u8; 32],
    short_id: Vec<u8>,
    server_name: String,
    cipher_suites: Vec<CipherSuite>,
    alpn_protocols: Vec<String>,
    support_x25519mlkem768: bool,
}

impl Client {
    pub fn new(
        public_key: [u8; 32],
        short_id: Vec<u8>,
        server_name: String,
        cipher_suites: Vec<CipherSuite>,
    ) -> Self {
        Self::new_with_alpn(
            public_key,
            short_id,
            server_name,
            cipher_suites,
            Vec::new(),
        )
    }

    pub fn new_with_alpn(
        public_key: [u8; 32],
        short_id: Vec<u8>,
        server_name: String,
        cipher_suites: Vec<CipherSuite>,
        alpn_protocols: Vec<String>,
    ) -> Self {
        Self {
            public_key,
            short_id,
            server_name,
            cipher_suites,
            alpn_protocols,
            support_x25519mlkem768: false,
        }
    }

    /// Offer X25519MLKEM768 and its X25519 fallback share. Classic X25519-only
    /// remains the default; the negotiated ServerHello group is validated.
    #[must_use]
    pub fn with_x25519mlkem768(mut self, enabled: bool) -> Self {
        self.support_x25519mlkem768 = enabled;
        self
    }

    pub fn offers_x25519mlkem768(&self) -> bool {
        self.support_x25519mlkem768
    }

    /// Establish a REALITY TLS session over the caller-provided stream.
    pub async fn handshake_stream<IO>(
        &self,
        mut stream: IO,
    ) -> std::io::Result<CryptoTlsStream<IO>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let config = reality_client_connection::RealityClientConfig {
            public_key: self.public_key,
            short_id: self.short_id.clone(),
            server_name: self.server_name.clone(),
            cipher_suites: self.cipher_suites.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            support_x25519mlkem768: self.support_x25519mlkem768,
        };
        let conn = reality_client_connection::RealityClientConnection::new(config)?;
        let mut connection =
            crypto_connection::CryptoConnection::new_reality_client(conn);
        crypto_handshake::perform_crypto_handshake(
            &mut connection,
            &mut stream,
            common::TLS_MAX_RECORD_SIZE,
        )
        .await?;
        Ok(CryptoTlsStream::new(stream, connection))
    }
}
