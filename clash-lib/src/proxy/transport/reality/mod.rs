use async_trait::async_trait;
use std::{
    io,
    sync::{Arc, atomic::AtomicBool},
};

use super::Transport;
use crate::proxy::transport::splice_tls::SplicableTlsStream;
use crate::proxy::{AnyStream, transport::VisionOptions};

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
mod reality_io_state;
mod reality_reader_writer;
mod reality_records;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;
mod slide_buffer;
mod sync_adapter;
mod util;

pub use reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
pub use reality_util::{decode_public_key, decode_short_id};

pub(crate) use crypto_connection::{CryptoConnection, feed_crypto_connection};
pub(crate) use crypto_handshake::perform_crypto_handshake;
pub(crate) use crypto_tls_stream::CryptoTlsStream;
pub(crate) use sync_adapter::{SyncReadAdapter, SyncWriteAdapter};
pub(crate) use util::allocate_vec;

pub const DEFAULT_REALITY_SHORT_ID: &str = "0000000000000000";

#[derive(Clone, Debug)]
pub struct Client {
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: String,
    cipher_suites: Vec<CipherSuite>,
}

impl Client {
    pub fn new(
        public_key: [u8; 32],
        short_id: [u8; 8],
        server_name: String,
        cipher_suites: Vec<CipherSuite>,
    ) -> Self {
        Self {
            public_key,
            short_id,
            server_name,
            cipher_suites,
        }
    }

    pub async fn handshake_stream(
        &self,
        stream: AnyStream,
    ) -> io::Result<CryptoTlsStream<AnyStream>> {
        let config = reality_client_connection::RealityClientConfig {
            public_key: self.public_key,
            short_id: self.short_id,
            server_name: self.server_name.clone(),
            cipher_suites: self.cipher_suites.clone(),
        };
        let conn = reality_client_connection::RealityClientConnection::new(config)?;
        let mut connection = CryptoConnection::new_reality_client(conn);
        let mut stream = stream;
        perform_crypto_handshake(
            &mut connection,
            &mut stream,
            common::TLS_MAX_RECORD_SIZE,
        )
        .await?;
        Ok(CryptoTlsStream::new(stream, connection))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        tracing::debug!(
            "Starting Reality client handshake for server '{}'",
            self.server_name
        );
        let tls_stream = self.handshake_stream(stream).await?;
        Ok(Box::new(tls_stream))
    }

    /// Establish a Reality TLS connection and return the stream together with
    /// `VisionOptions` (a pair of `Arc<AtomicBool>` splice flags) that allow
    /// the upper `VisionStream` to signal this layer when XTLS-splice mode is
    /// triggered.
    ///
    /// ## Layer stack
    ///
    /// ```text
    ///  VisionStream          (owns VisionOptions – writes the flags)
    ///    └─ VlessStream      (VLESS framing)
    ///        └─ SplicableTlsStream  (reads the flags; bypasses TLS when set)
    ///            └─ Reality TLS
    ///                └─ TCP
    /// ```
    ///
    /// ## Handshake / splice sequence
    ///
    /// ```text
    ///  Client                                  Xray server
    ///    |                                          |
    ///    |---------- Reality TLS handshake -------->|
    ///    |<--------- Reality TLS handshake ---------|
    ///    |   (all traffic above is Reality-TLS encrypted)
    ///    |                                          |
    ///    |========== Vision framing mode ===========|
    ///    |--[UUID][CMD=0x00][inner TLS ClientHello]->|  Vision-framed inner TLS
    ///    |<-[UUID][CMD=0x00][inner TLS ServerHello]--|
    ///    |<-[CMD=0x02][inner TLS AppData]------------|  server triggers splice
    ///    |--[CMD=0x02][inner TLS AppData]----------->|  client triggers splice
    ///    |                                          |
    ///    |  (both sides received CMD_DIRECT)        |
    ///    |                                          |
    ///    |========== Splice mode (raw TCP) ==========|
    ///    |--[raw inner-TLS AppData]----------------->|  no outer TLS encryption
    ///    |<-[raw inner-TLS AppData]------------------|
    /// ```
    ///
    /// On `CMD_PADDING_DIRECT` (0x02):
    /// - `VisionStream` sets `read_flag` / `write_flag` to `true`.
    /// - `SplicableTlsStream` detects the flags and bypasses Reality TLS,
    ///   reading/writing raw bytes directly on the TCP socket.
    async fn proxy_stream_spliced(
        &self,
        stream: AnyStream,
    ) -> io::Result<(AnyStream, Option<VisionOptions>)> {
        let read_flag = Arc::new(AtomicBool::new(false));
        let write_flag = Arc::new(AtomicBool::new(false));
        let tls_stream = self.handshake_stream(stream).await?;
        let splittable = SplicableTlsStream::new(
            tls_stream,
            Arc::clone(&read_flag),
            Arc::clone(&write_flag),
        );
        let opts = VisionOptions {
            read_flag,
            write_flag,
        };
        Ok((Box::new(splittable), Some(opts)))
    }
}
