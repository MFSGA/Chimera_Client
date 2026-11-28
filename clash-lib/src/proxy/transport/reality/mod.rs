use std::{
    io,
    sync::{Arc, atomic::AtomicBool},
};

use crate::proxy::{AnyStream, transport::splice_tls::SplicableTlsStream};

use super::{Transport, VisionOptions};

pub use chimera_reality_core::{
    Client, DEFAULT_REALITY_SHORT_ID, decode_public_key, decode_short_id,
};

#[async_trait::async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        Ok(Box::new(self.handshake_stream(stream).await?))
    }

    async fn proxy_stream_spliced(
        &self,
        stream: AnyStream,
    ) -> io::Result<(AnyStream, Option<VisionOptions>)> {
        let read_flag = Arc::new(AtomicBool::new(false));
        let write_flag = Arc::new(AtomicBool::new(false));
        // Keep the REALITY I/O type consistent with VlessStream's downcast.
        // Passing Clash's child trait object directly would make
        // SplicableTlsStream<clash_lib::AnyStream>, which cannot be recovered
        // as SplicableTlsStream<chimera_reality_core::AnyStream> later.
        let stream: chimera_reality_core::AnyStream = stream;
        let tls_stream = self.handshake_stream(stream).await?;
        let splicable = SplicableTlsStream::new(
            tls_stream,
            Arc::clone(&read_flag),
            Arc::clone(&write_flag),
        );
        Ok((
            Box::new(splicable),
            Some(VisionOptions {
                read_flag,
                write_flag,
            }),
        ))
    }
}
