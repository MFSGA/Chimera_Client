mod grpc;
mod tls;

#[cfg(feature = "ws")]
mod ws;
mod xhttp;

#[cfg(any(feature = "hysteria", feature = "xhttp-h3"))]
pub(crate) use xhttp::quinn_datagram::ConnectorUdpSocket;

use crate::{app::flow::NetworkPathId, proxy::utils::NetworkPoolContext};

pub mod shadow_tls;
pub mod simple_obfs;
pub mod sip003;
#[cfg(feature = "ws")]
pub mod v2ray;

#[cfg(feature = "reality")]
pub mod splice_tls;

pub use grpc::Client as GrpcClient;
pub use tls::Client as TlsClient;
#[cfg(feature = "ws")]
pub use ws::Client as WsClient;
pub use xhttp::{
    Client as XhttpClient, MetadataPlacement as XhttpMetadataPlacement,
    UplinkDataPlacement as XhttpUplinkDataPlacement, XhttpChunkSizeRange,
    XhttpDownloadConfig, XhttpEndpointConfig, XhttpHttpVersion, XhttpMetadataConfig,
    XhttpMode, XhttpPaddingConfig, XhttpPaddingMethod, XhttpPaddingPlacement,
    XhttpRealityConfig, XhttpReusePolicy, XhttpReuseValueRange, XhttpSecurity,
    XhttpSessionIdConfig, XhttpUplinkConfig,
};

#[allow(unused_imports)]
pub use shadow_tls::Shadowtls;
#[allow(unused_imports)]
pub use simple_obfs::{
    SimpleOBFSMode, SimpleOBFSOption, SimpleObfsHttp, SimpleObfsTLS,
};
pub use sip003::Sip003Plugin;
#[cfg(feature = "reality")]
pub use splice_tls::VisionOptions;
#[cfg(not(feature = "reality"))]
#[derive(Clone, Debug, Default)]
pub struct VisionOptions {
    pub read_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub write_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(feature = "ws")]
#[allow(unused_imports)]
pub use v2ray::{V2RayOBFSOption, V2rayWsClient};

/// S04b-r: a pool reset can cancel an operation just as its async
/// construction becomes ready. Recheck after the biased select, before the
/// resulting logical stream crosses the caller boundary. Dropping a successful
/// result on cancellation prevents delivery; it cannot undo prior I/O.
pub(super) fn finish_pool_delivery<T>(
    cancellation: &tokio_util::sync::CancellationToken,
    result: std::io::Result<T>,
) -> std::io::Result<T> {
    if cancellation.is_cancelled() {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "network changed before transport stream delivery",
        ))
    } else {
        result
    }
}

#[cfg(test)]
mod s04br_tests {
    use super::finish_pool_delivery;
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio_util::sync::CancellationToken;

    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn s04br_cancel_when_stream_construction_becomes_ready_discards_result() {
        let cancellation = CancellationToken::new();
        let discarded = Arc::new(AtomicBool::new(false));
        let result: io::Result<DropFlag> = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(io::Error::other("unexpected pre-construction cancellation")),
            value = async {
                // Make the result ready on the very poll that signals reset.
                // The biased select has already polled the cancellation arm.
                cancellation.cancel();
                Ok(DropFlag(discarded.clone()))
            } => value,
        };
        let err = finish_pool_delivery(&cancellation, result)
            .err()
            .expect("cancelled stream must not be delivered");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(discarded.load(Ordering::SeqCst));
    }

    #[test]
    fn s04br_uncancelled_result_preserves_success_and_upstream_errors() {
        let cancellation = CancellationToken::new();
        assert_eq!(finish_pool_delivery(&cancellation, Ok(7)).unwrap(), 7);
        let error: io::Result<u32> = Err(io::Error::other("real handshake failure"));
        assert!(
            finish_pool_delivery(&cancellation, error)
                .unwrap_err()
                .to_string()
                .contains("handshake failure")
        );
    }
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Retire cached underlying connections after the physical path changes.
    /// Existing logical streams retain their own handles and are not replayed.
    async fn reset_connection_pool(&self) -> std::io::Result<u32> {
        Ok(0)
    }

    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;

    /// Build a stream whose reusable connection belongs to a known network
    /// generation. Transports without a reusable pool can keep the default.
    async fn proxy_stream_for_network_generation(
        &self,
        stream: super::AnyStream,
        _generation: Option<u64>,
    ) -> std::io::Result<super::AnyStream> {
        self.proxy_stream(stream).await
    }

    /// Build a stream associated with the actual network path selected by the
    /// connector. Reusable transports can use path eligibility to retain pools
    /// on unaffected interfaces while retiring stale ones.
    async fn proxy_stream_with_pool_context(
        &self,
        stream: super::AnyStream,
        context: NetworkPoolContext,
    ) -> std::io::Result<super::AnyStream> {
        self.proxy_stream_for_network_generation(stream, context.network_generation)
            .await
    }

    /// Let a transport establish its own underlying connection when its wire
    /// protocol cannot be layered over the caller's pre-dialed TCP stream.
    ///
    /// QUIC-based transports use this hook so they can dial UDP while still
    /// honoring the active resolver, interface/mark, and chained connector.
    /// Stream-based transports leave the default `None` result and continue
    /// through `proxy_stream` with the caller-owned TCP connection.
    async fn connect_stream_with_connector(
        &self,
        _sess: &crate::session::Session,
        _resolver: crate::app::dns::ThreadSafeDNSResolver,
        _connector: &dyn crate::proxy::utils::RemoteConnector,
    ) -> std::io::Result<Option<super::AnyStream>> {
        Ok(None)
    }

    /// As above, with the local NIC paths used by transport-owned sockets.
    /// The default has NO physical-socket evidence. A pre-dial connector
    /// context is routing intent, never proof of a transport-owned socket.
    /// Path-aware transports must override and return completed connection IDs.
    async fn connect_stream_with_connector_and_path_ids(
        &self,
        sess: &crate::session::Session,
        resolver: crate::app::dns::ThreadSafeDNSResolver,
        connector: &dyn crate::proxy::utils::RemoteConnector,
    ) -> std::io::Result<Option<(super::AnyStream, Vec<NetworkPathId>)>> {
        Ok(self
            .connect_stream_with_connector(sess, resolver, connector)
            .await?
            .map(|stream| (stream, Vec::new())))
    }

    /// Return a logical stream from an already-owned underlying connection.
    ///
    /// Transports that do not own reusable connections leave this as `None`.
    /// Callers must invoke this before dialing a new raw stream, otherwise
    /// connection reuse would still pay the TCP/TLS handshake cost.
    async fn try_reuse_stream(&self) -> std::io::Result<Option<super::AnyStream>> {
        Ok(None)
    }

    /// Only borrow a pooled connection created on the caller's current
    /// network generation. The default preserves transports without pools.
    async fn try_reuse_stream_for_network_generation(
        &self,
        _generation: Option<u64>,
    ) -> std::io::Result<Option<super::AnyStream>> {
        self.try_reuse_stream().await
    }

    /// Borrow a pooled connection only if it still belongs to an eligible
    /// network path. Transports that do not track paths keep generation-only
    /// behavior through the default implementation.
    async fn try_reuse_stream_with_pool_context(
        &self,
        context: NetworkPoolContext,
    ) -> std::io::Result<Option<super::AnyStream>> {
        self.try_reuse_stream_for_network_generation(context.network_generation)
            .await
    }

    /// Reuse an underlying connection and return its stored path metadata.
    /// The default is generation-only for transports that do not tag entries.
    async fn try_reuse_stream_with_pool_metadata(
        &self,
        context: NetworkPoolContext,
    ) -> std::io::Result<Option<(super::AnyStream, NetworkPoolContext)>> {
        Ok(self
            .try_reuse_stream_with_pool_context(context.clone())
            .await?
            .map(|stream| (stream, context)))
    }

    /// Like `proxy_stream`, but additionally returns a `VisionOptions` for
    /// transports that support XTLS-splice (Reality).  The default
    /// implementation delegates to `proxy_stream` and returns `None`,
    /// meaning no splice is available.
    async fn proxy_stream_spliced(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<(super::AnyStream, Option<VisionOptions>)> {
        Ok((self.proxy_stream(stream).await?, None))
    }
}
#[cfg(feature = "reality")]
pub mod reality;

#[cfg(feature = "reality")]
pub use reality::{
    Client as RealityClient, DEFAULT_REALITY_SHORT_ID, decode_public_key,
    decode_short_id,
};
