mod grpc;
mod tls;

#[cfg(feature = "ws")]
mod ws;
mod xhttp;

use crate::proxy::utils::NetworkPoolContext;

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
