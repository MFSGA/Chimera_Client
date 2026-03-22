#[cfg(feature = "tls")]
mod tls;

#[cfg(feature = "ws")]
mod ws;
mod xhttp;

pub mod splice_tls;

#[cfg(feature = "tls")]
pub use tls::Client as TlsClient;
#[cfg(feature = "ws")]
pub use ws::Client as WsClient;
pub use xhttp::{
    Client as XhttpClient, XhttpDownloadConfig, XhttpMode, XhttpRealityConfig,
    XhttpSecurity,
};

pub use splice_tls::VisionOptions;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;

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
