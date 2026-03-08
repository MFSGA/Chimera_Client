#[cfg(feature = "tls")]
mod tls;

#[cfg(feature = "ws")]
mod ws;
mod xhttp;

#[cfg(feature = "tls")]
pub use tls::Client as TlsClient;
#[cfg(feature = "ws")]
pub use ws::Client as WsClient;
pub use xhttp::{Client as XhttpClient, XhttpMode};

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;
}
#[cfg(feature = "reality")]
pub mod reality;

#[cfg(feature = "reality")]
pub use reality::{
    Client as RealityClient, DEFAULT_REALITY_SHORT_ID, decode_public_key,
    decode_short_id,
};
