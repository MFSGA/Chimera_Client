#[cfg(feature = "tls")]
mod tls;

#[cfg(feature = "ws")]
mod ws;

#[cfg(feature = "tls")]
pub use tls::Client as TlsClient;
#[cfg(feature = "ws")]
pub use ws::Client as WsClient;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn proxy_stream(&self, stream: super::AnyStream) -> std::io::Result<super::AnyStream>;
}
