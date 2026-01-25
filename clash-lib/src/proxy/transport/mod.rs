mod tls;
mod ws;

pub use tls::Client as TlsClient;
pub use ws::Client as WsClient;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;
}