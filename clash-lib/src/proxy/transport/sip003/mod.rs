#![allow(dead_code)]

use async_trait::async_trait;

use super::Transport;
use crate::proxy::AnyStream;

/// SIP003 plugin trait. Wraps a TCP stream with an obfuscation / transport
/// layer before handing it to the Shadowsocks proxy. The `ss` outbound
/// exposes these as `plugin: Option<Box<dyn Sip003Plugin>>`.
#[async_trait]
pub trait Sip003Plugin: Send + Sync {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream>;
}

/// Any `Transport` (TLS, WS, simple-obfs, v2ray-plugin, shadow-tls, ...) is
/// also usable as a SIP003 plugin. This is the bridge the Shadowsocks
/// converter relies on so it can store all plugin variants in one
/// `Box<dyn Sip003Plugin>` slot.
#[async_trait]
impl<T: Transport> Sip003Plugin for T {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        Transport::proxy_stream(self, stream).await
    }
}
