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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use tokio::io::duplex;

    use super::{Sip003Plugin, Transport};
    use crate::proxy::AnyStream;

    /// Pass-through Transport that records each `proxy_stream` call.
    #[derive(Default)]
    struct CountingTransport {
        calls: Arc<AtomicUsize>,
        inner: Arc<Mutex<Option<AnyStream>>>,
    }

    #[async_trait]
    impl Transport for CountingTransport {
        async fn proxy_stream(
            &self,
            stream: AnyStream,
        ) -> std::io::Result<AnyStream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut slot = self.inner.lock().unwrap();
            *slot = Some(Box::new(stream));
            let (a, _b) = duplex(64);
            Ok(Box::new(a))
        }
    }

    #[tokio::test]
    async fn blanked_impl_dispatches_to_transport_proxy_stream() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(Mutex::new(None));
        let t = CountingTransport {
            calls: calls.clone(),
            inner: inner.clone(),
        };

        let plugin: Box<dyn Sip003Plugin> = Box::new(t);

        let (client, _server) = duplex(64);
        let result = plugin.proxy_stream(Box::new(client)).await;
        assert!(result.is_ok(), "plugin proxy_stream should succeed");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
