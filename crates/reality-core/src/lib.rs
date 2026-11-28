//! Minimal REALITY and VLESS Vision transport primitives shared by Chimera
//! and the standalone transport benchmark client.

#[cfg(feature = "vision")]
use std::sync::{Arc, atomic::AtomicBool};

#[cfg(feature = "vless")]
use std::net::SocketAddr;

#[cfg(any(feature = "vless", feature = "vision"))]
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "vless")]
pub trait ProxyStream:
    AsyncRead + AsyncWrite + Send + Sync + Unpin + std::any::Any
{
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

#[cfg(feature = "vless")]
impl<T> ProxyStream for T
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + std::any::Any,
{
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(feature = "vless")]
pub type AnyStream = Box<dyn ProxyStream>;

/// Shared flags used by VLESS Vision and the outer REALITY stream adapter.
#[cfg(feature = "vision")]
#[derive(Clone, Debug, Default)]
pub struct VisionOptions {
    pub read_flag: Arc<AtomicBool>,
    pub write_flag: Arc<AtomicBool>,
}

/// Address encoded into a VLESS TCP request header.
#[cfg(feature = "vless")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[cfg(feature = "vless")]
impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(address) => write!(f, "{address}"),
            Self::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

#[cfg(feature = "vless")]
impl TargetAddr {
    pub fn write_to_vless_buffer(&self, buffer: &mut impl bytes::BufMut) {
        match self {
            Self::Ip(SocketAddr::V4(address)) => {
                buffer.put_u16(address.port());
                buffer.put_u8(0x01);
                buffer.put_slice(&address.ip().octets());
            }
            Self::Ip(SocketAddr::V6(address)) => {
                buffer.put_u16(address.port());
                buffer.put_u8(0x03);
                for segment in &address.ip().segments() {
                    buffer.put_u16(*segment);
                }
            }
            Self::Domain(domain, port) => {
                buffer.put_u16(*port);
                buffer.put_u8(0x02);
                buffer.put_u8(domain.len() as u8);
                buffer.put_slice(domain.as_bytes());
            }
        }
    }
}

#[cfg(feature = "vless")]
impl From<std::net::SocketAddr> for TargetAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

#[cfg(feature = "vision")]
pub mod vision;

#[cfg(feature = "vless")]
pub mod vless;

#[cfg(feature = "reality")]
pub mod reality;

#[cfg(feature = "reality")]
pub use reality::{
    CipherSuite, Client, Client as RealityClient, CryptoTlsStream,
    DEFAULT_REALITY_SHORT_ID, decode_public_key, decode_short_id,
};

#[cfg(all(feature = "reality", feature = "vision"))]
pub use reality::SplicableTlsStream;

#[cfg(feature = "vision")]
pub use vision::VisionStream;

#[cfg(feature = "vless")]
pub use vless::VlessStream;

#[cfg(test)]
pub(crate) fn setup_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
