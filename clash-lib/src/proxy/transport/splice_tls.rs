/// XTLS-splice capable TLS stream.
///
/// Wraps a `TlsStream<AnyStream>` and can switch to raw (bypass-TLS) mode when
/// signalled via shared `Arc<AtomicBool>` flags.  This is required for
/// XTLS-Vision: after both sides exchange `CMD_PADDING_DIRECT`, they bypass the
/// outer Reality-TLS layer and communicate over the raw TCP socket.
use std::{
    io::{self, Read},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::proxy::AnyStream;
use crate::proxy::transport::reality::CryptoTlsStream;

type RealityTlsStream = CryptoTlsStream<AnyStream>;

/// Options passed to `VisionStream` when XTLS-splice mode is active.
///
/// Shared `Arc<AtomicBool>` flags are written by `VisionStream` when it
/// detects `CMD_PADDING_DIRECT`, and read by `SplicableTlsStream` to know
/// when to bypass the Reality TLS layer.
pub struct VisionOptions {
    pub read_flag: Arc<AtomicBool>,
    pub write_flag: Arc<AtomicBool>,
}

pub struct SplicableTlsStream {
    tls: RealityTlsStream,

    // Bytes drained from TLS plaintext buffer on the first raw-read.
    leftover: BytesMut,

    // Shared with VisionStream: set when CMD_DIRECT is received from server.
    read_flag: Arc<AtomicBool>,
    read_spliced: bool,

    // Shared with VisionStream: set when CMD_DIRECT is sent to server.
    write_flag: Arc<AtomicBool>,
    write_spliced: bool,
}

impl SplicableTlsStream {
    pub fn new(
        tls: RealityTlsStream,
        read_flag: Arc<AtomicBool>,
        write_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            tls,
            leftover: BytesMut::new(),
            read_flag,
            read_spliced: false,
            write_flag,
            write_spliced: false,
        }
    }

    /// Drain the TLS plaintext buffer into `self.leftover` and flip
    /// `read_spliced`.  After this, reads go directly to the raw IO.
    fn activate_read_splice(&mut self) {
        debug!("SplicableTlsStream: activating read splice (bypassing Reality TLS)");
        let (_, conn) = self.tls.get_mut();
        let mut tmp = [0u8; 4096];
        loop {
            match conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => self.leftover.put_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        debug!(
            "SplicableTlsStream: drained {} plaintext bytes before read splice",
            self.leftover.len()
        );
        let pending_raw = conn.take_remaining_ciphertext();
        if !pending_raw.is_empty() {
            debug!(
                "SplicableTlsStream: carrying {} raw bytes buffered past REALITY",
                pending_raw.len()
            );
            self.leftover.put_slice(&pending_raw);
        }
        self.read_spliced = true;
    }

    fn activate_write_splice(&mut self) {
        debug!(
            "SplicableTlsStream: activating write splice (bypassing Reality TLS)"
        );
        self.write_spliced = true;
    }

    fn should_recover_from_reality_read_error(&self, err: &io::Error) -> bool {
        should_recover_from_reality_read_error(
            err.kind(),
            self.tls.is_reality(),
            self.write_spliced,
            self.read_spliced,
        )
    }
}

impl AsyncRead for SplicableTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check if we need to switch to raw read.
        if !this.read_spliced && this.read_flag.load(Ordering::Acquire) {
            this.activate_read_splice();
        }

        // Return leftover plaintext drained from TLS first.
        if !this.leftover.is_empty() {
            let amt = this.leftover.len().min(buf.remaining());
            buf.put_slice(&this.leftover[..amt]);
            this.leftover.advance(amt);
            return Poll::Ready(Ok(()));
        }

        if this.read_spliced {
            // Bypass Reality TLS — read raw bytes from the underlying IO.
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_read(cx, buf)
        } else {
            match Pin::new(&mut this.tls).poll_read(cx, buf) {
                Poll::Ready(Err(err))
                    if this.should_recover_from_reality_read_error(&err) =>
                {
                    debug!(
                        "SplicableTlsStream: recovering from REALITY read error after write splice: {}",
                        err
                    );
                    this.activate_read_splice();

                    if !this.leftover.is_empty() {
                        let amt = this.leftover.len().min(buf.remaining());
                        buf.put_slice(&this.leftover[..amt]);
                        this.leftover.advance(amt);
                        Poll::Ready(Ok(()))
                    } else {
                        let (io, _) = this.tls.get_mut();
                        Pin::new(io).poll_read(cx, buf)
                    }
                }
                other => other,
            }
        }
    }
}

impl AsyncWrite for SplicableTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.write_spliced && this.write_flag.load(Ordering::Acquire) {
            match Pin::new(&mut this.tls).poll_flush(cx) {
                Poll::Ready(Ok(())) => this.activate_write_splice(),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if this.write_spliced {
            // Bypass Reality TLS — write raw bytes to the underlying IO.
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_write(cx, buf)
        } else {
            Pin::new(&mut this.tls).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_spliced && this.write_flag.load(Ordering::Acquire) {
            match Pin::new(&mut this.tls).poll_flush(cx) {
                Poll::Ready(Ok(())) => this.activate_write_splice(),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if this.write_spliced {
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_flush(cx)
        } else {
            Pin::new(&mut this.tls).poll_flush(cx)
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_spliced && this.write_flag.load(Ordering::Acquire) {
            match Pin::new(&mut this.tls).poll_flush(cx) {
                Poll::Ready(Ok(())) => this.activate_write_splice(),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if this.write_spliced {
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_shutdown(cx)
        } else {
            Pin::new(&mut this.tls).poll_shutdown(cx)
        }
    }
}

fn should_recover_from_reality_read_error(
    err_kind: io::ErrorKind,
    is_reality: bool,
    write_spliced: bool,
    read_spliced: bool,
) -> bool {
    is_reality
        && write_spliced
        && !read_spliced
        && err_kind == io::ErrorKind::InvalidData
}

#[cfg(test)]
mod tests {
    use super::should_recover_from_reality_read_error;
    use std::io;

    #[test]
    fn recovers_only_for_reality_invalid_data_after_write_splice() {
        assert!(should_recover_from_reality_read_error(
            io::ErrorKind::InvalidData,
            true,
            true,
            false,
        ));
    }

    #[test]
    fn does_not_recover_before_write_splice() {
        assert!(!should_recover_from_reality_read_error(
            io::ErrorKind::InvalidData,
            true,
            false,
            false,
        ));
    }

    #[test]
    fn does_not_recover_after_read_splice_is_active() {
        assert!(!should_recover_from_reality_read_error(
            io::ErrorKind::InvalidData,
            true,
            true,
            true,
        ));
    }

    #[test]
    fn does_not_recover_non_invalid_data_errors() {
        assert!(!should_recover_from_reality_read_error(
            io::ErrorKind::ConnectionReset,
            true,
            true,
            false,
        ));
    }
}
