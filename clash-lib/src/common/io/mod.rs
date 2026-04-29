/// copy of https://github.com/eycorsican/leaf/blob/a77a1e497ae034f3a2a89c8628d5e7ebb2af47f0/leaf/src/common/io.rs
use std::future::Future;
use std::{
    io,
    mem::MaybeUninit,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
mod splice;
#[cfg(all(target_os = "linux", feature = "zero_copy"))]
pub use splice::zero_copy_bidirectional;

use crate::{app::dispatcher::TrackedStream, proxy::ClientStream};

#[derive(Debug)]
pub enum CopyBidirectionalError {
    LeftClosed(std::io::Error),
    RightClosed(std::io::Error),
    Other(std::io::Error),
}

impl std::fmt::Display for CopyBidirectionalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CopyBidirectionalError::LeftClosed(e) => {
                write!(f, "left side closed with error: {e}")
            }
            CopyBidirectionalError::RightClosed(e) => {
                write!(f, "right side closed with error: {e}")
            }
            CopyBidirectionalError::Other(e) => {
                write!(f, "error: {e}")
            }
        }
    }
}

impl std::error::Error for CopyBidirectionalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CopyBidirectionalError::LeftClosed(e) => Some(e),
            CopyBidirectionalError::RightClosed(e) => Some(e),
            CopyBidirectionalError::Other(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for CopyBidirectionalError {
    fn from(e: std::io::Error) -> Self {
        CopyBidirectionalError::Other(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownMode {
    HalfClose,
    FlushOnly,
}

#[derive(Debug)]
pub struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    #[allow(unused)]
    pub fn new() -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; 2 * 1024].into_boxed_slice(),
        }
    }

    pub fn new_with_capacity(size: usize) -> Result<Self, std::io::Error> {
        let mut buf = Vec::new();
        buf.try_reserve(size)
            .map_err(|e| std::io::Error::other(format!("new buffer failed: {e}")))?;
        buf.resize(size, 0);
        Ok(Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: buf.into_boxed_slice(),
        })
    }

    pub fn amount_transferred(&self) -> u64 {
        self.amt
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);

                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Try flushing when the reader has no progress to avoid
                        // deadlock when the reader
                        // depends on buffered writer.
                        if self.need_flush {
                            ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }

                        return Poll::Pending;
                    }
                }

                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let me = &mut *self;
                let i =
                    ready!(writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                }
            }

            // If pos larger than cap, this loop will never stop.
            // In particular, user's wrong poll_write implementation returning
            // incorrect written length may lead to thread blocking.
            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
    a_to_b_count: u64,
    b_to_a_count: u64,
    a_to_b_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    b_to_a_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
    shutdown_mode: ShutdownMode,
}

fn reset_idle_timeout(
    delay: &mut Option<Pin<Box<tokio::time::Sleep>>>,
    duration: Duration,
) {
    if let Some(delay) = delay {
        delay.as_mut().reset(tokio::time::Instant::now() + duration);
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = Result<(u64, u64), CopyBidirectionalError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
            a_to_b_count,
            b_to_a_count,
            a_to_b_delay,
            b_to_a_delay,
            a_to_b_timeout_duration,
            b_to_a_timeout_duration,
            shutdown_mode,
        } = &mut *self;

        let mut a = Pin::new(a);
        let mut b = Pin::new(b);

        loop {
            match a_to_b {
                TransferState::Running(buf) => {
                    let transferred_before = buf.amount_transferred();
                    let res = buf.poll_copy(cx, a.as_mut(), b.as_mut());
                    if buf.amount_transferred() != transferred_before {
                        reset_idle_timeout(a_to_b_delay, *a_to_b_timeout_duration);
                    }
                    match res {
                        Poll::Ready(Ok(count)) => {
                            if *shutdown_mode == ShutdownMode::FlushOnly {
                                *a_to_b_count += count;
                                *a_to_b = TransferState::Done;
                                b_to_a_delay.replace(Box::pin(tokio::time::sleep(
                                    *b_to_a_timeout_duration,
                                )));
                            } else {
                                *a_to_b = TransferState::ShuttingDown(count);
                            }
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::LeftClosed(err),
                            ));
                        }
                        Poll::Pending => {
                            if let Some(delay) = a_to_b_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        // After the opposite direction has fully
                                        // shut down, this timeout is an
                                        // inactivity guard for the remaining
                                        // half-open stream, not an absolute
                                        // lifetime cap. Progress above refreshes
                                        // the timer.
                                        *a_to_b = TransferState::ShuttingDown(
                                            buf.amount_transferred(),
                                        );
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = b.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *a_to_b_count += *count;
                            *a_to_b = TransferState::Done;
                            b_to_a_delay.replace(Box::pin(tokio::time::sleep(
                                *b_to_a_timeout_duration,
                            )));
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::LeftClosed(err),
                            ));
                        }
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match b_to_a {
                TransferState::Running(buf) => {
                    let transferred_before = buf.amount_transferred();
                    let res = buf.poll_copy(cx, b.as_mut(), a.as_mut());
                    if buf.amount_transferred() != transferred_before {
                        reset_idle_timeout(b_to_a_delay, *b_to_a_timeout_duration);
                    }
                    match res {
                        Poll::Ready(Ok(count)) => {
                            if *shutdown_mode == ShutdownMode::FlushOnly {
                                *b_to_a_count += count;
                                *b_to_a = TransferState::Done;
                                a_to_b_delay.replace(Box::pin(tokio::time::sleep(
                                    *a_to_b_timeout_duration,
                                )));
                            } else {
                                *b_to_a = TransferState::ShuttingDown(count);
                            }
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::RightClosed(err),
                            ));
                        }
                        Poll::Pending => {
                            if let Some(delay) = b_to_a_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *b_to_a = TransferState::ShuttingDown(
                                            buf.amount_transferred(),
                                        );
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = a.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *b_to_a_count += *count;
                            *b_to_a = TransferState::Done;
                            a_to_b_delay.replace(Box::pin(tokio::time::sleep(
                                *a_to_b_timeout_duration,
                            )));
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::RightClosed(err),
                            ));
                        }
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match (&a_to_b, &b_to_a) {
                (TransferState::Done, TransferState::Done) => break,
                _ => return Poll::Pending,
            }
        }

        Poll::Ready(Ok((*a_to_b_count, *b_to_a_count)))
    }
}

pub async fn copy_bidirectional(
    mut a: Box<dyn ClientStream>,
    mut b: TrackedStream,
    size: usize,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
    shutdown_mode: ShutdownMode,
) -> Result<(u64, u64), CopyBidirectionalError> {
    // zero copy is only available on linux
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    {
        // for zero copy, we need to track the download and upload amount with the
        // assistance of the tracker it's somehow ugly, but i could not
        // figure out a better way
        let (r_tracker, w_tracker) = b.trackers();
        // for socks5 & http listener, a is a raw TcpStream
        let a_raw = a.downcast_mut::<tokio::net::TcpStream>();
        // for direct outbound handler **without further chains**, b is a chained
        // stream wrapper over tcpstream
        let b_raw = b
            .inner_mut()
            .downcast_mut::<crate::app::dispatcher::ChainedStreamWrapper<tokio::net::TcpStream>>();
        match (a_raw, b_raw) {
            // zero copy is only available when both streams are raw TcpStream
            (Some(a), Some(wrapper)) => {
                tracing::trace!("using zero copy for bidirectional copy");
                zero_copy_bidirectional(
                    a,
                    wrapper.inner_mut(),
                    r_tracker,
                    w_tracker,
                    a_to_b_timeout_duration,
                    b_to_a_timeout_duration,
                )
                .await
            }
            _ => {
                copy_buf_bidirectional_with_timeout(
                    &mut a,
                    &mut b,
                    size,
                    a_to_b_timeout_duration,
                    b_to_a_timeout_duration,
                    shutdown_mode,
                )
                .await
            }
        }
    }
    #[cfg(not(all(target_os = "linux", feature = "zero_copy")))]
    {
        copy_buf_bidirectional_with_timeout(
            &mut a,
            &mut b,
            size,
            a_to_b_timeout_duration,
            b_to_a_timeout_duration,
            shutdown_mode,
        )
        .await
    }
}

pub async fn copy_buf_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    size: usize,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
    shutdown_mode: ShutdownMode,
) -> Result<(u64, u64), CopyBidirectionalError>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running(CopyBuffer::new_with_capacity(size)?),
        b_to_a: TransferState::Running(CopyBuffer::new_with_capacity(size)?),
        a_to_b_count: 0,
        b_to_a_count: 0,
        a_to_b_delay: None,
        b_to_a_delay: None,
        a_to_b_timeout_duration,
        b_to_a_timeout_duration,
        shutdown_mode,
    }
    .await
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        time::timeout,
    };

    use super::{ShutdownMode, copy_buf_bidirectional_with_timeout};

    #[tokio::test]
    async fn half_closed_stream_keeps_running_while_peer_makes_progress() {
        let (mut proxy_local, mut local) = duplex(1024);
        let (mut proxy_remote, mut remote) = duplex(1024);

        let relay = tokio::spawn(async move {
            copy_buf_bidirectional_with_timeout(
                &mut proxy_local,
                &mut proxy_remote,
                256,
                Duration::from_millis(100),
                Duration::from_millis(100),
                ShutdownMode::HalfClose,
            )
            .await
        });

        let local_task = tokio::spawn(async move {
            local.write_all(b"req").await?;
            local.shutdown().await?;

            let mut response = Vec::new();
            local.read_to_end(&mut response).await?;

            Ok::<Vec<u8>, std::io::Error>(response)
        });

        let remote_task = tokio::spawn(async move {
            let mut req = [0u8; 3];
            remote.read_exact(&mut req).await?;
            assert_eq!(&req, b"req");

            remote.write_all(b"chunk-1").await?;
            tokio::time::sleep(Duration::from_millis(80)).await;
            remote.write_all(b"chunk-2").await?;
            tokio::time::sleep(Duration::from_millis(80)).await;
            remote.write_all(b"chunk-3").await?;
            remote.shutdown().await?;

            Ok::<(), std::io::Error>(())
        });

        remote_task
            .await
            .expect("remote task join")
            .expect("remote io");

        let response = timeout(Duration::from_secs(2), local_task)
            .await
            .expect("local task timeout")
            .expect("local task join")
            .expect("local io");
        assert_eq!(response, b"chunk-1chunk-2chunk-3");

        relay
            .await
            .expect("relay task join")
            .expect("relay should finish cleanly");
    }

    struct NoHalfClose<T> {
        inner: T,
        shutdown_called: bool,
    }

    impl<T> NoHalfClose<T> {
        fn new(inner: T) -> Self {
            Self {
                inner,
                shutdown_called: false,
            }
        }
    }

    impl<T: AsyncRead + Unpin> AsyncRead for NoHalfClose<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for NoHalfClose<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            self.shutdown_called = true;
            Poll::Ready(Err(std::io::Error::other(
                "half-close should not be propagated",
            )))
        }
    }

    #[tokio::test]
    async fn flush_only_mode_skips_half_close_propagation() {
        let (client, mut observer) = duplex(1024);
        let (mut upstream, relay_peer) = duplex(1024);

        let relay = tokio::spawn(async move {
            let mut lhs = NoHalfClose::new(client);
            copy_buf_bidirectional_with_timeout(
                &mut lhs,
                &mut upstream,
                256,
                Duration::from_millis(100),
                Duration::from_millis(100),
                ShutdownMode::FlushOnly,
            )
            .await
            .map(|result| (result, lhs.shutdown_called))
        });

        let peer = tokio::spawn(async move {
            let mut relay_peer = relay_peer;
            relay_peer.write_all(b"req").await?;
            relay_peer.shutdown().await?;
            let mut response = Vec::new();
            relay_peer.read_to_end(&mut response).await?;
            Ok::<Vec<u8>, std::io::Error>(response)
        });

        let mut req = [0u8; 3];
        observer.read_exact(&mut req).await.expect("observer read");
        assert_eq!(&req, b"req");

        observer
            .write_all(b"resp")
            .await
            .expect("observer writes after flush-only transition");
        observer.shutdown().await.expect("observer shutdown");

        let ((up, down), shutdown_called) =
            relay.await.expect("relay join").expect("relay io");
        assert_eq!((up, down), (4, 3));
        let response = peer.await.expect("peer join").expect("peer io");
        assert_eq!(response, b"resp");
        assert!(
            !shutdown_called,
            "flush-only mode should not call poll_shutdown on peer"
        );
    }
}

#[allow(dead_code)]
pub trait ReadExactBase {
    /// inner stream to be polled
    type I: AsyncRead + Unpin;
    /// prepare the inner stream, read buffer and read position
    fn decompose(&mut self) -> (&mut Self::I, &mut BytesMut, &mut usize);
}

#[allow(dead_code)]
pub trait ReadExt: ReadExactBase {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>>;
}

impl<T: ReadExactBase> ReadExt for T {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>> {
        let (raw, read_buf, read_pos) = self.decompose();
        read_buf.reserve(size);
        // # safety: read_buf has reserved `size`
        unsafe { read_buf.set_len(size) }
        loop {
            if *read_pos < size {
                // # safety: read_pos<size==read_buf.len(), and
                // read_buf[0..read_pos] is initialized
                let dst = unsafe {
                    &mut *((&mut read_buf[*read_pos..size]) as *mut _
                        as *mut [MaybeUninit<u8>])
                };
                let mut buf = ReadBuf::uninit(dst);
                let ptr = buf.filled().as_ptr();
                ready!(Pin::new(&mut *raw).poll_read(cx, &mut buf))?;
                assert_eq!(ptr, buf.filled().as_ptr());
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected eof",
                    )));
                }
                *read_pos += buf.filled().len();
            } else {
                assert!(*read_pos == size);
                *read_pos = 0;
                return Poll::Ready(Ok(()));
            }
        }
    }
}
