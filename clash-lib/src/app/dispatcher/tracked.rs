use std::{pin::Pin, sync::Arc};

use async_trait::async_trait;
use downcast_rs::{Downcast, impl_downcast};
use std::task::Poll;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot::{Receiver, error::TryRecvError},
};
use tracing::debug;

use crate::{
    app::{
        dispatcher::{
            StatisticsManager,
            statistics_manager::{ProxyChain, TrackerInfo},
        },
        router::RuleMatcher,
    },
    proxy::ProxyStream,
    session::Session,
};

pub struct Tracked(uuid::Uuid, Arc<TrackerInfo>);

impl Tracked {
    pub fn id(&self) -> uuid::Uuid {
        self.0
    }

    pub fn tracker_info(&self) -> Arc<TrackerInfo> {
        self.1.clone()
    }
}

#[async_trait]
pub trait ChainedStream: ProxyStream + Downcast {
    fn chain(&self) -> &ProxyChain;
    async fn append_to_chain(&self, name: &str);
}
impl_downcast!(ChainedStream);

pub type BoxedChainedStream = Box<dyn ChainedStream>;

pub struct ChainedStreamWrapper<T> {
    inner: T,
    chain: ProxyChain,
}

impl<T> ChainedStreamWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chain: ProxyChain::default(),
        }
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[async_trait]
impl<T> ChainedStream for ChainedStreamWrapper<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    fn chain(&self) -> &ProxyChain {
        &self.chain
    }

    async fn append_to_chain(&self, name: &str) {
        self.chain.push(name.to_owned()).await;
    }
}

impl<T> AsyncRead for ChainedStreamWrapper<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for ChainedStreamWrapper<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct TrackedStream {
    inner: BoxedChainedStream,
    manager: Arc<StatisticsManager>,
    tracker: Arc<TrackerInfo>,
    /// 4
    close_notify: Receiver<()>,
}

#[allow(unused)]
impl TrackedStream {
    #[allow(clippy::borrowed_box)]
    pub async fn new(
        inner: BoxedChainedStream,
        manager: Arc<StatisticsManager>,
        sess: Session,
        rule: Option<&Box<dyn RuleMatcher>>,
    ) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let chain = inner.chain().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let s = Self {
            inner,
            manager: manager.clone(),
            tracker: Arc::new(TrackerInfo {
                uuid,
                ..Default::default()
            }),
            close_notify: rx,
        };

        manager.track(Tracked(uuid, s.tracker_info()), tx).await;

        s
    }

    pub fn tracker_info(&self) -> Arc<TrackerInfo> {
        self.tracker.clone()
    }

    pub fn inner_mut(&mut self) -> &mut BoxedChainedStream {
        &mut self.inner
    }

    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    pub fn trackers(
        &self,
    ) -> (
        Arc<dyn TrackCopy + Send + Sync>,
        Arc<dyn TrackCopy + Send + Sync>,
    ) {
        let r = Arc::new(ReadTracker::new(self.tracker.clone(), self.manager.clone()));
        let w = Arc::new(WriteTracker::new(
            self.tracker.clone(),
            self.manager.clone(),
        ));
        (r, w)
    }

    fn id(&self) -> uuid::Uuid {
        self.tracker.uuid
    }
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
pub trait TrackCopy {
    fn track(&self, total: usize);
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
impl TrackCopy for ReadTracker {
    fn track(&self, total: usize) {
        self.push_downloaded(total);
    }
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
impl TrackCopy for WriteTracker {
    fn track(&self, total: usize) {
        self.push_uploaded(total);
    }
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
pub struct ReadTracker {
    tracker: Arc<TrackerInfo>,
    manager: Arc<StatisticsManager>,
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
impl ReadTracker {
    fn new(tracker: Arc<TrackerInfo>, manager: Arc<StatisticsManager>) -> Self {
        Self { tracker, manager }
    }

    fn push_downloaded(&self, download: usize) {
        self.manager.push_downloaded(download);
        self.tracker
            .download_total
            .fetch_add(download as u64, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
pub struct WriteTracker {
    tracker: Arc<TrackerInfo>,
    manager: Arc<StatisticsManager>,
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
impl WriteTracker {
    fn new(tracker: Arc<TrackerInfo>, manager: Arc<StatisticsManager>) -> Self {
        Self { tracker, manager }
    }

    fn push_uploaded(&self, upload: usize) {
        self.manager.push_uploaded(upload);
        self.tracker
            .upload_total
            .fetch_add(upload as u64, std::sync::atomic::Ordering::Release);
    }
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.close_notify.try_recv() {
            Ok(_) => {
                debug!("connection closed by sig: {}", self.id());
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    debug!("connection closed drop: {}", self.id());
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        let v = Pin::new(self.inner.as_mut()).poll_read(cx, buf);
        let download = buf.filled().len();
        self.manager.push_downloaded(download);
        self.tracker
            .download_total
            .fetch_add(download as u64, std::sync::atomic::Ordering::Release);

        v
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        let v = Pin::new(self.inner.as_mut()).poll_write(cx, buf);
        let upload = match v {
            Poll::Ready(Ok(n)) => n,
            _ => return v,
        };
        self.manager.push_uploaded(upload);
        self.tracker
            .upload_total
            .fetch_add(upload as u64, std::sync::atomic::Ordering::Release);

        v
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        Pin::new(&mut self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}
