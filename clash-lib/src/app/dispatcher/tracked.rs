use std::{io, pin::Pin, sync::Arc, task::Poll};

use async_trait::async_trait;
use downcast_rs::{Downcast, impl_downcast};
use futures::{Sink, Stream};
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
        flow::{FlowContext, FlowId},
        router::RuleMatcher,
    },
    proxy::{ProxyStream, datagram::UdpPacket},
    session::{Session, SocksAddr},
};

pub struct Tracked(uuid::Uuid, Arc<TrackerInfo>);

impl Tracked {
    pub fn id(&self) -> uuid::Uuid {
        self.0
    }

    #[allow(dead_code)]
    #[allow(dead_code)]
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
    close_notify: Receiver<()>,
    traffic_proof: Option<crate::app::runtime_state::TrafficProof>,
}

#[allow(unused)]
impl TrackedStream {
    pub async fn new(
        inner: BoxedChainedStream,
        manager: Arc<StatisticsManager>,
        sess: Session,
        rule: Option<&dyn RuleMatcher>,
    ) -> Self {
        let inbound_destination = sess.destination.clone();
        Self::new_with_inbound_destination(
            inner,
            manager,
            sess,
            inbound_destination,
            rule,
        )
        .await
    }

    pub(crate) async fn new_with_inbound_destination(
        inner: BoxedChainedStream,
        manager: Arc<StatisticsManager>,
        sess: Session,
        inbound_destination: SocksAddr,
        rule: Option<&dyn RuleMatcher>,
    ) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let flow_context =
            FlowContext::from_session(FlowId::new(uuid), &sess, inbound_destination);
        let chain = inner.chain().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let s = Self {
            inner,
            manager: manager.clone(),
            tracker: Arc::new(TrackerInfo {
                uuid,
                session_holder: sess,
                flow_context: Some(flow_context),
                start_time: chrono::Utc::now(),
                rule: rule
                    .map(|matcher| matcher.type_name().to_owned())
                    .unwrap_or_default(),
                rule_payload: rule
                    .map(|matcher| matcher.payload())
                    .unwrap_or_default(),
                proxy_chain_holder: chain.clone(),
                ..Default::default()
            }),
            close_notify: rx,
            traffic_proof: None,
        };

        manager.track(Tracked(uuid, s.tracker_info()), tx).await;

        s
    }

    pub(crate) fn with_traffic_proof(
        mut self,
        proof: Option<crate::app::runtime_state::TrafficProof>,
    ) -> Self {
        self.traffic_proof = proof;
        self
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
        let r = Arc::new(ReadTracker::new(
            self.tracker.clone(),
            self.manager.clone(),
            self.traffic_proof.clone(),
        ));
        let w = Arc::new(WriteTracker::new(
            self.tracker.clone(),
            self.manager.clone(),
        ));
        (r, w)
    }

    pub(crate) fn id(&self) -> uuid::Uuid {
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
    traffic_proof: Option<crate::app::runtime_state::TrafficProof>,
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
impl ReadTracker {
    fn new(
        tracker: Arc<TrackerInfo>,
        manager: Arc<StatisticsManager>,
        traffic_proof: Option<crate::app::runtime_state::TrafficProof>,
    ) -> Self {
        Self {
            tracker,
            manager,
            traffic_proof,
        }
    }

    fn push_downloaded(&self, download: usize) {
        if let Some(proof) = &self.traffic_proof {
            proof.received(download);
        }
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

        let before = buf.filled().len();
        let v = Pin::new(self.inner.as_mut()).poll_read(cx, buf);
        let download = buf.filled().len().saturating_sub(before);
        if let Some(proof) = &self.traffic_proof {
            proof.received(download);
        }
        self.manager.push_downloaded(download);
        self.tracker
            .download_total
            .fetch_add(download as u64, std::sync::atomic::Ordering::Release);
        if self.tracker.session_holder.inbound_user.is_some() {
            self.tracker
                .user_download
                .fetch_add(download as u64, std::sync::atomic::Ordering::Relaxed);
        }

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
        if self.tracker.session_holder.inbound_user.is_some() {
            self.tracker
                .user_upload
                .fetch_add(upload as u64, std::sync::atomic::Ordering::Relaxed);
        }

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

#[async_trait]
pub trait ChainedDatagram:
    Stream<Item = UdpPacket> + Sink<UdpPacket, Error = io::Error> + Send + Sync + Unpin
{
    fn chain(&self) -> &ProxyChain;
    async fn append_to_chain(&self, name: &str);
}

pub type BoxedChainedDatagram = Box<dyn ChainedDatagram + Send + Sync>;

#[async_trait]
impl<T> ChainedDatagram for ChainedDatagramWrapper<T>
where
    T: Sink<UdpPacket, Error = std::io::Error> + Unpin + Send + Sync + 'static,
    T: Stream<Item = UdpPacket>,
{
    fn chain(&self) -> &ProxyChain {
        &self.chain
    }

    async fn append_to_chain(&self, name: &str) {
        self.chain.push(name.to_owned()).await;
    }
}

pub struct ChainedDatagramWrapper<T> {
    inner: T,
    chain: ProxyChain,
}

impl<T> ChainedDatagramWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chain: ProxyChain::default(),
        }
    }
}

impl<T> Stream for ChainedDatagramWrapper<T>
where
    T: Stream<Item = UdpPacket> + Unpin,
{
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl<T> Sink<UdpPacket> for ChainedDatagramWrapper<T>
where
    T: Sink<UdpPacket, Error = io::Error> + Unpin,
{
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        Pin::new(&mut self.get_mut().inner).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

pub struct TrackedDatagram {
    inner: BoxedChainedDatagram,
    manager: Arc<StatisticsManager>,
    tracker: Arc<TrackerInfo>,
    close_notify: Receiver<()>,
}

impl TrackedDatagram {
    pub async fn new(
        inner: BoxedChainedDatagram,
        manager: Arc<StatisticsManager>,
        sess: Session,
        rule: Option<&dyn RuleMatcher>,
    ) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let chain = inner.chain().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tracker = Arc::new(TrackerInfo {
            uuid,
            session_holder: sess,
            start_time: chrono::Utc::now(),
            rule: rule
                .map(|matcher| matcher.type_name().to_owned())
                .unwrap_or_default(),
            rule_payload: rule.map(|matcher| matcher.payload()).unwrap_or_default(),
            proxy_chain_holder: chain.clone(),
            ..Default::default()
        });
        let s = Self {
            inner,
            manager: manager.clone(),
            tracker: tracker.clone(),
            close_notify: rx,
        };

        manager.track(Tracked(uuid, tracker), tx).await;

        s
    }

    pub fn id(&self) -> uuid::Uuid {
        self.tracker.uuid
    }

    #[allow(dead_code)]
    pub fn tracker_info(&self) -> Arc<TrackerInfo> {
        self.tracker.clone()
    }
}

impl Stream for TrackedDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(None),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => return Poll::Ready(None),
            },
        }

        let r = Pin::new(self.inner.as_mut()).poll_next(cx);
        if let Poll::Ready(Some(ref pkt)) = r {
            let n = pkt.data.len();
            self.manager.push_downloaded(n);
            self.tracker
                .download_total
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            if self.tracker.session_holder.inbound_user.is_some() {
                self.tracker
                    .user_download
                    .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        r
    }
}

impl Sink<UdpPacket> for TrackedDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }
        Pin::new(self.inner.as_mut()).poll_ready(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        match self.close_notify.try_recv() {
            Ok(_) => return Err(std::io::ErrorKind::BrokenPipe.into()),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
            },
        }

        let upload = item.data.len();
        self.manager.push_uploaded(upload);
        self.tracker
            .upload_total
            .fetch_add(upload as u64, std::sync::atomic::Ordering::Relaxed);
        if self.tracker.session_holder.inbound_user.is_some() {
            self.tracker
                .user_upload
                .fetch_add(upload as u64, std::sync::atomic::Ordering::Relaxed);
        }
        Pin::new(self.inner.as_mut()).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        Pin::new(self.inner.as_mut()).poll_close(cx)
    }
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        let manager = self.manager.clone();
        let id = self.id();
        debug!("untrack connection: {}", id);
        tokio::spawn(async move {
            manager.untrack(id).await;
        });
    }
}

impl Drop for TrackedDatagram {
    fn drop(&mut self) {
        let manager = self.manager.clone();
        let id = self.id();
        debug!("untrack connection: {}", id);
        tokio::spawn(async move {
            manager.untrack(id).await;
        });
    }
}

#[cfg(test)]
mod flow_context_tests {
    use std::net::SocketAddr;

    use crate::{
        app::dispatcher::{StatisticsManager, tracked::ChainedStreamWrapper},
        session::{Network, Session, SocksAddr, Type},
    };

    use super::{BoxedChainedStream, TrackedStream};

    #[tokio::test]
    async fn tracked_tcp_flow_keeps_ingress_destination_without_changing_api_json() {
        let (io, _peer) = tokio::io::duplex(64);
        let inner: BoxedChainedStream = Box::new(ChainedStreamWrapper::new(io));
        let inbound_destination =
            SocksAddr::Ip("198.19.0.10:443".parse::<SocketAddr>().unwrap());
        let session = Session {
            network: Network::Tcp,
            typ: Type::Socks5,
            source: "192.0.2.10:51000".parse().unwrap(),
            destination: SocksAddr::Domain("example.com".to_string(), 443),
            ..Default::default()
        };
        let tracked = TrackedStream::new_with_inbound_destination(
            inner,
            StatisticsManager::new(),
            session,
            inbound_destination.clone(),
            None,
        )
        .await;

        let tracker = tracked.tracker_info();
        let flow = tracker.flow_context.as_ref().unwrap();
        assert_eq!(flow.id.as_uuid(), tracker.uuid);
        assert_eq!(flow.inbound_destination, inbound_destination);
        assert_eq!(
            flow.destination,
            SocksAddr::Domain("example.com".to_string(), 443)
        );

        let api_value = serde_json::to_value(tracker.as_ref()).unwrap();
        assert!(api_value.get("flowContext").is_none());
        assert!(api_value.get("flow_context").is_none());
    }
}
