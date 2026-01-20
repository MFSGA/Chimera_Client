use std::sync::Arc;

use async_trait::async_trait;
use downcast_rs::{Downcast, impl_downcast};

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

pub struct TrackedStream {
    inner: BoxedChainedStream,
    manager: Arc<StatisticsManager>,
    tracker: Arc<TrackerInfo>,
    // close_notify: Receiver<()>,
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
            tracker: Arc::new(TrackerInfo { uuid }),
            // close_notify: rx,
        };

        manager.track(Tracked(uuid, s.tracker_info()), tx).await;

        s
    }

    pub fn tracker_info(&self) -> Arc<TrackerInfo> {
        self.tracker.clone()
    }
}
