use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::{DateTime, Utc};
use memory_stats::memory_stats;
use serde::Serialize;
use tokio::sync::{Mutex, RwLock, oneshot::Sender};

use crate::{app::dispatcher::tracked::Tracked, session::Session};

#[derive(Serialize, Clone, Debug, Default)]
pub struct UserTraffic {
    pub upload: u64,
    pub download: u64,
}

#[derive(Default, Clone, Debug)]
pub struct ProxyChain(Arc<RwLock<Vec<String>>>);

impl ProxyChain {
    pub async fn push(&self, s: String) {
        let mut chain = self.0.write().await;
        chain.push(s);
    }

    pub async fn snapshot(&self) -> Vec<String> {
        self.0.read().await.clone()
    }
}

type ConnectionMap = HashMap<uuid::Uuid, (Tracked, Sender<()>)>;

pub struct StatisticsManager {
    connections: Arc<Mutex<ConnectionMap>>,
    closed_flows: Arc<Mutex<VecDeque<Arc<TrackerInfo>>>>,
    upload_temp: AtomicU64,
    download_temp: AtomicU64,
    upload_blip: AtomicU64,
    download_blip: AtomicU64,
    upload_total: AtomicU64,
    download_total: AtomicU64,
    user_period_stats: Arc<Mutex<HashMap<String, UserTraffic>>>,
}

impl StatisticsManager {
    pub fn new() -> Arc<Self> {
        let v = Arc::new(Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            closed_flows: Arc::new(Mutex::new(VecDeque::new())),
            upload_temp: AtomicU64::new(0),
            download_temp: AtomicU64::new(0),
            upload_blip: AtomicU64::new(0),
            download_blip: AtomicU64::new(0),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            user_period_stats: Arc::new(Mutex::new(HashMap::new())),
        });
        let c = v.clone();
        tokio::spawn(async move {
            c.kick_off().await;
        });
        v
    }

    async fn kick_off(&self) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            ticker.tick().await;
            self.upload_blip
                .store(self.upload_temp.load(Ordering::Relaxed), Ordering::Relaxed);
            self.upload_temp.store(0, Ordering::Relaxed);
            self.download_blip.store(
                self.download_temp.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            self.download_temp.store(0, Ordering::Relaxed);
        }
    }

    pub async fn track(&self, item: Tracked, close_notify: Sender<()>) {
        let mut connections = self.connections.lock().await;

        connections.insert(item.id(), (item, close_notify));
    }

    pub async fn untrack(&self, id: uuid::Uuid) {
        let Some((tracked, _)) = self.connections.lock().await.remove(&id) else {
            return;
        };

        let info = tracked.tracker_info();
        let upload = info.user_upload.swap(0, Ordering::AcqRel);
        let download = info.user_download.swap(0, Ordering::AcqRel);
        if let Some(user) = &info.session_holder.inbound_user
            && (upload > 0 || download > 0)
        {
            let mut stats = self.user_period_stats.lock().await;
            let entry = stats.entry(user.clone()).or_default();
            entry.upload += upload;
            entry.download += download;
        }

        let mut closed_flows = self.closed_flows.lock().await;
        closed_flows.push_back(info);
        if closed_flows.len() > 1000 {
            closed_flows.pop_front();
        }
    }

    pub async fn active_connections_snapshot(&self) -> Vec<Arc<TrackerInfo>> {
        let connections = self.connections.lock().await;
        connections
            .values()
            .map(|(tracked, _)| tracked.tracker_info())
            .collect()
    }

    pub async fn closed_flows_snapshot(&self) -> Vec<Arc<TrackerInfo>> {
        let closed_flows = self.closed_flows.lock().await;
        closed_flows.iter().cloned().collect()
    }

    pub async fn drain_user_stats(&self) -> HashMap<String, UserTraffic> {
        let mut result = {
            let mut stats = self.user_period_stats.lock().await;
            std::mem::take(&mut *stats)
        };

        let connections = self.connections.lock().await;
        for (tracked, _) in connections.values() {
            let info = tracked.tracker_info();
            if let Some(user) = &info.session_holder.inbound_user {
                let upload = info.user_upload.swap(0, Ordering::AcqRel);
                let download = info.user_download.swap(0, Ordering::AcqRel);
                if upload > 0 || download > 0 {
                    let entry = result.entry(user.clone()).or_default();
                    entry.upload += upload;
                    entry.download += download;
                }
            }
        }

        result
    }

    pub async fn snapshot(&self) -> Snapshot {
        let tracked = {
            let connections = self.connections.lock().await;
            connections
                .values()
                .map(|(tracked, _)| tracked.tracker_info())
                .collect::<Vec<_>>()
        };

        let mut connections = Vec::with_capacity(tracked.len());
        for tracker in tracked {
            let chain = tracker.proxy_chain_holder.snapshot().await;
            connections.push(TrackerInfo {
                uuid: tracker.uuid,
                session: tracker.session_holder.as_map(),
                upload_total: AtomicU64::new(
                    tracker.upload_total.load(Ordering::Acquire),
                ),
                download_total: AtomicU64::new(
                    tracker.download_total.load(Ordering::Acquire),
                ),
                start_time: tracker.start_time,
                proxy_chain: chain,
                rule: tracker.rule.clone(),
                rule_payload: tracker.rule_payload.clone(),
                ..Default::default()
            });
        }

        Snapshot {
            download_total: self.download_total.load(Ordering::Relaxed),
            upload_total: self.upload_total.load(Ordering::Relaxed),
            memory: self.memory_usage(),
            connections,
        }
    }

    pub async fn close(&self, id: uuid::Uuid) -> bool {
        let close_notify =
            self.connections.lock().await.remove(&id).map(|(_, tx)| tx);

        match close_notify {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    pub async fn close_all(&self) -> usize {
        let close_notifiers = {
            let mut connections = self.connections.lock().await;
            connections
                .drain()
                .map(|(_, (_, tx))| tx)
                .collect::<Vec<_>>()
        };

        let count = close_notifiers.len();
        for tx in close_notifiers {
            let _ = tx.send(());
        }
        count
    }

    pub fn push_downloaded(&self, n: usize) {
        self.download_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.download_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn push_uploaded(&self, n: usize) {
        self.upload_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.upload_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn now(&self) -> (u64, u64) {
        (
            self.upload_blip.load(Ordering::Relaxed),
            self.download_blip.load(Ordering::Relaxed),
        )
    }

    #[allow(dead_code)]
    pub fn reset_statistic(&self) {
        self.upload_temp.store(0, Ordering::Relaxed);
        self.upload_blip.store(0, Ordering::Relaxed);
        self.upload_total.store(0, Ordering::Relaxed);
        self.download_temp.store(0, Ordering::Relaxed);
        self.download_blip.store(0, Ordering::Relaxed);
        self.download_total.store(0, Ordering::Relaxed);
    }

    pub fn memory_usage(&self) -> usize {
        memory_stats().map(|x| x.physical_mem).unwrap_or(0)
    }
}

#[derive(Serialize, Default)]
pub struct TrackerInfo {
    #[serde(rename = "id")]
    pub uuid: uuid::Uuid,
    #[serde(rename = "metadata")]
    pub session: HashMap<String, Box<dyn erased_serde::Serialize + Send + Sync>>,

    #[serde(rename = "upload")]
    pub upload_total: AtomicU64,
    #[serde(rename = "download")]
    pub download_total: AtomicU64,
    #[serde(rename = "start")]
    pub start_time: DateTime<Utc>,
    #[serde(rename = "chains")]
    pub proxy_chain: Vec<String>,
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,

    #[serde(skip)]
    pub proxy_chain_holder: ProxyChain,
    #[serde(skip)]
    pub session_holder: Session,

    /// Per-user byte counters, separate from `upload_total`/`download_total`.
    /// Only incremented when `session_holder.inbound_user` is set.
    /// Swapped to 0 on drain — never touched by `snapshot()`.
    #[serde(skip)]
    pub user_upload: AtomicU64,
    #[serde(skip)]
    pub user_download: AtomicU64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub download_total: u64,
    pub upload_total: u64,
    pub memory: usize,
    pub connections: Vec<TrackerInfo>,
}
