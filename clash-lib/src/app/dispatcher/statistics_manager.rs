use std::{
    collections::HashMap,
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
    upload_temp: AtomicU64,
    download_temp: AtomicU64,
    upload_blip: AtomicU64,
    download_blip: AtomicU64,
    upload_total: AtomicU64,
    download_total: AtomicU64,
}

impl StatisticsManager {
    pub fn new() -> Arc<Self> {
        let v = Arc::new(Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            upload_temp: AtomicU64::new(0),
            download_temp: AtomicU64::new(0),
            upload_blip: AtomicU64::new(0),
            download_blip: AtomicU64::new(0),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
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
        self.connections.lock().await.remove(&id);
    }

    pub async fn snapshot(&self) -> ConnectionsResponse {
        let tracked = {
            let connections = self.connections.lock().await;
            connections
                .values()
                .map(|(tracked, _)| tracked.tracker_info())
                .collect::<Vec<_>>()
        };

        let mut connections = Vec::with_capacity(tracked.len());
        for tracker in tracked {
            connections.push(Connection::from_tracker(tracker).await);
        }

        ConnectionsResponse {
            download_total: self.download_total.load(Ordering::Relaxed),
            upload_total: self.upload_total.load(Ordering::Relaxed),
            memory: self.memory_usage() as u64,
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

    pub fn memory_usage(&self) -> usize {
        memory_stats().map(|x| x.physical_mem).unwrap_or(0)
    }
}

#[derive(Clone)]
pub struct TrackerMetadata {
    pub start: DateTime<Utc>,
    pub chains: ProxyChain,
    pub session: Session,
}

impl Default for TrackerMetadata {
    fn default() -> Self {
        Self {
            start: Utc::now(),
            chains: ProxyChain::default(),
            session: Session::default(),
        }
    }
}

#[derive(Serialize, Default)]
pub struct TrackerInfo {
    #[serde(rename = "id")]
    pub uuid: uuid::Uuid,
    #[serde(skip)]
    pub metadata: TrackerMetadata,

    #[serde(rename = "upload")]
    pub upload_total: AtomicU64,
    #[serde(rename = "download")]
    pub download_total: AtomicU64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionsResponse {
    pub download_total: u64,
    pub upload_total: u64,
    pub memory: u64,
    pub connections: Vec<Connection>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub id: uuid::Uuid,
    pub upload: u64,
    pub download: u64,
    pub start: DateTime<Utc>,
    pub chains: Vec<String>,
    pub metadata: ConnectionMetadata,
}

impl Connection {
    async fn from_tracker(tracker: Arc<TrackerInfo>) -> Self {
        let session = tracker.metadata.session.clone();
        let destination_ip = match &session.destination {
            crate::session::SocksAddr::Ip(addr) => Some(addr.ip().to_string()),
            crate::session::SocksAddr::Domain(_, _) => None,
        };

        Self {
            id: tracker.uuid,
            upload: tracker.upload_total.load(Ordering::Relaxed),
            download: tracker.download_total.load(Ordering::Relaxed),
            start: tracker.metadata.start,
            chains: tracker.metadata.chains.snapshot().await,
            metadata: ConnectionMetadata {
                network: format!("{:?}", session.network).to_lowercase(),
                typ: format!("{:?}", session.typ).to_lowercase(),
                source_ip: session.source.ip().to_string(),
                destination_ip,
                source_port: session.source.port(),
                destination_port: session.destination.port(),
                host: session.destination.host(),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMetadata {
    pub network: String,
    #[serde(rename = "type")]
    pub typ: String,
    pub source_ip: String,
    pub destination_ip: Option<String>,
    pub source_port: u16,
    pub destination_port: u16,
    pub host: String,
}
