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

/// Lightweight snapshot kept after a connection closes.
///
/// Unlike `TrackerInfo`, this does not retain the full `Session` or
/// `ProxyChain`, so the closed-flow history cannot keep those heavier runtime
/// objects alive after the connection is gone.
#[derive(Serialize, Clone, Debug)]
pub struct ClosedFlowInfo {
    #[serde(rename = "id")]
    pub uuid: uuid::Uuid,
    #[serde(rename = "upload")]
    pub upload_total: u64,
    #[serde(rename = "download")]
    pub download_total: u64,
    #[serde(rename = "start")]
    pub start_time: DateTime<Utc>,
    #[serde(rename = "chains")]
    pub proxy_chain: Vec<String>,
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
    pub host: String,
    pub destination_port: u16,
    pub network: String,
    pub source_ip: String,
    pub country: Option<String>,
    pub asn: Option<String>,
}

impl ClosedFlowInfo {
    pub async fn from_tracker_info(info: &TrackerInfo) -> Self {
        Self {
            uuid: info.uuid,
            upload_total: info.upload_total.load(Ordering::Acquire),
            download_total: info.download_total.load(Ordering::Acquire),
            start_time: info.start_time,
            proxy_chain: info.proxy_chain_holder.snapshot().await,
            rule: info.rule.clone(),
            rule_payload: info.rule_payload.clone(),
            host: info.session_holder.destination.host(),
            destination_port: info.session_holder.destination.port(),
            network: match info.session_holder.network {
                crate::session::Network::Tcp => "tcp".to_string(),
                crate::session::Network::Udp => "udp".to_string(),
            },
            source_ip: info.session_holder.source.ip().to_string(),
            country: info.session_holder.country.clone(),
            asn: info.session_holder.asn.clone(),
        }
    }
}

pub struct StatisticsManager {
    connections: Arc<Mutex<ConnectionMap>>,
    closed_flows: Arc<Mutex<VecDeque<ClosedFlowInfo>>>,
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

        let flow = ClosedFlowInfo::from_tracker_info(&info).await;
        drop(info);

        let mut closed_flows = self.closed_flows.lock().await;
        closed_flows.push_back(flow);
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

    pub async fn closed_flows_snapshot(&self) -> Vec<ClosedFlowInfo> {
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

    pub async fn summary(&self) -> ConnectionSummary {
        let connection_count = self.connections.lock().await.len();
        ConnectionSummary {
            download_total: self.download_total.load(Ordering::Relaxed),
            upload_total: self.upload_total.load(Ordering::Relaxed),
            connection_count,
        }
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

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSummary {
    pub download_total: u64,
    pub upload_total: u64,
    pub connection_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub download_total: u64,
    pub upload_total: u64,
    pub memory: usize,
    pub connections: Vec<TrackerInfo>,
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::atomic::AtomicU64};

    use chrono::Utc;

    use crate::session::{Network, Session, SocksAddr};

    use super::{ClosedFlowInfo, StatisticsManager, TrackerInfo};

    #[tokio::test]
    async fn closed_flow_info_extracts_only_flow_fields() {
        let chain = super::ProxyChain::default();
        chain.push("proxy-a".to_string()).await;
        let info = TrackerInfo {
            uuid: uuid::Uuid::new_v4(),
            upload_total: AtomicU64::new(12),
            download_total: AtomicU64::new(34),
            start_time: Utc::now(),
            proxy_chain_holder: chain,
            rule: "MATCH".to_string(),
            rule_payload: "payload".to_string(),
            session_holder: Session {
                network: Network::Udp,
                source: "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                destination: SocksAddr::Domain("example.com".to_string(), 443),
                country: Some("US".to_string()),
                asn: Some("AS-example".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let flow = ClosedFlowInfo::from_tracker_info(&info).await;

        assert_eq!(flow.uuid, info.uuid);
        assert_eq!(flow.upload_total, 12);
        assert_eq!(flow.download_total, 34);
        assert_eq!(flow.host, "example.com");
        assert_eq!(flow.destination_port, 443);
        assert_eq!(flow.network, "udp");
        assert_eq!(flow.source_ip, "127.0.0.1");
        assert_eq!(flow.proxy_chain, vec!["proxy-a"]);
        assert_eq!(flow.country.as_deref(), Some("US"));
        assert_eq!(flow.asn.as_deref(), Some("AS-example"));
    }

    #[tokio::test]
    async fn summary_reports_accumulated_totals() {
        let manager = StatisticsManager::new();
        manager.push_uploaded(7);
        manager.push_downloaded(11);

        let summary = manager.summary().await;

        assert_eq!(summary.upload_total, 7);
        assert_eq!(summary.download_total, 11);
        assert_eq!(summary.connection_count, 0);
    }
}
