//! Passive per-upstream DNS health observations. Only actual upstream network
//! exchanges update this registry. Cache, hosts and synthetic Fake-IP answers
//! cannot affect these counters; no active probes are performed.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use serde::Serialize;

use super::{Client, ThreadSafeDNSClient};

/// Passive observations expire without new queries; silence is not health.
const OBSERVATION_MAX_AGE_SECS: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsHealthStatus {
    Disabled,
    Unknown,
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsUpstreamHealth {
    pub server: String,
    pub status: DnsHealthStatus,
    pub successes: u64,
    pub failures: u64,
    pub consecutive_failures: u64,
    pub last_success_at: Option<u64>,
    pub last_failure_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsGroupHealth {
    pub name: String,
    pub status: DnsHealthStatus,
    pub upstreams: Vec<DnsUpstreamHealth>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsHealthSnapshot {
    pub enabled: bool,
    /// State of the main+fallback path, based on each upstream's last result.
    /// Auxiliary groups (bootstrap/policy/direct) are reported independently.
    pub status: DnsHealthStatus,
    pub passive: bool,
    pub groups: Vec<DnsGroupHealth>,
}

impl DnsHealthSnapshot {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            status: DnsHealthStatus::Disabled,
            passive: true,
            groups: Vec::new(),
        }
    }
}

#[derive(Default, Debug)]
struct TrackerState {
    clients: Vec<(String, DnsUpstreamHealth)>,
}

#[derive(Default, Debug)]
pub(crate) struct DnsHealthTracker {
    inner: Mutex<TrackerState>,
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl DnsHealthTracker {
    fn lock(&self) -> std::sync::MutexGuard<'_, TrackerState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn register(&self, group: &str, server: String) -> usize {
        let mut state = self.lock();
        let index = state.clients.len();
        state.clients.push((
            group.to_owned(),
            DnsUpstreamHealth {
                server,
                status: DnsHealthStatus::Unknown,
                successes: 0,
                failures: 0,
                consecutive_failures: 0,
                last_success_at: None,
                last_failure_at: None,
                last_error: None,
            },
        ));
        index
    }

    fn record(&self, index: usize, result: &Result<Message>) {
        let mut state = self.lock();
        let Some((_, entry)) = state.clients.get_mut(index) else {
            return;
        };
        let timestamp = unix_timestamp();
        let failure = match result {
            Ok(message) => match message.metadata.response_code {
                ResponseCode::NoError | ResponseCode::NXDomain => None,
                code => Some(format!("DNS response code {code}")),
            },
            Err(error) => Some(error.to_string()),
        };
        if let Some(message) = failure {
            entry.status = DnsHealthStatus::Unavailable;
            entry.failures = entry.failures.saturating_add(1);
            entry.consecutive_failures =
                entry.consecutive_failures.saturating_add(1);
            entry.last_failure_at = Some(timestamp);
            // Bound the returned diagnostic payload. It can contain error
            // contexts supplied by transports, never DNS request payloads.
            entry.last_error = Some(message.chars().take(512).collect());
        } else {
            entry.status = DnsHealthStatus::Healthy;
            entry.successes = entry.successes.saturating_add(1);
            entry.consecutive_failures = 0;
            entry.last_success_at = Some(timestamp);
            entry.last_error = None;
        }
    }

    pub(crate) fn record_initialization_failure(
        &self,
        group: &str,
        server: String,
        error: &str,
    ) {
        let index = self.register(group, server);
        self.record(
            index,
            &Err(anyhow::anyhow!("initialization failed: {error}")),
        );
    }

    pub(crate) fn invalidate(&self) {
        // Network-path changes make previous observations stale. Keep the
        // history, but require a fresh real upstream exchange before claiming
        // the new path is healthy or unavailable.
        for (_, entry) in &mut self.lock().clients {
            entry.status = DnsHealthStatus::Unknown;
        }
    }

    pub(crate) fn snapshot(&self) -> DnsHealthSnapshot {
        let state = self.lock();
        let mut groups: BTreeMap<String, Vec<DnsUpstreamHealth>> = BTreeMap::new();
        let now = unix_timestamp();
        for (group, client) in &state.clients {
            let mut current = client.clone();
            let last_observed = current.last_success_at.max(current.last_failure_at);
            if last_observed.is_none_or(|timestamp| {
                now.saturating_sub(timestamp) > OBSERVATION_MAX_AGE_SECS
            }) {
                current.status = DnsHealthStatus::Unknown;
            }
            groups.entry(group.clone()).or_default().push(current);
        }
        let groups: Vec<_> = groups
            .into_iter()
            .map(|(name, upstreams)| {
                let status =
                    status_of(upstreams.iter().map(|client| &client.status));
                DnsGroupHealth {
                    name,
                    status,
                    upstreams,
                }
            })
            .collect();

        let main = groups.iter().find(|g| g.name == "main");
        let fallback = groups.iter().find(|g| g.name == "fallback");
        let status = match (main, fallback) {
            (None, _) => DnsHealthStatus::Unknown,
            (Some(main), None) => main.status.clone(),
            (Some(main), Some(fallback)) => match (&main.status, &fallback.status) {
                (
                    DnsHealthStatus::Healthy,
                    DnsHealthStatus::Unavailable | DnsHealthStatus::Degraded,
                ) => DnsHealthStatus::Degraded,
                (DnsHealthStatus::Healthy, _) => DnsHealthStatus::Healthy,
                (DnsHealthStatus::Unavailable, DnsHealthStatus::Unavailable) => {
                    DnsHealthStatus::Unavailable
                }
                (DnsHealthStatus::Unknown, _) | (_, DnsHealthStatus::Unknown) => {
                    DnsHealthStatus::Unknown
                }
                _ => DnsHealthStatus::Degraded,
            },
        };
        DnsHealthSnapshot {
            enabled: true,
            status,
            passive: true,
            groups,
        }
    }
}

fn status_of<'a>(
    states: impl IntoIterator<Item = &'a DnsHealthStatus>,
) -> DnsHealthStatus {
    let states: Vec<_> = states.into_iter().collect();
    if states.is_empty() || states.iter().any(|s| **s == DnsHealthStatus::Unknown) {
        return DnsHealthStatus::Unknown;
    }
    let healthy = states
        .iter()
        .filter(|s| ***s == DnsHealthStatus::Healthy)
        .count();
    if healthy == states.len() {
        DnsHealthStatus::Healthy
    } else if healthy == 0 {
        DnsHealthStatus::Unavailable
    } else {
        DnsHealthStatus::Degraded
    }
}

#[derive(Debug)]
struct ObservedClient {
    inner: ThreadSafeDNSClient,
    tracker: Arc<DnsHealthTracker>,
    index: usize,
}

#[async_trait]
impl Client for ObservedClient {
    fn id(&self) -> String {
        self.inner.id()
    }

    async fn exchange(&self, request: &Message) -> Result<Message> {
        let result = self.inner.exchange(request).await;
        self.tracker.record(self.index, &result);
        result
    }

    async fn reset_transport(&self) -> Result<u32> {
        self.inner.reset_transport().await
    }

    fn mark_query_timeout(&self) {
        self.tracker.record(
            self.index,
            &Err(anyhow::anyhow!(
                "upstream did not respond before DNS batch timeout"
            )),
        );
    }
}

pub(crate) fn observe_clients(
    clients: Vec<ThreadSafeDNSClient>,
    group: &str,
    tracker: &Arc<DnsHealthTracker>,
) -> Vec<ThreadSafeDNSClient> {
    clients
        .into_iter()
        .map(|client| {
            let index = tracker.register(group, client.id());
            Arc::new(ObservedClient {
                inner: client,
                tracker: tracker.clone(),
                index,
            }) as ThreadSafeDNSClient
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode};

    #[test]
    fn new_health_is_unknown_and_not_assumed_healthy() {
        let tracker = DnsHealthTracker::default();
        tracker.register("main", "dns-1".into());
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.status, DnsHealthStatus::Unknown);
        assert_eq!(snapshot.groups[0].upstreams[0].successes, 0);
        assert!(snapshot.passive);
    }

    #[test]
    fn records_failures_and_recovery_separately_from_dns_negative_answers() {
        let tracker = DnsHealthTracker::default();
        let a = tracker.register("main", "a".into());
        let b = tracker.register("main", "b".into());
        tracker.record(a, &Err(anyhow::anyhow!("timeout")));
        tracker.record(b, &Err(anyhow::anyhow!("refused")));
        assert_eq!(tracker.snapshot().status, DnsHealthStatus::Unavailable);
        tracker.record(
            b,
            &Ok({
                let mut m = Message::response(0, OpCode::Query);
                m.metadata.response_code = ResponseCode::NXDomain;
                m
            }),
        );
        let status = tracker.snapshot();
        assert_eq!(status.status, DnsHealthStatus::Degraded);
        assert_eq!(status.groups[0].upstreams[1].successes, 1);
        assert_eq!(status.groups[0].upstreams[1].consecutive_failures, 0);
        tracker.record(a, &Ok(Message::response(0, OpCode::Query)));
        assert_eq!(tracker.snapshot().status, DnsHealthStatus::Healthy);
    }

    #[test]
    fn batch_timeout_marks_inflight_upstream_as_unavailable() {
        #[derive(Debug)]
        struct PendingClient;
        #[async_trait]
        impl Client for PendingClient {
            fn id(&self) -> String {
                "never-responding".into()
            }
            async fn exchange(&self, _: &Message) -> Result<Message> {
                std::future::pending().await
            }
        }
        let tracker = Arc::new(DnsHealthTracker::default());
        let clients =
            observe_clients(vec![Arc::new(PendingClient)], "main", &tracker);
        assert_eq!(tracker.snapshot().status, DnsHealthStatus::Unknown);
        clients[0].mark_query_timeout();
        let health = tracker.snapshot();
        assert_eq!(health.status, DnsHealthStatus::Unavailable);
        assert_eq!(health.groups[0].upstreams[0].failures, 1);
    }

    #[test]
    fn auxiliary_success_does_not_hide_main_dns_failure() {
        let tracker = DnsHealthTracker::default();
        let main = tracker.register("main", "main-1".into());
        let bootstrap = tracker.register("bootstrap", "bootstrap-1".into());
        tracker.record(main, &Err(anyhow::anyhow!("down")));
        tracker.record(bootstrap, &Ok(Message::response(0, OpCode::Query)));
        assert_eq!(tracker.snapshot().status, DnsHealthStatus::Unavailable);
    }

    #[test]
    fn failed_bootstrap_initialization_is_visible_in_health_snapshot() {
        let tracker = DnsHealthTracker::default();
        tracker.record_initialization_failure(
            "bootstrap",
            "unresolvable.example:53".into(),
            "bootstrap lookup failed",
        );
        let health = tracker.snapshot();
        assert_eq!(health.groups[0].status, DnsHealthStatus::Unavailable);
        assert_eq!(health.status, DnsHealthStatus::Unknown);
        assert!(
            health.groups[0].upstreams[0]
                .last_error
                .as_deref()
                .unwrap()
                .contains("bootstrap lookup failed")
        );
    }

    #[test]
    fn network_reset_invalidates_stale_health_without_erasing_history() {
        let tracker = DnsHealthTracker::default();
        let main = tracker.register("main", "upstream".into());
        tracker.record(main, &Ok(Message::response(0, OpCode::Query)));
        assert_eq!(tracker.snapshot().status, DnsHealthStatus::Healthy);
        tracker.invalidate();
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.status, DnsHealthStatus::Unknown);
        assert_eq!(snapshot.groups[0].upstreams[0].successes, 1);
    }

    #[test]
    fn old_observation_expires_to_unknown() {
        let tracker = DnsHealthTracker::default();
        let main = tracker.register("main", "old-dns".into());
        tracker.record(main, &Ok(Message::response(0, OpCode::Query)));
        tracker.lock().clients[main].1.last_success_at =
            Some(unix_timestamp().saturating_sub(OBSERVATION_MAX_AGE_SECS + 1));
        let health = tracker.snapshot();
        assert_eq!(health.status, DnsHealthStatus::Unknown);
        assert_eq!(health.groups[0].upstreams[0].successes, 1);
    }

    #[test]
    fn fallback_success_means_degraded_not_totally_down() {
        let tracker = DnsHealthTracker::default();
        let main = tracker.register("main", "primary".into());
        let fallback = tracker.register("fallback", "backup".into());
        tracker.record(main, &Err(anyhow::anyhow!("timeout")));
        assert_eq!(tracker.snapshot().status, DnsHealthStatus::Unknown);
        tracker.record(fallback, &Ok(Message::response(0, OpCode::Query)));
        assert_eq!(tracker.snapshot().status, DnsHealthStatus::Degraded);
    }
}
