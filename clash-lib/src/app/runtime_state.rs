//! Typed runtime transitions and bounded, credential-free recovery evidence.

use super::network::{
    AUTOMATIC_SUPPORTED, NetworkResetResponse, NetworkSnapshot,
    PathCandidateObservation, TunCandidateExclusion,
};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};

const HISTORY_LIMIT: usize = 32;
const PATH_HEALTH_LIMIT: usize = 128;
const DESTINATION_HEALTH_LIMIT: usize = 256;
const HEALTH_ENTRY_TTL: Duration = Duration::from_secs(300);
const PATH_FAILURE_WINDOW: Duration = Duration::from_secs(30);
const PATH_FAILURE_QUORUM: usize = 3;
const PATH_UNAVAILABLE_COOLDOWN: Duration = Duration::from_secs(30);
const PATH_RECOVERY_RESPONSE_QUORUM: u32 = 3;
const PATH_RECOVERY_STABILITY: Duration = Duration::from_secs(15);
pub(crate) const COMPONENT_READINESS_TIMEOUT: Duration = Duration::from_secs(30);
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn instant_to_epoch_ms(instant: Instant) -> i64 {
    now_ms().saturating_add(
        instant
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i64::MAX as u128) as i64,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum NetworkPhase {
    Observing,
    Unsupported,
    Recovering,
    AwaitingTraffic,
    TrafficVerified,
    WaitingForNetwork,
    Degraded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Lifecycle {
    Starting,
    Running,
    Reloading,
    Stopping,
    Stopped,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RuntimeComponent {
    Control,
    Api,
    Dns,
    Inbound,
    Tun,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RuntimeComponentPhase {
    Starting,
    Ready,
    NotConfigured,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeComponentStatus {
    pub name: RuntimeComponent,
    pub required: bool,
    pub phase: RuntimeComponentPhase,
    pub since_ms: i64,
    pub error: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RuntimeHealth {
    Starting,
    Healthy,
    Degraded,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RecoveryCause {
    NetworkChanged,
    Retry,
    ManualReset,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OperationToken {
    pub config_version: u64,
    pub network_version: u64,
    pub operation_id: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ComponentPhase {
    Refreshed,
    Skipped,
    Failed,
    TimedOut,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ComponentResult {
    pub phase: ComponentPhase,
    pub count: u32,
    pub error: Option<String>,
}
impl ComponentResult {
    pub fn refreshed(count: u32) -> Self {
        Self {
            phase: ComponentPhase::Refreshed,
            count,
            error: None,
        }
    }
    pub fn skipped() -> Self {
        Self {
            phase: ComponentPhase::Skipped,
            count: 0,
            error: None,
        }
    }
    pub fn failed(error: impl ToString) -> Self {
        Self {
            phase: ComponentPhase::Failed,
            count: 0,
            error: Some(error.to_string()),
        }
    }
    pub fn timed_out() -> Self {
        Self {
            phase: ComponentPhase::TimedOut,
            count: 0,
            error: Some("reset timed out".into()),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryReport {
    pub interface: ComponentResult,
    pub dns: ComponentResult,
    pub pools: ComponentResult,
    pub observation_error: Option<String>,
    pub offline: bool,
}
impl RecoveryReport {
    pub fn error(&self) -> Option<String> {
        let mut errors = Vec::new();
        for (name, result) in [
            ("interface", &self.interface),
            ("DNS", &self.dns),
            ("outbound pools", &self.pools),
        ] {
            if let Some(error) = &result.error {
                errors.push(format!("{name}: {error}"));
            }
        }
        if let Some(error) = &self.observation_error {
            errors.push(format!("observation: {error}"));
        }
        if self.offline {
            errors.push("no usable physical network path".into());
        }
        (!errors.is_empty()).then(|| errors.join("; "))
    }
    pub fn into_result(self) -> crate::Result<NetworkResetResponse> {
        if let Some(error) = self.error() {
            Err(crate::Error::Operation(error))
        } else {
            Ok(NetworkResetResponse {
                dns_transports_reset: self.dns.count,
                connection_pools_reset: self.pools.count,
            })
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
enum RecoveryOutcome {
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Superseded,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryOperation {
    token: OperationToken,
    cause: RecoveryCause,
    outcome: RecoveryOutcome,
    started_at_ms: i64,
    finished_at_ms: Option<i64>,
    duration_ms: Option<u64>,
    report: Option<RecoveryReport>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Transition {
    from: NetworkPhase,
    to: NetworkPhase,
    reason: &'static str,
    at_ms: i64,
    token: OperationToken,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationStatus {
    phase: Lifecycle,
    health: RuntimeHealth,
    since_ms: i64,
    reason: &'static str,
    last_reload_error: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum TrafficKind {
    DirectTcp,
    ProxyTcp,
    DirectUdp,
    ProxyUdp,
    ProxyEndpointTcp,
    ProxyEndpointUdp,
    Dns,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrafficEvidence {
    kind: TrafficKind,
    token: OperationToken,
    first_response_at_ms: i64,
    received_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum HealthState {
    Unknown,
    Available,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkPathHealth {
    path: crate::app::flow::NetworkPathId,
    state: HealthState,
    successful_responses: u64,
    independent_failures: u64,
    recovery_successes: u32,
    recovery_stable_since_ms: Option<i64>,
    cooldown_until_ms: Option<i64>,
    last_success_at_ms: Option<i64>,
    last_failure_at_ms: Option<i64>,
    last_error_kind: Option<String>,
    #[serde(skip)]
    last_updated: Instant,
    #[serde(skip)]
    failed_destinations: HashMap<String, Instant>,
    #[serde(skip)]
    recovery_started: Option<Instant>,
    #[serde(skip)]
    cooldown_until: Option<Instant>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DestinationPathHealth {
    /// Ephemeral identifier; the domain or address is deliberately not exposed.
    destination_id: String,
    path: crate::app::flow::NetworkPathId,
    family: Option<crate::app::flow::AddressFamily>,
    state: HealthState,
    successful_responses: u64,
    failures: u64,
    last_success_at_ms: Option<i64>,
    last_failure_at_ms: Option<i64>,
    last_error_kind: Option<String>,
    #[serde(skip)]
    destination_key: String,
    #[serde(skip)]
    last_updated: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrafficOutcome {
    Response,
    Failure(std::io::ErrorKind),
}

/// Mutated by the runtime control task. API callers only clone this snapshot.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeStatus {
    automatic_supported: bool,
    phase: NetworkPhase,
    // Compatibility: generation is the operation counter, not network identity.
    generation: u64,
    failures: u32,
    last_error: Option<String>,
    application: ApplicationStatus,
    components: Vec<RuntimeComponentStatus>,
    config_version: u64,
    network_version: u64,
    phase_since_ms: i64,
    last_observed_at_ms: Option<i64>,
    last_sample_sequence: Option<u64>,
    path_candidates: Vec<PathCandidateObservation>,
    path_candidates_truncated: usize,
    tun_candidate_exclusion: TunCandidateExclusion,
    observation_error: Option<String>,
    next_retry_at_ms: Option<u64>,
    last_operation: Option<RecoveryOperation>,
    operation_history: VecDeque<RecoveryOperation>,
    transitions: VecDeque<Transition>,
    traffic_evidence: Vec<TrafficEvidence>,
    path_health: Vec<NetworkPathHealth>,
    destination_path_health: Vec<DestinationPathHealth>,
    policy_version: u64,
    #[serde(skip)]
    path_priority: Vec<crate::app::flow::PathPriority>,
    #[serde(skip)]
    temporary_path_priority: Option<TemporaryPathPriority>,
    #[serde(skip)]
    path_decisions: VecDeque<crate::app::flow::PathDecisionRecord>,
    rejected_stale_results: u64,
    #[serde(serialize_with = "serialize_counter")]
    dropped_evidence: Arc<AtomicU64>,
    #[serde(skip)]
    observed: Option<NetworkSnapshot>,
    #[serde(skip)]
    operation_started: Option<Instant>,
    #[serde(skip)]
    epoch_tx: Option<watch::Sender<OperationToken>>,
}

#[derive(Clone, Debug)]
struct TemporaryPathPriority {
    priority: Vec<crate::app::flow::PathPriority>,
    source: String,
    created_at_ms: i64,
    expires_at_ms: i64,
    expires_at: Instant,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PathPreferenceView {
    pub automatic_supported: bool,
    pub policy_version: u64,
    pub source: String,
    pub priority: Vec<crate::app::flow::PathPriority>,
    pub created_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
}
fn serialize_counter<S: serde::Serializer>(
    counter: &Arc<AtomicU64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(counter.load(Ordering::Relaxed))
}
impl Default for RuntimeStatus {
    fn default() -> Self {
        let now = now_ms();
        Self {
            automatic_supported: AUTOMATIC_SUPPORTED,
            phase: if AUTOMATIC_SUPPORTED {
                NetworkPhase::Observing
            } else {
                NetworkPhase::Unsupported
            },
            generation: 0,
            failures: 0,
            last_error: None,
            application: ApplicationStatus {
                phase: Lifecycle::Starting,
                health: RuntimeHealth::Starting,
                since_ms: now,
                reason: "startup",
                last_reload_error: None,
            },
            components: [
                RuntimeComponent::Control,
                RuntimeComponent::Api,
                RuntimeComponent::Dns,
                RuntimeComponent::Inbound,
                RuntimeComponent::Tun,
            ]
            .into_iter()
            .map(|name| RuntimeComponentStatus {
                name,
                required: name == RuntimeComponent::Control,
                phase: RuntimeComponentPhase::Starting,
                since_ms: now,
                error: None,
            })
            .collect(),
            config_version: 1,
            network_version: 0,
            phase_since_ms: now,
            last_observed_at_ms: None,
            last_sample_sequence: None,
            path_candidates: Vec::new(),
            path_candidates_truncated: 0,
            tun_candidate_exclusion: TunCandidateExclusion::default(),
            observation_error: None,
            next_retry_at_ms: None,
            last_operation: None,
            operation_history: VecDeque::new(),
            transitions: VecDeque::new(),
            traffic_evidence: Vec::new(),
            path_health: Vec::new(),
            destination_path_health: Vec::new(),
            policy_version: 0,
            path_priority: Vec::new(),
            temporary_path_priority: None,
            path_decisions: VecDeque::new(),
            rejected_stale_results: 0,
            dropped_evidence: Arc::new(AtomicU64::new(0)),
            observed: None,
            operation_started: None,
            epoch_tx: None,
        }
    }
}
impl RuntimeStatus {
    #[cfg(test)]
    pub(crate) fn set_automatic_supported_for_test(&mut self, supported: bool) {
        self.automatic_supported = supported;
    }

    /// Clone the bounded OS path observations for shadow planning without
    /// exposing the mutable runtime status lock to the planner.
    pub(crate) fn shadow_path_snapshot(
        &self,
    ) -> Option<(u64, Vec<PathCandidateObservation>, bool)> {
        self.automatic_supported.then(|| {
            (
                self.network_version,
                self.path_candidates.clone(),
                !matches!(
                    self.tun_candidate_exclusion,
                    TunCandidateExclusion::Disabled
                ),
            )
        })
    }

    /// Versions captured by Explain records so a dial racing a reload remains
    /// attributable to the configuration and network snapshot it used.
    pub(crate) fn decision_versions(&self) -> (u64, u64, u64, u64) {
        (
            self.config_version,
            self.policy_version,
            self.network_version,
            self.generation,
        )
    }

    /// Refresh preference expiry and expose cache generations without copying
    /// the observed path list on every UDP packet.
    pub(crate) fn path_cache_versions(&mut self) -> Option<(u64, u64)> {
        self.expire_temporary_path_priority();
        self.automatic_supported
            .then_some((self.network_version, self.policy_version))
    }

    pub(crate) fn path_planning_snapshot(
        &mut self,
    ) -> Option<(
        u64,
        Vec<PathCandidateObservation>,
        bool,
        crate::app::flow::NetworkIntentSnapshot,
    )> {
        self.expire_temporary_path_priority();
        let (network_version, mut observations, tun_enabled) =
            self.shadow_path_snapshot()?;
        let now = Instant::now();
        for observation in &mut observations {
            let path_id = crate::app::flow::NetworkPathId {
                interface: observation.interface.clone(),
                family: observation.family,
                source_address: Some(observation.source_address),
                network_generation: network_version,
            };
            if self.path_health.iter().any(|health| {
                health.path == path_id
                    && health.state == HealthState::Unavailable
                    && health.cooldown_until.is_some_and(|until| now < until)
            }) {
                observation.binding = super::network::BindingStatus::Failed;
                observation.binding_error = Some(
                    "path is in cooldown after independent failures".to_owned(),
                );
            }
        }
        let priority = self.effective_path_priority();
        let intents: Vec<crate::app::flow::PathIntent> = priority
            .iter()
            .copied()
            .map(crate::app::flow::PathIntent::from)
            .collect();
        Some((
            network_version,
            observations,
            tun_enabled,
            crate::app::flow::NetworkIntentSnapshot {
                policy_generation: self.policy_version,
                intents,
            },
        ))
    }

    pub(crate) fn set_path_priority(
        &mut self,
        priority: Vec<crate::app::flow::PathPriority>,
        ttl_ms: Option<u64>,
    ) -> Result<PathPreferenceView, String> {
        if !self.automatic_supported {
            return Err(
                "runtime path preferences are unsupported by this platform observer"
                    .to_owned(),
            );
        }
        if priority.len() > 16 {
            return Err("path preference accepts at most 16 entries".to_owned());
        }
        let mut seen = std::collections::HashSet::new();
        if priority.iter().any(|entry| {
            entry.interface == crate::app::flow::InterfaceKind::Unknown
                || !seen.insert(*entry)
        }) {
            return Err(
                "path preference entries must be unique and use a known interface kind"
                    .to_owned(),
            );
        }
        if ttl_ms.is_some_and(|ttl| !(1_000..=86_400_000).contains(&ttl)) {
            return Err("ttlMs must be between 1000 and 86400000".to_owned());
        }
        let policy_version = self
            .policy_version
            .checked_add(1)
            .ok_or_else(|| "policyVersion is exhausted".to_owned())?;

        // Compile against the same currently observed facts before replacing
        // the live intent. An unavailable preference is valid; it simply has
        // no effect until a matching path is observed.
        let intents: Vec<crate::app::flow::PathIntent> = priority
            .iter()
            .copied()
            .map(crate::app::flow::PathIntent::from)
            .collect();
        if let Some((network_version, observations, _)) = self.shadow_path_snapshot()
        {
            for family in [
                crate::app::flow::AddressFamily::Ipv4,
                crate::app::flow::AddressFamily::Ipv6,
            ] {
                let _ = crate::app::path_policy::compile_path_plan(
                    &observations,
                    &crate::app::flow::NetworkIntentSnapshot {
                        policy_generation: policy_version,
                        intents: intents.clone(),
                    },
                    network_version,
                    crate::app::flow::RouteDecision {
                        outbound: "DIRECT".to_owned(),
                        rule: None,
                    },
                    Some(family),
                );
            }
        }

        let now_ms = now_ms();
        if let Some(ttl_ms) = ttl_ms {
            self.temporary_path_priority = Some(TemporaryPathPriority {
                priority,
                source: "temporaryOverride".to_owned(),
                created_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(ttl_ms as i64),
                expires_at: Instant::now() + Duration::from_millis(ttl_ms),
            });
        } else {
            self.path_priority = priority;
            self.temporary_path_priority = None;
        }
        self.policy_version = policy_version;
        tracing::info!(
            policy_version,
            temporary = ttl_ms.is_some(),
            "runtime network path preference updated"
        );
        Ok(self.path_preference_view())
    }

    pub(crate) fn clear_temporary_path_priority(
        &mut self,
    ) -> Result<PathPreferenceView, String> {
        if self.temporary_path_priority.is_some() {
            let policy_version = self
                .policy_version
                .checked_add(1)
                .ok_or_else(|| "policyVersion is exhausted".to_owned())?;
            self.temporary_path_priority = None;
            self.policy_version = policy_version;
        }
        Ok(self.path_preference_view())
    }

    pub(crate) fn path_preference_view(&mut self) -> PathPreferenceView {
        self.expire_temporary_path_priority();
        if let Some(temporary) = &self.temporary_path_priority {
            PathPreferenceView {
                automatic_supported: self.automatic_supported,
                policy_version: self.policy_version,
                source: temporary.source.clone(),
                priority: temporary.priority.clone(),
                created_at_ms: Some(temporary.created_at_ms),
                expires_at_ms: Some(temporary.expires_at_ms),
            }
        } else {
            PathPreferenceView {
                automatic_supported: self.automatic_supported,
                policy_version: self.policy_version,
                source: "runtime".to_owned(),
                priority: self.path_priority.clone(),
                created_at_ms: None,
                expires_at_ms: None,
            }
        }
    }

    fn effective_path_priority(&self) -> &[crate::app::flow::PathPriority] {
        self.temporary_path_priority
            .as_ref()
            .map_or(&self.path_priority, |temporary| &temporary.priority)
    }

    fn expire_temporary_path_priority(&mut self) {
        if self
            .temporary_path_priority
            .as_ref()
            .is_some_and(|temporary| Instant::now() >= temporary.expires_at)
        {
            self.temporary_path_priority = None;
            self.policy_version = self.policy_version.saturating_add(1);
            tracing::info!(
                policy_version = self.policy_version,
                "temporary network path preference expired"
            );
        }
    }

    pub(crate) fn effective_paths_view(&mut self) -> serde_json::Value {
        let Some((network_version, observations, tun_enabled, intent)) =
            self.path_planning_snapshot()
        else {
            return serde_json::json!({
                "automaticSupported": false,
                "policyVersion": self.policy_version,
                "networkVersion": self.network_version,
                "configuredPriority": self.effective_path_priority(),
                "paths": [],
                "effectivePreferredPath": { "ipv4": null, "ipv6": null },
                "decisions": {},
            });
        };

        let route = crate::app::flow::RouteDecision {
            outbound: "DIRECT".to_owned(),
            rule: None,
        };
        let compiled = [
            crate::app::flow::AddressFamily::Ipv4,
            crate::app::flow::AddressFamily::Ipv6,
        ]
        .map(|family| {
            (
                family,
                crate::app::path_policy::compile_path_plan(
                    &observations,
                    &intent,
                    network_version,
                    route.clone(),
                    Some(family),
                ),
            )
        });
        let mut preferred = serde_json::Map::new();
        let mut decisions = serde_json::Map::new();
        for (family, result) in &compiled {
            let selected = result.decision.selected.as_ref();
            preferred.insert(
                match family {
                    crate::app::flow::AddressFamily::Ipv4 => "ipv4",
                    crate::app::flow::AddressFamily::Ipv6 => "ipv6",
                }
                .to_owned(),
                serde_json::to_value(selected).unwrap_or(serde_json::Value::Null),
            );
            decisions.insert(
                match family {
                    crate::app::flow::AddressFamily::Ipv4 => "ipv4",
                    crate::app::flow::AddressFamily::Ipv6 => "ipv6",
                }
                .to_owned(),
                serde_json::json!({
                    "reason": result.decision.reason,
                    "selected": result.decision.selected,
                    "rejected": result.decision.rejected,
                }),
            );
        }

        let paths = observations
            .iter()
            .map(|observation| {
                let path_id = crate::app::flow::NetworkPathId {
                    interface: observation.interface.clone(),
                    family: observation.family,
                    source_address: Some(observation.source_address),
                    network_generation: network_version,
                };
                let health = self
                    .path_health
                    .iter()
                    .find(|health| health.path == path_id)
                    .map_or(HealthState::Unknown, |health| health.state);
                let preference_rank = self
                    .effective_path_priority()
                    .iter()
                    .position(|priority| {
                        priority.interface == observation.interface_kind
                            && priority.family == observation.family
                    })
                    .map(|index| index + 1);
                serde_json::json!({
                    "path": path_id,
                    "interfaceKind": observation.interface_kind,
                    "family": observation.family,
                    "sourceAddress": observation.source_address,
                    "defaultRouteEvidence": observation.default_route,
                    "binding": observation.binding,
                    "bindingError": observation.binding_error,
                    "health": health,
                    "preferenceRank": preference_rank,
                    "cooldownUntilMs": self.path_health.iter()
                        .find(|health| health.path == path_id)
                        .and_then(|health| health.cooldown_until_ms),
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "automaticSupported": true,
            "policyVersion": intent.policy_generation,
            "networkVersion": network_version,
            "tunEnabled": tun_enabled,
            "configuredPriority": self.effective_path_priority(),
            "paths": paths,
            "effectivePreferredPath": preferred,
            "decisions": decisions,
        })
    }

    pub(crate) fn record_path_decision(
        &mut self,
        decision: crate::app::flow::PathDecisionRecord,
    ) -> bool {
        self.expire_path_decisions();
        if decision.network_version != self.network_version {
            self.rejected_stale_results =
                self.rejected_stale_results.saturating_add(1);
            return false;
        }
        self.path_decisions
            .retain(|existing| existing.flow_id != decision.flow_id);
        if self.path_decisions.len() >= 256 {
            self.path_decisions.pop_front();
        }
        self.path_decisions.push_back(decision);
        true
    }

    pub(crate) fn path_decision(
        &mut self,
        flow_id: uuid::Uuid,
    ) -> Option<crate::app::flow::PathDecisionRecord> {
        self.expire_path_decisions();
        self.path_decisions
            .iter()
            .find(|decision| decision.flow_id == flow_id)
            .cloned()
    }

    pub(crate) fn path_decisions_snapshot(
        &mut self,
    ) -> Vec<crate::app::flow::PathDecisionRecord> {
        self.expire_path_decisions();
        self.path_decisions.iter().rev().cloned().collect()
    }

    fn expire_path_decisions(&mut self) {
        let now = now_ms();
        self.path_decisions.retain(|decision| {
            now.saturating_sub(decision.recorded_at_ms)
                < HEALTH_ENTRY_TTL.as_millis() as i64
        });
    }

    fn token(&self) -> OperationToken {
        OperationToken {
            config_version: self.config_version,
            network_version: self.network_version,
            operation_id: self.generation,
        }
    }
    fn publish_epoch(&self) {
        if let Some(tx) = &self.epoch_tx {
            tx.send_replace(self.token());
        }
    }
    fn transition(&mut self, to: NetworkPhase, reason: &'static str) {
        self.transition_inner(to, reason, false);
    }
    fn transition_inner(
        &mut self,
        to: NetworkPhase,
        reason: &'static str,
        record_reentry: bool,
    ) {
        if self.phase == to && !record_reentry {
            return;
        }
        let event = Transition {
            from: self.phase,
            to,
            reason,
            at_ms: now_ms(),
            token: self.token(),
        };
        tracing::info!(from = ?event.from, to = ?event.to, reason, config_version = self.config_version, network_version = self.network_version, operation_id = self.generation, "runtime network state changed");
        self.phase = to;
        self.phase_since_ms = event.at_ms;
        if self.transitions.len() == HISTORY_LIMIT {
            self.transitions.pop_front();
        }
        self.transitions.push_back(event);
    }
    pub fn lifecycle(&mut self, to: Lifecycle, reason: &'static str) -> bool {
        let from = self.application.phase;
        let allowed = matches!(
            (from, to),
            (
                Lifecycle::Starting,
                Lifecycle::Running | Lifecycle::Failed | Lifecycle::Stopping
            ) | (
                Lifecycle::Running,
                Lifecycle::Reloading | Lifecycle::Stopping | Lifecycle::Failed
            ) | (
                Lifecycle::Reloading,
                Lifecycle::Running | Lifecycle::Stopping | Lifecycle::Failed
            ) | (Lifecycle::Stopping, Lifecycle::Stopped | Lifecycle::Failed)
        );
        if !allowed {
            return false;
        }
        if matches!(to, Lifecycle::Stopping | Lifecycle::Failed) {
            if let Some(op) = self
                .last_operation
                .as_mut()
                .filter(|op| op.finished_at_ms.is_none())
            {
                op.outcome = RecoveryOutcome::Cancelled;
                op.finished_at_ms = Some(now_ms());
                op.duration_ms = self.operation_started.take().map(|start| {
                    start.elapsed().as_millis().min(u64::MAX as u128) as u64
                });
            }
            self.next_retry_at_ms = None;
        }
        self.application.phase = to;
        self.application.health = match to {
            Lifecycle::Starting => RuntimeHealth::Starting,
            Lifecycle::Stopped => RuntimeHealth::Stopped,
            Lifecycle::Failed => RuntimeHealth::Degraded,
            Lifecycle::Running | Lifecycle::Reloading | Lifecycle::Stopping => {
                if self.components.iter().any(|component| {
                    component.phase == RuntimeComponentPhase::Failed
                }) {
                    RuntimeHealth::Degraded
                } else {
                    RuntimeHealth::Healthy
                }
            }
        };
        self.application.reason = reason;
        self.application.since_ms = now_ms();
        self.publish_epoch();
        tracing::info!(?from, ?to, reason, "application lifecycle changed");
        true
    }
    pub fn set_component(
        &mut self,
        name: RuntimeComponent,
        phase: RuntimeComponentPhase,
        error: Option<String>,
    ) -> bool {
        let Some(component) =
            self.components.iter_mut().find(|item| item.name == name)
        else {
            return false;
        };
        let required = name == RuntimeComponent::Control
            || phase != RuntimeComponentPhase::NotConfigured;
        if component.phase == phase
            && component.required == required
            && component.error == error
        {
            return false;
        }
        component.required = required;
        component.phase = phase;
        component.since_ms = now_ms();
        component.error = error;
        if matches!(
            self.application.phase,
            Lifecycle::Running | Lifecycle::Reloading
        ) {
            self.application.health = if self
                .components
                .iter()
                .any(|item| item.phase == RuntimeComponentPhase::Failed)
            {
                RuntimeHealth::Degraded
            } else {
                RuntimeHealth::Healthy
            };
        }
        true
    }
    pub fn stop_components(&mut self) {
        for component in &mut self.components {
            if component.phase != RuntimeComponentPhase::Stopped {
                component.phase = RuntimeComponentPhase::Stopped;
                component.since_ms = now_ms();
                component.error = None;
            }
        }
        self.application.health = RuntimeHealth::Stopped;
    }
    pub fn reload_finished(&mut self, error: Option<String>) {
        if self.application.phase != Lifecycle::Reloading {
            return;
        }
        if error.is_none() {
            self.config_version = self.config_version.saturating_add(1);
            self.observed = None;
            self.traffic_evidence.clear();
            self.path_health.clear();
            self.destination_path_health.clear();
            self.last_operation = None;
            self.last_error = None;
            self.failures = 0;
            self.next_retry_at_ms = None;
            self.transition(
                if AUTOMATIC_SUPPORTED {
                    NetworkPhase::Observing
                } else {
                    NetworkPhase::Unsupported
                },
                "configCommitted",
            );
        }
        self.application.last_reload_error = error;
        self.lifecycle(Lifecycle::Running, "reloadFinished");
    }
    pub fn observed(&mut self, snapshot: &NetworkSnapshot) {
        self.path_candidates = snapshot.path_candidates.clone();
        self.path_candidates_truncated = snapshot.path_candidates_truncated;
        self.tun_candidate_exclusion = snapshot.tun_candidate_exclusion.clone();
        if self.observed.as_ref() != Some(snapshot) {
            self.network_version = self.network_version.saturating_add(1);
            self.observed = Some(snapshot.clone());
            self.traffic_evidence.clear();
            self.path_health.clear();
            self.destination_path_health.clear();
            self.publish_epoch();
        }
        self.last_observed_at_ms = Some(now_ms());
        let was_failed = self.observation_error.take().is_some();
        if was_failed
            && self.last_operation.as_ref().is_none_or(|op| {
                op.report
                    .as_ref()
                    .is_some_and(|report| report.error().is_none())
            })
        {
            self.last_error = None;
            self.transition(
                if !self.traffic_evidence.is_empty() {
                    NetworkPhase::TrafficVerified
                } else if self.last_operation.is_some() {
                    NetworkPhase::AwaitingTraffic
                } else {
                    NetworkPhase::Observing
                },
                "observationRestored",
            );
        }
    }
    pub fn observed_sample(&mut self, sample: &super::network::NetworkSample) {
        if let Ok(snapshot) = &sample.result {
            self.observed(snapshot);
            self.last_sample_sequence = Some(sample.sequence);
        }
    }
    pub fn observation_failed_sample(
        &mut self,
        sample: &super::network::NetworkSample,
    ) {
        self.last_sample_sequence = Some(sample.sequence);
        self.last_observed_at_ms = Some(now_ms());
        if let Err(error) = &sample.result {
            self.observation_failed(error);
        }
    }
    pub fn observation_failed(&mut self, error: impl ToString) {
        self.observation_error = Some(error.to_string());
        if self.last_error.is_none() {
            self.last_error = self.observation_error.clone();
        }
        self.transition(NetworkPhase::Degraded, "observationFailed");
    }
    pub fn begin(
        &mut self,
        cause: RecoveryCause,
        snapshot: Option<&NetworkSnapshot>,
    ) -> Option<OperationToken> {
        if self.application.phase != Lifecycle::Running {
            return None;
        }
        if self
            .last_operation
            .as_ref()
            .is_some_and(|op| op.finished_at_ms.is_none())
        {
            return None;
        }
        if let Some(snapshot) = snapshot {
            self.observed(snapshot);
        }
        self.generation = self.generation.saturating_add(1);
        self.traffic_evidence.clear();
        self.next_retry_at_ms = None;
        self.operation_started = Some(Instant::now());
        let token = self.token();
        if let Some(previous) = self.last_operation.take()
            && previous.finished_at_ms.is_some()
        {
            if self.operation_history.len() == HISTORY_LIMIT {
                self.operation_history.pop_front();
            }
            self.operation_history.push_back(previous);
        }
        self.last_operation = Some(RecoveryOperation {
            token,
            cause,
            outcome: RecoveryOutcome::Running,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            duration_ms: None,
            report: None,
        });
        self.publish_epoch();
        self.transition_inner(NetworkPhase::Recovering, "recoveryStarted", true);
        Some(token)
    }
    pub fn complete(
        &mut self,
        token: OperationToken,
        report: RecoveryReport,
        retry_delay: Option<Duration>,
    ) -> bool {
        if self.application.phase != Lifecycle::Running
            || token != self.token()
            || self
                .last_operation
                .as_ref()
                .is_none_or(|op| op.token != token || op.finished_at_ms.is_some())
        {
            self.rejected_stale_results =
                self.rejected_stale_results.saturating_add(1);
            return false;
        }
        let error = report.error();
        let offline = report.offline;
        if let Some(op) = self.last_operation.as_mut() {
            op.outcome = if error.is_some() {
                RecoveryOutcome::Failed
            } else {
                RecoveryOutcome::Succeeded
            };
            op.finished_at_ms = Some(now_ms());
            op.duration_ms = self.operation_started.take().map(|start| {
                start.elapsed().as_millis().min(u64::MAX as u128) as u64
            });
            op.report = Some(report);
        }
        self.next_retry_at_ms = retry_delay.map(|delay| {
            (now_ms().max(0) as u64)
                .saturating_add(delay.as_millis().min(u64::MAX as u128) as u64)
        });
        self.last_error = error.clone();
        if error.is_some() {
            self.failures = self.failures.saturating_add(1);
            self.transition(
                if offline {
                    NetworkPhase::WaitingForNetwork
                } else {
                    NetworkPhase::Degraded
                },
                "recoveryFailed",
            );
        } else {
            self.failures = 0;
            self.transition(NetworkPhase::AwaitingTraffic, "resourcesRefreshed");
        }
        true
    }
    pub fn supersede(
        &mut self,
        token: OperationToken,
        report: RecoveryReport,
    ) -> bool {
        if self.application.phase != Lifecycle::Running
            || self
                .last_operation
                .as_ref()
                .is_none_or(|op| op.token != token || op.finished_at_ms.is_some())
        {
            return false;
        }
        if let Some(op) = self.last_operation.as_mut() {
            op.outcome = RecoveryOutcome::Superseded;
            op.finished_at_ms = Some(now_ms());
            op.duration_ms = self.operation_started.take().map(|start| {
                start.elapsed().as_millis().min(u64::MAX as u128) as u64
            });
            op.report = Some(report);
        }
        true
    }
    pub fn traffic_reporter(
        &mut self,
        tx: mpsc::Sender<TrafficProofEvent>,
    ) -> TrafficReporter {
        let (epoch_tx, epoch) = watch::channel(self.token());
        self.epoch_tx = Some(epoch_tx);
        TrafficReporter {
            tx,
            epoch,
            dropped: self.dropped_evidence.clone(),
        }
    }
    pub fn record_traffic(&mut self, event: TrafficProofEvent) {
        if self.application.phase != Lifecycle::Running {
            return;
        }
        if event.token != self.token()
            || event.path_id.as_ref().is_some_and(|path| {
                path.network_generation != event.token.network_version
            })
        {
            self.rejected_stale_results =
                self.rejected_stale_results.saturating_add(1);
            return;
        }

        self.expire_health();
        if let Some(path) = event.path_id.as_ref() {
            self.record_path_health(path, event.destination.as_ref(), event.outcome);
        }

        if event.outcome != TrafficOutcome::Response || event.bytes == 0 {
            return;
        }
        if !self
            .traffic_evidence
            .iter()
            .any(|proof| proof.kind == event.kind)
        {
            self.traffic_evidence.push(TrafficEvidence {
                kind: event.kind,
                token: event.token,
                first_response_at_ms: now_ms(),
                received_bytes: event.bytes as u64,
            });
        }
        // Traffic proves only the recorded path. It cannot clear DNS/pool errors.
        if self.phase == NetworkPhase::AwaitingTraffic
            && self.observation_error.is_none()
        {
            self.transition(
                NetworkPhase::TrafficVerified,
                "upstreamResponseReceived",
            );
        }
    }

    fn record_path_health(
        &mut self,
        path_id: &crate::app::flow::NetworkPathId,
        destination: Option<&crate::session::SocksAddr>,
        outcome: TrafficOutcome,
    ) {
        let now = Instant::now();
        let destination_key = destination.map(destination_health_key);
        let destination_host_key = destination.map(destination_host_key);
        let path_index = match self
            .path_health
            .iter()
            .position(|health| &health.path == path_id)
        {
            Some(index) => index,
            None => {
                if self.path_health.len() >= PATH_HEALTH_LIMIT
                    && let Some(oldest) = self
                        .path_health
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, health)| health.last_updated)
                        .map(|(index, _)| index)
                {
                    let expired_path = self.path_health.remove(oldest).path;
                    self.destination_path_health
                        .retain(|health| health.path != expired_path);
                }
                self.path_health.push(NetworkPathHealth {
                    path: path_id.clone(),
                    state: HealthState::Unknown,
                    successful_responses: 0,
                    independent_failures: 0,
                    recovery_successes: 0,
                    recovery_stable_since_ms: None,
                    cooldown_until_ms: None,
                    last_success_at_ms: None,
                    last_failure_at_ms: None,
                    last_error_kind: None,
                    last_updated: now,
                    failed_destinations: HashMap::new(),
                    recovery_started: None,
                    cooldown_until: None,
                });
                self.path_health.len() - 1
            }
        };

        let health = &mut self.path_health[path_index];
        health.last_updated = now;
        let previous_path_state = health.state;
        match outcome {
            TrafficOutcome::Response => {
                health.successful_responses =
                    health.successful_responses.saturating_add(1);
                health.last_success_at_ms = Some(now_ms());
                health.last_error_kind = None;
                if previous_path_state == HealthState::Unavailable {
                    health.recovery_successes =
                        health.recovery_successes.saturating_add(1);
                    let recovery_started =
                        *health.recovery_started.get_or_insert(now);
                    health.recovery_stable_since_ms =
                        Some(instant_to_epoch_ms(recovery_started));
                    if health.recovery_successes >= PATH_RECOVERY_RESPONSE_QUORUM
                        && now.duration_since(recovery_started)
                            >= PATH_RECOVERY_STABILITY
                    {
                        health.state = HealthState::Available;
                        health.recovery_successes = 0;
                        health.recovery_started = None;
                        health.recovery_stable_since_ms = None;
                        health.cooldown_until = None;
                        health.cooldown_until_ms = None;
                        health.failed_destinations.clear();
                    }
                } else {
                    health.state = HealthState::Available;
                    health.recovery_successes = 0;
                    health.recovery_started = None;
                    health.recovery_stable_since_ms = None;
                    health.cooldown_until = None;
                    health.cooldown_until_ms = None;
                    health.failed_destinations.clear();
                }
            }
            TrafficOutcome::Failure(error_kind) => {
                health.last_failure_at_ms = Some(now_ms());
                health.last_error_kind = Some(format!("{error_kind:?}"));
                if is_path_level_failure(error_kind)
                    && let Some(destination_host_key) = destination_host_key.as_ref()
                {
                    health.recovery_successes = 0;
                    health.recovery_started = None;
                    health.recovery_stable_since_ms = None;
                    health.failed_destinations.retain(|_, at| {
                        now.duration_since(*at) < PATH_FAILURE_WINDOW
                    });
                    if !health
                        .failed_destinations
                        .contains_key(destination_host_key)
                        && health.failed_destinations.len() < PATH_FAILURE_QUORUM
                    {
                        health
                            .failed_destinations
                            .insert(destination_host_key.clone(), now);
                        health.independent_failures =
                            health.independent_failures.saturating_add(1);
                    }
                    if health.failed_destinations.len() >= PATH_FAILURE_QUORUM {
                        health.state = HealthState::Unavailable;
                        if previous_path_state != HealthState::Unavailable
                            || health.cooldown_until.is_none_or(|until| now >= until)
                        {
                            let cooldown_until = now + PATH_UNAVAILABLE_COOLDOWN;
                            health.cooldown_until = Some(cooldown_until);
                            health.cooldown_until_ms =
                                Some(instant_to_epoch_ms(cooldown_until));
                        }
                    }
                }
            }
        }
        if health.state != previous_path_state {
            tracing::info!(
                path = ?health.path,
                from = ?previous_path_state,
                to = ?health.state,
                network_generation = health.path.network_generation,
                "network path health changed"
            );
        }

        let Some(destination) = destination else {
            return;
        };
        let destination_key = destination_key.unwrap_or_default();
        let destination_index =
            match self.destination_path_health.iter().position(|health| {
                health.path == *path_id && health.destination_key == destination_key
            }) {
                Some(index) => index,
                None => {
                    if self.destination_path_health.len() >= DESTINATION_HEALTH_LIMIT
                        && let Some(oldest) = self
                            .destination_path_health
                            .iter()
                            .enumerate()
                            .min_by_key(|(_, health)| health.last_updated)
                            .map(|(index, _)| index)
                    {
                        self.destination_path_health.remove(oldest);
                    }
                    self.destination_path_health.push(DestinationPathHealth {
                        destination_id: uuid::Uuid::new_v4().to_string(),
                        path: path_id.clone(),
                        family: destination_family(destination),
                        state: HealthState::Unknown,
                        successful_responses: 0,
                        failures: 0,
                        last_success_at_ms: None,
                        last_failure_at_ms: None,
                        last_error_kind: None,
                        destination_key,
                        last_updated: now,
                    });
                    self.destination_path_health.len() - 1
                }
            };
        let health = &mut self.destination_path_health[destination_index];
        health.last_updated = now;
        let previous_destination_state = health.state;
        match outcome {
            TrafficOutcome::Response => {
                health.state = HealthState::Available;
                health.successful_responses =
                    health.successful_responses.saturating_add(1);
                health.last_success_at_ms = Some(now_ms());
                health.last_error_kind = None;
            }
            TrafficOutcome::Failure(error_kind) => {
                health.state = HealthState::Unavailable;
                health.failures = health.failures.saturating_add(1);
                health.last_failure_at_ms = Some(now_ms());
                health.last_error_kind = Some(format!("{error_kind:?}"));
            }
        }
        if health.state != previous_destination_state {
            tracing::info!(
                destination_id = %health.destination_id,
                path = ?health.path,
                from = ?previous_destination_state,
                to = ?health.state,
                "destination path health changed"
            );
        }
    }

    pub fn expire_health(&mut self) {
        let now = Instant::now();
        for health in &mut self.path_health {
            health
                .failed_destinations
                .retain(|_, at| now.duration_since(*at) < PATH_FAILURE_WINDOW);
        }
        self.path_health.retain(|health| {
            now.duration_since(health.last_updated) < HEALTH_ENTRY_TTL
        });
        self.destination_path_health.retain(|health| {
            now.duration_since(health.last_updated) < HEALTH_ENTRY_TTL
        });
    }

    /// Whether a path is currently excluded from new dials after independent
    /// failures. Expired cooldowns are treated as eligible so the path planner
    /// can probe recovery again.
    pub(crate) fn path_is_unavailable(
        &mut self,
        path: &crate::app::flow::NetworkPathId,
    ) -> bool {
        self.expire_health();
        let now = Instant::now();
        self.path_health.iter().any(|health| {
            health.path == *path
                && health.state == HealthState::Unavailable
                && health.cooldown_until.is_some_and(|until| now < until)
        })
    }
    #[cfg(test)]
    pub fn phase(&self) -> NetworkPhase {
        self.phase
    }
}

fn destination_host(destination: &crate::session::SocksAddr) -> String {
    match destination {
        crate::session::SocksAddr::Ip(address) => {
            format!("ip:{}", address.ip())
        }
        crate::session::SocksAddr::Domain(domain, _) => {
            format!("domain:{}", domain.to_ascii_lowercase())
        }
    }
}

fn hash_destination_key(key: String) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn destination_host_key(destination: &crate::session::SocksAddr) -> String {
    hash_destination_key(destination_host(destination))
}

fn destination_health_key(destination: &crate::session::SocksAddr) -> String {
    let host = destination_host(destination);
    let port = destination.port();
    hash_destination_key(format!("{host}:{port}"))
}

fn destination_family(
    destination: &crate::session::SocksAddr,
) -> Option<crate::app::flow::AddressFamily> {
    match destination {
        crate::session::SocksAddr::Ip(address) => {
            Some(crate::app::flow::AddressFamily::from(address.ip()))
        }
        crate::session::SocksAddr::Domain(_, _) => None,
    }
}

fn is_path_level_failure(error_kind: std::io::ErrorKind) -> bool {
    matches!(
        error_kind,
        std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkDown
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::TimedOut
    )
}

#[derive(Clone, Debug)]
pub(crate) struct TrafficReporter {
    tx: mpsc::Sender<TrafficProofEvent>,
    epoch: watch::Receiver<OperationToken>,
    dropped: Arc<AtomicU64>,
}
#[derive(Debug)]
pub(crate) struct TrafficProofEvent {
    token: OperationToken,
    kind: TrafficKind,
    bytes: usize,
    path_id: Option<crate::app::flow::NetworkPathId>,
    destination: Option<crate::session::SocksAddr>,
    outcome: TrafficOutcome,
}
#[derive(Clone, Debug)]
pub(crate) struct TrafficProof {
    reporter: TrafficReporter,
    token: OperationToken,
    kind: TrafficKind,
    reported: Arc<AtomicBool>,
    path_id: Option<crate::app::flow::NetworkPathId>,
    destination: Option<crate::session::SocksAddr>,
}
impl TrafficReporter {
    pub fn capture(&self, kind: TrafficKind) -> TrafficProof {
        self.capture_scoped(kind, None, None)
    }

    pub fn capture_scoped(
        &self,
        kind: TrafficKind,
        path_id: Option<crate::app::flow::NetworkPathId>,
        destination: Option<crate::session::SocksAddr>,
    ) -> TrafficProof {
        TrafficProof {
            reporter: self.clone(),
            token: *self.epoch.borrow(),
            kind,
            reported: Arc::new(AtomicBool::new(false)),
            path_id,
            destination,
        }
    }
}
impl TrafficProof {
    pub fn set_path_id(&mut self, path_id: Option<crate::app::flow::NetworkPathId>) {
        self.path_id = path_id;
    }

    pub fn received(&self, bytes: usize) {
        if bytes == 0 || self.reported.swap(true, Ordering::Relaxed) {
            return;
        }
        let event = TrafficProofEvent {
            token: self.token,
            kind: self.kind,
            bytes,
            path_id: self.path_id.clone(),
            destination: self.destination.clone(),
            outcome: TrafficOutcome::Response,
        };
        if self.reporter.tx.try_send(event).is_err() {
            self.reporter.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn failed(&self, error_kind: std::io::ErrorKind) {
        if self.path_id.is_none() || self.reported.swap(true, Ordering::Relaxed) {
            return;
        }
        let event = TrafficProofEvent {
            token: self.token,
            kind: self.kind,
            bytes: 0,
            path_id: self.path_id.clone(),
            destination: self.destination.clone(),
            outcome: TrafficOutcome::Failure(error_kind),
        };
        if self.reporter.tx.try_send(event).is_err() {
            self.reporter.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running() -> RuntimeStatus {
        let mut state = RuntimeStatus::default();
        assert!(state.lifecycle(Lifecycle::Running, "listenersReady"));
        state
    }
    fn report() -> RecoveryReport {
        RecoveryReport {
            interface: ComponentResult::refreshed(0),
            dns: ComponentResult::refreshed(2),
            pools: ComponentResult::refreshed(1),
            observation_error: None,
            offline: false,
        }
    }
    #[test]
    fn component_failure_survives_traffic_evidence() {
        let mut state = running();
        let token = state.begin(RecoveryCause::ManualReset, None).unwrap();
        let mut result = report();
        result.dns = ComponentResult::timed_out();
        assert!(state.complete(token, result, Some(Duration::from_secs(2))));
        state.record_traffic(TrafficProofEvent {
            token,
            kind: TrafficKind::DirectTcp,
            bytes: 4,
            path_id: None,
            destination: None,
            outcome: TrafficOutcome::Response,
        });
        assert_eq!(state.phase, NetworkPhase::Degraded);
        assert!(state.last_error.as_ref().unwrap().contains("DNS"));
        assert_eq!(state.traffic_evidence.len(), 1);
        assert!(state.next_retry_at_ms.unwrap() >= now_ms() as u64);
    }
    #[test]
    fn operation_and_config_versions_reject_stale_results() {
        let mut state = running();
        let old = state.begin(RecoveryCause::ManualReset, None).unwrap();
        assert!(state.supersede(old, report()));
        let current = state.begin(RecoveryCause::Retry, None).unwrap();
        assert!(!state.complete(old, report(), None));
        assert!(state.complete(current, report(), None));
        assert!(!state.complete(current, report(), None));
        assert!(state.lifecycle(Lifecycle::Reloading, "configReload"));
        state.reload_finished(Some("invalid configuration".into()));
        assert_eq!(state.config_version, 1);
        assert!(state.lifecycle(Lifecycle::Reloading, "configReload"));
        state.reload_finished(None);
        assert_eq!(state.config_version, 2);
        state.record_traffic(TrafficProofEvent {
            token: current,
            kind: TrafficKind::DirectTcp,
            bytes: 4,
            path_id: None,
            destination: None,
            outcome: TrafficOutcome::Response,
        });
        assert!(state.traffic_evidence.is_empty());
        assert_eq!(state.rejected_stale_results, 3);
    }
    #[test]
    fn network_version_changes_only_for_new_snapshot() {
        let mut state = running();
        let first = NetworkSnapshot::default();
        state.observed(&first);
        let token = state
            .begin(RecoveryCause::ManualReset, Some(&first))
            .unwrap();
        state.observed(&first);
        assert_eq!(state.network_version, token.network_version);
        let changed = NetworkSnapshot {
            dns: "new resolver".into(),
            ..first
        };
        state.observed(&changed);
        assert!(!state.complete(token, report(), None));
        assert_eq!(state.phase, NetworkPhase::Recovering);
        assert_eq!(state.network_version, token.network_version + 1);
    }
    #[test]
    fn terminal_lifecycle_rejects_recovery_and_responses() {
        let mut state = running();
        let token = state.begin(RecoveryCause::ManualReset, None).unwrap();
        assert!(state.lifecycle(Lifecycle::Stopping, "shutdown"));
        assert!(!state.complete(token, report(), None));
        assert!(state.begin(RecoveryCause::Retry, None).is_none());
        state.record_traffic(TrafficProofEvent {
            token,
            kind: TrafficKind::DirectUdp,
            bytes: 8,
            path_id: None,
            destination: None,
            outcome: TrafficOutcome::Response,
        });
        assert!(state.traffic_evidence.is_empty());
        assert!(state.lifecycle(Lifecycle::Stopped, "tasksJoined"));
        assert!(!state.lifecycle(Lifecycle::Running, "lateResult"));
    }
    #[test]
    fn component_task_failure_is_visible_and_degrades_application_health() {
        let mut state = running();
        assert!(state.set_component(
            RuntimeComponent::Dns,
            RuntimeComponentPhase::Failed,
            Some("DNS listener task exited unexpectedly".to_owned()),
        ));

        let value = serde_json::to_value(&state).unwrap();
        assert_eq!(value["application"]["health"], "degraded");
        let dns = value["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "dns")
            .unwrap();
        assert_eq!(dns["phase"], "failed");
        assert_eq!(dns["required"].as_bool(), Some(true));
        assert!(!state.set_component(
            RuntimeComponent::Dns,
            RuntimeComponentPhase::Failed,
            Some("DNS listener task exited unexpectedly".to_owned()),
        ));
    }

    fn test_health_path() -> crate::app::flow::NetworkPathId {
        crate::app::flow::NetworkPathId {
            interface: crate::app::flow::InterfaceId {
                name: "en0".to_string(),
                index: 4,
            },
            family: crate::app::flow::AddressFamily::Ipv4,
            source_address: Some("192.0.2.2".parse().unwrap()),
            network_generation: 0,
        }
    }

    fn health_event(
        token: OperationToken,
        path_id: crate::app::flow::NetworkPathId,
        destination: Option<crate::session::SocksAddr>,
        outcome: TrafficOutcome,
    ) -> TrafficProofEvent {
        TrafficProofEvent {
            token,
            kind: TrafficKind::DirectTcp,
            bytes: usize::from(outcome == TrafficOutcome::Response),
            path_id: Some(path_id),
            destination,
            outcome,
        }
    }

    #[test]
    fn one_destination_failure_does_not_mark_its_network_path_unavailable() {
        let mut state = running();
        let token = state.token();
        let path = test_health_path();
        let destination = "203.0.113.7:443".parse().unwrap();
        state.record_traffic(health_event(
            token,
            path,
            Some(crate::session::SocksAddr::Ip(destination)),
            TrafficOutcome::Failure(std::io::ErrorKind::ConnectionRefused),
        ));

        assert_eq!(state.path_health[0].state, HealthState::Unknown);
        assert_eq!(
            state.destination_path_health[0].state,
            HealthState::Unavailable
        );
        let value = serde_json::to_value(&state).unwrap();
        assert_eq!(value["pathHealth"][0]["state"], "unknown");
        assert_eq!(value["destinationPathHealth"][0]["state"], "unavailable");
        let serialized = value.to_string();
        assert!(!serialized.contains("203.0.113.7"));
    }

    #[test]
    fn distinct_network_failures_mark_path_unavailable_then_response_recovers_it() {
        let mut state = running();
        let token = state.token();
        let path = test_health_path();
        for octet in [1, 2, 3] {
            let destination = format!("203.0.113.{octet}:443").parse().unwrap();
            state.record_traffic(health_event(
                token,
                path.clone(),
                Some(crate::session::SocksAddr::Ip(destination)),
                TrafficOutcome::Failure(std::io::ErrorKind::NetworkUnreachable),
            ));
            if octet < 3 {
                assert_eq!(state.path_health[0].state, HealthState::Unknown);
            }
            if octet == 1 {
                let same_host_different_port = "203.0.113.1:80".parse().unwrap();
                state.record_traffic(health_event(
                    token,
                    path.clone(),
                    Some(crate::session::SocksAddr::Ip(same_host_different_port)),
                    TrafficOutcome::Failure(std::io::ErrorKind::NetworkUnreachable),
                ));
                assert_eq!(state.path_health[0].independent_failures, 1);
            }
        }
        assert_eq!(state.path_health[0].state, HealthState::Unavailable);

        let destination = "203.0.113.3:443".parse().unwrap();
        state.record_traffic(health_event(
            token,
            path.clone(),
            Some(crate::session::SocksAddr::Ip(destination)),
            TrafficOutcome::Response,
        ));
        assert_eq!(state.path_health[0].state, HealthState::Unavailable);
        assert_eq!(state.path_health[0].recovery_successes, 1);
        state.path_health[0].recovery_successes = 2;
        state.path_health[0].recovery_started =
            Some(Instant::now() - PATH_RECOVERY_STABILITY);
        state.record_traffic(health_event(
            token,
            path,
            Some(crate::session::SocksAddr::Ip(destination)),
            TrafficOutcome::Response,
        ));
        assert_eq!(state.path_health[0].state, HealthState::Available);
        let destination_health = state
            .destination_path_health
            .iter()
            .find(|health| health.last_success_at_ms.is_some())
            .expect("successful destination should be tracked");
        assert_eq!(destination_health.state, HealthState::Available);
    }

    #[test]
    fn path_cooldown_excludes_new_flows_then_allows_recovery_attempts() {
        let mut state = running();
        state.set_automatic_supported_for_test(true);
        state.path_candidates.push(PathCandidateObservation {
            interface: test_health_path().interface,
            interface_kind: crate::app::flow::InterfaceKind::Ethernet,
            family: crate::app::flow::AddressFamily::Ipv4,
            source_address: "192.0.2.2".parse().unwrap(),
            scope_id: None,
            gateway: None,
            default_route:
                super::super::network::DefaultRouteEvidence::PrimaryDefaultRoute,
            binding: super::super::network::BindingStatus::Verified,
            binding_error: None,
        });
        let token = state.token();
        let path = test_health_path();
        for octet in [1, 2, 3] {
            state.record_traffic(health_event(
                token,
                path.clone(),
                Some(crate::session::SocksAddr::Ip(
                    format!("203.0.113.{octet}:443").parse().unwrap(),
                )),
                TrafficOutcome::Failure(std::io::ErrorKind::NetworkUnreachable),
            ));
        }

        let (_, candidates, _, _) =
            state.path_planning_snapshot().expect("observer is enabled");
        assert_eq!(
            candidates[0].binding,
            super::super::network::BindingStatus::Failed
        );
        assert!(
            candidates[0]
                .binding_error
                .as_deref()
                .unwrap_or_default()
                .contains("cooldown")
        );

        state.path_health[0].cooldown_until =
            Some(Instant::now() - Duration::from_secs(1));
        let (_, candidates, _, _) =
            state.path_planning_snapshot().expect("observer is enabled");
        assert_eq!(
            candidates[0].binding,
            super::super::network::BindingStatus::Verified
        );
    }

    #[test]
    fn path_decisions_are_version_checked_bounded_and_expiring() {
        let mut state = running();
        let flow_id = uuid::Uuid::new_v4();
        let decision = crate::app::flow::PathDecisionRecord {
            flow_id,
            config_version: state.config_version,
            config_version_at_completion: None,
            policy_version: 3,
            network_version: state.network_version,
            operation_id: state.generation,
            outcome: crate::app::flow::PathExecutionOutcome::Connected,
            route: crate::app::flow::RouteDecision {
                outbound: "DIRECT".to_owned(),
                rule: None,
            },
            candidate_paths: vec![test_health_path()],
            selected_path: Some(test_health_path()),
            rejected: Vec::new(),
            failure_kind: None,
            reason: "connectedOnBoundPath".to_owned(),
            recorded_at_ms: now_ms(),
        };
        assert!(state.record_path_decision(decision.clone()));
        assert_eq!(state.path_decision(flow_id), Some(decision.clone()));
        assert_eq!(state.path_decisions_snapshot(), vec![decision.clone()]);
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["outcome"], "connected");
        assert_eq!(json["configVersion"], state.config_version);
        assert_eq!(json["operationId"], state.generation);

        let mut stale = decision;
        stale.flow_id = uuid::Uuid::new_v4();
        stale.network_version += 1;
        assert!(!state.record_path_decision(stale));

        state.path_decisions[0].recorded_at_ms =
            now_ms() - HEALTH_ENTRY_TTL.as_millis() as i64 - 1;
        assert!(state.path_decision(flow_id).is_none());
    }

    #[test]
    fn path_preference_update_is_atomic_and_temporary_expiry_restores_base() {
        let mut state = running();
        state.set_automatic_supported_for_test(true);
        use crate::app::flow::{AddressFamily, InterfaceKind, PathPriority};
        let base = vec![PathPriority {
            interface: InterfaceKind::Wifi,
            family: AddressFamily::Ipv4,
        }];
        let base_view = state.set_path_priority(base.clone(), None).unwrap();
        assert_eq!(base_view.policy_version, 1);
        assert_eq!(base_view.priority, base);

        let invalid = vec![
            PathPriority {
                interface: InterfaceKind::Ethernet,
                family: AddressFamily::Ipv4,
            },
            PathPriority {
                interface: InterfaceKind::Ethernet,
                family: AddressFamily::Ipv4,
            },
        ];
        assert!(state.set_path_priority(invalid, None).is_err());
        assert_eq!(state.policy_version, 1);

        let temporary = vec![PathPriority {
            interface: InterfaceKind::Ethernet,
            family: AddressFamily::Ipv6,
        }];
        let temporary_view = state
            .set_path_priority(temporary.clone(), Some(60_000))
            .unwrap();
        assert_eq!(temporary_view.policy_version, 2);
        assert_eq!(temporary_view.source, "temporaryOverride");
        assert_eq!(temporary_view.priority, temporary);
        assert!(temporary_view.expires_at_ms.is_some());

        state.temporary_path_priority.as_mut().unwrap().expires_at =
            Instant::now() - Duration::from_millis(1);
        let restored = state.path_preference_view();
        assert_eq!(restored.policy_version, 3);
        assert_eq!(restored.source, "runtime");
        assert_eq!(restored.priority, base);
    }

    #[test]
    fn stale_health_evidence_is_rejected_and_health_expires() {
        let mut state = running();
        let mut stale = state.token();
        stale.network_version += 1;
        state.record_traffic(health_event(
            stale,
            test_health_path(),
            Some(crate::session::SocksAddr::Ip(
                "203.0.113.9:443".parse().unwrap(),
            )),
            TrafficOutcome::Response,
        ));
        assert!(state.path_health.is_empty());
        assert_eq!(state.rejected_stale_results, 1);

        let token = state.token();
        let path = test_health_path();
        state.record_traffic(health_event(
            token,
            path,
            Some(crate::session::SocksAddr::Ip(
                "203.0.113.9:443".parse().unwrap(),
            )),
            TrafficOutcome::Response,
        ));
        state.path_health[0].last_updated = Instant::now() - HEALTH_ENTRY_TTL;
        state.destination_path_health[0].last_updated =
            Instant::now() - HEALTH_ENTRY_TTL;
        state.expire_health();
        assert!(state.path_health.is_empty());
        assert!(state.destination_path_health.is_empty());
    }

    #[test]
    fn health_tables_evict_old_entries_at_their_capacity() {
        let mut state = running();
        let token = state.token();
        for index in 0..=PATH_HEALTH_LIMIT {
            let mut path = test_health_path();
            path.interface.index = index as u32 + 1;
            let destination = std::net::SocketAddr::new(
                "203.0.113.7".parse().unwrap(),
                40000 + index as u16,
            );
            state.record_traffic(health_event(
                token,
                path,
                Some(crate::session::SocksAddr::Ip(destination)),
                TrafficOutcome::Response,
            ));
        }

        assert_eq!(state.path_health.len(), PATH_HEALTH_LIMIT);
        assert_eq!(state.destination_path_health.len(), PATH_HEALTH_LIMIT);
    }

    #[tokio::test]
    async fn proof_is_captured_before_dial_and_reported_once() {
        let mut state = running();
        let (tx, mut rx) = mpsc::channel(2);
        let reporter = state.traffic_reporter(tx);
        let old = reporter.capture(TrafficKind::DirectUdp);
        let token = state.begin(RecoveryCause::ManualReset, None).unwrap();
        assert!(state.complete(token, report(), None));
        old.received(8);
        state.record_traffic(rx.recv().await.unwrap());
        assert_eq!(state.phase, NetworkPhase::AwaitingTraffic);
        let new = reporter.capture(TrafficKind::DirectUdp);
        new.received(0);
        assert!(rx.try_recv().is_err());
        new.received(8);
        new.clone().received(16);
        state.record_traffic(rx.recv().await.unwrap());
        assert_eq!(state.phase, NetworkPhase::TrafficVerified);
        assert_eq!(state.traffic_evidence[0].received_bytes, 8);
        assert!(rx.try_recv().is_err());
    }
    #[tokio::test]
    async fn scoped_path_proof_reports_failure_once() {
        let mut state = running();
        let (tx, mut rx) = mpsc::channel(2);
        let reporter = state.traffic_reporter(tx);
        let proof = reporter.capture_scoped(
            TrafficKind::DirectTcp,
            Some(test_health_path()),
            Some("203.0.113.4:443".parse().unwrap()),
        );
        proof.failed(std::io::ErrorKind::NetworkUnreachable);
        proof.failed(std::io::ErrorKind::TimedOut);
        state.record_traffic(rx.recv().await.unwrap());

        assert_eq!(state.path_health[0].state, HealthState::Unknown);
        assert_eq!(state.path_health[0].independent_failures, 1);
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn transition_history_and_evidence_queue_are_bounded() {
        let mut state = running();
        for _ in 0..40 {
            let token = state.begin(RecoveryCause::ManualReset, None).unwrap();
            state.complete(token, report(), None);
        }
        assert_eq!(state.transitions.len(), HISTORY_LIMIT);
        let (tx, _rx) = mpsc::channel(1);
        let reporter = state.traffic_reporter(tx);
        reporter.capture(TrafficKind::DirectTcp).received(1);
        reporter.capture(TrafficKind::ProxyTcp).received(1);
        assert_eq!(state.dropped_evidence.load(Ordering::Relaxed), 1);
    }
}
