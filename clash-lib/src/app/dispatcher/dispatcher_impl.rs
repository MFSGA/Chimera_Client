use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, sync::RwLock, task::JoinHandle};
use tracing::{Instrument, debug, error, info_span, instrument, trace, warn};

use crate::{
    app::{
        dispatcher::{
            TrackedStream,
            statistics_manager::{FlowEndReason, StatisticsManager, TrackerInfo},
            tracked::TrackedDatagram,
        },
        dns::{ClashResolver, ThreadSafeDNSResolver},
        outbound::manager::ThreadSafeOutboundManager,
        path_policy::compile_path_plan,
        router::ThreadSafeRouter,
    },
    common::io::ShutdownMode,
    config::{
        def::RunMode,
        internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL},
    },
    proxy::{
        AnyInboundDatagram, ClientStream, OutboundType, datagram::UdpPacket,
        utils::ToCanonical,
    },
    session::{Session, SocksAddr, find_process_name},
};

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). A smaller
// relay buffer forces full packets into multiple encrypted chunks and increases
// encrypt/decrypt overhead.
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;
const UDP_SESSION_IDLE: Duration = Duration::from_secs(10);
const UDP_FLOW_DECISION_MAX: usize = 1024;
const UDP_HEALTH_PROOF_MAX: usize = 256;

#[derive(Clone, Debug)]
struct DirectPathPlanningError {
    kind: std::io::ErrorKind,
    message: String,
    policy_generation: u64,
    network_generation: u64,
    candidate_paths: Vec<crate::app::flow::NetworkPathId>,
    rejected: Vec<crate::app::flow::CandidateRejection>,
}

impl DirectPathPlanningError {
    fn kind(&self) -> std::io::ErrorKind {
        self.kind
    }
}

impl std::fmt::Display for DirectPathPlanningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DirectPathPlanningError {}

/// Preserve the rule's requested outbound separately from the actual handler.
/// Missing targets retain the existing compatibility fallback to DIRECT; lookup
/// errors are never treated as missing targets.
struct SelectedOutbound<H> {
    handler: H,
    effective_name: String,
    used_direct_fallback: bool,
}

async fn select_outbound_with_direct_fallback<H, F, Fut>(
    requested_name: &str,
    mut lookup: F,
) -> std::io::Result<Option<SelectedOutbound<H>>>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<Option<H>>>,
{
    if let Some(handler) = lookup(requested_name.to_owned()).await? {
        return Ok(Some(SelectedOutbound {
            handler,
            effective_name: requested_name.to_owned(),
            used_direct_fallback: false,
        }));
    }

    Ok(lookup(PROXY_DIRECT.to_owned())
        .await?
        .map(|handler| SelectedOutbound {
            handler,
            effective_name: PROXY_DIRECT.to_owned(),
            used_direct_fallback: true,
        }))
}

async fn explain_versions_from_status(
    status: Option<&Arc<RwLock<crate::app::network::NetworkStatus>>>,
    fallback_network_version: u64,
) -> (u64, u64, u64, u64) {
    match status {
        Some(status) => status.read().await.decision_versions(),
        None => (0, 0, fallback_network_version, 0),
    }
}

async fn udp_path_cache_versions(
    status: Option<&Arc<RwLock<crate::app::network::NetworkStatus>>>,
    fallback_network_version: u64,
) -> (u64, u64) {
    match status {
        Some(status) => status
            .write()
            .await
            .path_cache_versions()
            .unwrap_or((fallback_network_version, 0)),
        None => (fallback_network_version, 0),
    }
}

async fn udp_path_selection_is_current(
    status: Option<&Arc<RwLock<crate::app::network::NetworkStatus>>>,
    selection: &crate::app::flow::DirectPathSelection,
) -> bool {
    let Some(status) = status else {
        return false;
    };
    status.write().await.path_cache_versions()
        == Some((selection.network_generation, selection.policy_generation))
}

async fn store_path_decision(
    status: Option<&Arc<RwLock<crate::app::network::NetworkStatus>>>,
    decision: crate::app::flow::PathDecisionRecord,
) {
    if let Some(status) = status {
        let _ = status.write().await.record_path_decision(decision);
    }
}

fn confirmed_udp_path(
    planned: Option<&crate::app::flow::NetworkPathId>,
    observed: Option<&crate::app::flow::NetworkPathId>,
) -> Option<crate::app::flow::NetworkPathId> {
    observed.filter(|actual| Some(*actual) == planned).cloned()
}

fn classify_flow_end_reason(
    result: &Result<
        crate::common::io::BidirectionalCopyReport,
        crate::common::io::CopyBidirectionalError,
    >,
    network_changed: bool,
) -> FlowEndReason {
    match result {
        Ok(report) if report.idle_timeout => FlowEndReason::IdleTimeout,
        Ok(_) => FlowEndReason::Completed,
        Err(
            crate::common::io::CopyBidirectionalError::LeftClosed(error)
            | crate::common::io::CopyBidirectionalError::RightClosed(error)
            | crate::common::io::CopyBidirectionalError::Other(error),
        ) if error.kind() == std::io::ErrorKind::TimedOut => {
            FlowEndReason::IdleTimeout
        }
        Err(_) if network_changed => FlowEndReason::NetworkChanged,
        Err(crate::common::io::CopyBidirectionalError::LeftClosed(_)) => {
            FlowEndReason::InboundClosed
        }
        Err(crate::common::io::CopyBidirectionalError::RightClosed(_)) => {
            FlowEndReason::OutboundClosed
        }
        Err(crate::common::io::CopyBidirectionalError::Other(_)) => {
            FlowEndReason::IoError
        }
    }
}

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    resolver: ThreadSafeDNSResolver,
    manager: Arc<StatisticsManager>,
    tcp_buffer_size: usize,
    proxy_resolve_local: bool,
    mode: Arc<RwLock<RunMode>>,
    router: ThreadSafeRouter,
    network_generation: Arc<AtomicU64>,
    traffic_reporter: OnceLock<crate::app::runtime_state::TrafficReporter>,
    network_status: OnceLock<Arc<RwLock<crate::app::network::NetworkStatus>>>,
}

impl Debug for Dispatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish()
    }
}

impl Dispatcher {
    async fn explain_versions(&self) -> (u64, u64, u64, u64) {
        explain_versions_from_status(self.network_status.get(), 0).await
    }

    async fn record_path_decision(
        &self,
        decision: crate::app::flow::PathDecisionRecord,
    ) {
        store_path_decision(self.network_status.get(), decision).await;
    }

    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ThreadSafeRouter,
        resolver: ThreadSafeDNSResolver,
        mode: RunMode,
        statistics_manager: Arc<StatisticsManager>,
        tcp_buffer_size: Option<usize>,
        proxy_resolve_local: bool,
    ) -> Self {
        Self {
            outbound_manager,
            resolver,
            manager: statistics_manager,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            proxy_resolve_local,
            mode: Arc::new(RwLock::new(mode)),
            router,
            network_generation: Arc::new(AtomicU64::new(0)),
            traffic_reporter: OnceLock::new(),
            network_status: OnceLock::new(),
        }
    }

    pub(crate) fn attach_traffic_reporter(
        &self,
        reporter: crate::app::runtime_state::TrafficReporter,
    ) {
        let _ = self.traffic_reporter.set(reporter);
    }

    pub(crate) fn attach_network_status(
        &self,
        status: Arc<RwLock<crate::app::network::NetworkStatus>>,
    ) {
        let _ = self.network_status.set(status);
    }

    async fn plan_direct_path(
        &self,
        outbound_name: &str,
        rule: Option<&dyn crate::app::router::RuleMatcher>,
        connect_sess: &Session,
    ) -> Result<
        Option<(crate::app::flow::DirectPathSelection, u64)>,
        DirectPathPlanningError,
    > {
        let endpoint_family = if outbound_name == PROXY_DIRECT {
            match &connect_sess.destination {
                SocksAddr::Ip(address) => {
                    Some(crate::app::flow::AddressFamily::from(address.ip()))
                }
                SocksAddr::Domain(_, _) => None,
            }
        } else {
            None
        };
        Self::plan_direct_path_with_status(
            self.network_status.get().cloned(),
            outbound_name,
            rule,
            connect_sess,
            endpoint_family,
        )
        .await
    }

    async fn plan_direct_path_with_status(
        network_status: Option<Arc<RwLock<crate::app::network::NetworkStatus>>>,
        outbound_name: &str,
        rule: Option<&dyn crate::app::router::RuleMatcher>,
        connect_sess: &Session,
        endpoint_family: Option<crate::app::flow::AddressFamily>,
    ) -> Result<
        Option<(crate::app::flow::DirectPathSelection, u64)>,
        DirectPathPlanningError,
    > {
        if outbound_name == PROXY_DIRECT
            && connect_sess.iface.is_none()
            && matches!(
                &connect_sess.destination,
                SocksAddr::Ip(address)
                    if address.ip().is_loopback()
                        || address.ip().is_unspecified()
                        || address.ip().is_multicast()
            )
        {
            // Local and group destinations do not traverse an observed
            // physical default path. Preserve the system-managed socket path.
            return Ok(None);
        }
        let Some(status) = network_status.as_ref() else {
            return Ok(None);
        };
        let observation = status.write().await.path_planning_snapshot();
        let Some((network_generation, observations, tun_enabled, mut intent)) =
            observation
        else {
            return Ok(None);
        };

        let route = crate::app::flow::RouteDecision {
            outbound: outbound_name.to_string(),
            rule: rule.map(|matcher| rule_summary(Some(matcher))),
        };
        let requires_interface = connect_sess.iface.is_some();
        let explicit_interface =
            connect_sess
                .iface
                .as_ref()
                .map(|iface| crate::app::flow::PathIntent {
                    strength: crate::app::flow::IntentStrength::Require,
                    target: crate::app::flow::PathTarget::Interface(
                        crate::app::flow::InterfaceId {
                            name: iface.name.clone(),
                            index: iface.index,
                        },
                    ),
                });
        intent.intents.extend(explicit_interface);
        let result = compile_path_plan(
            &observations,
            &intent,
            network_generation,
            route.clone(),
            endpoint_family,
        );
        let can_apply = outbound_name == PROXY_DIRECT && !tun_enabled;
        let mut selection = crate::app::flow::DirectPathSelection {
            policy_generation: intent.policy_generation,
            network_generation,
            required: requires_interface,
            ..Default::default()
        };
        let mut family_decisions = Vec::new();
        if can_apply {
            for family in [
                crate::app::flow::AddressFamily::Ipv4,
                crate::app::flow::AddressFamily::Ipv6,
            ] {
                if endpoint_family.is_some_and(|known| known != family) {
                    continue;
                }
                let family_result = compile_path_plan(
                    &observations,
                    &intent,
                    network_generation,
                    route.clone(),
                    Some(family),
                );
                let selected_path = family_result
                    .decision
                    .selected
                    .as_ref()
                    .and_then(|selected| {
                        family_result
                            .plan
                            .candidates
                            .iter()
                            .find(|candidate| &candidate.id == selected)
                            .cloned()
                    });
                let mut candidates = family_result.plan.candidates;
                if let Some(selected) = selected_path.as_ref() {
                    candidates.sort_by_key(|candidate| candidate.id != selected.id);
                }
                if let Some(path) = selected_path.as_ref() {
                    match family {
                        crate::app::flow::AddressFamily::Ipv4 => {
                            selection.ipv4 = Some(path.clone());
                            selection.ipv4_candidates = candidates;
                        }
                        crate::app::flow::AddressFamily::Ipv6 => {
                            selection.ipv6 = Some(path.clone());
                            selection.ipv6_candidates = candidates;
                        }
                    }
                } else if !candidates.is_empty() {
                    match family {
                        crate::app::flow::AddressFamily::Ipv4 => {
                            selection.ipv4_candidates = candidates;
                        }
                        crate::app::flow::AddressFamily::Ipv6 => {
                            selection.ipv6_candidates = candidates;
                        }
                    }
                }
                selection
                    .rejected
                    .extend(family_result.decision.rejected.iter().cloned());
                family_decisions.push((
                    family,
                    family_result.decision.reason,
                    selected_path.map(|path| path.id),
                    family_result.decision.rejected,
                ));
            }
        }
        let has_selected_path = selection.ipv4.is_some() || selection.ipv6.is_some();
        let has_candidate_path = !selection.ipv4_candidates.is_empty()
            || !selection.ipv6_candidates.is_empty()
            || has_selected_path;
        let execution = if has_candidate_path {
            "directSocketPathApplied"
        } else {
            "shadowOnly"
        };
        debug!(
            outbound = outbound_name,
            rule = ?result.plan.route.rule,
            policy_generation = result.plan.policy_generation,
            network_generation = result.plan.network_generation,
            endpoint_family = ?endpoint_family,
            eligible_candidates = result.plan.candidates.len(),
            selected_path = ?result.decision.selected,
            selection_reason = ?result.decision.reason,
            rejected_candidates = ?result.decision.rejected,
            family_decisions = ?family_decisions,
            execution,
            "compiled network path plan"
        );
        if can_apply && !has_candidate_path && requires_interface {
            let rejected = family_decisions
                .iter()
                .flat_map(|(_, _, _, rejected)| rejected.iter().cloned())
                .collect::<Vec<_>>();
            let mut candidate_paths = rejected
                .iter()
                .map(|rejection| rejection.path.clone())
                .collect::<Vec<_>>();
            candidate_paths.dedup();
            return Err(DirectPathPlanningError {
                kind: std::io::ErrorKind::NetworkUnreachable,
                message: format!(
                    "required outbound interface is unavailable for the resolved destination family: {family_decisions:?}"
                ),
                policy_generation: intent.policy_generation,
                network_generation,
                candidate_paths,
                rejected,
            });
        }
        Ok(has_candidate_path.then_some((selection, network_generation)))
    }

    pub fn tcp_buffer_size(&self) -> usize {
        self.tcp_buffer_size
    }

    /// Retire reusable UDP sockets bound to a previous network.
    pub(crate) fn invalidate_network_sessions(&self) {
        self.network_generation.fetch_add(1, Ordering::AcqRel);
    }

    pub fn resolver(&self) -> ThreadSafeDNSResolver {
        self.resolver.clone()
    }

    fn resolver_for_outbound(
        resolver: &ThreadSafeDNSResolver,
        outbound_name: &str,
    ) -> ThreadSafeDNSResolver {
        if outbound_name == PROXY_DIRECT {
            resolver
                .direct_resolver()
                .unwrap_or_else(|| resolver.clone())
        } else {
            resolver.clone()
        }
    }

    async fn maybe_resolve_proxy_destination_locally(
        resolver: &ThreadSafeDNSResolver,
        enabled: bool,
        outbound_name: &str,
        sess: &mut Session,
    ) {
        if !enabled || outbound_name == PROXY_DIRECT {
            return;
        }

        let (host, port) = match &sess.destination {
            SocksAddr::Domain(host, port) => (host.clone(), *port),
            SocksAddr::Ip(_) => return,
        };

        let mut resolved = sess.resolved_ip;
        if let Some(ip) = resolved
            && resolver.fake_ip_enabled()
            && resolver.is_fake_ip(ip).await
        {
            resolved = None;
        }

        if resolved.is_none() {
            let lookup_resolver = resolver
                .direct_resolver()
                .unwrap_or_else(|| resolver.clone());
            match lookup_resolver.resolve(&host, false).await {
                Ok(ip) => resolved = ip,
                Err(error) => {
                    debug!(
                        outbound_name,
                        host = %host,
                        error = %error,
                        "local proxy destination resolution failed; keeping domain target"
                    );
                    return;
                }
            }
        }

        let Some(ip) = resolved else {
            debug!(
                outbound_name,
                host = %host,
                "local proxy destination resolution returned no address; keeping domain target"
            );
            return;
        };

        if resolver.fake_ip_enabled() && resolver.is_fake_ip(ip).await {
            warn!(
                outbound_name,
                host = %host,
                ip = %ip,
                "local proxy destination resolution returned a fake IP; keeping domain target"
            );
            return;
        }

        sess.resolved_ip = Some(ip);
        sess.destination = SocksAddr::Ip(SocketAddr::new(ip, port));
        debug!(
            outbound_name,
            host = %host,
            ip = %ip,
            "resolved proxy destination locally"
        );
    }

    pub fn statistics_manager(&self) -> Arc<StatisticsManager> {
        self.manager.clone()
    }

    pub async fn get_mode(&self) -> RunMode {
        *self.mode.read().await
    }

    pub async fn set_mode(&self, mode: RunMode) {
        *self.mode.write().await = mode;
    }

    #[instrument(skip(self, sess, lhs))]
    pub async fn dispatch_stream(
        &self,
        mut sess: Session,
        mut lhs: Box<dyn ClientStream>,
    ) {
        let inbound_destination = sess.destination.clone();
        let dest: SocksAddr = match reverse_lookup(&self.resolver, &sess.destination)
            .await
        {
            Some(dest) => dest,
            None => {
                warn!(
                    "dropping flow with fake-IP destination because its domain mapping is missing: {}",
                    sess
                );
                return;
            }
        };

        sess.destination = dest.clone();
        if sess.process_name.is_none() {
            sess.process_name = find_process_name(
                sess.source,
                dest.clone().try_into_socket_addr(),
                sess.network,
            );
        }

        let mode = *self.mode.read().await;
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&mut sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
        };

        let rule_summary = rule_summary(rule.map(Box::as_ref));
        let explain_flow_id = uuid::Uuid::new_v4();
        let explain_versions_at_start = self.explain_versions().await;
        let explain_route = crate::app::flow::RouteDecision {
            outbound: outbound_name.to_owned(),
            rule: Some(rule_summary.clone()),
        };
        debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

        let mgr = self.outbound_manager.clone();
        let selected = match select_outbound_with_direct_fallback(
            outbound_name,
            |name| {
                let mgr = mgr.clone();
                async move { mgr.get_outbound_for_new_flow(&name).await }
            },
        )
        .await
        {
            Ok(Some(selected)) => selected,
            Ok(None) => {
                warn!(
                    requested_outbound = outbound_name,
                    "DIRECT outbound is unavailable; closing flow"
                );
                let _ = lhs.shutdown().await;
                return;
            }
            Err(error) => {
                warn!(requested_outbound = outbound_name, error = %error, "could not select outbound; closing flow");
                let _ = lhs.shutdown().await;
                return;
            }
        };
        if selected.used_direct_fallback {
            debug!(
                requested_outbound = outbound_name,
                "unknown outbound; falling back to DIRECT"
            );
        }
        let is_dynamic_group = matches!(
            selected.handler.proto(),
            OutboundType::Selector
                | OutboundType::Fallback
                | OutboundType::UrlTest
                | OutboundType::LoadBalance
        );
        let pinned = match crate::proxy::group::selector::PinnedOutbound::capture(
            selected.handler,
            &sess,
        )
        .await
        {
            Ok(pinned) => pinned,
            Err(error) => {
                warn!(requested_outbound = outbound_name, error = %error, "could not capture selector's outbound; closing flow");
                let _ = lhs.shutdown().await;
                return;
            }
        };
        // No failed child pool may be reused even if another group member is healthy.
        if let Err(error) = mgr
            .ensure_outbound_ready_for_new_flow(&pinned.handler)
            .await
        {
            warn!(requested_outbound = outbound_name, actual_outbound = pinned.handler.name(), error = %error, "outbound pool is not safe for new TCP flow");
            let _ = lhs.shutdown().await;
            return;
        }
        // Use this same pinned child for both path planning and the actual dial.
        let physical_outbound_name = if is_dynamic_group {
            pinned.handler.name().to_owned()
        } else {
            selected.effective_name
        };
        let outbound_name = physical_outbound_name.as_str();

        let connect_resolver =
            Self::resolver_for_outbound(&self.resolver, outbound_name);
        let mut connect_sess = sess.clone();
        Self::maybe_resolve_proxy_destination_locally(
            &self.resolver,
            self.proxy_resolve_local,
            outbound_name,
            &mut connect_sess,
        )
        .await;

        let selected_path = match self
            .plan_direct_path(
                outbound_name,
                rule.as_ref().map(|matcher| matcher.as_ref()),
                &connect_sess,
            )
            .await
        {
            Ok(path) => path,
            Err(err) => {
                let current_versions = self.explain_versions().await;
                self.record_path_decision(crate::app::flow::PathDecisionRecord {
                    flow_id: explain_flow_id,
                    config_version: explain_versions_at_start.0,
                    config_version_at_completion: (current_versions.0
                        != explain_versions_at_start.0)
                        .then_some(current_versions.0),
                    policy_version: err.policy_generation,
                    network_version: current_versions.2,
                    operation_id: explain_versions_at_start.3,
                    outcome: if current_versions.2 != err.network_generation {
                        crate::app::flow::PathExecutionOutcome::StaleNetworkDiscarded
                    } else {
                        crate::app::flow::PathExecutionOutcome::PathPlanningFailed
                    },
                    route: explain_route.clone(),
                    candidate_paths: err.candidate_paths.clone(),
                    selected_path: None,
                    rejected: err.rejected.clone(),
                    failure_kind: Some(err.kind().to_string()),
                    reason: if current_versions.2 != err.network_generation {
                        "networkChangedDuringPathPlanning".to_owned()
                    } else {
                        err.to_string()
                    },
                    recorded_at_ms: chrono::Utc::now().timestamp_millis(),
                })
                .await;
                warn!(
                    outbound_name,
                    destination = %connect_sess.destination,
                    error = %err,
                    "required network path is unavailable"
                );
                if let Err(close_error) = lhs.shutdown().await {
                    warn!("error closing local connection {}: {}", sess, close_error)
                }
                return;
            }
        };

        let mut traffic_proof = self.traffic_reporter.get().map(|reporter| {
            let kind = if outbound_name == PROXY_DIRECT {
                crate::app::runtime_state::TrafficKind::DirectTcp
            } else {
                crate::app::runtime_state::TrafficKind::ProxyTcp
            };
            let health_path = match &connect_sess.destination {
                SocksAddr::Ip(address) => {
                    selected_path.as_ref().and_then(|(selection, _)| {
                        let candidates = selection.candidates_for_family(
                            crate::app::flow::AddressFamily::from(address.ip()),
                        );
                        (candidates.len() == 1).then(|| candidates[0].id.clone())
                    })
                }
                SocksAddr::Domain(_, _) => None,
            };
            match health_path {
                Some(path_id) => reporter.capture_scoped(
                    kind,
                    Some(path_id),
                    Some(connect_sess.destination.clone()),
                ),
                None => reporter.capture(kind),
            }
        });
        let mut executed_path_id = None;
        let connect_result = if let Some((selection, _)) = &selected_path {
            match pinned
                .handler
                .connect_stream_with_path_selection_result(
                    &connect_sess,
                    connect_resolver,
                    selection,
                )
                .instrument(info_span!(
                    "connect_stream",
                    outbound_name = outbound_name,
                ))
                .await
            {
                Ok((stream, path_id)) => {
                    executed_path_id = path_id;
                    Ok(stream)
                }
                Err(error) => Err(error),
            }
        } else {
            pinned
                .handler
                .connect_stream(&connect_sess, connect_resolver)
                .instrument(info_span!(
                    "connect_stream",
                    outbound_name = outbound_name,
                ))
                .await
        };
        if connect_result.is_ok()
            && selected_path.is_some()
            && let Some(proof) = traffic_proof.as_mut()
        {
            proof.set_path_id(executed_path_id.clone());
        }
        match connect_result {
            Ok(mut rhs) => {
                pinned.append_stream_chain(&rhs).await;
                let observed_path_ids = rhs.network_path_ids();
                let opened_network_generation = observed_path_ids
                    .first()
                    .map(|path| path.network_generation)
                    .or_else(|| {
                        selected_path.as_ref().map(|(_, generation)| *generation)
                    });
                let current_versions = self.explain_versions().await;
                if opened_network_generation
                    .is_some_and(|generation| generation != current_versions.2)
                {
                    let _ = rhs.shutdown().await;
                    if let Err(close_error) = lhs.shutdown().await {
                        warn!(
                            "error closing stale local connection {}: {}",
                            sess, close_error
                        )
                    }
                    self.record_path_decision(
                        crate::app::flow::PathDecisionRecord {
                            flow_id: explain_flow_id,
                            config_version: explain_versions_at_start.0,
                            config_version_at_completion:
                                (current_versions.0 != explain_versions_at_start.0)
                                    .then_some(current_versions.0),
                            policy_version: selected_path
                                .as_ref()
                                .map_or(explain_versions_at_start.1, |(selection, _)| {
                                    selection.policy_generation
                                }),
                            network_version: current_versions.2,
                            operation_id: explain_versions_at_start.3,
                            outcome: crate::app::flow::PathExecutionOutcome::StaleNetworkDiscarded,
                            route: explain_route.clone(),
                            candidate_paths: Vec::new(),
                            selected_path: None,
                            rejected: Vec::new(),
                            failure_kind: None,
                            reason: "networkChangedDuringDial".to_owned(),
                            recorded_at_ms: chrono::Utc::now().timestamp_millis(),
                        },
                    )
                    .await;
                    warn!(
                        outbound_name,
                        opened_network_generation = ?opened_network_generation,
                        current_network_generation = current_versions.2,
                        destination = %connect_sess.destination,
                        "discarded connection completed on a stale network path"
                    );
                    return;
                }
                debug!(
                    outbound_name,
                    rule = %rule_summary,
                    mode = %mode,
                    source = %sess.source,
                    destination = %sess.destination,
                    "remote connection established"
                );
                let connection_network_generation = opened_network_generation
                    .or_else(|| {
                        self.network_status.get().map(|_| current_versions.2)
                    });
                let rhs = TrackedStream::new_with_inbound_destination_and_id(
                    rhs,
                    self.manager.clone(),
                    sess.clone(),
                    inbound_destination,
                    rule.map(|matcher| matcher.as_ref()),
                    explain_flow_id,
                )
                .await
                .with_network_generation(connection_network_generation);
                let tracker_info = rhs.tracker_info();
                let mut candidate_paths = selected_path
                    .as_ref()
                    .map(|(selection, _)| {
                        selection
                            .ipv4_candidates
                            .iter()
                            .chain(selection.ipv6_candidates.iter())
                            .map(|path| path.id.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                candidate_paths.dedup();
                let selected_explain_path = executed_path_id
                    .clone()
                    .or_else(|| tracker_info.network_paths.first().cloned());
                let policy_version = selected_path
                    .as_ref()
                    .map_or(explain_versions_at_start.1, |(selection, _)| {
                        selection.policy_generation
                    });
                let network_version =
                    opened_network_generation.unwrap_or(current_versions.2);
                let reason = if executed_path_id.is_some() {
                    "connectedOnBoundPath"
                } else if selected_explain_path.is_some() {
                    "connectedOnObservedPath"
                } else if selected_path.is_some() {
                    "connectedUsingSystemRouteFallback"
                } else if outbound_name == PROXY_DIRECT {
                    "connectedUsingSystemRoute"
                } else {
                    "connectedPathUnknown"
                };
                self.record_path_decision(crate::app::flow::PathDecisionRecord {
                    flow_id: rhs.id(),
                    config_version: explain_versions_at_start.0,
                    config_version_at_completion: (current_versions.0
                        != explain_versions_at_start.0)
                        .then_some(current_versions.0),
                    policy_version,
                    network_version,
                    operation_id: explain_versions_at_start.3,
                    outcome: crate::app::flow::PathExecutionOutcome::Connected,
                    route: explain_route.clone(),
                    candidate_paths,
                    selected_path: selected_explain_path,
                    rejected: selected_path
                        .as_ref()
                        .map(|(selection, _)| selection.rejected.clone())
                        .unwrap_or_default(),
                    failure_kind: None,
                    reason: reason.to_owned(),
                    recorded_at_ms: chrono::Utc::now().timestamp_millis(),
                })
                .await;
                let flow_tracker = rhs.tracker_info();
                let flow_network_generation = rhs.network_generation();
                let mut rhs = rhs.with_traffic_proof(traffic_proof);
                let shutdown_mode = if sess.typ == crate::session::Type::HttpConnect
                {
                    ShutdownMode::FlushOnly
                } else {
                    ShutdownMode::HalfClose
                };
                let copy_result = crate::common::io::copy_bidirectional_with_report(
                    lhs,
                    &mut rhs,
                    self.tcp_buffer_size,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                    shutdown_mode,
                )
                .instrument(info_span!(
                    "copy_bidirectional",
                    outbound_name = outbound_name,
                ))
                .await;
                if flow_tracker.end_reason() == FlowEndReason::Unknown {
                    let network_changed = if copy_result.is_err()
                        && let Some(opened_generation) = flow_network_generation
                        && let Some(status) = self.network_status.get()
                    {
                        status.read().await.shadow_path_snapshot().is_some_and(
                            |(generation, _, _)| generation != opened_generation,
                        )
                    } else {
                        false
                    };
                    // The flow could not be resumed at the transport layer.
                    // A concurrent network-generation change is useful
                    // diagnostic evidence, not proof of sole causality.
                    flow_tracker.set_end_reason(classify_flow_end_reason(
                        &copy_result,
                        network_changed,
                    ));
                }
                match copy_result {
                    Ok(report) => {
                        debug!(
                            "connection {} closed with {} bytes up, {} bytes down",
                            sess, report.uploaded, report.downloaded
                        );
                    }
                    Err(err) => match err {
                        crate::common::io::CopyBidirectionalError::LeftClosed(
                            err,
                        ) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!(
                                    "connection {} closed with error {} by local",
                                    sess, err
                                );
                            }
                            _ => {
                                warn!(
                                    "connection {} closed with error {} by local",
                                    sess, err
                                );
                            }
                        },
                        crate::common::io::CopyBidirectionalError::RightClosed(
                            err,
                        ) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!(
                                    "connection {} closed with error {} by remote",
                                    sess, err
                                );
                            }
                            _ => {
                                warn!(
                                    "connection {} closed with error {} by remote",
                                    sess, err
                                );
                            }
                        },
                        crate::common::io::CopyBidirectionalError::Other(err) => {
                            match err.kind() {
                                std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::BrokenPipe => {
                                    debug!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                                _ => {
                                    warn!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                            }
                        }
                    },
                }
            }
            Err(err) => {
                if let Some(proof) = &traffic_proof {
                    proof.failed(err.kind());
                }
                let current_versions = self.explain_versions().await;
                let proxy_endpoint_error = err.get_ref().and_then(|source| {
                    source.downcast_ref::<
                            crate::proxy::utils::ProxyEndpointConnectError,
                        >()
                });
                let mut candidate_paths = selected_path
                    .as_ref()
                    .map(|(selection, generation)| {
                        if *generation == current_versions.2 {
                            selection
                                .ipv4_candidates
                                .iter()
                                .chain(selection.ipv6_candidates.iter())
                                .map(|path| path.id.clone())
                                .collect::<Vec<_>>()
                        } else {
                            Vec::new()
                        }
                    })
                    .unwrap_or_default();
                if let Some(failure) = proxy_endpoint_error {
                    candidate_paths
                        .extend(failure.candidate_paths().iter().cloned());
                }
                candidate_paths.dedup();
                let mut rejected = selected_path
                    .as_ref()
                    .map(|(selection, _)| selection.rejected.clone())
                    .unwrap_or_default();
                if let Some(failure) = proxy_endpoint_error {
                    rejected.extend(failure.rejected().iter().cloned());
                    rejected.dedup_by(|left, right| left == right);
                }
                let stale_network =
                    current_versions.2 != explain_versions_at_start.2;
                let reason = if outbound_name == PROXY_DIRECT {
                    "directDialFailed".to_owned()
                } else if let Some(failure) = proxy_endpoint_error {
                    format!(
                        "proxyEndpointDialFailed; attemptedPaths={:?}; {err}",
                        failure.attempted_paths(),
                    )
                } else {
                    "proxyDialFailedPathUnknown".to_owned()
                };
                self.record_path_decision(crate::app::flow::PathDecisionRecord {
                    flow_id: explain_flow_id,
                    config_version: explain_versions_at_start.0,
                    config_version_at_completion: (current_versions.0
                        != explain_versions_at_start.0)
                        .then_some(current_versions.0),
                    policy_version: selected_path
                        .as_ref()
                        .map_or(explain_versions_at_start.1, |(selection, _)| {
                            selection.policy_generation
                        }),
                    network_version: current_versions.2,
                    operation_id: explain_versions_at_start.3,
                    outcome: if stale_network {
                        crate::app::flow::PathExecutionOutcome::StaleNetworkDiscarded
                    } else {
                        crate::app::flow::PathExecutionOutcome::DialFailed
                    },
                    route: explain_route,
                    candidate_paths,
                    selected_path: None,
                    rejected,
                    failure_kind: Some(err.kind().to_string()),
                    reason: if stale_network {
                        format!("networkChangedDuringDial; {reason}")
                    } else {
                        reason
                    },
                    recorded_at_ms: chrono::Utc::now().timestamp_millis(),
                })
                .await;
                warn!(
                    outbound_name,
                    rule = %rule_summary,
                    mode = %mode,
                    source = %sess.source,
                    destination = %sess.destination,
                    error = %err,
                    "failed to establish remote connection"
                );
                if let Err(e) = lhs.shutdown().await {
                    warn!("error closing local connection {}: {}", sess, e)
                }
            }
        }
    }

    /// Dispatch a UDP packet to outbound handler
    /// returns the close sender
    #[instrument]
    #[must_use]
    pub async fn dispatch_datagram(
        &self,
        sess: Session,
        udp_inbound: AnyInboundDatagram,
    ) -> tokio::sync::oneshot::Sender<u8> {
        let outbound_handle_guard =
            TimeoutUdpSessionManager::new(self.network_generation.clone());

        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let resolver = self.resolver.clone();
        let mode = self.mode.clone();
        let manager = self.manager.clone();
        let proxy_resolve_local = self.proxy_resolve_local;
        let traffic_reporter = self.traffic_reporter.get().cloned();
        let network_status = self.network_status.get().cloned();

        #[rustfmt::skip]
        /*
         *  implement details
         *
         *  data structure:
         *    local_r, local_w: stream/sink pair
         *    remote_r, remote_w: stream/sink pair
         *    remote_receiver_r, remote_receiver_w: channel pair
         *    remote_sender, remote_forwarder: channel pair
         *
         *  data flow:
         *    => local_r => init packet => connect_datagram => remote_sender     => remote_forwarder         => remote_w
         *    => local_w                                    <= remote_receiver_r <= NAT + remote_receiver_w  <= remote_r
         *
         *  notice:
         *    the NAT is binded to the session in the dispatch_datagram function arg and the closure
         *    so we need not to add a global NAT table and do the translation
         */
        let (mut local_w, mut local_r) = udp_inbound.split();
        let (remote_receiver_w, mut remote_receiver_r) =
            tokio::sync::mpsc::channel(256);

        let s = sess.clone();
        let ss = sess.clone();
        let t1 = tokio::spawn(async move {
            while let Some(mut packet) = local_r.next().await {
                let packet_generation =
                    outbound_handle_guard.generation.load(Ordering::Acquire);
                let mut sess = sess.clone();

                // SS2022 and dual-stack UDP inbounds can surface IPv4 targets as
                // IPv4-mapped IPv6. Keep the canonical IP before fake-IP reverse
                // lookup may replace the destination with a domain.
                if let SocksAddr::Ip(addr) = &packet.dst_addr {
                    let canonical = addr.to_canonical();
                    packet.dst_addr = SocksAddr::Ip(canonical);
                    sess.resolved_ip = Some(canonical.ip());
                }

                let dest = match reverse_lookup(&resolver, &packet.dst_addr).await {
                    Some(dest) => dest,
                    None => {
                        warn!(
                            "dropping flow with fake-IP destination because its domain mapping is missing: {}",
                            sess
                        );
                        continue;
                    }
                };

                // for TUN or Tproxy, we need the original destination address
                let orig_dest = packet.dst_addr.clone();
                sess.source = packet.src_addr.clone().must_into_socket_addr();
                sess.destination = dest.clone();
                sess.inbound_user = packet.inbound_user.clone();
                sess.process_name = find_process_name(
                    sess.source,
                    orig_dest.clone().try_into_socket_addr(),
                    sess.network,
                );

                let mode = *mode.read().await;

                let (outbound_name, rule) = match mode {
                    RunMode::Global => (PROXY_GLOBAL, None),
                    RunMode::Rule => router.match_route(&mut sess).await,
                    RunMode::Direct => (PROXY_DIRECT, None),
                };

                let requested_outbound_name = outbound_name.to_string();

                // Explain uses one ID for this UDP association attempt. On a
                // successful first packet, the same ID is attached to the
                // TrackedDatagram so `/flows` and Explain can be joined.
                let explain_flow_id = uuid::Uuid::new_v4();
                let explain_versions_at_start = explain_versions_from_status(
                    network_status.as_ref(),
                    packet_generation,
                )
                .await;

                let remote_receiver_w = remote_receiver_w.clone();

                let mgr = outbound_manager.clone();
                let selected = match select_outbound_with_direct_fallback(
                    &requested_outbound_name,
                    |name| {
                        let mgr = mgr.clone();
                        async move { mgr.get_outbound_for_new_flow(&name).await }
                    },
                )
                .await
                {
                    Ok(Some(selected)) => selected,
                    Ok(None) => {
                        warn!(requested_outbound = %requested_outbound_name, "DIRECT outbound unavailable for UDP flow");
                        continue;
                    }
                    Err(error) => {
                        warn!(requested_outbound = %requested_outbound_name, error = %error, "could not select outbound for UDP flow");
                        continue;
                    }
                };
                if selected.used_direct_fallback {
                    debug!(requested_outbound = %requested_outbound_name, "unknown outbound; falling back to DIRECT for UDP");
                }
                let used_direct_fallback = selected.used_direct_fallback;
                let is_dynamic_group = matches!(
                    selected.handler.proto(),
                    OutboundType::Selector
                        | OutboundType::Fallback
                        | OutboundType::UrlTest
                        | OutboundType::LoadBalance
                );
                let pinned =
                    match crate::proxy::group::selector::PinnedOutbound::capture(
                        selected.handler,
                        &sess,
                    )
                    .await
                    {
                        Ok(pinned) => pinned,
                        Err(error) => {
                            warn!(requested_outbound = %requested_outbound_name, error = %error, "could not capture selector's outbound for UDP flow");
                            continue;
                        }
                    };
                if let Err(error) = mgr
                    .ensure_outbound_ready_for_new_flow(&pinned.handler)
                    .await
                {
                    warn!(requested_outbound = %requested_outbound_name, actual_outbound = pinned.handler.name(), error = %error, "outbound pool is not safe for new UDP flow");
                    continue;
                }
                let handler = &pinned.handler;
                let outbound_name = if is_dynamic_group {
                    handler.name().to_owned()
                } else if let Some(group) = handler.try_as_group_handler() {
                    group
                        .get_active_proxy()
                        .await
                        .map(|x| x.name().to_owned())
                        .unwrap_or(selected.effective_name)
                } else {
                    selected.effective_name
                };

                let rule_summary = rule_summary(rule.map(Box::as_ref));
                let explain_route = crate::app::flow::RouteDecision {
                    outbound: if used_direct_fallback {
                        requested_outbound_name.clone()
                    } else {
                        outbound_name.clone()
                    },
                    rule: Some(rule_summary.clone()),
                };
                let mut connect_sess = sess.clone();
                Self::maybe_resolve_proxy_destination_locally(
                    &resolver,
                    proxy_resolve_local,
                    &outbound_name,
                    &mut connect_sess,
                )
                .await;
                let mut resolved_direct_target = None;
                let can_resolve_for_path = if outbound_name == PROXY_DIRECT {
                    match network_status.as_ref() {
                        Some(status) => status
                            .read()
                            .await
                            .shadow_path_snapshot()
                            .is_some_and(|(_, _, tun_enabled)| !tun_enabled),
                        None => false,
                    }
                } else {
                    false
                };
                if can_resolve_for_path
                    && let SocksAddr::Domain(host, port) = &sess.destination
                {
                    let known_real_ip = match (&orig_dest, sess.resolved_ip) {
                        (SocksAddr::Ip(original), Some(resolved))
                            if original.ip() == resolved =>
                        {
                            let is_fake = resolver.fake_ip_enabled()
                                && resolver.is_fake_ip(resolved).await;
                            (!is_fake).then_some(resolved)
                        }
                        _ => None,
                    };
                    let resolved_ip = if let Some(ip) = known_real_ip {
                        Some(ip)
                    } else {
                        let lookup =
                            Self::resolver_for_outbound(&resolver, &outbound_name);
                        match lookup.resolve_all(host, false).await {
                            Ok(addresses) => preferred_udp_path_address(&addresses),
                            Err(error) => {
                                debug!(
                                    outbound_name,
                                    host,
                                    error = %error,
                                    "UDP path planning could not resolve the logical destination; retaining the existing resolver path"
                                );
                                None
                            }
                        }
                    };
                    if let Some(ip) = resolved_ip
                        && (!resolver.fake_ip_enabled()
                            || !resolver.is_fake_ip(ip).await)
                    {
                        let target = SocketAddr::new(ip, *port);
                        resolved_direct_target = Some(target);
                        connect_sess.destination = target.into();
                    }
                }

                // A literal or resolved DIRECT target supplies the family for
                // this UDP destination. Fake-IP is never used as a network
                // destination or family hint.
                let target_family = if outbound_name == PROXY_DIRECT {
                    if let Some(target) = resolved_direct_target {
                        Some(crate::app::flow::AddressFamily::from(target.ip()))
                    } else {
                        match (&orig_dest, &sess.destination) {
                            (SocksAddr::Ip(original), SocksAddr::Ip(logical))
                                if original.ip() == logical.ip() =>
                            {
                                Some(crate::app::flow::AddressFamily::from(
                                    original.ip(),
                                ))
                            }
                            _ => None,
                        }
                    }
                } else {
                    None
                };
                let (network_version, policy_generation) = udp_path_cache_versions(
                    network_status.as_ref(),
                    packet_generation,
                )
                .await;
                let source = packet.src_addr.clone().must_into_socket_addr();
                let mut path_selection = None;
                let mut path_failure = None;
                let mut path_failure_details = None;
                let mut path_decision_cache_hit = false;
                if let Some(family) = target_family {
                    let decision_key = UdpFlowDecisionKey {
                        outbound_name: outbound_name.clone(),
                        inbound: sess.typ,
                        source,
                        process_name: sess.process_name.clone(),
                        inbound_user: sess.inbound_user.clone(),
                        original_destination: orig_dest.clone(),
                        logical_destination: sess.destination.clone(),
                        target_family: Some(family),
                        session_generation: packet_generation,
                        network_version,
                        policy_generation,
                    };
                    if let Some(cached) =
                        outbound_handle_guard.get_flow_decision(&decision_key).await
                    {
                        path_decision_cache_hit = true;
                        path_selection = cached.selection;
                        path_failure = cached.failure;
                    } else {
                        match Self::plan_direct_path_with_status(
                            network_status.clone(),
                            &outbound_name,
                            rule.as_ref().map(|matcher| matcher.as_ref()),
                            &connect_sess,
                            Some(family),
                        )
                        .await
                        {
                            Ok(Some((selection, observed_version)))
                                if observed_version == network_version
                                    && selection.policy_generation
                                        == policy_generation =>
                            {
                                path_selection = Some(selection);
                            }
                            Ok(Some((selection, observed_version))) => {
                                let current_versions = explain_versions_from_status(
                                    network_status.as_ref(),
                                    packet_generation,
                                )
                                .await;
                                store_path_decision(
                                    network_status.as_ref(),
                                    crate::app::flow::PathDecisionRecord {
                                        flow_id: explain_flow_id,
                                        config_version: explain_versions_at_start.0,
                                        config_version_at_completion:
                                            (current_versions.0
                                                != explain_versions_at_start.0)
                                                .then_some(current_versions.0),
                                        policy_version: explain_versions_at_start.1,
                                        network_version: current_versions.2,
                                        operation_id: explain_versions_at_start.3,
                                        outcome: crate::app::flow::PathExecutionOutcome::StaleNetworkDiscarded,
                                        route: explain_route.clone(),
                                        candidate_paths: Vec::new(),
                                        selected_path: None,
                                        rejected: Vec::new(),
                                        failure_kind: None,
                                        reason: format!(
                                            "networkOrPolicyChangedDuringUdpPathPlanning:network={observed_version},policy={}",
                                            selection.policy_generation
                                        ),
                                        recorded_at_ms: chrono::Utc::now()
                                            .timestamp_millis(),
                                    },
                                )
                                .await;
                                warn!(
                                    outbound_name = %outbound_name,
                                    source = %source,
                                    destination = %sess.destination,
                                    expected_network_version = network_version,
                                    observed_network_version = observed_version,
                                    expected_policy_generation = policy_generation,
                                    observed_policy_generation = selection.policy_generation,
                                    "dropping UDP packet because path decision became stale"
                                );
                                continue;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                path_failure = Some(error.to_string());
                                path_failure_details = Some(error);
                            }
                        }
                        outbound_handle_guard
                            .insert_flow_decision(
                                decision_key,
                                path_selection.clone(),
                                path_failure.clone(),
                            )
                            .await;
                    }
                }
                if resolved_direct_target.is_some()
                    && path_selection.is_none()
                    && path_failure.is_none()
                {
                    // No unambiguous automatic path was observed. Keep the
                    // pre-existing system-managed DNS and UDP behavior.
                    connect_sess.destination = sess.destination.clone();
                }
                let outbound_dest = connect_sess.destination.clone();
                if let Some(failure) = path_failure {
                    let current_versions = explain_versions_from_status(
                        network_status.as_ref(),
                        packet_generation,
                    )
                    .await;
                    let planning_error = path_failure_details.as_ref();
                    let stale_plan = planning_error.is_some_and(|error| {
                        current_versions.2 != error.network_generation
                    });
                    store_path_decision(
                        network_status.as_ref(),
                        crate::app::flow::PathDecisionRecord {
                            flow_id: explain_flow_id,
                            config_version: explain_versions_at_start.0,
                            config_version_at_completion:
                                (current_versions.0 != explain_versions_at_start.0)
                                    .then_some(current_versions.0),
                            policy_version: planning_error.map_or_else(
                                || {
                                    path_selection.as_ref().map_or(
                                        explain_versions_at_start.1,
                                        |selection| selection.policy_generation,
                                    )
                                },
                                |error| error.policy_generation,
                            ),
                            network_version: current_versions.2,
                            operation_id: explain_versions_at_start.3,
                            outcome: if stale_plan {
                                crate::app::flow::PathExecutionOutcome::StaleNetworkDiscarded
                            } else {
                                crate::app::flow::PathExecutionOutcome::PathPlanningFailed
                            },
                            route: explain_route.clone(),
                            candidate_paths: planning_error
                                .map_or_else(Vec::new, |error| error.candidate_paths.clone()),
                            selected_path: None,
                            rejected: planning_error
                                .map_or_else(Vec::new, |error| error.rejected.clone()),
                            failure_kind: planning_error.map(|error| error.kind().to_string()),
                            reason: if stale_plan {
                                "networkChangedDuringPathPlanning".to_owned()
                            } else {
                                failure.clone()
                            },
                            recorded_at_ms: chrono::Utc::now().timestamp_millis(),
                        },
                    )
                    .await;
                    warn!(
                        outbound_name = %outbound_name,
                        source = %source,
                        orig_dest = %orig_dest,
                        resolved_dest = %sess.destination,
                        error = %failure,
                        "dropping UDP packet because required network path is unavailable"
                    );
                    // A hard interface requirement is a property of the UDP
                    // association, not just this datagram. End that
                    // association so later packets cannot look like a live
                    // flow that is silently black-holed.
                    break;
                }
                let path_id = target_family
                    .and_then(|family| {
                        path_selection
                            .as_ref()
                            .and_then(|selection| selection.for_family(family))
                    })
                    .map(|path| path.id.clone());
                // `path_id` is the planned association/cache key, not proof
                // that the socket actually opened on that interface.
                if !outbound_handle_guard.generation_is_current(packet_generation) {
                    debug!(
                        source = %source,
                        destination = %sess.destination,
                        "dropping UDP packet from a stale network generation"
                    );
                    continue;
                }
                if let Some(selection) = path_selection.as_ref()
                    && !udp_path_selection_is_current(
                        network_status.as_ref(),
                        selection,
                    )
                    .await
                {
                    debug!(
                        source = %source,
                        destination = %sess.destination,
                        selected_network_version = selection.network_generation,
                        selected_policy_generation = selection.policy_generation,
                        "dropping UDP packet because selected network or policy version is stale"
                    );
                    continue;
                }

                debug!(
                    outbound_name = %outbound_name,
                    rule = %rule_summary,
                    mode = %mode,
                    source = %sess.source,
                    orig_dest = %orig_dest,
                    resolved_dest = %sess.destination,
                    connect_dest = %outbound_dest,
                    target_family = ?target_family,
                    policy_generation = path_selection
                        .as_ref()
                        .map(|selection| selection.policy_generation)
                        .unwrap_or(0),
                    network_version,
                    selected_path = ?path_id,
                    path_decision_cache_hit,
                    path_execution = if path_id.is_some() {
                        "pathPlanned"
                    } else {
                        "systemManaged"
                    },
                    "dispatching udp packet"
                );

                match outbound_handle_guard
                    .get_outbound_sender_mut(
                        &outbound_name,
                        source, /* this is only
                                 * expected to be
                                 * socket addr as it's
                                 * from local
                                 * udp */
                        path_id.clone(),
                    )
                    .await
                {
                    None => {
                        debug!(
                            outbound_name = %outbound_name,
                            rule = %rule_summary,
                            source = %sess.source,
                            orig_dest = %orig_dest,
                            resolved_dest = %sess.destination,
                            "building outbound datagram"
                        );
                        let connect_resolver =
                            Self::resolver_for_outbound(&resolver, &outbound_name);
                        let traffic_proof =
                            traffic_reporter.as_ref().map(|reporter| {
                                let kind = if outbound_name == PROXY_DIRECT {
                                    crate::app::runtime_state::TrafficKind::DirectUdp
                                } else {
                                    crate::app::runtime_state::TrafficKind::ProxyUdp
                                };
                                reporter.capture(kind)
                            });
                        let connect_result = match path_selection.as_ref() {
                            Some(selection) => {
                                handler
                                    .connect_datagram_with_path_selection(
                                        &connect_sess,
                                        connect_resolver,
                                        selection,
                                    )
                                    .await
                            }
                            None => {
                                handler
                                    .connect_datagram(
                                        &connect_sess,
                                        connect_resolver,
                                    )
                                    .await
                            }
                        };
                        let outbound_datagram = match connect_result {
                            Ok(v) => v,
                            Err(err) => {
                                let current_versions = explain_versions_from_status(
                                    network_status.as_ref(),
                                    packet_generation,
                                )
                                .await;
                                let proxy_endpoint_error = err
                                    .get_ref()
                                    .and_then(|source| {
                                        source.downcast_ref::<
                                            crate::proxy::utils::ProxyEndpointConnectError,
                                        >()
                                    });
                                let mut candidate_paths = target_family
                                    .and_then(|family| {
                                        path_selection.as_ref().map(|selection| {
                                            selection
                                                .candidates_for_family(family)
                                                .iter()
                                                .map(|path| path.id.clone())
                                                .collect::<Vec<_>>()
                                        })
                                    })
                                    .unwrap_or_default();
                                if let Some(failure) = proxy_endpoint_error {
                                    candidate_paths.extend(
                                        failure.candidate_paths().iter().cloned(),
                                    );
                                }
                                candidate_paths.dedup();
                                let mut rejected = path_selection
                                    .as_ref()
                                    .map(|selection| selection.rejected.clone())
                                    .unwrap_or_default();
                                if let Some(failure) = proxy_endpoint_error {
                                    rejected
                                        .extend(failure.rejected().iter().cloned());
                                    rejected.dedup_by(|left, right| left == right);
                                }
                                let stale_network = current_versions.2
                                    != explain_versions_at_start.2;
                                let reason = if outbound_name == PROXY_DIRECT {
                                    "directUdpDialFailed".to_owned()
                                } else if let Some(failure) = proxy_endpoint_error {
                                    format!(
                                        "proxyUdpEndpointDialFailed; attemptedPaths={:?}; {err}",
                                        failure.attempted_paths(),
                                    )
                                } else {
                                    "proxyUdpDialFailedPathUnknown".to_owned()
                                };
                                store_path_decision(
                                    network_status.as_ref(),
                                    crate::app::flow::PathDecisionRecord {
                                        flow_id: explain_flow_id,
                                        config_version: explain_versions_at_start.0,
                                        config_version_at_completion:
                                            (current_versions.0
                                                != explain_versions_at_start.0)
                                                .then_some(current_versions.0),
                                        policy_version: path_selection
                                            .as_ref()
                                            .map_or(explain_versions_at_start.1, |selection| {
                                                selection.policy_generation
                                            }),
                                        network_version: current_versions.2,
                                        operation_id: explain_versions_at_start.3,
                                        outcome: if stale_network {
                                            crate::app::flow::PathExecutionOutcome::StaleNetworkDiscarded
                                        } else {
                                            crate::app::flow::PathExecutionOutcome::DialFailed
                                        },
                                        route: explain_route.clone(),
                                        candidate_paths,
                                        selected_path: None,
                                        rejected,
                                        failure_kind: Some(err.kind().to_string()),
                                        reason: if stale_network {
                                            format!("networkChangedDuringUdpDial; {reason}")
                                        } else {
                                            reason
                                        },
                                        recorded_at_ms: chrono::Utc::now()
                                            .timestamp_millis(),
                                    },
                                )
                                .await;
                                error!(
                                    outbound_name = %outbound_name,
                                    rule = %rule_summary,
                                    source = %sess.source,
                                    orig_dest = %orig_dest,
                                    resolved_dest = %sess.destination,
                                    error = %err,
                                    "failed to connect outbound datagram"
                                );
                                if path_selection
                                    .as_ref()
                                    .is_some_and(|selection| selection.required)
                                {
                                    break;
                                }
                                continue;
                            }
                        };

                        pinned.append_datagram_chain(&outbound_datagram).await;
                        let observed_path_id =
                            outbound_datagram.network_path_ids().first().cloned();
                        let confirmed_path = confirmed_udp_path(
                            path_id.as_ref(),
                            observed_path_id.as_ref(),
                        );
                        let flow_health_proof = confirmed_path.as_ref().and_then(|path| {
                            traffic_reporter.as_ref().map(|reporter| {
                                reporter.capture_scoped(
                                    crate::app::runtime_state::TrafficKind::DirectUdp,
                                    Some(path.clone()),
                                    direct_udp_health_destination(&outbound_dest),
                                )
                            })
                        });

                        let stale_network_path =
                            if let Some(selection) = path_selection.as_ref() {
                                !udp_path_selection_is_current(
                                    network_status.as_ref(),
                                    selection,
                                )
                                .await
                            } else {
                                false
                            };
                        if !outbound_handle_guard
                            .generation_is_current(packet_generation)
                            || stale_network_path
                        {
                            let current_versions = explain_versions_from_status(
                                network_status.as_ref(),
                                packet_generation,
                            )
                            .await;
                            store_path_decision(
                                network_status.as_ref(),
                                crate::app::flow::PathDecisionRecord {
                                    flow_id: explain_flow_id,
                                    config_version: explain_versions_at_start.0,
                                    config_version_at_completion:
                                        (current_versions.0
                                            != explain_versions_at_start.0)
                                            .then_some(current_versions.0),
                                    policy_version: path_selection
                                        .as_ref()
                                        .map_or(explain_versions_at_start.1, |selection| {
                                            selection.policy_generation
                                        }),
                                    network_version: current_versions.2,
                                    operation_id: explain_versions_at_start.3,
                                    outcome: crate::app::flow::PathExecutionOutcome::StaleNetworkDiscarded,
                                    route: explain_route.clone(),
                                    candidate_paths: Vec::new(),
                                    selected_path: observed_path_id.clone(),
                                    rejected: path_selection
                                        .as_ref()
                                        .map(|selection| selection.rejected.clone())
                                        .unwrap_or_default(),
                                    failure_kind: None,
                                    reason: "networkOrPolicyChangedWhileOpeningUdpAssociation".to_owned(),
                                    recorded_at_ms: chrono::Utc::now()
                                        .timestamp_millis(),
                                },
                            )
                            .await;
                            drop(outbound_datagram);
                            debug!(
                                source = %source,
                                destination = %sess.destination,
                                "discarding UDP socket created for a stale network path"
                            );
                            continue;
                        }

                        debug!(
                            outbound_name = %outbound_name,
                            rule = %rule_summary,
                            source = %sess.source,
                            orig_dest = %orig_dest,
                            resolved_dest = %sess.destination,
                            "outbound datagram connected"
                        );

                        let outbound_datagram = TrackedDatagram::new_with_id(
                            outbound_datagram,
                            manager.clone(),
                            sess.clone(),
                            rule.map(|matcher| matcher.as_ref()),
                            explain_flow_id,
                        )
                        .await;
                        let tracked_flow_id = outbound_datagram.id();
                        let tracker_info = outbound_datagram.tracker_info();

                        let (mut remote_w, mut remote_r) = outbound_datagram.split();
                        let (remote_sender, mut remote_forwarder) =
                            tokio::sync::mpsc::channel::<OutboundDatagramPacket>(
                                256,
                            );
                        let sess_for_rw = sess.clone();
                        let outbound_name_for_rw = outbound_name.clone();

                        let rw_handle = tokio::spawn(async move {
                            const ORIG_MAP_MAX: usize = 256;
                            let mut orig_map: HashMap<SocksAddr, SocksAddr> =
                                HashMap::new();
                            let mut health_proofs =
                                PendingUdpHealthProofs::default();
                            let mut last_orig_addr: Option<SocksAddr> = None;

                            loop {
                                tokio::select! {
                                    packet = remote_forwarder.recv() => {
                                        let Some(OutboundDatagramPacket {
                                            mut packet,
                                            destination: dest,
                                            health_proof,
                                        }) = packet else { break };
                                        let orig = packet.dst_addr.clone();
                                        packet.dst_addr = dest;
                                        if orig != packet.dst_addr {
                                            if orig_map.len() >= ORIG_MAP_MAX
                                                && let Some(key) =
                                                    orig_map.keys().next().cloned()
                                            {
                                                orig_map.remove(&key);
                                            }
                                            orig_map.insert(packet.dst_addr.clone(), orig.clone());
                                        }
                                        last_orig_addr = Some(orig.clone());

                                        if let Some(proof) = health_proof.as_ref() {
                                            health_proofs.insert(
                                                packet.dst_addr.clone(),
                                                proof.clone(),
                                                Instant::now(),
                                            );
                                        }

                                        if let Err(err) = remote_w.send(packet).await {
                                            if let Some(proof) = &health_proof {
                                                proof.failed(err.kind());
                                            }
                                            if let Some(proof) = &traffic_proof {
                                                proof.failed(err.kind());
                                            }
                                            warn!(
                                                outbound_name = %outbound_name_for_rw,
                                                session = %sess_for_rw,
                                                orig_dest = %orig,
                                                error = ?err,
                                                "failed to send packet to remote"
                                            );
                                            break;
                                        }
                                    }

                                    packet = remote_r.next() => {
                                        let Some(mut packet) = packet else { break };
                                        if let Some(proof) = &traffic_proof { proof.received(packet.data.len()); }
                                        health_proofs.received(
                                            &packet.src_addr,
                                            packet.data.len(),
                                            Instant::now(),
                                        );
                                        if let Some(orig) =
                                            orig_map.get(&packet.src_addr).cloned()
                                        {
                                            packet.src_addr = orig;
                                        } else if !orig_map.is_empty()
                                            && let Some(ref fallback) = last_orig_addr
                                        {
                                            packet.src_addr = fallback.clone();
                                        }
                                        packet.dst_addr = sess.source.into();

                                        debug!(
                                            outbound_name = %outbound_name_for_rw,
                                            session = %sess_for_rw,
                                            packet = ?packet,
                                            "udp nat remote packet"
                                        );
                                        if let Err(err) = remote_receiver_w.send(packet).await {
                                            warn!(
                                                outbound_name = %outbound_name_for_rw,
                                                session = %sess_for_rw,
                                                error = %err,
                                                "failed to send packet to local"
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        });

                        if !outbound_handle_guard
                            .insert(
                                &outbound_name,
                                source,
                                rw_handle,
                                remote_sender.clone(),
                                OutboundUdpSessionState {
                                    path_id: path_id.clone(),
                                    tracker: tracker_info.clone(),
                                    generation: packet_generation,
                                },
                            )
                            .await
                        {
                            let current_versions = explain_versions_from_status(
                                network_status.as_ref(),
                                packet_generation,
                            )
                            .await;
                            store_path_decision(
                                network_status.as_ref(),
                                crate::app::flow::PathDecisionRecord {
                                    flow_id: tracked_flow_id,
                                    config_version: explain_versions_at_start.0,
                                    config_version_at_completion:
                                        (current_versions.0
                                            != explain_versions_at_start.0)
                                            .then_some(current_versions.0),
                                    policy_version: path_selection
                                        .as_ref()
                                        .map_or(explain_versions_at_start.1, |selection| {
                                            selection.policy_generation
                                        }),
                                    network_version: current_versions.2,
                                    operation_id: explain_versions_at_start.3,
                                    outcome: crate::app::flow::PathExecutionOutcome::StaleNetworkDiscarded,
                                    route: explain_route.clone(),
                                    candidate_paths: Vec::new(),
                                    selected_path: confirmed_path.clone(),
                                    rejected: path_selection
                                        .as_ref()
                                        .map(|selection| selection.rejected.clone())
                                        .unwrap_or_default(),
                                    failure_kind: None,
                                    reason: "networkChangedBeforeUdpAssociationRegistration".to_owned(),
                                    recorded_at_ms: chrono::Utc::now()
                                        .timestamp_millis(),
                                },
                            )
                            .await;
                            continue;
                        }

                        let current_versions = explain_versions_from_status(
                            network_status.as_ref(),
                            packet_generation,
                        )
                        .await;
                        let mut candidate_paths = target_family
                            .and_then(|family| {
                                path_selection.as_ref().map(|selection| {
                                    selection
                                        .candidates_for_family(family)
                                        .iter()
                                        .map(|path| path.id.clone())
                                        .collect::<Vec<_>>()
                                })
                            })
                            .unwrap_or_default();
                        candidate_paths.dedup();
                        let selected_explain_path =
                            tracker_info.network_paths.first().cloned();
                        store_path_decision(
                            network_status.as_ref(),
                            crate::app::flow::PathDecisionRecord {
                                flow_id: tracked_flow_id,
                                config_version: explain_versions_at_start.0,
                                config_version_at_completion:
                                    (current_versions.0
                                        != explain_versions_at_start.0)
                                        .then_some(current_versions.0),
                                policy_version: path_selection
                                    .as_ref()
                                    .map_or(explain_versions_at_start.1, |selection| {
                                        selection.policy_generation
                                    }),
                                network_version: current_versions.2,
                                operation_id: explain_versions_at_start.3,
                                outcome: crate::app::flow::PathExecutionOutcome::Connected,
                                route: explain_route.clone(),
                                candidate_paths,
                                selected_path: selected_explain_path.clone(),
                                rejected: path_selection
                                    .as_ref()
                                    .map(|selection| selection.rejected.clone())
                                    .unwrap_or_default(),
                                failure_kind: None,
                                reason: if selected_explain_path.is_some() {
                                    "udpAssociationOpenedOnObservedPath".to_owned()
                                } else {
                                    "udpAssociationOpenedWithPathUnknown".to_owned()
                                },
                                recorded_at_ms: chrono::Utc::now()
                                    .timestamp_millis(),
                            },
                        )
                        .await;

                        try_queue_outbound_packet(
                            &remote_sender,
                            packet,
                            outbound_dest,
                            flow_health_proof.clone(),
                            &sess,
                            &outbound_name,
                            &orig_dest,
                        );
                    }
                    Some(handle) => {
                        if !outbound_handle_guard
                            .generation_is_current(packet_generation)
                        {
                            continue;
                        }
                        // TODO: need to reset when GLOBAL select is changed
                        let observed_path = outbound_handle_guard
                            .get_observed_path_id(
                                &outbound_name,
                                source,
                                path_id.clone(),
                            )
                            .await;
                        let flow_health_proof = observed_path.and_then(|path| {
                            traffic_reporter.as_ref().map(|reporter| {
                                reporter.capture_scoped(
                                    crate::app::runtime_state::TrafficKind::DirectUdp,
                                    Some(path),
                                    direct_udp_health_destination(&outbound_dest),
                                )
                            })
                        });
                        try_queue_outbound_packet(
                            &handle,
                            packet,
                            outbound_dest,
                            flow_health_proof,
                            &sess,
                            &outbound_name,
                            &orig_dest,
                        );
                        debug!(
                            outbound_name = %outbound_name,
                            rule = %rule_summary,
                            source = %sess.source,
                            orig_dest = %orig_dest,
                            resolved_dest = %sess.destination,
                            "reusing outbound datagram"
                        );
                    }
                };
            }

            trace!("UDP session local -> remote finished for {}", ss);
        });

        let ss = s.clone();
        let t2 = tokio::spawn(async move {
            while let Some(packet) = remote_receiver_r.recv().await {
                match local_w.send(packet).await {
                    Ok(_) => {}
                    Err(err) => {
                        warn!("failed to send packet to local: {}", err);
                        break;
                    }
                }
            }
            trace!("UDP session remote -> local finished for {}", ss);
        });

        let (close_sender, close_receiver) = tokio::sync::oneshot::channel::<u8>();

        tokio::spawn(async move {
            match close_receiver.await {
                Ok(_) => {
                    trace!("UDP close signal for {} received", s);
                }
                Err(_) => {
                    trace!(
                        "UDP close sender for {} dropped before explicit close; treating as normal shutdown",
                        s
                    );
                }
            }

            t1.abort();
            t2.abort();
        });

        close_sender
    }
}

fn preferred_udp_path_address(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
}

fn direct_udp_health_destination(destination: &SocksAddr) -> Option<SocksAddr> {
    matches!(destination, SocksAddr::Ip(_)).then(|| destination.clone())
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
async fn reverse_lookup(
    resolver: &Arc<dyn ClashResolver>,
    dst: &SocksAddr,
) -> Option<SocksAddr> {
    let dst = match dst {
        crate::session::SocksAddr::Ip(socket_addr) => {
            if resolver.fake_ip_enabled() {
                let ip = socket_addr.ip();
                if resolver.is_fake_ip(ip).await {
                    trace!("looking up fake ip: {}", socket_addr.ip());
                    match resolver.reverse_lookup(ip).await {
                        Some(host) => (host, socket_addr.port())
                            .try_into()
                            .expect("must be valid domain"),
                        None => {
                            return None;
                        }
                    }
                } else {
                    (*socket_addr).into()
                }
            } else {
                trace!("looking up resolve cache ip: {}", socket_addr.ip());
                match resolver.cached_for(socket_addr.ip()).await {
                    Some(host) => (host, socket_addr.port())
                        .try_into()
                        .expect("must be valid domain"),
                    None => (*socket_addr).into(),
                }
            }
        }
        crate::session::SocksAddr::Domain(_, _) => dst.clone(),
    };
    Some(dst)
}

fn rule_summary(rule: Option<&dyn crate::app::router::RuleMatcher>) -> String {
    rule.map(|rule| {
        let payload = rule.payload();
        if payload.is_empty() {
            rule.type_name().to_string()
        } else {
            format!("{} {}", rule.type_name(), payload)
        }
    })
    .unwrap_or_else(|| "implicit MATCH".to_string())
}

struct OutboundDatagramPacket {
    packet: UdpPacket,
    destination: SocksAddr,
    health_proof: Option<crate::app::runtime_state::TrafficProof>,
}

#[derive(Default)]
struct PendingUdpHealthProofs {
    entries: HashMap<SocksAddr, (crate::app::runtime_state::TrafficProof, Instant)>,
}

impl PendingUdpHealthProofs {
    fn insert(
        &mut self,
        destination: SocksAddr,
        proof: crate::app::runtime_state::TrafficProof,
        now: Instant,
    ) {
        self.expire_at(now);
        if self.entries.len() >= UDP_HEALTH_PROOF_MAX
            && !self.entries.contains_key(&destination)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, updated))| updated)
                .map(|(destination, _)| destination.clone())
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(destination, (proof, now));
    }

    fn received(&mut self, source: &SocksAddr, bytes: usize, now: Instant) -> bool {
        self.expire_at(now);
        if let Some((proof, _)) = self.entries.remove(source) {
            proof.received(bytes);
            true
        } else {
            false
        }
    }

    fn expire_at(&mut self, now: Instant) {
        self.entries.retain(|_, (_, updated)| {
            now.duration_since(*updated) < UDP_SESSION_IDLE
        });
    }
}

type OutboundPacketSender = tokio::sync::mpsc::Sender<OutboundDatagramPacket>;

fn try_queue_outbound_packet(
    sender: &OutboundPacketSender,
    packet: UdpPacket,
    dest: SocksAddr,
    health_proof: Option<crate::app::runtime_state::TrafficProof>,
    sess: &Session,
    outbound_name: &str,
    orig_dest: &SocksAddr,
) {
    match sender.try_send(OutboundDatagramPacket {
        packet,
        destination: dest,
        health_proof,
    }) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            warn!(
                outbound_name,
                source = %sess.source,
                orig_dest = %orig_dest,
                resolved_dest = %sess.destination,
                "dropping UDP packet because outbound session queue is full"
            );
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            warn!(
                outbound_name,
                source = %sess.source,
                orig_dest = %orig_dest,
                resolved_dest = %sess.destination,
                "failed to send packet to remote: outbound session is closed"
            );
        }
    }
}

struct TimeoutUdpSessionManager {
    map: Arc<RwLock<OutboundHandleMap>>,
    generation: Arc<AtomicU64>,

    cleaner: Option<JoinHandle<()>>,
}

struct OutboundUdpSessionState {
    path_id: Option<crate::app::flow::NetworkPathId>,
    tracker: Arc<TrackerInfo>,
    generation: u64,
}

impl Drop for TimeoutUdpSessionManager {
    fn drop(&mut self) {
        trace!("dropping timeout udp session manager");
        if let Some(x) = self.cleaner.take() {
            x.abort()
        }
    }
}

impl TimeoutUdpSessionManager {
    fn new(generation: Arc<AtomicU64>) -> Self {
        let map = Arc::new(RwLock::new(OutboundHandleMap::new()));
        let timeout = UDP_SESSION_IDLE;

        let map_cloned = map.clone();
        let cleaner_generation = generation.clone();

        let cleaner = tokio::spawn(async move {
            trace!("timeout udp session cleaner scanning");
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                interval.tick().await;
                trace!("timeout udp session cleaner ticking");

                let mut g = map_cloned.write().await;
                g.refresh_generation(cleaner_generation.load(Ordering::Acquire));
                g.expire_flow_decisions(Instant::now(), timeout);
                let (alived, expired) = g.expire_sessions(Instant::now(), timeout);
                trace!(
                    "timeout udp session cleaner finished, alived: {}, expired: {}",
                    alived, expired
                );
            }
        });

        Self {
            map,
            generation,

            cleaner: Some(cleaner),
        }
    }

    async fn insert(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
        rw_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
        session: OutboundUdpSessionState,
    ) -> bool {
        let mut map = self.map.write().await;
        let current = self.generation.load(Ordering::Acquire);
        map.refresh_generation(current);
        if session.generation != current {
            session
                .tracker
                .set_end_reason(FlowEndReason::NetworkChanged);
            rw_handle.abort();
            return false;
        }
        map.insert(
            outbound_name,
            src_addr,
            session.path_id,
            rw_handle,
            sender,
            session.tracker,
        );
        true
    }

    async fn get_outbound_sender_mut(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
        path_id: Option<crate::app::flow::NetworkPathId>,
    ) -> Option<OutboundPacketSender> {
        let mut map = self.map.write().await;
        map.refresh_generation(self.generation.load(Ordering::Acquire));
        map.get_outbound_sender_mut(outbound_name, src_addr, path_id)
    }

    async fn get_flow_decision(
        &self,
        key: &UdpFlowDecisionKey,
    ) -> Option<CachedUdpPathDecision> {
        let mut map = self.map.write().await;
        map.refresh_generation(self.generation.load(Ordering::Acquire));
        map.get_flow_decision(key)
    }

    async fn insert_flow_decision(
        &self,
        key: UdpFlowDecisionKey,
        selection: Option<crate::app::flow::DirectPathSelection>,
        failure: Option<String>,
    ) {
        let mut map = self.map.write().await;
        map.refresh_generation(self.generation.load(Ordering::Acquire));
        map.insert_flow_decision(key, selection, failure);
    }

    async fn get_observed_path_id(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
        path_id: Option<crate::app::flow::NetworkPathId>,
    ) -> Option<crate::app::flow::NetworkPathId> {
        let map = self.map.read().await;
        map.get_observed_path_id(outbound_name, src_addr, path_id)
    }

    fn generation_is_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::Acquire) == generation
    }
}

/// Key identifying a unique UDP NAT session.
/// Scoped to outbound plus client source, one socket per client for full-cone NAT.
#[derive(Debug, PartialEq, Eq, Hash)]
struct OutboundHandleKey {
    outbound_name: String,
    src_addr: SocketAddr,
    path_id: Option<crate::app::flow::NetworkPathId>,
}

/// One UDP destination Flow's path decision, independent of the NAT socket
/// that may still be shared by multiple destinations on the same path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UdpFlowDecisionKey {
    outbound_name: String,
    inbound: crate::session::Type,
    source: SocketAddr,
    process_name: Option<String>,
    inbound_user: Option<String>,
    original_destination: SocksAddr,
    logical_destination: SocksAddr,
    target_family: Option<crate::app::flow::AddressFamily>,
    session_generation: u64,
    network_version: u64,
    policy_generation: u64,
}

#[derive(Clone, Debug)]
struct CachedUdpPathDecision {
    selection: Option<crate::app::flow::DirectPathSelection>,
    failure: Option<String>,
    last_active: Instant,
}

struct OutboundHandleVal {
    /// Handles both local-to-remote and remote-to-local packet forwarding.
    rw_handle: JoinHandle<()>,
    sender: OutboundPacketSender,
    /// Lets session retirement report why the forwarding task was stopped.
    tracker: Arc<TrackerInfo>,
    last_active: Instant,
}

struct OutboundHandleMap(
    HashMap<OutboundHandleKey, OutboundHandleVal>,
    u64,
    HashMap<UdpFlowDecisionKey, CachedUdpPathDecision>,
);

impl OutboundHandleMap {
    fn new() -> Self {
        Self(HashMap::new(), 0, HashMap::new())
    }

    fn refresh_generation(&mut self, generation: u64) {
        if self.1 != generation {
            for (_, value) in self.0.drain() {
                // Set the reason before abort: dropping TrackedDatagram
                // schedules asynchronous untracking, which snapshots it.
                value.tracker.set_end_reason(FlowEndReason::NetworkChanged);
                value.rw_handle.abort();
            }
            self.2.clear();
            self.1 = generation;
        }
    }

    fn expire_sessions(&mut self, now: Instant, idle: Duration) -> (usize, usize) {
        let mut alived = 0;
        let mut expired = 0;
        self.0.retain(|key, value| {
            let alive = now.duration_since(value.last_active) < idle;
            if alive {
                alived += 1;
            } else {
                expired += 1;
                trace!("udp session expired: {:?}", key);
                value.tracker.set_end_reason(FlowEndReason::IdleTimeout);
                value.rw_handle.abort();
            }
            alive
        });
        (alived, expired)
    }

    fn insert(
        &mut self,
        outbound_name: &str,
        src_addr: SocketAddr,
        path_id: Option<crate::app::flow::NetworkPathId>,
        rw_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
        tracker: Arc<TrackerInfo>,
    ) {
        self.0.insert(
            OutboundHandleKey {
                outbound_name: outbound_name.to_string(),
                src_addr,
                path_id,
            },
            OutboundHandleVal {
                rw_handle,
                sender,
                tracker,
                last_active: Instant::now(),
            },
        );
    }

    fn get_outbound_sender_mut(
        &mut self,
        outbound_name: &str,
        src_addr: SocketAddr,
        path_id: Option<crate::app::flow::NetworkPathId>,
    ) -> Option<OutboundPacketSender> {
        let key = OutboundHandleKey {
            outbound_name: outbound_name.to_owned(),
            src_addr,
            path_id,
        };
        self.0.get_mut(&key).map(|val| {
            trace!(
                "updating last access time for outbound {:?}",
                (outbound_name, src_addr)
            );
            val.last_active = Instant::now();
            val.sender.clone()
        })
    }

    fn get_observed_path_id(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
        path_id: Option<crate::app::flow::NetworkPathId>,
    ) -> Option<crate::app::flow::NetworkPathId> {
        let key = OutboundHandleKey {
            outbound_name: outbound_name.to_owned(),
            src_addr,
            path_id,
        };
        self.0.get(&key).and_then(|entry| {
            confirmed_udp_path(
                key.path_id.as_ref(),
                entry.tracker.network_paths.first(),
            )
        })
    }

    fn get_flow_decision(
        &mut self,
        key: &UdpFlowDecisionKey,
    ) -> Option<CachedUdpPathDecision> {
        self.2.get_mut(key).map(|decision| {
            decision.last_active = Instant::now();
            decision.clone()
        })
    }

    fn insert_flow_decision(
        &mut self,
        key: UdpFlowDecisionKey,
        selection: Option<crate::app::flow::DirectPathSelection>,
        failure: Option<String>,
    ) {
        if self.2.len() >= UDP_FLOW_DECISION_MAX
            && !self.2.contains_key(&key)
            && let Some(oldest) = self
                .2
                .iter()
                .min_by_key(|(_, decision)| decision.last_active)
                .map(|(key, _)| key.clone())
        {
            self.2.remove(&oldest);
        }
        self.2.insert(
            key,
            CachedUdpPathDecision {
                selection,
                failure,
                last_active: Instant::now(),
            },
        );
    }

    fn expire_flow_decisions(&mut self, now: Instant, idle: Duration) {
        self.2
            .retain(|_, decision| now.duration_since(decision.last_active) < idle);
    }
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::{
        Dispatcher, OutboundDatagramPacket, OutboundHandleMap,
        PendingUdpHealthProofs, UDP_HEALTH_PROOF_MAX, UDP_SESSION_IDLE,
        UdpFlowDecisionKey, classify_flow_end_reason, confirmed_udp_path,
        direct_udp_health_destination, preferred_udp_path_address, reverse_lookup,
        select_outbound_with_direct_fallback, try_queue_outbound_packet,
        udp_path_cache_versions, udp_path_selection_is_current,
    };
    use crate::{
        app::dns::{ClashResolver, MockClashResolver, ThreadSafeDNSResolver},
        config::internal::proxy::PROXY_DIRECT,
        proxy::datagram::UdpPacket,
        session::{Network, Session, SocksAddr, Type},
    };
    use std::{
        future::pending,
        net::{IpAddr, SocketAddr},
        str::FromStr,
        sync::Arc,
        time::Instant,
    };
    use tokio::sync::mpsc;

    #[test]
    fn flow_end_reason_links_transport_failure_to_network_change() {
        let reset = Err(crate::common::io::CopyBidirectionalError::Other(
            std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        ));
        assert_eq!(
            classify_flow_end_reason(&reset, true),
            super::FlowEndReason::NetworkChanged
        );
        assert_eq!(
            classify_flow_end_reason(&reset, false),
            super::FlowEndReason::IoError
        );

        let idle_timeout = Err(crate::common::io::CopyBidirectionalError::Other(
            std::io::Error::from(std::io::ErrorKind::TimedOut),
        ));
        assert_eq!(
            classify_flow_end_reason(&idle_timeout, true),
            super::FlowEndReason::IdleTimeout,
            "idle timeout remains distinguishable from a concurrent path change"
        );
        assert_eq!(
            classify_flow_end_reason(
                &Ok(crate::common::io::BidirectionalCopyReport {
                    uploaded: 4,
                    downloaded: 8,
                    idle_timeout: false,
                }),
                true,
            ),
            super::FlowEndReason::Completed
        );
        assert_eq!(
            classify_flow_end_reason(
                &Ok(crate::common::io::BidirectionalCopyReport {
                    uploaded: 4,
                    downloaded: 8,
                    idle_timeout: true,
                }),
                false,
            ),
            super::FlowEndReason::IdleTimeout
        );
    }

    #[tokio::test]
    async fn network_change_retires_udp_socket_and_rejects_stale_dial() {
        let generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sessions = super::TimeoutUdpSessionManager::new(generation.clone());
        let source = "127.0.0.1:53000".parse().unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let tracker = Arc::new(super::TrackerInfo::default());
        assert!(
            sessions
                .insert(
                    "DIRECT",
                    source,
                    tokio::spawn(pending()),
                    sender,
                    super::OutboundUdpSessionState {
                        path_id: None,
                        tracker: tracker.clone(),
                        generation: 0,
                    },
                )
                .await
        );
        assert!(
            sessions
                .get_outbound_sender_mut("DIRECT", source, None)
                .await
                .is_some()
        );
        generation.store(1, std::sync::atomic::Ordering::Release);
        assert!(
            sessions
                .get_outbound_sender_mut("DIRECT", source, None)
                .await
                .is_none()
        );
        assert_eq!(
            tracker.end_reason(),
            super::FlowEndReason::NetworkChanged,
            "retiring the old UDP association records its terminal cause"
        );
        assert!(receiver.recv().await.is_none());
        let (sender, mut receiver) = mpsc::channel(1);
        let stale_tracker = Arc::new(super::TrackerInfo::default());
        assert!(
            !sessions
                .insert(
                    "DIRECT",
                    source,
                    tokio::spawn(pending()),
                    sender,
                    super::OutboundUdpSessionState {
                        path_id: None,
                        tracker: stale_tracker.clone(),
                        generation: 0,
                    },
                )
                .await
        );
        assert_eq!(
            stale_tracker.end_reason(),
            super::FlowEndReason::NetworkChanged
        );
        assert!(receiver.recv().await.is_none());
        let (sender, _receiver) = mpsc::channel(1);
        assert!(
            sessions
                .insert(
                    "DIRECT",
                    source,
                    tokio::spawn(pending()),
                    sender,
                    super::OutboundUdpSessionState {
                        path_id: None,
                        tracker: Arc::new(super::TrackerInfo::default()),
                        generation: 1,
                    },
                )
                .await
        );
        assert!(
            sessions
                .get_outbound_sender_mut("DIRECT", source, None)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn udp_session_idle_expiry_records_idle_timeout() {
        let mut map = OutboundHandleMap::new();
        let source = "127.0.0.1:53000".parse().unwrap();
        let tracker = Arc::new(super::TrackerInfo::default());
        let (sender, _receiver) = mpsc::channel(1);
        map.insert(
            "DIRECT",
            source,
            None,
            tokio::spawn(pending()),
            sender,
            tracker.clone(),
        );

        let (alive, expired) =
            map.expire_sessions(Instant::now() + UDP_SESSION_IDLE, UDP_SESSION_IDLE);

        assert_eq!((alive, expired), (0, 1));
        assert_eq!(tracker.end_reason(), super::FlowEndReason::IdleTimeout);
    }

    #[tokio::test]
    async fn missing_outbound_fallback_uses_direct_network_behavior_for_tcp_and_udp()
    {
        use crate::proxy::{AnyOutboundHandler, OutboundType, direct};

        for network in [Network::Tcp, Network::Udp] {
            let handler: AnyOutboundHandler =
                Arc::new(direct::Handler::new(PROXY_DIRECT));
            let mut lookups = Vec::new();
            let requested = "REMOVED-PROXY";
            let selected = select_outbound_with_direct_fallback(requested, |name| {
                lookups.push(name.clone());
                let handler = handler.clone();
                async move { Ok((name == PROXY_DIRECT).then_some(handler)) }
            })
            .await
            .unwrap()
            .unwrap();

            assert_eq!(lookups, [requested, PROXY_DIRECT]);
            assert!(selected.used_direct_fallback);
            assert_eq!(selected.effective_name, PROXY_DIRECT);
            assert_eq!(selected.handler.name(), PROXY_DIRECT);
            assert!(matches!(selected.handler.proto(), OutboundType::Direct));

            let direct_resolver: ThreadSafeDNSResolver =
                Arc::new(MockClashResolver::new());
            let expected = direct_resolver.clone();
            let mut primary = MockClashResolver::new();
            primary
                .expect_direct_resolver()
                .once()
                .returning(move || Some(expected.clone()));
            let primary: ThreadSafeDNSResolver = Arc::new(primary);
            let resolved = Dispatcher::resolver_for_outbound(
                &primary,
                &selected.effective_name,
            );
            assert!(Arc::ptr_eq(&resolved, &direct_resolver));

            // proxy-resolve-local must not turn the final DIRECT target into
            // a locally resolved proxy destination before path planning.
            let original = SocksAddr::Domain("example.test".to_owned(), 443);
            let mut session = Session {
                network,
                destination: original.clone(),
                ..Default::default()
            };
            Dispatcher::maybe_resolve_proxy_destination_locally(
                &primary,
                true,
                &selected.effective_name,
                &mut session,
            )
            .await;
            assert_eq!(session.destination, original);
        }
    }

    #[tokio::test]
    async fn outbound_fallback_only_happens_when_target_is_missing() {
        use std::io;

        let mut lookups = Vec::new();
        let selected = select_outbound_with_direct_fallback("PROXY", |name| {
            lookups.push(name.clone());
            async move { Ok::<_, io::Error>(Some(name)) }
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(lookups, ["PROXY"]);
        assert_eq!(selected.effective_name, "PROXY");
        assert!(!selected.used_direct_fallback);

        let mut lookups = Vec::new();
        let failure = select_outbound_with_direct_fallback("BROKEN", |name| {
            lookups.push(name);
            async { Err::<Option<String>, _>(io::Error::other("pool reset failed")) }
        })
        .await;
        assert!(failure.is_err());
        assert_eq!(lookups, ["BROKEN"]);

        let missing =
            select_outbound_with_direct_fallback("UNKNOWN", |_name| async {
                Ok::<_, io::Error>(None::<String>)
            })
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn direct_outbound_uses_direct_resolver_when_configured() {
        let direct: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let expected = direct.clone();

        let mut primary = MockClashResolver::new();
        primary
            .expect_direct_resolver()
            .once()
            .returning(move || Some(expected.clone()));
        let primary: ThreadSafeDNSResolver = Arc::new(primary);

        let selected = Dispatcher::resolver_for_outbound(&primary, PROXY_DIRECT);
        assert!(Arc::ptr_eq(&selected, &direct));
    }

    #[test]
    fn non_direct_outbound_keeps_primary_resolver() {
        let primary: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let selected = Dispatcher::resolver_for_outbound(&primary, "PROXY");
        assert!(Arc::ptr_eq(&selected, &primary));
    }

    #[tokio::test]
    async fn proxy_local_resolution_replaces_connect_destination() {
        let real_ip: IpAddr = "203.0.113.7".parse().unwrap();
        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().once().return_const(false);
        resolver.expect_direct_resolver().once().return_const(None);
        resolver
            .expect_resolve()
            .withf(|host, enhanced| host == "www.google.com" && !enhanced)
            .once()
            .returning(move |_, _| Ok(Some(real_ip)));
        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);

        let mut sess = Session {
            destination: SocksAddr::Domain("www.google.com".to_owned(), 443),
            ..Default::default()
        };

        Dispatcher::maybe_resolve_proxy_destination_locally(
            &resolver, true, "PROXY", &mut sess,
        )
        .await;

        assert_eq!(sess.resolved_ip, Some(real_ip));
        assert_eq!(
            sess.destination,
            SocksAddr::Ip(SocketAddr::new(real_ip, 443))
        );
    }

    #[tokio::test]
    async fn proxy_local_resolution_prefers_direct_resolver() {
        let real_ip: IpAddr = "203.0.113.9".parse().unwrap();

        let mut direct = MockClashResolver::new();
        direct
            .expect_resolve()
            .withf(|host, enhanced| host == "www.google.com" && !enhanced)
            .once()
            .returning(move |_, _| Ok(Some(real_ip)));
        let direct: ThreadSafeDNSResolver = Arc::new(direct);
        let expected = direct.clone();

        let mut primary = MockClashResolver::new();
        primary.expect_fake_ip_enabled().once().return_const(false);
        primary
            .expect_direct_resolver()
            .once()
            .returning(move || Some(expected.clone()));
        let primary: ThreadSafeDNSResolver = Arc::new(primary);

        let mut sess = Session {
            destination: SocksAddr::Domain("www.google.com".to_owned(), 443),
            ..Default::default()
        };

        Dispatcher::maybe_resolve_proxy_destination_locally(
            &primary, true, "PROXY", &mut sess,
        )
        .await;

        assert_eq!(sess.resolved_ip, Some(real_ip));
        assert_eq!(
            sess.destination,
            SocksAddr::Ip(SocketAddr::new(real_ip, 443))
        );
    }

    #[tokio::test]
    async fn direct_outbound_keeps_domain_when_proxy_local_resolution_is_enabled() {
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let original = SocksAddr::Domain("www.example.com".to_owned(), 443);
        let mut sess = Session {
            destination: original.clone(),
            ..Default::default()
        };

        Dispatcher::maybe_resolve_proxy_destination_locally(
            &resolver,
            true,
            PROXY_DIRECT,
            &mut sess,
        )
        .await;

        assert_eq!(sess.destination, original);
        assert_eq!(sess.resolved_ip, None);
    }

    #[tokio::test]
    async fn proxy_local_resolution_replaces_existing_fake_resolved_ip() {
        let fake_ip: IpAddr = "198.19.0.10".parse().unwrap();
        let real_ip: IpAddr = "203.0.113.8".parse().unwrap();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_fake_ip_enabled()
            .times(2)
            .return_const(true);
        resolver.expect_direct_resolver().once().return_const(None);
        resolver
            .expect_is_fake_ip()
            .times(2)
            .returning(move |ip| ip == fake_ip);
        resolver
            .expect_resolve()
            .withf(|host, enhanced| host == "www.google.com" && !enhanced)
            .once()
            .returning(move |_, _| Ok(Some(real_ip)));
        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);

        let mut sess = Session {
            destination: SocksAddr::Domain("www.google.com".to_owned(), 443),
            resolved_ip: Some(fake_ip),
            ..Default::default()
        };

        Dispatcher::maybe_resolve_proxy_destination_locally(
            &resolver, true, "PROXY", &mut sess,
        )
        .await;

        assert_eq!(sess.resolved_ip, Some(real_ip));
        assert_eq!(
            sess.destination,
            SocksAddr::Ip(SocketAddr::new(real_ip, 443))
        );
    }

    #[tokio::test]
    async fn outbound_handle_map_reuses_session_by_source_for_full_cone_nat() {
        let mut map = OutboundHandleMap::new();
        let src_addr = SocketAddr::from_str("127.0.0.1:53000").unwrap();
        let dest_a = SocksAddr::from_str("8.8.8.8:53").unwrap();
        let dest_b = SocksAddr::from_str("1.1.1.1:53").unwrap();

        let (sender_a, mut receiver_a) = mpsc::channel(1);
        let (sender_b, mut receiver_b) = mpsc::channel(1);

        map.insert(
            "DIRECT",
            src_addr,
            None,
            tokio::spawn(pending()),
            sender_a,
            Arc::new(super::TrackerInfo::default()),
        );
        map.insert(
            "DIRECT",
            src_addr,
            None,
            tokio::spawn(pending()),
            sender_b,
            Arc::new(super::TrackerInfo::default()),
        );

        let handle_a = map
            .get_outbound_sender_mut("DIRECT", src_addr, None)
            .expect("session should exist");
        let handle_b = map
            .get_outbound_sender_mut("DIRECT", src_addr, None)
            .expect("session should still exist");

        assert!(receiver_a.try_recv().is_err());

        handle_a
            .send(OutboundDatagramPacket {
                packet: Default::default(),
                destination: dest_a,
                health_proof: None,
            })
            .await
            .unwrap();
        assert!(receiver_b.recv().await.is_some());

        handle_b
            .send(OutboundDatagramPacket {
                packet: Default::default(),
                destination: dest_b,
                health_proof: None,
            })
            .await
            .unwrap();
        assert!(receiver_b.recv().await.is_some());
    }

    #[tokio::test]
    async fn outbound_handle_map_separates_sockets_by_selected_path() {
        let mut map = OutboundHandleMap::new();
        let src_addr = SocketAddr::from_str("127.0.0.1:53000").unwrap();
        let path_a = crate::app::flow::NetworkPathId {
            interface: crate::app::flow::InterfaceId {
                name: "en0".to_string(),
                index: 4,
            },
            family: crate::app::flow::AddressFamily::Ipv4,
            source_address: Some("192.0.2.2".parse().unwrap()),
            network_generation: 0,
        };
        let path_b = crate::app::flow::NetworkPathId {
            interface: crate::app::flow::InterfaceId {
                name: "en1".to_string(),
                index: 5,
            },
            family: crate::app::flow::AddressFamily::Ipv4,
            source_address: Some("198.51.100.2".parse().unwrap()),
            network_generation: 1,
        };
        let (sender_a, mut receiver_a) = mpsc::channel(1);
        let (sender_b, mut receiver_b) = mpsc::channel(1);
        map.insert(
            "DIRECT",
            src_addr,
            Some(path_a.clone()),
            tokio::spawn(pending()),
            sender_a,
            Arc::new(super::TrackerInfo {
                network_paths: vec![path_a.clone()],
                ..Default::default()
            }),
        );
        map.insert(
            "DIRECT",
            src_addr,
            Some(path_b.clone()),
            tokio::spawn(pending()),
            sender_b,
            Arc::new(super::TrackerInfo {
                network_paths: vec![path_b.clone()],
                ..Default::default()
            }),
        );

        assert_eq!(
            map.get_observed_path_id("DIRECT", src_addr, Some(path_a.clone())),
            Some(path_a.clone()),
        );
        assert_eq!(
            map.get_observed_path_id("DIRECT", src_addr, Some(path_b.clone())),
            Some(path_b.clone()),
        );
        map.get_outbound_sender_mut("DIRECT", src_addr, Some(path_a))
            .unwrap()
            .send(super::OutboundDatagramPacket {
                packet: Default::default(),
                destination: SocksAddr::from_str("8.8.8.8:53").unwrap(),
                health_proof: None,
            })
            .await
            .unwrap();
        map.get_outbound_sender_mut("DIRECT", src_addr, Some(path_b))
            .unwrap()
            .send(super::OutboundDatagramPacket {
                packet: Default::default(),
                destination: SocksAddr::from_str("1.1.1.1:53").unwrap(),
                health_proof: None,
            })
            .await
            .unwrap();

        assert!(receiver_a.recv().await.is_some());
        assert!(receiver_b.recv().await.is_some());
    }

    #[tokio::test]
    async fn planned_udp_path_is_not_treated_as_observed_socket_path() {
        use crate::app::flow::{AddressFamily, InterfaceId, NetworkPathId};

        let planned = NetworkPathId {
            interface: InterfaceId {
                name: "en0".to_owned(),
                index: 4,
            },
            family: AddressFamily::Ipv4,
            source_address: Some("192.0.2.5".parse().unwrap()),
            network_generation: 9,
        };
        let observed = NetworkPathId {
            interface: InterfaceId {
                name: "en1".to_owned(),
                index: 5,
            },
            family: planned.family,
            source_address: planned.source_address,
            network_generation: planned.network_generation,
        };
        assert_eq!(confirmed_udp_path(Some(&planned), None), None);
        assert_eq!(confirmed_udp_path(Some(&planned), Some(&observed)), None);
        assert_eq!(
            confirmed_udp_path(Some(&planned), Some(&planned)),
            Some(planned.clone())
        );

        let mut cache = OutboundHandleMap::new();
        let source: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let (sender, _receiver) = mpsc::channel(1);
        cache.insert(
            "DIRECT",
            source,
            Some(planned.clone()),
            tokio::spawn(pending()),
            sender,
            Arc::new(super::TrackerInfo::default()),
        );
        assert!(
            cache
                .get_outbound_sender_mut("DIRECT", source, Some(planned.clone()))
                .is_some()
        );
        assert_eq!(
            cache.get_observed_path_id("DIRECT", source, Some(planned)),
            None
        );
    }

    #[test]
    fn udp_flow_decision_cache_is_scoped_to_target_and_inbound_user() {
        let mut map = OutboundHandleMap::new();
        let source = SocketAddr::from_str("127.0.0.1:53000").unwrap();
        let destination = SocksAddr::from_str("8.8.8.8:53").unwrap();
        let base = UdpFlowDecisionKey {
            outbound_name: "DIRECT".to_string(),
            inbound: Type::Socks5,
            source,
            process_name: Some("resolver".to_string()),
            inbound_user: Some("alice".to_string()),
            original_destination: destination.clone(),
            logical_destination: destination,
            target_family: Some(crate::app::flow::AddressFamily::Ipv4),
            session_generation: 2,
            network_version: 7,
            policy_generation: 0,
        };
        let mut other_user = base.clone();
        other_user.inbound_user = Some("bob".to_string());
        let mut other_target = base.clone();
        other_target.original_destination =
            SocksAddr::from_str("1.1.1.1:53").unwrap();
        let mut other_family = base.clone();
        other_family.target_family = Some(crate::app::flow::AddressFamily::Ipv6);

        map.insert_flow_decision(base.clone(), None, None);
        map.insert_flow_decision(
            other_user.clone(),
            None,
            Some("user-specific path rejection".to_string()),
        );
        map.insert_flow_decision(other_target.clone(), None, None);
        map.insert_flow_decision(other_family.clone(), None, None);

        assert_eq!(map.2.len(), 4);
        assert!(map.get_flow_decision(&base).unwrap().failure.is_none());
        assert_eq!(
            map.get_flow_decision(&other_user)
                .unwrap()
                .failure
                .as_deref(),
            Some("user-specific path rejection")
        );
        assert!(map.get_flow_decision(&other_target).is_some());
        assert!(map.get_flow_decision(&other_family).is_some());

        map.expire_flow_decisions(
            Instant::now() + super::UDP_SESSION_IDLE,
            super::UDP_SESSION_IDLE,
        );
        assert!(map.2.is_empty());
    }

    #[tokio::test]
    async fn udp_flow_decision_cache_invalidates_after_policy_change() {
        use crate::app::{
            flow::{AddressFamily, InterfaceKind, PathPriority},
            network::{NetworkSnapshot, NetworkStatus},
        };

        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        status.observed(&NetworkSnapshot::default());
        let status = Arc::new(tokio::sync::RwLock::new(status));
        let (network_version, policy_generation) =
            udp_path_cache_versions(Some(&status), 7).await;
        let source = SocketAddr::from_str("127.0.0.1:53000").unwrap();
        let destination = SocksAddr::from_str("198.51.100.3:53").unwrap();
        let mut cache = OutboundHandleMap::new();
        let base = UdpFlowDecisionKey {
            outbound_name: "DIRECT".to_owned(),
            inbound: Type::Socks5,
            source,
            process_name: None,
            inbound_user: None,
            original_destination: destination.clone(),
            logical_destination: destination,
            target_family: Some(AddressFamily::Ipv4),
            session_generation: 7,
            network_version,
            policy_generation,
        };
        cache.insert_flow_decision(base.clone(), None, None);
        assert!(cache.get_flow_decision(&base).is_some());

        let expected_policy_version = status
            .write()
            .await
            .set_path_priority(
                vec![PathPriority {
                    interface: InterfaceKind::Ethernet,
                    family: AddressFamily::Ipv4,
                }],
                None,
            )
            .unwrap()
            .policy_version;
        let (new_network_version, new_policy_generation) =
            udp_path_cache_versions(Some(&status), 7).await;
        assert_eq!(new_network_version, network_version);
        assert_eq!(new_policy_generation, expected_policy_version);
        assert_ne!(new_policy_generation, policy_generation);
        let next = UdpFlowDecisionKey {
            policy_generation: new_policy_generation,
            ..base.clone()
        };
        assert!(cache.get_flow_decision(&next).is_none());
        assert!(cache.get_flow_decision(&base).is_some());

        let selected = crate::app::flow::DirectPathSelection {
            network_generation: network_version,
            policy_generation,
            ..Default::default()
        };
        assert!(!udp_path_selection_is_current(Some(&status), &selected).await);
        let updated = crate::app::flow::DirectPathSelection {
            policy_generation: new_policy_generation,
            ..selected.clone()
        };
        assert!(udp_path_selection_is_current(Some(&status), &updated).await);
        let wrong_network = crate::app::flow::DirectPathSelection {
            network_generation: network_version + 1,
            ..updated
        };
        assert!(!udp_path_selection_is_current(Some(&status), &wrong_network).await);
    }

    #[test]
    fn direct_udp_domain_path_prefers_ipv4_and_uses_ipv6_when_needed() {
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::10".parse().unwrap();
        assert_eq!(preferred_udp_path_address(&[v6, v4]), Some(v4));
        assert_eq!(preferred_udp_path_address(&[v6]), Some(v6));
        assert_eq!(preferred_udp_path_address(&[]), None);
    }

    #[test]
    fn direct_udp_health_destination_uses_the_resolved_socket_target() {
        let logical_domain = SocksAddr::Domain("example.test".to_owned(), 443);
        let resolved_endpoint = SocksAddr::from_str("192.0.2.10:443").unwrap();

        assert_eq!(
            direct_udp_health_destination(&resolved_endpoint),
            Some(resolved_endpoint)
        );
        assert_eq!(direct_udp_health_destination(&logical_domain), None);
    }

    #[tokio::test]
    async fn direct_loopback_destination_keeps_system_managed_path() {
        let session = Session {
            destination: SocksAddr::from_str("127.0.0.1:53").unwrap(),
            ..Default::default()
        };
        let decision = Dispatcher::plan_direct_path_with_status(
            None,
            PROXY_DIRECT,
            None,
            &session,
            Some(crate::app::flow::AddressFamily::Ipv4),
        )
        .await
        .unwrap();
        assert!(decision.is_none());
    }

    #[tokio::test]
    async fn udp_health_proofs_follow_the_matching_nat_response_source() {
        let mut status = crate::app::network::NetworkStatus::default();
        status.lifecycle(crate::app::runtime_state::Lifecycle::Running, "test");
        let (tx, mut rx) = mpsc::channel(4);
        let reporter = status.traffic_reporter(tx);
        let path_id = crate::app::flow::NetworkPathId {
            interface: crate::app::flow::InterfaceId {
                name: "en0".to_string(),
                index: 4,
            },
            family: crate::app::flow::AddressFamily::Ipv4,
            source_address: Some("192.0.2.2".parse().unwrap()),
            network_generation: 0,
        };
        let target_a = SocksAddr::from_str("8.8.8.8:53").unwrap();
        let target_b = SocksAddr::from_str("1.1.1.1:53").unwrap();
        let mut pending = PendingUdpHealthProofs::default();
        pending.insert(
            target_a.clone(),
            reporter.capture_scoped(
                crate::app::runtime_state::TrafficKind::DirectUdp,
                Some(path_id.clone()),
                Some(target_a.clone()),
            ),
            Instant::now(),
        );
        pending.insert(
            target_b.clone(),
            reporter.capture_scoped(
                crate::app::runtime_state::TrafficKind::DirectUdp,
                Some(path_id.clone()),
                Some(target_b.clone()),
            ),
            Instant::now(),
        );

        assert!(!pending.received(
            &SocksAddr::from_str("9.9.9.9:53").unwrap(),
            12,
            Instant::now(),
        ));
        assert!(pending.received(&target_b, 12, Instant::now()));
        status.record_traffic(rx.recv().await.unwrap());
        assert!(pending.received(&target_a, 8, Instant::now()));
        status.record_traffic(rx.recv().await.unwrap());

        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["pathHealth"][0]["state"], "available");
        assert_eq!(value["pathHealth"][0]["successfulResponses"], 2);
        assert_eq!(value["destinationPathHealth"].as_array().unwrap().len(), 2);
        assert!(
            value["destinationPathHealth"]
                .as_array()
                .unwrap()
                .iter()
                .all(|health| health["state"] == "available")
        );

        let old_destination = SocksAddr::from_str("203.0.113.8:443").unwrap();
        let mut expiring = PendingUdpHealthProofs::default();
        expiring.insert(
            old_destination,
            reporter.capture_scoped(
                crate::app::runtime_state::TrafficKind::DirectUdp,
                Some(path_id.clone()),
                None,
            ),
            Instant::now() - UDP_SESSION_IDLE,
        );
        expiring.expire_at(Instant::now());
        assert!(expiring.entries.is_empty());

        let mut bounded = PendingUdpHealthProofs::default();
        for index in 0..=UDP_HEALTH_PROOF_MAX {
            let destination = SocksAddr::Ip(SocketAddr::new(
                "203.0.113.9".parse().unwrap(),
                40000 + index as u16,
            ));
            bounded.insert(
                destination.clone(),
                reporter.capture_scoped(
                    crate::app::runtime_state::TrafficKind::DirectUdp,
                    Some(path_id.clone()),
                    Some(destination),
                ),
                Instant::now(),
            );
        }
        assert_eq!(bounded.entries.len(), UDP_HEALTH_PROOF_MAX);
    }

    #[test]
    fn try_queue_outbound_packet_drops_when_session_queue_is_full() {
        let (sender, mut receiver) = mpsc::channel(1);
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            source: SocketAddr::from_str("127.0.0.1:53000").unwrap(),
            destination: SocksAddr::from_str("8.8.8.8:53").unwrap(),
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            process_name: None,
            inbound_user: None,
        };

        sender
            .try_send(super::OutboundDatagramPacket {
                packet: UdpPacket::default(),
                destination: sess.destination.clone(),
                health_proof: None,
            })
            .unwrap();
        try_queue_outbound_packet(
            &sender,
            Default::default(),
            sess.destination.clone(),
            None,
            &sess,
            "DIRECT",
            &sess.destination,
        );

        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn reverse_lookup_rejects_fake_ip_when_mapping_is_missing() {
        let fake_ip: std::net::IpAddr = "198.18.0.10".parse().unwrap();
        let destination = SocksAddr::from_str("198.18.0.10:443").unwrap();

        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_is_fake_ip()
            .returning(move |ip| ip == fake_ip);
        resolver.expect_reverse_lookup().returning(|_| None);

        let resolved = reverse_lookup(
            &(Arc::new(resolver) as Arc<dyn ClashResolver>),
            &destination,
        )
        .await;

        assert!(resolved.is_none());
    }
}

impl Drop for OutboundHandleMap {
    fn drop(&mut self) {
        trace!(
            "dropping inner outbound handle map that has {} sessions",
            self.0.len()
        );
        for (_, val) in self.0.drain() {
            val.rw_handle.abort();
        }
    }
}
