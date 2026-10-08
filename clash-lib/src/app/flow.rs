//! Service-free facts and intent types used by Flow and network-path planning.
//!
//! These types describe a connection and possible paths. They do not resolve
//! names, select routes, bind sockets, or infer link types from interface names.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::session::{Network, Session, SocksAddr, Type};

/// Stable identity shared with the existing connection tracker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FlowId(uuid::Uuid);

impl FlowId {
    pub const fn new(id: uuid::Uuid) -> Self {
        Self(id)
    }

    pub const fn as_uuid(self) -> uuid::Uuid {
        self.0
    }
}

/// Immutable connection facts. The inbound and logical destinations remain
/// separate so fake-IP reverse lookup does not erase the address seen at ingress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowContext {
    pub id: FlowId,
    pub source: SocketAddr,
    pub inbound_destination: SocksAddr,
    pub destination: SocksAddr,
    pub resolved_ip: Option<IpAddr>,
    pub protocol: Network,
    pub inbound: Type,
    pub process_name: Option<String>,
    pub inbound_user: Option<String>,
}

impl FlowContext {
    /// Capture session facts while retaining the address originally presented by
    /// the inbound, before fake-IP reverse lookup changes `Session.destination`.
    pub fn from_session(
        id: FlowId,
        session: &Session,
        inbound_destination: SocksAddr,
    ) -> Self {
        Self {
            id,
            source: session.source,
            inbound_destination,
            destination: session.destination.clone(),
            resolved_ip: session.resolved_ip,
            protocol: session.network,
            inbound: session.typ,
            process_name: session.process_name.clone(),
            inbound_user: session.inbound_user.clone(),
        }
    }
}

/// Address family of one independently selectable network path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl From<IpAddr> for AddressFamily {
    fn from(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

/// Interface classification from an operating-system observer.
///
/// `Unknown` is intentional: names such as `en0` and `utun3` are not a
/// portable proof that an interface is Wi-Fi, Ethernet, or a VPN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceKind {
    Ethernet,
    Wifi,
    Cellular,
    Vpn,
    Virtual,
    Loopback,
    Other,
    Unknown,
}

/// Operating-system interface identity. Index changes distinguish a recreated
/// interface even when the operating system reuses its name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceId {
    pub name: String,
    pub index: u32,
}

/// Versioned identity for one interface and address-family path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPathId {
    pub interface: InterfaceId,
    pub family: AddressFamily,
    /// Source address makes same-interface, same-family candidates distinct.
    pub source_address: Option<IpAddr>,
    pub network_generation: u64,
}

/// Observed path facts. Presence here means observed, not proven reachable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPath {
    pub id: NetworkPathId,
    pub interface_kind: InterfaceKind,
    pub source_address: Option<IpAddr>,
    pub scope_id: Option<u32>,
    pub gateway: Option<IpAddr>,
}

/// Whether a path target is a preference that may fall back or a hard
/// requirement that must be satisfied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IntentStrength {
    Prefer,
    Require,
}

/// A single path dimension to prefer or require. Multiple intents can express,
/// for example, a required interface and a preferred address family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "dimension", content = "value")]
pub enum PathTarget {
    Interface(InterfaceId),
    Kind(InterfaceKind),
    Family(AddressFamily),
    KindAndFamily {
        kind: InterfaceKind,
        family: AddressFamily,
    },
    ExactPath(NetworkPathId),
}

/// One ordered runtime preference entry, matching the user-facing API shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathPriority {
    pub interface: InterfaceKind,
    pub family: AddressFamily,
}

impl From<PathPriority> for PathIntent {
    fn from(priority: PathPriority) -> Self {
        Self {
            strength: IntentStrength::Prefer,
            target: PathTarget::KindAndFamily {
                kind: priority.interface,
                family: priority.family,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathIntent {
    pub strength: IntentStrength,
    pub target: PathTarget,
}

/// Immutable policy input. Its generation is independent from observed network
/// generations and is not assigned by the current runtime yet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkIntentSnapshot {
    pub policy_generation: u64,
    /// Entries are ordered by preference; `Require` entries remain hard filters.
    pub intents: Vec<PathIntent>,
}

/// The route result produced by the existing Router/mode selection. Path
/// planning consumes this value and never changes which outbound was routed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteDecision {
    pub outbound: String,
    pub rule: Option<String>,
}

/// Candidate set stamped with the exact policy and environment generations
/// from which it was produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathPlan {
    pub policy_generation: u64,
    pub network_generation: u64,
    pub route: RouteDecision,
    pub candidates: Vec<NetworkPath>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PathSelectionReason {
    SystemDefault,
    Preferred,
    Required,
    AmbiguousSystemDefault,
    AmbiguousPreference,
    NoDefaultRouteEvidence,
    NoEligiblePath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateRejection {
    pub path: NetworkPathId,
    pub reason: PathRejectionReason,
    pub intent_index: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PathRejectionReason {
    RequiredIntentMismatch,
    Unavailable,
    EndpointFamilyMismatch,
    Unsupported,
}

/// Explainable path-selection result, kept separate from route and execution
/// results. The pure path-policy compiler produces this intermediate value;
/// dispatchers may copy its facts into a bounded runtime Explain record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathDecision {
    pub policy_generation: u64,
    pub network_generation: u64,
    pub selected: Option<NetworkPathId>,
    pub reason: PathSelectionReason,
    pub rejected: Vec<CandidateRejection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PathExecutionOutcome {
    Connected,
    DialFailed,
    PathPlanningFailed,
    StaleNetworkDiscarded,
}

/// Bounded, credential-free explanation retained for a flow attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathDecisionRecord {
    pub flow_id: uuid::Uuid,
    pub config_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_version_at_completion: Option<u64>,
    pub policy_version: u64,
    pub network_version: u64,
    pub operation_id: u64,
    pub outcome: PathExecutionOutcome,
    pub route: RouteDecision,
    pub candidate_paths: Vec<NetworkPathId>,
    pub selected_path: Option<NetworkPathId>,
    pub rejected: Vec<CandidateRejection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<String>,
    pub reason: String,
    pub recorded_at_ms: i64,
}

/// Per-family path decisions passed only to a direct TCP dial. DNS may produce
/// both families, so the connector must bind each resolved address to the
/// matching selected path. A hard requirement forbids legacy fallback.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectPathSelection {
    pub policy_generation: u64,
    pub network_generation: u64,
    pub ipv4: Option<NetworkPath>,
    pub ipv6: Option<NetworkPath>,
    /// Eligible paths in attempt order for each address family. A selected
    /// path, when present, is first; otherwise the paths are raced without
    /// treating interface enumeration order as a preference.
    pub ipv4_candidates: Vec<NetworkPath>,
    pub ipv6_candidates: Vec<NetworkPath>,
    /// Candidate rejections observed while compiling the per-family plan.
    /// Kept for local Explain records and omitted from wire serialization of
    /// the transient socket instruction.
    #[serde(skip)]
    pub rejected: Vec<CandidateRejection>,
    pub required: bool,
}

impl DirectPathSelection {
    pub fn for_family(&self, family: AddressFamily) -> Option<&NetworkPath> {
        match family {
            AddressFamily::Ipv4 => self.ipv4.as_ref(),
            AddressFamily::Ipv6 => self.ipv6.as_ref(),
        }
    }

    pub fn candidates_for_family(&self, family: AddressFamily) -> &[NetworkPath] {
        let candidates = match family {
            AddressFamily::Ipv4 => &self.ipv4_candidates,
            AddressFamily::Ipv6 => &self.ipv6_candidates,
        };
        if !candidates.is_empty() {
            return candidates;
        }
        self.for_family(family).map_or(&[], std::slice::from_ref)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use crate::session::{Network, Session, SocksAddr, Type};

    use super::{
        AddressFamily, CandidateRejection, FlowContext, FlowId, IntentStrength,
        InterfaceId, InterfaceKind, NetworkIntentSnapshot, NetworkPath,
        NetworkPathId, PathDecision, PathIntent, PathPlan, PathRejectionReason,
        PathSelectionReason, PathTarget, RouteDecision,
    };

    #[test]
    fn flow_context_preserves_fake_ip_and_logical_domain_separately() {
        let fake_ip: IpAddr = "198.19.0.10".parse().unwrap();
        let inbound_destination = SocksAddr::Ip(SocketAddr::new(fake_ip, 443));
        let logical_destination = SocksAddr::Domain("example.com".to_string(), 443);
        let id = FlowId::new(uuid::Uuid::new_v4());
        let session = Session {
            network: Network::Tcp,
            typ: Type::Socks5,
            source: "192.0.2.10:51000".parse().unwrap(),
            destination: logical_destination.clone(),
            resolved_ip: Some(fake_ip),
            process_name: Some("browser".to_string()),
            inbound_user: Some("alice".to_string()),
            ..Default::default()
        };

        let flow =
            FlowContext::from_session(id, &session, inbound_destination.clone());

        assert_eq!(flow.id, id);
        assert_eq!(flow.protocol, Network::Tcp);
        assert_eq!(flow.inbound, Type::Socks5);
        assert_eq!(flow.inbound_destination, inbound_destination);
        assert_eq!(flow.destination, logical_destination);
        assert_eq!(flow.resolved_ip, Some(fake_ip));
        assert_eq!(flow.process_name.as_deref(), Some("browser"));
        assert_eq!(flow.inbound_user.as_deref(), Some("alice"));
    }

    #[test]
    fn path_plan_and_decision_keep_policy_and_network_generations_separate() {
        let interface = InterfaceId {
            name: "en0".to_string(),
            index: 4,
        };
        let path_id = NetworkPathId {
            interface: interface.clone(),
            family: AddressFamily::Ipv4,
            source_address: Some("192.0.2.2".parse().unwrap()),
            network_generation: 7,
        };
        let path = NetworkPath {
            id: path_id.clone(),
            interface_kind: InterfaceKind::Unknown,
            source_address: Some("192.0.2.2".parse().unwrap()),
            scope_id: None,
            gateway: Some("192.0.2.1".parse().unwrap()),
        };
        let intent = NetworkIntentSnapshot {
            policy_generation: 3,
            intents: vec![PathIntent {
                strength: IntentStrength::Require,
                target: PathTarget::Interface(interface),
            }],
        };
        let plan = PathPlan {
            policy_generation: intent.policy_generation,
            network_generation: 7,
            route: RouteDecision {
                outbound: "DIRECT".to_string(),
                rule: None,
            },
            candidates: vec![path],
        };
        let rejected = CandidateRejection {
            path: path_id,
            reason: PathRejectionReason::Unavailable,
            intent_index: None,
        };
        let decision = PathDecision {
            policy_generation: 3,
            network_generation: 7,
            selected: None,
            reason: PathSelectionReason::NoEligiblePath,
            rejected: vec![rejected],
        };

        assert_eq!(plan.policy_generation, 3);
        assert_eq!(plan.network_generation, 7);
        assert_eq!(decision.policy_generation, 3);
        assert_eq!(decision.network_generation, 7);
        assert_eq!(
            decision.rejected[0].reason,
            PathRejectionReason::Unavailable
        );
        assert_eq!(intent.intents[0].strength, IntentStrength::Require);
    }
}
