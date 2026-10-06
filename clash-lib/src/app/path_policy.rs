//! Pure shadow compiler for network path candidates.
//!
//! This module consumes observed facts and immutable intent. It does not open
//! sockets or alter the existing Router/outbound decision.

use super::{
    flow::{
        AddressFamily, CandidateRejection, NetworkIntentSnapshot, NetworkPath,
        NetworkPathId, PathDecision, PathPlan, PathRejectionReason,
        PathSelectionReason, PathTarget, RouteDecision,
    },
    network::{BindingStatus, DefaultRouteEvidence, PathCandidateObservation},
};

pub(crate) struct PathPlanningResult {
    pub plan: PathPlan,
    pub decision: PathDecision,
}

/// Compile current OS observations and immutable policy into an explainable
/// shadow plan. Preferences rank eligible paths; requirements filter them.
pub(crate) fn compile_path_plan(
    observations: &[PathCandidateObservation],
    intent: &NetworkIntentSnapshot,
    network_generation: u64,
    route: RouteDecision,
    endpoint_family: Option<AddressFamily>,
) -> PathPlanningResult {
    let mut eligible = Vec::new();
    let mut rejected = Vec::new();

    for observation in observations {
        let path = NetworkPath {
            id: NetworkPathId {
                interface: observation.interface.clone(),
                family: observation.family,
                source_address: Some(observation.source_address),
                network_generation,
            },
            interface_kind: observation.interface_kind,
            source_address: Some(observation.source_address),
            scope_id: observation.scope_id,
            gateway: observation.gateway,
        };

        if observation.binding == BindingStatus::Failed {
            rejected.push(CandidateRejection {
                path: path.id,
                reason: PathRejectionReason::Unavailable,
                intent_index: None,
            });
            continue;
        }
        if endpoint_family.is_some_and(|family| family != path.id.family) {
            rejected.push(CandidateRejection {
                path: path.id,
                reason: PathRejectionReason::EndpointFamilyMismatch,
                intent_index: None,
            });
            continue;
        }

        let mut mismatched_requirements = 0;
        for (index, entry) in intent.intents.iter().enumerate() {
            if entry.strength == super::flow::IntentStrength::Require
                && !matches_target(&path, &entry.target)
            {
                rejected.push(CandidateRejection {
                    path: path.id.clone(),
                    reason: PathRejectionReason::RequiredIntentMismatch,
                    intent_index: Some(index),
                });
                mismatched_requirements += 1;
            }
        }
        if mismatched_requirements == 0 {
            eligible.push((path, observation.default_route));
        }
    }

    let has_requirements = intent
        .intents
        .iter()
        .any(|entry| entry.strength == super::flow::IntentStrength::Require);
    let mut selected_index = None;
    let mut reason = PathSelectionReason::NoEligiblePath;

    'preferences: for entry in intent
        .intents
        .iter()
        .filter(|entry| entry.strength == super::flow::IntentStrength::Prefer)
    {
        let matching = eligible
            .iter()
            .enumerate()
            .filter_map(|(index, (path, _))| {
                matches_target(path, &entry.target).then_some(index)
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        match choose_with_default_evidence(&matching, &eligible) {
            Some(index) => {
                selected_index = Some(index);
                reason = PathSelectionReason::Preferred;
            }
            None => reason = PathSelectionReason::AmbiguousPreference,
        }
        break 'preferences;
    }

    if selected_index.is_none() && reason != PathSelectionReason::AmbiguousPreference
    {
        let primary = eligible
            .iter()
            .enumerate()
            .filter_map(|(index, (_, evidence))| {
                (*evidence == DefaultRouteEvidence::PrimaryDefaultRoute)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        match primary.as_slice() {
            [index] => {
                selected_index = Some(*index);
                reason = if has_requirements {
                    PathSelectionReason::Required
                } else {
                    PathSelectionReason::SystemDefault
                };
            }
            [] if has_requirements && eligible.len() == 1 => {
                selected_index = Some(0);
                reason = PathSelectionReason::Required;
            }
            [] if !eligible.is_empty() => {
                reason = PathSelectionReason::NoDefaultRouteEvidence
            }
            [] => reason = PathSelectionReason::NoEligiblePath,
            _ => reason = PathSelectionReason::AmbiguousSystemDefault,
        }
    }

    let candidates = eligible
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let selected = selected_index.map(|index| eligible[index].0.id.clone());
    let plan = PathPlan {
        policy_generation: intent.policy_generation,
        network_generation,
        route,
        candidates,
    };
    let decision = PathDecision {
        policy_generation: intent.policy_generation,
        network_generation,
        selected,
        reason,
        rejected,
    };
    PathPlanningResult { plan, decision }
}

fn choose_with_default_evidence(
    matching: &[usize],
    candidates: &[(NetworkPath, DefaultRouteEvidence)],
) -> Option<usize> {
    match matching {
        [index] => Some(*index),
        _ => {
            let primary = matching
                .iter()
                .copied()
                .filter(|index| {
                    candidates[*index].1 == DefaultRouteEvidence::PrimaryDefaultRoute
                })
                .collect::<Vec<_>>();
            match primary.as_slice() {
                [index] => Some(*index),
                _ => None,
            }
        }
    }
}

fn matches_target(path: &NetworkPath, target: &PathTarget) -> bool {
    match target {
        PathTarget::Interface(interface) => path.id.interface == *interface,
        PathTarget::Kind(kind) => path.interface_kind == *kind,
        PathTarget::Family(family) => path.id.family == *family,
        PathTarget::KindAndFamily { kind, family } => {
            path.interface_kind == *kind && path.id.family == *family
        }
        PathTarget::ExactPath(path_id) => path.id == *path_id,
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::app::flow::{IntentStrength, InterfaceId, InterfaceKind, PathIntent};
    use crate::app::network::BindingStatus;

    fn observation(
        name: &str,
        index: u32,
        kind: InterfaceKind,
        family: AddressFamily,
        default_route: DefaultRouteEvidence,
        binding: BindingStatus,
    ) -> PathCandidateObservation {
        let source_address: IpAddr = match family {
            AddressFamily::Ipv4 => "192.0.2.10".parse().unwrap(),
            AddressFamily::Ipv6 => "2001:db8::10".parse().unwrap(),
        };
        PathCandidateObservation {
            interface: InterfaceId {
                name: name.to_string(),
                index,
            },
            interface_kind: kind,
            family,
            source_address,
            scope_id: None,
            gateway: None,
            default_route,
            binding,
            binding_error: None,
        }
    }

    fn verified(
        name: &str,
        index: u32,
        kind: InterfaceKind,
        family: AddressFamily,
        default_route: DefaultRouteEvidence,
    ) -> PathCandidateObservation {
        observation(
            name,
            index,
            kind,
            family,
            default_route,
            BindingStatus::Verified,
        )
    }

    fn route(outbound: &str) -> RouteDecision {
        RouteDecision {
            outbound: outbound.to_string(),
            rule: Some("MATCH".to_string()),
        }
    }

    #[test]
    fn require_ethernet_and_ipv4_never_falls_back_across_requirements() {
        let observations = [
            verified(
                "wifi0",
                1,
                InterfaceKind::Wifi,
                AddressFamily::Ipv4,
                DefaultRouteEvidence::PrimaryDefaultRoute,
            ),
            verified(
                "eth0",
                2,
                InterfaceKind::Ethernet,
                AddressFamily::Ipv6,
                DefaultRouteEvidence::OtherInterface,
            ),
        ];
        let intent = NetworkIntentSnapshot {
            policy_generation: 4,
            intents: vec![
                PathIntent {
                    strength: IntentStrength::Require,
                    target: PathTarget::Kind(InterfaceKind::Ethernet),
                },
                PathIntent {
                    strength: IntentStrength::Require,
                    target: PathTarget::Family(AddressFamily::Ipv4),
                },
            ],
        };

        let result =
            compile_path_plan(&observations, &intent, 9, route("DIRECT"), None);

        assert!(result.decision.selected.is_none());
        assert_eq!(result.decision.rejected.len(), 2);
        assert_eq!(result.decision.rejected[0].intent_index, Some(0));
        assert_eq!(result.decision.rejected[1].intent_index, Some(1));
        assert!(result.plan.candidates.is_empty());
    }

    #[test]
    fn unavailable_family_preference_falls_back_to_ipv6_default() {
        let observations = [verified(
            "eth0",
            2,
            InterfaceKind::Ethernet,
            AddressFamily::Ipv6,
            DefaultRouteEvidence::PrimaryDefaultRoute,
        )];
        let intent = NetworkIntentSnapshot {
            policy_generation: 5,
            intents: vec![PathIntent {
                strength: IntentStrength::Prefer,
                target: PathTarget::Family(AddressFamily::Ipv4),
            }],
        };

        let result =
            compile_path_plan(&observations, &intent, 10, route("DIRECT"), None);

        assert_eq!(
            result.decision.selected.as_ref().unwrap().family,
            AddressFamily::Ipv6
        );
        assert_eq!(result.decision.reason, PathSelectionReason::SystemDefault);
    }

    #[test]
    fn explicit_preference_order_beats_runtime_candidate_order() {
        let observations = [
            verified(
                "wifi0",
                1,
                InterfaceKind::Wifi,
                AddressFamily::Ipv4,
                DefaultRouteEvidence::PrimaryDefaultRoute,
            ),
            verified(
                "eth0",
                2,
                InterfaceKind::Ethernet,
                AddressFamily::Ipv4,
                DefaultRouteEvidence::OtherInterface,
            ),
        ];
        let intent = NetworkIntentSnapshot {
            policy_generation: 6,
            intents: vec![
                PathIntent {
                    strength: IntentStrength::Prefer,
                    target: PathTarget::Interface(InterfaceId {
                        name: "eth0".to_string(),
                        index: 2,
                    }),
                },
                PathIntent {
                    strength: IntentStrength::Prefer,
                    target: PathTarget::Interface(InterfaceId {
                        name: "wifi0".to_string(),
                        index: 1,
                    }),
                },
            ],
        };

        let result =
            compile_path_plan(&observations, &intent, 11, route("Proxy-A"), None);

        assert_eq!(
            result.decision.selected.as_ref().unwrap().interface.name,
            "eth0"
        );
        assert_eq!(result.decision.reason, PathSelectionReason::Preferred);
        assert_eq!(result.plan.route, route("Proxy-A"));
    }

    #[test]
    fn combined_family_preferences_override_system_default_and_degrade() {
        let ethernet = verified(
            "eth0",
            2,
            InterfaceKind::Ethernet,
            AddressFamily::Ipv4,
            DefaultRouteEvidence::OtherInterface,
        );
        let wifi = verified(
            "wifi0",
            1,
            InterfaceKind::Wifi,
            AddressFamily::Ipv4,
            DefaultRouteEvidence::PrimaryDefaultRoute,
        );
        let preference = |interface| PathIntent {
            strength: IntentStrength::Prefer,
            target: PathTarget::KindAndFamily {
                kind: interface,
                family: AddressFamily::Ipv4,
            },
        };
        let intent = NetworkIntentSnapshot {
            policy_generation: 7,
            intents: vec![
                preference(InterfaceKind::Ethernet),
                preference(InterfaceKind::Wifi),
            ],
        };

        let selected = compile_path_plan(
            &[ethernet, wifi.clone()],
            &intent,
            3,
            route("DIRECT"),
            Some(AddressFamily::Ipv4),
        );
        assert_eq!(selected.decision.selected.unwrap().interface.name, "eth0");

        let unavailable_ethernet = observation(
            "eth0",
            2,
            InterfaceKind::Ethernet,
            AddressFamily::Ipv4,
            DefaultRouteEvidence::OtherInterface,
            BindingStatus::Failed,
        );
        let degraded = compile_path_plan(
            &[unavailable_ethernet, wifi],
            &intent,
            3,
            route("DIRECT"),
            Some(AddressFamily::Ipv4),
        );
        assert_eq!(degraded.decision.selected.unwrap().interface.name, "wifi0");
        assert_eq!(degraded.decision.policy_generation, 7);
    }

    #[test]
    fn proxy_target_does_not_inherit_website_family_hint() {
        let observations = [
            verified(
                "wifi0",
                1,
                InterfaceKind::Wifi,
                AddressFamily::Ipv4,
                DefaultRouteEvidence::PrimaryDefaultRoute,
            ),
            verified(
                "wifi0",
                1,
                InterfaceKind::Wifi,
                AddressFamily::Ipv6,
                DefaultRouteEvidence::PrimaryDefaultRoute,
            ),
        ];

        // The final destination may be IPv4, but the proxy endpoint family is
        // unknown here. The caller therefore passes None and preserves the tie.
        let result = compile_path_plan(
            &observations,
            &NetworkIntentSnapshot::default(),
            12,
            route("Proxy-A"),
            None,
        );

        assert!(result.decision.selected.is_none());
        assert_eq!(
            result.decision.reason,
            PathSelectionReason::AmbiguousSystemDefault
        );
    }

    #[test]
    fn failed_local_bind_is_rejected_and_route_is_retained() {
        let observations = [observation(
            "eth0",
            2,
            InterfaceKind::Ethernet,
            AddressFamily::Ipv4,
            DefaultRouteEvidence::PrimaryDefaultRoute,
            BindingStatus::Failed,
        )];

        let result = compile_path_plan(
            &observations,
            &NetworkIntentSnapshot::default(),
            13,
            route("DIRECT"),
            Some(AddressFamily::Ipv4),
        );

        assert!(result.decision.selected.is_none());
        assert_eq!(result.decision.rejected.len(), 1);
        assert_eq!(
            result.decision.rejected[0].reason,
            PathRejectionReason::Unavailable
        );
        assert_eq!(result.plan.route.outbound, "DIRECT");
    }

    #[test]
    fn known_direct_endpoint_family_filters_other_candidates() {
        let observations = [
            verified(
                "eth0",
                2,
                InterfaceKind::Ethernet,
                AddressFamily::Ipv4,
                DefaultRouteEvidence::PrimaryDefaultRoute,
            ),
            verified(
                "eth0",
                2,
                InterfaceKind::Ethernet,
                AddressFamily::Ipv6,
                DefaultRouteEvidence::PrimaryDefaultRoute,
            ),
        ];

        let result = compile_path_plan(
            &observations,
            &NetworkIntentSnapshot::default(),
            14,
            route("DIRECT"),
            Some(AddressFamily::Ipv4),
        );

        assert_eq!(
            result.decision.selected.as_ref().unwrap().family,
            AddressFamily::Ipv4
        );
        assert_eq!(result.decision.rejected.len(), 1);
        assert_eq!(
            result.decision.rejected[0].reason,
            PathRejectionReason::EndpointFamilyMismatch
        );
    }

    #[test]
    fn same_interface_family_source_addresses_have_distinct_path_ids() {
        let first = verified(
            "eth0",
            2,
            InterfaceKind::Ethernet,
            AddressFamily::Ipv4,
            DefaultRouteEvidence::OtherInterface,
        );
        let mut second = first.clone();
        second.source_address = "192.0.2.11".parse().unwrap();
        let result = compile_path_plan(
            &[first, second],
            &NetworkIntentSnapshot::default(),
            15,
            route("DIRECT"),
            None,
        );

        assert_eq!(result.plan.candidates.len(), 2);
        assert_ne!(result.plan.candidates[0].id, result.plan.candidates[1].id);
        assert_eq!(
            result.decision.reason,
            PathSelectionReason::NoDefaultRouteEvidence
        );
    }
}
