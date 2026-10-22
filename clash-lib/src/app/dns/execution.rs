//! S03a: strict, opt-in DNS outbound preflight and mockable transport boundary.
//!
//! No live resolver calls this module yet. A matched policy must not fall
//! through to the legacy path when explicit DNS egress cannot be enforced.

use std::{io, sync::Arc, time::Duration};

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, ResponseCode};

use crate::{
    config::internal::proxy::PROXY_DIRECT,
    proxy::{
        AnyOutboundHandler, OutboundType, direct, group::selector::PinnedOutbound,
        utils::OutboundHandlerRegistry,
    },
    session::Session,
};

use super::{
    config::NameServer,
    plan::{
        EffectiveDnsPlan, EgressChoice, FailureChoice, LegacyDnsPlan,
        LegacyDnsRoute, ResolverChoice,
    },
    policy::{CompiledDnsPolicy, DnsEgress, DnsFailure},
};

/// Network operations in S03b must use the exact chosen handler and server.
/// The transport cannot request a different (e.g. DIRECT) outbound from this
/// interface. S03a tests use fake implementations; no DNS socket is created.
#[async_trait]
pub trait DnsStrictTransport: Send + Sync {
    async fn exchange(
        &self,
        server: &NameServer,
        outbound: AnyOutboundHandler,
        query: &Message,
    ) -> io::Result<Message>;
}

pub enum PreparedDnsExecution {
    /// The legacy resolver owns local Fake-IP/hosts responses.
    LocalAnswer,
    /// Unmatched policies are delegated wholly to the existing resolver.
    Legacy(LegacyDnsPlan),
    /// Explicit policy with a pinned handler and a named resolver profile.
    Strict(StrictDnsExecution),
}

pub struct StrictDnsExecution {
    pub ordinal: usize,
    pub egress: DnsEgress,
    pub profile: String,
    pub servers: Vec<NameServer>,
    pub outbound: AnyOutboundHandler,
}

impl StrictDnsExecution {
    /// Retry only within the declared resolver profile, always through the
    /// SAME pinned outbound. Never invoke legacy fallback or business Router.
    /// A failed proxy cannot be retried via DIRECT.
    pub async fn exchange<T: DnsStrictTransport>(
        &self,
        transport: &T,
        request: &Message,
    ) -> io::Result<Message> {
        // Keep the WHOLE strict attempt bounded, including retries among
        // servers in the same declared profile. No network dial can remain
        // stuck indefinitely in this execution layer.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut failures = Vec::with_capacity(self.servers.len());
        for server in &self.servers {
            let result = tokio::time::timeout_at(
                deadline,
                transport.exchange(server, self.outbound.clone(), request),
            )
            .await;
            match result {
                Ok(Ok(answer))
                    if answer.metadata.message_type == MessageType::Response
                        && answer.metadata.id == request.metadata.id
                        && answer.queries == request.queries
                        && !answer.metadata.truncation
                        && matches!(
                            answer.metadata.response_code,
                            ResponseCode::NoError | ResponseCode::NXDomain
                        ) =>
                {
                    return Ok(answer);
                }
                Ok(Ok(answer)) => failures.push(format!(
                    "{server}: invalid, truncated or unsuccessful DNS response (rcode {})",
                    answer.metadata.response_code
                )),
                Ok(Err(error)) => failures.push(format!("{server}: {error}")),
                Err(_) => {
                    failures.push(format!("{server}: strict DNS total deadline exceeded"));
                    break;
                }
            }
        }
        Err(io::Error::other(format!(
            "strict DNS rule[{}] profile '{}' failed via {:?};              no DIRECT/legacy fallback permitted: {}",
            self.ordinal,
            self.profile,
            self.egress,
            failures.join("; ")
        )))
    }
}

/// Prepare one immutable egress decision from an S02 plan. This is not the
/// production DNS runtime activation path: it is deliberately strict about
/// unimplemented partial-override semantics.
pub async fn prepare_dns_execution(
    plan: &EffectiveDnsPlan,
    profiles: &CompiledDnsPolicy,
    registry: &OutboundHandlerRegistry,
    session: &Session,
) -> io::Result<PreparedDnsExecution> {
    if plan.legacy.route == LegacyDnsRoute::LocalAnswer {
        return Ok(PreparedDnsExecution::LocalAnswer);
    }
    let Some(ordinal) = plan.matched_rule else {
        return Ok(PreparedDnsExecution::Legacy(plan.legacy.clone()));
    };

    // Preserve partial actions in S02, but don't pretend that an inherited
    // resolver/fallback can already satisfy a strict egress failure policy.
    let ResolverChoice::Profile(profile) = &plan.resolver else {
        return Err(io::Error::other(format!(
            "strict DNS rule[{ordinal}] cannot yet execute without an explicit resolver profile"
        )));
    };
    let EgressChoice::Explicit(egress) = &plan.egress else {
        return Err(io::Error::other(format!(
            "strict DNS rule[{ordinal}] cannot yet execute without an explicit DNS egress"
        )));
    };
    if plan.failure != FailureChoice::Explicit(DnsFailure::Fail) {
        return Err(io::Error::other(format!(
            "strict DNS rule[{ordinal}] requires on-failure: fail until bounded inheritance is implemented"
        )));
    }
    let servers = profiles.profiles.get(profile).filter(|v| !v.is_empty()).ok_or_else(|| {
        io::Error::other(format!(
            "strict DNS rule[{ordinal}] resolver profile '{profile}' is unavailable"
        ))
    })?;

    // S01 disallows forced #proxy/#interface with explicit egress. Recheck at
    // runtime too: the profile is held in public mutable compiled data.
    if servers
        .iter()
        .any(|s| s.proxy.is_some() || s.interface.is_some())
    {
        return Err(io::Error::other(format!(
            "strict DNS rule[{ordinal}] profile '{profile}' conflicts with #proxy/#interface"
        )));
    }

    let outbound: AnyOutboundHandler = match egress {
        DnsEgress::Direct => Arc::new(direct::Handler::new(PROXY_DIRECT)),
        DnsEgress::Proxy(name) => {
            // NEVER use SharedOutboundHandler: missing names silently map to DIRECT.
            let named = registry.read().await.get(name).cloned().ok_or_else(|| {
                io::Error::other(format!(
                    "strict DNS rule[{ordinal}] proxy '{name}' missing; refusing DIRECT fallback"
                ))
            })?;
            let pinned = PinnedOutbound::capture(named, session).await.map_err(|error| {
                io::Error::other(format!(
                    "strict DNS rule[{ordinal}] proxy '{name}' unavailable: {error}"
                ))
            })?;
            if matches!(
                pinned.handler.proto(),
                OutboundType::Direct | OutboundType::Reject
            ) {
                return Err(io::Error::other(format!(
                    "strict DNS rule[{ordinal}] proxy '{name}' selected a DIRECT/REJECT leaf;                      refusing downgrade"
                )));
            }
            pinned.handler
        }
    };

    Ok(PreparedDnsExecution::Strict(StrictDnsExecution {
        ordinal,
        egress: egress.clone(),
        profile: profile.clone(),
        servers: servers.clone(),
        outbound,
    }))
}

#[cfg(test)]
mod tests;
