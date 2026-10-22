//! S02 side-effect-free DNS planning. Execution remains behind the S01 gate
//! until S03 validates outbound selection, fallback and cache isolation.
//!
//! The caller supplies a snapshot of the *existing* legacy route. The planner
//! does not reimplement nameserver-policy, Fake-IP, routing or fallback logic;
//! it preserves that route as an opaque executable contract for S03.

use hickory_proto::{
    op::{Message, MessageType, OpCode},
    rr::{DNSClass, RecordType},
};

use crate::Error;

use super::policy::{CompiledDnsPolicy, DnsEgress, DnsFailure, canonical_domain};

/// Why a real DNS answer may be needed. Not an outbound/business target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPurpose {
    ClientRealAnswer,
    RouteClassification,
    DirectDestination,
    ProxyDestinationLocal,
    ProxyNodeBootstrap,
    ResolverBootstrap,
    Diagnostic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsSourceScope {
    Host,
    Gateway { namespace: String },
}

/// Relevant request metadata is carried forward for future S04 cache keys.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsQueryFlags {
    pub recursion_desired: bool,
    pub checking_disabled: bool,
    pub authentic_data: bool,
    pub has_edns: bool,
    pub dnssec_ok: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQueryContext {
    pub qname: String,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub purpose: DnsPurpose,
    pub source: DnsSourceScope,
    pub network_generation: u64,
    pub config_generation: u64,
    pub flags: DnsQueryFlags,
}

impl DnsQueryContext {
    pub fn new(
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        purpose: DnsPurpose,
    ) -> Result<Self, Error> {
        Ok(Self {
            qname: canonical_domain(qname, "DNS query name")?,
            qtype,
            qclass,
            purpose,
            source: DnsSourceScope::Host,
            network_generation: 0,
            config_generation: 0,
            flags: DnsQueryFlags::default(),
        })
    }

    /// Reject multi-question requests instead of applying one policy to all
    /// questions. No implicit network operations or DNS lookups are performed.
    pub fn from_message(
        message: &Message,
        purpose: DnsPurpose,
    ) -> Result<Self, Error> {
        if message.metadata.message_type != MessageType::Query
            || message.metadata.op_code != OpCode::Query
            || message.queries.len() != 1
        {
            return Err(Error::InvalidConfig(
                "dns query plan requires exactly one standard DNS Question"
                    .to_owned(),
            ));
        }
        let question = &message.queries[0];
        let mut context = Self::new(
            &question.name().to_ascii(),
            question.query_type(),
            question.query_class(),
            purpose,
        )?;
        context.flags = DnsQueryFlags {
            recursion_desired: message.metadata.recursion_desired,
            checking_disabled: message.metadata.checking_disabled,
            authentic_data: message.metadata.authentic_data,
            has_edns: message.edns.is_some(),
            dnssec_ok: message
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok),
        };
        Ok(context)
    }
}

/// Names of legacy paths only; their original request execution, fallback,
/// caching and local-answer behavior are NOT reimplemented in S02.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyDnsRoute {
    /// Fake-IP/hosts answer: no upstream should be queried by a DNS policy.
    LocalAnswer,
    Main,
    /// Primary, then fallback based on the actual response and IP filters.
    MainWithResponseDependentFallback,
    FallbackOnly,
    NameserverPolicy {
        selector: String,
    },
    ProxyServerNameserver,
    /// Existing direct-nameserver resolver with its main-DNS fallback logic.
    DirectWithMainFallback,
}

/// An exact token supplied by the legacy decision-maker (not guessed from
/// QTYPE or purpose). S03 will use this to delegate to legacy unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyDnsPlan {
    pub route: LegacyDnsRoute,
}

impl LegacyDnsPlan {
    pub fn new(route: LegacyDnsRoute) -> Self {
        Self { route }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolverChoice {
    InheritLegacy,
    Profile(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgressChoice {
    InheritLegacy,
    Explicit(DnsEgress),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureChoice {
    InheritLegacy,
    Explicit(DnsFailure),
}

/// The overlay is declarative and non-executable. Inherited dimensions never
/// silently become DIRECT, a default resolver or an invented failure policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveDnsPlan {
    pub context: DnsQueryContext,
    pub legacy: LegacyDnsPlan,
    pub matched_rule: Option<usize>,
    pub resolver: ResolverChoice,
    pub egress: EgressChoice,
    pub failure: FailureChoice,
}

impl CompiledDnsPolicy {
    /// Plan only. No resolver construction, outbound selection, DNS lookup,
    /// cache access or business route matching occurs here.
    pub fn build_effective_plan(
        &self,
        context: DnsQueryContext,
        legacy: LegacyDnsPlan,
    ) -> Result<EffectiveDnsPlan, Error> {
        let mut result = EffectiveDnsPlan {
            context,
            legacy,
            matched_rule: None,
            resolver: ResolverChoice::InheritLegacy,
            egress: EgressChoice::InheritLegacy,
            failure: FailureChoice::InheritLegacy,
        };

        // ClientAnswerPolicy must remain authoritative for Fake-IP and hosts.
        // The S01 matcher does not define special handling for non-IN classes.
        if result.legacy.route == LegacyDnsRoute::LocalAnswer
            || result.context.qclass != DNSClass::IN
        {
            return Ok(result);
        }

        let Some(rule) =
            self.match_query(&result.context.qname, result.context.qtype)
        else {
            return Ok(result);
        };
        result.matched_rule = Some(rule.ordinal);
        if let Some(resolver) = &rule.action.resolver {
            if !self.profiles.contains_key(resolver) {
                return Err(Error::InvalidConfig(format!(
                    "dns plan rule[{}] references a missing resolver profile '{resolver}'",
                    rule.ordinal
                )));
            }
            result.resolver = ResolverChoice::Profile(resolver.clone());
        }
        if let Some(egress) = &rule.action.egress {
            result.egress = EgressChoice::Explicit(egress.clone());
        }
        if let Some(failure) = &rule.action.on_failure {
            result.failure = FailureChoice::Explicit(failure.clone());
        }
        Ok(result)
    }
}
