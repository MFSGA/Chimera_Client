//! Deterministic, side-effect-free candidate selection for a future Smart group.
//!
//! This is only the selection policy. Group parsing, health reporting, provider
//! updates, dialing, and persisted statistics are not wired up yet.
use std::time::Duration;

/// A single candidate's most recent, already collected health observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate<'a> {
    pub name: &'a str,
    pub alive: bool,
    pub last_delay: Option<Duration>,
    pub consecutive_failures: u32,
}

/// Choose an eligible candidate in provider order, returning its index.
///
/// Only alive candidates are eligible. Prefer fewer consecutive failures, then
/// lower known delay, retaining provider order on ties. A missing delay sorts
/// after measured delays. If the previously chosen name is still alive, has
/// the same failure count as the best candidate, and is within the delay
/// tolerance, retain it to prevent needless switching. Names rather than
/// indices preserve stickiness when a provider reorders its candidates.
///
/// An empty or entirely unhealthy candidate set has no selection; it must
/// never silently pick a dead endpoint.
pub fn choose(
    candidates: &[Candidate<'_>],
    previous_name: Option<&str>,
    tolerance: Duration,
) -> Option<usize> {
    let score = |candidate: &Candidate<'_>| {
        (
            candidate.consecutive_failures,
            candidate.last_delay.unwrap_or(Duration::MAX),
        )
    };

    let (best_index, best) = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.alive)
        .min_by_key(|(_, candidate)| score(candidate))?;

    if let Some(previous_name) = previous_name
        && let Some((index, previous)) =
            candidates.iter().enumerate().find(|(_, candidate)| {
                candidate.alive && candidate.name == previous_name
            })
        && previous.consecutive_failures == best.consecutive_failures
        && previous.last_delay.unwrap_or(Duration::MAX)
            <= best
                .last_delay
                .unwrap_or(Duration::MAX)
                .saturating_add(tolerance)
    {
        return Some(index);
    }

    Some(best_index)
}

#[cfg(test)]
mod tests {
    use super::{Candidate, choose};
    use std::time::Duration;

    fn candidate(
        name: &'static str,
        alive: bool,
        delay_ms: Option<u64>,
        failures: u32,
    ) -> Candidate<'static> {
        Candidate {
            name,
            alive,
            last_delay: delay_ms.map(Duration::from_millis),
            consecutive_failures: failures,
        }
    }

    #[test]
    fn no_candidate_or_no_healthy_candidate_never_selects_a_dead_endpoint() {
        assert_eq!(choose(&[], None, Duration::ZERO), None);
        assert_eq!(
            choose(
                &[candidate("dead", false, Some(1), 0)],
                Some("dead"),
                Duration::ZERO
            ),
            None
        );
    }

    #[test]
    fn fewer_failures_win_before_latency_and_ties_keep_provider_order() {
        let candidates = [
            candidate("flaky", true, Some(1), 2),
            candidate("stable", true, Some(80), 0),
            candidate("stable-two", true, Some(80), 0),
        ];
        assert_eq!(choose(&candidates, None, Duration::ZERO), Some(1));
    }

    #[test]
    fn measured_latency_wins_over_unknown_latency() {
        let candidates = [
            candidate("unmeasured", true, None, 0),
            candidate("measured", true, Some(50), 0),
        ];
        assert_eq!(choose(&candidates, None, Duration::ZERO), Some(1));
    }

    #[test]
    fn previous_name_survives_provider_reordering_within_tolerance() {
        let candidates = [
            candidate("fast", true, Some(30), 0),
            candidate("previous", true, Some(45), 0),
        ];
        assert_eq!(
            choose(&candidates, Some("previous"), Duration::from_millis(20)),
            Some(1)
        );
        assert_eq!(
            choose(&candidates, Some("previous"), Duration::from_millis(14)),
            Some(0)
        );
    }

    #[test]
    fn dead_or_unreliable_previous_candidate_is_replaced() {
        let candidates = [
            candidate("fast", true, Some(30), 0),
            candidate("previous", true, Some(1), 3),
        ];
        assert_eq!(
            choose(&candidates, Some("previous"), Duration::MAX),
            Some(0)
        );
        let candidates = [
            candidate("fast", true, Some(30), 0),
            candidate("previous", false, Some(1), 0),
        ];
        assert_eq!(
            choose(&candidates, Some("previous"), Duration::MAX),
            Some(0)
        );
    }

    #[test]
    fn tolerance_overflow_is_saturated() {
        let candidates = [
            candidate("fast", true, Some(20), 0),
            candidate("current", true, None, 0),
        ];
        assert_eq!(choose(&candidates, Some("current"), Duration::MAX), Some(1));
    }
}
