//! Penalty mechanism for smart proxy group.

use crate::common::utils::current_timestamp_secs;

/// Tracks and manages the penalty score for a proxy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyPenalty {
    value: f64,
    last_update_secs: u64,
}

impl ProxyPenalty {
    #[inline]
    pub fn new() -> Self {
        Self {
            value: 0.0,
            last_update_secs: current_timestamp_secs(),
        }
    }

    #[inline]
    pub fn value(&self) -> f64 {
        self.value
    }

    #[inline]
    pub fn add_penalty(&mut self) {
        self.value = (self.value + 1.0) * 2.0;
        self.last_update_secs = current_timestamp_secs();
    }

    #[inline]
    pub fn decay(&mut self) {
        let now_secs = current_timestamp_secs();
        let elapsed_secs = now_secs.saturating_sub(self.last_update_secs) as f64;

        if self.value < 0.01 || elapsed_secs > 300.0 {
            self.value = 0.0;
        } else if elapsed_secs > 0.0 {
            self.value *= 0.5f64.powf(elapsed_secs / 10.0);
        }
        self.last_update_secs = now_secs;
    }

    #[inline]
    pub fn reward(&mut self) {
        self.value *= 0.2;
        self.last_update_secs = current_timestamp_secs();
    }
}

impl Default for ProxyPenalty {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::common::utils::current_timestamp_secs;

    use super::*;

    #[test]
    fn penalty_creation_starts_at_zero() {
        let penalty = ProxyPenalty::new();
        assert_eq!(penalty.value(), 0.0);
    }

    #[test]
    fn penalty_growth_matches_reference_curve() {
        let mut penalty = ProxyPenalty::new();

        penalty.add_penalty();
        assert_eq!(penalty.value(), 2.0);
        penalty.add_penalty();
        assert_eq!(penalty.value(), 6.0);
        penalty.add_penalty();
        assert_eq!(penalty.value(), 14.0);
    }

    #[test]
    fn reward_reduces_penalty_by_eighty_percent() {
        let mut penalty = ProxyPenalty::new();
        penalty.add_penalty();
        penalty.add_penalty();

        penalty.reward();
        assert!((penalty.value() - 1.2).abs() < 1e-6);
        penalty.reward();
        assert!((penalty.value() - 0.24).abs() < 1e-6);
    }

    #[test]
    fn decay_halves_penalty_after_ten_seconds() {
        let mut penalty = ProxyPenalty::new();
        penalty.add_penalty();

        penalty.last_update_secs = current_timestamp_secs().saturating_sub(10);
        penalty.decay();

        assert!((penalty.value() - 1.0).abs() < 0.1);
    }
}
