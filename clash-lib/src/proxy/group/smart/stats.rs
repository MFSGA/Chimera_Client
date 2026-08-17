use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::{
    app::remote_content_manager::TrafficStats, common::utils::current_timestamp_secs,
};
use serde::{Deserialize, Serialize};

const MAX_HISTORY_SIZE: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteStats {
    pub delay_history: Vec<f64>,
    pub success_history: Vec<bool>,
    last_attempt_secs: u64,
}

impl SiteStats {
    pub fn new() -> Self {
        Self {
            delay_history: Vec::with_capacity(MAX_HISTORY_SIZE),
            success_history: Vec::with_capacity(MAX_HISTORY_SIZE),
            last_attempt_secs: current_timestamp_secs(),
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.success_history.is_empty() {
            return 0.0;
        }

        let success_count = self.success_history.iter().filter(|&&x| x).count();
        success_count as f64 / self.success_history.len() as f64
    }

    pub fn add_result(&mut self, delay: f64, success: bool) {
        if success {
            if self.delay_history.len() >= MAX_HISTORY_SIZE {
                self.delay_history.remove(0);
            }
            self.delay_history.push(delay);
        }

        if self.success_history.len() >= MAX_HISTORY_SIZE {
            self.success_history.remove(0);
        }
        self.success_history.push(success);
        self.last_attempt_secs = current_timestamp_secs();
    }

    pub fn is_stale(&self) -> bool {
        current_timestamp_secs().saturating_sub(self.last_attempt_secs) > 300
    }

    pub fn get_delay_score(&self) -> f64 {
        if self.delay_history.is_empty() {
            return 9999.0;
        }

        let mut sum = 0.0;
        let mut weight_sum = 0.0;
        let age_secs =
            current_timestamp_secs().saturating_sub(self.last_attempt_secs) as f64;

        for delay in &self.delay_history {
            let time_weight = (-0.1 * age_secs).exp();
            let delay_weight = (-0.001 * *delay).exp();
            let weight = time_weight * delay_weight;
            sum += delay * weight;
            weight_sum += weight;
        }

        let avg_delay = if weight_sum > 0.0 {
            sum / weight_sum
        } else {
            9999.0
        };

        avg_delay * (2.0 - self.success_rate())
    }

    pub fn get_trend(&self) -> i8 {
        if self.delay_history.len() < 3 {
            return 0;
        }

        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;
        let n = self.delay_history.len() as f64;

        for (i, &y) in self.delay_history.iter().enumerate() {
            let x = i as f64;
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);

        if slope < -0.5 {
            1
        } else if slope > 0.5 {
            -1
        } else {
            0
        }
    }

    pub fn latency_stability(&self) -> f64 {
        if self.delay_history.is_empty() {
            return 0.0;
        }

        let mean =
            self.delay_history.iter().sum::<f64>() / self.delay_history.len() as f64;
        let variance = self
            .delay_history
            .iter()
            .map(|&delay| (delay - mean).powi(2))
            .sum::<f64>()
            / self.delay_history.len() as f64;
        variance.sqrt()
    }
}

impl Default for SiteStats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TrafficStatsCollector {
    connection_start: HashMap<String, Instant>,
    session_bytes: HashMap<String, (u64, u64)>,
    request_counts: HashMap<String, VecDeque<Instant>>,
    throughput_samples: HashMap<String, VecDeque<(Instant, f64)>>,
}

impl TrafficStatsCollector {
    pub fn new() -> Self {
        Self {
            connection_start: HashMap::new(),
            session_bytes: HashMap::new(),
            request_counts: HashMap::new(),
            throughput_samples: HashMap::new(),
        }
    }

    pub fn start_session(&mut self, session_id: &str) {
        self.connection_start
            .insert(session_id.to_string(), Instant::now());
        self.session_bytes.insert(session_id.to_string(), (0, 0));
        self.request_counts
            .insert(session_id.to_string(), VecDeque::new());
        self.throughput_samples
            .insert(session_id.to_string(), VecDeque::new());
    }

    pub fn record_transfer(
        &mut self,
        session_id: &str,
        uploaded: u64,
        downloaded: u64,
    ) {
        if let Some((up, down)) = self.session_bytes.get_mut(session_id) {
            *up += uploaded;
            *down += downloaded;

            if let Some(start_time) = self.connection_start.get(session_id) {
                let elapsed = start_time.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    let current_throughput =
                        (uploaded + downloaded) as f64 / elapsed;
                    if let Some(samples) =
                        self.throughput_samples.get_mut(session_id)
                    {
                        samples.push_back((Instant::now(), current_throughput));
                        if samples.len() > 10 {
                            samples.pop_front();
                        }
                    }
                }
            }
        }
    }

    pub fn record_request(&mut self, session_id: &str) {
        if let Some(requests) = self.request_counts.get_mut(session_id) {
            requests.push_back(Instant::now());
            let cutoff = Instant::now() - Duration::from_secs(60);
            while let Some(&front_time) = requests.front() {
                if front_time < cutoff {
                    requests.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    pub fn get_stats(&self, session_id: &str) -> Option<TrafficStats> {
        let start_time = self.connection_start.get(session_id)?;
        let (uploaded, downloaded) = self.session_bytes.get(session_id)?;
        let connection_duration = start_time.elapsed();
        let total_bytes = uploaded + downloaded;

        let average_throughput = if connection_duration.as_secs_f64() > 0.0 {
            total_bytes as f64 / connection_duration.as_secs_f64()
        } else {
            0.0
        };

        let peak_throughput = self
            .throughput_samples
            .get(session_id)
            .map(|samples| {
                samples
                    .iter()
                    .map(|(_, throughput)| *throughput)
                    .fold(0.0, f64::max)
            })
            .unwrap_or(0.0);

        let request_frequency = self
            .request_counts
            .get(session_id)
            .map(|requests| requests.len() as f64 / 60.0)
            .unwrap_or(0.0);

        let is_bidirectional = if total_bytes > 0 {
            let upload_ratio = *uploaded as f64 / total_bytes as f64;
            upload_ratio > 0.1 && upload_ratio < 0.9
        } else {
            false
        };

        Some(TrafficStats {
            bytes_uploaded: *uploaded,
            bytes_downloaded: *downloaded,
            connection_duration,
            average_throughput,
            peak_throughput,
            request_frequency,
            is_bidirectional,
        })
    }

    pub fn cleanup_old_sessions(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(300);
        self.connection_start
            .retain(|_, start_time| *start_time > cutoff);
        self.session_bytes
            .retain(|session_id, _| self.connection_start.contains_key(session_id));
        self.request_counts
            .retain(|session_id, _| self.connection_start.contains_key(session_id));
        self.throughput_samples
            .retain(|session_id, _| self.connection_start.contains_key(session_id));
    }
}

impl Default for TrafficStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_stats_success_rate_matches_reference() {
        let mut stats = SiteStats::new();
        stats.add_result(100.0, true);
        stats.add_result(150.0, true);
        stats.add_result(200.0, false);

        assert_eq!(stats.success_rate(), 2.0 / 3.0);
        assert!(stats.get_delay_score() > 0.0);
    }

    #[test]
    fn failed_connection_does_not_enter_delay_history() {
        let mut stats = SiteStats::new();
        stats.add_result(100.0, true);
        stats.add_result(200.0, true);
        stats.add_result(300.0, false);

        assert_eq!(stats.delay_history, vec![100.0, 200.0]);
        let score = stats.get_delay_score();
        assert!(score > 0.0);
        assert!(score < 9999.0);
    }

    #[test]
    fn decreasing_delay_history_reports_improving_trend() {
        let mut stats = SiteStats::new();
        stats.add_result(100.0, false);
        stats.add_result(100.0, false);
        stats.add_result(150.0, true);
        stats.add_result(120.0, true);
        stats.add_result(100.0, true);

        assert_eq!(stats.get_trend(), 1);
    }

    #[test]
    fn histories_keep_only_ten_most_recent_results() {
        let mut stats = SiteStats::new();
        for delay in 0..12 {
            stats.add_result(delay as f64, true);
        }

        assert_eq!(stats.delay_history.len(), MAX_HISTORY_SIZE);
        assert_eq!(stats.success_history.len(), MAX_HISTORY_SIZE);
        assert_eq!(stats.delay_history[0], 2.0);
    }

    #[test]
    fn traffic_collector_matches_reference_counters() {
        let mut collector = TrafficStatsCollector::new();
        collector.start_session("test-session");
        collector.record_transfer("test-session", 1000, 2000);
        collector.record_request("test-session");

        let stats = collector
            .get_stats("test-session")
            .expect("tracked session should have stats");
        assert_eq!(stats.bytes_uploaded, 1000);
        assert_eq!(stats.bytes_downloaded, 2000);
        assert!(stats.is_bidirectional);
        assert!(stats.request_frequency > 0.0);
    }

    #[test]
    fn unknown_session_has_no_traffic_stats() {
        let collector = TrafficStatsCollector::new();
        assert!(collector.get_stats("missing").is_none());
    }
}
