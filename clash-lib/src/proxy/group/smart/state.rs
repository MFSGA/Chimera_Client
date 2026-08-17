use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{app::remote_content_manager::TrafficStats, session::Session};

use super::{
    penalty::ProxyPenalty,
    stats::{SiteStats, TrafficStatsCollector},
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmartStateData {
    pub penalty: HashMap<String, ProxyPenalty>,
    pub site_stats: HashMap<String, HashMap<String, SiteStats>>,
}

pub struct SmartState {
    penalty: HashMap<String, ProxyPenalty>,
    pub site_stats: HashMap<String, HashMap<String, SiteStats>>,
    traffic_collector: TrafficStatsCollector,
}

impl SmartState {
    pub fn new() -> Self {
        Self {
            penalty: HashMap::new(),
            site_stats: HashMap::new(),
            traffic_collector: TrafficStatsCollector::new(),
        }
    }

    pub fn new_with_imported_data(data: Option<SmartStateData>) -> Self {
        if let Some(data) = data {
            Self {
                penalty: data.penalty,
                site_stats: data.site_stats,
                traffic_collector: TrafficStatsCollector::new(),
            }
        } else {
            Self::new()
        }
    }

    pub fn get_penalty_mut(&mut self, proxy_name: &str) -> &mut ProxyPenalty {
        self.penalty.entry(proxy_name.to_string()).or_default()
    }

    pub fn get_penalty(&self, proxy_name: &str) -> Option<&ProxyPenalty> {
        self.penalty.get(proxy_name)
    }

    pub fn get_site_stats_mut(
        &mut self,
        proxy_name: &str,
        site: &str,
    ) -> &mut SiteStats {
        self.site_stats
            .entry(proxy_name.to_string())
            .or_default()
            .entry(site.to_string())
            .or_default()
    }

    pub fn get_site_stats(
        &self,
        proxy_name: &str,
        site: &str,
    ) -> Option<&SiteStats> {
        self.site_stats
            .get(proxy_name)
            .and_then(|sites| sites.get(site))
    }

    pub fn record_connection_result(
        &mut self,
        proxy_name: &str,
        site: &str,
        dest_ip: Option<&str>,
        delay: f64,
        success: bool,
    ) {
        let penalty = self.get_penalty_mut(proxy_name);
        if success {
            penalty.reward();
        } else {
            penalty.add_penalty();
        }

        self.get_site_stats_mut(proxy_name, site)
            .add_result(delay, success);
        if let Some(ip) = dest_ip {
            self.get_site_stats_mut(proxy_name, ip)
                .add_result(delay, success);
        }
    }

    pub fn generate_session_id(sess: &Session) -> String {
        format!("{}:{}->{}", sess.network, sess.source, sess.destination)
    }

    pub fn start_traffic_tracking(&mut self, sess: &Session) {
        let session_id = Self::generate_session_id(sess);
        self.traffic_collector.start_session(&session_id);
    }

    pub fn record_traffic(
        &mut self,
        sess: &Session,
        uploaded: u64,
        downloaded: u64,
    ) {
        let session_id = Self::generate_session_id(sess);
        self.traffic_collector
            .record_transfer(&session_id, uploaded, downloaded);
    }

    pub fn record_request(&mut self, sess: &Session) {
        let session_id = Self::generate_session_id(sess);
        self.traffic_collector.record_request(&session_id);
    }

    pub fn get_traffic_stats(&self, sess: &Session) -> Option<TrafficStats> {
        let session_id = Self::generate_session_id(sess);
        self.traffic_collector.get_stats(&session_id)
    }

    pub fn cleanup_stale(&mut self) {
        self.site_stats.retain(|_, sites| {
            sites.retain(|_, site_stat| !site_stat.is_stale());
            !sites.is_empty()
        });
        self.traffic_collector.cleanup_old_sessions();

        let negligible_threshold = 0.01;
        self.penalty.retain(|_, penalty| {
            penalty.decay();
            penalty.value() > negligible_threshold
        });
    }

    pub fn export_data(&self) -> SmartStateData {
        SmartStateData {
            penalty: self.penalty.clone(),
            site_stats: self.site_stats.clone(),
        }
    }
}

impl Default for SmartState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::session::SocksAddr;

    use super::*;

    #[test]
    fn failure_updates_penalty_and_site_stats() {
        let mut state = SmartState::new();
        state.record_connection_result(
            "proxy1",
            "example.com",
            Some("203.0.113.7"),
            1000.0,
            false,
        );

        assert!(state.get_penalty("proxy1").unwrap().value() > 0.0);
        assert_eq!(
            state
                .get_site_stats("proxy1", "example.com")
                .unwrap()
                .success_rate(),
            0.0
        );
        assert!(state.get_site_stats("proxy1", "203.0.113.7").is_some());
    }

    #[test]
    fn success_rewards_existing_penalty() {
        let mut state = SmartState::new();
        state.record_connection_result("proxy1", "example.com", None, 1000.0, false);
        let before = state.get_penalty("proxy1").unwrap().value();

        state.record_connection_result("proxy1", "example.com", None, 100.0, true);
        assert!(state.get_penalty("proxy1").unwrap().value() < before);
    }

    #[test]
    fn traffic_tracking_uses_session_identity() {
        let mut state = SmartState::new();
        let mut session = Session::default();
        session.destination = SocksAddr::Domain("example.com".to_string(), 443);

        state.start_traffic_tracking(&session);
        state.record_traffic(&session, 123, 456);
        state.record_request(&session);

        let stats = state.get_traffic_stats(&session).unwrap();
        assert_eq!(stats.bytes_uploaded, 123);
        assert_eq!(stats.bytes_downloaded, 456);
        assert!(stats.request_frequency > 0.0);
    }

    #[test]
    fn exported_state_can_be_imported() {
        let mut state = SmartState::new();
        state.record_connection_result("proxy1", "example.com", None, 100.0, true);
        let restored = SmartState::new_with_imported_data(Some(state.export_data()));

        assert!(restored.get_penalty("proxy1").is_some());
        assert!(restored.get_site_stats("proxy1", "example.com").is_some());
    }
}
