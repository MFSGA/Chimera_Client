use crate::{
    app::router::rules::RuleMatcher,
    session::{Network, Session},
};

#[derive(Clone)]
pub struct NetworkRule {
    pub network: Network,
    pub target: String,
}

impl std::fmt::Display for NetworkRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} network {}", self.target, self.network)
    }
}

impl RuleMatcher for NetworkRule {
    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.network.to_string()
    }

    fn apply(&self, sess: &Session) -> bool {
        sess.network == self.network
    }

    fn type_name(&self) -> &str {
        "Network"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_tcp_session() {
        let rule = NetworkRule {
            network: Network::Tcp,
            target: "DIRECT".to_string(),
        };
        let session = Session {
            network: Network::Tcp,
            ..Default::default()
        };
        assert!(rule.apply(&session));
        assert_eq!(rule.payload(), "TCP");
        assert_eq!(rule.target(), "DIRECT");
    }

    #[test]
    fn rejects_wrong_network() {
        let rule = NetworkRule {
            network: Network::Udp,
            target: "PROXY".to_string(),
        };
        let session = Session {
            network: Network::Tcp,
            ..Default::default()
        };
        assert!(!rule.apply(&session));
    }
}
