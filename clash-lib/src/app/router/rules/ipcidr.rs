use ipnet::IpNet;

use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct IpCidr {
    pub ipnet: IpNet,
    pub target: String,
    pub no_resolve: bool,
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ipcidr {}", self.target, self.ipnet)
    }
}

impl RuleMatcher for IpCidr {
    fn payload(&self) -> String {
        self.ipnet.to_string()
    }

    fn apply(&self, sess: &session::Session) -> bool {
        let ip = sess.resolved_ip.or(sess.destination.ip());

        if let Some(ip) = ip {
            self.ipnet.contains(&ip)
        } else {
            false
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn type_name(&self) -> &str {
        "IPCIDR"
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}
