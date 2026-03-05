use ipnet::IpNet;

use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct IpCidr {
    pub ipnet: IpNet,
    pub target: String,
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ipcidr {}", self.target, self.ipnet)
    }
}

impl RuleMatcher for IpCidr {
    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::SocksAddr::Ip(addr) => self.ipnet.contains(&addr.ip()),
            session::SocksAddr::Domain(_, _) => false,
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn type_name(&self) -> &str {
        "IPCIDR"
    }
}
