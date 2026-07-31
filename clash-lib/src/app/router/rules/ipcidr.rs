use ipnet::IpNet;

use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct IpCidr {
    pub ipnet: IpNet,
    pub target: String,
    pub match_source: bool,
    pub no_resolve: bool,
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.target,
            if self.match_source { "src" } else { "dst" },
            self.ipnet
        )
    }
}

impl RuleMatcher for IpCidr {
    fn payload(&self) -> String {
        self.ipnet.to_string()
    }

    fn apply(&self, sess: &session::Session) -> bool {
        if self.match_source {
            self.ipnet.contains(&sess.source.ip())
        } else {
            sess.resolved_ip
                .or(sess.destination.ip())
                .is_some_and(|ip| self.ipnet.contains(&ip))
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn type_name(&self) -> &str {
        "IPCIDR"
    }

    fn should_resolve_ip(&self) -> bool {
        !self.match_source && !self.no_resolve
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Session, SocksAddr};

    #[test]
    fn source_and_destination_cidrs_use_different_addresses() {
        let session = Session {
            source: "192.168.1.20:50000".parse().unwrap(),
            destination: SocksAddr::Ip("10.0.0.8:443".parse().unwrap()),
            ..Default::default()
        };
        assert!(
            IpCidr {
                ipnet: "192.168.1.0/24".parse().unwrap(),
                target: "DIRECT".to_string(),
                match_source: true,
                no_resolve: false,
            }
            .apply(&session)
        );
        assert!(
            IpCidr {
                ipnet: "10.0.0.0/8".parse().unwrap(),
                target: "PROXY".to_string(),
                match_source: false,
                no_resolve: false,
            }
            .apply(&session)
        );
    }
}
