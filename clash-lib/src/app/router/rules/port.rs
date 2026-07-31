use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
pub struct PortRule {
    pub port: u16,
    pub target: String,
    pub source: bool,
}

impl std::fmt::Display for PortRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} port {}",
            self.target,
            if self.source { "src" } else { "dst" },
            self.port
        )
    }
}

impl RuleMatcher for PortRule {
    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.port.to_string()
    }

    fn apply(&self, session: &Session) -> bool {
        if self.source {
            session.source.port() == self.port
        } else {
            session.destination.port() == self.port
        }
    }

    fn type_name(&self) -> &str {
        if self.source { "SrcPort" } else { "DstPort" }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;

    #[test]
    fn matches_source_and_destination_ports() {
        let session = Session {
            source: "127.0.0.1:12345".parse().unwrap(),
            destination: SocksAddr::Ip("127.0.0.1:443".parse().unwrap()),
            ..Default::default()
        };
        assert!(
            PortRule {
                port: 12345,
                target: "DIRECT".to_string(),
                source: true,
            }
            .apply(&session)
        );
        assert!(
            PortRule {
                port: 443,
                target: "PROXY".to_string(),
                source: false,
            }
            .apply(&session)
        );
    }
}
