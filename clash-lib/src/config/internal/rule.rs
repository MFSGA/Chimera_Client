use std::str::FromStr;

use crate::Error;

/// todo: support more rule type
pub enum RuleType {
    Domain {
        domain: String,
        target: String,
    },
    DomainSuffix {
        domain_suffix: String,
        target: String,
    },
    DomainKeyword {
        domain_keyword: String,
        target: String,
    },
    Match {
        target: String,
    },
}

impl RuleType {
    pub fn new(
        proto: &str,
        payload: &str,
        target: &str,
        params: Option<Vec<&str>>,
    ) -> Result<Self, Error> {
        match proto {
            "DOMAIN" => Ok(RuleType::Domain {
                domain: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-SUFFIX" => Ok(RuleType::DomainSuffix {
                domain_suffix: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-KEYWORD" => Ok(RuleType::DomainKeyword {
                domain_keyword: payload.to_string(),
                target: target.to_string(),
            }),
            "MATCH" => Ok(RuleType::Match {
                target: target.to_string(),
            }),
            _ => Err(Error::InvalidConfig(format!(
                "unsupported rule type: {proto}"
            ))),
        }
    }

    pub fn target(&self) -> &str {
        match self {
            RuleType::Domain { target, .. } => target,
            RuleType::DomainSuffix { target, .. } => target,
            RuleType::DomainKeyword { target, .. } => target,
            RuleType::Match { target } => target,
        }
    }
}

impl TryFrom<String> for RuleType {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        let parts = line.split(',').map(str::trim).collect::<Vec<&str>>();

        match parts.as_slice() {
            [proto, target] => RuleType::new(proto, "", target, None),
            [proto, payload, target] => RuleType::new(proto, payload, target, None),
            [proto, payload, target, params @ ..] => {
                RuleType::new(proto, payload, target, Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {line}"))),
        }
    }
}

impl FromStr for RuleType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::RuleType;

    #[test]
    fn parse_domain_suffix_rule() {
        let rule = RuleType::try_from("DOMAIN-SUFFIX,example.com,PROXY".to_string())
            .unwrap();
        match rule {
            RuleType::DomainSuffix {
                domain_suffix,
                target,
            } => {
                assert_eq!(domain_suffix, "example.com");
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected DomainSuffix rule"),
        }
    }

    #[test]
    fn parse_domain_keyword_rule() {
        let rule =
            RuleType::try_from("DOMAIN-KEYWORD,example,PROXY".to_string()).unwrap();
        match rule {
            RuleType::DomainKeyword {
                domain_keyword,
                target,
            } => {
                assert_eq!(domain_keyword, "example");
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected DomainKeyword rule"),
        }
    }

    #[test]
    fn domain_suffix_target_returns_proxy_name() {
        let rule = RuleType::DomainSuffix {
            domain_suffix: "example.com".to_string(),
            target: "PROXY".to_string(),
        };
        assert_eq!(rule.target(), "PROXY");
    }

    #[test]
    fn invalid_rule_line_still_errors() {
        let rule = RuleType::try_from("DOMAIN-SUFFIX".to_string());
        assert!(rule.is_err());
    }
}
