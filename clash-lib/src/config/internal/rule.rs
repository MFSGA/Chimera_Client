use std::str::FromStr;

use crate::{Error, session::Network};

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
    DomainRegex {
        regex: regex::Regex,
        target: String,
    },
    GeoIP {
        target: String,
        country_code: String,
        no_resolve: bool,
    },
    GeoSite {
        target: String,
        country_code: String,
    },
    Match {
        target: String,
    },
    IpCidr {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
    },
    SrcCidr {
        ipnet: ipnet::IpNet,
        target: String,
    },
    RuleSet {
        rule_set: String,
        target: String,
    },
    SrcPort {
        port: u16,
        target: String,
    },
    DstPort {
        port: u16,
        target: String,
    },
    ProcessName {
        process_name: String,
        target: String,
    },
    ProcessPath {
        process_path: String,
        target: String,
    },
    Network {
        network: Network,
        target: String,
    },
    Composite {
        operator: String,
        expression: String,
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
            "DOMAIN-REGEX" => Ok(RuleType::DomainRegex {
                regex: regex::Regex::new(payload)
                    .map_err(|err| Error::InvalidConfig(err.to_string()))?,
                target: target.to_string(),
            }),
            "GEOIP" => Ok(RuleType::GeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
                no_resolve: if let Some(params) = params {
                    params.contains(&"no-resolve")
                } else {
                    false
                },
            }),
            "GEOSITE" => Ok(RuleType::GeoSite {
                target: target.to_string(),
                country_code: payload.to_string(),
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(RuleType::IpCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: if let Some(params) = params {
                    params.contains(&"no-resolve")
                } else {
                    false
                },
            }),
            "SRC-IP-CIDR" => Ok(RuleType::SrcCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
            }),
            "RULE-SET" => Ok(RuleType::RuleSet {
                rule_set: payload.to_string(),
                target: target.to_string(),
            }),
            "SRC-PORT" => Ok(RuleType::SrcPort {
                port: payload.parse().map_err(|_| {
                    Error::InvalidConfig(format!("invalid source port: {payload}"))
                })?,
                target: target.to_string(),
            }),
            "DST-PORT" => Ok(RuleType::DstPort {
                port: payload.parse().map_err(|_| {
                    Error::InvalidConfig(format!(
                        "invalid destination port: {payload}"
                    ))
                })?,
                target: target.to_string(),
            }),
            "PROCESS-NAME" => Ok(RuleType::ProcessName {
                process_name: payload.to_string(),
                target: target.to_string(),
            }),
            "PROCESS-PATH" => Ok(RuleType::ProcessPath {
                process_path: payload.to_string(),
                target: target.to_string(),
            }),
            "NETWORK" => Ok(RuleType::Network {
                network: match payload.to_ascii_uppercase().as_str() {
                    "TCP" => Network::Tcp,
                    "UDP" => Network::Udp,
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "unsupported network rule payload: {payload}"
                        )));
                    }
                },
                target: target.to_string(),
            }),
            "AND" | "OR" | "NOT" => Ok(RuleType::Composite {
                operator: proto.to_string(),
                expression: payload.to_string(),
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
            RuleType::DomainRegex { target, .. } => target,
            RuleType::GeoIP { target, .. } => target,
            RuleType::GeoSite { target, .. } => target,
            RuleType::Match { target } => target,
            RuleType::IpCidr { target, .. } => target,
            RuleType::SrcCidr { target, .. } => target,
            RuleType::RuleSet { target, .. } => target,
            RuleType::SrcPort { target, .. } => target,
            RuleType::DstPort { target, .. } => target,
            RuleType::ProcessName { target, .. } => target,
            RuleType::ProcessPath { target, .. } => target,
            RuleType::Network { target, .. } => target,
            RuleType::Composite { target, .. } => target,
        }
    }
}

fn split_rule_tokens(line: &str) -> Result<Vec<&str>, Error> {
    let mut tokens = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;

    for (idx, ch) in line.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(Error::InvalidConfig(format!(
                        "unbalanced parentheses in rule: {line}"
                    )));
                }
            }
            ',' if depth == 0 => {
                tokens.push(line[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(Error::InvalidConfig(format!(
            "unbalanced parentheses in rule: {line}"
        )));
    }
    tokens.push(line[start..].trim());
    Ok(tokens)
}

impl TryFrom<String> for RuleType {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        let parts = split_rule_tokens(&line)?;

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

    #[test]
    fn parse_composite_rule_preserves_nested_expression() {
        let rule = RuleType::try_from(
            "AND,((DOMAIN,example.com),(NETWORK,TCP)),PROXY".to_string(),
        )
        .unwrap();
        match rule {
            RuleType::Composite {
                operator,
                expression,
                target,
            } => {
                assert_eq!(operator, "AND");
                assert_eq!(expression, "((DOMAIN,example.com),(NETWORK,TCP))");
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Composite rule"),
        }
    }

    #[test]
    fn parse_domain_regex_and_source_cidr_rules() {
        let regex = RuleType::try_from(
            "DOMAIN-REGEX,^api[0-9]+\\.example\\.com$,PROXY".to_string(),
        )
        .unwrap();
        assert!(matches!(regex, RuleType::DomainRegex { .. }));
        assert!(
            RuleType::try_from("DOMAIN-REGEX,[invalid,PROXY".to_string()).is_err()
        );

        let source =
            RuleType::try_from("SRC-IP-CIDR,192.168.1.0/24,DIRECT".to_string())
                .unwrap();
        assert!(matches!(source, RuleType::SrcCidr { .. }));
    }

    #[test]
    fn parse_process_rules() {
        let name =
            RuleType::try_from("PROCESS-NAME,steam.exe,GAME".to_string()).unwrap();
        assert!(matches!(name, RuleType::ProcessName { .. }));
        let path = RuleType::try_from(
            "PROCESS-PATH,C:\\Games\\Steam\\steam.exe,GAME".to_string(),
        )
        .unwrap();
        assert!(matches!(path, RuleType::ProcessPath { .. }));
    }

    #[test]
    fn parse_port_rules() {
        let source =
            RuleType::try_from("SRC-PORT,12345,DIRECT".to_string()).unwrap();
        assert!(matches!(source, RuleType::SrcPort { port: 12345, .. }));
        let destination =
            RuleType::try_from("DST-PORT,443,PROXY".to_string()).unwrap();
        assert!(matches!(destination, RuleType::DstPort { port: 443, .. }));
        assert!(RuleType::try_from("DST-PORT,invalid,PROXY".to_string()).is_err());
    }

    #[test]
    fn parse_network_rule() {
        let rule = RuleType::try_from("NETWORK,udp,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network { network, target } => {
                assert_eq!(network, crate::session::Network::Udp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }
    }

    #[test]
    fn reject_invalid_network_rule() {
        let rule = RuleType::try_from("NETWORK,icmp,PROXY".to_string());
        assert!(rule.is_err());
    }

    #[test]
    fn parse_geosite_rule() {
        let rule = RuleType::try_from("GEOSITE,cn,PROXY".to_string()).unwrap();
        match rule {
            RuleType::GeoSite {
                country_code,
                target,
            } => {
                assert_eq!(country_code, "cn");
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected GeoSite rule"),
        }
    }
}
