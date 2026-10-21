use std::str::FromStr;

use crate::{Error, session::Network};

/// todo: support more rule type
pub enum RuleType {
    WithInterface {
        rule: Box<RuleType>,
        interface: String,
    },
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
        let mut interface: Option<String> = None;
        let mut no_resolve = false;
        for param in params.unwrap_or_default() {
            if param == "no-resolve" {
                if no_resolve {
                    return Err(Error::InvalidConfig(
                        "rule option `no-resolve` can only be specified once"
                            .to_string(),
                    ));
                }
                no_resolve = true;
            } else if let Some(name) = param.strip_prefix("interface=") {
                if name.is_empty() || name.trim() != name {
                    return Err(Error::InvalidConfig(
                        "rule interface name must not be empty or padded with whitespace"
                            .to_string(),
                    ));
                }
                if interface.replace(name.to_string()).is_some() {
                    return Err(Error::InvalidConfig(
                        "rule interface can only be specified once".to_string(),
                    ));
                }
            } else {
                return Err(Error::InvalidConfig(format!(
                    "unsupported rule option: {param}"
                )));
            }
        }
        let rule = match proto {
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
                regex: regex::RegexBuilder::new(payload)
                    .case_insensitive(true)
                    .build()
                    .map_err(|err| Error::InvalidConfig(err.to_string()))?,
                target: target.to_string(),
            }),
            "GEOIP" => Ok(RuleType::GeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
                no_resolve,
            }),
            "GEOSITE" => Ok(RuleType::GeoSite {
                target: target.to_string(),
                country_code: payload.to_string(),
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(RuleType::IpCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve,
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
        }?;

        // Match ref/: no-resolve only makes sense for IP-address/GeoIP
        // matching. For source CIDR it is accepted for compatibility; source
        // addresses are already IPs and never require DNS resolution.
        if no_resolve
            && !matches!(
                &rule,
                RuleType::GeoIP { .. }
                    | RuleType::IpCidr { .. }
                    | RuleType::SrcCidr { .. }
            )
        {
            return Err(Error::InvalidConfig(format!(
                "rule option `no-resolve` is not supported for {proto}"
            )));
        }

        Ok(match interface {
            Some(interface) => RuleType::WithInterface {
                rule: Box::new(rule),
                interface,
            },
            None => rule,
        })
    }

    pub fn target(&self) -> &str {
        match self {
            RuleType::WithInterface { rule, .. } => rule.target(),
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
            ["MATCH", target, params @ ..] => {
                RuleType::new("MATCH", "", target, Some(params.to_vec()))
            }
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
    fn interface_rule_options_preserve_match_target_and_ip_no_resolve() {
        let rule = RuleType::try_from("MATCH,DIRECT,interface=en0".to_string())
            .expect("MATCH rule must treat the third field as an option");
        match rule {
            RuleType::WithInterface { rule, interface } => {
                assert_eq!(interface, "en0");
                assert_eq!(rule.target(), "DIRECT");
                assert!(matches!(*rule, RuleType::Match { .. }));
            }
            _ => panic!("MATCH interface option was lost"),
        }

        let rule = RuleType::try_from(
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve,interface=en1".to_string(),
        )
        .unwrap();
        match rule {
            RuleType::WithInterface { rule, interface } => {
                assert_eq!(interface, "en1");
                assert!(matches!(
                    *rule,
                    RuleType::IpCidr {
                        no_resolve: true,
                        ..
                    }
                ));
            }
            _ => panic!("IP-CIDR interface option was lost"),
        }
    }

    #[test]
    fn invalid_rule_options_fail_closed_instead_of_being_ignored() {
        for rule in [
            "MATCH,DIRECT,unknown=true",
            "MATCH,DIRECT,interface=",
            "MATCH,DIRECT,interface=en0,interface=en1",
            "MATCH,DIRECT,no-resolve,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,unexpected",
            "DOMAIN,example.com,PROXY,interface= en0",
        ] {
            assert!(
                RuleType::try_from(rule.to_string()).is_err(),
                "invalid rule options must be rejected: {rule}"
            );
        }
    }

    #[test]
    fn no_resolve_is_only_valid_for_ip_and_geo_rules() {
        for line in [
            "DOMAIN,example.com,PROXY,no-resolve",
            "DOMAIN-SUFFIX,example.com,PROXY,no-resolve",
            "DOMAIN-REGEX,^api\\.example\\.com$,PROXY,no-resolve",
            "GEOSITE,cn,PROXY,no-resolve",
            "RULE-SET,provider,PROXY,no-resolve",
            "PROCESS-NAME,browser,PROXY,no-resolve",
            "NETWORK,TCP,PROXY,no-resolve",
            "MATCH,DIRECT,no-resolve",
            "MATCH,DIRECT,no-resolve,interface=en0",
            "AND,((DOMAIN,example.com),(NETWORK,TCP)),PROXY,no-resolve",
        ] {
            let result = RuleType::try_from(line.to_string());
            assert!(
                result.is_err(),
                "no-resolve must not be silently accepted for {line}"
            );
            let error = result.err().unwrap().to_string();
            assert!(
                error.contains("no-resolve") && error.contains("not supported"),
                "unexpected error for {line}: {error}"
            );
        }
    }

    #[test]
    fn no_resolve_preserves_valid_rules_and_explicit_interface() {
        for line in [
            "GEOIP,CN,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR6,2001:db8::/32,DIRECT,no-resolve",
            "SRC-IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve,interface=en0",
        ] {
            assert!(
                RuleType::try_from(line.to_string()).is_ok(),
                "valid no-resolve rule should still parse: {line}"
            );
        }
    }

    #[test]
    fn domain_regex_matches_case_insensitively_like_upstream() {
        let rule = RuleType::try_from(
            r"DOMAIN-REGEX,^api\.example\.com$,PROXY".to_string(),
        )
        .unwrap();
        match rule {
            RuleType::DomainRegex { regex, .. } => {
                assert!(regex.is_match("API.EXAMPLE.COM"));
                assert!(regex.is_match("api.example.com"));
                assert!(!regex.is_match("other.example.com"));
            }
            _ => panic!("expected domain regex"),
        }
    }

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
