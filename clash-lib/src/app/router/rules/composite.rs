use std::{collections::HashMap, fmt::Display};

use crate::{
    app::{
        remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider,
        router::{RuleMatcher, map_rule_type},
    },
    common::{geodata::GeoDataLookup, mmdb::MmdbLookup},
    config::internal::rule::RuleType,
    session::Session,
};

enum RuleExpression {
    Rule(Box<dyn RuleMatcher>),
    And(Vec<RuleExpression>),
    Or(Vec<RuleExpression>),
    Not(Box<RuleExpression>),
}

impl RuleExpression {
    fn evaluate(&self, session: &Session) -> bool {
        match self {
            Self::Rule(rule) => rule.apply(session),
            Self::And(expressions) => {
                expressions.iter().all(|expr| expr.evaluate(session))
            }
            Self::Or(expressions) => {
                expressions.iter().any(|expr| expr.evaluate(session))
            }
            Self::Not(expression) => !expression.evaluate(session),
        }
    }
}

pub struct CompositeRule {
    operator: String,
    expression: RuleExpression,
    target: String,
    raw_expression: String,
}

impl CompositeRule {
    pub fn new(
        operator: &str,
        expression: &str,
        target: &str,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        providers: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    ) -> Result<Self, crate::Error> {
        let parsed =
            Self::parse_expression(operator, expression, mmdb, geodata, providers)?;
        Ok(Self {
            operator: operator.to_string(),
            expression: parsed,
            target: target.to_string(),
            raw_expression: expression.to_string(),
        })
    }

    fn parse_expression(
        operator: &str,
        expression: &str,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        providers: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    ) -> Result<RuleExpression, crate::Error> {
        let expression = expression.trim();
        if !expression.starts_with('(') || !expression.ends_with(')') {
            return Err(crate::Error::InvalidConfig(format!(
                "composite expression must be wrapped in parentheses: {expression}"
            )));
        }
        let children = Self::parse_children(
            &expression[1..expression.len() - 1],
            mmdb,
            geodata,
            providers,
        )?;
        match operator {
            "AND" => Ok(RuleExpression::And(children)),
            "OR" => Ok(RuleExpression::Or(children)),
            "NOT" if children.len() == 1 => Ok(RuleExpression::Not(Box::new(
                children.into_iter().next().unwrap(),
            ))),
            "NOT" => Err(crate::Error::InvalidConfig(
                "NOT operator requires exactly one sub-expression".to_string(),
            )),
            _ => Err(crate::Error::InvalidConfig(format!(
                "unknown composite operator: {operator}"
            ))),
        }
    }

    fn parse_children(
        input: &str,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        providers: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    ) -> Result<Vec<RuleExpression>, crate::Error> {
        let chars: Vec<char> = input.chars().collect();
        let mut children = Vec::new();
        let mut cursor = 0usize;

        while cursor < chars.len() {
            while cursor < chars.len()
                && (chars[cursor].is_whitespace() || chars[cursor] == ',')
            {
                cursor += 1;
            }
            if cursor == chars.len() {
                break;
            }
            if chars[cursor] != '(' {
                return Err(crate::Error::InvalidConfig(format!(
                    "expected '(' at position {cursor} in: {input}"
                )));
            }

            let start = cursor;
            let mut depth = 0i32;
            while cursor < chars.len() {
                match chars[cursor] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            cursor += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                cursor += 1;
            }
            if depth != 0 {
                return Err(crate::Error::InvalidConfig(format!(
                    "unbalanced parentheses in: {input}"
                )));
            }

            let child: String = chars[start..cursor].iter().collect();
            children.push(Self::parse_child(
                &child,
                mmdb.clone(),
                geodata.clone(),
                providers,
            )?);
        }

        if children.is_empty() {
            return Err(crate::Error::InvalidConfig(
                "no sub-expressions found".to_string(),
            ));
        }
        Ok(children)
    }

    fn parse_child(
        expression: &str,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        providers: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    ) -> Result<RuleExpression, crate::Error> {
        let expression = expression.trim();
        let inner = &expression[1..expression.len() - 1];
        let comma = inner.find(',').ok_or_else(|| {
            crate::Error::InvalidConfig(format!(
                "no comma found in expression: {expression}"
            ))
        })?;
        let rule_type = inner[..comma].trim();
        let rest = inner[comma + 1..].trim();

        if matches!(rule_type, "AND" | "OR" | "NOT") {
            return Self::parse_expression(
                rule_type, rest, mmdb, geodata, providers,
            );
        }

        let rule = RuleType::new(rule_type, rest, "", None)?;
        Ok(RuleExpression::Rule(map_rule_type(
            rule, mmdb, geodata, providers,
        )))
    }
}

impl Display for CompositeRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.target,
            self.operator.to_lowercase(),
            self.raw_expression
        )
    }
}

impl RuleMatcher for CompositeRule {
    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.raw_expression.clone()
    }

    fn apply(&self, session: &Session) -> bool {
        self.expression.evaluate(session)
    }

    fn type_name(&self) -> &str {
        &self.operator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Network, SocksAddr};

    fn session(domain: &str, port: u16, network: Network) -> Session {
        Session {
            destination: SocksAddr::Domain(domain.to_string(), port),
            network,
            ..Default::default()
        }
    }

    fn rule(operator: &str, expression: &str) -> CompositeRule {
        CompositeRule::new(operator, expression, "PROXY", None, None, None).unwrap()
    }

    #[test]
    fn and_requires_every_child() {
        let rule = rule("AND", "((DOMAIN,example.com),(NETWORK,UDP))");
        assert!(rule.apply(&session("example.com", 53, Network::Udp)));
        assert!(!rule.apply(&session("example.com", 53, Network::Tcp)));
        assert!(!rule.apply(&session("other.com", 53, Network::Udp)));
        assert_eq!(rule.target(), "PROXY");
        assert_eq!(rule.type_name(), "AND");
    }

    #[test]
    fn or_accepts_any_child() {
        let rule = rule("OR", "((DOMAIN,example.com),(NETWORK,UDP))");
        assert!(rule.apply(&session("example.com", 443, Network::Tcp)));
        assert!(rule.apply(&session("other.com", 53, Network::Udp)));
        assert!(!rule.apply(&session("other.com", 443, Network::Tcp)));
    }

    #[test]
    fn not_inverts_one_child() {
        let rule = rule("NOT", "((DOMAIN,example.com))");
        assert!(rule.apply(&session("other.com", 443, Network::Tcp)));
        assert!(!rule.apply(&session("example.com", 443, Network::Tcp)));
    }

    #[test]
    fn not_rejects_multiple_children() {
        assert!(
            CompositeRule::new(
                "NOT",
                "((DOMAIN,example.com),(NETWORK,UDP))",
                "PROXY",
                None,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn nested_and_with_or_matches_both_networks() {
        let rule = rule(
            "AND",
            "((DOMAIN,example.com),(OR,((NETWORK,UDP),(NETWORK,TCP))))",
        );
        assert!(rule.apply(&session("example.com", 53, Network::Udp)));
        assert!(rule.apply(&session("example.com", 443, Network::Tcp)));
        assert!(!rule.apply(&session("other.com", 53, Network::Udp)));
    }

    #[test]
    fn nested_or_with_and_keeps_pairing() {
        let rule = rule(
            "OR",
            "((AND,((DOMAIN,a.com),(NETWORK,UDP))),(AND,((DOMAIN,b.com),(NETWORK,TCP))))",
        );
        assert!(rule.apply(&session("a.com", 53, Network::Udp)));
        assert!(rule.apply(&session("b.com", 443, Network::Tcp)));
        assert!(!rule.apply(&session("a.com", 443, Network::Tcp)));
        assert!(!rule.apply(&session("b.com", 53, Network::Udp)));
    }

    #[test]
    fn nested_not_can_filter_network() {
        let rule = rule("AND", "((DOMAIN,example.com),(NOT,((NETWORK,TCP))))");
        assert!(rule.apply(&session("example.com", 53, Network::Udp)));
        assert!(!rule.apply(&session("example.com", 443, Network::Tcp)));
    }

    #[test]
    fn or_supports_more_than_two_children() {
        let rule = rule("OR", "((DOMAIN,a.com),(DOMAIN,b.com),(DOMAIN,c.com))");
        for domain in ["a.com", "b.com", "c.com"] {
            assert!(rule.apply(&session(domain, 443, Network::Tcp)));
        }
        assert!(!rule.apply(&session("d.com", 443, Network::Tcp)));
    }

    #[test]
    fn domain_suffix_and_keyword_work_as_leaves() {
        let suffix = rule("AND", "((DOMAIN-SUFFIX,example.com),(NETWORK,TCP))");
        assert!(suffix.apply(&session("api.example.com", 443, Network::Tcp)));
        assert!(!suffix.apply(&session("api.example.com", 53, Network::Udp)));

        let keyword =
            rule("OR", "((DOMAIN-KEYWORD,google),(DOMAIN-KEYWORD,youtube))");
        assert!(keyword.apply(&session("www.google.com", 443, Network::Tcp)));
        assert!(keyword.apply(&session("m.youtube.com", 443, Network::Tcp)));
        assert!(!keyword.apply(&session("example.com", 443, Network::Tcp)));
    }

    #[test]
    fn rejects_missing_or_unbalanced_parentheses() {
        for expression in [
            "(DOMAIN,example.com),(NETWORK,UDP)",
            "((DOMAIN,example.com),(NETWORK,UDP)",
            "((DOMAIN,example.com)),(NETWORK,UDP)))",
        ] {
            assert!(
                CompositeRule::new("AND", expression, "PROXY", None, None, None,)
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_unknown_operator_and_empty_expression() {
        assert!(
            CompositeRule::new(
                "XOR",
                "((DOMAIN,example.com))",
                "PROXY",
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(CompositeRule::new("AND", "()", "PROXY", None, None, None).is_err());
    }

    #[test]
    fn payload_and_display_preserve_expression() {
        let expression = "((DOMAIN,example.com),(NETWORK,UDP))";
        let rule = rule("AND", expression);
        assert_eq!(rule.payload(), expression);
        assert!(rule.to_string().contains("PROXY"));
        assert!(rule.to_string().contains("and"));
    }

    #[test]
    fn deeply_nested_expression_matches_expected_pairs() {
        let rule = rule(
            "OR",
            "((AND,((DOMAIN,a.com),(NETWORK,TCP))),(AND,((DOMAIN,b.com),(NETWORK,UDP))))",
        );
        assert!(rule.apply(&session("a.com", 443, Network::Tcp)));
        assert!(rule.apply(&session("b.com", 53, Network::Udp)));
        assert!(!rule.apply(&session("a.com", 53, Network::Udp)));
        assert!(!rule.apply(&session("b.com", 443, Network::Tcp)));
    }
}
