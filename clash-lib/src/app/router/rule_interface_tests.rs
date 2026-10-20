use super::{apply_rule_interface, map_rule_type};
use crate::{
    config::internal::rule::RuleType,
    session::{Session, SocksAddr},
};

#[test]
fn interface_constraint_survives_parsing_and_runtime_matcher_mapping() {
    let parsed = RuleType::try_from(
        r"DOMAIN-REGEX,^api\.example\.com$,PROXY,interface=en0".to_string(),
    )
    .unwrap();
    let matcher = map_rule_type(parsed, None, None, None).unwrap();

    assert_eq!(matcher.target(), "PROXY");
    assert_eq!(matcher.interface(), Some("en0"));
    assert_eq!(matcher.type_name(), "DomainRegex");
    assert!(matcher.apply(&Session {
        destination: SocksAddr::Domain("API.EXAMPLE.COM".to_owned(), 443),
        ..Default::default()
    }));
    assert!(!matcher.apply(&Session {
        destination: SocksAddr::Domain("other.example.com".to_owned(), 443),
        ..Default::default()
    }));
}

#[tokio::test]
async fn unavailable_rule_interface_is_never_replaced_by_default() {
    let parsed = RuleType::try_from(
        "MATCH,DIRECT,interface=chimera-missing-egress-test-iface".to_string(),
    )
    .unwrap();
    let matcher = map_rule_type(parsed, None, None, None).unwrap();
    let mut sess = Session::default();

    let error = apply_rule_interface(&mut sess, Some(matcher.as_ref()))
        .await
        .expect_err("missing explicit interface must fail closed");
    assert!(
        error
            .to_string()
            .contains("chimera-missing-egress-test-iface")
    );
    assert!(
        sess.iface.is_none(),
        "must not select the default interface"
    );
}

#[tokio::test]
async fn ordinary_rules_keep_existing_interface_unchanged() {
    let parsed = RuleType::try_from("MATCH,DIRECT".to_string()).unwrap();
    let matcher = map_rule_type(parsed, None, None, None).unwrap();
    let mut sess = Session::default();
    assert!(matcher.interface().is_none());
    apply_rule_interface(&mut sess, Some(matcher.as_ref()))
        .await
        .unwrap();
    assert!(sess.iface.is_none());
}
