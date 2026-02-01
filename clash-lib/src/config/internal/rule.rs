use std::str::FromStr;

use crate::Error;

/// todo: support more rule type
pub enum RuleType {
    Domain {
        domain: String,
        target: String,
    },
    GeoSite {
        target: String,
        country_code: String,
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
            "GEOSITE" => Ok(RuleType::GeoSite {
                target: target.to_string(),
                country_code: payload.to_string(),
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
            RuleType::GeoSite { target, .. } => target,
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
