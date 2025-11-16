use serde::Deserialize;
use serde_yaml::Value;
use std::{path::PathBuf, str::FromStr};

use crate::Error;

#[derive(Deserialize)]
pub struct Config {}

impl TryFrom<PathBuf> for Config {
    type Error = Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        let content = std::fs::read_to_string(value)?;
        let config = content.parse::<Config>()?;
        Ok(config)
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut val: Value = serde_yaml::from_str(s).map_err(|e| {
            Error::InvalidConfig(format!("couldn't not parse config content {s}: {e}"))
        })?;

        val.apply_merge().map_err(|e| {
            Error::InvalidConfig(format!(
                "failed to process anchors in config content {s}: {e}"
            ))
        })?;

        serde_yaml::from_value(val)
            .map_err(|e| Error::InvalidConfig(format!("could not parse config content: {e}")))
    }
}
