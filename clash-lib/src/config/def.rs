use serde::Deserialize;
use serde_yaml::Value;
use std::{collections::HashMap, path::PathBuf, str::FromStr};

use crate::{Error, config::internal::config::BindAddress};

#[derive(Deserialize)]
pub struct Config {
    /// 1. Allow connections from IP addresses other than local listening address
    pub allow_lan: Option<bool>,
    /// The address that the inbound listens on
    /// 2. # Note
    /// - setting this to `*` will listen on all interfaces, which is
    ///   essentially the same as setting it to `0.0.0.0`
    /// - setting this to non local IP will enable `allow_lan` automatically
    /// - and if you don't want `allow_lan` to be enabled, you should set this
    ///   to `localhost` or `127.1`
    pub bind_address: BindAddress,
    /// Proxy settings
    #[serde(rename = "proxies")]
    pub proxy: Option<Vec<HashMap<String, Value>>>,
}

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
