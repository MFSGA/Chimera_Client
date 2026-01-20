use std::collections::{HashMap, HashSet};

use tracing::warn;

use crate::{
    Error,
    common::auth,
    config::{
        def,
        internal::{
            config::{self, Profile},
            proxy::{
                OutboundDirect, OutboundProxy, OutboundProxyProtocol, OutboundReject, PROXY_DIRECT,
                PROXY_REJECT,
            },
            rule::RuleType,
        },
    },
};

mod general;
mod proxy_group;
/// 3
mod listener;

impl TryFrom<def::Config> for config::Config {
    type Error = crate::Error;

    fn try_from(value: def::Config) -> Result<Self, Self::Error> {
        convert(value)
    }
}

pub(super) fn convert(mut c: def::Config) -> Result<config::Config, crate::Error> {
    let mut proxy_names = vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];

    if c.allow_lan.unwrap_or_default() && c.bind_address.is_localhost() {
        warn!(
            "allow-lan is set to true, but bind-address is set to localhost. This \
             will not allow any connections from the local network."
        );
    }

    config::Config {
        proxies: c.proxy.take().unwrap_or_default().into_iter().try_fold(
            HashMap::from([
                (
                    String::from(PROXY_DIRECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Direct(OutboundDirect {
                        name: PROXY_DIRECT.to_string(),
                    })),
                ),
                (
                    String::from(PROXY_REJECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Reject(OutboundReject {
                        name: PROXY_REJECT.to_string(),
                    })),
                ),
            ]),
            |mut rv, x| {
                let proxy = OutboundProxy::ProxyServer(OutboundProxyProtocol::try_from(x)?);
                let name = proxy.name();
                if rv.contains_key(name.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "duplicated proxy name: {name}"
                    )));
                }
                proxy_names.push(name.clone());
                rv.insert(name, proxy);
                Ok(rv)
            },
        )?,
        proxy_groups: proxy_group::convert(c.proxy_group.take(), &mut proxy_names)?,
        proxy_providers: HashMap::new(),
        proxy_names,
        users: c
            .authentication
            .clone()
            .into_iter()
            .map(|u| {
                let mut parts = u.splitn(2, ':');
                let username = parts.next().unwrap_or_default().to_string();
                let password = parts.next().unwrap_or_default().to_string();
                auth::User::new(username, password)
            })
            .collect(),
        listeners: listener::convert(c.listeners.take(), &c)?,
        rules: c
            .rule
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|x| {
                x.parse::<RuleType>()
                    .map_err(|x| Error::InvalidConfig(x.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        general: general::convert(&c)?,
        // relate to dns::Config
        dns: (&c).try_into()?,
        profile: Profile {
            store_selected: c.profile.store_selected,
            store_smart_stats: c.profile.store_smart_stats,
        },
    }
    .validate()
}
