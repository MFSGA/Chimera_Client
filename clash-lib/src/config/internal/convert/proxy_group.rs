use std::collections::HashMap;

use crate::{
    Error,
    config::internal::proxy::{OutboundGroupProtocol, OutboundProxy},
};

pub fn convert(
    before: Option<Vec<OutboundGroupProtocol>>,
    proxy_names: &mut Vec<String>,
) -> Result<HashMap<String, OutboundProxy>, crate::Error> {
    before.unwrap_or_default().into_iter().try_fold(
        HashMap::<String, OutboundProxy>::new(),
        |mut rv, protocol| {
            let group = OutboundProxy::ProxyGroup(protocol);
            if rv.contains_key(&group.name()) {
                return Err(Error::InvalidConfig(format!(
                    "duplicated proxy group name: {}",
                    group.name()
                )));
            }
            proxy_names.push(group.name());
            rv.insert(group.name(), group);
            Ok::<HashMap<String, OutboundProxy>, Error>(rv)
        },
    )
}
