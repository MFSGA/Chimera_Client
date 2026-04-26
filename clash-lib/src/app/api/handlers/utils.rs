use std::{io, time::Duration};

use http::{HeaderMap, header};
use serde::Deserialize;

use crate::{
    app::outbound::manager::ThreadSafeOutboundManager, proxy::AnyOutboundHandler,
};

#[derive(Deserialize)]
pub struct DelayRequest {
    pub url: String,
    pub timeout: u16,
}

pub async fn group_url_test(
    outbound_manager: &ThreadSafeOutboundManager,
    proxy: AnyOutboundHandler,
    fallback_url: &str,
    timeout: Duration,
) -> io::Result<(Duration, Duration)> {
    let group = proxy.try_as_group_handler().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "proxy is not a group")
    })?;
    let latency_test_url = group.get_latency_test_url();
    let members = group.get_proxies().await;
    let active_proxy = group.get_active_proxy().await;
    let active_idx = active_proxy
        .as_ref()
        .and_then(|active| members.iter().position(|p| p.name() == active.name()));

    let results = outbound_manager
        .url_test(
            &[vec![proxy], members].concat(),
            latency_test_url.as_deref().unwrap_or(fallback_url),
            timeout,
        )
        .await;

    let result = if let Some(idx) = active_idx {
        results
            .get(idx + 1)
            .or_else(|| results.first())
            .ok_or_else(|| {
                io::Error::other("missing latency result for active proxy")
            })?
    } else {
        results
            .first()
            .ok_or_else(|| io::Error::other("no proxies in group"))?
    };

    match result {
        Ok(latency) => Ok(*latency),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}

pub fn is_request_websocket(header: HeaderMap) -> bool {
    header
        .get(header::CONNECTION)
        .and_then(|x| x.to_str().ok().map(|x| x.to_ascii_lowercase()))
        .is_some_and(|x| x.contains(&"upgrade".to_ascii_lowercase()))
        && header
            .get(header::UPGRADE)
            .and_then(|x| x.to_str().ok().map(|x| x.to_ascii_lowercase()))
            == Some("websocket".to_ascii_lowercase())
}
