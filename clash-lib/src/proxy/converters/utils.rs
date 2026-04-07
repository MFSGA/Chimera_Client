#![cfg(feature = "ws")]

use std::collections::HashMap;

use crate::{
    config::internal::proxy::{CommonConfigOptions, WsOpt},
    proxy::transport::{self, WsClient},
};

pub(crate) fn build_ws_client(
    ws_opts: &WsOpt,
    common: &CommonConfigOptions,
    preferred_host: Option<&str>,
) -> WsClient {
    let path = ws_opts
        .path
        .as_ref()
        .map(|value| value.to_owned())
        .unwrap_or_default();
    let headers = ws_opts
        .headers
        .as_ref()
        .map(|value| value.to_owned())
        .unwrap_or_default();
    let max_early_data = ws_opts.max_early_data.unwrap_or_default() as usize;
    let early_data_header_name = ws_opts
        .early_data_header_name
        .as_ref()
        .map(|value| value.to_owned())
        .unwrap_or_default();

    // Keep the WS request authority aligned with mihomo/xray expectations:
    // explicit Host header wins, then the TLS name, then the dial target.
    let request_host = resolve_ws_request_host(
        ws_opts.headers.as_ref(),
        preferred_host,
        &common.server,
    );

    transport::WsClient::new(
        request_host,
        common.port,
        path,
        headers,
        None,
        max_early_data,
        early_data_header_name,
    )
}

pub(crate) fn resolve_ws_request_host(
    headers: Option<&HashMap<String, String>>,
    preferred_host: Option<&str>,
    default_host: &str,
) -> String {
    find_header_ignore_ascii_case(headers, "host")
        .map(normalize_ws_authority_host)
        .or_else(|| preferred_host.map(normalize_ws_authority_host))
        .unwrap_or_else(|| normalize_ws_authority_host(default_host))
}

fn find_header_ignore_ascii_case<'a>(
    headers: Option<&'a HashMap<String, String>>,
    target: &str,
) -> Option<&'a str> {
    headers.and_then(|headers| {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(target))
            .map(|(_, value)| value.trim())
            .filter(|value| !value.is_empty())
    })
}

fn normalize_ws_authority_host(candidate: &str) -> String {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if let Ok(authority) = trimmed.parse::<http::uri::Authority>() {
        if authority.port().is_some() {
            if trimmed.starts_with('[')
                && let Some(end) = trimmed.find(']')
            {
                return trimmed[..=end].to_owned();
            }
            return authority.host().to_owned();
        }
        return trimmed.to_owned();
    }

    if trimmed.matches(':').count() > 1
        && !trimmed.starts_with('[')
        && !trimmed.ends_with(']')
    {
        return format!("[{trimmed}]");
    }

    trimmed.to_owned()
}

impl TryFrom<(&WsOpt, &CommonConfigOptions)> for WsClient {
    type Error = std::io::Error;

    fn try_from(pair: (&WsOpt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        Ok(build_ws_client(x, common, None))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::resolve_ws_request_host;

    #[test]
    fn ws_request_host_prefers_explicit_host_header() {
        let headers =
            HashMap::from([("Host".to_owned(), "cdn.example.com".to_owned())]);

        let resolved = resolve_ws_request_host(
            Some(&headers),
            Some("sni.example.com"),
            "203.0.113.10",
        );

        assert_eq!(resolved, "cdn.example.com");
    }

    #[test]
    fn ws_request_host_falls_back_to_preferred_tls_name() {
        let resolved =
            resolve_ws_request_host(None, Some("sni.example.com"), "203.0.113.10");

        assert_eq!(resolved, "sni.example.com");
    }

    #[test]
    fn ws_request_host_strips_port_from_explicit_host_header() {
        let headers =
            HashMap::from([("host".to_owned(), "cdn.example.com:8443".to_owned())]);

        let resolved = resolve_ws_request_host(
            Some(&headers),
            Some("sni.example.com"),
            "203.0.113.10",
        );

        assert_eq!(resolved, "cdn.example.com");
    }

    #[test]
    fn ws_request_host_wraps_ipv6_literals_for_uri_authority() {
        let resolved = resolve_ws_request_host(None, None, "2001:db8::1");

        assert_eq!(resolved, "[2001:db8::1]");
    }
}
