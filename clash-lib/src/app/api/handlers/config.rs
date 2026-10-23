use std::{collections::HashSet, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};

use http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::error;

use crate::{
    GlobalState,
    app::{
        api::AppState,
        dispatcher,
        dns::{ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::{InboundEndpoint, InboundManager, Ports},
        outbound::manager::{OutboundValidationResult, ThreadSafeOutboundManager},
    },
    config::{
        def,
        internal::{
            InternalConfig,
            config::BindAddress,
            proxy::{
                OutboundGroupProtocol, OutboundProxy, PROXY_DIRECT, PROXY_GLOBAL,
                PROXY_REJECT,
            },
        },
    },
};

#[derive(Serialize)]
struct DnsListenInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    udp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doh3: Option<String>,
}

#[derive(Clone)]
struct ConfigState {
    inbound_manager: Arc<InboundManager>,
    outbound_manager: ThreadSafeOutboundManager,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
    ipv6_allowed: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn routes(
    inbound_manager: Arc<InboundManager>,
    outbound_manager: ThreadSafeOutboundManager,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
    ipv6_allowed: bool,
) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/",
            get(get_configs).put(update_configs).patch(patch_configs),
        )
        .route("/validate", axum::routing::post(validate_config))
        .route(
            "/mode",
            get(get_mode).put(put_mode).delete(clear_mode_override),
        )
        .with_state(ConfigState {
            inbound_manager,
            outbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
            dns_listen_addr,
            dns_enabled,
            ipv6_allowed,
        })
}

async fn get_configs(State(state): State<ConfigState>) -> impl IntoResponse {
    let run_mode = state.dispatcher.get_mode().await;
    let log_level = {
        let global_state = state.global_state.lock().await;
        global_state.log_level
    };
    let inbound_manager = state.inbound_manager.clone();

    let ports = inbound_manager.get_ports().await;
    let allow_lan = inbound_manager.get_allow_lan().await;
    let listeners = inbound_manager.get_listeners().await;
    let bind_address = inbound_manager.get_bind_address().await.0.to_string();

    let lan_ips = if allow_lan {
        use network_interface::{NetworkInterface, NetworkInterfaceConfig};
        Some({
            let mut ips = NetworkInterface::show()
                .unwrap_or_default()
                .into_iter()
                .flat_map(|iface| {
                    iface.addr.into_iter().filter_map(|addr| match addr {
                        network_interface::Addr::V4(v4)
                            if !v4.ip.is_loopback() && !v4.ip.is_link_local() =>
                        {
                            Some(v4.ip.to_string())
                        }
                        _ => None,
                    })
                })
                .collect::<Vec<_>>();
            ips.sort();
            ips.dedup();
            ips
        })
    } else {
        None
    };

    let dns_listen = if state.dns_enabled {
        let addr = &state.dns_listen_addr;
        Some(DnsListenInfo {
            udp: addr.udp.map(|a| a.to_string()),
            tcp: addr.tcp.map(|a| a.to_string()),
            doh: addr.doh.as_ref().map(|c| c.addr.to_string()),
            dot: addr.dot.as_ref().map(|c| c.addr.to_string()),
            doh3: addr.doh3.as_ref().map(|c| c.addr.to_string()),
        })
    } else {
        None
    };

    axum::response::Json(GetConfigResponse {
        port: ports.port,
        socks_port: ports.socks_port,
        redir_port: ports.redir_port,
        tproxy_port: ports.tproxy_port,
        mixed_port: ports.mixed_port,
        bind_address: Some(bind_address),
        mode: Some(run_mode),
        log_level: Some(log_level),
        ipv6: Some(state.dns_resolver.ipv6()),
        allow_lan: Some(allow_lan),
        listeners: Some(listeners),
        lan_ips,
        dns_listen,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModeView {
    configured_mode: def::RunMode,
    effective_mode: def::RunMode,
    override_mode: Option<def::RunMode>,
}

#[derive(Deserialize)]
struct ModeRequest {
    mode: def::RunMode,
}

async fn get_mode(State(state): State<ConfigState>) -> Json<ModeView> {
    Json(ModeView {
        configured_mode: state.dispatcher.configured_mode(),
        effective_mode: state.dispatcher.get_mode().await,
        override_mode: state.dispatcher.mode_override().await,
    })
}

async fn put_mode(
    State(state): State<ConfigState>,
    Json(request): Json<ModeRequest>,
) -> Json<ModeView> {
    state.dispatcher.set_mode(request.mode).await;
    get_mode(State(state)).await
}

async fn clear_mode_override(State(state): State<ConfigState>) -> Json<ModeView> {
    state.dispatcher.clear_mode_override().await;
    get_mode(State(state)).await
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ValidateConfigRequest {
    payload: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidationIssue {
    code: &'static str,
    node: Option<String>,
    field_path: Option<String>,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateConfigResponse {
    valid: bool,
    validation_scope: &'static str,
    errors: Vec<ValidationIssue>,
    outbounds: Vec<OutboundValidationResult>,
}

async fn validate_config(
    State(state): State<ConfigState>,
    Json(request): Json<ValidateConfigRequest>,
) -> Json<ValidateConfigResponse> {
    let definition = match parse_config_definition(&request.payload) {
        Ok(definition) => definition,
        Err(issue) => return invalid_config_response(issue),
    };

    let internal: InternalConfig = match definition.try_into() {
        Ok(config) => config,
        Err(error) => {
            return invalid_config_response(ValidationIssue {
                code: "config_conversion",
                node: None,
                field_path: None,
                message: error.to_string(),
            });
        }
    };
    let internal = match internal.validate() {
        Ok(config) => config,
        Err(error) => {
            return invalid_config_response(ValidationIssue {
                code: "config_validation",
                node: None,
                field_path: None,
                message: error.to_string(),
            });
        }
    };

    let groups: Vec<_> = internal
        .proxy_groups
        .values()
        .filter_map(|group| match group {
            OutboundProxy::ProxyGroup(group) => Some(group.clone()),
            OutboundProxy::ProxyServer(_) => None,
        })
        .collect();
    let provider_names: HashSet<_> =
        internal.proxy_providers.keys().cloned().collect();
    let declared_plain_names: HashSet<_> = internal
        .proxies
        .values()
        .filter_map(|proxy| match proxy {
            OutboundProxy::ProxyServer(outbound) => Some(outbound.name().to_owned()),
            OutboundProxy::ProxyGroup(_) => None,
        })
        .collect();
    let mut outbound_connectors = Vec::new();
    for proxy in internal.proxies.values() {
        if let OutboundProxy::ProxyServer(outbound) = proxy
            && let Some(connector) = outbound.connect_via()
        {
            outbound_connectors
                .push((outbound.name().to_owned(), connector.to_owned()));
        }
    }
    let outbounds = internal
        .proxies
        .into_values()
        .filter_map(|proxy| match proxy {
            OutboundProxy::ProxyServer(outbound)
                if outbound.name() != "DIRECT" && outbound.name() != "REJECT" =>
            {
                Some(outbound)
            }
            _ => None,
        })
        .collect();
    let mut outbounds = state.outbound_manager.validate_plain_outbounds(outbounds);
    outbounds.sort_by(|left, right| left.name.cmp(&right.name));
    let valid_plain_names = outbounds
        .iter()
        .filter(|outbound| outbound.valid)
        .map(|outbound| outbound.name.clone())
        .collect::<HashSet<_>>();
    let mut errors = outbounds
        .iter()
        .filter_map(|outbound| {
            outbound.error.as_ref().map(|message| ValidationIssue {
                code: "outbound_conversion",
                node: Some(outbound.name.clone()),
                field_path: None,
                message: message.clone(),
            })
        })
        .collect::<Vec<_>>();
    if declared_plain_names.contains(PROXY_GLOBAL) {
        errors.push(ValidationIssue {
            code: "proxy_name_reserved",
            node: Some(PROXY_GLOBAL.to_owned()),
            field_path: Some(format!("proxies.{PROXY_GLOBAL}.name")),
            message: format!("proxy name `{PROXY_GLOBAL}` is reserved"),
        });
    }
    let available_connector_names: HashSet<_> = valid_plain_names
        .iter()
        .cloned()
        .chain(groups.iter().map(|group| group.name().to_owned()))
        .chain([
            PROXY_DIRECT.to_owned(),
            PROXY_REJECT.to_owned(),
            PROXY_GLOBAL.to_owned(),
        ])
        .collect();
    errors.extend(outbound_connectors.into_iter().filter_map(
        |(node, connector)| {
            (!available_connector_names.contains(&connector)).then(|| {
                ValidationIssue {
                    code: "outbound_connector_reference",
                    node: Some(node.clone()),
                    field_path: Some(format!("proxies.{node}.dialer-proxy")),
                    message: format!("connector {connector} not found"),
                }
            })
        },
    ));
    errors.extend(validate_proxy_groups(
        &groups,
        &declared_plain_names,
        &valid_plain_names,
        &provider_names,
    ));

    Json(ValidateConfigResponse {
        valid: errors.is_empty(),
        validation_scope: "offline-config-outbound-connector-and-group-validation",
        errors,
        outbounds,
    })
}

fn validate_proxy_groups(
    groups: &[OutboundGroupProtocol],
    declared_plain_names: &HashSet<String>,
    valid_plain_names: &HashSet<String>,
    provider_names: &HashSet<String>,
) -> Vec<ValidationIssue> {
    let group_names: HashSet<_> =
        groups.iter().map(|group| group.name().to_owned()).collect();
    let mut issues = Vec::new();

    for group in groups {
        let name = group.name();
        if matches!(name, PROXY_DIRECT | PROXY_REJECT | PROXY_GLOBAL) {
            issues.push(ValidationIssue {
                code: "proxy_group_name",
                node: Some(name.to_owned()),
                field_path: Some(format!("proxy-groups.{name}.name")),
                message: format!("proxy group name `{name}` is reserved"),
            });
        }
        if declared_plain_names.contains(name) {
            issues.push(ValidationIssue {
                code: "proxy_group_name",
                node: Some(name.to_owned()),
                field_path: Some(format!("proxy-groups.{name}.name")),
                message: format!(
                    "proxy group name `{name}` duplicates a proxy name"
                ),
            });
        }

        let proxies = group.proxies().map_or(&[][..], Vec::as_slice);
        let providers = group.use_providers().map_or(&[][..], Vec::as_slice);
        if proxies.is_empty() && providers.is_empty() {
            issues.push(ValidationIssue {
                code: "proxy_group_empty",
                node: Some(name.to_owned()),
                field_path: Some(format!("proxy-groups.{name}")),
                message: format!("proxy group {name} has no proxies or providers"),
            });
        }

        if let OutboundGroupProtocol::Smart(smart) = group
            && let Err(error) = smart.validate()
        {
            issues.push(ValidationIssue {
                code: "proxy_group_config",
                node: Some(name.to_owned()),
                field_path: Some(format!("proxy-groups.{name}")),
                message: error.to_string(),
            });
        }

        for (index, proxy_name) in proxies.iter().enumerate() {
            if !valid_plain_names.contains(proxy_name)
                && !matches!(proxy_name.as_str(), PROXY_DIRECT | PROXY_REJECT)
                && !group_names.contains(proxy_name)
            {
                issues.push(ValidationIssue {
                    code: "proxy_group_reference",
                    node: Some(name.to_owned()),
                    field_path: Some(format!(
                        "proxy-groups.{name}.proxies[{index}]"
                    )),
                    message: format!("proxy {proxy_name} not found"),
                });
            }
        }

        for (index, provider_name) in providers.iter().enumerate() {
            if !provider_names.contains(provider_name) {
                issues.push(ValidationIssue {
                    code: "proxy_provider_reference",
                    node: Some(name.to_owned()),
                    field_path: Some(format!("proxy-groups.{name}.use[{index}]")),
                    message: format!("provider {provider_name} not found"),
                });
            }
        }
    }

    if let Err(error) =
        crate::app::outbound::manager::OutboundManager::validate_proxy_group_dependencies(
            groups,
        )
    {
        issues.push(ValidationIssue {
            code: "proxy_group_graph",
            node: None,
            field_path: Some("proxy-groups".to_owned()),
            message: error.to_string(),
        });
    }

    issues.sort_by(|left, right| {
        left.node
            .cmp(&right.node)
            .then_with(|| left.field_path.cmp(&right.field_path))
            .then_with(|| left.code.cmp(right.code))
    });
    issues
}

fn parse_config_definition(payload: &str) -> Result<def::Config, ValidationIssue> {
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(payload).map_err(|error| ValidationIssue {
            code: "yaml_syntax",
            node: None,
            field_path: None,
            message: error.to_string(),
        })?;
    value.apply_merge().map_err(|error| ValidationIssue {
        code: "yaml_merge",
        node: None,
        field_path: None,
        message: error.to_string(),
    })?;
    serde_path_to_error::deserialize(value.clone()).map_err(|error| {
        let path = error.path().to_string();
        ValidationIssue {
            code: "config_deserialization",
            node: node_for_config_path(&value, &path),
            field_path: (!path.is_empty()).then_some(path),
            message: error.inner().to_string(),
        }
    })
}

fn invalid_config_response(issue: ValidationIssue) -> Json<ValidateConfigResponse> {
    Json(ValidateConfigResponse {
        valid: false,
        validation_scope: "offline-config-outbound-connector-and-group-validation",
        errors: vec![issue],
        outbounds: Vec::new(),
    })
}

fn node_for_config_path(value: &serde_yaml::Value, path: &str) -> Option<String> {
    let index = path
        .strip_prefix("proxies[")?
        .split_once(']')?
        .0
        .parse::<usize>()
        .ok()?;
    value
        .get("proxies")?
        .as_sequence()?
        .get(index)?
        .get("name")?
        .as_str()
        .map(str::to_owned)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UpdateConfigRequest {
    path: Option<String>,
    payload: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct UploadConfigQuery {
    force: Option<bool>,
}

async fn update_configs(
    _q: Query<UploadConfigQuery>,
    State(state): State<ConfigState>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    let (reload_tx, cwd, config_path) = {
        let g = state.global_state.lock().await;
        (g.reload_tx.clone(), g.cwd.clone(), g.config_path.clone())
    };

    let cfg = match (req.path.as_deref(), req.payload) {
        (_, Some(payload)) => crate::Config::Str(payload),
        (Some(path), None) if !path.is_empty() => {
            let mut path = path.to_string();
            if !PathBuf::from(&path).is_absolute() {
                path = PathBuf::from(&cwd).join(path).to_string_lossy().to_string();
            }
            if !PathBuf::from(&path).exists() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("config file {path} not found"),
                )
                    .into_response();
            }
            if PathBuf::from(&path).is_dir() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("config path {path} is a directory"),
                )
                    .into_response();
            }
            crate::Config::File(path)
        }
        _ => match config_path {
            Some(path) => crate::Config::File(path),
            None => {
                return (StatusCode::BAD_REQUEST, "no path or payload provided")
                    .into_response();
            }
        },
    };

    let (done, wait) = tokio::sync::oneshot::channel();
    match reload_tx.send((cfg, done)).await {
        Ok(_) => match wait.await {
            Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
            Ok(Err(err)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "config reload task terminated unexpectedly",
            )
                .into_response(),
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not signal config reload",
        )
            .into_response(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct GetConfigResponse {
    port: Option<u16>,
    socks_port: Option<u16>,
    redir_port: Option<u16>,
    tproxy_port: Option<u16>,
    mixed_port: Option<u16>,
    bind_address: Option<String>,
    mode: Option<def::RunMode>,
    log_level: Option<def::LogLevel>,
    ipv6: Option<bool>,
    allow_lan: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listeners: Option<Vec<InboundEndpoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lan_ips: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_listen: Option<DnsListenInfo>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PatchConfigRequest {
    port: Option<u16>,
    socks_port: Option<u16>,
    redir_port: Option<u16>,
    tproxy_port: Option<u16>,
    mixed_port: Option<u16>,
    bind_address: Option<String>,
    mode: Option<def::RunMode>,
    log_level: Option<def::LogLevel>,
    ipv6: Option<bool>,
    allow_lan: Option<bool>,
}

impl PatchConfigRequest {
    fn rebuild_listeners(&self) -> bool {
        self.port.is_some()
            || self.socks_port.is_some()
            || self.redir_port.is_some()
            || self.tproxy_port.is_some()
            || self.mixed_port.is_some()
            || self.bind_address.is_some()
    }
}

fn validate_ipv6_update(
    requested: Option<bool>,
    allowed: bool,
) -> Result<(), &'static str> {
    if requested == Some(true) && !allowed {
        Err("IPv6 cannot be enabled while TUN is IPv4-only")
    } else {
        Ok(())
    }
}

async fn patch_configs(
    State(state): State<ConfigState>,
    Json(payload): Json<PatchConfigRequest>,
) -> impl IntoResponse {
    if let Err(message) = validate_ipv6_update(payload.ipv6, state.ipv6_allowed) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }

    let inbound_manager = state.inbound_manager.clone();
    let listener_snapshot = if payload.rebuild_listeners() {
        Some(inbound_manager.snapshot_options().await)
    } else {
        None
    };
    let mut need_restart = false;
    if let Some(bind_address) = payload.bind_address.clone() {
        match bind_address.parse::<BindAddress>() {
            Ok(bind_address) => {
                inbound_manager.set_bind_address(bind_address).await;
                need_restart = true;
            }
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid bind address: {bind_address}"),
                )
                    .into_response();
            }
        }
    }

    if payload.rebuild_listeners() {
        let ports = Ports {
            port: payload.port,
            socks_port: payload.socks_port,
            redir_port: payload.redir_port,
            tproxy_port: payload.tproxy_port,
            mixed_port: payload.mixed_port,
        };
        let changed = inbound_manager.change_ports(ports).await;
        need_restart |= changed;
    }

    if let Some(allow_lan) = payload.allow_lan
        && allow_lan != inbound_manager.get_allow_lan().await
    {
        inbound_manager.set_allow_lan(allow_lan).await;
    }

    if let Some(mode) = payload.mode {
        state.dispatcher.set_mode(mode).await;
    }

    if need_restart && let Err(err) = inbound_manager.restart().await {
        error!("failed to apply inbound config patch: {err}");
        if let Some(snapshot) = listener_snapshot {
            inbound_manager.restore_options(snapshot).await;
            if let Err(restore_err) = inbound_manager.restart().await {
                error!(
                    "failed to restore inbound listeners after patch failure: {restore_err}"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "failed to apply inbound configuration: {err}; failed to restore previous listeners: {restore_err}"
                    ),
                )
                    .into_response();
            }
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to apply inbound configuration: {err}"),
        )
            .into_response();
    }

    if let Some(log_level) = payload.log_level {
        let mut global_state = state.global_state.lock().await;
        global_state.log_level = log_level;
    }

    if let Some(ipv6) = payload.ipv6 {
        state.dns_resolver.set_ipv6(ipv6);
    }

    StatusCode::ACCEPTED.into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        node_for_config_path, parse_config_definition, validate_ipv6_update,
    };

    #[test]
    fn blocks_enabling_ipv6_for_ipv4_only_tun() {
        assert!(validate_ipv6_update(Some(true), false).is_err());
        assert!(validate_ipv6_update(Some(false), false).is_ok());
        assert!(validate_ipv6_update(None, false).is_ok());
        assert!(validate_ipv6_update(Some(true), true).is_ok());
    }

    #[test]
    fn client_capability_validation_path_identifies_outbound_name() {
        let value: serde_yaml::Value = serde_yaml::from_str(
            "proxies:\n  - name: edge-a\n    type: vless\n    uuid: invalid\n",
        )
        .unwrap();

        assert_eq!(
            node_for_config_path(&value, "proxies[0].uuid"),
            Some("edge-a".to_owned())
        );
    }

    #[test]
    fn client_capability_validation_reports_field_and_node() {
        let error = match parse_config_definition(
            "proxies:\n  - name: edge-a\n    type: not-supported\n",
        ) {
            Ok(_) => panic!("unsupported outbound type should fail deserialization"),
            Err(error) => error,
        };

        assert_eq!(error.node.as_deref(), Some("edge-a"));
        assert_eq!(error.field_path.as_deref(), Some("proxies[0].type"));
        assert_eq!(error.code, "config_deserialization");
        assert!(!error.message.is_empty());
    }
}
