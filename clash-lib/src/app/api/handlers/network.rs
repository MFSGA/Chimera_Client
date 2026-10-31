use std::sync::Arc;

use crate::{
    GlobalState,
    app::{
        api::AppState,
        network::{NetworkResetResponse, NetworkStatus},
    },
};
use axum::{Json, Router, extract::State, routing::post};
use http::StatusCode;
use serde::Deserialize;

#[derive(Clone)]
struct NetworkState {
    global: Arc<tokio::sync::Mutex<GlobalState>>,
}

pub fn routes(
    global: Arc<tokio::sync::Mutex<GlobalState>>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", axum::routing::get(network_status))
        .route("/reset", post(reset_network))
        .with_state(NetworkState { global })
}

pub fn status_routes(
    global: Arc<tokio::sync::Mutex<GlobalState>>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", axum::routing::get(network_status))
        .route(
            "/network/path-preference",
            axum::routing::get(get_path_preference)
                .put(put_path_preference)
                .delete(clear_temporary_path_preference),
        )
        .route(
            "/network/effective-paths",
            axum::routing::get(effective_paths),
        )
        .route(
            "/network/path-decision/{flow_id}",
            axum::routing::get(path_decision),
        )
        .route(
            "/network/path-decisions",
            axum::routing::get(path_decisions),
        )
        .with_state(NetworkState { global })
}

async fn network_status(State(state): State<NetworkState>) -> Json<NetworkStatus> {
    let status = state.global.lock().await.network_status.clone();
    Json(status.read().await.clone())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PathPreferenceRequest {
    priority: Vec<crate::app::flow::PathPriority>,
    ttl_ms: Option<u64>,
}

async fn get_path_preference(
    State(state): State<NetworkState>,
) -> Json<crate::app::runtime_state::PathPreferenceView> {
    let status = state.global.lock().await.network_status.clone();
    Json(status.write().await.path_preference_view())
}

async fn put_path_preference(
    State(state): State<NetworkState>,
    Json(request): Json<PathPreferenceRequest>,
) -> Result<Json<crate::app::runtime_state::PathPreferenceView>, (StatusCode, String)>
{
    let status = state.global.lock().await.network_status.clone();
    status
        .write()
        .await
        .set_path_priority(request.priority, request.ttl_ms)
        .map(Json)
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))
}

async fn clear_temporary_path_preference(
    State(state): State<NetworkState>,
) -> Result<Json<crate::app::runtime_state::PathPreferenceView>, (StatusCode, String)>
{
    let status = state.global.lock().await.network_status.clone();
    status
        .write()
        .await
        .clear_temporary_path_priority()
        .map(Json)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))
}

async fn effective_paths(
    State(state): State<NetworkState>,
) -> Json<serde_json::Value> {
    let status = state.global.lock().await.network_status.clone();
    Json(status.write().await.effective_paths_view())
}

async fn path_decision(
    State(state): State<NetworkState>,
    axum::extract::Path(flow_id): axum::extract::Path<String>,
) -> Result<Json<crate::app::flow::PathDecisionRecord>, (StatusCode, String)> {
    let flow_id = uuid::Uuid::parse_str(&flow_id)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let status = state.global.lock().await.network_status.clone();
    status
        .write()
        .await
        .path_decision(flow_id)
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "path decision not found or expired".to_owned(),
            )
        })
}

async fn path_decisions(
    State(state): State<NetworkState>,
) -> Json<Vec<crate::app::flow::PathDecisionRecord>> {
    let status = state.global.lock().await.network_status.clone();
    Json(status.write().await.path_decisions_snapshot())
}

async fn reset_network(
    State(state): State<NetworkState>,
) -> Result<Json<NetworkResetResponse>, (StatusCode, String)> {
    let sender = state.global.lock().await.network_reset_tx.clone();
    let (done, receiver) = tokio::sync::oneshot::channel();
    tokio::time::timeout(std::time::Duration::from_secs(5), sender.send(done))
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;
    let response =
        tokio::time::timeout(std::time::Duration::from_secs(45), receiver)
            .await
            .map_err(internal_error)?
            .map_err(internal_error)?
            .map_err(internal_error)?;
    Ok(Json(response))
}

fn internal_error(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GlobalState, runner::Runner};
    use futures::future::BoxFuture;
    use http_body_util::BodyExt;

    struct NoopRunner;

    impl Runner for NoopRunner {
        fn run_async(&self) {}

        fn shutdown(&self) {}

        fn join(&self) -> BoxFuture<'_, crate::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn fake_ip_mapping_failure_round_trips_through_explain_api() {
        let expired_flow_id = uuid::Uuid::new_v4();
        let mut status = NetworkStatus::default();
        let (config_version, policy_version, network_version, operation_id) =
            status.decision_versions();
        assert!(
            status.record_path_decision(crate::app::flow::PathDecisionRecord {
                flow_id: expired_flow_id,
                config_version,
                config_version_at_completion: None,
                policy_version,
                network_version,
                operation_id,
                outcome: crate::app::flow::PathExecutionOutcome::Connected,
                route: crate::app::flow::RouteDecision {
                    outbound: "DIRECT".to_owned(),
                    rule: None,
                },
                destination: None,
                candidate_paths: Vec::new(),
                selected_path: None,
                rejected: Vec::new(),
                failure_kind: None,
                reason: "connectedOnBoundPath".to_owned(),
                recorded_at_ms: chrono::Utc::now().timestamp_millis(),
            })
        );
        status.expire_path_decisions_for_test();

        let flow_id = uuid::Uuid::new_v4();
        let (config_version, policy_version, network_version, operation_id) =
            status.decision_versions();
        let explain_record = crate::app::flow::PathDecisionRecord {
            flow_id,
            config_version,
            config_version_at_completion: None,
            policy_version,
            network_version,
            operation_id,
            outcome: crate::app::flow::PathExecutionOutcome::PathPlanningFailed,
            route: crate::app::flow::RouteDecision {
                outbound: "notEvaluated".to_owned(),
                rule: None,
            },
            destination: Some("198.18.0.10:443".to_owned()),
            candidate_paths: Vec::new(),
            selected_path: None,
            rejected: Vec::new(),
            failure_kind: Some("fakeIpMappingMissing".to_owned()),
            reason: "fake-IP destination has no reverse mapping; route selection was skipped"
                .to_owned(),
            recorded_at_ms: chrono::Utc::now().timestamp_millis(),
        };
        assert!(status.record_path_decision(explain_record.clone()));

        let (network_reset_tx, _) = tokio::sync::mpsc::channel(1);
        let global = Arc::new(tokio::sync::Mutex::new(GlobalState {
            log_level: crate::config::def::LogLevel::Info,
            #[cfg(feature = "tun")]
            tunnel_runner: Arc::new(NoopRunner),
            dns_listener: Arc::new(NoopRunner),
            reload_tx: tokio::sync::mpsc::channel(1).0,
            network_reset_tx,
            network_status: Arc::new(tokio::sync::RwLock::new(status)),
            cwd: String::new(),
            config_path: None,
        }));
        let (log_source_tx, _) = tokio::sync::broadcast::channel(1);
        let app_state = Arc::new(crate::app::api::AppState {
            log_source_tx,
            statistics_manager: crate::app::dispatcher::StatisticsManager::new(),
        });
        let cors_origins = vec!["https://network-test.example".to_owned()];
        let (cors, valid_origin_count) =
            crate::app::api::runner::build_cors_layer(Some(&cors_origins));
        assert_eq!(valid_origin_count, 1);
        let app = crate::app::api::runner::add_shared_http_layers(
            Router::new().nest("/runtime", status_routes(global)),
            app_state,
            cors,
        )
        .route_layer(
            crate::app::api::middlewares::auth::AuthMiddlewareLayer::new(
                "test-secret".to_owned(),
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test API listener should serve requests");
        });
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(io).await.unwrap();
        let connection_task = tokio::spawn(async move {
            connection
                .await
                .expect("test API HTTP connection should remain usable");
        });

        let unauthorized_list = sender
            .send_request(
                http::Request::builder()
                    .uri("/runtime/network/path-decisions")
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized_list.status(), StatusCode::UNAUTHORIZED);

        let list = sender
            .send_request(
                http::Request::builder()
                    .uri("/runtime/network/path-decisions")
                    .header(http::header::AUTHORIZATION, "Bearer test-secret")
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let list_body = list.into_body().collect().await.unwrap();
        let list_body = list_body.to_bytes();
        let listed: serde_json::Value = serde_json::from_slice(&list_body).unwrap();
        let expected = serde_json::to_value(&explain_record).unwrap();
        assert_eq!(listed, serde_json::json!([expected.clone()]));

        let active_detail = sender
            .send_request(
                http::Request::builder()
                    .uri(format!("/runtime/network/path-decision/{flow_id}"))
                    .header(http::header::AUTHORIZATION, "Bearer test-secret")
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(active_detail.status(), StatusCode::OK);
        let active_detail_body = active_detail
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&active_detail_body)
                .unwrap(),
            expected
        );

        let detail = sender
            .send_request(
                http::Request::builder()
                    .uri(format!("/runtime/network/path-decision/{expired_flow_id}"))
                    .header(http::header::AUTHORIZATION, "Bearer test-secret")
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::NOT_FOUND);
        let detail_body = detail.into_body().collect().await.unwrap();
        let detail_body = detail_body.to_bytes();
        assert!(String::from_utf8_lossy(&detail_body).contains("expired"));

        let preflight = sender
            .send_request(
                http::Request::builder()
                    .method(http::Method::OPTIONS)
                    .uri(format!("/runtime/network/path-decision/{flow_id}"))
                    .header(http::header::ORIGIN, "https://network-test.example")
                    .header(http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .header(
                        http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "authorization",
                    )
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::OK);
        assert_eq!(
            preflight
                .headers()
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("https://network-test.example")
        );
        drop(sender);
        connection_task.abort();
        server_task.abort();
    }

    #[test]
    fn response_uses_stable_camel_case_fields() {
        let value = serde_json::to_value(NetworkResetResponse {
            dns_transports_reset: 2,
            connection_pools_reset: 1,
        })
        .unwrap();

        assert_eq!(value["dnsTransportsReset"], 2);
        assert_eq!(value["connectionPoolsReset"], 1);
    }
}
