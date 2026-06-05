use std::sync::Arc;

use axum::{Json, extract::State};

use crate::app::{api::AppState, dispatcher::StatisticsManager};

pub async fn handle(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mgr: Arc<StatisticsManager> = state.statistics_manager.clone();
    let stats = mgr.drain_user_stats().await;
    Json(
        serde_json::to_value(stats)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
    )
}
