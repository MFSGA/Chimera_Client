use std::{collections::HashMap, sync::Arc};

use axum::{Json, Router, extract::State, routing::get};

use crate::app::{api::AppState, router::ThreadSafeRouter};

#[derive(Clone)]
struct RuleState {
    router: ThreadSafeRouter,
}

pub fn routes(router: ThreadSafeRouter) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_rules))
        .with_state(RuleState { router })
}

async fn get_rules(
    State(state): State<RuleState>,
) -> Json<HashMap<&'static str, serde_json::Value>> {
    let rules = state.router.get_all_rules();
    let mut response = HashMap::new();
    response.insert("rules", serde_json::to_value(rules).unwrap_or_default());
    Json(response)
}
