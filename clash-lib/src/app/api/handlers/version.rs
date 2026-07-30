use axum::response::IntoResponse;
use serde_json::json;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn handle() -> impl IntoResponse {
    axum::Json(json!({
        "version": VERSION,
        "meta": false
    }))
}
