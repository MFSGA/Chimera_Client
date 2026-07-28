use axum::{
    body::Body,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../clash-dashboard/dist/"]
struct Assets;

pub async fn serve_index() -> impl IntoResponse {
    serve_path("index.html")
}

pub async fn serve_asset(Path(path): Path<String>) -> impl IntoResponse {
    serve_path(path.trim_start_matches('/'))
}

fn serve_path(path: &str) -> Response {
    match Assets::get(path) {
        Some(asset) => {
            let mime = content_type(path);
            let cache = if path == "index.html" {
                "no-cache"
            } else {
                "public, max-age=31536000, immutable"
            };
            Response::builder()
                .header(header::CONTENT_TYPE, mime)
                .header(header::CACHE_CONTROL, cache)
                .body(Body::from(asset.data.into_owned()))
                .unwrap()
        }
        None => match Assets::get("index.html") {
            Some(asset) => Response::builder()
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header(header::CACHE_CONTROL, "no-cache")
                .body(Body::from(asset.data.into_owned()))
                .unwrap(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain",
        _ => "application/octet-stream",
    }
}
