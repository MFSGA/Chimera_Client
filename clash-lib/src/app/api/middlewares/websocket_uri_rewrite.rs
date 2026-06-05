use axum::{body::Body, http::Request};

#[allow(dead_code)]
pub fn rewrite_websocket_uri(mut req: Request<Body>) -> Request<Body> {
    let is_websocket = req
        .headers()
        .get("upgrade")
        .map(|upgrade| upgrade == "websocket")
        .unwrap_or(false);

    if !is_websocket {
        return req;
    }

    let uri = req.uri().clone();
    let path = uri.path();
    let has_ws_prefix = path == "/ws" || path.starts_with("/ws/");
    if has_ws_prefix {
        return req;
    }

    let new_path = if path == "/" {
        "/ws".to_string()
    } else {
        format!("/ws{}", path.trim_end_matches('/'))
    };
    let new_path_and_query = match uri.query() {
        Some(query) => format!("{new_path}?{query}"),
        None => new_path,
    };

    if let Ok(path_and_query) = new_path_and_query.parse() {
        let mut parts = uri.into_parts();
        parts.path_and_query = Some(path_and_query);
        if let Ok(uri) = http::Uri::from_parts(parts) {
            *req.uri_mut() = uri;
        }
    }

    req
}
