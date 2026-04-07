use axum::{
    extract::Request, http::HeaderValue, middleware::Next, response::Response,
};

pub(crate) async fn fix_content_type(mut req: Request, next: Next) -> Response {
    if let Some(content_type) = req.headers().get("content-type")
        && content_type != "application/json"
    {
        req.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
    }

    next.run(req).await
}
