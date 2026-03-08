#[derive(Clone, Debug)]
pub struct MetaCfg {
    pub base_path: String, // e.g. "/xhttp/"
}

pub fn normalize_base_path(mut p: String) -> String {
    if !p.starts_with('/') {
        p = format!("/{p}");
    }
    if !p.ends_with('/') {
        p.push('/');
    }
    p
}

/// Minimal placement = path.
/// Supports:
/// - stream-one: `/xhttp/` (no sessionId/seq)
/// - stream-down: `/xhttp/<sessionId>`
/// - packet-up: `/xhttp/<sessionId>/<seq>`
pub fn extract_meta_path(
    url_path: &str,
    base_path: &str,
) -> (Option<String>, Option<String>) {
    if !url_path.starts_with(base_path) {
        return (None, None);
    }
    let tail = &url_path[base_path.len()..];
    let mut it = tail.split('/').filter(|s| !s.is_empty());
    let sid = it.next().map(|s| s.to_string());
    let seq = it.next().map(|s| s.to_string());
    (sid, seq)
}
