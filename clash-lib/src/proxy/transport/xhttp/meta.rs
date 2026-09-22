use std::{collections::HashMap, io};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MetadataPlacement {
    #[default]
    Path,
    Query,
    Cookie,
    Header,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataConfig {
    pub session_placement: MetadataPlacement,
    pub session_key: Option<String>,
    pub seq_placement: MetadataPlacement,
    pub seq_key: Option<String>,
}

impl MetadataConfig {
    pub fn apply(
        &self,
        base_path: &str,
        headers: &mut HashMap<String, String>,
        session_id: &str,
        seq: Option<u64>,
    ) -> io::Result<String> {
        let mut path = base_path.to_owned();
        apply_value(
            &mut path,
            headers,
            self.session_placement,
            self.session_key.as_deref(),
            session_id,
        )?;

        if let Some(seq) = seq {
            apply_value(
                &mut path,
                headers,
                self.seq_placement,
                self.seq_key.as_deref(),
                &seq.to_string(),
            )?;
        }

        Ok(path)
    }
}

fn apply_value(
    path: &mut String,
    headers: &mut HashMap<String, String>,
    placement: MetadataPlacement,
    key: Option<&str>,
    value: &str,
) -> io::Result<()> {
    match placement {
        MetadataPlacement::Path => {
            append_path_segment(path, value);
        }
        MetadataPlacement::Query => {
            let key = require_key(key, "query")?;
            let separator = if path.contains('?') { '&' } else { '?' };
            path.push(separator);
            path.push_str(key);
            path.push('=');
            path.push_str(value);
        }
        MetadataPlacement::Cookie => {
            let key = require_key(key, "cookie")?;
            append_cookie(headers, key, value);
        }
        MetadataPlacement::Header => {
            let key = require_key(key, "header")?;
            headers.insert(key.to_owned(), value.to_owned());
        }
    }

    Ok(())
}

fn append_path_segment(path: &mut String, value: &str) {
    if let Some(query_index) = path.find('?') {
        let query = path.split_off(query_index);
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(value);
        path.push_str(&query);
    } else {
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(value);
    }
}

fn require_key<'a>(key: Option<&'a str>, placement: &str) -> io::Result<&'a str> {
    key.filter(|key| !key.is_empty()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("xhttp {placement} metadata placement requires a non-empty key"),
        )
    })
}

fn append_cookie(headers: &mut HashMap<String, String>, key: &str, value: &str) {
    if let Some(existing_key) = headers
        .keys()
        .find(|candidate| candidate.eq_ignore_ascii_case("cookie"))
        .cloned()
    {
        if let Some(existing) = headers.get_mut(&existing_key) {
            if !existing.is_empty() {
                existing.push_str("; ");
            }
            existing.push_str(key);
            existing.push('=');
            existing.push_str(value);
        }
    } else {
        headers.insert("Cookie".to_owned(), format!("{key}={value}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_placement_preserves_legacy_shape() {
        let config = MetadataConfig::default();
        let mut headers = HashMap::new();

        let path = config
            .apply("/xhttp/", &mut headers, "session-id", Some(7))
            .expect("path placement should apply");

        assert_eq!(path, "/xhttp/session-id/7");
        assert!(headers.is_empty());
    }

    #[test]
    fn path_placement_inserts_metadata_before_existing_query() {
        let config = MetadataConfig::default();
        let mut headers = HashMap::new();

        let path = config
            .apply("/xhttp/?ed=2048", &mut headers, "session-id", Some(7))
            .expect("path placement should preserve query");

        assert_eq!(path, "/xhttp/session-id/7?ed=2048");
        assert!(headers.is_empty());
    }

    #[test]
    fn query_placement_adds_session_and_seq() {
        let config = MetadataConfig {
            session_placement: MetadataPlacement::Query,
            session_key: Some("auth".to_owned()),
            seq_placement: MetadataPlacement::Query,
            seq_key: Some("offset".to_owned()),
        };
        let mut headers = HashMap::new();

        let path = config
            .apply("/upload/", &mut headers, "abc", Some(3))
            .expect("query placement should apply");

        assert_eq!(path, "/upload/?auth=abc&offset=3");
    }

    #[test]
    fn cookie_and_header_placements_apply_without_path_changes() {
        let config = MetadataConfig {
            session_placement: MetadataPlacement::Cookie,
            session_key: Some("sid".to_owned()),
            seq_placement: MetadataPlacement::Header,
            seq_key: Some("X-Seq".to_owned()),
        };
        let mut headers =
            HashMap::from([("Cookie".to_owned(), "existing=yes".to_owned())]);

        let path = config
            .apply("/upload/", &mut headers, "abc", Some(9))
            .expect("cookie/header placement should apply");

        assert_eq!(path, "/upload/");
        assert_eq!(
            headers.get("Cookie").map(String::as_str),
            Some("existing=yes; sid=abc")
        );
        assert_eq!(headers.get("X-Seq").map(String::as_str), Some("9"));
    }

    #[test]
    fn non_path_placement_requires_key() {
        let config = MetadataConfig {
            session_placement: MetadataPlacement::Query,
            ..Default::default()
        };
        let mut headers = HashMap::new();

        let err = config
            .apply("/upload/", &mut headers, "abc", None)
            .expect_err("query placement without key must fail");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
