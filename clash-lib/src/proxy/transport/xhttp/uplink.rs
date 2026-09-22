use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use rand::RngExt;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UplinkDataPlacement {
    #[default]
    Body,
    Header,
    Cookie,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkSizeRange {
    pub min: usize,
    pub max: usize,
}

impl ChunkSizeRange {
    pub fn fixed(size: usize) -> Self {
        Self {
            min: size,
            max: size,
        }
    }

    fn sample(self) -> usize {
        let min = self.min.max(1);
        let max = self.max.max(min);
        if min == max {
            min
        } else {
            rand::rng().random_range(min..=max)
        }
    }
}

impl Default for ChunkSizeRange {
    fn default() -> Self {
        Self::fixed(4096)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UplinkConfig {
    pub method: String,
    pub placement: UplinkDataPlacement,
    pub key: Option<String>,
    pub chunk_size: ChunkSizeRange,
}

impl Default for UplinkConfig {
    fn default() -> Self {
        Self {
            method: "POST".to_owned(),
            placement: UplinkDataPlacement::Body,
            key: None,
            chunk_size: ChunkSizeRange::default(),
        }
    }
}

impl UplinkConfig {
    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn content_type(&self) -> Option<&'static str> {
        matches!(self.placement, UplinkDataPlacement::Body)
            .then_some("application/octet-stream")
    }

    pub fn apply_payload(
        &self,
        payload: &[u8],
        headers: &mut HashMap<String, String>,
    ) -> Bytes {
        match self.placement {
            UplinkDataPlacement::Body => Bytes::copy_from_slice(payload),
            UplinkDataPlacement::Header => {
                let key = self.key.as_deref().unwrap_or("X-Data");
                let encoded = URL_SAFE_NO_PAD.encode(payload);
                for (index, chunk) in
                    sampled_chunks(&encoded, self.chunk_size).enumerate()
                {
                    headers.insert(format!("{key}-{index}"), chunk.to_owned());
                }
                Bytes::new()
            }
            UplinkDataPlacement::Cookie => {
                let key = self.key.as_deref().unwrap_or("x_data");
                let encoded = URL_SAFE_NO_PAD.encode(payload);
                for (index, chunk) in
                    sampled_chunks(&encoded, self.chunk_size).enumerate()
                {
                    append_cookie(headers, &format!("{key}_{index}"), chunk);
                }
                Bytes::new()
            }
        }
    }
}

fn sampled_chunks(
    encoded: &str,
    range: ChunkSizeRange,
) -> impl Iterator<Item = &str> {
    let mut offset = 0;
    std::iter::from_fn(move || {
        if offset >= encoded.len() {
            return None;
        }
        let end = (offset + range.sample()).min(encoded.len());
        let chunk = &encoded[offset..end];
        offset = end;
        Some(chunk)
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
    fn body_placement_preserves_raw_payload() {
        let config = UplinkConfig::default();
        let mut headers = HashMap::new();

        let body = config.apply_payload(b"hello", &mut headers);

        assert_eq!(body.as_ref(), b"hello");
        assert!(headers.is_empty());
        assert_eq!(config.content_type(), Some("application/octet-stream"));
    }

    #[test]
    fn header_placement_uses_base64url_chunks() {
        let config = UplinkConfig {
            method: "POST".to_owned(),
            placement: UplinkDataPlacement::Header,
            key: Some("X-Payload".to_owned()),
            chunk_size: ChunkSizeRange::fixed(4),
        };
        let mut headers = HashMap::new();

        let body = config.apply_payload(b"hello", &mut headers);

        assert!(body.is_empty());
        assert_eq!(headers.get("X-Payload-0").map(String::as_str), Some("aGVs"));
        assert_eq!(headers.get("X-Payload-1").map(String::as_str), Some("bG8"));
        assert_eq!(config.content_type(), None);
    }

    #[test]
    fn cookie_placement_appends_chunks_to_existing_cookie() {
        let config = UplinkConfig {
            method: "PUT".to_owned(),
            placement: UplinkDataPlacement::Cookie,
            key: Some("data".to_owned()),
            chunk_size: ChunkSizeRange::fixed(4),
        };
        let mut headers =
            HashMap::from([("Cookie".to_owned(), "existing=yes".to_owned())]);

        let body = config.apply_payload(b"hello", &mut headers);

        assert!(body.is_empty());
        assert_eq!(
            headers.get("Cookie").map(String::as_str),
            Some("existing=yes; data_0=aGVs; data_1=bG8")
        );
    }
}
