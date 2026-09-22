use std::{collections::HashMap, io};

use rand::RngExt;

use super::uplink::ChunkSizeRange;

const BASE62: &[u8] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PaddingPlacement {
    Cookie,
    Header,
    Query,
    #[default]
    QueryInHeader,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PaddingMethod {
    #[default]
    RepeatX,
    Tokenish,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaddingConfig {
    pub bytes: ChunkSizeRange,
    pub obfs_mode: bool,
    pub key: String,
    pub header: String,
    pub placement: PaddingPlacement,
    pub method: PaddingMethod,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            bytes: ChunkSizeRange {
                min: 100,
                max: 1_000,
            },
            obfs_mode: false,
            key: "x_padding".to_owned(),
            header: "Referer".to_owned(),
            placement: PaddingPlacement::QueryInHeader,
            method: PaddingMethod::RepeatX,
        }
    }
}

impl PaddingConfig {
    pub fn apply(
        &self,
        uri: &mut String,
        headers: &mut HashMap<String, String>,
    ) -> io::Result<()> {
        let target = sample_range(self.bytes);
        let (placement, key, header, method) = if self.obfs_mode {
            (
                self.placement,
                self.key.as_str(),
                self.header.as_str(),
                self.method,
            )
        } else {
            (
                PaddingPlacement::QueryInHeader,
                "x_padding",
                "Referer",
                PaddingMethod::RepeatX,
            )
        };
        let padding = generate_padding(method, target)?;

        match placement {
            PaddingPlacement::Cookie => append_cookie(headers, key, &padding),
            PaddingPlacement::Header => {
                headers.insert(header.to_owned(), padding);
            }
            PaddingPlacement::Query => append_query(uri, key, &padding),
            PaddingPlacement::QueryInHeader => {
                let base = uri.split_once('?').map(|(base, _)| base).unwrap_or(uri);
                headers.insert(header.to_owned(), format!("{base}?{key}={padding}"));
            }
        }

        Ok(())
    }
}

fn sample_range(range: ChunkSizeRange) -> usize {
    if range.min >= range.max {
        range.min
    } else {
        rand::rng().random_range(range.min..=range.max)
    }
}

fn generate_padding(method: PaddingMethod, target: usize) -> io::Result<String> {
    match method {
        PaddingMethod::RepeatX => Ok("X".repeat(target)),
        PaddingMethod::Tokenish => generate_tokenish_padding(target),
    }
}

fn generate_tokenish_padding(target: usize) -> io::Result<String> {
    if target == 0 {
        return Ok(String::new());
    }

    let mut rng = rand::rng();
    let initial_len = ((target * 5) / 4).max(1);
    let mut token = String::with_capacity(initial_len + 8);
    for _ in 0..initial_len {
        let index = rng.random_range(0..BASE62.len());
        token.push(BASE62[index] as char);
    }

    for iteration in 0..150 {
        let encoded_len = hpack_huffman_encoded_len(token.as_bytes())?;
        if encoded_len.abs_diff(target) <= 2 {
            return Ok(token);
        }

        if encoded_len < target {
            // X/Z both use 8-bit HPACK Huffman codes and therefore provide
            // stable one-byte growth while preserving a base62-looking token.
            token.push(if iteration % 2 == 0 { 'X' } else { 'Z' });
        } else if token.pop().is_none() {
            break;
        }
    }

    Err(io::Error::other(format!(
        "failed to generate tokenish padding near {target} HPACK bytes"
    )))
}

fn hpack_huffman_encoded_len(input: &[u8]) -> io::Result<usize> {
    let mut bits = 0usize;
    for byte in input {
        bits = bits
            .checked_add(base62_hpack_bits(*byte).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tokenish padding contains non-base62 byte",
                )
            })?)
            .ok_or_else(|| io::Error::other("HPACK padding length overflow"))?;
    }
    Ok(bits.div_ceil(8))
}

fn base62_hpack_bits(byte: u8) -> Option<usize> {
    Some(match byte {
        b'0'..=b'2' => 5,
        b'3'..=b'9' => 6,
        b'A' => 6,
        b'B'..=b'W' => 7,
        b'X' => 8,
        b'Y' => 7,
        b'Z' => 8,
        b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'b' | b'd' | b'f' | b'g' | b'h' | b'l' | b'm' | b'n' | b'p' | b'r'
        | b'u' => 6,
        b'j' | b'k' | b'q' | b'v'..=b'z' => 7,
        _ => return None,
    })
}

fn append_query(uri: &mut String, key: &str, value: &str) {
    let separator = if uri.contains('?') { '&' } else { '?' };
    uri.push(separator);
    uri.push_str(key);
    uri.push('=');
    uri.push_str(value);
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
    fn default_config_matches_mihomo_referer_header() {
        let config = PaddingConfig::default();

        assert_eq!(config.header, "Referer");
        assert_eq!(config.key, "x_padding");

        let mut uri = "https://example.com/xhttp/".to_owned();
        let mut headers = HashMap::new();
        config.apply(&mut uri, &mut headers).unwrap();

        assert!(headers.contains_key("Referer"));
    }

    #[test]
    fn legacy_padding_uses_referer_and_ignores_obfs_fields() {
        let config = PaddingConfig {
            bytes: ChunkSizeRange::fixed(8),
            obfs_mode: false,
            key: "ignored".to_owned(),
            header: "X-Ignored".to_owned(),
            placement: PaddingPlacement::Header,
            method: PaddingMethod::Tokenish,
        };
        let mut uri = "https://example.com/xhttp/session/0".to_owned();
        let mut headers = HashMap::new();

        config.apply(&mut uri, &mut headers).unwrap();

        assert_eq!(uri, "https://example.com/xhttp/session/0");
        assert_eq!(
            headers.get("Referer").map(String::as_str),
            Some("https://example.com/xhttp/session/0?x_padding=XXXXXXXX")
        );
        assert!(!headers.contains_key("X-Ignored"));
    }

    #[test]
    fn obfs_query_in_header_replaces_raw_url_query() {
        let config = PaddingConfig {
            bytes: ChunkSizeRange::fixed(4),
            obfs_mode: true,
            key: "_dc".to_owned(),
            header: "X-Cache".to_owned(),
            placement: PaddingPlacement::QueryInHeader,
            method: PaddingMethod::RepeatX,
        };
        let mut uri = "https://example.com/xhttp/?auth=session".to_owned();
        let mut headers = HashMap::new();

        config.apply(&mut uri, &mut headers).unwrap();

        assert_eq!(uri, "https://example.com/xhttp/?auth=session");
        assert_eq!(
            headers.get("X-Cache").map(String::as_str),
            Some("https://example.com/xhttp/?_dc=XXXX")
        );
    }

    #[test]
    fn obfs_query_and_cookie_placements_apply_to_request() {
        let query = PaddingConfig {
            bytes: ChunkSizeRange::fixed(3),
            obfs_mode: true,
            key: "pad".to_owned(),
            header: "X-Padding".to_owned(),
            placement: PaddingPlacement::Query,
            method: PaddingMethod::RepeatX,
        };
        let mut uri = "https://example.com/xhttp/?auth=session".to_owned();
        let mut headers = HashMap::new();
        query.apply(&mut uri, &mut headers).unwrap();
        assert_eq!(uri, "https://example.com/xhttp/?auth=session&pad=XXX");

        let cookie = PaddingConfig {
            placement: PaddingPlacement::Cookie,
            ..query
        };
        let mut uri = "https://example.com/xhttp/".to_owned();
        let mut headers =
            HashMap::from([("Cookie".to_owned(), "existing=yes".to_owned())]);
        cookie.apply(&mut uri, &mut headers).unwrap();
        assert_eq!(
            headers.get("Cookie").map(String::as_str),
            Some("existing=yes; pad=XXX")
        );
    }

    #[test]
    fn tokenish_padding_matches_hpack_target_tolerance() {
        for target in [16, 64, 100, 256] {
            let token = generate_tokenish_padding(target)
                .expect("tokenish padding should converge");
            assert!(token.bytes().all(|byte| BASE62.contains(&byte)));
            assert!(
                hpack_huffman_encoded_len(token.as_bytes())
                    .unwrap()
                    .abs_diff(target)
                    <= 2
            );
        }
    }
}
