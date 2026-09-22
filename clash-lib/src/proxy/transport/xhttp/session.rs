use std::io;

use rand::RngExt;
use uuid::Uuid;

use super::uplink::ChunkSizeRange;

const MIN_SESSION_SPACE: u128 = 2u128 << 30;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SessionIdConfig {
    #[default]
    Uuid,
    Table {
        table: Vec<u8>,
        length: ChunkSizeRange,
    },
}

impl SessionIdConfig {
    pub fn from_table(table: &str, length: ChunkSizeRange) -> io::Result<Self> {
        if table.is_empty() || table == "uuid" {
            return Ok(Self::Uuid);
        }

        if length.min == 0 || length.min > length.max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xhttp session-length must start above zero and not be reversed",
            ));
        }

        let resolved = predefined_table(table).unwrap_or(table).as_bytes().to_vec();
        if resolved.is_empty() || !resolved.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xhttp session-table must contain non-empty ASCII characters",
            ));
        }

        if room_size(resolved.len(), length) < MIN_SESSION_SPACE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xhttp session-table or session-length is too small",
            ));
        }

        Ok(Self::Table {
            table: resolved,
            length,
        })
    }

    pub fn generate(&self) -> String {
        match self {
            Self::Uuid => Uuid::new_v4().to_string(),
            Self::Table { table, length } => {
                let len = sample_range(*length);
                let mut rng = rand::rng();
                let mut session = String::with_capacity(len);
                for _ in 0..len {
                    let index = rng.random_range(0..table.len());
                    session.push(table[index] as char);
                }
                session
            }
        }
    }
}

fn sample_range(range: ChunkSizeRange) -> usize {
    if range.min >= range.max {
        range.min
    } else {
        rand::rng().random_range(range.min..=range.max)
    }
}

fn room_size(table_size: usize, length: ChunkSizeRange) -> u128 {
    let base = table_size as u128;
    let mut sum = 0u128;

    for len in length.min..=length.max {
        let mut term = 1u128;
        for _ in 0..len {
            term = term.saturating_mul(base);
            if term >= MIN_SESSION_SPACE {
                break;
            }
        }
        sum = sum.saturating_add(term);
        if sum >= MIN_SESSION_SPACE {
            return sum;
        }
    }

    sum
}

fn predefined_table(name: &str) -> Option<&'static str> {
    Some(match name {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_uuid_modes_generate_canonical_uuid() {
        for config in [
            SessionIdConfig::default(),
            SessionIdConfig::from_table("uuid", ChunkSizeRange::fixed(10)).unwrap(),
        ] {
            let generated = config.generate();
            assert!(Uuid::parse_str(&generated).is_ok());
        }
    }

    #[test]
    fn predefined_base62_generates_requested_length() {
        let config =
            SessionIdConfig::from_table("Base62", ChunkSizeRange::fixed(10))
                .expect("Base62 with length 10 has sufficient entropy");

        let generated = config.generate();

        assert_eq!(generated.len(), 10);
        assert!(generated.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    }

    #[test]
    fn custom_ascii_table_is_supported() {
        let config = SessionIdConfig::from_table(
            "abcdef0123456789",
            ChunkSizeRange::fixed(10),
        )
        .expect("custom hex-like table should be valid");

        let generated = config.generate();

        assert_eq!(generated.len(), 10);
        assert!(
            generated
                .bytes()
                .all(|byte| b"abcdef0123456789".contains(&byte))
        );
    }

    #[test]
    fn too_small_session_space_is_rejected() {
        let err = SessionIdConfig::from_table("number", ChunkSizeRange::fixed(4))
            .expect_err("10^4 is below the minimum session space");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn non_ascii_custom_table_is_rejected() {
        let err = SessionIdConfig::from_table("abc中", ChunkSizeRange::fixed(16))
            .expect_err("session table must be ASCII");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
