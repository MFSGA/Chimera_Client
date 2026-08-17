use base64::{Engine, engine::general_purpose::STANDARD};

pub(crate) struct KeyBytes(pub [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                let decoded_key =
                    STANDARD.decode(s).map_err(|_| "Illegal character in key")?;
                if decoded_key.len() != internal.len() {
                    return Err("Illegal character in key");
                }
                internal.copy_from_slice(&decoded_key);
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::KeyBytes;

    const BASE64_KEY: &str = "KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=";

    #[test]
    fn wireguard_key_accepts_base64_and_hex() {
        let base64 =
            KeyBytes::from_str(BASE64_KEY).expect("base64 key should parse");
        let hex = base64
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let parsed_hex = KeyBytes::from_str(&hex).expect("hex key should parse");
        assert_eq!(parsed_hex.0, base64.0);
    }

    #[test]
    fn wireguard_key_rejects_invalid_size_and_characters() {
        assert!(matches!(
            KeyBytes::from_str("short"),
            Err("Illegal key size")
        ));
        assert!(matches!(
            KeyBytes::from_str(&"z".repeat(64)),
            Err("Illegal character in key")
        ));
    }
}
