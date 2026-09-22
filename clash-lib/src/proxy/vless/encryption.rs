use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const METHOD: &str = "mlkem768x25519plus";
const X25519_PUBLIC_KEY_LEN: usize = 32;
const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
const KEY_TOKEN_MIN_CHARS: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Appearance {
    Native,
    XorPub,
    Random,
}

impl Appearance {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::XorPub => "xorpub",
            Self::Random => "random",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RttMode {
    OneRtt,
    ZeroRtt,
}

impl RttMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OneRtt => "1rtt",
            Self::ZeroRtt => "0rtt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyKind {
    X25519,
    MlKem768,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyMaterial {
    pub(crate) kind: KeyKind,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) appearance: Appearance,
    pub(crate) rtt: RttMode,
    pub(crate) padding: Vec<String>,
    pub(crate) keys: Vec<KeyMaterial>,
}

impl Config {
    pub(crate) fn parse(raw: &str) -> io::Result<Self> {
        let parts = raw.split('.').collect::<Vec<_>>();
        if parts.len() < 4 {
            return Err(invalid(
                "vless encryption must contain method, appearance, RTT mode, and at least one key",
            ));
        }

        if parts[0] != METHOD {
            return Err(invalid(format!(
                "unsupported vless encryption method: {}",
                parts[0]
            )));
        }

        let appearance = match parts[1] {
            "native" => Appearance::Native,
            "xorpub" => Appearance::XorPub,
            "random" => Appearance::Random,
            other => {
                return Err(invalid(format!(
                    "unsupported vless encryption appearance: {other}"
                )));
            }
        };

        let rtt = match parts[2] {
            "1rtt" => RttMode::OneRtt,
            "0rtt" => RttMode::ZeroRtt,
            other => {
                return Err(invalid(format!(
                    "unsupported vless encryption RTT mode: {other}"
                )));
            }
        };

        let mut padding = Vec::new();
        let mut keys = Vec::new();
        let mut key_section_started = false;

        for token in &parts[3..] {
            if token.is_empty() {
                return Err(invalid("vless encryption contains an empty block"));
            }

            if token.len() < KEY_TOKEN_MIN_CHARS {
                if key_section_started {
                    return Err(invalid(
                        "vless encryption padding blocks must precede key material",
                    ));
                }
                padding.push((*token).to_owned());
                continue;
            }

            key_section_started = true;
            let decoded = URL_SAFE_NO_PAD.decode(token).map_err(|err| {
                invalid(format!(
                    "invalid vless encryption base64url key material: {err}"
                ))
            })?;

            let kind = match decoded.len() {
                X25519_PUBLIC_KEY_LEN => KeyKind::X25519,
                MLKEM768_PUBLIC_KEY_LEN => KeyKind::MlKem768,
                len => {
                    return Err(invalid(format!(
                        "invalid vless encryption key length: expected 32 or 1184 bytes, got {len}"
                    )));
                }
            };
            keys.push(KeyMaterial {
                kind,
                bytes: decoded,
            });
        }

        if keys.is_empty() {
            return Err(invalid(
                "vless encryption requires at least one X25519 or ML-KEM-768 key",
            ));
        }

        Ok(Self {
            appearance,
            rtt,
            padding,
            keys,
        })
    }

    #[cfg(feature = "aws-lc-rs")]
    pub(crate) fn validate_crypto_keys(&self) -> io::Result<()> {
        use aws_lc_rs::{
            agreement,
            kem::{EncapsulationKey, ML_KEM_768},
        };

        for key in &self.keys {
            match key.kind {
                KeyKind::X25519 => {
                    let unparsed = agreement::UnparsedPublicKey::new(
                        &agreement::X25519,
                        &key.bytes,
                    );
                    let _: agreement::ParsedPublicKey =
                        unparsed.try_into().map_err(|err| {
                            invalid(format!(
                                "invalid X25519 vless encryption public key: {err}"
                            ))
                        })?;
                }
                KeyKind::MlKem768 => {
                    EncapsulationKey::new(&ML_KEM_768, &key.bytes).map_err(|err| {
                        invalid(format!(
                            "invalid ML-KEM-768 vless encryption public key: {err}"
                        ))
                    })?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn summary(&self) -> String {
        let x25519 = self
            .keys
            .iter()
            .filter(|key| matches!(key.kind, KeyKind::X25519))
            .count();
        let mlkem768 = self
            .keys
            .iter()
            .filter(|key| matches!(key.kind, KeyKind::MlKem768))
            .count();

        format!(
            "{}.{}; padding-blocks={}; x25519-keys={x25519}; mlkem768-keys={mlkem768}",
            self.appearance.as_str(),
            self.rtt.as_str(),
            self.padding.len(),
        )
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_key(len: usize, value: u8) -> String {
        URL_SAFE_NO_PAD.encode(vec![value; len])
    }

    #[test]
    fn parses_x25519_and_mlkem_key_chain() {
        let x25519 = encoded_key(X25519_PUBLIC_KEY_LEN, 7);
        let mlkem = encoded_key(MLKEM768_PUBLIC_KEY_LEN, 9);
        let raw =
            format!("{METHOD}.xorpub.1rtt.100-111-1111.75-0-111.{x25519}.{mlkem}");

        let config = Config::parse(&raw).expect("valid encryption should parse");

        assert_eq!(config.appearance, Appearance::XorPub);
        assert_eq!(config.rtt, RttMode::OneRtt);
        assert_eq!(
            config.padding,
            vec!["100-111-1111".to_owned(), "75-0-111".to_owned()]
        );
        assert_eq!(
            config.keys.iter().map(|key| key.kind).collect::<Vec<_>>(),
            vec![KeyKind::X25519, KeyKind::MlKem768]
        );
    }

    #[test]
    fn parses_zero_rtt_random_mode() {
        let key = encoded_key(X25519_PUBLIC_KEY_LEN, 3);
        let raw = format!("{METHOD}.random.0rtt.{key}");

        let config = Config::parse(&raw).expect("0rtt encryption should parse");

        assert_eq!(config.appearance, Appearance::Random);
        assert_eq!(config.rtt, RttMode::ZeroRtt);
        assert!(config.padding.is_empty());
    }

    #[test]
    fn rejects_wrong_method_appearance_and_rtt() {
        let key = encoded_key(X25519_PUBLIC_KEY_LEN, 1);

        for raw in [
            format!("other.native.1rtt.{key}"),
            format!("{METHOD}.opaque.1rtt.{key}"),
            format!("{METHOD}.native.2rtt.{key}"),
        ] {
            assert!(Config::parse(&raw).is_err(), "{raw} must fail");
        }
    }

    #[test]
    fn rejects_missing_or_invalid_key_material() {
        for raw in [
            format!("{METHOD}.native.1rtt.100-200"),
            format!("{METHOD}.native.1rtt.not-a-valid-base64url-key-token"),
            format!("{METHOD}.native.1rtt.{}", encoded_key(64, 5)),
        ] {
            assert!(Config::parse(&raw).is_err(), "{raw} must fail");
        }
    }

    #[test]
    fn rejects_padding_after_key_material() {
        let key = encoded_key(X25519_PUBLIC_KEY_LEN, 8);
        let raw = format!("{METHOD}.native.1rtt.{key}.100-200");

        let err =
            Config::parse(&raw).expect_err("padding after key material must fail");

        assert!(
            err.to_string().contains("must precede key material"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn summary_reports_parsed_shape_without_key_material() {
        let key = encoded_key(X25519_PUBLIC_KEY_LEN, 2);
        let raw = format!("{METHOD}.native.1rtt.100-200.{key}");
        let config = Config::parse(&raw).unwrap();

        assert_eq!(
            config.summary(),
            "native.1rtt; padding-blocks=1; x25519-keys=1; mlkem768-keys=0"
        );
    }

    #[cfg(feature = "aws-lc-rs")]
    #[test]
    fn crypto_validation_accepts_generated_x25519_and_mlkem_keys() {
        use aws_lc_rs::{
            agreement,
            kem::{DecapsulationKey, ML_KEM_768},
        };

        let x25519_private =
            agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let x25519_public = x25519_private.compute_public_key().unwrap();

        let mlkem_private = DecapsulationKey::generate(&ML_KEM_768).unwrap();
        let mlkem_public = mlkem_private.encapsulation_key().unwrap();
        let mlkem_public_bytes = mlkem_public.key_bytes().unwrap();

        let raw = format!(
            "{METHOD}.native.1rtt.{}.{}",
            URL_SAFE_NO_PAD.encode(x25519_public.as_ref()),
            URL_SAFE_NO_PAD.encode(mlkem_public_bytes.as_ref()),
        );
        let config = Config::parse(&raw).expect("generated keys should parse");

        config
            .validate_crypto_keys()
            .expect("generated crypto keys should validate");
    }
}
