use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const METHOD: &str = "mlkem768x25519plus";
const X25519_PUBLIC_KEY_LEN: usize = 32;
const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
#[cfg(feature = "vless-encryption")]
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const KEY_TOKEN_MIN_CHARS: usize = 20;
const DEFAULT_PADDING: [(PaddingKind, i64, i64, i64); 3] = [
    (PaddingKind::Length, 100, 111, 1111),
    (PaddingKind::Gap, 75, 0, 111),
    (PaddingKind::Length, 50, 0, 3333),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Appearance {
    Native,
    XorPub,
    Random,
}

impl Appearance {
    #[cfg(feature = "vless-encryption")]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::XorPub => "xorpub",
            Self::Random => "random",
        }
    }

    #[cfg(feature = "vless-encryption")]
    const fn xor_mode(self) -> u32 {
        match self {
            Self::Native => 0,
            Self::XorPub => 1,
            Self::Random => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RttMode {
    OneRtt,
    ZeroRtt,
}

impl RttMode {
    #[cfg(feature = "vless-encryption")]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PaddingKind {
    Length,
    Gap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PaddingRule {
    pub(crate) kind: PaddingKind,
    pub(crate) probability: i64,
    pub(crate) from: i64,
    pub(crate) to: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) appearance: Appearance,
    pub(crate) rtt: RttMode,
    pub(crate) padding: Vec<PaddingRule>,
    pub(crate) keys: Vec<KeyMaterial>,
}

#[cfg(feature = "vless-encryption")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedCrypto {
    pub(crate) xor_mode: u32,
    pub(crate) relays_length: usize,
    pub(crate) key_hashes: Vec<[u8; 32]>,
}

#[cfg(feature = "vless-encryption")]
impl PreparedCrypto {
    pub(crate) fn summary(&self) -> String {
        format!(
            "xor-mode={}; relay-bytes={}; key-hashes={}",
            self.xor_mode,
            self.relays_length,
            self.key_hashes.len()
        )
    }
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

        let padding = parse_padding(&padding)?;

        Ok(Self {
            appearance,
            rtt,
            padding,
            keys,
        })
    }

    #[cfg(any(feature = "aws-lc-rs", feature = "vless-encryption"))]
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

    #[cfg(feature = "vless-encryption")]
    pub(crate) fn prepare_crypto(&self) -> io::Result<PreparedCrypto> {
        self.validate_crypto_keys()?;

        let relays_length = self
            .keys
            .iter()
            .map(|key| match key.kind {
                KeyKind::X25519 => X25519_PUBLIC_KEY_LEN + 32,
                KeyKind::MlKem768 => MLKEM768_CIPHERTEXT_LEN + 32,
            })
            .sum::<usize>()
            .checked_sub(32)
            .ok_or_else(|| invalid("vless encryption key chain is empty"))?;

        let key_hashes = self
            .keys
            .iter()
            .map(|key| *blake3::hash(&key.bytes).as_bytes())
            .collect();

        Ok(PreparedCrypto {
            xor_mode: self.appearance.xor_mode(),
            relays_length,
            key_hashes,
        })
    }

    #[cfg(feature = "vless-encryption")]
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

fn parse_padding(blocks: &[String]) -> io::Result<Vec<PaddingRule>> {
    if blocks.is_empty() {
        return Ok(DEFAULT_PADDING
            .into_iter()
            .map(|(kind, probability, from, to)| PaddingRule {
                kind,
                probability,
                from,
                to,
            })
            .collect());
    }

    let mut rules = Vec::with_capacity(blocks.len());
    let mut max_padding_len = 0_i64;

    for (index, block) in blocks.iter().enumerate() {
        let parts = block.split('-').collect::<Vec<_>>();
        if parts.len() < 3 || parts[..3].iter().any(|part| part.is_empty()) {
            return Err(invalid(format!(
                "invalid vless encryption padding length/gap parameter: {block}"
            )));
        }

        let parse = |value: &str| {
            value.parse::<i64>().map_err(|err| {
                invalid(format!(
                    "invalid vless encryption padding parameter '{block}': {err}"
                ))
            })
        };
        let probability = parse(parts[0])?;
        let from = parse(parts[1])?;
        let to = parse(parts[2])?;

        if !(0..=100).contains(&probability) {
            return Err(invalid(format!(
                "vless encryption padding probability must be between 0 and 100: {block}"
            )));
        }
        if from < 0 || to < 0 || from > to {
            return Err(invalid(format!(
                "invalid vless encryption padding range: {block}"
            )));
        }
        if index == 0 && (probability != 100 || from < 35 || to < 35) {
            return Err(invalid(
                "first vless encryption padding length must be 100% and at least 35 bytes",
            ));
        }

        let kind = if index % 2 == 0 {
            max_padding_len = max_padding_len.saturating_add(from.max(to));
            PaddingKind::Length
        } else {
            PaddingKind::Gap
        };
        rules.push(PaddingRule {
            kind,
            probability,
            from,
            to,
        });
    }

    if max_padding_len > 65_553 {
        return Err(invalid(
            "total vless encryption padding length must not exceed 65553 bytes",
        ));
    }

    Ok(rules)
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
            vec![
                PaddingRule {
                    kind: PaddingKind::Length,
                    probability: 100,
                    from: 111,
                    to: 1111,
                },
                PaddingRule {
                    kind: PaddingKind::Gap,
                    probability: 75,
                    from: 0,
                    to: 111,
                },
            ]
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
        assert_eq!(
            config.padding,
            vec![
                PaddingRule {
                    kind: PaddingKind::Length,
                    probability: 100,
                    from: 111,
                    to: 1111,
                },
                PaddingRule {
                    kind: PaddingKind::Gap,
                    probability: 75,
                    from: 0,
                    to: 111,
                },
                PaddingRule {
                    kind: PaddingKind::Length,
                    probability: 50,
                    from: 0,
                    to: 3333,
                },
            ]
        );
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
        let raw = format!("{METHOD}.native.1rtt.100-200-300.{key}");
        let config = Config::parse(&raw).unwrap();

        assert_eq!(
            config.summary(),
            "native.1rtt; padding-blocks=1; x25519-keys=1; mlkem768-keys=0"
        );
    }

    #[test]
    fn rejects_invalid_padding_rules() {
        let key = encoded_key(X25519_PUBLIC_KEY_LEN, 4);

        for raw in [
            format!("{METHOD}.native.1rtt.99-111-1111.{key}"),
            format!("{METHOD}.native.1rtt.100-34-1111.{key}"),
            format!("{METHOD}.native.1rtt.100-111.{key}"),
            format!("{METHOD}.native.1rtt.101-111-1111.{key}"),
            format!("{METHOD}.native.1rtt.100-1111-111.{key}"),
            format!("{METHOD}.native.1rtt.100--1-1111.{key}"),
            format!(
                "{METHOD}.native.1rtt.100-40000-40000.50-0-10.100-30000-30000.{key}"
            ),
        ] {
            assert!(Config::parse(&raw).is_err(), "{raw} must fail");
        }
    }

    #[test]
    fn parses_default_padding_shape() {
        let key = encoded_key(X25519_PUBLIC_KEY_LEN, 6);
        let raw =
            format!("{METHOD}.native.1rtt.100-111-1111.75-0-111.50-0-3333.{key}");

        let config =
            Config::parse(&raw).expect("default padding shape should parse");

        assert_eq!(config.padding.len(), 3);
        assert_eq!(config.padding[0].kind, PaddingKind::Length);
        assert_eq!(config.padding[1].kind, PaddingKind::Gap);
        assert_eq!(config.padding[2].kind, PaddingKind::Length);
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn prepared_crypto_matches_xray_relay_layout_and_key_hashes() {
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
            "{METHOD}.random.1rtt.{}.{}",
            URL_SAFE_NO_PAD.encode(x25519_public.as_ref()),
            URL_SAFE_NO_PAD.encode(mlkem_public_bytes.as_ref()),
        );
        let config = Config::parse(&raw).expect("generated keys should parse");
        let prepared = config.prepare_crypto().expect("crypto should prepare");

        assert_eq!(prepared.xor_mode, 2);
        assert_eq!(
            prepared.relays_length,
            (X25519_PUBLIC_KEY_LEN + 32) + (MLKEM768_CIPHERTEXT_LEN + 32) - 32
        );
        assert_eq!(prepared.key_hashes.len(), 2);
        assert_eq!(
            prepared.key_hashes[0],
            *blake3::hash(x25519_public.as_ref()).as_bytes()
        );
        assert_eq!(
            prepared.key_hashes[1],
            *blake3::hash(mlkem_public_bytes.as_ref()).as_bytes()
        );
    }

    #[cfg(any(feature = "aws-lc-rs", feature = "vless-encryption"))]
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
