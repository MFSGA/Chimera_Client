use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;

const METHOD: &str = "mlkem768x25519plus";
const X25519_PUBLIC_KEY_LEN: usize = 32;
const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
#[cfg(feature = "vless-encryption")]
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const KEY_TOKEN_MIN_CHARS: usize = 20;
#[cfg(feature = "vless-encryption")]
const CLIENT_HELLO_IV_LEN: usize = 16;
#[cfg(feature = "vless-encryption")]
const PFS_KEY_EXCHANGE_LEN: usize =
    18 + MLKEM768_PUBLIC_KEY_LEN + X25519_PUBLIC_KEY_LEN + 16;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaddingPlan {
    pub(crate) total_len: usize,
    pub(crate) write_lengths: Vec<usize>,
    pub(crate) gaps_ms: Vec<u64>,
}

impl PaddingPlan {
    #[cfg(feature = "vless-encryption")]
    pub(crate) fn with_hello_prefix(
        &self,
        hello_prefix_len: usize,
    ) -> io::Result<Vec<usize>> {
        let mut write_lengths = self.write_lengths.clone();
        let first = write_lengths.first_mut().ok_or_else(|| {
            invalid("vless encryption padding plan has no length segment")
        })?;
        *first = first.checked_add(hello_prefix_len).ok_or_else(|| {
            invalid("vless encryption hello write length overflow")
        })?;
        Ok(write_lengths)
    }
}

#[cfg(feature = "vless-encryption")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedNfsRelays {
    pub(crate) iv: [u8; CLIENT_HELLO_IV_LEN],
    pub(crate) relays: Vec<u8>,
    pub(crate) nfs_key: Vec<u8>,
}

#[cfg(feature = "vless-encryption")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedCrypto {
    pub(crate) xor_mode: u32,
    pub(crate) relays_length: usize,
    pub(crate) nfs_relays: PreparedNfsRelays,
    pub(crate) key_hashes: Vec<[u8; 32]>,
    pub(crate) padding_min_len: usize,
    pub(crate) padding_max_len: usize,
    pub(crate) client_hello_min_len: usize,
    pub(crate) client_hello_max_len: usize,
    pub(crate) hello_write_lengths: Vec<usize>,
    pub(crate) padding_gaps_ms: Vec<u64>,
}

#[cfg(feature = "vless-encryption")]
impl PreparedCrypto {
    pub(crate) fn summary(&self) -> String {
        format!(
            "xor-mode={}; relay-bytes={}; key-hashes={}; padding-bytes={}-{}; hello-bytes={}-{}; write-segments={}; gap-segments={}",
            self.xor_mode,
            self.relays_length,
            self.key_hashes.len(),
            self.padding_min_len,
            self.padding_max_len,
            self.client_hello_min_len,
            self.client_hello_max_len,
            self.hello_write_lengths.len(),
            self.padding_gaps_ms.len(),
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
    pub(crate) fn prepare_nfs_relays(
        &self,
        iv: [u8; CLIENT_HELLO_IV_LEN],
    ) -> io::Result<PreparedNfsRelays> {
        use aws_lc_rs::{
            agreement,
            kem::{EncapsulationKey, ML_KEM_768},
        };

        self.validate_crypto_keys()?;

        let mut relays = Vec::new();
        let mut nfs_key = Vec::new();
        let mut previous_chain_mask: Option<[u8; 64]> = None;

        for (index, key) in self.keys.iter().enumerate() {
            let (mut relay, shared_secret) = match key.kind {
                KeyKind::X25519 => {
                    let private_key =
                        agreement::PrivateKey::generate(&agreement::X25519)
                            .map_err(|_| {
                                invalid("failed to generate X25519 relay key")
                            })?;
                    let public_key =
                        private_key.compute_public_key().map_err(|_| {
                            invalid("failed to compute X25519 relay public key")
                        })?;
                    let peer = agreement::UnparsedPublicKey::new(
                        &agreement::X25519,
                        &key.bytes,
                    );
                    let mut shared_secret = Vec::new();
                    agreement::agree(
                        &private_key,
                        peer,
                        invalid("failed X25519 relay agreement"),
                        |material| {
                            shared_secret.extend_from_slice(material);
                            Ok(())
                        },
                    )?;
                    (public_key.as_ref().to_vec(), shared_secret)
                }
                KeyKind::MlKem768 => {
                    let peer = EncapsulationKey::new(&ML_KEM_768, &key.bytes)
                        .map_err(|_| {
                            invalid("invalid ML-KEM-768 relay public key")
                        })?;
                    let (ciphertext, shared_secret) =
                        peer.encapsulate().map_err(|_| {
                            invalid("failed ML-KEM-768 relay encapsulation")
                        })?;
                    (
                        ciphertext.as_ref().to_vec(),
                        shared_secret.as_ref().to_vec(),
                    )
                }
            };

            if !matches!(self.appearance, Appearance::Native) {
                xor_vless_ctr(&key.bytes, &iv, &mut relay)?;
            }

            if let Some(mask) = previous_chain_mask {
                if relay.len() < 32 {
                    return Err(invalid(
                        "vless encryption relay is shorter than 32 bytes",
                    ));
                }
                for (byte, mask_byte) in relay[..32].iter_mut().zip(&mask[32..]) {
                    *byte ^= mask_byte;
                }
            }

            relays.extend_from_slice(&relay);
            nfs_key = shared_secret;

            if index + 1 < self.keys.len() {
                let mut mask = [0u8; 64];
                xor_vless_ctr(&nfs_key, &iv, &mut mask)?;

                let next_hash = blake3::hash(&self.keys[index + 1].bytes);
                let mut chained_hash = *next_hash.as_bytes();
                for (byte, mask_byte) in chained_hash.iter_mut().zip(&mask[..32]) {
                    *byte ^= mask_byte;
                }
                relays.extend_from_slice(&chained_hash);
                previous_chain_mask = Some(mask);
            }
        }

        Ok(PreparedNfsRelays {
            iv,
            relays,
            nfs_key,
        })
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

        let mut iv = [0u8; CLIENT_HELLO_IV_LEN];
        rand::rng().fill(&mut iv);
        let nfs_relays = self.prepare_nfs_relays(iv)?;
        if nfs_relays.relays.len() != relays_length {
            return Err(invalid(format!(
                "vless encryption relay length mismatch: expected {relays_length}, got {}",
                nfs_relays.relays.len()
            )));
        }
        if nfs_relays.nfs_key.is_empty() {
            return Err(invalid("vless encryption final NFS key is empty"));
        }

        let (padding_min_len, padding_max_len) = self.padding_length_bounds()?;
        let fixed_hello_len = CLIENT_HELLO_IV_LEN
            .checked_add(relays_length)
            .and_then(|len| len.checked_add(PFS_KEY_EXCHANGE_LEN))
            .ok_or_else(|| {
                invalid("vless encryption client hello length overflow")
            })?;
        let client_hello_min_len = fixed_hello_len
            .checked_add(padding_min_len)
            .ok_or_else(|| {
                invalid("vless encryption client hello length overflow")
            })?;
        let client_hello_max_len = fixed_hello_len
            .checked_add(padding_max_len)
            .ok_or_else(|| {
                invalid("vless encryption client hello length overflow")
            })?;
        let padding_plan = self.sample_padding_plan();
        let hello_write_lengths = padding_plan.with_hello_prefix(fixed_hello_len)?;

        Ok(PreparedCrypto {
            xor_mode: self.appearance.xor_mode(),
            relays_length,
            nfs_relays,
            key_hashes,
            padding_min_len,
            padding_max_len,
            client_hello_min_len,
            client_hello_max_len,
            hello_write_lengths,
            padding_gaps_ms: padding_plan.gaps_ms,
        })
    }

    #[cfg(feature = "vless-encryption")]
    fn padding_length_bounds(&self) -> io::Result<(usize, usize)> {
        let mut min_len = 0usize;
        let mut max_len = 0usize;

        for rule in &self.padding {
            if !matches!(rule.kind, PaddingKind::Length) {
                continue;
            }

            let min = if rule.probability == 100 {
                usize::try_from(rule.from).map_err(|_| {
                    invalid("negative vless encryption padding length")
                })?
            } else {
                0
            };
            let max = usize::try_from(rule.to)
                .map_err(|_| invalid("negative vless encryption padding length"))?;

            min_len = min_len.checked_add(min).ok_or_else(|| {
                invalid("vless encryption padding length overflow")
            })?;
            max_len = max_len.checked_add(max).ok_or_else(|| {
                invalid("vless encryption padding length overflow")
            })?;
        }

        Ok((min_len, max_len))
    }

    pub(crate) fn sample_padding_plan(&self) -> PaddingPlan {
        let mut rng = rand::rng();
        let mut total_len = 0usize;
        let mut write_lengths = Vec::new();
        let mut gaps_ms = Vec::new();

        for rule in &self.padding {
            let selected = if rule.probability >= 100 {
                true
            } else if rule.probability <= 0 {
                false
            } else {
                rng.random_range(0..100) < rule.probability
            };

            let sampled = if selected {
                if rule.from == rule.to {
                    rule.from
                } else {
                    rng.random_range(rule.from..=rule.to)
                }
            } else {
                0
            };

            match rule.kind {
                PaddingKind::Length => {
                    let sampled = sampled as usize;
                    total_len = total_len.saturating_add(sampled);
                    write_lengths.push(sampled);
                }
                PaddingKind::Gap => gaps_ms.push(sampled as u64),
            }
        }

        PaddingPlan {
            total_len,
            write_lengths,
            gaps_ms,
        }
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

#[cfg(feature = "vless-encryption")]
fn xor_vless_ctr(
    key_material: &[u8],
    iv: &[u8; CLIENT_HELLO_IV_LEN],
    in_out: &mut [u8],
) -> io::Result<()> {
    use aws_lc_rs::{
        cipher::{AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey},
        iv::FixedLength,
    };

    let key_bytes = blake3::derive_key("VLESS", key_material);
    let unbound = UnboundCipherKey::new(&AES_256, &key_bytes)
        .map_err(|_| invalid("failed to create VLESS AES-CTR key"))?;
    let cipher = EncryptingKey::ctr(unbound)
        .map_err(|_| invalid("failed to create VLESS AES-CTR cipher"))?;
    cipher
        .less_safe_encrypt(in_out, EncryptionContext::Iv128(FixedLength::from(*iv)))
        .map_err(|_| invalid("failed to apply VLESS AES-CTR"))?;
    Ok(())
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
    fn padding_plan_matches_xray_length_gap_shape() {
        let key = encoded_key(X25519_PUBLIC_KEY_LEN, 6);
        let raw =
            format!("{METHOD}.native.1rtt.100-111-1111.75-0-111.50-0-3333.{key}");
        let config = Config::parse(&raw).expect("padding config");

        for _ in 0..64 {
            let plan = config.sample_padding_plan();

            assert_eq!(plan.write_lengths.len(), 2);
            assert_eq!(plan.gaps_ms.len(), 1);
            assert!((111..=1111).contains(&plan.write_lengths[0]));
            assert!(plan.write_lengths[1] <= 3333);
            assert!(plan.gaps_ms[0] <= 111);
            assert_eq!(plan.total_len, plan.write_lengths.iter().sum::<usize>());
        }
    }

    #[test]
    fn padding_plan_honors_zero_probability() {
        let key = encoded_key(X25519_PUBLIC_KEY_LEN, 6);
        let raw = format!("{METHOD}.native.1rtt.100-64-64.0-9-9.0-128-128.{key}");
        let config = Config::parse(&raw).expect("padding config");

        let plan = config.sample_padding_plan();

        assert_eq!(plan.write_lengths, vec![64, 0]);
        assert_eq!(plan.gaps_ms, vec![0]);
        assert_eq!(plan.total_len, 64);
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn padding_plan_adds_fixed_client_hello_prefix_to_first_write() {
        let plan = PaddingPlan {
            total_len: 96,
            write_lengths: vec![64, 32],
            gaps_ms: vec![7],
        };

        let writes = plan
            .with_hello_prefix(1500)
            .expect("hello prefix should fit");

        assert_eq!(writes, vec![1564, 32]);
        assert_eq!(plan.write_lengths, vec![64, 32]);
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
    fn nfs_relay_chain_round_trips_x25519_and_mlkem() {
        use aws_lc_rs::{
            agreement,
            kem::{Ciphertext, DecapsulationKey, ML_KEM_768},
        };

        let x25519_private =
            agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let x25519_public = x25519_private.compute_public_key().unwrap();

        let mlkem_private = DecapsulationKey::generate(&ML_KEM_768).unwrap();
        let mlkem_public = mlkem_private.encapsulation_key().unwrap();
        let mlkem_public_bytes = mlkem_public.key_bytes().unwrap();

        for appearance in ["native", "xorpub", "random"] {
            let raw = format!(
                "{METHOD}.{appearance}.1rtt.{}.{}",
                URL_SAFE_NO_PAD.encode(x25519_public.as_ref()),
                URL_SAFE_NO_PAD.encode(mlkem_public_bytes.as_ref()),
            );
            let config = Config::parse(&raw).expect("relay config should parse");
            let iv = [0x42; CLIENT_HELLO_IV_LEN];
            let prepared = config
                .prepare_nfs_relays(iv)
                .expect("relay chain should prepare");

            assert_eq!(
                prepared.relays.len(),
                X25519_PUBLIC_KEY_LEN + 32 + MLKEM768_CIPHERTEXT_LEN
            );
            assert_eq!(prepared.iv, iv);

            let mut cursor = 0usize;

            let mut x25519_relay =
                prepared.relays[cursor..cursor + X25519_PUBLIC_KEY_LEN].to_vec();
            cursor += X25519_PUBLIC_KEY_LEN;
            if appearance != "native" {
                xor_vless_ctr(x25519_public.as_ref(), &iv, &mut x25519_relay)
                    .expect("appearance mask should reverse");
            }

            let peer =
                agreement::UnparsedPublicKey::new(&agreement::X25519, &x25519_relay);
            let mut first_secret = Vec::new();
            agreement::agree(
                &x25519_private,
                peer,
                invalid("server-side X25519 agreement failed"),
                |material| {
                    first_secret.extend_from_slice(material);
                    Ok(())
                },
            )
            .expect("server should recover first shared secret");

            let mut chain_mask = [0u8; 64];
            xor_vless_ctr(&first_secret, &iv, &mut chain_mask)
                .expect("chain mask should derive");

            let mut chained_hash = prepared.relays[cursor..cursor + 32].to_vec();
            cursor += 32;
            for (byte, mask_byte) in chained_hash.iter_mut().zip(&chain_mask[..32]) {
                *byte ^= mask_byte;
            }
            assert_eq!(
                chained_hash.as_slice(),
                blake3::hash(mlkem_public_bytes.as_ref()).as_bytes()
            );

            let mut mlkem_relay =
                prepared.relays[cursor..cursor + MLKEM768_CIPHERTEXT_LEN].to_vec();
            for (byte, mask_byte) in
                mlkem_relay[..32].iter_mut().zip(&chain_mask[32..])
            {
                *byte ^= mask_byte;
            }
            if appearance != "native" {
                xor_vless_ctr(mlkem_public_bytes.as_ref(), &iv, &mut mlkem_relay)
                    .expect("appearance mask should reverse");
            }

            let final_secret = mlkem_private
                .decapsulate(Ciphertext::from(mlkem_relay.as_slice()))
                .expect("server should recover final ML-KEM secret");
            assert_eq!(prepared.nfs_key, final_secret.as_ref());
        }
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
        assert_eq!(prepared.padding_min_len, 111);
        assert_eq!(prepared.padding_max_len, 4_444);
        let fixed =
            CLIENT_HELLO_IV_LEN + prepared.relays_length + PFS_KEY_EXCHANGE_LEN;
        assert_eq!(prepared.client_hello_min_len, fixed + 111);
        assert_eq!(prepared.client_hello_max_len, fixed + 4_444);
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
