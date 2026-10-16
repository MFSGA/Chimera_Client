use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "vless-encryption")]
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
const AEAD_TAG_LEN: usize = 16;
#[cfg(feature = "vless-encryption")]
const ENCRYPTED_LENGTH_LEN: usize = 2 + AEAD_TAG_LEN;
#[cfg(feature = "vless-encryption")]
const PFS_PUBLIC_KEY_LEN: usize = MLKEM768_PUBLIC_KEY_LEN + X25519_PUBLIC_KEY_LEN;
#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
const SERVER_PFS_PUBLIC_KEY_LEN: usize =
    MLKEM768_CIPHERTEXT_LEN + X25519_PUBLIC_KEY_LEN;
#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
const SERVER_PFS_RESPONSE_LEN: usize = SERVER_PFS_PUBLIC_KEY_LEN + AEAD_TAG_LEN;
#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
const ENCRYPTED_TICKET_LEN: usize = 16 + AEAD_TAG_LEN;
#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
const RECORD_HEADER_LEN: usize = 5;
#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
const MAX_RECORD_PLAINTEXT_LEN: usize = 8192;
#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
const MAX_RECORD_CIPHERTEXT_LEN: usize = 16640;
#[cfg(feature = "vless-encryption")]
const PFS_KEY_EXCHANGE_LEN: usize =
    ENCRYPTED_LENGTH_LEN + PFS_PUBLIC_KEY_LEN + AEAD_TAG_LEN;
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
    #[cfg(test)]
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
    #[cfg(test)]
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
pub(crate) struct PaddingPlan {
    pub(crate) total_len: usize,
    pub(crate) write_lengths: Vec<usize>,
    pub(crate) gaps_ms: Vec<u64>,
}

#[cfg(feature = "vless-encryption")]
impl PaddingPlan {
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
pub(crate) struct PreparedOneRttHello {
    pub(crate) bytes: Vec<u8>,
    pub(crate) pfs_public_key: Vec<u8>,
    pub(crate) mlkem_private_key: Vec<u8>,
    pub(crate) x25519_private_key: [u8; X25519_PUBLIC_KEY_LEN],
}

#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedOneRttSession {
    pub(crate) united_key: Vec<u8>,
    pub(crate) write_aead_context: Vec<u8>,
    pub(crate) read_aead_context: Vec<u8>,
    pub(crate) write_aead_key: [u8; 32],
    pub(crate) read_aead_key: [u8; 32],
}

#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedOneRttServerTail {
    pub(crate) ticket: [u8; 16],
    pub(crate) ticket_seconds: u16,
    pub(crate) peer_padding_ciphertext_len: usize,
    pub(crate) read_aead_nonce: [u8; 12],
}

#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
pub(crate) struct EncryptionRecordCodec {
    aead: EncryptionAead,
}

#[cfg(feature = "vless-encryption")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedCrypto {
    pub(crate) xor_mode: u32,
    pub(crate) relays_length: usize,
    pub(crate) nfs_relays: PreparedNfsRelays,
    pub(crate) nfs_aead_key: [u8; 32],
    pub(crate) one_rtt_hello: Option<PreparedOneRttHello>,
    pub(crate) key_hashes: Vec<[u8; 32]>,
    pub(crate) padding_min_len: usize,
    pub(crate) padding_max_len: usize,
    pub(crate) client_hello_min_len: usize,
    pub(crate) client_hello_max_len: usize,
    pub(crate) hello_write_lengths: Vec<usize>,
    pub(crate) padding_gaps_ms: Vec<u64>,
}

#[cfg(feature = "vless-encryption")]
impl PreparedOneRttHello {
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "consumed by the next VLESS encryption runtime-stream slice"
        )
    )]
    pub(crate) fn derive_server_session(
        &self,
        nfs_aead_key: &[u8; 32],
        nfs_key: &[u8],
        encrypted_server_pfs: &[u8],
    ) -> io::Result<PreparedOneRttSession> {
        use aws_lc_rs::{
            agreement,
            kem::{Ciphertext, DecapsulationKey, ML_KEM_768},
        };

        if encrypted_server_pfs.len() != SERVER_PFS_RESPONSE_LEN {
            return Err(invalid(format!(
                "unexpected VLESS encryption server PFS response length: expected {SERVER_PFS_RESPONSE_LEN}, got {}",
                encrypted_server_pfs.len()
            )));
        }

        let aead = EncryptionAead::new(nfs_aead_key)?;
        let server_pfs = aead.open_with_nonce(encrypted_server_pfs, [0xff; 12])?;
        if server_pfs.len() != SERVER_PFS_PUBLIC_KEY_LEN {
            return Err(invalid(format!(
                "unexpected decrypted VLESS server PFS length: {}",
                server_pfs.len()
            )));
        }

        let mlkem_private =
            DecapsulationKey::new(&ML_KEM_768, &self.mlkem_private_key).map_err(
                |_| invalid("failed to reconstruct ML-KEM-768 PFS private key"),
            )?;
        let mlkem_secret = mlkem_private
            .decapsulate(Ciphertext::from(&server_pfs[..MLKEM768_CIPHERTEXT_LEN]))
            .map_err(|_| {
                invalid("failed to decapsulate server ML-KEM-768 PFS key")
            })?;

        let x25519_private = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &self.x25519_private_key,
        )
        .map_err(|_| invalid("failed to reconstruct X25519 PFS private key"))?;
        let peer = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            &server_pfs[MLKEM768_CIPHERTEXT_LEN..],
        );
        let mut x25519_secret = Vec::new();
        agreement::agree(
            &x25519_private,
            peer,
            invalid("failed X25519 server PFS agreement"),
            |material| {
                x25519_secret.extend_from_slice(material);
                Ok(())
            },
        )?;

        let mut united_key = Vec::with_capacity(
            mlkem_secret.as_ref().len() + x25519_secret.len() + nfs_key.len(),
        );
        united_key.extend_from_slice(mlkem_secret.as_ref());
        united_key.extend_from_slice(&x25519_secret);
        united_key.extend_from_slice(nfs_key);

        let write_aead_context = self.pfs_public_key.clone();
        let read_aead_context = server_pfs;
        let write_aead_key =
            blake3_derive_key_raw_context(&write_aead_context, &united_key)?;
        let read_aead_key =
            blake3_derive_key_raw_context(&read_aead_context, &united_key)?;

        Ok(PreparedOneRttSession {
            united_key,
            write_aead_context,
            read_aead_context,
            write_aead_key,
            read_aead_key,
        })
    }
}

#[cfg(feature = "vless-encryption")]
impl PreparedOneRttSession {
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "consumed by the next VLESS encryption runtime-stream slice"
        )
    )]
    pub(crate) fn decrypt_server_tail(
        &self,
        encrypted_ticket: &[u8],
        encrypted_padding_length: &[u8],
    ) -> io::Result<PreparedOneRttServerTail> {
        if encrypted_ticket.len() != ENCRYPTED_TICKET_LEN {
            return Err(invalid(format!(
                "unexpected VLESS encryption ticket length: expected {ENCRYPTED_TICKET_LEN}, got {}",
                encrypted_ticket.len()
            )));
        }
        if encrypted_padding_length.len() != ENCRYPTED_LENGTH_LEN {
            return Err(invalid(format!(
                "unexpected VLESS encryption padding length field: expected {ENCRYPTED_LENGTH_LEN}, got {}",
                encrypted_padding_length.len()
            )));
        }

        let mut read_aead = EncryptionAead::new(&self.read_aead_key)?;
        let ticket_plain = read_aead.open(encrypted_ticket)?;
        let ticket: [u8; 16] = ticket_plain
            .as_slice()
            .try_into()
            .map_err(|_| invalid("unexpected decrypted VLESS ticket length"))?;
        let ticket_seconds = u16::from_be_bytes([ticket[0], ticket[1]]);

        let padding_len_plain = read_aead.open(encrypted_padding_length)?;
        let padding_len_bytes: [u8; 2] =
            padding_len_plain.as_slice().try_into().map_err(|_| {
                invalid("unexpected decrypted VLESS padding length size")
            })?;
        let peer_padding_ciphertext_len =
            u16::from_be_bytes(padding_len_bytes) as usize;

        Ok(PreparedOneRttServerTail {
            ticket,
            ticket_seconds,
            peer_padding_ciphertext_len,
            read_aead_nonce: read_aead.nonce,
        })
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "consumed by the next VLESS encryption runtime-stream slice"
        )
    )]
    pub(crate) fn record_codecs(
        &self,
        tail: &PreparedOneRttServerTail,
    ) -> io::Result<(EncryptionRecordCodec, EncryptionRecordCodec)> {
        Ok((
            EncryptionRecordCodec::new(&self.write_aead_key, [0u8; 12])?,
            EncryptionRecordCodec::new(&self.read_aead_key, tail.read_aead_nonce)?,
        ))
    }
}

#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
impl EncryptionRecordCodec {
    fn new(key: &[u8; 32], nonce: [u8; 12]) -> io::Result<Self> {
        Ok(Self {
            aead: EncryptionAead::new_with_nonce(key, nonce)?,
        })
    }

    pub(crate) fn seal_record(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }
        if plaintext.len() > MAX_RECORD_PLAINTEXT_LEN {
            return Err(invalid(format!(
                "VLESS encryption record plaintext too large: {} > {MAX_RECORD_PLAINTEXT_LEN}",
                plaintext.len()
            )));
        }

        let ciphertext_len = plaintext
            .len()
            .checked_add(AEAD_TAG_LEN)
            .ok_or_else(|| invalid("VLESS encryption record length overflow"))?;
        let header = encode_record_header(ciphertext_len)?;
        let ciphertext = self.aead.seal_with_aad(plaintext, &header)?;

        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + ciphertext.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }

    pub(crate) fn open_record(&mut self, record: &[u8]) -> io::Result<Vec<u8>> {
        if record.len() < RECORD_HEADER_LEN {
            return Err(invalid(
                "VLESS encryption record is shorter than its header",
            ));
        }

        let header: [u8; RECORD_HEADER_LEN] = record[..RECORD_HEADER_LEN]
            .try_into()
            .map_err(|_| invalid("invalid VLESS encryption record header"))?;
        let ciphertext_len = decode_record_header(&header)?;
        if record.len() != RECORD_HEADER_LEN + ciphertext_len {
            return Err(invalid(format!(
                "VLESS encryption record length mismatch: header={ciphertext_len}, actual={}",
                record.len() - RECORD_HEADER_LEN
            )));
        }

        self.aead
            .open_with_aad(&record[RECORD_HEADER_LEN..], &header)
    }

    pub(crate) fn open_peer_padding(
        &mut self,
        ciphertext: &[u8],
    ) -> io::Result<Vec<u8>> {
        self.aead.open(ciphertext)
    }

    #[cfg(test)]
    fn nonce(&self) -> [u8; 12] {
        self.aead.nonce
    }
}

#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
fn encode_record_header(
    ciphertext_len: usize,
) -> io::Result<[u8; RECORD_HEADER_LEN]> {
    if !(AEAD_TAG_LEN + 1..=MAX_RECORD_CIPHERTEXT_LEN).contains(&ciphertext_len) {
        return Err(invalid(format!(
            "invalid VLESS encryption record ciphertext length: {ciphertext_len}"
        )));
    }

    let length = u16::try_from(ciphertext_len)
        .map_err(|_| invalid("VLESS encryption record length exceeds u16"))?;
    Ok([23, 3, 3, (length >> 8) as u8, length as u8])
}

#[cfg(feature = "vless-encryption")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "consumed by the next VLESS encryption runtime-stream slice"
    )
)]
fn decode_record_header(header: &[u8; RECORD_HEADER_LEN]) -> io::Result<usize> {
    if header[0] != 23 || header[1] != 3 || header[2] != 3 {
        return Err(invalid(format!(
            "invalid VLESS encryption record header: {header:?}"
        )));
    }

    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if !(AEAD_TAG_LEN + 1..=MAX_RECORD_CIPHERTEXT_LEN).contains(&length) {
        return Err(invalid(format!(
            "invalid VLESS encryption record ciphertext length: {length}"
        )));
    }
    Ok(length)
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
    fn prepare_one_rtt_hello(
        &self,
        nfs_relays: &PreparedNfsRelays,
        nfs_aead_key: &[u8; 32],
        padding_plan: &PaddingPlan,
    ) -> io::Result<PreparedOneRttHello> {
        use aws_lc_rs::{
            agreement,
            encoding::{AsBigEndian, Curve25519SeedBin},
            kem::{DecapsulationKey, ML_KEM_768},
        };

        if !matches!(self.rtt, RttMode::OneRtt) {
            return Err(invalid(
                "1-RTT hello requested for non-1rtt vless encryption config",
            ));
        }

        let mlkem_private = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| invalid("failed to generate ML-KEM-768 PFS key"))?;
        let mlkem_public = mlkem_private
            .encapsulation_key()
            .map_err(|_| invalid("failed to derive ML-KEM-768 PFS public key"))?;
        let mlkem_public_bytes = mlkem_public
            .key_bytes()
            .map_err(|_| invalid("failed to serialize ML-KEM-768 PFS public key"))?;

        let x25519_private = agreement::PrivateKey::generate(&agreement::X25519)
            .map_err(|_| invalid("failed to generate X25519 PFS key"))?;
        let x25519_public = x25519_private
            .compute_public_key()
            .map_err(|_| invalid("failed to derive X25519 PFS public key"))?;

        let mut pfs_public_key = Vec::with_capacity(PFS_PUBLIC_KEY_LEN);
        pfs_public_key.extend_from_slice(mlkem_public_bytes.as_ref());
        pfs_public_key.extend_from_slice(x25519_public.as_ref());
        if pfs_public_key.len() != PFS_PUBLIC_KEY_LEN {
            return Err(invalid(format!(
                "unexpected VLESS PFS public key length: {}",
                pfs_public_key.len()
            )));
        }

        let mlkem_private_key = mlkem_private
            .key_bytes()
            .map_err(|_| invalid("failed to serialize ML-KEM-768 PFS private key"))?
            .as_ref()
            .to_vec();
        let x25519_seed: Curve25519SeedBin<'static> =
            x25519_private.as_be_bytes().map_err(|_| {
                invalid("failed to serialize X25519 PFS private key")
            })?;
        let x25519_private_key: [u8; X25519_PUBLIC_KEY_LEN] = x25519_seed
            .as_ref()
            .try_into()
            .map_err(|_| invalid("unexpected X25519 PFS private key length"))?;

        let padding_len = padding_plan.total_len;
        if padding_len < ENCRYPTED_LENGTH_LEN + AEAD_TAG_LEN + 1 {
            return Err(invalid(format!(
                "vless encryption padding is too short for AEAD framing: {padding_len}"
            )));
        }

        let mut aead = EncryptionAead::new(nfs_aead_key)?;
        let encrypted_pfs_len = encode_length(PFS_PUBLIC_KEY_LEN + AEAD_TAG_LEN)?;
        let encrypted_pfs_len = aead.seal(&encrypted_pfs_len)?;
        if encrypted_pfs_len.len() != ENCRYPTED_LENGTH_LEN {
            return Err(invalid("unexpected encrypted PFS length field size"));
        }

        let encrypted_pfs_public = aead.seal(&pfs_public_key)?;
        if encrypted_pfs_public.len() != PFS_PUBLIC_KEY_LEN + AEAD_TAG_LEN {
            return Err(invalid("unexpected encrypted PFS public key size"));
        }

        let encrypted_padding_body_len = padding_len
            .checked_sub(ENCRYPTED_LENGTH_LEN)
            .ok_or_else(|| invalid("vless encryption padding length underflow"))?;
        let encrypted_padding_len =
            aead.seal(&encode_length(encrypted_padding_body_len)?)?;
        if encrypted_padding_len.len() != ENCRYPTED_LENGTH_LEN {
            return Err(invalid("unexpected encrypted padding length field size"));
        }

        let padding_plaintext_len = encrypted_padding_body_len
            .checked_sub(AEAD_TAG_LEN)
            .ok_or_else(|| invalid("vless encryption padding body underflow"))?;
        let encrypted_padding = aead.seal(&vec![0u8; padding_plaintext_len])?;
        if encrypted_padding.len() != encrypted_padding_body_len {
            return Err(invalid("unexpected encrypted padding body size"));
        }

        let fixed_len =
            CLIENT_HELLO_IV_LEN + nfs_relays.relays.len() + PFS_KEY_EXCHANGE_LEN;
        let mut bytes = Vec::with_capacity(fixed_len + padding_len);
        bytes.extend_from_slice(&nfs_relays.iv);
        bytes.extend_from_slice(&nfs_relays.relays);
        bytes.extend_from_slice(&encrypted_pfs_len);
        bytes.extend_from_slice(&encrypted_pfs_public);
        bytes.extend_from_slice(&encrypted_padding_len);
        bytes.extend_from_slice(&encrypted_padding);

        if bytes.len() != fixed_len + padding_len {
            return Err(invalid(format!(
                "unexpected VLESS encryption client hello length: {}",
                bytes.len()
            )));
        }

        Ok(PreparedOneRttHello {
            bytes,
            pfs_public_key,
            mlkem_private_key,
            x25519_private_key,
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
        let nfs_aead_key =
            blake3_derive_key_raw_context(&nfs_relays.iv, &nfs_relays.nfs_key)?;

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
        let one_rtt_hello = if matches!(self.rtt, RttMode::OneRtt) {
            Some(self.prepare_one_rtt_hello(
                &nfs_relays,
                &nfs_aead_key,
                &padding_plan,
            )?)
        } else {
            None
        };

        Ok(PreparedCrypto {
            xor_mode: self.appearance.xor_mode(),
            relays_length,
            nfs_relays,
            nfs_aead_key,
            one_rtt_hello,
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

    #[cfg(feature = "vless-encryption")]
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

    #[cfg(test)]
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
struct EncryptionAead {
    key: aws_lc_rs::aead::LessSafeKey,
    nonce: [u8; 12],
}

#[cfg(feature = "vless-encryption")]
impl EncryptionAead {
    fn new(key: &[u8; 32]) -> io::Result<Self> {
        Self::new_with_nonce(key, [0u8; 12])
    }

    fn new_with_nonce(key: &[u8; 32], nonce: [u8; 12]) -> io::Result<Self> {
        use aws_lc_rs::aead::{AES_256_GCM, LessSafeKey, UnboundKey};

        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| invalid("failed to create VLESS AES-256-GCM key"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            nonce,
        })
    }

    fn next_nonce(&mut self) -> io::Result<aws_lc_rs::aead::Nonce> {
        let mut next = self.nonce;
        for index in (0..next.len()).rev() {
            let (value, carry) = next[index].overflowing_add(1);
            next[index] = value;
            if !carry {
                let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&next)
                    .map_err(|_| invalid("failed to construct VLESS AEAD nonce"))?;
                self.nonce = next;
                return Ok(nonce);
            }
        }

        // Reusing an AES-GCM nonce under the same traffic key is unsafe.
        // Keep the counter at its final value and fail closed permanently.
        Err(invalid("VLESS AEAD nonce exhausted"))
    }

    fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        self.seal_with_aad(plaintext, &[])
    }

    fn seal_with_aad(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        use aws_lc_rs::aead::Aad;

        let nonce = self.next_nonce()?;
        let mut output = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut output)
            .map_err(|_| invalid("failed to seal VLESS encryption field"))?;
        Ok(output)
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "consumed by the next VLESS encryption runtime-stream slice"
        )
    )]
    fn open_with_nonce(
        &self,
        ciphertext: &[u8],
        nonce_bytes: [u8; 12],
    ) -> io::Result<Vec<u8>> {
        use aws_lc_rs::aead::{Aad, Nonce};

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| invalid("failed to construct VLESS AEAD nonce"))?;
        let mut output = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut output)
            .map_err(|_| {
                invalid("failed to open VLESS encryption handshake field")
            })?;
        let len = plaintext.len();
        output.truncate(len);
        Ok(output)
    }

    fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        self.open_with_aad(ciphertext, &[])
    }

    fn open_with_aad(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        use aws_lc_rs::aead::Aad;

        let nonce = self.next_nonce()?;
        let mut output = ciphertext.to_vec();
        let plaintext =
            self.key
                .open_in_place(nonce, Aad::from(aad), &mut output)
                .map_err(|_| invalid("failed to open VLESS encryption field"))?;
        let len = plaintext.len();
        output.truncate(len);
        Ok(output)
    }

    #[cfg(test)]
    fn seal_with_nonce(
        &self,
        plaintext: &[u8],
        nonce_bytes: [u8; 12],
    ) -> io::Result<Vec<u8>> {
        use aws_lc_rs::aead::{Aad, Nonce};

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| invalid("failed to construct VLESS AEAD nonce"))?;
        let mut output = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut output)
            .map_err(|_| {
                invalid("failed to seal VLESS encryption handshake field")
            })?;
        Ok(output)
    }
}

#[cfg(feature = "vless-encryption")]
fn encode_length(length: usize) -> io::Result<[u8; 2]> {
    let length = u16::try_from(length).map_err(|_| {
        invalid(format!("VLESS encryption length exceeds u16: {length}"))
    })?;
    Ok(length.to_be_bytes())
}

#[cfg(feature = "vless-encryption")]
mod blake3_compat;
#[cfg(feature = "vless-encryption")]
use blake3_compat::blake3_derive_key_raw_context;
#[cfg(feature = "vless-encryption")]
pub(super) use blake3_compat::xor_vless_ctr;
mod padding;
use padding::parse_padding;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests;
