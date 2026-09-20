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
        for index in (0..self.nonce.len()).rev() {
            self.nonce[index] = self.nonce[index].wrapping_add(1);
            if self.nonce[index] != 0 {
                break;
            }
        }
        aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&self.nonce)
            .map_err(|_| invalid("failed to construct VLESS AEAD nonce"))
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
const BLAKE3_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

#[cfg(feature = "vless-encryption")]
const BLAKE3_CHUNK_START: u8 = 1 << 0;
#[cfg(feature = "vless-encryption")]
const BLAKE3_CHUNK_END: u8 = 1 << 1;
#[cfg(feature = "vless-encryption")]
const BLAKE3_PARENT: u8 = 1 << 2;
#[cfg(feature = "vless-encryption")]
const BLAKE3_ROOT: u8 = 1 << 3;
#[cfg(feature = "vless-encryption")]
const BLAKE3_DERIVE_KEY_CONTEXT: u8 = 1 << 5;

#[cfg(feature = "vless-encryption")]
fn blake3_chunk_cv(
    chunk: &[u8],
    chunk_counter: u64,
    platform: blake3::platform::Platform,
) -> [u32; 8] {
    let mut cv = BLAKE3_IV;
    let block_count = chunk.len().div_ceil(blake3::BLOCK_LEN).max(1);

    for block_index in 0..block_count {
        let start = block_index * blake3::BLOCK_LEN;
        let end = (start + blake3::BLOCK_LEN).min(chunk.len());
        let bytes = &chunk[start..end];
        let mut block = [0u8; blake3::BLOCK_LEN];
        block[..bytes.len()].copy_from_slice(bytes);

        let mut flags = BLAKE3_DERIVE_KEY_CONTEXT;
        if block_index == 0 {
            flags |= BLAKE3_CHUNK_START;
        }
        if block_index + 1 == block_count {
            flags |= BLAKE3_CHUNK_END;
        }

        platform.compress_in_place(
            &mut cv,
            &block,
            bytes.len() as u8,
            chunk_counter,
            flags,
        );
    }

    cv
}

#[cfg(feature = "vless-encryption")]
fn blake3_single_chunk_root(
    chunk: &[u8],
    platform: blake3::platform::Platform,
) -> [u8; 32] {
    let mut cv = BLAKE3_IV;
    let block_count = chunk.len().div_ceil(blake3::BLOCK_LEN).max(1);

    for block_index in 0..block_count {
        let start = block_index * blake3::BLOCK_LEN;
        let end = (start + blake3::BLOCK_LEN).min(chunk.len());
        let bytes = &chunk[start..end];
        let mut block = [0u8; blake3::BLOCK_LEN];
        block[..bytes.len()].copy_from_slice(bytes);

        let mut flags = BLAKE3_DERIVE_KEY_CONTEXT;
        if block_index == 0 {
            flags |= BLAKE3_CHUNK_START;
        }
        if block_index + 1 == block_count {
            flags |= BLAKE3_CHUNK_END | BLAKE3_ROOT;
            let output =
                platform.compress_xof(&cv, &block, bytes.len() as u8, 0, flags);
            let mut root = [0u8; 32];
            root.copy_from_slice(&output[..32]);
            return root;
        }

        platform.compress_in_place(&mut cv, &block, bytes.len() as u8, 0, flags);
    }

    unreachable!("at least one BLAKE3 block is always processed")
}

#[cfg(feature = "vless-encryption")]
fn blake3_parent_block(left: &[u32; 8], right: &[u32; 8]) -> [u8; 64] {
    let mut block = [0u8; 64];
    for (index, word) in left.iter().chain(right.iter()).enumerate() {
        block[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    block
}

#[cfg(feature = "vless-encryption")]
fn blake3_parent_cv(
    left: &[u32; 8],
    right: &[u32; 8],
    platform: blake3::platform::Platform,
) -> [u32; 8] {
    let block = blake3_parent_block(left, right);
    let mut cv = BLAKE3_IV;
    platform.compress_in_place(
        &mut cv,
        &block,
        64,
        0,
        BLAKE3_PARENT | BLAKE3_DERIVE_KEY_CONTEXT,
    );
    cv
}

#[cfg(feature = "vless-encryption")]
fn blake3_subtree_cv(
    cvs: &[[u32; 8]],
    platform: blake3::platform::Platform,
) -> [u32; 8] {
    if cvs.len() == 1 {
        return cvs[0];
    }

    let mut split = 1usize;
    while split * 2 < cvs.len() {
        split *= 2;
    }

    let left = blake3_subtree_cv(&cvs[..split], platform);
    let right = blake3_subtree_cv(&cvs[split..], platform);
    blake3_parent_cv(&left, &right, platform)
}

#[cfg(feature = "vless-encryption")]
fn blake3_raw_context_key(context: &[u8]) -> [u8; 32] {
    let platform = blake3::platform::Platform::detect();
    if context.len() <= blake3::CHUNK_LEN {
        return blake3_single_chunk_root(context, platform);
    }

    let cvs = context
        .chunks(blake3::CHUNK_LEN)
        .enumerate()
        .map(|(index, chunk)| blake3_chunk_cv(chunk, index as u64, platform))
        .collect::<Vec<_>>();

    let mut split = 1usize;
    while split * 2 < cvs.len() {
        split *= 2;
    }
    let left = blake3_subtree_cv(&cvs[..split], platform);
    let right = blake3_subtree_cv(&cvs[split..], platform);
    let block = blake3_parent_block(&left, &right);
    let output = platform.compress_xof(
        &BLAKE3_IV,
        &block,
        64,
        0,
        BLAKE3_PARENT | BLAKE3_ROOT | BLAKE3_DERIVE_KEY_CONTEXT,
    );

    let mut root = [0u8; 32];
    root.copy_from_slice(&output[..32]);
    root
}

#[cfg(feature = "vless-encryption")]
fn blake3_derive_key_raw_context(
    context: &[u8],
    key_material: &[u8],
) -> io::Result<[u8; 32]> {
    use blake3::hazmat::HasherExt;

    // Xray passes arbitrary binary bytes through Go's string type as the
    // BLAKE3 derive-key context. Rust's high-level API requires UTF-8, so
    // reproduce the context-hash stage with the public compression primitive.
    let context_key = blake3_raw_context_key(context);
    let mut hasher = blake3::Hasher::new_from_context_key(&context_key);
    hasher.update(key_material);
    Ok(*hasher.finalize().as_bytes())
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

    #[cfg(feature = "vless-encryption")]
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

    #[cfg(feature = "vless-encryption")]
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
    fn raw_context_derivation_matches_rust_for_utf8_context() {
        let material = [0x11u8; 32];

        for len in [0usize, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3000] {
            let context = "a".repeat(len);
            let derived =
                blake3_derive_key_raw_context(context.as_bytes(), &material)
                    .expect("raw context derivation should work");

            assert_eq!(
                derived,
                blake3::derive_key(&context, &material),
                "context length {len}"
            );
        }
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn raw_context_derivation_matches_xray_go_for_non_utf8_context() {
        let context = [
            0xff, 0x00, 0x80, 0x41, 0x42, 0x43, 0x7f, 0x01, 0xfe, 0x10, 0x20, 0x30,
            0x40, 0x50, 0x60, 0x70,
        ];
        let material = [0x11u8; 32];

        // Generated with Xray's Go dependency:
        // lukechampine.com/blake3.DeriveKey(out, string(context), material).
        let expected = [
            0x26, 0x73, 0x7d, 0xde, 0x8e, 0xf1, 0xa3, 0x42, 0x63, 0xea, 0x7a, 0xf3,
            0x72, 0x92, 0xc0, 0x8c, 0xce, 0x0f, 0xff, 0xfb, 0x62, 0xf0, 0xd2, 0xab,
            0xab, 0xde, 0x7e, 0x98, 0x80, 0xf0, 0xb2, 0xa9,
        ];

        let derived = blake3_derive_key_raw_context(&context, &material)
            .expect("binary context derivation should work");

        assert_eq!(derived, expected);
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn raw_long_binary_context_matches_xray_go_vector() {
        let context = (0..1216)
            .map(|index| (index * 37 + 11) as u8)
            .collect::<Vec<_>>();
        let material = [0x33u8; 96];
        let expected = [
            0xd5, 0x8b, 0x3c, 0x9a, 0x5b, 0x8f, 0x49, 0xc5, 0x2b, 0x16, 0xdd, 0x70,
            0xe7, 0x03, 0x16, 0x24, 0x11, 0x45, 0x0a, 0x12, 0x90, 0xe8, 0x46, 0x74,
            0x48, 0x93, 0x27, 0x34, 0x82, 0xc5, 0x9a, 0xc0,
        ];

        let derived = blake3_derive_key_raw_context(&context, &material)
            .expect("long binary context should derive");

        assert_eq!(derived, expected);
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn nfs_aead_first_seal_matches_xray_go_vector() {
        let context = [
            0xff, 0x00, 0x80, 0x41, 0x42, 0x43, 0x7f, 0x01, 0xfe, 0x10, 0x20, 0x30,
            0x40, 0x50, 0x60, 0x70,
        ];
        let material = [0x22u8; 32];
        let expected_key = [
            0x79, 0x22, 0x4b, 0x3e, 0xbd, 0xac, 0xc4, 0x03, 0x6d, 0x7a, 0x6f, 0x9b,
            0x81, 0x19, 0xae, 0xcf, 0x8a, 0xa5, 0x4f, 0x7e, 0x2f, 0x0c, 0x81, 0x15,
            0xf1, 0xae, 0x6e, 0xa9, 0x28, 0xe4, 0x24, 0xb1,
        ];
        let expected_ciphertext = [
            0xfa, 0x78, 0xc8, 0xfd, 0x36, 0x18, 0x6b, 0x14, 0x0f, 0xe4, 0x07, 0xdd,
            0xfd, 0x70, 0x9b, 0x6c, 0x5c, 0x92,
        ];

        let key = blake3_derive_key_raw_context(&context, &material)
            .expect("binary context should derive");
        assert_eq!(key, expected_key);

        let mut aead = EncryptionAead::new(&key).expect("AEAD should build");
        let sealed = aead
            .seal(&[0x04, 0xd0])
            .expect("first Xray-compatible seal should succeed");

        assert_eq!(sealed, expected_ciphertext);
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
    fn one_rtt_client_hello_matches_xray_nfs_aead_layout() {
        use aws_lc_rs::{
            agreement,
            kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768},
        };

        let server_private =
            agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public = server_private.compute_public_key().unwrap();
        let raw = format!(
            "{METHOD}.native.1rtt.100-64-64.{}",
            URL_SAFE_NO_PAD.encode(server_public.as_ref()),
        );
        let config = Config::parse(&raw).expect("1rtt config should parse");
        let prepared = config.prepare_crypto().expect("crypto should prepare");
        let hello = prepared
            .one_rtt_hello
            .as_ref()
            .expect("1rtt hello should be prepared");

        assert_eq!(
            hello.bytes.len(),
            CLIENT_HELLO_IV_LEN + prepared.relays_length + PFS_KEY_EXCHANGE_LEN + 64
        );
        assert_eq!(
            prepared.hello_write_lengths.iter().sum::<usize>(),
            hello.bytes.len()
        );

        let mut cursor = CLIENT_HELLO_IV_LEN + prepared.relays_length;
        let mut aead =
            EncryptionAead::new(&prepared.nfs_aead_key).expect("AEAD key");

        let pfs_length_plain = aead
            .open(&hello.bytes[cursor..cursor + ENCRYPTED_LENGTH_LEN])
            .expect("PFS length should decrypt");
        cursor += ENCRYPTED_LENGTH_LEN;
        assert_eq!(
            u16::from_be_bytes(pfs_length_plain.as_slice().try_into().unwrap())
                as usize,
            PFS_PUBLIC_KEY_LEN + AEAD_TAG_LEN
        );

        let encrypted_pfs_len = PFS_PUBLIC_KEY_LEN + AEAD_TAG_LEN;
        let pfs_public = aead
            .open(&hello.bytes[cursor..cursor + encrypted_pfs_len])
            .expect("PFS public key should decrypt");
        cursor += encrypted_pfs_len;
        assert_eq!(pfs_public, hello.pfs_public_key);

        let padding_length_plain = aead
            .open(&hello.bytes[cursor..cursor + ENCRYPTED_LENGTH_LEN])
            .expect("padding length should decrypt");
        cursor += ENCRYPTED_LENGTH_LEN;
        let encrypted_padding_len =
            u16::from_be_bytes(padding_length_plain.as_slice().try_into().unwrap())
                as usize;
        assert_eq!(encrypted_padding_len, 64 - ENCRYPTED_LENGTH_LEN);

        let padding_plain = aead
            .open(&hello.bytes[cursor..cursor + encrypted_padding_len])
            .expect("padding should decrypt");
        cursor += encrypted_padding_len;
        assert_eq!(
            padding_plain.len(),
            64 - ENCRYPTED_LENGTH_LEN - AEAD_TAG_LEN
        );
        assert!(padding_plain.iter().all(|byte| *byte == 0));
        assert_eq!(cursor, hello.bytes.len());

        let mlkem_private =
            DecapsulationKey::new(&ML_KEM_768, &hello.mlkem_private_key)
                .expect("serialized ML-KEM private key should reconstruct");
        let mlkem_public = EncapsulationKey::new(
            &ML_KEM_768,
            &hello.pfs_public_key[..MLKEM768_PUBLIC_KEY_LEN],
        )
        .expect("serialized ML-KEM public key should reconstruct");
        let (ciphertext, shared_client) =
            mlkem_public.encapsulate().expect("ML-KEM encapsulation");
        let shared_server = mlkem_private
            .decapsulate(Ciphertext::from(ciphertext.as_ref()))
            .expect("ML-KEM private key should decapsulate");
        assert_eq!(shared_client.as_ref(), shared_server.as_ref());

        let x25519_private = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &hello.x25519_private_key,
        )
        .expect("serialized X25519 private key should reconstruct");
        let x25519_public = x25519_private
            .compute_public_key()
            .expect("X25519 public key should reconstruct");
        assert_eq!(
            x25519_public.as_ref(),
            &hello.pfs_public_key[MLKEM768_PUBLIC_KEY_LEN..]
        );
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn one_rtt_server_pfs_response_derives_xray_united_key() {
        use aws_lc_rs::{
            agreement,
            kem::{EncapsulationKey, ML_KEM_768},
        };

        let nfs_private =
            agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let nfs_public = nfs_private.compute_public_key().unwrap();
        let raw = format!(
            "{METHOD}.native.1rtt.100-64-64.{}",
            URL_SAFE_NO_PAD.encode(nfs_public.as_ref()),
        );
        let config = Config::parse(&raw).expect("1rtt config should parse");
        let prepared = config.prepare_crypto().expect("crypto should prepare");
        let hello = prepared
            .one_rtt_hello
            .as_ref()
            .expect("1rtt hello should be prepared");

        let client_mlkem_public = EncapsulationKey::new(
            &ML_KEM_768,
            &hello.pfs_public_key[..MLKEM768_PUBLIC_KEY_LEN],
        )
        .expect("client ML-KEM public key");
        let (server_mlkem_ciphertext, server_mlkem_secret) = client_mlkem_public
            .encapsulate()
            .expect("server ML-KEM encapsulation");

        let server_x25519_private =
            agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_x25519_public =
            server_x25519_private.compute_public_key().unwrap();
        let client_x25519_public = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            &hello.pfs_public_key[MLKEM768_PUBLIC_KEY_LEN..],
        );
        let mut server_x25519_secret = Vec::new();
        agreement::agree(
            &server_x25519_private,
            client_x25519_public,
            invalid("server X25519 agreement failed"),
            |material| {
                server_x25519_secret.extend_from_slice(material);
                Ok(())
            },
        )
        .expect("server X25519 agreement");

        let mut server_pfs_public = Vec::with_capacity(SERVER_PFS_PUBLIC_KEY_LEN);
        server_pfs_public.extend_from_slice(server_mlkem_ciphertext.as_ref());
        server_pfs_public.extend_from_slice(server_x25519_public.as_ref());
        assert_eq!(server_pfs_public.len(), SERVER_PFS_PUBLIC_KEY_LEN);

        let nfs_aead =
            EncryptionAead::new(&prepared.nfs_aead_key).expect("NFS AEAD");
        let encrypted_server_pfs = nfs_aead
            .seal_with_nonce(&server_pfs_public, [0xff; 12])
            .expect("server PFS should encrypt");
        assert_eq!(encrypted_server_pfs.len(), SERVER_PFS_RESPONSE_LEN);

        let session = hello
            .derive_server_session(
                &prepared.nfs_aead_key,
                &prepared.nfs_relays.nfs_key,
                &encrypted_server_pfs,
            )
            .expect("client should derive server PFS session");

        let mut expected_united = Vec::new();
        expected_united.extend_from_slice(server_mlkem_secret.as_ref());
        expected_united.extend_from_slice(&server_x25519_secret);
        expected_united.extend_from_slice(&prepared.nfs_relays.nfs_key);

        assert_eq!(session.united_key, expected_united);
        assert_eq!(session.write_aead_context, hello.pfs_public_key);
        assert_eq!(session.read_aead_context, server_pfs_public);
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn one_rtt_server_tail_decrypts_ticket_and_padding_length() {
        use aws_lc_rs::{
            agreement,
            kem::{EncapsulationKey, ML_KEM_768},
        };

        let nfs_private =
            agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let nfs_public = nfs_private.compute_public_key().unwrap();
        let raw = format!(
            "{METHOD}.native.1rtt.100-64-64.{}",
            URL_SAFE_NO_PAD.encode(nfs_public.as_ref()),
        );
        let config = Config::parse(&raw).expect("1rtt config should parse");
        let prepared = config.prepare_crypto().expect("crypto should prepare");
        let hello = prepared
            .one_rtt_hello
            .as_ref()
            .expect("1rtt hello should be prepared");

        let client_mlkem_public = EncapsulationKey::new(
            &ML_KEM_768,
            &hello.pfs_public_key[..MLKEM768_PUBLIC_KEY_LEN],
        )
        .expect("client ML-KEM public key");
        let (server_mlkem_ciphertext, _) = client_mlkem_public
            .encapsulate()
            .expect("server ML-KEM encapsulation");

        let server_x25519_private =
            agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_x25519_public =
            server_x25519_private.compute_public_key().unwrap();

        let mut server_pfs_public = Vec::with_capacity(SERVER_PFS_PUBLIC_KEY_LEN);
        server_pfs_public.extend_from_slice(server_mlkem_ciphertext.as_ref());
        server_pfs_public.extend_from_slice(server_x25519_public.as_ref());

        let nfs_aead =
            EncryptionAead::new(&prepared.nfs_aead_key).expect("NFS AEAD");
        let encrypted_server_pfs = nfs_aead
            .seal_with_nonce(&server_pfs_public, [0xff; 12])
            .expect("server PFS should encrypt");

        let session = hello
            .derive_server_session(
                &prepared.nfs_aead_key,
                &prepared.nfs_relays.nfs_key,
                &encrypted_server_pfs,
            )
            .expect("client should derive server PFS session");

        let mut ticket_plain = [0x44u8; 16];
        ticket_plain[..2].copy_from_slice(&600u16.to_be_bytes());
        let mut server_aead =
            EncryptionAead::new(&session.read_aead_key).expect("server AEAD");
        let encrypted_ticket = server_aead
            .seal(&ticket_plain)
            .expect("ticket should encrypt");
        let encrypted_padding_length = server_aead
            .seal(&encode_length(96).expect("padding length"))
            .expect("padding length should encrypt");

        let tail = session
            .decrypt_server_tail(&encrypted_ticket, &encrypted_padding_length)
            .expect("server tail should decrypt");

        assert_eq!(tail.ticket, ticket_plain);
        assert_eq!(tail.ticket_seconds, 600);
        assert_eq!(tail.peer_padding_ciphertext_len, 96);
        assert_eq!(tail.read_aead_nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(
            session.write_aead_key,
            blake3_derive_key_raw_context(
                &session.write_aead_context,
                &session.united_key,
            )
            .expect("write AEAD key")
        );
        assert_eq!(
            session.read_aead_key,
            blake3_derive_key_raw_context(
                &session.read_aead_context,
                &session.united_key,
            )
            .expect("read AEAD key")
        );
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn one_rtt_server_tail_rejects_wrong_field_lengths() {
        let session = PreparedOneRttSession {
            united_key: vec![0u8; 96],
            write_aead_context: vec![0u8; PFS_PUBLIC_KEY_LEN],
            read_aead_context: vec![0u8; SERVER_PFS_PUBLIC_KEY_LEN],
            write_aead_key: [0u8; 32],
            read_aead_key: [0u8; 32],
        };

        let ticket_err = session
            .decrypt_server_tail(&[0u8; 16], &[0u8; ENCRYPTED_LENGTH_LEN])
            .expect_err("short ticket must fail");
        assert!(
            ticket_err.to_string().contains("ticket length"),
            "unexpected error: {ticket_err}"
        );

        let padding_err = session
            .decrypt_server_tail(&[0u8; ENCRYPTED_TICKET_LEN], &[0u8; 2])
            .expect_err("short padding length field must fail");
        assert!(
            padding_err.to_string().contains("padding length field"),
            "unexpected error: {padding_err}"
        );
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn encryption_record_codec_matches_xray_header_and_aad() {
        let key = [0x31u8; 32];
        let mut writer =
            EncryptionRecordCodec::new(&key, [0u8; 12]).expect("writer codec");
        let mut reader =
            EncryptionRecordCodec::new(&key, [0u8; 12]).expect("reader codec");

        let record = writer.seal_record(b"hello").expect("record should encrypt");

        assert_eq!(&record[..RECORD_HEADER_LEN], &[23, 3, 3, 0, 21]);
        assert_eq!(
            decode_record_header(
                record[..RECORD_HEADER_LEN]
                    .try_into()
                    .expect("record header")
            )
            .expect("header should decode"),
            21
        );
        assert_eq!(
            reader.open_record(&record).expect("record should decrypt"),
            b"hello"
        );
        assert_eq!(writer.nonce(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(reader.nonce(), writer.nonce());
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn encryption_record_codec_continues_after_peer_padding() {
        let key = [0x52u8; 32];
        let session = PreparedOneRttSession {
            united_key: vec![0u8; 96],
            write_aead_context: vec![0u8; PFS_PUBLIC_KEY_LEN],
            read_aead_context: vec![0u8; SERVER_PFS_PUBLIC_KEY_LEN],
            write_aead_key: [0x41u8; 32],
            read_aead_key: key,
        };
        let tail = PreparedOneRttServerTail {
            ticket: [0u8; 16],
            ticket_seconds: 0,
            peer_padding_ciphertext_len: 48,
            read_aead_nonce: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };
        let (_, mut reader) = session
            .record_codecs(&tail)
            .expect("record codecs should build");

        let mut server_aead =
            EncryptionAead::new_with_nonce(&key, tail.read_aead_nonce)
                .expect("server AEAD");
        let peer_padding = server_aead
            .seal(&vec![0u8; 32])
            .expect("peer padding should encrypt");
        assert_eq!(peer_padding.len(), tail.peer_padding_ciphertext_len);

        let mut server_codec = EncryptionRecordCodec { aead: server_aead };
        let record = server_codec
            .seal_record(b"reply")
            .expect("server record should encrypt");

        let padding_plain = reader
            .open_peer_padding(&peer_padding)
            .expect("peer padding should decrypt");
        assert_eq!(padding_plain, vec![0u8; 32]);
        assert_eq!(reader.nonce(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

        assert_eq!(
            reader
                .open_record(&record)
                .expect("server record should decrypt"),
            b"reply"
        );
        assert_eq!(reader.nonce(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn encryption_record_codec_rejects_invalid_lengths_and_header() {
        let key = [0x63u8; 32];
        let mut codec = EncryptionRecordCodec::new(&key, [0u8; 12]).expect("codec");

        let oversized = vec![0u8; MAX_RECORD_PLAINTEXT_LEN + 1];
        let err = codec
            .seal_record(&oversized)
            .expect_err("oversized plaintext must fail");
        assert!(
            err.to_string().contains("plaintext too large"),
            "unexpected error: {err}"
        );

        let mut invalid_header = vec![0u8; RECORD_HEADER_LEN + 17];
        invalid_header[..RECORD_HEADER_LEN].copy_from_slice(&[22, 3, 3, 0, 17]);
        let err = codec
            .open_record(&invalid_header)
            .expect_err("invalid record header must fail");
        assert!(
            err.to_string()
                .contains("invalid VLESS encryption record header"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "vless-encryption")]
    #[test]
    fn one_rtt_server_pfs_rejects_wrong_response_length() {
        let nfs_private = aws_lc_rs::agreement::PrivateKey::generate(
            &aws_lc_rs::agreement::X25519,
        )
        .unwrap();
        let nfs_public = nfs_private.compute_public_key().unwrap();
        let raw = format!(
            "{METHOD}.native.1rtt.100-64-64.{}",
            URL_SAFE_NO_PAD.encode(nfs_public.as_ref()),
        );
        let config = Config::parse(&raw).expect("1rtt config should parse");
        let prepared = config.prepare_crypto().expect("crypto should prepare");
        let hello = prepared
            .one_rtt_hello
            .as_ref()
            .expect("1rtt hello should be prepared");

        let err = hello
            .derive_server_session(
                &prepared.nfs_aead_key,
                &prepared.nfs_relays.nfs_key,
                &[0u8; 16],
            )
            .expect_err("short server PFS response must fail");

        assert!(
            err.to_string().contains("server PFS response length"),
            "unexpected error: {err}"
        );
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
