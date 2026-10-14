//! Prepared X25519MLKEM768 key exchange for REALITY.
//!
//! This module does not negotiate the TLS group. The connection must send the
//! generated key share and use the matching private state when processing the
//! ServerHello before hybrid support can be enabled at runtime.

use std::io::{self, ErrorKind};

use aws_lc_rs::{
    agreement,
    kem::{Ciphertext, DecapsulationKey, ML_KEM_768},
};
#[cfg(test)]
use rand::Rng;

use super::reality_auth::perform_ecdh;
use super::reality_util::{
    RealityKeyShare, X25519_KEY_SHARE_LEN, X25519_MLKEM768_CLIENT_KEY_SHARE_LEN,
    X25519_MLKEM768_GROUP,
};

const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
const ML_KEM_768_PUBLIC_KEY_LEN: usize =
    X25519_MLKEM768_CLIENT_KEY_SHARE_LEN - X25519_KEY_SHARE_LEN;
const HYBRID_SHARED_SECRET_LEN: usize = 64;

/// Private per-connection state tied to a single offered hybrid ClientHello key share.
///
/// The encapsulation key is public. Never log the decapsulation key, either
/// derived shared secret, or the concatenated TLS key exchange secret.
pub(super) struct HybridKeyExchange {
    ml_kem_decapsulation_key: DecapsulationKey,
    x25519_private_key: [u8; X25519_KEY_SHARE_LEN],
    client_key_share: Vec<u8>,
}

impl HybridKeyExchange {
    /// Generate fresh ML-KEM-768 and X25519 key pairs.
    #[cfg(test)]
    pub(super) fn generate() -> io::Result<Self> {
        let mut x25519_private_key = [0u8; X25519_KEY_SHARE_LEN];
        rand::rng().fill_bytes(&mut x25519_private_key);
        Self::generate_with_x25519_private_key(x25519_private_key)
    }

    /// Bind the TLS X25519 key share to the same ephemeral key used to derive
    /// the REALITY authentication secret, as Mihomo's Hybrid path does.
    pub(super) fn generate_with_x25519_private_key(
        x25519_private_key: [u8; X25519_KEY_SHARE_LEN],
    ) -> io::Result<Self> {
        let ml_kem_decapsulation_key = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| io::Error::other("Failed to generate ML-KEM-768 key"))?;
        let ml_kem_public_key = ml_kem_decapsulation_key
            .encapsulation_key()
            .and_then(|key| key.key_bytes())
            .map_err(|_| {
                io::Error::other("Failed to obtain ML-KEM-768 public key")
            })?;
        if ml_kem_public_key.as_ref().len() != ML_KEM_768_PUBLIC_KEY_LEN {
            return Err(io::Error::other("Unexpected ML-KEM-768 public key length"));
        }

        let x25519_public_key = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &x25519_private_key,
        )
        .map_err(|_| io::Error::other("Failed to create hybrid X25519 private key"))?
        .compute_public_key()
        .map_err(|_| {
            io::Error::other("Failed to compute hybrid X25519 public key")
        })?;

        // TLS X25519MLKEM768 ClientHello: ML-KEM public key first, followed
        // by the X25519 public key bound to REALITY authentication.
        let mut client_key_share =
            Vec::with_capacity(X25519_MLKEM768_CLIENT_KEY_SHARE_LEN);
        client_key_share.extend_from_slice(ml_kem_public_key.as_ref());
        client_key_share.extend_from_slice(x25519_public_key.as_ref());

        Ok(Self {
            ml_kem_decapsulation_key,
            x25519_private_key,
            client_key_share,
        })
    }

    /// Return the bytes to offer in a ClientHello key share for group 0x11ec.
    pub(super) fn client_key_share(&self) -> &[u8] {
        &self.client_key_share
    }

    /// Decapsulate the server's 1088-byte ML-KEM ciphertext and agree on X25519.
    ///
    /// The TLS 1.3 shared secret is ML-KEM's 32 bytes followed by X25519's
    /// 32 bytes. Both shares must belong to this instance's ClientHello.
    pub(super) fn derive_shared_secret(
        &self,
        server_key_share: &RealityKeyShare,
    ) -> io::Result<[u8; HYBRID_SHARED_SECRET_LEN]> {
        if server_key_share.group != X25519_MLKEM768_GROUP {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ServerHello key share group does not match hybrid ClientHello",
            ));
        }
        if server_key_share.data.len()
            != ML_KEM_768_CIPHERTEXT_LEN + X25519_KEY_SHARE_LEN
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Invalid X25519MLKEM768 ServerHello key share length",
            ));
        }

        let (ciphertext, server_x25519_public_key) =
            server_key_share.data.split_at(ML_KEM_768_CIPHERTEXT_LEN);
        let mut peer_public_key = [0u8; X25519_KEY_SHARE_LEN];
        peer_public_key.copy_from_slice(server_x25519_public_key);

        let ml_kem_shared_secret = self
            .ml_kem_decapsulation_key
            .decapsulate(Ciphertext::from(ciphertext))
            .map_err(|_| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "ML-KEM-768 decapsulation failed",
                )
            })?;
        if ml_kem_shared_secret.as_ref().len() != X25519_KEY_SHARE_LEN {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Invalid ML-KEM-768 shared secret length",
            ));
        }

        let x25519_shared_secret = perform_ecdh(
            &self.x25519_private_key,
            &peer_public_key,
        )
        .map_err(|_| {
            io::Error::new(ErrorKind::InvalidData, "Hybrid X25519 agreement failed")
        })?;

        let mut combined = [0u8; HYBRID_SHARED_SECRET_LEN];
        combined[..X25519_KEY_SHARE_LEN]
            .copy_from_slice(ml_kem_shared_secret.as_ref());
        combined[X25519_KEY_SHARE_LEN..].copy_from_slice(&x25519_shared_secret);
        Ok(combined)
    }
}

#[cfg(test)]
mod tests {
    use super::super::reality_cipher_suite::CipherSuite;
    use super::super::reality_tls13_keys::derive_handshake_keys;
    use super::*;
    use aws_lc_rs::kem::EncapsulationKey;

    #[test]
    fn hybrid_key_exchange_matches_server_secrets_and_tls_hkdf() {
        let client = HybridKeyExchange::generate().unwrap();
        assert_eq!(
            client.client_key_share().len(),
            X25519_MLKEM768_CLIENT_KEY_SHARE_LEN
        );
        let (ml_kem_public_key, client_x25519_public_key) = client
            .client_key_share()
            .split_at(ML_KEM_768_PUBLIC_KEY_LEN);

        let (ciphertext, server_ml_kem_secret) =
            EncapsulationKey::new(&ML_KEM_768, ml_kem_public_key)
                .unwrap()
                .encapsulate()
                .unwrap();
        assert_eq!(ciphertext.as_ref().len(), ML_KEM_768_CIPHERTEXT_LEN);

        let server_x25519_private_key = [0x42u8; X25519_KEY_SHARE_LEN];
        let server_x25519_public_key = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &server_x25519_private_key,
        )
        .unwrap()
        .compute_public_key()
        .unwrap();

        let mut server_share_data = ciphertext.as_ref().to_vec();
        server_share_data.extend_from_slice(server_x25519_public_key.as_ref());
        let server_share = RealityKeyShare {
            group: X25519_MLKEM768_GROUP,
            data: server_share_data,
        };

        let hybrid_secret = client.derive_shared_secret(&server_share).unwrap();
        assert_eq!(&hybrid_secret[..32], server_ml_kem_secret.as_ref());
        let expected_x25519 = perform_ecdh(
            &server_x25519_private_key,
            client_x25519_public_key.try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(&hybrid_secret[32..], &expected_x25519);

        for suite in [
            CipherSuite::AES_128_GCM_SHA256,
            CipherSuite::AES_256_GCM_SHA384,
        ] {
            let transcript = vec![0x5a; suite.hash_len()];
            let keys = derive_handshake_keys(
                suite,
                &hybrid_secret,
                &transcript,
                &transcript,
            )
            .unwrap();
            assert_eq!(keys.client_handshake_traffic_secret.len(), suite.hash_len());
        }
    }

    #[test]
    fn hybrid_key_exchange_rejects_wrong_group_and_lengths() {
        let client = HybridKeyExchange::generate().unwrap();
        for group in [0x001d, 0x11ed] {
            let invalid = RealityKeyShare {
                group,
                data: vec![0u8; ML_KEM_768_CIPHERTEXT_LEN + X25519_KEY_SHARE_LEN],
            };
            assert_eq!(
                client.derive_shared_secret(&invalid).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }

        for len in [0, 32, 1088, 1119, 1121] {
            let invalid = RealityKeyShare {
                group: X25519_MLKEM768_GROUP,
                data: vec![0u8; len],
            };
            assert_eq!(
                client.derive_shared_secret(&invalid).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn hybrid_key_exchange_rejects_invalid_x25519_public_key() {
        let client = HybridKeyExchange::generate().unwrap();
        let (ml_kem_public_key, _) = client
            .client_key_share()
            .split_at(ML_KEM_768_PUBLIC_KEY_LEN);
        let (ciphertext, _) = EncapsulationKey::new(&ML_KEM_768, ml_kem_public_key)
            .unwrap()
            .encapsulate()
            .unwrap();
        let mut invalid_data = ciphertext.as_ref().to_vec();
        invalid_data.extend_from_slice(&[0u8; X25519_KEY_SHARE_LEN]);
        let invalid = RealityKeyShare {
            group: X25519_MLKEM768_GROUP,
            data: invalid_data,
        };
        assert_eq!(
            client.derive_shared_secret(&invalid).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn hybrid_key_exchange_uses_fresh_public_keys() {
        let first = HybridKeyExchange::generate().unwrap();
        let second = HybridKeyExchange::generate().unwrap();
        assert_ne!(first.client_key_share(), second.client_key_share());
    }

    #[test]
    fn hybrid_key_exchange_uses_reality_authentication_x25519_key() {
        let x25519_private_key = [0x33u8; X25519_KEY_SHARE_LEN];
        let client =
            HybridKeyExchange::generate_with_x25519_private_key(x25519_private_key)
                .unwrap();
        let expected_public = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &x25519_private_key,
        )
        .unwrap()
        .compute_public_key()
        .unwrap();
        assert_eq!(
            &client.client_key_share()[ML_KEM_768_PUBLIC_KEY_LEN..],
            expected_public.as_ref()
        );
    }
}
