use super::*;

fn encoded_key(len: usize, value: u8) -> String {
    URL_SAFE_NO_PAD.encode(vec![value; len])
}

#[test]
fn parses_x25519_and_mlkem_key_chain() {
    let x25519 = encoded_key(X25519_PUBLIC_KEY_LEN, 7);
    let mlkem = encoded_key(MLKEM768_PUBLIC_KEY_LEN, 9);
    let raw = format!("{METHOD}.xorpub.1rtt.100-111-1111.75-0-111.{x25519}.{mlkem}");

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

    let err = Config::parse(&raw).expect_err("padding after key material must fail");

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
    let raw = format!("{METHOD}.native.1rtt.100-111-1111.75-0-111.50-0-3333.{key}");
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
    let raw = format!("{METHOD}.native.1rtt.100-111-1111.75-0-111.50-0-3333.{key}");

    let config = Config::parse(&raw).expect("default padding shape should parse");

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
        let derived = blake3_derive_key_raw_context(context.as_bytes(), &material)
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
        for (byte, mask_byte) in mlkem_relay[..32].iter_mut().zip(&chain_mask[32..])
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
    let mut aead = EncryptionAead::new(&prepared.nfs_aead_key).expect("AEAD key");

    let pfs_length_plain = aead
        .open(&hello.bytes[cursor..cursor + ENCRYPTED_LENGTH_LEN])
        .expect("PFS length should decrypt");
    cursor += ENCRYPTED_LENGTH_LEN;
    assert_eq!(
        u16::from_be_bytes(pfs_length_plain.as_slice().try_into().unwrap()) as usize,
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

    let mlkem_private = DecapsulationKey::new(&ML_KEM_768, &hello.mlkem_private_key)
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

    let nfs_private = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
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
    let server_x25519_public = server_x25519_private.compute_public_key().unwrap();
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

    let nfs_aead = EncryptionAead::new(&prepared.nfs_aead_key).expect("NFS AEAD");
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

    let nfs_private = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
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
    let server_x25519_public = server_x25519_private.compute_public_key().unwrap();

    let mut server_pfs_public = Vec::with_capacity(SERVER_PFS_PUBLIC_KEY_LEN);
    server_pfs_public.extend_from_slice(server_mlkem_ciphertext.as_ref());
    server_pfs_public.extend_from_slice(server_x25519_public.as_ref());

    let nfs_aead = EncryptionAead::new(&prepared.nfs_aead_key).expect("NFS AEAD");
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

    let mut server_aead = EncryptionAead::new_with_nonce(&key, tail.read_aead_nonce)
        .expect("server AEAD");
    let peer_padding = server_aead
        .seal(&[0u8; 32])
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
#[tokio::test]
async fn encryption_stream_native_one_rtt_round_trips_records() {
    encryption_stream_one_rtt_round_trips_records("native").await;
}

#[cfg(feature = "vless-encryption")]
#[tokio::test]
async fn encryption_stream_xorpub_one_rtt_round_trips_records() {
    encryption_stream_one_rtt_round_trips_records("xorpub").await;
}

#[cfg(feature = "vless-encryption")]
async fn encryption_stream_one_rtt_round_trips_records(appearance: &str) {
    use aws_lc_rs::{
        agreement,
        kem::{EncapsulationKey, ML_KEM_768},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::encryption_stream::EncryptionStream;

    let nfs_private = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
    let nfs_public = nfs_private.compute_public_key().unwrap();
    let raw = format!(
        "{METHOD}.{appearance}.1rtt.100-64-64.{}",
        URL_SAFE_NO_PAD.encode(nfs_public.as_ref()),
    );
    let config = Config::parse(&raw).expect("1rtt config should parse");
    let prepared = config.prepare_crypto().expect("crypto should prepare");
    let server_prepared = prepared.clone();

    let (client, mut server) = tokio::io::duplex(128);
    let server_task = tokio::spawn(async move {
        let hello = server_prepared.one_rtt_hello.as_ref().expect("1rtt hello");

        let mut received_hello = vec![0u8; hello.bytes.len()];
        server
            .read_exact(&mut received_hello)
            .await
            .expect("client hello");
        assert_eq!(received_hello, hello.bytes);

        // Recover the NFS relay from the actual ClientHello bytes. xorpub must
        // be reversible with the configured server public key and transmitted IV.
        let mut relay = received_hello
            [CLIENT_HELLO_IV_LEN..CLIENT_HELLO_IV_LEN + X25519_PUBLIC_KEY_LEN]
            .to_vec();
        if appearance == "xorpub" {
            xor_vless_ctr(
                nfs_public.as_ref(),
                &server_prepared.nfs_relays.iv,
                &mut relay,
            )
            .expect("unmask xorpub relay");
        }
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, &relay);
        let mut recovered_nfs = Vec::new();
        agreement::agree(
            &nfs_private,
            peer,
            invalid("server NFS agreement failed"),
            |material| {
                recovered_nfs.extend_from_slice(material);
                Ok(())
            },
        )
        .expect("server NFS agreement");
        assert_eq!(recovered_nfs, server_prepared.nfs_relays.nfs_key);

        let client_mlkem_public = EncapsulationKey::new(
            &ML_KEM_768,
            &hello.pfs_public_key[..MLKEM768_PUBLIC_KEY_LEN],
        )
        .expect("client ML-KEM public key");
        let (mlkem_ciphertext, mlkem_secret) = client_mlkem_public
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
        let mut x25519_secret = Vec::new();
        agreement::agree(
            &server_x25519_private,
            client_x25519_public,
            invalid("server X25519 agreement failed"),
            |material| {
                x25519_secret.extend_from_slice(material);
                Ok(())
            },
        )
        .expect("server X25519 agreement");

        let mut server_pfs = Vec::with_capacity(SERVER_PFS_PUBLIC_KEY_LEN);
        server_pfs.extend_from_slice(mlkem_ciphertext.as_ref());
        server_pfs.extend_from_slice(server_x25519_public.as_ref());

        let nfs_aead =
            EncryptionAead::new(&server_prepared.nfs_aead_key).expect("NFS AEAD");
        let encrypted_server_pfs = nfs_aead
            .seal_with_nonce(&server_pfs, [0xff; 12])
            .expect("server PFS encryption");

        let mut united_key = Vec::new();
        united_key.extend_from_slice(mlkem_secret.as_ref());
        united_key.extend_from_slice(&x25519_secret);
        united_key.extend_from_slice(&server_prepared.nfs_relays.nfs_key);

        let client_write_key =
            blake3_derive_key_raw_context(&hello.pfs_public_key, &united_key)
                .expect("client write key");
        let server_write_key =
            blake3_derive_key_raw_context(&server_pfs, &united_key)
                .expect("server write key");

        let mut server_aead =
            EncryptionAead::new(&server_write_key).expect("server AEAD");
        let ticket = [0u8; 16];
        let encrypted_ticket = server_aead.seal(&ticket).expect("server ticket");
        let encrypted_padding_len = server_aead
            .seal(&encode_length(48).expect("padding length"))
            .expect("server padding length");
        let encrypted_padding =
            server_aead.seal(&[0u8; 32]).expect("server padding");
        assert_eq!(encrypted_padding.len(), 48);

        let mut server_hello = Vec::new();
        server_hello.extend_from_slice(&encrypted_server_pfs);
        server_hello.extend_from_slice(&encrypted_ticket);
        server_hello.extend_from_slice(&encrypted_padding_len);
        server_hello.extend_from_slice(&encrypted_padding);
        server.write_all(&server_hello).await.expect("server hello");

        let mut header = [0u8; RECORD_HEADER_LEN];
        server
            .read_exact(&mut header)
            .await
            .expect("client record header");
        let body_len = decode_record_header(&header).expect("client record header");
        let mut body = vec![0u8; body_len];
        server
            .read_exact(&mut body)
            .await
            .expect("client record body");
        let mut record = header.to_vec();
        record.extend_from_slice(&body);

        let mut client_reader =
            EncryptionRecordCodec::new(&client_write_key, [0u8; 12])
                .expect("client record codec");
        assert_eq!(
            client_reader
                .open_record(&record)
                .expect("client record decrypt"),
            b"ping"
        );

        let mut server_writer = EncryptionRecordCodec::new(
            &server_write_key,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
        )
        .expect("server record codec");
        let pong = server_writer
            .seal_record(b"pong")
            .expect("server record encrypt");
        server.write_all(&pong).await.expect("server pong");
    });

    let mut stream =
        EncryptionStream::new(Box::new(client), prepared).expect("stream");
    stream.write_all(b"ping").await.expect("encrypted ping");

    let mut pong = [0u8; 4];
    stream.read_exact(&mut pong).await.expect("encrypted pong");
    assert_eq!(&pong, b"pong");

    server_task.await.expect("server task");
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
    let nfs_private =
        aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::X25519)
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
    let fixed = CLIENT_HELLO_IV_LEN + prepared.relays_length + PFS_KEY_EXCHANGE_LEN;
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
