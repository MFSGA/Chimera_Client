use std::io;

use super::{CLIENT_HELLO_IV_LEN, invalid};

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
pub(super) fn blake3_derive_key_raw_context(
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
pub(in crate::proxy::vless) fn xor_vless_ctr(
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
