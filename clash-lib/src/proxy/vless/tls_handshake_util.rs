pub const MIN_TLS_HANDSHAKE_PATTERN_LEN: usize = 6;

fn is_valid_tls_handshake_prefix(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    if data[0] != 0x16 {
        return false;
    }
    if data.len() >= 2 && data[1] != 0x03 {
        return false;
    }
    if data.len() >= 3 && !(0x01..=0x03).contains(&data[2]) {
        return false;
    }
    true
}

pub fn find_tls_handshake_start(data: &[u8]) -> Option<usize> {
    if data.len() < MIN_TLS_HANDSHAKE_PATTERN_LEN {
        return None;
    }

    data.windows(MIN_TLS_HANDSHAKE_PATTERN_LEN)
        .position(|candidate| {
            candidate[0] == 0x16
                && candidate[1] == 0x03
                && (0x01..=0x03).contains(&candidate[2])
                && (candidate[5] == 0x01 || candidate[5] == 0x02)
        })
}

pub fn find_potential_tls_suffix_len(data: &[u8]) -> usize {
    let max_suffix = data.len().min(5);
    for suffix_len in (1..=max_suffix).rev() {
        if is_valid_tls_handshake_prefix(&data[data.len() - suffix_len..]) {
            return suffix_len;
        }
    }
    0
}
