use std::io;

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS13_CIPHER_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS13_CIPHER_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS13_CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS13_CIPHER_AES_128_CCM_SHA256: u16 = 0x1304;

#[derive(Debug)]
pub struct VisionFilter {
    record_filter_count: usize,
    is_tls: bool,
    is_tls12_or_above: bool,
    supports_xtls: bool,
}

struct ParsedServerHello {
    cipher_suite: u16,
    is_tls13: bool,
}

impl VisionFilter {
    pub fn new() -> Self {
        Self {
            record_filter_count: 8,
            is_tls: false,
            is_tls12_or_above: false,
            supports_xtls: false,
        }
    }

    pub fn is_filtering(&self) -> bool {
        self.record_filter_count > 0
    }

    pub fn remaining_filter_count(&self) -> usize {
        self.record_filter_count
    }

    pub fn decrement_filter_count(&mut self) {
        self.record_filter_count = self.record_filter_count.saturating_sub(1);
    }

    pub fn stop_filtering(&mut self, reason: &str) {
        tracing::debug!("VISION: stopping filtering - {reason}");
        self.record_filter_count = 0;
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    pub fn supports_xtls(&self) -> bool {
        self.supports_xtls
    }

    pub fn filter_record(&mut self, data: &[u8]) {
        if self.record_filter_count == 0 {
            return;
        }

        self.record_filter_count = self.record_filter_count.saturating_sub(1);

        if data.len() < 6 {
            self.stop_filtering("invalid record length");
            return;
        }

        if !self.is_tls
            && data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03
            && data[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        {
            self.is_tls = true;
        }

        if !self.is_tls12_or_above
            && data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03
            && data[2] == 0x03
            && data[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
        {
            self.is_tls12_or_above = true;
            self.is_tls = true;

            match parse_server_hello(data) {
                Ok(parsed) => {
                    if parsed.is_tls13 && supports_xtls_cipher(parsed.cipher_suite) {
                        self.supports_xtls = true;
                    }
                    if parsed.is_tls13 {
                        self.stop_filtering("TLS 1.3 handshake detected");
                    }
                }
                Err(err) => {
                    self.stop_filtering(&format!("invalid ServerHello: {err}"))
                }
            }
        }
    }
}

fn supports_xtls_cipher(cipher_suite: u16) -> bool {
    matches!(
        cipher_suite,
        TLS13_CIPHER_AES_128_GCM_SHA256
            | TLS13_CIPHER_AES_256_GCM_SHA384
            | TLS13_CIPHER_CHACHA20_POLY1305_SHA256
            | TLS13_CIPHER_AES_128_CCM_SHA256
    )
}

fn parse_server_hello(record: &[u8]) -> io::Result<ParsedServerHello> {
    if record.len() < 5 + 4 + 2 + 32 + 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello too short",
        ));
    }

    let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete TLS record",
        ));
    }

    let payload = &record[5..5 + body_len];
    if payload[0] != TLS_HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a ServerHello",
        ));
    }

    let handshake_len = ((payload[1] as usize) << 16)
        | ((payload[2] as usize) << 8)
        | payload[3] as usize;
    if payload.len() < 4 + handshake_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete ServerHello handshake",
        ));
    }

    let msg = &payload[4..4 + handshake_len];
    let mut offset = 2 + 32;
    if msg.len() <= offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello missing session id",
        ));
    }

    let session_id_len = msg[offset] as usize;
    offset += 1 + session_id_len;
    if msg.len() < offset + 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello missing cipher suite",
        ));
    }

    let cipher_suite = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
    offset += 3;

    let mut is_tls13 = false;
    if msg.len() >= offset + 2 {
        let extensions_len =
            u16::from_be_bytes([msg[offset], msg[offset + 1]]) as usize;
        offset += 2;
        let end = (offset + extensions_len).min(msg.len());
        while offset + 4 <= end {
            let ext_type = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
            let ext_len =
                u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]) as usize;
            offset += 4;
            if offset + ext_len > end {
                break;
            }
            if ext_type == 0x002b
                && ext_len >= 2
                && u16::from_be_bytes([msg[offset], msg[offset + 1]]) == 0x0304
            {
                is_tls13 = true;
                break;
            }
            offset += ext_len;
        }
    }

    Ok(ParsedServerHello {
        cipher_suite,
        is_tls13,
    })
}

#[cfg(test)]
mod tests {
    use super::VisionFilter;

    fn server_hello(cipher: u16, tls13: bool) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&[0x03, 0x03]);
        message.extend_from_slice(&[0x11; 32]);
        message.push(0);
        message.extend_from_slice(&cipher.to_be_bytes());
        message.push(0);
        if tls13 {
            message.extend_from_slice(&6u16.to_be_bytes());
            message.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        } else {
            message.extend_from_slice(&0u16.to_be_bytes());
        }

        let mut handshake = vec![0x02];
        handshake.extend_from_slice(&(message.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&message);

        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn xray_tls13_cipher_matrix() {
        for cipher in [0x1301, 0x1302, 0x1303, 0x1304] {
            let mut filter = VisionFilter::new();
            filter.filter_record(&server_hello(cipher, true));
            assert!(filter.supports_xtls(), "cipher {cipher:#06x}");
        }

        for cipher in [0x1305, 0x0a0a, 0xc02f] {
            let mut filter = VisionFilter::new();
            filter.filter_record(&server_hello(cipher, true));
            assert!(!filter.supports_xtls(), "cipher {cipher:#06x}");
        }
    }

    #[test]
    fn tls12_and_non_tls_never_enable_direct() {
        let mut tls12 = VisionFilter::new();
        tls12.filter_record(&server_hello(0xc02f, false));
        assert!(tls12.is_tls12_or_above());
        assert!(!tls12.supports_xtls());

        let mut plaintext = VisionFilter::new();
        plaintext.filter_record(b"GET / HTTP/1.1\r\n");
        assert!(!plaintext.is_tls());
        assert!(!plaintext.supports_xtls());
    }
}
