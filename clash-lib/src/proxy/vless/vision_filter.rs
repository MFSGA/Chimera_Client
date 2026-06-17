use std::io;

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS13_CIPHER_AES_128_CCM_8_SHA256: u16 = 0x1305;

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
                    if parsed.is_tls13
                        && parsed.cipher_suite != TLS13_CIPHER_AES_128_CCM_8_SHA256
                    {
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
