use std::io;

use bytes::{Bytes, BytesMut};

const TLS_RECORD_HEADER_SIZE: usize = 5;
const MAX_TLS_CIPHERTEXT_LEN: usize = 16_384 + 2_048;
const TLS_PROTOCOL_VERSION_MAJOR: u8 = 0x03;
const TLS_PROTOCOL_VERSION_MINOR_MIN: u8 = 0x01;
const TLS_PROTOCOL_VERSION_MINOR_MAX: u8 = 0x03;

#[derive(Debug, PartialEq)]
pub struct TlsDeframer {
    buffer: BytesMut,
    state: DeframerState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DeframerState {
    ReadingHeader,
    ReadingPayload { payload_len: usize },
}

impl TlsDeframer {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(
                TLS_RECORD_HEADER_SIZE + MAX_TLS_CIPHERTEXT_LEN,
            ),
            state: DeframerState::ReadingHeader,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn next_record(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            match self.state {
                DeframerState::ReadingHeader => {
                    if self.buffer.len() < TLS_RECORD_HEADER_SIZE {
                        return Ok(None);
                    }

                    let content_type = self.buffer[0];
                    let version_major = self.buffer[1];
                    let version_minor = self.buffer[2];
                    let payload_len =
                        u16::from_be_bytes([self.buffer[3], self.buffer[4]])
                            as usize;

                    if version_major != TLS_PROTOCOL_VERSION_MAJOR
                        || !(TLS_PROTOCOL_VERSION_MINOR_MIN
                            ..=TLS_PROTOCOL_VERSION_MINOR_MAX)
                            .contains(&version_minor)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "invalid TLS protocol version: 0x{version_major:02x}{version_minor:02x}"
                            ),
                        ));
                    }

                    if payload_len > MAX_TLS_CIPHERTEXT_LEN {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "TLS record ciphertext length {payload_len} exceeds maximum {MAX_TLS_CIPHERTEXT_LEN}"
                            ),
                        ));
                    }

                    if !(0x14..=0x18).contains(&content_type) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "invalid TLS content type: 0x{content_type:02x}"
                            ),
                        ));
                    }

                    self.state = DeframerState::ReadingPayload { payload_len };
                }
                DeframerState::ReadingPayload { payload_len } => {
                    let total_len = TLS_RECORD_HEADER_SIZE + payload_len;
                    if self.buffer.len() < total_len {
                        return Ok(None);
                    }
                    let record = self.buffer.split_to(total_len).freeze();
                    self.state = DeframerState::ReadingHeader;
                    return Ok(Some(record));
                }
            }
        }
    }

    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn remaining_data(&self) -> &[u8] {
        &self.buffer
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.state = DeframerState::ReadingHeader;
    }
}

impl Default for TlsDeframer {
    fn default() -> Self {
        Self::new()
    }
}
