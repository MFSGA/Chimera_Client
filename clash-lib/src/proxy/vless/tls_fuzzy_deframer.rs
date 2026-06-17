use std::io;

use bytes::{Bytes, BytesMut};

use super::tls_deframer::TlsDeframer;
use super::tls_handshake_util::{
    MIN_TLS_HANDSHAKE_PATTERN_LEN, find_potential_tls_suffix_len,
    find_tls_handshake_start,
};

#[derive(Debug, PartialEq)]
pub enum DeframeResult {
    TlsRecord(Bytes),
    UnknownPrefix(Bytes),
    NeedData,
}

pub struct FuzzyTlsDeframer {
    inner: TlsDeframer,
    search_buffer: BytesMut,
    state: FuzzyState,
}

#[derive(Debug, PartialEq)]
enum FuzzyState {
    Searching,
    Deframing,
}

impl FuzzyTlsDeframer {
    pub fn new() -> Self {
        Self {
            inner: TlsDeframer::new(),
            search_buffer: BytesMut::new(),
            state: FuzzyState::Searching,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        match self.state {
            FuzzyState::Searching => self.search_buffer.extend_from_slice(data),
            FuzzyState::Deframing => self.inner.feed(data),
        }
    }

    pub fn next_record(&mut self) -> io::Result<DeframeResult> {
        loop {
            match self.state {
                FuzzyState::Searching => {
                    if self.search_buffer.is_empty() {
                        return Ok(DeframeResult::NeedData);
                    }

                    if self.search_buffer.len() >= MIN_TLS_HANDSHAKE_PATTERN_LEN
                        && let Some(offset) =
                            find_tls_handshake_start(&self.search_buffer)
                    {
                        if offset > 0 {
                            let prefix =
                                self.search_buffer.split_to(offset).freeze();
                            self.inner.feed(&self.search_buffer);
                            self.search_buffer.clear();
                            self.state = FuzzyState::Deframing;
                            return Ok(DeframeResult::UnknownPrefix(prefix));
                        }

                        self.inner.feed(&self.search_buffer);
                        self.search_buffer.clear();
                        self.state = FuzzyState::Deframing;
                        continue;
                    }

                    let suffix_len =
                        find_potential_tls_suffix_len(&self.search_buffer);
                    if suffix_len < self.search_buffer.len() {
                        let prefix_len = self.search_buffer.len() - suffix_len;
                        return Ok(DeframeResult::UnknownPrefix(
                            self.search_buffer.split_to(prefix_len).freeze(),
                        ));
                    }

                    return Ok(DeframeResult::NeedData);
                }
                FuzzyState::Deframing => {
                    return match self.inner.next_record()? {
                        Some(record) => Ok(DeframeResult::TlsRecord(record)),
                        None => Ok(DeframeResult::NeedData),
                    };
                }
            }
        }
    }

    pub fn pending_bytes(&self) -> usize {
        match self.state {
            FuzzyState::Searching => self.search_buffer.len(),
            FuzzyState::Deframing => self.inner.pending_bytes(),
        }
    }

    pub fn remaining_data(&self) -> &[u8] {
        match self.state {
            FuzzyState::Searching => &self.search_buffer,
            FuzzyState::Deframing => self.inner.remaining_data(),
        }
    }

    pub fn clear(&mut self) {
        self.search_buffer.clear();
        self.inner.clear();
        self.state = FuzzyState::Searching;
    }
}

impl Default for FuzzyTlsDeframer {
    fn default() -> Self {
        Self::new()
    }
}
