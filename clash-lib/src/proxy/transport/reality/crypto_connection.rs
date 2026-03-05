// Unified crypto connection wrapper for Reality client sessions.

use std::io::{self, Read, Write};

use super::reality_client_connection::{
    RealityClientConnection, feed_reality_client_connection,
};
use super::reality_io_state::RealityIoState;
use super::reality_reader_writer::{RealityReader, RealityWriter};

pub struct CryptoConnection {
    inner: RealityClientConnection,
}

impl CryptoConnection {
    pub fn new_reality_client(conn: RealityClientConnection) -> Self {
        Self { inner: conn }
    }

    pub fn is_server(&self) -> bool {
        false
    }

    pub fn is_client(&self) -> bool {
        true
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        None
    }

    pub fn is_reality(&self) -> bool {
        true
    }

    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        self.inner.read_tls(rd)
    }

    pub fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        self.inner.process_new_packets()
    }

    pub fn reader(&mut self) -> RealityReader<'_> {
        self.inner.reader()
    }

    pub fn writer(&mut self) -> RealityWriter<'_> {
        self.inner.writer()
    }

    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        self.inner.write_tls(wr)
    }

    pub fn wants_write(&self) -> bool {
        self.inner.wants_write()
    }

    pub fn wants_read(&self) -> bool {
        self.inner.wants_read()
    }

    pub fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    pub fn send_close_notify(&mut self) {
        self.inner.send_close_notify();
    }
}

#[inline]
pub fn feed_crypto_connection(
    connection: &mut CryptoConnection,
    data: &[u8],
) -> io::Result<()> {
    feed_reality_client_connection(&mut connection.inner, data)
}
