use std::io::ErrorKind;

use bytes::{Buf, BufMut, BytesMut};
use quinn_proto::{VarInt, coding::Codec};
use rand::{RngExt, distr::Alphanumeric};
use tokio_util::codec::{Decoder, Encoder};

use crate::session::SocksAddr;

pub struct Hy2TcpCodec;

#[derive(Debug)]
pub struct Hy2TcpResp {
    pub status: u8,
    pub msg: String,
}

impl Decoder for Hy2TcpCodec {
    type Error = std::io::Error;
    type Item = Hy2TcpResp;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let mut tmp = src.clone();

        let status = tmp.get_u8();
        let msg_len = match VarInt::decode(&mut tmp) {
            Ok(value) => value.into_inner() as usize,
            Err(_) => return Ok(None),
        };

        if tmp.remaining() < msg_len {
            return Ok(None);
        }

        let msg = String::from_utf8(tmp.split_to(msg_len).to_vec()).map_err(|e| {
            std::io::Error::new(ErrorKind::InvalidData, format!("invalid utf-8: {e}"))
        })?;

        let padding_len = match VarInt::decode(&mut tmp) {
            Ok(value) => value.into_inner() as usize,
            Err(_) => return Ok(None),
        };

        if tmp.remaining() < padding_len {
            return Ok(None);
        }
        tmp.advance(padding_len);

        let consumed = src.len() - tmp.len();
        src.advance(consumed);

        Ok(Some(Hy2TcpResp { status, msg }))
    }
}

pub fn padding(range: std::ops::RangeInclusive<u32>) -> Vec<u8> {
    let mut rng = rand::rng();
    let len = rng.random_range(range) as usize;
    rng.sample_iter(Alphanumeric).take(len).collect()
}

impl Encoder<&'_ SocksAddr> for Hy2TcpCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: &'_ SocksAddr, dst: &mut BytesMut) -> Result<(), Self::Error> {
        const REQUEST_ID: VarInt = VarInt::from_u32(0x401);

        let padding = padding(64..=512);
        let padding_var = VarInt::from_u32(padding.len() as u32);

        let addr = format_socks_addr(item).into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);

        dst.reserve(
            var_size(REQUEST_ID)
                + var_size(addr_var)
                + var_size(padding_var)
                + addr.len()
                + padding.len(),
        );

        REQUEST_ID.encode(dst);
        addr_var.encode(dst);
        dst.put_slice(&addr);
        padding_var.encode(dst);
        dst.put_slice(&padding);

        Ok(())
    }
}

fn format_socks_addr(addr: &SocksAddr) -> String {
    match addr {
        SocksAddr::Ip(socket_addr) => socket_addr.to_string(),
        SocksAddr::Domain(domain, port) => format!("{domain}:{port}"),
    }
}

fn var_size(var: VarInt) -> usize {
    let value = var.into_inner();
    if value < 2u64.pow(6) {
        1
    } else if value < 2u64.pow(14) {
        2
    } else if value < 2u64.pow(30) {
        4
    } else if value < 2u64.pow(62) {
        8
    } else {
        unreachable!("invalid varint range")
    }
}
