use std::{io::ErrorKind, str::FromStr};

use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
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

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
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

        let msg =
            String::from_utf8(tmp.split_to(msg_len).to_vec()).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid utf-8: {e}"),
                )
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

    fn encode(
        &mut self,
        item: &'_ SocksAddr,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
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

#[allow(unused)]
#[derive(Clone)]
pub struct HysUdpPacket {
    pub session_id: u32,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: SocksAddr,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for HysUdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysUdpPacket")
            .field("session_id", &format_args!("{:#010x}", self.session_id))
            .field("pkt_id", &self.pkt_id)
            .field("frag_id", &self.frag_id)
            .field("frag_count", &self.frag_count)
            .field("addr", &self.addr)
            .field("data_size", &self.data.len())
            .finish()
    }
}

impl HysUdpPacket {
    pub fn decode(buf: &mut BytesMut) -> anyhow::Result<Self> {
        if buf.len() < 8 {
            return Err(anyhow!("packet too short"));
        }

        let session_id = buf.get_u32();
        let pkt_id = buf.get_u16();
        let frag_id = buf.get_u8();
        let frag_count = buf.get_u8();
        let addr_len =
            VarInt::decode(buf).map_err(|_| anyhow!("invalid address length"))?;
        let addr_len = addr_len.into_inner() as usize;
        let addr: Vec<u8> = buf.split_to(addr_len).into();
        let data = buf.split().to_vec();

        Ok(Self {
            session_id,
            pkt_id,
            frag_id,
            frag_count,
            addr: to_socksaddr(&addr)?,
            data,
        })
    }
}

fn to_socksaddr(bytes: &[u8]) -> std::io::Result<SocksAddr> {
    let addr_str = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid UTF-8 in address",
        )
    })?;

    let (host, port_str) = addr_str.rsplit_once(':').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "address must be in host:port format",
        )
    })?;

    let port = port_str.parse::<u16>().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid port number")
    })?;

    if let Ok(sock_addr) = std::net::SocketAddr::from_str(addr_str) {
        Ok(SocksAddr::Ip(sock_addr))
    } else {
        Ok(SocksAddr::Domain(host.to_owned(), port))
    }
}

#[derive(Debug)]
pub struct Fragments<'a, P> {
    session_id: u32,
    pkt_id: u16,
    addr: (Vec<u8>, VarInt),
    frag_total: u8,
    next_frag_id: u8,
    next_frag_start: usize,
    payload: P,
    max_pkt_size: usize,
    fixed_size: usize,
    _marker: std::marker::PhantomData<&'a P>,
}

impl<'a, P> Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    pub fn new(
        session_id: u32,
        pkt_id: u16,
        addr: SocksAddr,
        max_pkt_size: usize,
        payload: P,
    ) -> Self {
        let addr = addr.to_string().into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);
        let fixed_size = 4 + 2 + 1 + 1 + addr.len() + var_size(addr_var);
        let max_data_size = max_pkt_size - fixed_size;
        let frag_total = payload.as_ref().len().div_ceil(max_data_size) as u8;

        Self {
            session_id,
            pkt_id,
            addr: (addr, addr_var),
            frag_total,
            next_frag_id: 0,
            next_frag_start: 0,
            payload,
            max_pkt_size,
            fixed_size,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, P> Iterator for Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_frag_id >= self.frag_total {
            return None;
        }

        let max_payload_size = self.max_pkt_size - self.fixed_size;
        let next_frag_end = (self.next_frag_start + max_payload_size)
            .min(self.payload.as_ref().len());
        let payload = &self.payload.as_ref()[self.next_frag_start..next_frag_end];

        let mut buf = BytesMut::new();
        buf.reserve(self.fixed_size + payload.len());
        buf.put_u32(self.session_id);
        buf.put_u16(self.pkt_id);
        buf.put_u8(self.next_frag_id);
        buf.put_u8(self.frag_total);
        self.addr.1.encode(&mut buf);
        buf.put_slice(self.addr.0.as_slice());
        buf.put_slice(payload);

        self.next_frag_id += 1;
        self.next_frag_start = next_frag_end;

        Some(buf.freeze())
    }
}

impl<P> ExactSizeIterator for Fragments<'_, P>
where
    P: AsRef<[u8]>,
{
    fn len(&self) -> usize {
        self.frag_total as usize
    }
}

#[derive(Default)]
pub struct Defragger {
    pub pkt_id: u16,
    pub frags: Vec<Option<HysUdpPacket>>,
    pub cnt: u16,
}

impl Defragger {
    pub fn feed(&mut self, pkt: HysUdpPacket) -> Option<HysUdpPacket> {
        if pkt.frag_count == 1 {
            return Some(pkt);
        }

        if pkt.frag_count <= pkt.frag_id {
            tracing::warn!(
                "invalid hysteria2 fragment, id={}, count={}",
                pkt.frag_id,
                pkt.frag_count
            );
            return None;
        }

        let frag_id = pkt.frag_id as usize;
        if pkt.pkt_id != self.pkt_id || pkt.frag_count as usize != self.frags.len() {
            self.pkt_id = pkt.pkt_id;
            self.frags.clear();
            self.frags.resize_with(pkt.frag_count as usize, || None);
            self.cnt = 0;
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
            return None;
        }

        if frag_id >= self.frags.len() || self.frags[frag_id].is_some() {
            return None;
        }

        self.frags[frag_id] = Some(pkt);
        self.cnt += 1;
        if self.cnt as usize != self.frags.len() {
            return None;
        }

        let mut frags = std::mem::take(&mut self.frags);
        let mut first = frags[0].take()?;
        for frag in frags.into_iter().skip(1).flatten() {
            first.data.extend(frag.data);
        }
        self.cnt = 0;
        Some(first)
    }
}
