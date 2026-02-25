use std::{
    io::IoSliceMut,
    ops::DerefMut,
    sync::Arc,
    task::{Context, Poll},
};

use blake2::{Blake2b, Digest};
use bytes::{BufMut, Bytes, BytesMut};
use digest::consts::U32;
use futures::ready;
use quinn::{
    AsyncUdpSocket, TokioRuntime,
    udp::{RecvMeta, Transmit},
};
use rand::RngExt;

type Blake2b256 = Blake2b<U32>;

struct SalamanderObfs {
    key: Vec<u8>,
}

impl SalamanderObfs {
    fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    fn xor_with_keystream(&self, salt: &[u8], data: &mut [u8]) {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.key);
        hasher.update(salt);
        let hash: [u8; 32] = hasher.finalize().into();

        for (idx, value) in data.iter_mut().enumerate() {
            *value ^= hash[idx % hash.len()];
        }
    }

    fn encrypt(&self, data: &mut [u8]) -> Bytes {
        let salt: [u8; 8] = rand::rng().random();

        let mut output = BytesMut::with_capacity(8 + data.len());
        output.put_slice(&salt);
        self.xor_with_keystream(&salt, data);
        output.put_slice(data);
        output.freeze()
    }

    fn decrypt(&self, data: &mut [u8]) {
        assert!(data.len() > 8, "salamander packet length should be > 8");
        let (salt, payload) = data.split_at_mut(8);
        self.xor_with_keystream(salt, payload);
    }
}

pub struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: SalamanderObfs,
}

impl Salamander {
    pub fn new(socket: std::net::UdpSocket, key: Vec<u8>) -> std::io::Result<Self> {
        use quinn::Runtime;
        let inner = TokioRuntime.wrap_udp_socket(socket)?;
        Ok(Self {
            inner,
            obfs: SalamanderObfs::new(key),
        })
    }
}

impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let mut transmit = transmit.to_owned();
        let encrypted = self.obfs.encrypt(&mut transmit.contents.to_vec());
        transmit.contents = &encrypted;
        self.inner.try_send(&transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let packet_count = ready!(self.inner.poll_recv(cx, bufs, meta))?;

        bufs.iter_mut()
            .zip(meta.iter_mut())
            .take(packet_count)
            .filter(|(_, meta)| meta.len > 8)
            .for_each(|(buf, meta)| {
                let packet = &mut buf.deref_mut()[..meta.len];
                self.obfs.decrypt(packet);
                let payload = &mut packet[8..];
                unsafe {
                    let slice: IoSliceMut<'_> = std::mem::transmute(payload);
                    *buf = slice;
                }
                meta.len -= 8;
            });

        Poll::Ready(Ok(packet_count))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
