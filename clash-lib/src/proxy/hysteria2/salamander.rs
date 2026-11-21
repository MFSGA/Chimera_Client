use std::{
    io::{self, IoSliceMut},
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
        Ok(Self::with_inner(inner, key))
    }

    pub(crate) fn with_inner(inner: Arc<dyn AsyncUdpSocket>, key: Vec<u8>) -> Self {
        Self {
            inner,
            obfs: SalamanderObfs::new(key),
        }
    }
}

impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(
        self: Arc<Self>,
    ) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
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

        if packet_count > bufs.len().min(meta.len()) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP socket returned too many receive buffers",
            )));
        }

        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(packet_count) {
            let len = meta.len;
            let stride = meta.stride;
            if len > buf.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP socket returned a packet larger than its buffer",
                )));
            }
            if len <= 8 || stride <= 8 {
                // Count the received datagram for Quinn's work limiter while
                // keeping its empty payload out of the QUIC parser.
                meta.len = 0;
                meta.stride = 1;
                continue;
            }

            let mut read_offset = 0;
            let mut write_offset = 0;
            while read_offset < len {
                let segment_len = stride.min(len - read_offset);
                if segment_len <= 8 {
                    break;
                }
                let end = read_offset + segment_len;
                self.obfs.decrypt(&mut buf[read_offset..end]);
                buf.copy_within(read_offset + 8..end, write_offset);
                write_offset += segment_len - 8;
                read_offset = end;
            }
            meta.len = write_offset;
            meta.stride = stride - 8;
        }

        Poll::Ready(Ok(packet_count))
    }

    fn max_receive_segments(&self) -> usize {
        // Quinn 0.11 sizes each receive buffer as its configured maximum UDP
        // payload (at least 1200 bytes) times this value. Preserve the inner
        // socket's GRO capacity and reserve 8 bytes per segment for the salt.
        // A conservative upper bound avoids changing QUIC's advertised MTU.
        let segments = self.inner.max_receive_segments();
        segments.saturating_add(segments.div_ceil(150))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        net::SocketAddr,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use futures::task::noop_waker;
    use quinn::{AsyncUdpSocket, UdpPoller, udp::RecvMeta};

    use super::*;

    #[derive(Debug)]
    struct PacketSocket {
        packets: Mutex<VecDeque<(Vec<u8>, usize)>>,
        max_segments: usize,
    }

    #[derive(Debug)]
    struct ReadyPoller;

    #[derive(Debug)]
    struct CaptureSocket {
        inner: Arc<dyn AsyncUdpSocket>,
        capacity: Mutex<Option<tokio::sync::oneshot::Sender<usize>>>,
        received: Arc<Mutex<Vec<(usize, usize)>>>,
    }

    impl AsyncUdpSocket for CaptureSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.inner.clone().create_io_poller()
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            self.inner.try_send(transmit)
        }

        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            if let Some(sender) = self.capacity.lock().unwrap().take() {
                let _ = sender.send(bufs[0].len());
            }
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => {
                    self.received.lock().unwrap().extend(
                        meta.iter().take(count).map(|item| (item.len, item.stride)),
                    );
                    Poll::Ready(Ok(count))
                }
                result => result,
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn max_receive_segments(&self) -> usize {
            self.inner.max_receive_segments()
        }
    }

    impl UdpPoller for ReadyPoller {
        fn poll_writable(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncUdpSocket for PacketSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(ReadyPoller)
        }

        fn try_send(&self, _transmit: &Transmit<'_>) -> io::Result<()> {
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let mut count = 0;
            let mut packets = self.packets.lock().unwrap();
            for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()) {
                let Some((packet, stride)) = packets.pop_front() else {
                    break;
                };
                if packet.len() > buf.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "packet exceeds receive buffer",
                    )));
                }
                buf[..packet.len()].copy_from_slice(&packet);
                *meta = RecvMeta {
                    len: packet.len(),
                    stride,
                    ..RecvMeta::default()
                };
                count += 1;
            }
            if count == 0 {
                Poll::Pending
            } else {
                Poll::Ready(Ok(count))
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(([127, 0, 0, 1], 0).into())
        }

        fn max_receive_segments(&self) -> usize {
            self.max_segments
        }
    }

    fn encrypted(obfs: &SalamanderObfs, payload: &[u8]) -> Vec<u8> {
        obfs.encrypt(&mut payload.to_vec()).to_vec()
    }

    fn receiver(packets: Vec<(Vec<u8>, usize)>, max_segments: usize) -> Salamander {
        Salamander::with_inner(
            Arc::new(PacketSocket {
                packets: Mutex::new(packets.into()),
                max_segments,
            }),
            b"test-password".to_vec(),
        )
    }

    #[test]
    fn receive_reuses_full_buffer_for_larger_next_packet() {
        let obfs = SalamanderObfs::new(b"test-password".to_vec());
        let first = encrypted(&obfs, b"first");
        let second = encrypted(&obfs, b"a longer second datagram");
        let socket = receiver(
            vec![(first.clone(), first.len()), (second.clone(), second.len())],
            1,
        );
        let mut storage = [0u8; 128];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            socket.poll_recv(&mut cx, &mut bufs, &mut meta),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(&bufs[0][..meta[0].len], b"first");
        assert!(matches!(
            socket.poll_recv(&mut cx, &mut bufs, &mut meta),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(&bufs[0][..meta[0].len], b"a longer second datagram");
        assert_eq!(bufs[0].len(), 128);
    }

    #[test]
    fn receive_decrypts_each_gro_segment_and_preserves_stride() {
        let obfs = SalamanderObfs::new(b"test-password".to_vec());
        let first = encrypted(&obfs, b"packet-1");
        let second = encrypted(&obfs, b"packet-2");
        let last = encrypted(&obfs, b"end");
        let stride = first.len();
        let mut merged = first;
        merged.extend_from_slice(&second);
        merged.extend_from_slice(&last);
        let socket = receiver(vec![(merged, stride)], 64);
        let mut storage = [0u8; 128];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            socket.poll_recv(&mut cx, &mut bufs, &mut meta),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(meta[0].stride, b"packet-1".len());
        assert_eq!(&bufs[0][..meta[0].len], b"packet-1packet-2end");
        assert_eq!(bufs[0].len(), 128);
        assert_eq!(socket.max_receive_segments(), 65);
    }

    #[test]
    fn receive_ignores_short_datagrams_without_shrinking_buffer() {
        let socket = receiver(vec![(vec![0u8; 8], 8)], 1);
        let mut storage = [0u8; 128];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            socket.poll_recv(&mut cx, &mut bufs, &mut meta),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(meta[0].len, 0);
        assert_eq!(bufs[0].len(), 128);
    }

    #[test]
    fn receive_buffer_has_space_for_every_gro_salt() {
        // Quinn sizes each receive buffer as max_udp_payload_size times the
        // socket's advertised maximum number of receive segments.
        let obfs = SalamanderObfs::new(b"test-password".to_vec());
        let payload = vec![0x5a; 1472];
        let mut merged = Vec::new();
        for _ in 0..64 {
            merged.extend_from_slice(&encrypted(&obfs, &payload));
        }
        let socket = receiver(vec![(merged, payload.len() + 8)], 64);
        let mut storage = vec![0u8; payload.len() * socket.max_receive_segments()];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            socket.poll_recv(&mut cx, &mut bufs, &mut meta),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(meta[0].stride, payload.len());
        assert_eq!(meta[0].len, payload.len() * 64);
        assert!(bufs[0][..meta[0].len].iter().all(|&byte| byte == 0x5a));
    }

    #[test]
    fn receive_batch_drops_short_gro_tail_and_keeps_other_packets() {
        let obfs = SalamanderObfs::new(b"test-password".to_vec());
        let mut merged = encrypted(&obfs, b"packet-1");
        let stride = merged.len();
        merged.extend_from_slice(&encrypted(&obfs, b"packet-2"));
        merged.extend_from_slice(&[0u8; 8]);
        let next = encrypted(&obfs, b"another datagram");
        let socket =
            receiver(vec![(merged, stride), (next.clone(), next.len())], 64);
        let mut first = [0u8; 128];
        let mut second = [0u8; 128];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let mut meta = [RecvMeta::default(); 2];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            socket.poll_recv(&mut cx, &mut bufs, &mut meta),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(meta[0].stride, b"packet-1".len());
        assert_eq!(&bufs[0][..meta[0].len], b"packet-1packet-2");
        assert_eq!(&bufs[1][..meta[1].len], b"another datagram");
    }

    #[tokio::test]
    async fn quinn_allocates_receive_headroom_for_salamander() {
        for (segments, max_payload) in [
            (1, 1200),
            (64, 1200),
            (150, 1200),
            (151, 1200),
            (1, 1472),
            (64, 1472),
        ] {
            let socket = Arc::new(receiver(Vec::new(), segments));
            let (tx, rx) = tokio::sync::oneshot::channel();
            let capture = Arc::new(CaptureSocket {
                inner: socket,
                capacity: Mutex::new(Some(tx)),
                received: Arc::default(),
            });
            let mut config = quinn::EndpointConfig::default();
            config.max_udp_payload_size(max_payload).unwrap();
            let endpoint = quinn::Endpoint::new_with_abstract_socket(
                config,
                None,
                capture,
                Arc::new(TokioRuntime),
            )
            .unwrap();
            let capacity =
                tokio::time::timeout(std::time::Duration::from_secs(2), rx)
                    .await
                    .expect("Quinn did not poll its UDP socket")
                    .expect("capture socket did not report its receive capacity");
            assert!(capacity >= (usize::from(max_payload) + 8) * segments);
            drop(endpoint);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux UDP GSO and GRO on loopback"]
    async fn native_socket_decrypts_real_gro_segments() {
        use quinn::Runtime;

        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let inner = TokioRuntime.wrap_udp_socket(receiver).unwrap();
        assert!(inner.max_receive_segments() >= 4, "UDP GRO is unavailable");
        let received = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::new(CaptureSocket {
            inner,
            capacity: Mutex::new(None),
            received: received.clone(),
        });
        let socket = Salamander::with_inner(capture, b"test-password".to_vec());

        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.set_nonblocking(true).unwrap();
        let sender = TokioRuntime.wrap_udp_socket(sender).unwrap();
        assert!(
            sender.max_transmit_segments() >= 4,
            "UDP GSO is unavailable"
        );
        let obfs = SalamanderObfs::new(b"test-password".to_vec());
        let mut encrypted_segments = Vec::new();
        let mut expected = Vec::new();
        for byte in 1..=4 {
            let payload = vec![byte; 1200];
            encrypted_segments.extend_from_slice(&encrypted(&obfs, &payload));
            expected.extend_from_slice(&payload);
        }
        let transmit = Transmit {
            destination: receiver_addr,
            ecn: None,
            contents: &encrypted_segments,
            segment_size: Some(1208),
            src_ip: None,
        };
        let mut poller = sender.clone().create_io_poller();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                    .await
                    .unwrap();
                match sender.try_send(&transmit) {
                    Ok(()) => break,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => panic!("UDP GSO send failed: {err}"),
                }
            }
        })
        .await
        .expect("native UDP send timed out");
        let mut storage = vec![0u8; 1472 * socket.max_receive_segments()];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("native UDP receive timed out")
        .expect("native UDP receive failed");
        assert_eq!(count, 1);
        assert_eq!(&*received.lock().unwrap(), &[(1208 * 4, 1208)]);
        assert_eq!(meta[0].stride, 1200);
        assert_eq!(&bufs[0][..meta[0].len], expected);
    }

    #[tokio::test]
    async fn connector_adapter_receives_consecutive_salamander_packets() {
        use crate::{
            app::dns::MockClashResolver,
            proxy::{
                AnyOutboundDatagram, direct::datagram::OutboundDatagramImpl,
                transport::ConnectorUdpSocket,
            },
        };

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = udp.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let datagram: AnyOutboundDatagram = Box::new(OutboundDatagramImpl::new(
            udp,
            Arc::new(MockClashResolver::new()),
        ));
        let socket = Salamander::with_inner(
            ConnectorUdpSocket::new(datagram, peer_addr),
            b"test-password".to_vec(),
        );
        let obfs = SalamanderObfs::new(b"test-password".to_vec());
        let first = encrypted(&obfs, b"first");
        let second = encrypted(&obfs, b"a longer second datagram");
        let mut storage = [0u8; 128];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];

        for (packet, expected) in [
            (first, &b"first"[..]),
            (second, &b"a longer second datagram"[..]),
        ] {
            peer.send_to(&packet, local_addr).await.unwrap();
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                std::future::poll_fn(|cx| {
                    socket.poll_recv(cx, &mut bufs, &mut meta)
                }),
            )
            .await
            .expect("Salamander receive timed out")
            .expect("Salamander receive failed");
            assert_eq!(received, 1);
            assert_eq!(&bufs[0][..meta[0].len], expected);
            assert_eq!(bufs[0].len(), 128);
        }
    }

    #[tokio::test]
    async fn connector_adapter_receives_full_sized_salamander_packet() {
        use crate::{
            app::dns::MockClashResolver,
            proxy::{
                AnyOutboundDatagram, direct::datagram::OutboundDatagramImpl,
                transport::ConnectorUdpSocket,
            },
        };

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = udp.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let datagram: AnyOutboundDatagram = Box::new(OutboundDatagramImpl::new(
            udp,
            Arc::new(MockClashResolver::new()),
        ));
        let socket = Salamander::with_inner(
            ConnectorUdpSocket::new(datagram, peer.local_addr().unwrap()),
            b"test-password".to_vec(),
        );
        let obfs = SalamanderObfs::new(b"test-password".to_vec());
        let payload = vec![0x5a; 1472];
        let packet = encrypted(&obfs, &payload);
        let mut storage = vec![0u8; payload.len() * socket.max_receive_segments()];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];

        peer.send_to(&packet, local_addr).await.unwrap();
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("Salamander receive timed out")
        .expect("Salamander receive failed");
        assert_eq!(received, 1);
        assert_eq!(&bufs[0][..meta[0].len], payload);
    }
}
