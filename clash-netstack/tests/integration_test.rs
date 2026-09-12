use futures::{SinkExt, StreamExt};
use watfaq_netstack::{NetStack, Packet, UdpSocket};

mod common;
mod mock_tun;

use common::{
    build_tcp_ack, build_tcp_syn_packet, build_tcp_syn_packet_with_port,
    build_udp_packet, init, is_rst, is_syn_ack, parse_server_isn, parse_tcp_data,
    tcp_dst_port,
};
use mock_tun::MockTun;

fn build_ipv4_udp_fragments(payload: &[u8]) -> [Vec<u8>; 2] {
    let source = [1, 1, 1, 1];
    let destination = [2, 2, 2, 2];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv4(source, destination, 64)
        .udp(5000, 5001)
        .write(&mut full, payload)
        .unwrap();
    let udp = &full[20..];
    let split = 16;

    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let mut header = etherparse::Ipv4Header::new(
            part.len() as u16,
            64,
            etherparse::ip_number::UDP,
            source,
            destination,
        )
        .unwrap();
        header.identification = 0x4242;
        header.dont_fragment = false;
        header.more_fragments = more_fragments;
        header.fragment_offset =
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap();
        header.header_checksum = header.calc_header_checksum();

        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(part);
        packet
    };

    [
        build(&udp[..split], 0, true),
        build(&udp[split..], split, false),
    ]
}

fn build_ipv6_udp_fragments(payload: &[u8]) -> [Vec<u8>; 2] {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .udp(5000, 5001)
        .write(&mut full, payload)
        .unwrap();
    let udp = &full[40..];
    let split = 16;

    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let header = etherparse::Ipv6Header {
            payload_length: (etherparse::Ipv6FragmentHeader::LEN + part.len())
                as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source,
            destination,
            ..Default::default()
        };
        let fragment = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::UDP,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more_fragments,
            0x1122_3344,
        );

        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(&fragment.to_bytes());
        packet.extend_from_slice(part);
        packet
    };

    [
        build(&udp[..split], 0, true),
        build(&udp[split..], split, false),
    ]
}

#[tokio::test]
async fn test_stack_with_mock_tun_real_tcp_udp() {
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from mock_tun to stack_sink (TUN -> NetStack)
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            let packet = Packet::new(pkt);
            stack_sink.send(packet).await.unwrap();
        }
    });

    // Send a TCP SYN packet
    let tcp_syn = build_tcp_syn_packet();
    tun_in.send(tcp_syn.clone()).unwrap();

    log::info!("Sent TCP SYN and UDP packets to mock TUN");

    let Some(Ok(reply)) = stack_stream.next().await else {
        panic!("No packets received from stack");
    };

    assert!(is_syn_ack(reply.data()));
    log::info!("Received TCP SYN-ACK packet from stack");

    let stream = tcp_listener.next().await.unwrap();
    log::info!("Accepted TCP stream: {:?}", stream);
    assert_eq!(stream.local_addr(), "1.1.1.1:1024".parse().unwrap());
    assert_eq!(stream.remote_addr(), "2.2.2.2:80".parse().unwrap());

    // Send a UDP packet
    let udp_pkt = build_udp_packet();
    tun_in.send(udp_pkt.clone()).unwrap();

    log::info!("Sent UDP packet to mock TUN");
    let (mut udp_read, _) = udp_socket.split();
    let Some(udp_packet) = udp_read.recv().await else {
        panic!("No UDP packet received");
    };
    assert_eq!(udp_packet.local_addr, "1.1.1.1:5000".parse().unwrap());
    assert_eq!(udp_packet.remote_addr, "2.2.2.2:5001".parse().unwrap());
}

/// Verifies that a relay can sustain a 16 MB bulk TCP transfer through the
/// netstack without stalling. A relay task writes into the netstack TcpStream
/// while a simulated client reads segments from StackSplitStream and sends
/// cumulative ACKs back. The test fails if throughput stalls for more than
/// 5 seconds or the whole transfer exceeds 30 s.
///
/// This catches the regression where poll_sockets runs in a tight loop and
/// starves StackSplitStream, blocking the consumer from draining the tx channel
/// and sending ACKs, which fills smoltcp's send window and triggers RTO.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_speedtest_bulk_download() {
    init();

    const TRANSFER_BYTES: usize = 16 * 1024 * 1024; // 16 MB

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from the mock TUN into the netstack.
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            stack_sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    // Client simulation task: performs the TCP handshake, reads data segments
    // from StackSplitStream, and sends cumulative ACKs back through the mock TUN.
    // Spawned before awaiting tcp_listener so its SYN is in-flight while we wait.
    let client = tokio::spawn(async move {
        tun_in.send(build_tcp_syn_packet()).unwrap();

        let server_isn = loop {
            let pkt = stack_stream
                .next()
                .await
                .expect("stack_stream closed")
                .expect("stack_stream error");
            if is_syn_ack(pkt.data()) {
                break parse_server_isn(pkt.data());
            }
        };

        // SYN consumed client seq=0, so client_seq after handshake = 1.
        let client_seq: u32 = 1;
        // cumulative_ack tracks the highest contiguous byte acknowledged from
        // the server, starting just past the SYN-ACK's sequence number.
        let mut cumulative_ack = server_isn.wrapping_add(1);
        tun_in
            .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
            .unwrap();

        // Receive bulk data and ACK each segment.
        let mut received = 0usize;
        let start = std::time::Instant::now();
        let mut last_check = start;
        let mut bytes_since_check = 0usize;

        while received < TRANSFER_BYTES {
            let pkt = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stack_stream.next(),
            )
            .await
            .expect("STALL: no TCP segment received for 5 s")
            .expect("stack_stream closed")
            .expect("stack_stream error");

            if let Some((seq, payload_len)) = parse_tcp_data(pkt.data()) {
                if payload_len > 0 {
                    let end_seq = seq.wrapping_add(payload_len as u32);
                    let advance = end_seq.wrapping_sub(cumulative_ack);
                    if advance > 0 && advance < (1u32 << 31) {
                        received += advance as usize;
                        bytes_since_check += advance as usize;
                        cumulative_ack = end_seq;
                    }
                    tun_in
                        .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
                        .unwrap();
                }
            } else {
                let _ = pkt;
            }

            let now = std::time::Instant::now();
            if now.duration_since(last_check) >= std::time::Duration::from_secs(1) {
                let mb = bytes_since_check as f64 / (1024.0 * 1024.0);
                eprintln!(
                    "[bulk] {:.1} MB/s  ({}/{} KB)",
                    mb,
                    received / 1024,
                    TRANSFER_BYTES / 1024,
                );
                bytes_since_check = 0;
                last_check = now;
            }
        }

        let elapsed = start.elapsed();
        let throughput = received as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!(
            "[bulk] done: {} KB in {:.2}s = {:.1} MB/s",
            received / 1024,
            elapsed.as_secs_f64(),
            throughput,
        );
        received
    });

    // Await the TcpStream here, not inside the relay task. This keeps
    // tcp_listener alive until after join!() completes, preventing
    // TcpListener::Drop from aborting the netstack task while data is in-flight.
    let stream = tcp_listener.next().await.expect("no TcpStream");

    // Relay task: writes TRANSFER_BYTES into the TcpStream.
    let relay = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;

        let mut stream = stream;
        let chunk = vec![0xABu8; 16 * 1024]; // 16 KB chunks
        let mut written = 0usize;
        while written < TRANSFER_BYTES {
            let n = (TRANSFER_BYTES - written).min(chunk.len());
            stream
                .write_all(&chunk[..n])
                .await
                .expect("write_all failed");
            written += n;
        }
        written
    });

    let (relay_res, client_res) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::join!(relay, client)
        })
        .await
        .expect("Test timed out (30 s) - likely a stall in the netstack");

    // tcp_listener is dropped here, after relay and client both complete.
    drop(tcp_listener);

    assert_eq!(relay_res.unwrap(), TRANSFER_BYTES);
    assert_eq!(client_res.unwrap(), TRANSFER_BYTES);
}

/// Verifies that a new TCP connection gets a SYN-ACK (not RST) while another
/// connection is actively bulk-transferring data.
///
/// Bug B root cause: poll_sockets only drained notifier_rx in the else branch,
/// which was skipped whenever should_poll_now = true. During an active
/// download, poll_delay near zero keeps should_poll_now = true permanently, so
/// new IfaceEvent::TcpStream events were never consumed before iface.poll() ran.
/// smoltcp saw the incoming SYN with no matching socket and replied with RST.
///
/// Fix: drain notifier_rx with try_recv() before every iface.poll() call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_new_connection_during_active_transfer() {
    init();

    use tokio::sync::mpsc;

    const CONN1_BYTES: usize = 4 * 1024 * 1024; // 4 MB keeps smoltcp in hot path.

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward mock TUN packets into the netstack.
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            stack_sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    // Per-connection demultiplexer: routes outbound smoltcp packets to each
    // simulated client by TCP destination port (= client's source port).
    let (tx1, mut rx1) = mpsc::unbounded_channel::<Packet>();
    let (tx2, mut rx2) = mpsc::unbounded_channel::<Packet>();
    tokio::spawn(async move {
        while let Some(Ok(pkt)) = stack_stream.next().await {
            match tcp_dst_port(pkt.data()) {
                Some(1024) => {
                    let _ = tx1.send(pkt);
                }
                Some(1025) => {
                    let _ = tx2.send(pkt);
                }
                _ => {}
            }
        }
    });

    // Oneshot: conn1 client signals conn2 client once data is flowing.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let tun_in2 = tun_in.clone();

    // Client 1 (port 1024): handshake + receive CONN1_BYTES, ACKing each segment.
    let client1 = tokio::spawn(async move {
        tun_in.send(build_tcp_syn_packet()).unwrap();

        let server_isn = loop {
            let pkt = rx1.recv().await.expect("rx1 closed before SYN-ACK");
            if is_syn_ack(pkt.data()) {
                break parse_server_isn(pkt.data());
            }
        };
        let client_seq: u32 = 1;
        let mut cumulative_ack = server_isn.wrapping_add(1);
        tun_in
            .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
            .unwrap();

        let mut received = 0usize;
        let mut signalled = false;
        let mut ready_tx = Some(ready_tx);

        while received < CONN1_BYTES {
            let pkt =
                tokio::time::timeout(std::time::Duration::from_secs(5), rx1.recv())
                    .await
                    .expect("conn1 stalled for 5 s")
                    .expect("rx1 closed");

            if let Some((seq, payload_len)) = parse_tcp_data(pkt.data())
                && payload_len > 0
            {
                let end_seq = seq.wrapping_add(payload_len as u32);
                let advance = end_seq.wrapping_sub(cumulative_ack);
                if advance > 0 && advance < (1u32 << 31) {
                    received += advance as usize;
                    cumulative_ack = end_seq;
                }
                tun_in
                    .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
                    .unwrap();
                // Signal conn2 client on the first received data segment.
                if !signalled {
                    signalled = true;
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
            }
        }
        received
    });

    // Client 2 (port 1025): waits until conn1 is actively transferring, then
    // sends a SYN and asserts it receives a SYN-ACK, not RST or timeout.
    let client2 = tokio::spawn(async move {
        ready_rx
            .await
            .expect("ready signal lost - conn1 relay never started");

        tun_in2.send(build_tcp_syn_packet_with_port(1025)).unwrap();

        // Expect SYN-ACK within 5 s. Without the drain-loop fix smoltcp
        // responds with RST or the packet is silently dropped.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let pkt = rx2.recv().await.expect("rx2 closed before SYN-ACK");
                if is_syn_ack(pkt.data()) {
                    return;
                }
                if is_rst(pkt.data()) {
                    panic!(
                        "connection 2 received RST - Bug B not fixed (drain \
                         notifier_rx before iface.poll() is missing)"
                    );
                }
            }
        })
        .await
        .expect("timed out waiting for SYN-ACK on connection 2 - Bug B not fixed");
    });

    // Accept conn1.
    let stream1 = tcp_listener.next().await.expect("no stream for conn1");

    // Relay 1: write CONN1_BYTES so smoltcp stays in the hot path long enough
    // for conn2's SYN to arrive.
    let relay1 = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;

        let mut stream = stream1;
        let chunk = vec![0u8; 16 * 1024];
        let mut written = 0usize;
        while written < CONN1_BYTES {
            let n = (CONN1_BYTES - written).min(chunk.len());
            stream
                .write_all(&chunk[..n])
                .await
                .expect("relay1 write failed");
            written += n;
        }
        written
    });

    // Accept conn2.
    let stream2 = tcp_listener.next().await.expect("no stream for conn2");
    drop(stream2);

    let (relay1_res, client1_res, client2_res) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::join!(relay1, client1, client2)
        })
        .await
        .expect("test timed out (30 s)");

    drop(tcp_listener);

    assert_eq!(relay1_res.unwrap(), CONN1_BYTES, "relay1 bytes mismatch");
    assert_eq!(client1_res.unwrap(), CONN1_BYTES, "client1 bytes mismatch");
    client2_res.unwrap(); // panics if client2 saw RST or timed out
}

#[tokio::test]
async fn malformed_udp_does_not_end_receive_stream() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    let mut malformed = build_udp_packet().to_vec();
    malformed[24..26].copy_from_slice(&7_u16.to_be_bytes());
    stack_sink.send(Packet::new(malformed)).await.unwrap();
    stack_sink
        .send(Packet::new(build_udp_packet()))
        .await
        .unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("valid UDP packet was not delivered after malformed input")
            .expect("UDP receive stream ended after malformed input");

    assert_eq!(packet.local_addr, "1.1.1.1:5000".parse().unwrap());
    assert_eq!(packet.remote_addr, "2.2.2.2:5001".parse().unwrap());
}

#[tokio::test]
async fn zero_length_udp_is_emitted() {
    let (_input_tx, input_rx) = tokio::sync::mpsc::channel(8);
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(1);
    let (_reader, mut writer) = UdpSocket::new(input_rx, output_tx).split();

    writer
        .send(
            (
                Vec::<u8>::new(),
                "1.1.1.1:5000".parse().unwrap(),
                "2.2.2.2:5001".parse().unwrap(),
            )
                .into(),
        )
        .await
        .unwrap();

    let packet = output_rx
        .recv()
        .await
        .expect("zero-length UDP datagram was not emitted");
    assert_eq!(packet.data().len(), 28);
}

#[tokio::test]
async fn stack_sink_consecutive_feed_calls_make_progress() {
    let (stack, _tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();

    stack_sink
        .feed(Packet::new(build_udp_packet()))
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stack_sink.feed(Packet::new(build_udp_packet())),
    )
    .await
    .expect("second feed blocked without making progress")
    .unwrap();
    stack_sink.flush().await.unwrap();
}

#[tokio::test]
async fn stack_sink_backpressure_wakes_after_udp_queue_drains() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    for _ in 0..4096 {
        stack_sink
            .send(Packet::new(build_udp_packet()))
            .await
            .unwrap();
    }

    let blocked = stack_sink.send(Packet::new(build_udp_packet()));
    tokio::pin!(blocked);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut blocked)
            .await
            .is_err(),
        "bounded stack input queue did not apply backpressure"
    );

    udp_read.recv().await.expect("queued UDP packet missing");
    tokio::time::timeout(std::time::Duration::from_millis(300), blocked)
        .await
        .expect("stack sink was not woken after queue capacity became available")
        .unwrap();
}

#[tokio::test]
async fn stack_sink_reports_closed_udp_receiver() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    drop(udp_socket);

    let err = stack_sink
        .send(Packet::new(build_udp_packet()))
        .await
        .expect_err("closed UDP receiver must be reported to the sink");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn listener_drop_closes_existing_stream_io() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (stack, mut tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    stack_sink
        .send(Packet::new(build_tcp_syn_packet()))
        .await
        .unwrap();

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tcp_listener.next(),
    )
    .await
    .expect("TCP stream was not created")
    .expect("TCP listener ended unexpectedly");

    drop(tcp_listener);

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stream.read(&mut byte),
    )
    .await
    .expect("stream read remained pending after listener shutdown")
    .unwrap();
    assert_eq!(read, 0, "listener shutdown should surface EOF");

    let err = stream
        .write(b"x")
        .await
        .expect_err("write succeeded after TCP engine shutdown");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn invalid_tcp_checksum_does_not_create_stream() {
    let (stack, mut tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let mut packet = build_tcp_syn_packet().to_vec();
    packet[36] ^= 0xff;

    stack_sink.send(Packet::new(packet)).await.unwrap();

    let accepted = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tcp_listener.next(),
    )
    .await;
    assert!(
        accepted.is_err(),
        "invalid TCP checksum created an application stream"
    );
}

#[tokio::test]
async fn ipv6_hop_by_hop_udp_is_delivered() {
    let mut packet = Vec::new();
    etherparse::PacketBuilder::ipv6([0x20; 16], [0x21; 16], 64)
        .udp(1234, 4321)
        .write(&mut packet, b"test")
        .unwrap();
    packet[6] = 0;
    packet.splice(40..40, [17, 0, 0, 0, 0, 0, 0, 0]);
    let payload_len = (packet.len() - 40) as u16;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());

    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();
    stack_sink.send(Packet::new(packet)).await.unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("IPv6 UDP behind Hop-by-Hop header was not delivered")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.data(), b"test");
}

#[tokio::test]
async fn icmp_echo_reply_works_without_tcp_socket() {
    let mut packet = Vec::new();
    etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
        .icmpv4_echo_request(1, 1)
        .write(&mut packet, b"ping")
        .unwrap();

    let (stack, _tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();
    stack_sink.send(Packet::new(packet)).await.unwrap();

    let reply = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stack_stream.next(),
    )
    .await
    .expect("ICMP echo reply timed out")
    .expect("stack output ended unexpectedly")
    .expect("stack returned an error");
    let ihl = ((reply.data()[0] & 0x0f) as usize) * 4;
    assert_eq!(reply.data()[9], 1);
    assert_eq!(reply.data()[ihl], 0, "expected ICMP Echo Reply");
}

#[tokio::test]
async fn fragmented_ipv4_udp_reassembles_out_of_order() {
    let payload = b"fragmented-ipv4-udp-payload";
    let [first, second] = build_ipv4_udp_fragments(payload);
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    stack_sink.send(Packet::new(second)).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), udp_read.recv(),)
            .await
            .is_err(),
        "incomplete IPv4 fragments produced a UDP datagram"
    );

    stack_sink.send(Packet::new(first)).await.unwrap();
    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("reassembled IPv4 UDP datagram timed out")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.data(), payload);
}

#[tokio::test]
async fn fragmented_ipv6_udp_reassembles_out_of_order() {
    let payload = b"fragmented-ipv6-udp-payload";
    let [first, second] = build_ipv6_udp_fragments(payload);
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    stack_sink.send(Packet::new(second)).await.unwrap();
    stack_sink.send(Packet::new(first)).await.unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("reassembled IPv6 UDP datagram timed out")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.data(), payload);
}

#[tokio::test]
async fn invalid_udp_checksum_is_dropped_without_ending_stream() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();
    let mut invalid = build_udp_packet().to_vec();
    invalid[26] ^= 0xff;
    stack_sink.send(Packet::new(invalid)).await.unwrap();
    stack_sink
        .send(Packet::new(build_udp_packet()))
        .await
        .unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("valid UDP packet was not delivered after bad checksum")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.local_addr, "1.1.1.1:5000".parse().unwrap());
}
