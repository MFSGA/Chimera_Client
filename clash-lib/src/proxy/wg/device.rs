use bytes::{Bytes, BytesMut};
use smoltcp::phy::Device;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{Instrument, error, trace_span};

use super::events::PortProtocol;

pub struct VirtualIpDevice {
    mtu: usize,

    packet_sender: Sender<Bytes>,
    packet_receiver: Receiver<(PortProtocol, Bytes)>,
}

impl VirtualIpDevice {
    pub fn new(
        // send packet to wg stack
        packet_sender: Sender<Bytes>,
        // when wg stack receives a packet, it will send it to this receiver
        mut packet_receiver: Receiver<(PortProtocol, Bytes)>,

        // when wg stack receives a packet, it will send a notification to this
        // sender
        packet_notifier: Sender<()>,
        mtu: usize,
    ) -> Self {
        let (inner_packet_sender, inner_packet_receiver) =
            tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move {
            loop {
                let span = trace_span!("receive_packet");

                match packet_receiver.recv().instrument(span).await {
                    Some((proto, data)) => {
                        inner_packet_sender.send((proto, data)).await.unwrap();
                        let _ = packet_notifier.try_send(());
                    }
                    _ => {
                        break;
                    }
                }
            }
        });

        Self {
            mtu,
            packet_sender,
            packet_receiver: inner_packet_receiver,
        }
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let next = self.packet_receiver.try_recv().ok();
        match next {
            Some((_proto, data)) => {
                // Convert to mutable buffer for potential checksum fix
                let mut buffer = BytesMut::from(&data[..]);

                // Fix UDP checksum if needed
                // Some environments (NAT, checksum offload, virtualization) may
                // corrupt the checksum We recalculate it here since
                // WireGuard AEAD already guarantees data integrity
                // Note: An alternative approach is to skip RX checksum
                // verification by setting `caps.checksum.udp =
                // smoltcp::phy::Checksum::Tx` in capabilities(), but
                // recalculating feels cleaner than disabling verification
                // entirely
                use smoltcp::wire::*;
                if let Ok(IpVersion::Ipv4) = IpVersion::of_packet(&buffer)
                    && let Ok(ipv4) = Ipv4Packet::new_checked(&buffer[..])
                    && ipv4.next_header() == IpProtocol::Udp
                {
                    let src_addr = ipv4.src_addr();
                    let dst_addr = ipv4.dst_addr();
                    let ip_header_len = ipv4.header_len() as usize;

                    // Recalculate UDP checksum
                    if let Ok(mut udp) =
                        UdpPacket::new_checked(&mut buffer[ip_header_len..])
                    {
                        udp.fill_checksum(
                            &IpAddress::Ipv4(src_addr),
                            &IpAddress::Ipv4(dst_addr),
                        );
                    }
                }

                let rx_token = RxToken { buffer };
                let tx_token = TxToken {
                    sender: self.packet_sender.clone(),
                };
                Some((rx_token, tx_token))
            }
            None => None,
        }
    }

    fn transmit(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            sender: self.packet_sender.clone(),
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct RxToken {
    buffer: BytesMut,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct TxToken {
    sender: Sender<Bytes>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        match self.sender.try_send(buffer.into()) {
            Ok(_) => {}
            Err(err) => {
                error!("failed to send packet: {}", err);
            }
        }
        result
    }
}
