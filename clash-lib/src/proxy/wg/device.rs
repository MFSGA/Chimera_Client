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
        packet_sender: Sender<Bytes>,
        mut packet_receiver: Receiver<(PortProtocol, Bytes)>,
        packet_notifier: Sender<()>,
        mtu: usize,
    ) -> Self {
        let (inner_packet_sender, inner_packet_receiver) =
            tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move {
            loop {
                let span = trace_span!("receive_packet");
                match packet_receiver.recv().instrument(span).await {
                    Some((protocol, data)) => {
                        if inner_packet_sender.send((protocol, data)).await.is_err()
                        {
                            break;
                        }
                        let _ = packet_notifier.try_send(());
                    }
                    None => break,
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
        let (_protocol, data) = self.packet_receiver.try_recv().ok()?;
        let mut buffer = BytesMut::from(&data[..]);

        use smoltcp::wire::*;
        if let Ok(IpVersion::Ipv4) = IpVersion::of_packet(&buffer)
            && let Ok(ipv4) = Ipv4Packet::new_checked(&buffer[..])
            && ipv4.next_header() == IpProtocol::Udp
        {
            let src_addr = ipv4.src_addr();
            let dst_addr = ipv4.dst_addr();
            let ip_header_len = ipv4.header_len() as usize;
            if let Ok(mut udp) = UdpPacket::new_checked(&mut buffer[ip_header_len..])
            {
                udp.fill_checksum(
                    &IpAddress::Ipv4(src_addr),
                    &IpAddress::Ipv4(dst_addr),
                );
            }
        }

        Some((
            RxToken { buffer },
            TxToken {
                sender: self.packet_sender.clone(),
            },
        ))
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
        let mut capabilities = smoltcp::phy::DeviceCapabilities::default();
        capabilities.medium = smoltcp::phy::Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

pub struct RxToken {
    buffer: BytesMut,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
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
        if let Err(error) = self.sender.try_send(buffer.into()) {
            error!("failed to send packet: {error}");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use smoltcp::phy::{Device, Medium, RxToken as _, TxToken as _};

    use super::*;

    #[tokio::test]
    async fn wireguard_virtual_device_tokens_use_memory_channels() {
        let (to_tunnel_tx, mut to_tunnel_rx) = tokio::sync::mpsc::channel(4);
        let (from_tunnel_tx, from_tunnel_rx) = tokio::sync::mpsc::channel(4);
        let (notifier_tx, mut notifier_rx) = tokio::sync::mpsc::channel(4);
        let mut device =
            VirtualIpDevice::new(to_tunnel_tx, from_tunnel_rx, notifier_tx, 1380);

        from_tunnel_tx
            .send((PortProtocol::Tcp, Bytes::from_static(b"input")))
            .await
            .unwrap();
        notifier_rx.recv().await.unwrap();

        let (rx, tx) = device
            .receive(smoltcp::time::Instant::from_millis(0))
            .expect("packet should be available");
        let received = rx.consume(|data| data.to_vec());
        assert_eq!(received, b"input");

        tx.consume(3, |buffer| buffer.copy_from_slice(b"out"));
        assert_eq!(
            to_tunnel_rx.recv().await.unwrap(),
            Bytes::from_static(b"out")
        );
    }

    #[tokio::test]
    async fn wireguard_virtual_device_reports_reference_capabilities() {
        let (to_tunnel_tx, _to_tunnel_rx) = tokio::sync::mpsc::channel(1);
        let (_from_tunnel_tx, from_tunnel_rx) = tokio::sync::mpsc::channel(1);
        let (notifier_tx, _notifier_rx) = tokio::sync::mpsc::channel(1);
        let device =
            VirtualIpDevice::new(to_tunnel_tx, from_tunnel_rx, notifier_tx, 1420);
        let capabilities = device.capabilities();
        assert_eq!(capabilities.medium, Medium::Ip);
        assert_eq!(capabilities.max_transmission_unit, 1420);
    }
}
