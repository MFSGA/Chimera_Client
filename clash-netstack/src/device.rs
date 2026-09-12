use crate::{Packet, stack::IfaceEvent};
use log::error;
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

const DEVICE_RX_QUEUE_SIZE: usize = 4096;

pub struct NetstackDevice {
    rx_sender: mpsc::Sender<Packet>,
    rx_queue: mpsc::Receiver<Packet>,

    tx_sender: mpsc::Sender<Packet>,
    capabilities: DeviceCapabilities,

    iface_notifier: mpsc::Sender<IfaceEvent<'static>>,
}

impl NetstackDevice {
    pub fn new(
        tx_sender: mpsc::Sender<Packet>,
        iface_notifier: mpsc::Sender<IfaceEvent<'static>>,
    ) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = 1500;
        capabilities.medium = Medium::Ip;

        let (rx_sender, rx_queue) = mpsc::channel::<Packet>(DEVICE_RX_QUEUE_SIZE);

        Self {
            rx_sender,
            rx_queue,
            tx_sender,
            capabilities,
            iface_notifier,
        }
    }

    pub fn create_injector(&self) -> mpsc::Sender<Packet> {
        self.rx_sender.clone()
    }
}

impl Device for NetstackDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(
        &mut self,
        _timestamp: Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Reserve a tx slot first before touching rx_queue. If rx_queue were
        // consumed first, try_reserve() failure would silently drop inbound ACKs
        // and prevent smoltcp from advancing its send window.
        let permit = self.tx_sender.try_reserve().ok()?;
        let packet = self.rx_queue.try_recv().ok()?;

        let rx_token = RxTokenImpl { packet };
        let tx_token = TxTokenImpl { tx_sender: permit };
        match self.iface_notifier.try_send(IfaceEvent::DeviceReady) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("device ready notifier closed");
            }
        }
        Some((rx_token, tx_token))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.tx_sender
            .try_reserve()
            .map(|permit| TxTokenImpl { tx_sender: permit })
            .ok()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub struct RxTokenImpl {
    packet: Packet,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.data())
    }
}

pub struct TxTokenImpl<'a> {
    tx_sender: mpsc::Permit<'a, Packet>,
}

impl<'a> TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        let packet = Packet::new(buffer);
        self.tx_sender.send(packet);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::Device;

    /// Reproduces the ACK-drop bug when the outbound tx channel is full.
    ///
    /// Without the receive() ordering fix, the inbound ACK is consumed from
    /// rx_queue before a tx slot is reserved and disappears forever.
    #[tokio::test]
    async fn test_receive_drops_inbound_packet_when_tx_channel_full() {
        let (tx_sender, mut tx_receiver) = tokio::sync::mpsc::channel::<Packet>(1);
        let (iface_notifier, _iface_rx) =
            tokio::sync::mpsc::channel::<IfaceEvent<'static>>(8);
        let mut device = NetstackDevice::new(tx_sender, iface_notifier);
        let injector = device.create_injector();

        // Fill the tx channel to its capacity of 1.
        device
            .tx_sender
            .try_send(Packet::new(vec![0u8; 60]))
            .expect("should fit in empty channel");

        // Simulate an inbound ACK entering rx_queue.
        injector
            .send(Packet::new(vec![0u8; 60]))
            .await
            .expect("device rx queue should accept packet");

        // receive() must not consume the ACK while there is no tx slot.
        {
            let result = device.receive(smoltcp::time::Instant::now());
            assert!(
                result.is_none(),
                "receive() must return None when tx channel is full"
            );
        }

        // Drain the tx channel to make space, then verify the ACK is still
        // available for smoltcp to process.
        tx_receiver.recv().await.expect("should have a packet");

        let result = device.receive(smoltcp::time::Instant::now());
        assert!(
            result.is_some(),
            "inbound ACK was dropped when tx channel was full; smoltcp will stall"
        );
    }
}
