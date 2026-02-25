use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use quinn_proto::congestion::{Bbr, BbrConfig, Controller, ControllerFactory};

pub struct DynCongestion {
    cwnd_packets: Option<u64>,
}

impl DynCongestion {
    pub fn new(cwnd_packets: Option<u64>) -> Self {
        Self {
            cwnd_packets: cwnd_packets.filter(|value| *value > 0),
        }
    }
}

impl ControllerFactory for DynCongestion {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let mut bbr_config = BbrConfig::default();
        if let Some(cwnd_packets) = self.cwnd_packets {
            let cwnd_bytes = cwnd_packets.saturating_mul(current_mtu as u64);
            let min_cwnd_bytes = 2 * current_mtu as u64;
            bbr_config.initial_window(cwnd_bytes.max(min_cwnd_bytes));
        }

        let bbr = Bbr::new(Arc::new(bbr_config), current_mtu);
        Box::new(DynController::new(Box::new(bbr)))
    }
}

const SLOT_COUNT: u64 = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CONGESTION_WINDOW_MULTIPLIER: u64 = 2;
const INITIAL_PACKET_SIZE_IPV4: u64 = 1252;

#[derive(Copy, Clone)]
struct SlotInfo {
    time: u64,
    ack: u64,
    lost: u64,
}

#[derive(Clone)]
pub struct Brutal {
    bps: u64,
    connection: quinn::Connection,
    ack: u64,
    last_lost_packet_num: u64,
    slots: [SlotInfo; SLOT_COUNT as usize],
    ack_rate: f64,
    max_datagram_size: u64,
    last_send_time: Option<Instant>,
    budget_at_last_sent: u64,
    rtt: Duration,
    in_flight: u64,
    start_time: Instant,
}

impl Brutal {
    pub fn new(bps: u64, connection: quinn::Connection) -> Self {
        Self {
            bps,
            connection,
            ack: 0,
            last_lost_packet_num: 0,
            slots: [SlotInfo {
                time: 0,
                ack: 0,
                lost: 0,
            }; SLOT_COUNT as usize],
            ack_rate: 1.0,
            max_datagram_size: INITIAL_PACKET_SIZE_IPV4,
            last_send_time: None,
            budget_at_last_sent: 0,
            rtt: Duration::ZERO,
            in_flight: 0,
            start_time: Instant::now(),
        }
    }

    fn effective_bandwidth(&self) -> f64 {
        if self.ack_rate <= 0.0 {
            self.bps as f64
        } else {
            self.bps as f64 / self.ack_rate
        }
    }
}

impl Controller for Brutal {
    fn initial_window(&self) -> u64 {
        self.window()
    }

    fn window(&self) -> u64 {
        if self.budget_at_last_sent < self.max_datagram_size && self.last_send_time.is_some() {
            return 0;
        }

        if self.rtt.is_zero() {
            return 10_240;
        }

        let window =
            (self.bps as f64 * self.rtt.as_secs_f64() * CONGESTION_WINDOW_MULTIPLIER as f64
                / self.ack_rate.max(MIN_ACK_RATE)) as u64;
        window.max(self.max_datagram_size)
    }

    fn on_sent(&mut self, now: Instant, bytes: u64, _last_packet_number: u64) {
        let max_budget = (2_000_000.0 * self.effective_bandwidth() / 1e9)
            .max((10 * self.max_datagram_size) as f64);

        let budget = match self.last_send_time {
            Some(last_send_time) => {
                let elapsed = now.saturating_duration_since(last_send_time).as_secs_f64();
                (self.budget_at_last_sent as f64 + elapsed * self.effective_bandwidth())
                    .min(max_budget)
            }
            None => max_budget,
        };

        self.budget_at_last_sent = if bytes > budget as u64 {
            0
        } else {
            budget as u64 - bytes
        };
        self.last_send_time = Some(now);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = new_mtu as u64;
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.in_flight = in_flight;
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        let slot_time = now.saturating_duration_since(self.start_time).as_secs();
        let slot_idx = (slot_time % SLOT_COUNT) as usize;
        let current_lost_packet_num = self.connection.stats().path.lost_packets;
        let lost_delta = current_lost_packet_num.saturating_sub(self.last_lost_packet_num);

        if self.slots[slot_idx].time != slot_time {
            self.slots[slot_idx] = SlotInfo {
                time: slot_time,
                ack: self.ack,
                lost: lost_delta,
            };
        } else {
            self.slots[slot_idx].ack = self.slots[slot_idx].ack.saturating_add(self.ack);
            self.slots[slot_idx].lost = self.slots[slot_idx].lost.saturating_add(lost_delta);
        }

        self.last_lost_packet_num = current_lost_packet_num;
        self.ack = 0;

        let (acked, lost) = self
            .slots
            .iter()
            .filter(|slot| slot_time.saturating_sub(slot.time) < SLOT_COUNT)
            .fold((0_u64, 0_u64), |(acked, lost), slot| {
                (
                    acked.saturating_add(slot.ack),
                    lost.saturating_add(slot.lost),
                )
            });

        let sample_total = acked.saturating_add(lost);
        if sample_total < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
        } else {
            self.ack_rate = (acked as f64 / sample_total as f64).max(MIN_ACK_RATE);
        }
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.rtt = rtt.get();
        self.ack = self.ack.saturating_add(1);
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

pub struct DynController(Arc<RwLock<Box<dyn Controller>>>);

impl DynController {
    fn new(controller: Box<dyn Controller>) -> Self {
        Self(Arc::new(RwLock::new(controller)))
    }

    pub fn set_controller(&self, controller: Box<dyn Controller>) {
        *self
            .0
            .write()
            .expect("hysteria2 dyn controller lock poisoned") = controller;
    }
}

impl Controller for DynController {
    fn initial_window(&self) -> u64 {
        self.0
            .read()
            .expect("hysteria2 dyn controller lock poisoned")
            .initial_window()
    }

    fn window(&self) -> u64 {
        self.0
            .read()
            .expect("hysteria2 dyn controller lock poisoned")
            .window()
    }

    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.0
            .write()
            .expect("hysteria2 dyn controller lock poisoned")
            .on_sent(now, bytes, last_packet_number);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.0
            .write()
            .expect("hysteria2 dyn controller lock poisoned")
            .on_mtu_update(new_mtu);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.0
            .write()
            .expect("hysteria2 dyn controller lock poisoned")
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.0
            .write()
            .expect("hysteria2 dyn controller lock poisoned")
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.0
            .write()
            .expect("hysteria2 dyn controller lock poisoned")
            .on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self(self.0.clone()))
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dyn_congestion_applies_cwnd_packets() {
        let mtu = 1_250;
        let controller = Arc::new(DynCongestion::new(Some(8))).build(Instant::now(), mtu);
        assert_eq!(controller.initial_window(), 8 * mtu as u64);
    }
}
