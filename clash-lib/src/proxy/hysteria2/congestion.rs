use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use quinn_proto::congestion::{Bbr, BbrConfig, Controller, ControllerFactory};

const DEFAULT_CWND_PACKETS: u64 = 32;

pub struct DynCongestion {
    cwnd_packets: u64,
}

impl DynCongestion {
    pub fn new(cwnd_packets: Option<u64>) -> Self {
        Self {
            cwnd_packets: cwnd_packets
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_CWND_PACKETS),
        }
    }
}

impl ControllerFactory for DynCongestion {
    fn build(
        self: Arc<Self>,
        _now: Instant,
        current_mtu: u16,
    ) -> Box<dyn Controller> {
        let mut bbr_config = BbrConfig::default();
        let cwnd_bytes = self.cwnd_packets.saturating_mul(current_mtu as u64);
        let min_cwnd_bytes = 2 * current_mtu as u64;
        bbr_config.initial_window(cwnd_bytes.max(min_cwnd_bytes));

        let bbr = Bbr::new(Arc::new(bbr_config), current_mtu);
        Box::new(DynController::new(Box::new(bbr)))
    }
}

const SLOT_COUNT: u64 = 5;
const MIN_SAMPLE_PACKETS: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CONGESTION_WINDOW_MULTIPLIER: u64 = 2;
const INITIAL_PACKET_SIZE_IPV4: u64 = 1252;

#[derive(Copy, Clone)]
struct SlotInfo {
    time: u64,
    acked_bytes: u64,
    lost_bytes: u64,
}

#[derive(Clone)]
pub struct Brutal {
    bps: u64,
    acked_bytes: u64,
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
    pub fn new(bps: u64) -> Self {
        Self {
            bps,
            acked_bytes: 0,
            slots: [SlotInfo {
                time: 0,
                acked_bytes: 0,
                lost_bytes: 0,
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

    fn record_congestion_sample(&mut self, now: Instant, lost_bytes: u64) {
        let slot_time = now.saturating_duration_since(self.start_time).as_secs();
        let slot_idx = (slot_time % SLOT_COUNT) as usize;

        if self.slots[slot_idx].time != slot_time {
            self.slots[slot_idx] = SlotInfo {
                time: slot_time,
                acked_bytes: self.acked_bytes,
                lost_bytes,
            };
        } else {
            self.slots[slot_idx].acked_bytes = self.slots[slot_idx]
                .acked_bytes
                .saturating_add(self.acked_bytes);
            self.slots[slot_idx].lost_bytes =
                self.slots[slot_idx].lost_bytes.saturating_add(lost_bytes);
        }

        self.acked_bytes = 0;

        let (acked_bytes, lost_bytes) = self
            .slots
            .iter()
            .filter(|slot| slot_time.saturating_sub(slot.time) < SLOT_COUNT)
            .fold((0_u64, 0_u64), |(acked, lost), slot| {
                (
                    acked.saturating_add(slot.acked_bytes),
                    lost.saturating_add(slot.lost_bytes),
                )
            });

        let sample_bytes = acked_bytes.saturating_add(lost_bytes);
        let min_sample_bytes =
            MIN_SAMPLE_PACKETS.saturating_mul(self.max_datagram_size);
        self.ack_rate = if sample_bytes < min_sample_bytes {
            1.0
        } else {
            (acked_bytes as f64 / sample_bytes as f64).max(MIN_ACK_RATE)
        };
    }
}

impl Controller for Brutal {
    fn initial_window(&self) -> u64 {
        self.window()
    }

    fn window(&self) -> u64 {
        if self.budget_at_last_sent < self.max_datagram_size
            && self.last_send_time.is_some()
        {
            return 0;
        }

        if self.rtt.is_zero() {
            return 10_240;
        }

        let window = (self.bps as f64
            * self.rtt.as_secs_f64()
            * CONGESTION_WINDOW_MULTIPLIER as f64
            / self.ack_rate.max(MIN_ACK_RATE)) as u64;
        window.max(self.max_datagram_size)
    }

    fn on_sent(&mut self, now: Instant, bytes: u64, _last_packet_number: u64) {
        let max_budget = (2_000_000.0 * self.effective_bandwidth() / 1e9)
            .max((10 * self.max_datagram_size) as f64);

        let budget = match self.last_send_time {
            Some(last_send_time) => {
                let elapsed =
                    now.saturating_duration_since(last_send_time).as_secs_f64();
                (self.budget_at_last_sent as f64
                    + elapsed * self.effective_bandwidth())
                .min(max_budget)
            }
            None => max_budget,
        };

        self.budget_at_last_sent = (budget as u64).saturating_sub(bytes);
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
        lost_bytes: u64,
    ) {
        self.record_congestion_sample(now, lost_bytes);
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.rtt = rtt.get();
        self.acked_bytes = self.acked_bytes.saturating_add(bytes);
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
    fn brutal_records_acknowledged_and_lost_bytes_without_connection_stats() {
        let mut controller = Brutal::new(1_000_000);
        let now = Instant::now();
        controller.acked_bytes = 45 * INITIAL_PACKET_SIZE_IPV4;

        controller.record_congestion_sample(now, 5 * INITIAL_PACKET_SIZE_IPV4);

        assert!((controller.ack_rate - 0.9).abs() < f64::EPSILON);
        assert_eq!(controller.acked_bytes, 0);
    }

    #[test]
    fn brutal_ignores_small_byte_samples_until_enough_data_is_observed() {
        let mut controller = Brutal::new(1_000_000);
        let now = Instant::now();
        controller.acked_bytes =
            MIN_SAMPLE_PACKETS * controller.max_datagram_size - 1;

        controller.record_congestion_sample(now, 0);

        assert_eq!(controller.ack_rate, 1.0);
    }

    #[test]
    fn dyn_congestion_applies_cwnd_packets() {
        let mtu = 1_250;
        let controller =
            Arc::new(DynCongestion::new(Some(8))).build(Instant::now(), mtu);
        assert_eq!(controller.initial_window(), 8 * mtu as u64);
    }

    #[test]
    fn dyn_congestion_uses_mihomo_default_cwnd_packets() {
        let mtu = 1_250;
        let controller =
            Arc::new(DynCongestion::new(None)).build(Instant::now(), mtu);
        assert_eq!(
            controller.initial_window(),
            DEFAULT_CWND_PACKETS * mtu as u64
        );
    }

    #[test]
    fn dyn_congestion_treats_zero_cwnd_as_default() {
        let mtu = 1_250;
        let controller =
            Arc::new(DynCongestion::new(Some(0))).build(Instant::now(), mtu);
        assert_eq!(
            controller.initial_window(),
            DEFAULT_CWND_PACKETS * mtu as u64
        );
    }

    #[test]
    fn dyn_congestion_enforces_two_packet_minimum() {
        let mtu = 1_250;
        let controller =
            Arc::new(DynCongestion::new(Some(1))).build(Instant::now(), mtu);
        assert_eq!(controller.initial_window(), 2 * mtu as u64);
    }
}
