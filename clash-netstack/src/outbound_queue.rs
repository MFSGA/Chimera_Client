use crate::Packet;
use futures::task::AtomicWaker;
use std::{
    collections::{HashMap, VecDeque, hash_map::RandomState},
    hash::{BuildHasher, Hash, Hasher},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

const FLOW_REFILL_DELAY: Duration = Duration::from_millis(40);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) enum OutboundFlowKey {
    Udp {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Wire(u64),
}

impl OutboundFlowKey {
    pub(crate) fn udp(local: SocketAddr, remote: SocketAddr) -> Self {
        Self::Udp { local, remote }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BestEffortSend {
    Enqueued,
    Replaced,
    Full,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowClass {
    New,
    Old,
    OldDue,
    Detached,
}

struct Flow {
    packets: VecDeque<Packet>,
    queued_bytes: usize,
    credit: isize,
    class: FlowClass,
    detached_at: Option<Instant>,
}

struct QueueState {
    flows: HashMap<OutboundFlowKey, Flow>,
    new_flows: VecDeque<OutboundFlowKey>,
    old_flows: VecDeque<OutboundFlowKey>,
    queued: usize,
    reserved: usize,
    closed: bool,
}

struct Inner {
    state: Mutex<QueueState>,
    waker: AtomicWaker,
    senders: AtomicUsize,
    capacity: usize,
    quantum: isize,
    initial: isize,
    hash_builder: RandomState,
}

pub(crate) struct FairPacketSender {
    inner: Arc<Inner>,
}

pub(crate) struct FairPacketReceiver {
    inner: Arc<Inner>,
}

pub(crate) struct FairPacketPermit {
    inner: Arc<Inner>,
    active: bool,
}

pub(crate) fn fair_packet_channel(
    capacity: usize,
    mtu: usize,
) -> (FairPacketSender, FairPacketReceiver) {
    let mtu = mtu.max(1);
    let inner = Arc::new(Inner {
        state: Mutex::new(QueueState {
            flows: HashMap::with_capacity(capacity),
            new_flows: VecDeque::with_capacity(capacity),
            old_flows: VecDeque::with_capacity(capacity),
            queued: 0,
            reserved: 0,
            closed: false,
        }),
        waker: AtomicWaker::new(),
        senders: AtomicUsize::new(1),
        capacity,
        quantum: mtu.saturating_mul(2).min(isize::MAX as usize) as isize,
        initial: mtu.saturating_mul(10).min(isize::MAX as usize) as isize,
        hash_builder: RandomState::new(),
    });
    (
        FairPacketSender {
            inner: inner.clone(),
        },
        FairPacketReceiver { inner },
    )
}

impl Clone for FairPacketSender {
    fn clone(&self) -> Self {
        self.inner.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for FairPacketSender {
    fn drop(&mut self) {
        if self.inner.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.waker.wake();
        }
    }
}

impl FairPacketSender {
    pub(crate) fn try_reserve_strict(&self) -> Option<FairPacketPermit> {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || state.queued + state.reserved >= self.inner.capacity {
            return None;
        }
        state.reserved += 1;
        Some(FairPacketPermit {
            inner: self.inner.clone(),
            active: true,
        })
    }

    pub(crate) fn try_send_best_effort(
        &self,
        packet: Packet,
        flow: OutboundFlowKey,
    ) -> BestEffortSend {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return BestEffortSend::Closed;
        }

        let mut replaced = false;
        if state.queued + state.reserved >= self.inner.capacity {
            if !drop_from_fattest_flow(&mut state) {
                return BestEffortSend::Full;
            }
            replaced = true;
        }

        enqueue(&self.inner, &mut state, flow, packet, Instant::now());
        drop(state);
        self.inner.waker.wake();

        if replaced {
            BestEffortSend::Replaced
        } else {
            BestEffortSend::Enqueued
        }
    }
}

impl FairPacketPermit {
    pub(crate) fn send(mut self, packet: Packet) {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        debug_assert!(state.reserved > 0);
        state.reserved = state.reserved.saturating_sub(1);
        self.active = false;
        if state.closed {
            return;
        }
        let flow = classify_wire_packet(&self.inner, packet.data());
        enqueue(&self.inner, &mut state, flow, packet, Instant::now());
        drop(state);
        self.inner.waker.wake();
    }
}

impl Drop for FairPacketPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.reserved = state.reserved.saturating_sub(1);
        drop(state);
        self.inner.waker.wake();
    }
}

impl FairPacketReceiver {
    pub(crate) fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<Packet>> {
        loop {
            {
                let mut state =
                    self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(packet) = dequeue(&self.inner, &mut state) {
                    return Poll::Ready(Some(packet));
                }
                if self.inner.senders.load(Ordering::Acquire) == 0
                    && state.reserved == 0
                {
                    return Poll::Ready(None);
                }
            }

            self.inner.waker.register(cx.waker());

            let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.queued == 0
                && (self.inner.senders.load(Ordering::Acquire) != 0
                    || state.reserved != 0)
            {
                return Poll::Pending;
            }
        }
    }
}

impl Drop for FairPacketReceiver {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        state.flows.clear();
        state.new_flows.clear();
        state.old_flows.clear();
        state.queued = 0;
        drop(state);
        self.inner.waker.wake();
    }
}

fn enqueue(
    inner: &Inner,
    state: &mut QueueState,
    key: OutboundFlowKey,
    packet: Packet,
    now: Instant,
) {
    if !state.flows.contains_key(&key) {
        evict_detached_if_needed(inner, state);
        state.flows.insert(
            key.clone(),
            Flow {
                packets: VecDeque::new(),
                queued_bytes: 0,
                credit: inner.initial,
                class: FlowClass::New,
                detached_at: None,
            },
        );
        state.new_flows.push_back(key.clone());
    } else {
        let reactivate = state
            .flows
            .get(&key)
            .is_some_and(|flow| flow.class == FlowClass::Detached);
        if reactivate {
            let flow = state.flows.get_mut(&key).expect("flow exists");
            if flow.detached_at.is_some_and(|detached| {
                now.duration_since(detached) >= FLOW_REFILL_DELAY
            }) && flow.credit < inner.quantum
            {
                flow.credit = inner.quantum;
            }
            flow.class = FlowClass::New;
            flow.detached_at = None;
            state.new_flows.push_back(key.clone());
        }
    }

    let flow = state.flows.get_mut(&key).expect("flow must exist");
    flow.queued_bytes = flow.queued_bytes.saturating_add(packet.data().len());
    flow.packets.push_back(packet);
    state.queued += 1;
}

fn evict_detached_if_needed(inner: &Inner, state: &mut QueueState) {
    if state.flows.len() < inner.capacity {
        return;
    }
    if let Some(key) = state
        .flows
        .iter()
        .filter(|(_, flow)| flow.class == FlowClass::Detached)
        .min_by_key(|(_, flow)| flow.detached_at)
        .map(|(key, _)| key.clone())
    {
        state.flows.remove(&key);
    }
}

fn drop_from_fattest_flow(state: &mut QueueState) -> bool {
    let Some(key) = state
        .flows
        .iter()
        .filter(|(_, flow)| !flow.packets.is_empty())
        .max_by_key(|(_, flow)| flow.queued_bytes)
        .map(|(key, _)| key.clone())
    else {
        return false;
    };

    let flow = state.flows.get_mut(&key).expect("flow exists");
    let Some(packet) = flow.packets.pop_front() else {
        return false;
    };
    flow.queued_bytes = flow.queued_bytes.saturating_sub(packet.data().len());
    state.queued = state.queued.saturating_sub(1);
    if flow.packets.is_empty() {
        detach_flow(state, &key, Instant::now());
    }
    true
}

fn dequeue(inner: &Inner, state: &mut QueueState) -> Option<Packet> {
    while state.queued != 0 {
        let key = state
            .new_flows
            .front()
            .cloned()
            .or_else(|| state.old_flows.front().cloned())?;
        let class = state.flows.get(&key)?.class;

        if state
            .flows
            .get(&key)
            .is_none_or(|flow| flow.packets.is_empty())
        {
            if class == FlowClass::New {
                demote_new_flow(state, &key, inner.quantum);
            } else {
                detach_flow(state, &key, Instant::now());
            }
            continue;
        }

        if state.flows.get(&key).is_some_and(|flow| flow.credit <= 0) {
            state.flows.get_mut(&key).expect("flow exists").credit += inner.quantum;
            match class {
                FlowClass::New => demote_new_flow(state, &key, inner.quantum),
                FlowClass::OldDue => {}
                FlowClass::Old => rotate_old_flow(state, &key),
                FlowClass::Detached => unreachable!(),
            }
            continue;
        }

        let flow = state.flows.get_mut(&key).expect("flow exists");
        let packet = flow.packets.pop_front().expect("nonempty flow");
        let len = packet.data().len();
        flow.queued_bytes = flow.queued_bytes.saturating_sub(len);
        flow.credit -= len.min(isize::MAX as usize) as isize;
        state.queued = state.queued.saturating_sub(1);

        let empty = state
            .flows
            .get(&key)
            .is_none_or(|flow| flow.packets.is_empty());
        let exhausted = state.flows.get(&key).is_some_and(|flow| flow.credit <= 0);
        match (class, empty, exhausted) {
            (FlowClass::OldDue, true, _) => detach_flow(state, &key, Instant::now()),
            (FlowClass::OldDue, false, true) => {
                state.flows.get_mut(&key).expect("flow exists").credit +=
                    inner.quantum;
                move_old_due_to_old(state, &key);
            }
            (FlowClass::New, true, _) => demote_new_flow(state, &key, inner.quantum),
            (FlowClass::Old, true, _) => detach_flow(state, &key, Instant::now()),
            (FlowClass::New, false, true) => {
                state.flows.get_mut(&key).expect("flow exists").credit +=
                    inner.quantum;
                demote_new_flow(state, &key, inner.quantum);
            }
            (FlowClass::Old, false, true) => {
                state.flows.get_mut(&key).expect("flow exists").credit +=
                    inner.quantum;
                rotate_old_flow(state, &key);
            }
            _ => {}
        }
        return Some(packet);
    }
    None
}

fn demote_new_flow(state: &mut QueueState, key: &OutboundFlowKey, quantum: isize) {
    remove_key(&mut state.new_flows, key);
    schedule_old_due(state, quantum);
    if let Some(flow) = state.flows.get_mut(key) {
        flow.class = FlowClass::Old;
    }
    state.old_flows.push_back(key.clone());
}

fn schedule_old_due(state: &mut QueueState, quantum: isize) {
    loop {
        let Some(key) = state.old_flows.pop_front() else {
            return;
        };
        let Some(flow) = state.flows.get_mut(&key) else {
            continue;
        };
        if flow.packets.is_empty() {
            flow.class = FlowClass::Detached;
            flow.detached_at = Some(Instant::now());
            continue;
        }
        if flow.credit <= 0 {
            flow.credit += quantum;
            state.old_flows.push_back(key);
            continue;
        }
        flow.class = FlowClass::OldDue;
        state.new_flows.push_back(key);
        return;
    }
}

fn rotate_old_flow(state: &mut QueueState, key: &OutboundFlowKey) {
    remove_key(&mut state.old_flows, key);
    state.old_flows.push_back(key.clone());
}

fn move_old_due_to_old(state: &mut QueueState, key: &OutboundFlowKey) {
    remove_key(&mut state.new_flows, key);
    if let Some(flow) = state.flows.get_mut(key) {
        flow.class = FlowClass::Old;
    }
    state.old_flows.push_back(key.clone());
}

fn detach_flow(state: &mut QueueState, key: &OutboundFlowKey, now: Instant) {
    remove_key(&mut state.new_flows, key);
    remove_key(&mut state.old_flows, key);
    if let Some(flow) = state.flows.get_mut(key) {
        flow.class = FlowClass::Detached;
        flow.detached_at = Some(now);
    }
}

fn remove_key(queue: &mut VecDeque<OutboundFlowKey>, key: &OutboundFlowKey) {
    if let Some(index) = queue.iter().position(|candidate| candidate == key) {
        queue.remove(index);
    }
}

fn classify_wire_packet(inner: &Inner, packet: &[u8]) -> OutboundFlowKey {
    let mut hasher = inner.hash_builder.build_hasher();
    if let Ok((ip, _)) = etherparse::LaxIpSlice::from_slice(packet) {
        ip.source_addr().hash(&mut hasher);
        ip.destination_addr().hash(&mut hasher);
        let payload = ip.payload();
        payload.ip_number.0.hash(&mut hasher);

        if let etherparse::LaxIpSlice::Ipv6(ipv6) = &ip {
            let flow_label = ipv6.header().flow_label().value();
            if flow_label != 0 {
                flow_label.hash(&mut hasher);
                return OutboundFlowKey::Wire(hasher.finish());
            }
        }

        if matches!(
            payload.ip_number,
            etherparse::ip_number::TCP | etherparse::ip_number::UDP
        ) && payload.payload.len() >= 4
        {
            payload.payload[..4].hash(&mut hasher);
        } else if payload.payload.len() >= 6 {
            payload.payload[..6].hash(&mut hasher);
        }
    } else {
        packet[..packet.len().min(40)].hash(&mut hasher);
    }
    OutboundFlowKey::Wire(hasher.finish())
}
#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;

    fn packet(size: usize, marker: u8) -> Packet {
        Packet::new(vec![marker; size])
    }

    async fn recv(receiver: &FairPacketReceiver) -> Packet {
        poll_fn(|cx| receiver.poll_recv(cx))
            .await
            .expect("queue should stay open")
    }

    #[tokio::test]
    async fn rotates_new_flow_after_initial_byte_credit() {
        let (sender, receiver) = fair_packet_channel(16, 80);
        let first = OutboundFlowKey::Wire(1);
        let second = OutboundFlowKey::Wire(2);
        for _ in 0..12 {
            assert_eq!(
                sender.try_send_best_effort(packet(80, 1), first.clone()),
                BestEffortSend::Enqueued
            );
        }
        assert_eq!(
            sender.try_send_best_effort(packet(80, 2), second),
            BestEffortSend::Enqueued
        );

        for _ in 0..10 {
            assert_eq!(recv(&receiver).await.data()[0], 1);
        }
        assert_eq!(recv(&receiver).await.data()[0], 2);
    }

    #[tokio::test]
    async fn service_is_byte_fair_after_initial_credit() {
        let (sender, receiver) = fair_packet_channel(128, 1500);
        let large = OutboundFlowKey::Wire(1);
        let small = OutboundFlowKey::Wire(2);
        for _ in 0..64 {
            assert!(matches!(
                sender.try_send_best_effort(packet(1400, 1), large.clone()),
                BestEffortSend::Enqueued
            ));
            assert!(matches!(
                sender.try_send_best_effort(packet(200, 2), small.clone()),
                BestEffortSend::Enqueued
            ));
        }

        let mut large_bytes = 0usize;
        let mut small_bytes = 0usize;
        for _ in 0..75 {
            let next = recv(&receiver).await;
            if next.data()[0] == 1 {
                large_bytes += next.data().len();
            } else {
                small_bytes += next.data().len();
            }
        }
        assert!(large_bytes.abs_diff(small_bytes) <= 3000);
    }

    #[tokio::test]
    async fn full_queue_replaces_oldest_packet_from_fattest_flow() {
        let (sender, receiver) = fair_packet_channel(4, 1500);
        let fat = OutboundFlowKey::Wire(1);
        let thin = OutboundFlowKey::Wire(2);
        for marker in [1, 2, 3] {
            assert_eq!(
                sender.try_send_best_effort(packet(100, marker), fat.clone()),
                BestEffortSend::Enqueued
            );
        }
        assert_eq!(
            sender.try_send_best_effort(packet(50, 9), thin.clone()),
            BestEffortSend::Enqueued
        );
        assert_eq!(
            sender.try_send_best_effort(packet(60, 8), thin),
            BestEffortSend::Replaced
        );

        let mut markers = Vec::new();
        for _ in 0..4 {
            markers.push(recv(&receiver).await.data()[0]);
        }
        assert!(!markers.contains(&1));
        assert!(markers.contains(&8));
    }

    #[test]
    fn strict_reservations_cannot_be_displaced() {
        let (sender, _receiver) = fair_packet_channel(1, 1500);
        let _permit = sender.try_reserve_strict().expect("slot available");
        assert_eq!(
            sender.try_send_best_effort(packet(10, 1), OutboundFlowKey::Wire(1)),
            BestEffortSend::Full
        );
    }
}
