//! One node's standing, and the arithmetic that changes it.
//!
//! This is the state the scheduler is built on: how many times a node has failed
//! since it last worked, how long it may not lead a connection, what its
//! connections have been taking, and how many times it lost a race it was still
//! fighting in. All of it is derived from attempts made for a real application,
//! which is what makes the health *passive* — nothing here needs a probe to know
//! what a node is doing, and nothing here is allowed to forget what a node did.
//!
//! Three rules give the state its shape.
//!
//! * **A fault is only evidence if the node caused it.** [`Fault::of`] sorts the
//!   crate's taxonomy into what indicts a node, what indicts a destination, and what
//!   indicts nobody. Getting this split wrong in either direction is what makes a
//!   scheduler harmful: charge a dead web site to the proxy that reported it dead
//!   and a browser following broken links takes the proxy out of service; refuse to
//!   charge a node for its own timeouts and it leads forever.
//! * **Recovery is earned, and paid for once.** A tripped node gets one attempt per
//!   window — held as a *lease* on a deadline rather than as a counter, so it cannot
//!   leak — and the window grows geometrically with each trip until
//!   [`Policy::cooldown_max`]. Without the lease, one node that is down and one page
//!   that opens twenty connections produce twenty timeouts per node per window.
//! * **A verdict that cannot be tested is not re-tested.** A node tripped by a
//!   credentials refusal is never probed, because a probe authenticates the REALITY
//!   layer only: it would answer a question nobody asked, on the node's clock,
//!   forever.
//!
//! Every field is an atomic and every write saturates, for the two reasons the
//! family layer already gives: attempts settle concurrently, and a counter that
//! wrapped would turn one outage into a permanently healthy node.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use super::Policy;
use crate::error::{Error, Failure, RejectReason};

/// Seven parts history to one part sample.
///
/// The weight the family beliefs use, so that one fast connection never erases a
/// pattern and one slow one never creates one — and so that the two layers of this
/// client answer to the same criticism.
const EWMA_HISTORY: u64 = 7;

/// `probe_clears` for a node nobody has tripped.
const CLEAR_UNSET: u8 = 0;
/// `probe_clears` for a trip an active probe can answer.
const CLEAR_YES: u8 = 1;
/// `probe_clears` for a trip an active probe cannot answer.
const CLEAR_NO: u8 = 2;

/// What one settled failure says about the node that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// The node was reached and went wrong: one of the taxonomy's families.
    Node(Failure),
    /// The node reached the destination and reported it dead. The node worked.
    Destination,
    /// Nothing about any node was learned.
    Nothing,
}

impl Fault {
    /// Reads one error through the taxonomy.
    ///
    /// The one case the families cannot express is sorted out here rather than in
    /// [`crate::error`], because it is a scheduler question: `Rejected` names
    /// everything a node answered, and a node that answers "that destination is
    /// dead" answered correctly.
    #[must_use]
    pub fn of(error: &Error) -> Self {
        if matches!(error, Error::Rejected(RejectReason::DestinationUnreachable)) {
            return Self::Destination;
        }
        match error.classify() {
            Failure::Local => Self::Nothing,
            failure => Self::Node(failure),
        }
    }

    /// Whether an active probe can answer this fault.
    ///
    /// A probe resolves, connects and authenticates the REALITY layer, so it tests
    /// reachability, the cover, and this node's public key and short ID. It never
    /// sends a VLESS request, so it cannot test a user id — and a refusal is entirely
    /// about the user id or about the policy behind it.
    #[must_use]
    pub const fn clears_on_probe(self) -> bool {
        matches!(
            self,
            Self::Node(
                Failure::Connect
                    | Failure::Timeout
                    | Failure::Handshake
                    | Failure::Dns
                    | Failure::Idle
            )
        )
    }
}

/// What one node has earned, and for how long.
#[derive(Debug)]
pub struct Health {
    /// Consecutive faults counting toward the next trip.
    strikes: AtomicU8,
    /// Trips since the last opened tunnel, which is the backoff exponent.
    trips: AtomicU8,
    /// Until when this node may not lead. `0` means it never tripped.
    penalty_until_ms: AtomicU64,
    /// Until when one recovery attempt is already somebody's job.
    lease_until_ms: AtomicU64,
    /// Whether the current trip is a kind a probe can clear: see the `CLEAR_*` codes.
    probe_clears: AtomicU8,
    /// Exponentially weighted whole-establishment latency, microseconds.
    total_micros: AtomicU64,
    /// Exponentially weighted connect time, for the split `explain` prints.
    connect_micros: AtomicU64,
    /// Exponentially weighted authenticate-and-answer time.
    setup_micros: AtomicU64,
    /// When the last sample was taken, so an old one can age out.
    sample_ms: AtomicU64,
    /// Tunnels opened.
    successes: AtomicU64,
    /// Faults charged to this node.
    failures: AtomicU64,
    /// Probes run.
    probes: AtomicU64,
    /// Races this node was still fighting in when another node won them.
    hedge_losses: AtomicU8,
    /// The last fault's family, as a code. `0` is "none".
    last_fault: AtomicU8,
}

impl Health {
    /// A node that has never been attempted.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            strikes: AtomicU8::new(0),
            trips: AtomicU8::new(0),
            penalty_until_ms: AtomicU64::new(0),
            lease_until_ms: AtomicU64::new(0),
            probe_clears: AtomicU8::new(CLEAR_UNSET),
            total_micros: AtomicU64::new(0),
            connect_micros: AtomicU64::new(0),
            setup_micros: AtomicU64::new(0),
            sample_ms: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            probes: AtomicU64::new(0),
            hedge_losses: AtomicU8::new(0),
            last_fault: AtomicU8::new(0),
        }
    }

    /// Whether this node may be handed a connection right now.
    ///
    /// Two clocks answer this and both are needed: the penalty is the outage's own
    /// length, and the lease is the single attempt allowed once it is over. A node
    /// that never tripped holds neither, so the first connection of a process is not
    /// gated by state it has no reason to have.
    #[must_use]
    pub fn available(&self, now_ms: u64) -> bool {
        self.penalty_until_ms.load(Ordering::Acquire) <= now_ms
            && self.lease_until_ms.load(Ordering::Acquire) <= now_ms
    }

    /// Whether this node's one recovery attempt is already somebody's job.
    ///
    /// Asked separately from [`Health::available`] because the two answer different
    /// questions: a cooling node whose lease is free is still not a candidate to route
    /// traffic onto, but it is the node a connection may honestly be spent *testing*.
    #[must_use]
    pub fn leased(&self, now_ms: u64) -> bool {
        self.lease_until_ms.load(Ordering::Acquire) > now_ms
    }

    /// Records one opened tunnel: the breaker is paid off, and the three timings are
    /// folded into the memory that decides the next hedge.
    pub fn open(&self, now_ms: u64, cost: &Cost, policy: &Policy) {
        self.clear();
        let fresh = self.sample_is_fresh(now_ms, policy);
        fold(&self.total_micros, cost.total, fresh);
        fold(&self.connect_micros, cost.connect, fresh);
        fold(&self.setup_micros, cost.setup, fresh);
        self.sample_ms.store(now_ms, Ordering::Release);
        self.successes.fetch_add(1, Ordering::AcqRel);
        // A node that has just opened a tunnel has no explanation left for a younger
        // node taking the route from it.
        self.hedge_losses.store(0, Ordering::Release);
    }

    /// Records one settled failure.
    ///
    /// A fault that indicts nobody moves no counter — not the failure count, not the
    /// strikes. The report is read by someone asking "is this node broken", and a
    /// number that counts our own limits answers a different question.
    pub fn fault(&self, now_ms: u64, fault: Fault, policy: &Policy) {
        let Fault::Node(failure) = fault else {
            // Either the destination was at fault — the node answered, correctly,
            // about something else — or no node was asked at all. Both are neutral:
            // a destination's death does not clear a trip, and does not deepen one.
            return;
        };
        self.failures.fetch_add(1, Ordering::AcqRel);
        self.last_fault
            .store(failure_code(failure), Ordering::Release);
        if increment(&self.strikes) >= policy.strikes {
            self.trip(now_ms, failure, policy);
        }
    }

    /// Takes the one recovery attempt this node is allowed.
    ///
    /// The lease is written before the attempt is made and lifted only when a tunnel
    /// opens, so an attempt that is abandoned (a hedge loser) leaves the lease to age
    /// out on its own. That is the cost of having no way to be told about an
    /// abandonment, and it is bounded by [`Policy::lease`].
    #[must_use]
    pub fn claim(&self, now_ms: u64, policy: &Policy) -> bool {
        let current = self.lease_until_ms.load(Ordering::Acquire);
        if current > now_ms {
            return false;
        }
        self.lease_until_ms
            .compare_exchange(
                current,
                now_ms.saturating_add(millis(policy.lease)),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Whether this node is worth probing: cooling, due within one handshake's time,
    /// and tripped by something a probe can answer.
    #[must_use]
    pub fn probe_due(&self, now_ms: u64, policy: &Policy) -> bool {
        let until = self.penalty_until_ms.load(Ordering::Acquire);
        until > now_ms
            && self.probe_clears.load(Ordering::Acquire) == CLEAR_YES
            && until.saturating_sub(millis(policy.probe_lead)) <= now_ms
    }

    /// Counts a probe that authenticated the node.
    ///
    /// A probe's latency is deliberately not folded into the timings. Reaching a node
    /// and proving the REALITY identity costs less than a VLESS round trip, and a
    /// scheduler that learned its hedge delay from probes would start hedging too
    /// late on a node that is up but slow.
    pub fn probe_open(&self) {
        self.probes.fetch_add(1, Ordering::AcqRel);
        if self.probe_clears.load(Ordering::Acquire) == CLEAR_YES {
            self.clear();
            self.successes.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Counts a probe that did not work, and re-trips the node at once.
    ///
    /// A probe runs at the end of a window, so its failure is not a first strike but
    /// a confirmed outage: waiting for the usual strikes would double the time the
    /// node spends unreachable.
    pub fn probe_fault(&self, now_ms: u64, fault: Fault, policy: &Policy) {
        self.probes.fetch_add(1, Ordering::AcqRel);
        let Fault::Node(failure) = fault else {
            return;
        };
        self.failures.fetch_add(1, Ordering::AcqRel);
        self.last_fault
            .store(failure_code(failure), Ordering::Release);
        self.trip(now_ms, failure, policy);
    }

    /// Notes that this node was still in flight when another node won the race.
    ///
    /// Returns the consecutive count, which is all a cancellation proves: this node
    /// had not answered yet, and nothing about whether it was going to.
    pub fn hedge_lost(&self) -> u8 {
        increment(&self.hedge_losses)
    }

    /// What the next connection to this node is expected to take, or `None` once the
    /// sample has aged out. Five minutes is not long for a route that may have
    /// changed twice since.
    #[must_use]
    pub fn estimate(&self, now_ms: u64, policy: &Policy) -> Option<Duration> {
        self.remembered(&self.total_micros, now_ms, policy)
    }

    /// Everything a diagnostic is allowed to say about this node.
    #[must_use]
    pub fn snapshot(&self, now_ms: u64, policy: &Policy) -> Snapshot {
        Snapshot {
            available: self.available(now_ms),
            cooling: self.remaining(now_ms),
            latency: self.remembered(&self.total_micros, now_ms, policy),
            connect: self.remembered(&self.connect_micros, now_ms, policy),
            setup: self.remembered(&self.setup_micros, now_ms, policy),
            successes: self.successes.load(Ordering::Acquire),
            failures: self.failures.load(Ordering::Acquire),
            probes: self.probes.load(Ordering::Acquire),
            strikes: self.strikes.load(Ordering::Acquire),
            trips: self.trips.load(Ordering::Acquire),
            hedge_losses: self.hedge_losses.load(Ordering::Acquire),
            last_failure: failure_of(self.last_fault.load(Ordering::Acquire)),
        }
    }

    /// How much of the penalty window is left, which is what a refusal promises to
    /// wait for.
    #[must_use]
    pub fn remaining(&self, now_ms: u64) -> Duration {
        Duration::from_millis(self.penalty_end().saturating_sub(now_ms))
    }

    /// When this node becomes eligible to lead again: `0` if it never tripped.
    ///
    /// Sorting candidates by this is how the scheduler picks which cooling node gets
    /// the one recovery attempt it is allowed — the node that will be back soonest,
    /// not the node that was tripped most recently.
    #[must_use]
    pub fn penalty_end(&self) -> u64 {
        self.penalty_until_ms.load(Ordering::Acquire)
    }

    /// Opens the breaker for one more window, growing that window with every trip
    /// since the node last worked.
    fn trip(&self, now_ms: u64, failure: Failure, policy: &Policy) {
        let trips = increment(&self.trips);
        let window = window(trips, policy);
        self.penalty_until_ms
            .fetch_max(now_ms.saturating_add(millis(window)), Ordering::AcqRel);
        self.probe_clears.store(
            if Fault::Node(failure).clears_on_probe() {
                CLEAR_YES
            } else {
                CLEAR_NO
            },
            Ordering::Release,
        );
        // The strikes are spent: a trip is what they bought, and the next set counts
        // toward the next window rather than toward this one.
        self.strikes.store(0, Ordering::Release);
    }

    fn clear(&self) {
        self.strikes.store(0, Ordering::Release);
        self.trips.store(0, Ordering::Release);
        self.penalty_until_ms.store(0, Ordering::Release);
        self.lease_until_ms.store(0, Ordering::Release);
        self.probe_clears.store(CLEAR_UNSET, Ordering::Release);
    }

    fn sample_is_fresh(&self, now_ms: u64, policy: &Policy) -> bool {
        let last = self.sample_ms.load(Ordering::Acquire);
        last != 0 && now_ms.saturating_sub(last) <= millis(policy.latency_memory)
    }

    fn remembered(&self, counter: &AtomicU64, now_ms: u64, policy: &Policy) -> Option<Duration> {
        if !self.sample_is_fresh(now_ms, policy) {
            return None;
        }
        let micros = counter.load(Ordering::Acquire);
        (micros != 0).then_some(Duration::from_micros(micros))
    }
}

impl Default for Health {
    fn default() -> Self {
        Self::new()
    }
}

/// What one opened tunnel cost, apart from the tunnel.
///
/// Split three ways because the three parts mean different things: connect time is
/// the path, authenticate-and-answer time is the node's own work, and the total is
/// what the application waited for. A scheduler that folds only the total cannot
/// tell a slow route from a loaded server, which are two different operator
/// decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cost {
    /// Whole establishment, resolution included.
    pub total: Duration,
    /// First SYN to established socket.
    pub connect: Duration,
    /// Authenticate to the node's answer.
    pub setup: Duration,
}

/// Everything a report may say about one node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Whether a connection may be started on this node right now.
    pub available: bool,
    /// Time left on the breaker window, zero when the node is not cooling.
    pub cooling: Duration,
    /// Remembered whole-establishment latency, if a recent one exists.
    pub latency: Option<Duration>,
    /// Remembered connect time.
    pub connect: Option<Duration>,
    /// Remembered authenticate-and-answer time.
    pub setup: Option<Duration>,
    /// Tunnels opened.
    pub successes: u64,
    /// Faults charged to this node.
    pub failures: u64,
    /// Probes run.
    pub probes: u64,
    /// Faults toward the next trip.
    pub strikes: u8,
    /// Trips since the last opened tunnel.
    pub trips: u8,
    /// Races lost while still in flight.
    pub hedge_losses: u8,
    /// The last fault's family.
    pub last_failure: Option<Failure>,
}

/// The geometric backoff: `cooldown * 2^(trips - 1)`, capped.
fn window(trips: u8, policy: &Policy) -> Duration {
    let cap = millis(policy.cooldown_max);
    let mut window = millis(policy.cooldown);
    for _ in 1..trips {
        window = window.saturating_mul(2);
        if window >= cap {
            return Duration::from_millis(cap);
        }
    }
    Duration::from_millis(window.min(cap))
}

/// Folds one sample into a history, or starts the history.
fn weighted(previous: u64, sample: u64) -> u64 {
    if previous == 0 {
        sample
    } else {
        previous.saturating_mul(EWMA_HISTORY).saturating_add(sample) / (EWMA_HISTORY + 1)
    }
}

/// Folds one timing into one memory, restarting the memory when the old sample has
/// aged out.
///
/// Restarting rather than continuing is what keeps a node that was out of use for ten
/// minutes from being judged by a connection made before the outage: `fresh` is the
/// caller's answer to "is this the same conversation", and a stale history is not.
fn fold(counter: &AtomicU64, sample: Duration, fresh: bool) {
    let previous = if fresh {
        counter.load(Ordering::Acquire)
    } else {
        0
    };
    counter.store(weighted(previous, micros(sample)), Ordering::Release);
}

fn increment(counter: &AtomicU8) -> u8 {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.saturating_add(1);
        if counter
            .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return next;
        }
        current = counter.load(Ordering::Acquire);
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Stores a family in one byte without depending on the enum's discriminants.
fn failure_code(failure: Failure) -> u8 {
    match failure {
        Failure::Local => 1,
        Failure::Dns => 2,
        Failure::Connect => 3,
        Failure::Timeout => 4,
        Failure::Handshake => 5,
        Failure::Rejected => 6,
        Failure::Idle => 7,
    }
}

fn failure_of(code: u8) -> Option<Failure> {
    match code {
        1 => Some(Failure::Local),
        2 => Some(Failure::Dns),
        3 => Some(Failure::Connect),
        4 => Some(Failure::Timeout),
        5 => Some(Failure::Handshake),
        6 => Some(Failure::Rejected),
        7 => Some(Failure::Idle),
        _ => None,
    }
}
