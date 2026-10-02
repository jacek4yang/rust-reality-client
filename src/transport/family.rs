//! Which address family to try first, and how long to keep believing that.
//!
//! This is the client's copy of the process-wide dual-stack state v2.0.1 keeps
//! for its own dials (`src/network.rs`), reduced to what a client needs and
//! matched to it everywhere the two can be compared. The reason a proxy cares is
//! that the second-most-common cause of a slow first byte is not a dead node but
//! a *live, broken* path: a host with an IPv6 address that routes into a tunnel
//! that black-holes it. Trying that path on every connection costs a round of
//! 250 ms of waiting plus a timeout, and doing it forever is what makes a proxy
//! feel unreliable on a network that is merely imperfect.
//!
//! Three properties carry over from upstream and each earns its place:
//!
//! - **Two strikes, not one.** A single route-shaped error (`ENETUNREACH` and
//!   friends) does not deprioritise a family, because one can be a transient
//!   blip during a handover. Two consecutive ones do, for thirty seconds
//!   ([`Tuning::hard_failure_penalty`]).
//! - **Refusal is not failure.** `ECONNREFUSED`/`ECONNRESET` prove packets
//!   reached the peer, so they clear the hard-failure count instead of adding to
//!   it. A family that is refusing connections is a family that works.
//! - **Recovery is tested, not assumed.** A penalised family gets one attempt per
//!   penalty window — a *recovery probe* — and only returns to primary after
//!   [`RECOVERY_SUCCESS_THRESHOLD`] successes. Without this, one thirty-second
//!   outage would strand the process on the alternate family until restart.
//!
//! Route availability is observed rather than configured: a UDP socket is bound
//! to each family's wildcard address and `connect`ed to an unreachable
//! documentation address, which makes the kernel run its route lookup and pick a
//! source address without sending a packet. That is the whole test, and it is the
//! same one upstream runs (`src/network.rs:676-703`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

/// Which families to dial, and which to start from.
///
/// v2.0.1 `src/config/node/network.rs:37-53`. This is the only dual-stack choice
/// an operator has information to make; every timing in [`Tuning`] is derived.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DialPolicy {
    /// Both families, starting from whichever is observed to be healthy.
    ///
    /// The default, because it is the only policy that is right without knowing
    /// anything about the network, and that is what a client with no operator
    /// opinion to inherit should assume.
    #[default]
    Auto,
    /// Both families, starting from IPv4 unless it is unhealthy.
    PreferIpv4,
    /// Both families, starting from IPv6 unless it is unhealthy.
    PreferIpv6,
    /// IPv4 only.
    Ipv4Only,
    /// IPv6 only.
    Ipv6Only,
}

impl DialPolicy {
    /// The name used in configuration, logs and `doctor` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PreferIpv4 => "preferIpv4",
            Self::PreferIpv6 => "preferIpv6",
            Self::Ipv4Only => "ipv4Only",
            Self::Ipv6Only => "ipv6Only",
        }
    }

    /// Reads the configuration spelling, refusing anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "preferIpv4" => Some(Self::PreferIpv4),
            "preferIpv6" => Some(Self::PreferIpv6),
            "ipv4Only" => Some(Self::Ipv4Only),
            "ipv6Only" => Some(Self::Ipv6Only),
            _ => None,
        }
    }

    /// Whether IPv4 candidates may be dialed at all.
    #[must_use]
    pub const fn allows_ipv4(self) -> bool {
        !matches!(self, Self::Ipv6Only)
    }

    /// Whether IPv6 candidates may be dialed at all.
    #[must_use]
    pub const fn allows_ipv6(self) -> bool {
        !matches!(self, Self::Ipv4Only)
    }

    /// The family an explicit preference names, or `None` for `Auto`.
    #[must_use]
    pub const fn prefers_ipv4(self) -> Option<bool> {
        match self {
            Self::PreferIpv4 | Self::Ipv4Only => Some(true),
            Self::PreferIpv6 | Self::Ipv6Only => Some(false),
            Self::Auto => None,
        }
    }
}

/// One Internet address family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

impl AddressFamily {
    /// Classifies one address.
    #[must_use]
    pub const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    /// The other family.
    #[must_use]
    pub const fn alternate(self) -> Self {
        match self {
            Self::Ipv4 => Self::Ipv6,
            Self::Ipv6 => Self::Ipv4,
        }
    }

    /// The name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    /// The bit this family owns in the route bitmask.
    const fn route_bit(self) -> u8 {
        match self {
            Self::Ipv4 => ROUTE_IPV4,
            Self::Ipv6 => ROUTE_IPV6,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Ipv4 => 1,
            Self::Ipv6 => 2,
        }
    }

    fn from_code(code: u8) -> Self {
        if code == Self::Ipv6.code() {
            Self::Ipv6
        } else {
            Self::Ipv4
        }
    }
}

const ROUTE_IPV4: u8 = 1;
const ROUTE_IPV6: u8 = 2;

/// Two consecutive route-shaped errors deprioritise a family.
///
/// v2.0.1 `src/network.rs:66` (`HARD_FAILURE_THRESHOLD`).
const HARD_FAILURE_THRESHOLD: u8 = 2;

/// Three times the alternate family won while this one was still pending.
///
/// v2.0.1 `src/network.rs:67` (`WEAK_LOSS_THRESHOLD`).
const WEAK_LOSS_THRESHOLD: u8 = 3;

/// Probe successes before a penalised family may become primary again.
///
/// v2.0.1 `src/network.rs:68` (`RECOVERY_SUCCESS_THRESHOLD`).
const RECOVERY_SUCCESS_THRESHOLD: u8 = 2;

/// The derived dial timings for one policy.
///
/// Every value here is v2.0.1's `DialTuning::for_policy`
/// (`src/network.rs:44-53`). They are not operator-facing for the same reason:
/// none of them is a call an operator can make better than the process, which is
/// the only party that sees this network's actual latencies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tuning {
    /// Which families to dial, and which to prefer.
    pub mode: DialPolicy,
    /// Wait before starting the alternate-family attempt.
    pub fallback_delay: Duration,
    /// How long a route observation stays trusted.
    pub route_refresh: Duration,
    /// How long two route-shaped errors keep a family deprioritised.
    pub hard_failure_penalty: Duration,
    /// How long a latency sample is worth remembering.
    pub latency_memory: Duration,
}

impl Tuning {
    /// The derived timing for one family preference.
    #[must_use]
    pub const fn for_policy(mode: DialPolicy) -> Self {
        Self {
            mode,
            fallback_delay: Duration::from_millis(250),
            route_refresh: Duration::from_secs(30),
            hard_failure_penalty: Duration::from_secs(30),
            latency_memory: Duration::from_secs(300),
        }
    }
}

impl Default for Tuning {
    fn default() -> Self {
        Self::for_policy(DialPolicy::default())
    }
}

/// What one failed attempt says about the family it used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureEvidence {
    /// A route, device, address or protocol failure: the family itself is suspect.
    StrongFamily,
    /// The family delivered the attempt and the endpoint refused it: the family
    /// is demonstrably working.
    ReachableEndpoint,
    /// Destination-local or ambiguous: global health is unchanged.
    DestinationOnly,
}

/// Classifies one connect error.
///
/// Upstream matches Linux errno numbers (`src/network.rs:603-613`: 97, 93, 101,
/// 113, 99, 19 are family-level; 111 and 104 prove reachability). This goes
/// through `ErrorKind` instead, which the standard library maps from both the
/// Unix errno set and the Windows socket codes, so one error is read the same way
/// on every platform this client ships on. That equivalence was measured here
/// rather than assumed: `ENETUNREACH`/`WSAENETUNREACH` both yield
/// `NetworkUnreachable`, `EHOSTUNREACH`/`WSAEHOSTUNREACH` both yield
/// `HostUnreachable`, `EADDRNOTAVAIL`/`WSAEADDRNOTAVAIL` both yield
/// `AddrNotAvailable`, and 111/104 (10061/10054) both yield the two refusal
/// kinds below.
///
/// Two of upstream's six family-level errnos — `EAFNOSUPPORT` and
/// `EPROTONOSUPPORT`, plus `ENODEV` — collapse into `Uncategorized` on both
/// platforms, and `Uncategorized` is also what an error built by
/// `io::Error::other` gets, so it cannot be used as evidence without indicting
/// every custom error in the process. Those three cases mean a stack that does
/// not implement the family at all, which [`detect_routes`] already excludes
/// before a dial is planned. A timeout is deliberately `DestinationOnly`: a
/// black-holed host is evidence about that host, and promoting it to a family
/// verdict is how one bad peer quietly disables a working stack.
#[must_use]
pub fn classify_connect_error(error: &io::Error) -> FailureEvidence {
    match error.kind() {
        io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::AddrNotAvailable => FailureEvidence::StrongFamily,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
            FailureEvidence::ReachableEndpoint
        }
        _ => FailureEvidence::DestinationOnly,
    }
}

/// Per-family counters, all atomic because every dial updates them concurrently.
#[derive(Debug)]
struct FamilyHealth {
    penalty_until_ms: AtomicU64,
    next_recovery_probe_ms: AtomicU64,
    last_success_ms: AtomicU64,
    latency_micros: AtomicU64,
    consecutive_hard_failures: AtomicU8,
    consecutive_weak_losses: AtomicU8,
    recovery_successes: AtomicU8,
}

impl FamilyHealth {
    const fn new() -> Self {
        Self {
            penalty_until_ms: AtomicU64::new(0),
            next_recovery_probe_ms: AtomicU64::new(0),
            last_success_ms: AtomicU64::new(0),
            latency_micros: AtomicU64::new(0),
            consecutive_hard_failures: AtomicU8::new(0),
            consecutive_weak_losses: AtomicU8::new(0),
            recovery_successes: AtomicU8::new(0),
        }
    }
}

/// Shared, process-lifetime family state.
///
/// Cloning is cheap and every dial consults the same instance, so the belief a
/// connection forms is the belief the next connection starts from.
#[derive(Clone, Debug)]
pub struct Environment {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    mode: DialPolicy,
    initial_primary: AddressFamily,
    routes: AtomicU8,
    primary: AtomicU8,
    ipv4: FamilyHealth,
    ipv6: FamilyHealth,
    last_route_refresh: AtomicU64,
    started: Instant,
}

impl Environment {
    /// Observes the local routes once and picks the starting family.
    #[must_use]
    pub fn detect(mode: DialPolicy) -> Self {
        Self::with_routes(mode, detect_routes())
    }

    fn with_routes(mode: DialPolicy, routes: u8) -> Self {
        Self::build(mode, routes, initial_primary(mode, routes))
    }

    fn build(mode: DialPolicy, routes: u8, primary: AddressFamily) -> Self {
        Self {
            inner: Arc::new(Inner {
                mode,
                initial_primary: primary,
                routes: AtomicU8::new(routes),
                primary: AtomicU8::new(primary.code()),
                ipv4: FamilyHealth::new(),
                ipv6: FamilyHealth::new(),
                last_route_refresh: AtomicU64::new(0),
                started: Instant::now(),
            }),
        }
    }

    /// A stated route table and starting family, for tests only.
    ///
    /// v2.0.1 keeps the same hook (`src/network.rs:439-452`), for the same
    /// reason: whether this machine has a usable IPv6 route is not a question a
    /// test can answer consistently, and it is not the question under test. The
    /// dial layer needs it too, because proving that a cancelled candidate is not
    /// charged as a failure requires a family the test put in charge.
    #[cfg(test)]
    pub(super) fn with_routes_and_primary(
        mode: DialPolicy,
        ipv4: bool,
        ipv6: bool,
        primary: AddressFamily,
    ) -> Self {
        let mut routes = 0;
        if ipv4 {
            routes |= ROUTE_IPV4;
        }
        if ipv6 {
            routes |= ROUTE_IPV6;
        }
        Self::build(mode, routes, primary)
    }

    /// The family dials start from right now.
    #[must_use]
    pub fn primary(&self) -> AddressFamily {
        AddressFamily::from_code(self.inner.primary.load(Ordering::Acquire))
    }

    /// Whether a route for `family` was observed locally.
    #[must_use]
    pub fn route_available(&self, family: AddressFamily) -> bool {
        self.inner.routes.load(Ordering::Acquire) & family.route_bit() != 0
    }

    /// Whether `family` is currently deprioritised.
    ///
    /// A policy that excludes a family is expressed as a penalty that never
    /// expires, which is how one rule (`never dial it`) reaches every caller
    /// without each of them re-reading the policy.
    #[must_use]
    pub fn is_penalized(&self, family: AddressFamily, tuning: &Tuning) -> bool {
        !allows(tuning.mode, family)
            || self.health(family).penalty_until_ms.load(Ordering::Acquire) > self.elapsed_millis()
    }

    /// Re-runs the route observation if the cached one has aged out.
    ///
    /// Cheap enough to call from every dial: two connected UDP sockets and a
    /// `getsockname`, no packets, no resolver, and at most once per
    /// [`Tuning::route_refresh`].
    pub fn refresh_routes(&self, tuning: &Tuning) {
        let now_ms = self.elapsed_millis();
        let window = millis(tuning.route_refresh);
        let previous = self.inner.last_route_refresh.load(Ordering::Acquire);
        if previous != 0 && now_ms.saturating_sub(previous) < window {
            return;
        }
        // Losing the compare-and-swap means another dial is already refreshing;
        // its result lands in the same bits this one would have written.
        if self
            .inner
            .last_route_refresh
            .compare_exchange(previous, now_ms, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.update_routes(detect_routes());
    }

    fn update_routes(&self, routes: u8) {
        let previous_routes = self.inner.routes.swap(routes, Ordering::AcqRel);
        let primary = self.primary();
        let alternate = primary.alternate();
        // Losing the route the process was dialing from is the one event that
        // must switch families immediately, not after two strikes.
        if !self.route_available(primary)
            && self.route_available(alternate)
            && allows(self.inner.mode, alternate)
        {
            self.inner
                .primary
                .store(alternate.code(), Ordering::Release);
            self.health(alternate)
                .recovery_successes
                .store(0, Ordering::Release);
        }
        let preferred = self.preferred_recovery_family();
        if previous_routes & preferred.route_bit() == 0
            && routes & preferred.route_bit() != 0
            && self.primary() != preferred
        {
            // The family the operator actually wants came back: test it on the
            // next connection instead of waiting out the normal probe interval.
            self.health(preferred)
                .next_recovery_probe_ms
                .store(self.elapsed_millis(), Ordering::Release);
        }
    }

    /// Orders a resolved address list for dialing: filtered, de-duplicated and
    /// interleaved so the preferred family always goes first but the alternate is
    /// never more than one candidate behind.
    ///
    /// v2.0.1 `src/network.rs:535-578`. Interleaving rather than exhausting one
    /// family first is what bounds the worst case: with the 250 ms fallback delay
    /// a host that has four IPv6 addresses and one usable IPv4 still reaches the
    /// IPv4 within half a second instead of after four timeouts.
    #[must_use]
    pub fn plan(&self, addresses: &[SocketAddr], tuning: &Tuning) -> Vec<SocketAddr> {
        let allows_v4 = tuning.mode.allows_ipv4();
        let allows_v6 = tuning.mode.allows_ipv6();
        let has_v4 = allows_v4 && addresses.iter().any(SocketAddr::is_ipv4);
        let has_v6 = allows_v6 && addresses.iter().any(SocketAddr::is_ipv6);
        let first = match (has_v4, has_v6) {
            (true, true) => self.preferred_family(tuning),
            (true, false) => AddressFamily::Ipv4,
            // Nothing dialable was resolved, or only IPv6 was: the IPv6 candidates
            // still get tried, because the resolver's answer is not a reason to
            // refuse a connection.
            (false, _) => AddressFamily::Ipv6,
        };
        let second = first.alternate();
        let mut ordered = Vec::with_capacity(addresses.len());
        let mut first_index = 0;
        let mut second_index = 0;
        loop {
            let first_address =
                next_unique_family(addresses, &mut first_index, first, tuning, &ordered);
            if let Some(address) = first_address {
                ordered.push(address);
            }
            let second_address =
                next_unique_family(addresses, &mut second_index, second, tuning, &ordered);
            if let Some(address) = second_address {
                ordered.push(address);
            }
            if first_address.is_none() && second_address.is_none() {
                break;
            }
        }
        ordered
    }

    /// The family to start from, after penalties, route loss and recovery probes.
    fn preferred_family(&self, tuning: &Tuning) -> AddressFamily {
        let primary = self.primary();
        let alternate = primary.alternate();
        if self.claim_recovery_probe(alternate, tuning) {
            return alternate;
        }
        let primary_healthy = !self.is_penalized(primary, tuning);
        let alternate_healthy = !self.is_penalized(alternate, tuning);
        if (!primary_healthy && alternate_healthy)
            || (!self.route_available(primary) && self.route_available(alternate))
        {
            alternate
        } else {
            primary
        }
    }

    /// Takes the single probe slot that a demoted family gets this window.
    ///
    /// Only the family the operator prefers is ever probed, and only one dial at
    /// a time wins the claim, so a penalised path costs at most one attempt per
    /// [`Tuning::hard_failure_penalty`] no matter how many connections are open.
    fn claim_recovery_probe(&self, family: AddressFamily, tuning: &Tuning) -> bool {
        if family == self.primary()
            || family != self.preferred_recovery_family()
            || !self.route_available(family)
            || self.is_penalized(family, tuning)
        {
            return false;
        }
        let health = self.health(family);
        let due = health.next_recovery_probe_ms.load(Ordering::Acquire);
        if due == 0 || self.elapsed_millis() < due {
            return false;
        }
        health
            .next_recovery_probe_ms
            .compare_exchange(
                due,
                self.elapsed_millis()
                    .saturating_add(millis(tuning.hard_failure_penalty)),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Records a successful setup: clears penalties, folds the latency into a
    /// short memory, and counts toward taking the preferred family back.
    pub fn record_success(&self, family: AddressFamily, latency: Duration, tuning: &Tuning) {
        let now_ms = self.elapsed_millis();
        let health = self.health(family);
        let sample = u64::try_from(latency.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        let last = health.last_success_ms.load(Ordering::Acquire);
        let previous = if last != 0 && now_ms.saturating_sub(last) <= millis(tuning.latency_memory)
        {
            health.latency_micros.load(Ordering::Acquire)
        } else {
            0
        };
        // Seven parts history to one part sample: one fast connection must not
        // erase a pattern, and one slow one must not create one.
        let next = if previous == 0 {
            sample
        } else {
            previous.saturating_mul(7).saturating_add(sample) / 8
        };
        health.latency_micros.store(next.max(1), Ordering::Release);
        health.last_success_ms.store(now_ms, Ordering::Release);
        health.consecutive_hard_failures.store(0, Ordering::Release);
        health.consecutive_weak_losses.store(0, Ordering::Release);
        health.penalty_until_ms.store(0, Ordering::Release);

        if family == self.primary() {
            health.recovery_successes.store(0, Ordering::Release);
            return;
        }
        let recoveries = saturating_increment(&health.recovery_successes);
        if recoveries >= RECOVERY_SUCCESS_THRESHOLD
            && self.preferred_recovery_family() == family
            && self.route_available(family)
        {
            self.inner.primary.store(family.code(), Ordering::Release);
            health.recovery_successes.store(0, Ordering::Release);
            health.next_recovery_probe_ms.store(0, Ordering::Release);
        } else {
            // One successful probe earns another attempt on the very next
            // connection rather than another full penalty window: the point of
            // the threshold is to require evidence, not to delay it.
            health
                .next_recovery_probe_ms
                .store(now_ms, Ordering::Release);
        }
    }

    /// Records one failed attempt, with the two-strike rule and the refusal
    /// exception described in the module documentation.
    pub fn record_connect_error(&self, family: AddressFamily, error: &io::Error, tuning: &Tuning) {
        match classify_connect_error(error) {
            FailureEvidence::ReachableEndpoint => {
                let health = self.health(family);
                health.consecutive_hard_failures.store(0, Ordering::Release);
                health.penalty_until_ms.store(0, Ordering::Release);
            }
            FailureEvidence::DestinationOnly => {}
            FailureEvidence::StrongFamily => {
                let failures = saturating_increment(&self.health(family).consecutive_hard_failures);
                if failures >= HARD_FAILURE_THRESHOLD {
                    self.penalize_and_fail_over(family, tuning);
                }
            }
        }
    }

    fn penalize_and_fail_over(&self, family: AddressFamily, tuning: &Tuning) {
        let now_ms = self.elapsed_millis();
        let until = now_ms.saturating_add(millis(tuning.hard_failure_penalty));
        let health = self.health(family);
        health.penalty_until_ms.fetch_max(until, Ordering::AcqRel);
        health
            .next_recovery_probe_ms
            .fetch_max(until, Ordering::AcqRel);
        let alternate = family.alternate();
        if self.primary() == family
            && allows(self.inner.mode, alternate)
            && self.route_available(alternate)
        {
            self.inner
                .primary
                .store(alternate.code(), Ordering::Release);
        }
    }

    /// Notes that the alternate family won while this one was still in flight.
    ///
    /// This is the weak signal that a slower-but-working family is not worth
    /// starting from, and it is the only route to a primary switch that no error
    /// produced. Three occurrences, because on a healthy dual-stack host the
    /// first two are noise.
    pub fn record_alternate_success(&self, winner: AddressFamily, pending_loser: AddressFamily) {
        if winner == pending_loser || self.primary() != pending_loser {
            return;
        }
        let losses = saturating_increment(&self.health(pending_loser).consecutive_weak_losses);
        if losses >= WEAK_LOSS_THRESHOLD
            && self.route_available(winner)
            && allows(self.inner.mode, winner)
        {
            self.inner.primary.store(winner.code(), Ordering::Release);
            self.health(pending_loser)
                .consecutive_weak_losses
                .store(0, Ordering::Release);
        }
    }

    /// The mean setup latency remembered for one family, if any is remembered.
    ///
    /// Diagnostics only (`doctor` and `explain`), which is why it is a read of
    /// two atomics rather than a lock.
    #[must_use]
    pub fn recent_latency(&self, family: AddressFamily, tuning: &Tuning) -> Option<Duration> {
        let health = self.health(family);
        let last = health.last_success_ms.load(Ordering::Acquire);
        if last == 0 || self.elapsed_millis().saturating_sub(last) > millis(tuning.latency_memory) {
            return None;
        }
        let latency = health.latency_micros.load(Ordering::Acquire);
        (latency != 0).then_some(Duration::from_micros(latency))
    }

    /// The family an explicit preference wants back first when it returns.
    fn preferred_recovery_family(&self) -> AddressFamily {
        match self.inner.mode.prefers_ipv4() {
            Some(true) => AddressFamily::Ipv4,
            Some(false) => AddressFamily::Ipv6,
            None => self.inner.initial_primary,
        }
    }

    fn health(&self, family: AddressFamily) -> &FamilyHealth {
        match family {
            AddressFamily::Ipv4 => &self.inner.ipv4,
            AddressFamily::Ipv6 => &self.inner.ipv6,
        }
    }

    fn elapsed_millis(&self) -> u64 {
        // Never zero: every timestamp field in `FamilyHealth` reserves 0 for
        // "unset", and a failure recorded inside the first millisecond of a
        // process would otherwise be written as 0 and read back as never
        // scheduled. v2.0.1 keeps the same distance from zero
        // (`src/network.rs:720-723`).
        millis(self.inner.started.elapsed()).saturating_add(1)
    }
}

fn allows(mode: DialPolicy, family: AddressFamily) -> bool {
    match family {
        AddressFamily::Ipv4 => mode.allows_ipv4(),
        AddressFamily::Ipv6 => mode.allows_ipv6(),
    }
}

/// The family to start from, before any connection has been attempted.
///
/// v2.0.1 `src/network.rs:639-660` states this as a seven-arm table. The same
/// decision is written here as "what does the policy want, and may it have it",
/// because the table's arms collapse into one another — every preference's
/// fallback is some other policy's answer — and a reader of a startup rule should
/// not have to prove seven arm equivalences to trust it. The tests in
/// `family/tests.rs` pin the table case by case.
fn initial_primary(mode: DialPolicy, routes: u8) -> AddressFamily {
    if mode == DialPolicy::Auto {
        // With both routes up, `Auto` follows the resolver's own ordering for
        // `localhost`, which is how RFC 6724's preference reaches the process
        // without reimplementing its address-selection table.
        return match (routes & ROUTE_IPV4 != 0, routes & ROUTE_IPV6 != 0) {
            (true, false) => AddressFamily::Ipv4,
            (false, true) => AddressFamily::Ipv6,
            _ => system_preferred_family(),
        };
    }
    let wanted = if mode.prefers_ipv4() == Some(true) {
        AddressFamily::Ipv4
    } else {
        AddressFamily::Ipv6
    };
    let alternate = wanted.alternate();
    let wanted_up = routes & wanted.route_bit() != 0;
    let alternate_up = routes & alternate.route_bit() != 0;
    // A preference yields when its family has no route and the other does. An
    // exclusion never yields: `ipv4Only` on an IPv6-only network is the operator's
    // order, and dialing IPv6 anyway because it works would be the client
    // overruling the one thing the operator actually specified.
    if wanted_up || !alternate_up || !allows(mode, alternate) {
        wanted
    } else {
        alternate
    }
}

/// The family the local resolver puts first for `localhost`.
fn system_preferred_family() -> AddressFamily {
    // A named lookup of `localhost` is answered by the resolver configuration,
    // which is the closest thing to a stated preference the platform exposes.
    // Port 0 is never connected to; this only reads the ordering.
    let Ok(mut addresses) = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 0)) else {
        // A platform that cannot answer `localhost` is not expressing a
        // preference, so RFC 6724's own default ordering applies.
        return AddressFamily::Ipv6;
    };
    addresses.next().map_or(AddressFamily::Ipv6, |address| {
        AddressFamily::of(address.ip())
    })
}

/// Observes which families have a route and a source address, without traffic.
fn detect_routes() -> u8 {
    let mut routes = 0;
    if route_and_source_available(
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        // TEST-NET-1 on the discard port: guaranteed unroutable, so the kernel
        // does the route lookup and picks a source without sending anything.
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 9),
    ) {
        routes |= ROUTE_IPV4;
    }
    if route_and_source_available(
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        SocketAddr::new(Ipv6Addr::from([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]).into(), 9),
    ) {
        routes |= ROUTE_IPV6;
    }
    routes
}

fn route_and_source_available(bind: SocketAddr, target: SocketAddr) -> bool {
    UdpSocket::bind(bind)
        .and_then(|socket| {
            socket.connect(target)?;
            socket.local_addr()
        })
        .is_ok_and(|local| !local.ip().is_unspecified())
}

fn next_unique_family(
    addresses: &[SocketAddr],
    index: &mut usize,
    family: AddressFamily,
    tuning: &Tuning,
    ordered: &[SocketAddr],
) -> Option<SocketAddr> {
    while *index < addresses.len() {
        let candidate = addresses[*index];
        *index += 1;
        if AddressFamily::of(candidate.ip()) != family || !allows(tuning.mode, family) {
            continue;
        }
        // A resolver can return the same address twice across AAAA/A records, and
        // dialing it twice in one plan wastes the whole fallback budget.
        if ordered.contains(&candidate) {
            continue;
        }
        return Some(candidate);
    }
    None
}

fn saturating_increment(value: &AtomicU8) -> u8 {
    let mut current = value.load(Ordering::Acquire);
    loop {
        let next = current.saturating_add(1);
        match value.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

fn millis(duration: Duration) -> u64 {
    // Saturating rather than wrapping: a duration this module produces is never
    // legitimately over 584 million seconds, and a misconfigured one must not
    // become a small number that expires a penalty immediately.
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
