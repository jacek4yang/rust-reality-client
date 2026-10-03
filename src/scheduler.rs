//! Which node a connection is born on, and how seldom that answer changes.
//!
//! [`Scheduler`] is the whole of the stability story, and it sits in exactly one
//! place in the client: above [`Handoff`], which is where a choice still exists, and
//! below the inbounds, which is where the answer has already been given to an
//! application. That position is not a layering preference. v2.0.1 defines no
//! cross-node resume, so a destination committed to a node is committed for the life
//! of the connection; everything this module decides must be decided before anyone is
//! told the tunnel exists. Read together with [`Established`], the contract is:
//!
//! * **The node that is asked first is the node that is preferred.** Every
//!   connection starts from the sticky primary. Nothing is sent to a second node
//!   because it was also configured.
//! * **A second node is started late, rarely, and never as a third.** The hedge
//!   delay is [`Scheduler::hedge_delay`], which is twice the primary's own remembered
//!   pace clamped into [`Policy::hedge_min`]..[`Policy::hedge_max`]: a connection that
//!   is behind schedule gets company, a connection that is merely normal does not. The
//!   plan is a [`Plan`] and cannot hold more than two candidates, so "fan out to every
//!   node" is not a state this type can represent.
//! * **A candidate that was abandoned is not a node that failed.** [`Health`] is
//!   written where an attempt *settles*. A dropped future never settles, so the only
//!   thing a lost race can record is the weak evidence that the winner was quicker —
//!   [`Policy::hedge_losses`] of them before the route moves, which is the same
//!   three-strikes rule the dial layer uses to move between address families.
//! * **A fault is charged to the party that caused it.** [`Fault::of`] separates a
//!   node that broke from a destination that was dead and from our own limits, and the
//!   last two do not move a node's score at all.
//!
//! ## What "sticky" costs, and why it is still right
//!
//! Keeping one node in the lead means one bad node can be reached by every connection
//! until it fails twice and the breaker opens. That is the deal this module makes on
//! purpose: routing every new connection to the node that has been working is what
//! makes a long download survive, because *any* switch means a new tunnel on a path
//! nobody has measured. The tools that make the sticky choice safe are the ones the
//! list above names — a late hedge, a breaker that trips after two charged faults,
//! and an [`Policy::dwell`] window plus a relative-and-improvement margin that an
//! elective switch has to clear. The result is a client that switches when a node is
//! broken and when a node is *plain* worse, and does not switch because an estimate
//! moved by 30 ms.
//!
//! ## Recovery
//!
//! A tripped node gets one attempt per window ([`Health::claim`], held as a lease on a
//! deadline rather than as a counter, so it cannot leak), and its window doubles with
//! each trip until [`Policy::cooldown_max`]. The attempt is normally taken by an
//! active probe rather than by a user: [`Health::probe_due`] fires
//! [`Policy::probe_lead`] before a window ends, so the node is measured warm at the
//! moment the next connection could use it. A probe is a dial plus a REALITY
//! handshake and no VLESS request — see [`Handoff::probe`] — so it costs the node no
//! work toward a destination and costs this process one authentication. A node tripped
//! by a credentials refusal is never probed, because a probe cannot test a user id.
//!
//! ## What is *not* here
//!
//! No session moves, no byte is replayed, and no connection is re-established on
//! another node: the returned future can be dropped before it answers, and nothing
//! above this module gets to retry after an answer. Once this module returns `Ok`, the
//! session inside belongs to one node, and the only honest report of it going wrong
//! later is the failure the relay gives the application.

pub mod health;
pub mod quality;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{self, Instant};

use crate::config::Config;
use crate::error::{Error, Limit};
use crate::handoff::{Established, Handoff};
use crate::inbound::{Establish, Establishment};
use crate::protocol::vless::Destination;
use crate::transport::{Dial, VisionSession};

use health::Health;
pub use health::{Cost, Fault, Snapshot};

/// The shortest time a connection may run alone before it gets company.
///
/// Below this, a scheduler hedges against its own jitter rather than against an
/// outage, and every page load pays for two authentications.
pub const HEDGE_MIN: Duration = Duration::from_millis(150);

/// The hedge delay for a node this client has not measured yet.
///
/// Midpoint of the 250–300 ms band the plan sets for a first connection: long enough
/// that a node on a normal round trip answers alone, short enough that a black-holed
/// path is noticed within one screen of waiting.
pub const HEDGE_INITIAL: Duration = Duration::from_millis(275);

/// The longest this client will make an application wait before trying a second node.
///
/// Past three quarters of a second a user has already decided the page is broken, and
/// a hedge that arrives after that decision improves nothing.
pub const HEDGE_MAX: Duration = Duration::from_millis(750);

/// The most candidates one logical connection may have in flight.
///
/// [`Plan`] cannot express more than this; the constant is here so the claim can be
/// tested rather than asserted in prose.
pub const MAX_HEDGED_CANDIDATES: usize = 2;

/// The most nodes this client authenticates against at once, process-wide, on nothing
/// but its own curiosity.
pub const MAX_ACTIVE_PROBES: usize = 4;

/// The most second candidates this client will run at once, process-wide.
///
/// A hedge is a spare: it exists so that one slow connection does not become a stalled
/// one. Ten times the dial-layer's authentication ceiling would be a second, larger
/// fan-out with a different name, so the budget is deliberately smaller than the
/// number of connections that could each want one.
pub const MAX_HEDGED_ATTEMPTS: usize = 16;

/// How long one node may be measured before anything else is allowed to take the lead.
///
/// The same thirty seconds the family layer gives a penalised path, and for the same
/// reason: without it, two nodes whose estimates cross back and forth move every
/// connection with each crossing.
pub const MIN_DWELL: Duration = Duration::from_secs(30);

/// The absolute improvement an alternate needs, on top of the relative one.
///
/// Twenty milliseconds is roughly one packet's worth of a real difference on the
/// networks this client runs on, and far more than the noise between two measurements
/// of the same node.
pub const MIN_MARGIN: Duration = Duration::from_millis(20);

/// How much faster an alternate must be, as a percentage of the leader's own pace.
pub const MIN_IMPROVEMENT: u64 = 25;

/// The breaker window after the first charged fault pair.
pub const COOLDOWN: Duration = Duration::from_secs(2);

/// The ceiling on a breaker window, however many times the node has tripped.
///
/// Long enough that a node that is really gone costs one attempt per half minute
/// instead of one per connection, and short enough that an operator who fixes a
/// configuration mistake does not wait on the client to notice.
pub const COOLDOWN_MAX: Duration = Duration::from_secs(30);

/// How far before a window ends the recovery probe runs.
///
/// One authentication's worth of time, so the answer arrives with the window rather
/// than after it, and the first connection that could have used the node finds it
/// already measured.
pub const PROBE_LEAD: Duration = Duration::from_millis(250);

/// How long a recovery attempt stays somebody's job.
///
/// Equal to the shortest breaker window: an attempt that is abandoned without settling
/// — a hedge loser, a task the caller dropped — leaves its lease to age out rather
/// than to be lifted, and this is the bound on how long that can cost.
pub const RECOVERY_LEASE: Duration = Duration::from_secs(2);

/// How long a latency sample is worth remembering.
///
/// v2.0.1's dial tuning (`src/network.rs:49`, `latency_memory`), so the node beliefs
/// and the family beliefs age at the same rate.
pub const LATENCY_MEMORY: Duration = Duration::from_secs(300);

/// The two consecutive charged faults that open a node's breaker.
///
/// Two rather than one because a single failure is often the destination or a moment on
/// the path, and one rather than three because the hedge already covers the connection
/// that saw it: the second fault is what tells us the first was not alone.
pub const BREAKER_STRIKES: u8 = 2;

/// The consecutive lost races that move a route without any failure to point at.
///
/// The dial layer's `WEAK_LOSS_THRESHOLD` (`src/network.rs:67`), reused so that a node
/// which is merely 40 ms behind its alternate has to be caught three separate times
/// before it stops leading.
pub const HEDGE_SWITCH_THRESHOLD: u8 = 3;

/// The timings a scheduler runs by.
///
/// Every one of these is a bound on *how often this client changes its own mind*,
/// which is the only thing an operator can reasonably want to tune here: the node
/// latencies are measured, not configured. The defaults are the numbers the stability
/// plan sets; a test shrinks the windows because a test that waits out thirty seconds
/// of dwell is a test that cannot tell slowness from a hang.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Shortest hedge delay.
    pub hedge_min: Duration,
    /// Hedge delay for a node with no measurement yet.
    pub hedge_initial: Duration,
    /// Longest hedge delay.
    pub hedge_max: Duration,
    /// Charged faults before a node's breaker opens.
    pub strikes: u8,
    /// First breaker window.
    pub cooldown: Duration,
    /// Ceiling on the breaker window.
    pub cooldown_max: Duration,
    /// Shortest gap between two elective route switches.
    pub dwell: Duration,
    /// Absolute improvement an alternate needs to take the lead.
    pub margin: Duration,
    /// Relative improvement an alternate needs, as a percentage.
    pub improvement: u64,
    /// Lost races that move a route with no failure behind them.
    pub hedge_losses: u8,
    /// How early a recovery probe runs.
    pub probe_lead: Duration,
    /// How long a recovery attempt holds a node.
    pub lease: Duration,
    /// How long a latency sample is trusted.
    pub latency_memory: Duration,
    /// Process-wide probe budget.
    pub max_probes: usize,
    /// Process-wide spare-candidate budget.
    pub max_spares: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            hedge_min: HEDGE_MIN,
            hedge_initial: HEDGE_INITIAL,
            hedge_max: HEDGE_MAX,
            strikes: BREAKER_STRIKES,
            cooldown: COOLDOWN,
            cooldown_max: COOLDOWN_MAX,
            dwell: MIN_DWELL,
            margin: MIN_MARGIN,
            improvement: MIN_IMPROVEMENT,
            hedge_losses: HEDGE_SWITCH_THRESHOLD,
            probe_lead: PROBE_LEAD,
            lease: RECOVERY_LEASE,
            latency_memory: LATENCY_MEMORY,
            max_probes: MAX_ACTIVE_PROBES,
            max_spares: MAX_HEDGED_ATTEMPTS,
        }
    }
}

/// What the scheduler can ask of one node.
///
/// [`Handoff`] is the production answer and a test's scripted pipe is the other, which
/// is the only way the paths that matter — a failover, a hedge that wins, a breaker
/// that trips and then recovers — are decided in microseconds instead of by a server
/// that has to cooperate. Nothing here may retry, replay or move a session: the trait
/// inherits the rule, and a dropped future is the only cancellation there is.
pub trait Node: Send + Sync + 'static {
    /// What one of this node's successes hands back.
    type Session: Send + 'static;

    /// Opens one tunnel to `destination` on `port`.
    fn establish(&self, destination: Destination, port: u16) -> Opening<Self::Session>;

    /// Reaches the node and authenticates it, without asking for a tunnel.
    fn probe(&self) -> Probe;
}

/// One [`Node::establish`] call in flight.
pub type Opening<S> = Pin<Box<dyn Future<Output = Result<Established<S>, Error>> + Send>>;

/// One [`Node::probe`] call in flight.
pub type Probe = Pin<Box<dyn Future<Output = Result<Duration, Error>> + Send>>;

impl Node for Handoff {
    type Session = VisionSession<TcpStream>;

    fn establish(&self, destination: Destination, port: u16) -> Opening<Self::Session> {
        let handoff = self.clone();
        Box::pin(async move { handoff.establish(&destination, port).await })
    }

    fn probe(&self) -> Probe {
        let handoff = self.clone();
        Box::pin(async move { handoff.probe().await })
    }
}

/// What the scheduler would do with a connection that arrived right now.
///
/// A sum type rather than a `Vec`, because "never fan out to all nodes" is the kind of
/// guarantee that survives only if the code cannot express otherwise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plan {
    /// One node, no hedge: either there is nothing to hedge against or there is no
    /// second node worth starting.
    Alone {
        /// The node to dial.
        node: usize,
    },
    /// Two nodes, the second one started only if the first is late.
    Hedged {
        /// The sticky leader.
        lead: usize,
        /// The challenger, started after [`Scheduler::hedge_delay`].
        trail: usize,
    },
    /// Nothing may be tried: every node is cooling and one recovery attempt is already
    /// in flight for each of them.
    Busy,
}

impl Plan {
    /// The node this connection starts on, whatever else it may get company from.
    ///
    /// `explain` prints one route, and a plan that may start nothing has none to print.
    #[must_use]
    pub const fn lead(self) -> Option<usize> {
        match self {
            Self::Alone { node } | Self::Hedged { lead: node, .. } => Some(node),
            Self::Busy => None,
        }
    }
}

/// Which node each connection starts on, and what it has to say about that choice.
///
/// Cloning shares everything, including [`Health`]: two schedulers with separate
/// beliefs would be two schedulers learning the same outage twice, and the sticky
/// primary would stop being sticky the moment a second inbound was opened.
pub struct Scheduler<E = Handoff> {
    shared: Arc<Shared<E>>,
}

struct Shared<E> {
    nodes: Vec<E>,
    names: Vec<String>,
    health: Vec<Health>,
    quality: Vec<quality::Quality>,
    logger: Mutex<Option<crate::logging::Logger>>,
    policy: Policy,
    primary: AtomicUsize,
    switched_ms: AtomicU64,
    probes: Arc<Semaphore>,
    spares: Arc<Semaphore>,
    /// Every deadline this scheduler keeps is measured from here, so it is a clock the
    /// runtime can be asked to move: outside a runtime, and inside one that is not
    /// configured to pause, this is the operating system's monotonic clock.
    started: Instant,
}

impl<E: Node> Scheduler<E> {
    /// Pairs node handles with their operator-visible names, in the same order.
    #[must_use]
    pub fn new(nodes: Vec<E>, names: Vec<String>, policy: Policy) -> Self {
        let count = nodes.len();
        let probes = Arc::new(Semaphore::new(policy.max_probes));
        let spares = Arc::new(Semaphore::new(policy.max_spares));
        Self {
            shared: Arc::new(Shared {
                nodes,
                names,
                health: (0..count).map(|_| Health::new()).collect(),
                quality: (0..count).map(|_| quality::Quality::default()).collect(),
                logger: Mutex::new(None),
                policy,
                primary: AtomicUsize::new(0),
                switched_ms: AtomicU64::new(0),
                probes,
                spares,
                started: Instant::now(),
            }),
        }
    }

    /// Attach the service logger without exposing node credentials or destinations.
    pub fn observe_with(&self, logger: crate::logging::Logger) {
        *self
            .shared
            .logger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(logger);
    }

    /// The timings this scheduler runs by, for `explain`.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.shared.policy
    }

    /// The delay one connection would run alone before a second node is started.
    ///
    /// Twice the leader's own remembered pace, because the hedge exists to catch a
    /// connection that is behind schedule and not one that is merely normal, and clamped
    /// into the band an operator can predict. A leader that has never been measured is
    /// not doubled: [`Policy::hedge_initial`] is the delay the plan promises for the first
    /// connection, and treating it as another name for a sample would quietly move that
    /// promise to twice its length.
    #[must_use]
    pub fn hedge_delay(&self) -> Duration {
        let now_ms = self.elapsed_ms();
        let measured = self
            .shared
            .health
            .get(self.primary())
            .and_then(|health| health.estimate(now_ms, &self.shared.policy));
        let delay = measured.map_or(self.shared.policy.hedge_initial, |typical| {
            typical.saturating_mul(2)
        });
        delay.clamp(self.shared.policy.hedge_min, self.shared.policy.hedge_max)
    }

    /// Which node a connection arriving right now would be started on.
    ///
    /// Read-only, so that `explain` can show the same order the next connection will
    /// use without changing it: the decision is computed here, and [`Scheduler::plan`]
    /// is the only place that commits it.
    #[must_use]
    pub fn projection(&self) -> Plan {
        let now_ms = self.elapsed_ms();
        let ranked = self.ranked(now_ms);
        match (ranked.first(), ranked.get(1)) {
            (Some(&lead), Some(&trail)) => Plan::Hedged { lead, trail },
            (Some(&node), None) => Plan::Alone { node },
            // Nothing is available, which is not the same as nothing may be tried: one
            // cooling node is always owed its single test.
            (None, _) => self
                .soonest_free(now_ms)
                .map_or(Plan::Busy, |node| Plan::Alone { node }),
        }
    }

    /// Every node's standing, in configuration order, for `doctor` and `explain`.
    #[must_use]
    pub fn report(&self) -> Vec<NodeReport> {
        let now_ms = self.elapsed_ms();
        let primary = self.primary();
        (0..self.shared.nodes.len())
            .map(|index| NodeReport {
                name: self.shared.names[index].clone(),
                primary: index == primary,
                health: self.shared.health[index].snapshot(now_ms, &self.shared.policy),
            })
            .collect()
    }

    /// Opens one tunnel: chooses, races, records, and hands the winner over.
    ///
    /// This is the whole of the scheduler's work. Dropping the returned future
    /// abandons whichever candidate has not answered, which is a cancellation and not a
    /// failure — see [`Health::claim`] for what that costs a node inside its recovery
    /// window.
    ///
    /// # Errors
    ///
    /// Whatever the candidates reported, preferring the one that indicts a node, or
    /// [`Error::Limit(Limit::Candidates)`] when nothing may be tried yet.
    pub async fn open(
        &self,
        destination: Destination,
        port: u16,
    ) -> Result<Established<E::Session>, Error> {
        match self.plan() {
            // Every node is inside its window and every window has a recovery attempt
            // already running. This answers in no time at all, which is the point: the
            // alternative is to make the application wait on thirty seconds of
            // somebody else's outage.
            Plan::Busy => Err(Error::Limit(Limit::Candidates)),
            Plan::Alone { node } => self.attempt(node, &destination, port).await,
            Plan::Hedged { lead, trail } => self.race(lead, trail, &destination, port).await,
        }
    }

    /// Decides, schedules any recovery probe due, and commits a route switch.
    fn plan(&self) -> Plan {
        let now_ms = self.elapsed_ms();
        self.probe_cooling(now_ms);
        let ranked = self.ranked(now_ms);
        if let Some(&lead) = ranked.first() {
            if lead != self.primary() {
                self.promote(lead, now_ms);
            }
            return match ranked.get(1) {
                Some(&trail) => Plan::Hedged { lead, trail },
                None => Plan::Alone { node: lead },
            };
        }
        self.last_resort(now_ms)
    }

    /// The available nodes, best first, with the sticky leader placed first.
    ///
    /// Pure: nothing here writes to the state, which is what lets [`Scheduler::open`]
    /// and [`Scheduler::projection`] agree on one answer.
    fn ranked(&self, now_ms: u64) -> Vec<usize> {
        let live = self.live(now_ms);
        let Some(lead) = self.leader(&live, now_ms) else {
            return Vec::new();
        };
        let mut ranked: Vec<usize> = live.into_iter().filter(|&i| i != lead).collect();
        ranked.sort_by_key(|&index| self.score(index, now_ms));
        ranked.insert(0, lead);
        ranked
    }

    /// Every node a connection may be started on right now.
    fn live(&self, now_ms: u64) -> Vec<usize> {
        (0..self.shared.nodes.len())
            .filter(|&index| self.shared.health[index].available(now_ms))
            .collect()
    }

    /// Who leads: the sticky primary while it is available, and the best of what is
    /// left once it is not.
    fn leader(&self, live: &[usize], now_ms: u64) -> Option<usize> {
        let best = live
            .iter()
            .copied()
            .min_by_key(|&index| self.score(index, now_ms))?;
        let primary = self.primary();
        if !live.contains(&primary) {
            // The leader is unavailable, so keeping it would mean keeping nothing.
            return Some(best);
        }
        if best != primary && self.worth_switching(primary, best, now_ms) {
            Some(best)
        } else {
            Some(primary)
        }
    }

    /// Whether an elective switch is owed one.
    ///
    /// Both a relative and an absolute improvement are required because either one
    /// alone is wrong on its own: twenty-five percent of two nodes that are both at
    /// thirty milliseconds is a rounding error, and thirty milliseconds on a node that
    /// takes three seconds is not a reason to move traffic onto an unproven path. The
    /// dwell window is the third guard, and the one that stops a flip-flop: a node
    /// whose estimate crosses its alternate's back and forth would otherwise drag
    /// every connection with each crossing.
    fn worth_switching(&self, primary: usize, better: usize, now_ms: u64) -> bool {
        let switched = self.shared.switched_ms.load(Ordering::Acquire);
        if switched != 0 && now_ms.saturating_sub(switched) < millis(self.shared.policy.dwell) {
            return false;
        }
        let lead = self.score(primary, now_ms);
        let rival = self.score(better, now_ms);
        let percent = self.shared.policy.improvement.min(99);
        rival.saturating_add(millis(self.shared.policy.margin)) < lead
            && rival.saturating_mul(100) < lead.saturating_mul(100 - percent)
    }

    /// What a node is expected to cost, in milliseconds, lower being better.
    ///
    /// An unmeasured node is estimated at the initial hedge delay rather than at zero:
    /// a node nobody has tried is not known to be fast, and ranking it first would
    /// spend every connection of a startup discovering what the operator already told
    /// us to prefer.
    fn score(&self, index: usize, now_ms: u64) -> u64 {
        self.shared
            .health
            .get(index)
            .and_then(|health| health.estimate(now_ms, &self.shared.policy))
            .map_or_else(
                || millis(self.shared.policy.hedge_initial),
                |latency| millis(latency).max(1),
            )
            .saturating_add(self.shared.quality[index].penalty_ms(now_ms))
    }

    /// Makes `index` the leader and starts the dwell clock on that decision.
    fn promote(&self, index: usize, now_ms: u64) {
        self.shared.primary.store(index, Ordering::Release);
        self.shared.switched_ms.store(now_ms, Ordering::Release);
    }

    /// The one attempt allowed while nothing is available.
    ///
    /// Ordered by how soon each window ends, so the node that has been down longest is
    /// the one tested. This is a last resort, not a hedge: a refusal that arrives while
    /// an outage is running is honest, and one that arrives because every node's window
    /// is two seconds from ending would be the client giving up on a fix that is already
    /// on its way.
    fn last_resort(&self, now_ms: u64) -> Plan {
        self.soonest_free(now_ms).map_or(Plan::Busy, |index| {
            if self.shared.health[index].claim(now_ms, &self.shared.policy) {
                Plan::Alone { node: index }
            } else {
                // Somebody took the attempt between the read and the claim. It is the
                // only race in this module, and it costs one connection its answer.
                Plan::Busy
            }
        })
    }

    /// The cooling node whose window ends soonest and whose recovery attempt is still
    /// free — which node [`Scheduler::open`] would spend a connection on when nothing is
    /// available.
    ///
    /// Read-only so that [`Scheduler::projection`] and the routing agree on an outage
    /// instead of one of them promising a refusal the other never sends.
    fn soonest_free(&self, now_ms: u64) -> Option<usize> {
        (0..self.shared.nodes.len())
            .filter(|&index| !self.shared.health[index].leased(now_ms))
            .min_by_key(|&index| self.penalty_until(index))
    }

    fn penalty_until(&self, index: usize) -> u64 {
        self.shared
            .health
            .get(index)
            .map_or(u64::MAX, Health::penalty_end)
    }

    /// Runs any probe that is due, so recovery is measured before it is needed.
    fn probe_cooling(&self, now_ms: u64) {
        for index in 0..self.shared.nodes.len() {
            if self.shared.health[index].probe_due(now_ms, &self.shared.policy) {
                self.probe_now(index, now_ms);
            }
        }
    }

    /// Claims one node's recovery attempt and puts it on the runtime.
    fn probe_now(&self, index: usize, now_ms: u64) {
        let Ok(handle) = Handle::try_current() else {
            // No runtime to put a probe on. The reactive path still recovers the node,
            // so this costs nothing but the early measurement.
            return;
        };
        let Ok(permit) = Arc::clone(&self.shared.probes).try_acquire_owned() else {
            return;
        };
        if !self.shared.health[index].claim(now_ms, &self.shared.policy) {
            return;
        }
        let scheduler = self.clone();
        handle.spawn(async move {
            // The permit is held for the probe's whole life, so four nodes probing at
            // once is the most this client can ever be doing behind its user's back.
            let _permit: OwnedSemaphorePermit = permit;
            let result = scheduler.shared.nodes[index].probe().await;
            let now_ms = scheduler.elapsed_ms();
            match result {
                Ok(_latency) => scheduler.shared.health[index].probe_open(),
                Err(error) => scheduler.shared.health[index].probe_fault(
                    now_ms,
                    Fault::of(&error),
                    &scheduler.shared.policy,
                ),
            }
        });
    }

    /// Starts one candidate and records what it settles to — and only that.
    fn attempt(&self, index: usize, destination: &Destination, port: u16) -> Opening<E::Session> {
        let scheduler = self.clone();
        let destination = destination.clone();
        Box::pin(async move {
            let result = scheduler.shared.nodes[index]
                .establish(destination, port)
                .await;
            scheduler.record(index, &result);
            result.map(|mut established| {
                let family = established.family;
                let setup = established.total_latency;
                let opened = scheduler.elapsed_ms();
                established.completion = quality::Completion::new(Box::new(move |completion| {
                    scheduler.shared.quality[index].record(
                        family,
                        opened,
                        scheduler.elapsed_ms(),
                        completion,
                    );
                    let logger = scheduler
                        .shared
                        .logger
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    if let Some(logger) = logger {
                        let counts = completion.progress.transferred();
                        logger
                            .event_at(crate::logging::Level::Debug, "sessionFinished")
                            .count("nodeIndex", index as u64)
                            .text(
                                "family",
                                match family {
                                    crate::transport::AddressFamily::Ipv4 => "ipv4",
                                    crate::transport::AddressFamily::Ipv6 => "ipv6",
                                },
                            )
                            .duration("setup", setup)
                            .duration("age", completion.age())
                            .count("toRemote", counts.to_remote)
                            .count("toLocal", counts.to_local)
                            .text("cause", completion.cause.label())
                            .text(
                                "localOperation",
                                completion.progress.local.failed.unwrap_or("none"),
                            )
                            .text(
                                "tunnelOperation",
                                completion.progress.tunnel.failed.unwrap_or("none"),
                            )
                            .emit();
                    }
                }));
                established
            })
        })
    }

    /// Writes one settled attempt into the node's standing.
    fn record(&self, index: usize, result: &Result<Established<E::Session>, Error>) {
        let now_ms = self.elapsed_ms();
        match result {
            Ok(established) => self.shared.health[index].open(
                now_ms,
                &Cost {
                    total: established.total_latency,
                    connect: established.connect_latency,
                    setup: established.setup_latency,
                },
                &self.shared.policy,
            ),
            Err(error) => {
                self.shared.health[index].fault(now_ms, Fault::of(error), &self.shared.policy);
            }
        }
    }

    /// The two-candidate race: the leader alone until it is late or wrong, then both.
    ///
    /// A leader that *fails* inside its own budget starts the challenger immediately
    /// rather than returning the failure. That is not a hedge in the timing sense, it is
    /// the cheapest failover there is: the node has already answered "no", so there is
    /// nothing left to wait for and no application byte committed anywhere. It is also
    /// legal for exactly the reason the hedge is — the local client has not been told the
    /// tunnel exists yet — and it is the difference between one refused connection and a
    /// page that reloads.
    async fn race(
        &self,
        lead: usize,
        trail: usize,
        destination: &Destination,
        port: u16,
    ) -> Result<Established<E::Session>, Error> {
        let mut lead_attempt = self.attempt(lead, destination, port);
        let delay = self.hedge_delay();
        // A timeout that expires leaves the leader running: the whole value of this
        // shape is that the candidate being joined is the one that was already going.
        let mut lead_pending = true;
        let mut lead_error = None;
        match time::timeout(delay, &mut lead_attempt).await {
            // The leader answered inside its own expected pace, so nothing else was
            // started and nothing else needs explaining.
            Ok(Ok(established)) => return Ok(established),
            // The leader has settled, and what it settled to is a failure. Its future is
            // never polled again from here: the answer is held in `lead_error`.
            Ok(Err(error)) => {
                lead_pending = false;
                lead_error = Some(error);
            }
            Err(_elapsed) => {}
        }

        // The permit is held for the rest of the call, which is the whole point: it is
        // what makes "no third candidate anywhere in the process while this race runs"
        // a fact rather than a hope.
        let Ok(_spare) = Arc::clone(&self.shared.spares).try_acquire_owned() else {
            // The process is already hedging as much as it is willing to. Waiting on
            // the candidate this connection chose is honest; starting a third is not.
            return match lead_error {
                Some(error) => Err(error),
                None => lead_attempt.await,
            };
        };
        // A candidate started while the leader is still running is a hedge; one started
        // after the leader settled is the cheapest failover there is. `hedges` counts
        // only the first, because a rate over both would answer no question at all.
        let raced = lead_error.is_none();
        if raced {
            self.shared.health[trail].hedge_started();
        }
        let mut trail_attempt = self.attempt(trail, destination, port);
        let mut trail_pending = true;
        let mut trail_error = None;
        loop {
            tokio::select! {
                biased;
                // The leader is polled first, so a connection in which both candidates
                // are ready at the same moment stays on the node it started from.
                result = &mut lead_attempt, if lead_pending => match result {
                    Ok(established) => return Ok(established),
                    Err(error) => {
                        lead_pending = false;
                        lead_error = Some(error);
                        if !trail_pending {
                            return Err(worse(lead_error, trail_error));
                        }
                    }
                },
                result = &mut trail_attempt, if trail_pending => match result {
                    Ok(established) => {
                        // The leader is dropped here, and never settles: the only thing
                        // this can honestly record is that it was still behind.
                        if raced {
                            self.shared.health[trail].hedge_won();
                        }
                        self.lost_race(lead, trail);
                        return Ok(established);
                    }
                    Err(error) => {
                        trail_pending = false;
                        trail_error = Some(error);
                        if !lead_pending {
                            return Err(worse(lead_error, trail_error));
                        }
                    }
                },
            }
        }
    }

    /// One candidate won a race the other was still running.
    fn lost_race(&self, loser: usize, winner: usize) {
        let now_ms = self.elapsed_ms();
        if self.shared.health[loser].hedge_lost() < self.shared.policy.hedge_losses {
            return;
        }
        // Three of these and the route moves, without a single failure to point at. It
        // moves to the node that actually won, and only while that node is available,
        // so a challenger that is itself cooling cannot take the lead by default.
        if !self.shared.health[winner].available(now_ms) || winner == self.primary() {
            return;
        }
        // The dwell window guards this move as strictly as an elective one, because a
        // lost race arrives with every page load: without it the third loss would move
        // the route and the fourth, one connection later, would move it straight back.
        let switched = self.shared.switched_ms.load(Ordering::Acquire);
        if switched != 0 && now_ms.saturating_sub(switched) < millis(self.shared.policy.dwell) {
            return;
        }
        self.promote(winner, now_ms);
    }

    /// Milliseconds since this scheduler was built, never zero, so `0` can keep its
    /// meaning of "unset" in every deadline field.
    fn elapsed_ms(&self) -> u64 {
        millis(self.shared.started.elapsed()).saturating_add(1)
    }
}

impl<E> Scheduler<E> {
    /// The sticky primary's index.
    ///
    /// Read here rather than in the bounded block so that [`std::fmt::Debug`], which any
    /// `E` must satisfy, can report the same number the routing uses.
    #[must_use]
    fn primary(&self) -> usize {
        self.shared.primary.load(Ordering::Acquire)
    }
}

impl Scheduler<Handoff> {
    /// Builds one handoff per configured node over one shared dial.
    ///
    /// The dial is shared deliberately: which address family answers on this network is
    /// a fact about the network, not about the node, and a scheduler that gave each node
    /// its own beliefs would relearn the same broken IPv6 path once per node.
    #[must_use]
    pub fn from_config(config: &Config, dial: &Dial) -> Self {
        Self::new(
            config
                .nodes
                .iter()
                .map(|node| Handoff::new(node.clone(), dial.clone()))
                .collect(),
            config.nodes.iter().map(|node| node.name.clone()).collect(),
            Policy::default(),
        )
    }
}

impl<E: Node<Session = VisionSession<TcpStream>>> Establish for Scheduler<E> {
    fn establish(&self, destination: Destination, port: u16) -> Establishment {
        let scheduler = self.clone();
        Box::pin(async move { scheduler.open(destination, port).await })
    }
}

/// One node, as the scheduler sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeReport {
    /// The operator's label for the node.
    pub name: String,
    /// Whether connections start from this node right now.
    pub primary: bool,
    /// What the node has earned.
    pub health: Snapshot,
}

impl<E> Clone for Scheduler<E> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<E> std::fmt::Debug for Scheduler<E> {
    /// Prints the shape of the state, never its contents.
    ///
    /// Node names are operator text and may quote anything an operator was given, so
    /// they stay out; what is left is the part a diagnostic can be written from.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scheduler")
            .field("nodes", &self.shared.nodes.len())
            .field("primary", &self.primary())
            .field("hedge_min", &self.shared.policy.hedge_min)
            .field("hedge_max", &self.shared.policy.hedge_max)
            .field("probes_available", &self.shared.probes.available_permits())
            .field("spares_available", &self.shared.spares.available_permits())
            .finish_non_exhaustive()
    }
}

/// Which of two failed candidates explains the outage better.
///
/// The leader's answer wins unless it says nothing about any node: a caller reading
/// "handshake timed out" is being told something about a server, and a caller reading
/// "local connection limit" is being told about us. Two candidates both failing is the
/// only way here, so the remaining arm cannot be reached and is answered with the
/// refusal it most resembles.
fn worse(lead: Option<Error>, trail: Option<Error>) -> Error {
    match (lead, trail) {
        (Some(lead), Some(trail))
            if !lead.classify().counts_against_node() && trail.classify().counts_against_node() =>
        {
            trail
        }
        (Some(lead), _) => lead,
        (None, Some(trail)) => trail,
        (None, None) => Error::Limit(Limit::Candidates),
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
