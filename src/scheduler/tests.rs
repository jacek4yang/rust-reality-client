//! The scheduler decided by scripted nodes rather than by a server that has to
//! cooperate.
//!
//! Every claim here is one the plan makes and that only a choice can settle: that the
//! node asked first is the node preferred, that a second candidate is started late,
//! rarely and never as a third, that a candidate the caller abandoned is not a node
//! that failed, and that a fault is charged to the party that caused it. Driving those
//! through [`Handoff`] would need a v2.0.1 server that is late on purpose, refuses one
//! user and answers another in eleven milliseconds — a test rig that is itself the
//! outage. So [`Node`] is the seam: the fakes below hand back a pipe instead of a
//! tunnel, and the routing, breaking and hedging logic is the production logic.
//!
//! Two clocks are in play and the tests use them deliberately. [`Health`] answers to a
//! clock it is handed, so the breaker arithmetic — windows, leases, ageing samples — is
//! tested with synthetic instants and no waiting at all. The scheduler reads its own
//! elapsed time, so it is the *hedge delay* that the async tests care about, and those
//! run on a paused clock: twenty milliseconds of waiting costs nothing, and a leader
//! that sleeps an hour is observed to be late rather than slept through.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::DuplexStream;
use tokio::time;

use super::health::Health;
use super::{
    COOLDOWN, COOLDOWN_MAX, Cost, Established, Fault, HEDGE_INITIAL, HEDGE_MAX, HEDGE_MIN,
    MAX_ACTIVE_PROBES, MAX_HEDGED_CANDIDATES, MIN_MARGIN, Node, Opening, Plan, Policy, Probe,
    Scheduler, worse,
};
use crate::error::{Error, Failure, Limit, RejectReason};
use crate::protocol::vless::Destination;
use crate::transport::{AddressFamily, Dial, DialPolicy, Environment, Tuning};

/// The destination every test asks for. A fake never dials it: whatever the node does,
/// or fails to do, happens first.
const TARGET: Destination = Destination::IPv4([192, 0, 2, 1]);

/// What a node reports for its first SYN, when a test does not care.
const TYPICAL: Duration = Duration::from_millis(40);

/// Long enough that no test waits it out, short enough that a paused clock can jump it
/// if a test forgot to hold a task pending.
const HANG: Duration = Duration::from_secs(3600);

/// A node that refuses this connection's credentials.
fn unauthorized() -> Error {
    Error::Rejected(RejectReason::Unauthorized)
}

/// A node whose port is not answering.
fn refused() -> Error {
    Error::Io("the node refused the connection".to_owned())
}

/// A destination the node reached and found dead.
fn target_dead() -> Error {
    Error::Rejected(RejectReason::DestinationUnreachable)
}

/// What one scripted attempt does.
#[derive(Clone, Debug)]
enum Script {
    /// Settles after `wait` with a tunnel that cost `cost` end to end.
    Open { wait: Duration, cost: Duration },
    /// Settles after `wait` with this failure.
    Fault { wait: Duration, error: Error },
    /// Never settles: only the caller dropping it ends it.
    Silent,
}

impl Script {
    fn open(cost: Duration) -> Self {
        Self::Open {
            wait: Duration::ZERO,
            cost,
        }
    }

    fn late_open(wait: Duration) -> Self {
        Self::Open { wait, cost: wait }
    }

    fn fault(error: Error) -> Self {
        Self::Fault {
            wait: Duration::ZERO,
            error,
        }
    }

    fn silent() -> Self {
        Self::Silent
    }
}

/// One node's script: what its attempts do in order, and what its probes do.
///
/// Once a list runs out, attempts fall back to an instant success and probes to a hang,
/// which is the pair that keeps a test from accidentally proving recovery: nothing
/// clears a breaker unless the test wrote that probe down.
struct Spec {
    open: Vec<Script>,
    probe: Vec<Script>,
}

impl Spec {
    fn new(open: Vec<Script>) -> Self {
        Self {
            open,
            probe: Vec::new(),
        }
    }

    fn probing(self, probe: Vec<Script>) -> Self {
        Self { probe, ..self }
    }
}

/// Which of the two budgets a live future is counted against.
const ATTEMPTS: usize = 0;
const PROBES: usize = 1;

/// How many candidates this client has in flight right now, and the widest it ever got.
///
/// Shared by every fake in one rig, because the claim being tested — never more than two
/// candidates, never more than four probes — is about the whole process rather than about
/// one node.
#[derive(Debug)]
struct Crowd {
    live: [AtomicUsize; 2],
    widest: [AtomicUsize; 2],
}

impl Crowd {
    fn new() -> Self {
        Self {
            live: [AtomicUsize::new(0), AtomicUsize::new(0)],
            widest: [AtomicUsize::new(0), AtomicUsize::new(0)],
        }
    }

    /// Counts one future as started, and returns the guard that stops counting it.
    fn enter(&self, kind: usize) -> Guard<'_> {
        let live = self.live[kind].fetch_add(1, Ordering::AcqRel) + 1;
        self.widest[kind].fetch_max(live, Ordering::AcqRel);
        Guard { crowd: self, kind }
    }

    fn widest(&self, kind: usize) -> usize {
        self.widest[kind].load(Ordering::Acquire)
    }
}

struct Guard<'c> {
    crowd: &'c Crowd,
    kind: usize,
}

impl Drop for Guard<'_> {
    /// A task the caller dropped is a future that stopped counting, so the budget has to
    /// come back with it — otherwise a cancelled race would spend the spare pool forever.
    fn drop(&mut self) {
        self.crowd.live[self.kind].fetch_sub(1, Ordering::AcqRel);
    }
}

/// One scripted node.
#[derive(Clone)]
struct Fake {
    open: Arc<Mutex<VecDeque<Script>>>,
    probe: Arc<Mutex<VecDeque<Script>>>,
    crowd: Arc<Crowd>,
}

impl Fake {
    fn of(spec: Spec, crowd: &Arc<Crowd>) -> Self {
        Self {
            open: Arc::new(Mutex::new(spec.open.into())),
            probe: Arc::new(Mutex::new(spec.probe.into())),
            crowd: Arc::clone(crowd),
        }
    }
}

/// Takes the next scripted answer, falling back to what the node does once its script is
/// spent.
fn next(queue: &Mutex<VecDeque<Script>>, fallback: &Script) -> Script {
    queue
        .lock()
        .expect("the fixture's own queue")
        .pop_front()
        .unwrap_or_else(|| fallback.clone())
}

impl Node for Fake {
    type Session = DuplexStream;

    fn establish(&self, _destination: Destination, _port: u16) -> Opening<DuplexStream> {
        let script = next(&self.open, &Script::open(TYPICAL));
        let crowd = Arc::clone(&self.crowd);
        Box::pin(async move {
            let _live = crowd.enter(ATTEMPTS);
            match script {
                Script::Open { wait, cost } => {
                    time::sleep(wait).await;
                    Ok(tunnel(cost))
                }
                Script::Fault { wait, error } => {
                    time::sleep(wait).await;
                    Err(error)
                }
                Script::Silent => {
                    time::sleep(HANG).await;
                    // Only reachable if a test let the paused clock run past the hang,
                    // and then it is the honest answer: nobody was told anything.
                    Err(Error::Cancelled)
                }
            }
        })
    }

    fn probe(&self) -> Probe {
        let script = next(&self.probe, &Script::silent());
        let crowd = Arc::clone(&self.crowd);
        Box::pin(async move {
            let _live = crowd.enter(PROBES);
            match script {
                Script::Open { wait, cost } => {
                    time::sleep(wait).await;
                    Ok(cost)
                }
                Script::Fault { wait, error } => {
                    time::sleep(wait).await;
                    Err(error)
                }
                Script::Silent => {
                    time::sleep(HANG).await;
                    Err(Error::Cancelled)
                }
            }
        })
    }
}

/// One opened tunnel, with a pipe where the production session would be.
fn tunnel(cost: Duration) -> Established<DuplexStream> {
    let (session, _peer) = tokio::io::duplex(64);
    Established {
        completion: super::quality::Completion::untracked(),
        session,
        address: "127.0.0.1:44443"
            .parse()
            .expect("a loopback fixture address"),
        family: AddressFamily::Ipv4,
        connect_latency: cost / 3,
        setup_latency: cost.saturating_sub(cost / 3),
        total_latency: cost,
    }
}

/// One scheduler over scripted nodes, plus the counter they all report into.
fn rig(specs: Vec<Spec>, policy: Policy) -> (Scheduler<Fake>, Arc<Crowd>) {
    let crowd = Arc::new(Crowd::new());
    let nodes: Vec<Fake> = specs
        .into_iter()
        .map(|spec| Fake::of(spec, &crowd))
        .collect();
    let names = (0..nodes.len())
        .map(|index| format!("node-{index}"))
        .collect();
    (Scheduler::new(nodes, names, policy), Arc::clone(&crowd))
}

/// The plan's numbers, unchanged.
fn mandated() -> Policy {
    Policy::default()
}

/// The plan's shape at a scale a test can observe: the same guards, with windows of
/// tens of milliseconds rather than tens of seconds. The probe lead stays shorter than
/// the window it is a lead of, exactly as in the plan, so a node that has just tripped
/// is not owed a test the instant it trips — and a test that wants that probe has to
/// let the window run down for it.
fn quick() -> Policy {
    Policy {
        hedge_min: Duration::from_millis(10),
        hedge_initial: Duration::from_millis(20),
        hedge_max: Duration::from_millis(40),
        strikes: 2,
        cooldown: Duration::from_millis(50),
        cooldown_max: Duration::from_millis(200),
        dwell: Duration::from_millis(20),
        margin: MIN_MARGIN,
        improvement: 25,
        hedge_losses: 3,
        probe_lead: Duration::from_millis(20),
        lease: Duration::from_millis(30),
        latency_memory: Duration::from_secs(300),
        max_probes: MAX_ACTIVE_PROBES,
        max_spares: 16,
    }
}

/// One measured cost, split the way a real attempt splits it.
fn cost(total: Duration) -> Cost {
    Cost {
        total,
        connect: total / 3,
        setup: total.saturating_sub(total / 3),
    }
}

/// Writes one measured success into a node's standing, at this scheduler's own clock.
///
/// The routing tests need beliefs about nodes without having to earn them, and a fake
/// that lies about how long it took is no lie at all: the scheduler is only ever shown
/// the numbers a real attempt would have reported.
fn seed(scheduler: &Scheduler<Fake>, index: usize, total: Duration) {
    let now_ms = scheduler.elapsed_ms();
    scheduler.shared.health[index].open(now_ms, &cost(total), &scheduler.shared.policy);
}

/// Trips one node's breaker with a fault a probe could answer.
fn trip(scheduler: &Scheduler<Fake>, index: usize) {
    let policy = &scheduler.shared.policy;
    let now_ms = scheduler.elapsed_ms();
    for _ in 0..policy.strikes {
        scheduler.shared.health[index].fault(now_ms, Fault::Node(Failure::Connect), policy);
    }
}

/// How many times a node has been told to do anything, from its own report.
fn asked(scheduler: &Scheduler<Fake>, index: usize) -> usize {
    let health = &scheduler.report()[index].health;
    let settled = usize::try_from(health.successes.saturating_add(health.failures))
        .expect("a fixture cannot exceed a usize");
    settled.max(usize::try_from(health.probes).expect("a fixture cannot exceed a usize"))
}

/// Lets a tripped node's window run far enough that its one test is owed.
///
/// `quick` keeps the plan's shape — a probe lead shorter than the window it leads — so
/// the moment a test is worth running arrives `probe_lead` before the window ends, and
/// nothing runs itself until a test says so.
async fn until_probe_due() {
    time::sleep(Duration::from_millis(31)).await;
}

#[test]
fn the_band_is_the_numbers_the_plan_sets() {
    assert_eq!(HEDGE_MIN, Duration::from_millis(150));
    // The initial delay sits in the middle of the mandated 250–300 ms band.
    assert!(HEDGE_INITIAL > HEDGE_MIN && HEDGE_INITIAL < HEDGE_MAX);
    assert_eq!(HEDGE_MAX, Duration::from_millis(750));
    assert_eq!(MAX_HEDGED_CANDIDATES, 2);

    let policy = mandated();
    assert_eq!(policy.hedge_min, HEDGE_MIN);
    assert_eq!(policy.hedge_initial, HEDGE_INITIAL);
    assert_eq!(policy.hedge_max, HEDGE_MAX);
    assert_eq!(policy.cooldown, COOLDOWN);
    assert_eq!(policy.cooldown_max, COOLDOWN_MAX);
    assert_eq!(policy.max_probes, MAX_ACTIVE_PROBES);

    // That two is the ceiling is a property of the type, not of a loop bound: the only
    // variant that names candidates names exactly two.
    assert!(matches!(
        Plan::Hedged { lead: 0, trail: 1 },
        Plan::Hedged { .. }
    ));
}

#[test]
fn a_fault_is_charged_to_the_party_that_caused_it() {
    // A node that refused, timed out, or broke the tunnel is a node that did something.
    assert_eq!(Fault::of(&refused()), Fault::Node(Failure::Connect));
    assert_eq!(
        Fault::of(&Error::Handshake(crate::error::HandshakeError::Timeout)),
        Fault::Node(Failure::Timeout)
    );
    assert_eq!(Fault::of(&unauthorized()), Fault::Node(Failure::Rejected));

    // A node that reported a dead destination answered correctly about something else.
    assert_eq!(Fault::of(&target_dead()), Fault::Destination);

    // Our own limits and our own cancellation say nothing about anybody's server.
    assert_eq!(Fault::of(&Error::Cancelled), Fault::Nothing);
    assert_eq!(Fault::of(&Error::Limit(Limit::Handshakes)), Fault::Nothing);
    assert_eq!(
        Fault::of(&Error::Dns(crate::error::DnsError::NoAddress)),
        Fault::Nothing
    );
}

#[test]
fn only_a_trip_a_probe_can_answer_is_probed() {
    for failure in [
        Failure::Connect,
        Failure::Timeout,
        Failure::Handshake,
        Failure::Dns,
        Failure::Idle,
    ] {
        assert!(
            Fault::Node(failure).clears_on_probe(),
            "{failure:?} is reachability or identity, both of which a probe tests"
        );
    }
    // A refusal is about the user id, which travels only in the VLESS request a probe
    // never sends. Probing it asks a question nobody answered.
    assert!(!Fault::Node(Failure::Rejected).clears_on_probe());
    assert!(!Fault::Destination.clears_on_probe());
    assert!(!Fault::Nothing.clears_on_probe());
}

#[test]
fn the_breaker_window_is_the_outage_length_it_earned() {
    let policy = Policy {
        strikes: 2,
        cooldown: Duration::from_millis(200),
        cooldown_max: Duration::from_millis(800),
        ..Policy::default()
    };
    let health = Health::new();
    assert!(health.available(1_000));

    // One fault is not an outage.
    health.fault(1_000, Fault::Node(Failure::Connect), &policy);
    assert!(health.available(1_001));
    assert_eq!(health.snapshot(1_001, &policy).strikes, 1);

    // Two is, and the first window is the one the plan sets.
    health.fault(1_001, Fault::Node(Failure::Connect), &policy);
    assert!(!health.available(1_002));
    assert_eq!(health.remaining(1_001), Duration::from_millis(200));

    // The window doubles with each trip, then stops doubling.
    health.fault(1_202, Fault::Node(Failure::Connect), &policy);
    health.fault(1_202, Fault::Node(Failure::Connect), &policy);
    assert_eq!(health.remaining(1_202), Duration::from_millis(400));
    for _ in 0..8 {
        health.fault(2_000, Fault::Node(Failure::Connect), &policy);
    }
    assert_eq!(
        health.remaining(2_000),
        Duration::from_millis(800),
        "a window that outgrows its cap is a node that never comes back"
    );

    // The instant the window ends, it is leadable again.
    assert!(health.available(2_801));
}

#[test]
fn an_opened_tunnel_pays_off_the_breaker() {
    let policy = Policy {
        strikes: 1,
        ..Policy::default()
    };
    let health = Health::new();
    health.fault(1_000, Fault::Node(Failure::Connect), &policy);
    assert!(!health.available(1_001));

    health.open(
        1_001,
        &Cost {
            total: Duration::from_millis(90),
            connect: Duration::from_millis(30),
            setup: Duration::from_millis(60),
        },
        &policy,
    );
    let snapshot = health.snapshot(1_001, &policy);
    assert!(snapshot.available);
    assert_eq!(snapshot.trips, 0);
    assert_eq!(snapshot.strikes, 0);
    assert_eq!(snapshot.successes, 1);
    assert_eq!(snapshot.latency, Some(Duration::from_millis(90)));
    assert_eq!(snapshot.connect, Some(Duration::from_millis(30)));
    assert_eq!(snapshot.setup, Some(Duration::from_millis(60)));
    assert_eq!(
        snapshot.last_failure,
        Some(Failure::Connect),
        "the fault is history, not a description of the node now"
    );
}

#[test]
fn a_fault_that_indicts_nobody_moves_nothing() {
    let policy = Policy {
        strikes: 1,
        ..Policy::default()
    };
    let health = Health::new();
    health.fault(1_000, Fault::Nothing, &policy);
    health.fault(1_000, Fault::Destination, &policy);
    let snapshot = health.snapshot(1_000, &policy);
    assert!(snapshot.available);
    assert_eq!(snapshot.failures, 0);
    assert_eq!(snapshot.strikes, 0);
    assert_eq!(
        snapshot.trips, 0,
        "with strikes at one, an uncharged fault would have opened a breaker"
    );
}

#[test]
fn one_lease_bounds_the_recovery_attempts() {
    let policy = Policy {
        lease: Duration::from_millis(20),
        ..Policy::default()
    };
    let health = Health::new();
    assert!(
        health.claim(1_000, &policy),
        "the first attempt is anybody's to take"
    );
    assert!(
        !health.claim(1_010, &policy),
        "one attempt per window: a page that opens twenty connections must not spend twenty timeouts"
    );
    assert!(
        !health.available(1_010),
        "a node whose recovery attempt is running is not also a candidate"
    );
    assert!(
        health.claim(1_021, &policy),
        "an attempt that never settled ages out"
    );

    health.open(1_021, &cost(Duration::from_millis(20)), &policy);
    assert!(
        health.available(1_022),
        "a success lifts the lease it was holding"
    );
}

#[test]
fn a_sample_that_aged_out_is_not_a_belief() {
    let policy = Policy {
        latency_memory: Duration::from_millis(100),
        ..Policy::default()
    };
    let health = Health::new();
    assert_eq!(health.estimate(1_000, &policy), None);
    health.open(1_000, &cost(Duration::from_millis(80)), &policy);
    assert!(health.estimate(1_050, &policy).is_some());
    assert_eq!(
        health.estimate(1_200, &policy),
        None,
        "a route measured before the outage is not a belief about this one"
    );
    assert!(
        health.available(1_200),
        "an aged-out sample is a missing belief, not a fault"
    );
}

#[test]
fn the_ewma_is_seven_parts_history() {
    let policy = mandated();
    let health = Health::new();
    health.open(1_000, &cost(Duration::from_millis(100)), &policy);
    health.open(1_001, &cost(Duration::from_millis(10)), &policy);
    // (100 * 7 + 10) / 8, so one fast connection never erases a pattern.
    assert_eq!(
        health.estimate(1_002, &policy),
        Some(Duration::from_micros(88_750))
    );
}

#[tokio::test(start_paused = true)]
async fn a_fast_lead_is_never_given_company() {
    let (scheduler, crowd) = rig(
        vec![
            Spec::new(vec![Script::late_open(Duration::from_millis(5))]),
            Spec::new(vec![]),
        ],
        quick(),
    );
    let established = scheduler
        .open(TARGET, 443)
        .await
        .expect("the leader answers inside its own budget");
    assert_eq!(established.total_latency, Duration::from_millis(5));
    assert_eq!(asked(&scheduler, 1), 0, "a second node was never started");
    assert_eq!(
        crowd.widest(ATTEMPTS),
        1,
        "hedges are not what a page load is made of"
    );
}

#[tokio::test(start_paused = true)]
async fn a_lead_that_refuses_fails_over_at_once() {
    // The point of the hedge delay is to catch lateness. Refusal needs no catching: the
    // node has already answered, so the challenger starts on the spot and this
    // connection succeeds instead of showing the application an error.
    let (scheduler, crowd) = rig(
        vec![
            Spec::new(vec![Script::fault(unauthorized())]),
            Spec::new(vec![Script::open(Duration::from_millis(30))]),
        ],
        quick(),
    );
    let established = scheduler
        .open(TARGET, 443)
        .await
        .expect("the challenger serves what the leader refused");
    assert_eq!(established.total_latency, Duration::from_millis(30));

    let report = scheduler.report();
    assert_eq!(
        report[0].health.failures, 1,
        "a refusal is the leader's own"
    );
    assert_eq!(report[0].health.last_failure, Some(Failure::Rejected));
    assert_eq!(report[1].health.successes, 1);
    assert_eq!(
        report[1].health.hedges, 0,
        "a challenger started after the leader answered \"no\" is a failover, and \
         counting it as a hedge would make the win rate a number about nothing"
    );
    assert_eq!(report[1].health.hedge_wins, 0);
    assert_eq!(
        crowd.widest(ATTEMPTS),
        1,
        "the challenger was started after the leader settled, not alongside it"
    );
}

#[tokio::test(start_paused = true)]
async fn a_late_lead_is_replaced_by_its_challenger() {
    // Here the two do run together: the leader is only slow, so it is still running when
    // the challenger starts, and the challenger wins.
    let (scheduler, crowd) = rig(
        vec![
            Spec::new(vec![Script::late_open(Duration::from_millis(500))]),
            Spec::new(vec![Script::open(Duration::from_millis(1))]),
        ],
        quick(),
    );
    let established = scheduler
        .open(TARGET, 443)
        .await
        .expect("the challenger answers first");
    assert_eq!(established.total_latency, Duration::from_millis(1));
    assert_eq!(crowd.widest(ATTEMPTS), 2, "both were in flight at once");

    let report = scheduler.report();
    assert_eq!(report[0].health.successes, 0);
    assert_eq!(
        report[0].health.failures, 0,
        "a candidate that was abandoned is not a node that failed"
    );
    assert_eq!(report[0].health.hedge_losses, 1);
    assert_eq!(report[1].health.successes, 1);
    assert_eq!(
        report[1].health.hedges, 1,
        "the challenger was started as a hedge, over a leader still running"
    );
    assert_eq!(
        report[1].health.hedge_wins, 1,
        "and it is the candidate this connection adopted"
    );
    assert_eq!(report[0].health.hedges, 0);
    assert_eq!(report[0].health.hedge_wins, 0);
}

#[tokio::test(start_paused = true)]
async fn four_live_nodes_never_become_four_candidates() {
    let (scheduler, crowd) = rig(
        (0..4)
            .map(|_| Spec::new(vec![Script::fault(refused())]))
            .collect(),
        quick(),
    );
    assert!(
        matches!(scheduler.projection(), Plan::Hedged { lead: 0, trail: _ }),
        "four available nodes still name exactly two candidates"
    );

    let error = scheduler
        .open(TARGET, 443)
        .await
        .expect_err("every candidate refused");
    assert_eq!(error.classify(), Failure::Connect);

    assert!(
        crowd.widest(ATTEMPTS) <= MAX_HEDGED_CANDIDATES,
        "the fan-out ceiling is two; a leader that refuses outright is replaced in turn \
         rather than alongside, which is one and not two"
    );
    let report = scheduler.report();
    for index in [2, 3] {
        assert_eq!(asked(&scheduler, index), 0);
        assert!(
            report[index].health.available,
            "a node never asked cannot be marked down"
        );
    }
    assert_eq!(report[0].health.failures, 1);
    assert_eq!(report[1].health.failures, 1);
}

#[tokio::test(start_paused = true)]
async fn a_destination_that_is_dead_is_not_a_node_that_is_dead() {
    let (scheduler, _crowd) = rig(
        (0..2)
            .map(|_| Spec::new(vec![Script::fault(target_dead())]))
            .collect(),
        quick(),
    );
    let error = scheduler
        .open(TARGET, 443)
        .await
        .expect_err("the destination is dead");
    assert_eq!(error.classify(), Failure::Rejected);

    let report = scheduler.report();
    for node in &report {
        assert_eq!(node.health.failures, 0);
        assert_eq!(node.health.trips, 0);
        assert!(
            node.health.available,
            "a browser following broken links must not be able to take a proxy out of service"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_limit_we_hit_ourselves_is_not_a_node_that_failed() {
    let (scheduler, _crowd) = rig(
        vec![
            Spec::new(vec![Script::fault(Error::Limit(Limit::Handshakes))]),
            Spec::new(vec![Script::fault(Error::Cancelled)]),
        ],
        quick(),
    );
    let error = scheduler
        .open(TARGET, 443)
        .await
        .expect_err("both candidates were stopped by this client, not by either node");
    assert!(
        !error.classify().counts_against_node(),
        "the caller has to be told the truth about why nothing happened: {error}"
    );

    let report = scheduler.report();
    for node in &report {
        assert_eq!(node.health.failures, 0);
        assert_eq!(node.health.trips, 0);
        assert!(
            node.health.available,
            "saturating our own semaphores must leave both routes exactly as they were"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn every_window_held_refuses_instead_of_stalling() {
    let (scheduler, crowd) = rig(
        vec![
            Spec::new(vec![Script::silent()]),
            Spec::new(vec![Script::silent()]),
        ],
        quick(),
    );
    trip(&scheduler, 0);
    trip(&scheduler, 1);
    assert_eq!(
        scheduler.projection(),
        Plan::Alone { node: 0 },
        "both nodes are cooling, and one of them is still owed its single test"
    );

    // Two connections take the two recovery attempts the two nodes are allowed.
    let first = tokio::spawn({
        let scheduler = scheduler.clone();
        async move { scheduler.open(TARGET, 443).await }
    });
    let second = tokio::spawn({
        let scheduler = scheduler.clone();
        async move { scheduler.open(TARGET, 443).await }
    });
    time::sleep(Duration::from_millis(1)).await;
    assert_eq!(
        crowd.widest(ATTEMPTS),
        2,
        "one attempt per cooling node, and no more"
    );
    assert_eq!(
        scheduler.projection(),
        Plan::Busy,
        "and what the next connection would get is exactly what it does get"
    );

    // The third is answered now rather than after somebody else's window.
    let error = scheduler
        .open(TARGET, 443)
        .await
        .expect_err("nothing may be tried");
    assert_eq!(error, Error::Limit(Limit::Candidates));

    first.abort();
    second.abort();
}

#[tokio::test(start_paused = true)]
async fn a_probe_returns_a_cooling_node_to_service() {
    let (scheduler, crowd) = rig(
        vec![
            Spec::new(vec![Script::fault(refused()), Script::fault(refused())])
                .probing(vec![Script::open(Duration::ZERO)]),
            Spec::new(vec![]),
        ],
        quick(),
    );
    // Two charged faults, and the node spends the rest of the test cooling.
    for _ in 0..2 {
        let _ = scheduler.open(TARGET, 443).await;
    }
    let report = scheduler.report();
    assert_eq!(report[0].health.trips, 1);
    assert!(!report[0].health.available);

    // The route moves on the next decision: with node 0 out of service, node 1 leads.
    let _ = scheduler.open(TARGET, 443).await;
    assert!(scheduler.report()[1].primary, "the route moved on");

    // The window runs down until the outage is worth one test, and the connection that
    // arrives then is the one that measures it.
    until_probe_due().await;
    let _ = scheduler.open(TARGET, 443).await;
    time::sleep(Duration::from_millis(1)).await;

    let report = scheduler.report();
    assert_eq!(
        report[0].health.probes, 1,
        "the outage was measured, not guessed"
    );
    assert_eq!(
        crowd.widest(PROBES),
        1,
        "one node cannot be probed twice at once"
    );
    assert!(
        report[0].health.available,
        "a probe that authenticated the node ends the window it was paid for"
    );
    assert_eq!(report[0].health.trips, 0);
}

#[tokio::test(start_paused = true)]
async fn a_credentials_refusal_is_never_probed() {
    let (scheduler, crowd) = rig(
        vec![
            Spec::new(vec![
                Script::fault(unauthorized()),
                Script::fault(unauthorized()),
            ])
            .probing(vec![Script::open(Duration::ZERO)]),
            Spec::new(vec![]),
        ],
        quick(),
    );
    for _ in 0..2 {
        let _ = scheduler.open(TARGET, 443).await;
    }
    // Two more chances for a probe to be scheduled: it never is, because a probe
    // authenticates the TLS layer and this node's problem is the user id.
    let _ = scheduler.open(TARGET, 443).await;
    time::sleep(Duration::from_millis(1)).await;

    let report = scheduler.report();
    assert_eq!(report[0].health.trips, 1);
    assert_eq!(report[0].health.probes, 0);
    assert_eq!(
        crowd.widest(PROBES),
        0,
        "re-probing a refusal asks a question nobody answered, on the node's clock, forever"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failing_probe_re_trips_the_node_at_once() {
    let (scheduler, _crowd) = rig(
        vec![
            Spec::new(vec![Script::fault(refused()), Script::fault(refused())])
                .probing(vec![Script::fault(refused())]),
        ],
        quick(),
    );
    trip(&scheduler, 0);
    until_probe_due().await;
    let _ = scheduler.open(TARGET, 443).await;
    time::sleep(Duration::from_millis(1)).await;

    let health = &scheduler.report()[0].health;
    assert_eq!(health.probes, 1);
    assert_eq!(
        health.trips, 2,
        "a probe that failed at the end of a window is a confirmed outage, not a first strike"
    );
    assert!(!health.available);
}

#[tokio::test(start_paused = true)]
async fn the_probe_budget_bounds_the_curiosity() {
    let policy = Policy {
        max_probes: 2,
        ..quick()
    };
    let (scheduler, crowd) = rig(
        (0..6)
            .map(|_| Spec::new(vec![]).probing(vec![Script::late_open(Duration::from_millis(10))]))
            .collect(),
        policy,
    );
    for index in 0..6 {
        trip(&scheduler, index);
    }
    until_probe_due().await;
    let _ = scheduler.open(TARGET, 443).await;
    time::sleep(Duration::from_millis(1)).await;

    assert_eq!(
        crowd.widest(PROBES),
        2,
        "four is the process ceiling and two is what this policy said"
    );
    // Both probes are still running, so nothing has been counted yet; let them answer.
    time::sleep(Duration::from_millis(10)).await;
    let probed = scheduler
        .report()
        .iter()
        .filter(|node| node.health.probes > 0)
        .count();
    assert_eq!(
        probed, 2,
        "the rest are not this client's business right now"
    );
}

#[tokio::test(start_paused = true)]
async fn the_hedge_delay_follows_the_leader_and_stays_in_the_band() {
    // Nothing measured yet: the initial delay, which is where a first connection starts.
    let (fresh, _) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    assert_eq!(fresh.hedge_delay(), HEDGE_INITIAL);

    // A leader remembered at ten milliseconds would put a challenger on the wire in
    // twenty — half the floor the plan sets, so the floor is what it uses.
    let (fast, _) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    seed(&fast, 0, Duration::from_millis(10));
    assert_eq!(fast.hedge_delay(), HEDGE_MIN);

    // And a leader at four hundred milliseconds earns a wait of eight hundred, which the
    // ceiling turns into three quarters of a second.
    let (slow, _) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    seed(&slow, 0, Duration::from_millis(400));
    assert_eq!(slow.hedge_delay(), HEDGE_MAX);

    // Mid-band is mid-band: no clamp at either end.
    let (middle, _) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    seed(&middle, 0, Duration::from_millis(120));
    assert_eq!(middle.hedge_delay(), Duration::from_millis(240));
}

#[test]
fn the_first_connection_leads_with_the_first_configured_node() {
    let (scheduler, _crowd) = rig((0..3).map(|_| Spec::new(vec![])).collect(), mandated());
    // Nothing is measured and every node claims the same unknown cost, so nothing beats
    // the order the operator wrote down.
    assert_eq!(scheduler.projection(), Plan::Hedged { lead: 0, trail: 1 });
    assert_eq!(scheduler.primary(), 0);
    assert!(scheduler.report()[0].primary);
}

#[tokio::test(start_paused = true)]
async fn a_challenger_takes_the_lead_on_both_a_margin_and_a_percentage() {
    // Ninety against a hundred: the absolute guard is satisfied and the relative one is
    // not, so nothing moves.
    let (close, _crowd) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    seed(&close, 0, Duration::from_millis(100));
    seed(&close, 1, Duration::from_millis(90));
    assert_eq!(close.projection().lead(), Some(0));

    // Sixty against a hundred clears both guards. A second rig, because a belief moves
    // one eighth of the way per sample: node 1 measured at ninety and then at twenty is
    // a node that was once fast, which is not the pattern a switch is owed.
    let (clear, _crowd) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    seed(&clear, 0, Duration::from_millis(100));
    seed(&clear, 1, Duration::from_millis(20));
    assert_eq!(clear.projection().lead(), Some(1));
    assert_eq!(
        clear.primary(),
        0,
        "and a look is not a decision: projection only says what the next connection would do"
    );

    // The connection that arrives takes the route it predicted.
    let _ = clear.open(TARGET, 443).await;
    assert_eq!(
        clear.primary(),
        1,
        "the switch is committed by the decision"
    );
    assert_eq!(
        clear.report()[0].health.trips,
        0,
        "an elective switch is a measurement, not a fault"
    );
}

#[test]
fn the_dwell_window_holds_the_route_still() {
    let policy = Policy {
        dwell: Duration::from_secs(30),
        ..mandated()
    };
    let (scheduler, _crowd) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], policy);
    seed(&scheduler, 1, Duration::from_millis(500));
    seed(&scheduler, 0, Duration::from_millis(20));
    // Node 0 is twenty-five times faster, and it still cannot take the lead back inside
    // the dwell window it just earned.
    let now_ms = scheduler.elapsed_ms();
    scheduler.promote(1, now_ms);
    assert_eq!(scheduler.projection().lead(), Some(1));

    // The same numbers with no switch behind them do move.
    let (fresh, _crowd) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], policy);
    seed(&fresh, 1, Duration::from_millis(500));
    seed(&fresh, 0, Duration::from_millis(20));
    assert_eq!(fresh.projection().lead(), Some(0));
}

#[tokio::test(start_paused = true)]
async fn three_lost_races_move_the_route_with_no_failure_to_point_at() {
    let (scheduler, _crowd) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    for count in 1..=3 {
        scheduler.lost_race(0, 1);
        let report = scheduler.report();
        assert_eq!(report[0].health.hedge_losses, count);
        assert_eq!(report[0].health.failures, 0);
        assert_eq!(report[1].primary, count == 3);
    }
    assert_eq!(scheduler.primary(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_cooling_winner_cannot_take_the_lead_by_default() {
    let (scheduler, _crowd) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    trip(&scheduler, 1);
    for _ in 0..5 {
        scheduler.lost_race(0, 1);
    }
    assert_eq!(
        scheduler.primary(),
        0,
        "a challenger that is itself cooling is not a better path"
    );
    assert!(
        !scheduler.report()[1].health.available,
        "and the reason it was passed over is still true"
    );
}

#[tokio::test(start_paused = true)]
async fn one_configured_node_is_never_hedged() {
    let slow = Script::late_open(Duration::from_millis(300));
    let (scheduler, crowd) = rig(vec![Spec::new(vec![slow])], quick());
    assert_eq!(scheduler.projection(), Plan::Alone { node: 0 });
    let established = scheduler
        .open(TARGET, 443)
        .await
        .expect("the one node answers late, and is still the only node");
    assert_eq!(established.total_latency, Duration::from_millis(300));
    assert_eq!(
        crowd.widest(ATTEMPTS),
        1,
        "a hedge against a single node would be the same node dialed twice"
    );
}

#[tokio::test(start_paused = true)]
async fn no_configured_node_refuses_rather_than_panicking() {
    let (scheduler, _crowd) = rig(Vec::new(), mandated());
    assert!(scheduler.report().is_empty());
    assert_eq!(scheduler.projection(), Plan::Busy);
    let error = scheduler
        .open(TARGET, 443)
        .await
        .expect_err("with no nodes there is no candidate to name");
    assert_eq!(error, Error::Limit(Limit::Candidates));
}

#[test]
fn the_worse_of_two_failures_is_the_one_about_the_node() {
    let node = refused();
    let ours = Error::Cancelled;
    // Two candidates, one of which said something about itself: that is the report the
    // application gets.
    let chosen = worse(Some(ours.clone()), Some(node.clone()));
    assert_eq!(chosen.classify(), Failure::Connect);
    let chosen = worse(Some(node.clone()), Some(ours.clone()));
    assert_eq!(chosen.classify(), Failure::Connect);
    // Neither of them said anything about itself, so the application is told what
    // actually happened to the candidate it chose, rather than a refusal invented here.
    let chosen = worse(Some(ours.clone()), Some(ours.clone()));
    assert_eq!(chosen, ours);
    // A race that settled without ever naming an error is not a success either.
    let chosen = worse(None, None);
    assert_eq!(chosen, Error::Limit(Limit::Candidates));
}

#[test]
fn diagnostics_name_the_node_and_nothing_else() {
    use crate::config;

    let public_key = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x09; 32])
    };
    let user: &str = "123e4567-e89b-12d3-a456-426614174000";
    let text = format!(
        r#"[listen]
socks5 = "127.0.0.1:10808"
http = "127.0.0.1:10809"

[[node]]
name = "edge-a"
address = "127.0.0.1"
port = 44443
userId = "{user}"
[node.reality]
publicKey = "{public_key}"
shortId = "deadbeef"
serverName = "www.example.com"

[[node]]
name = "edge-b"
address = "127.0.0.1"
port = 44444
userId = "{user}"
[node.reality]
publicKey = "{public_key}"
shortId = "deadbeef"
serverName = "www.example.com"
"#
    );
    let parsed =
        config::parse(&text).expect("the fixture must be a configuration an operator could write");
    let dial = Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    );
    let scheduler = Scheduler::from_config(&parsed, &dial);

    let report = format!("{:?}", scheduler.report());
    let debug = format!("{scheduler:?}");
    for secret in [user, "deadbeef", "123e4567"] {
        assert!(
            !report.contains(secret) && !debug.contains(secret),
            "the scheduler's own diagnostics leaked {secret}"
        );
    }
    // What is left is the part a diagnostic needs: the label, and the counts.
    assert_eq!(scheduler.report().len(), 2);
    assert!(report.contains("edge-a") && report.contains("edge-b"));
    assert!(scheduler.report()[0].primary);
}

#[tokio::test(start_paused = true)]
async fn fast_handshakes_do_not_erase_repeated_session_protocol_failures() {
    let (scheduler, _) = rig(vec![Spec::new(vec![]), Spec::new(vec![])], mandated());
    seed(&scheduler, 0, Duration::from_millis(1));
    seed(&scheduler, 1, Duration::from_millis(80));
    let healthy_existing = scheduler.open(TARGET, 443).await.unwrap();
    for _ in 0..3 {
        let mut opened = scheduler.open(TARGET, 443).await.unwrap();
        opened.completion.begin();
        opened.completion.progress.tunnel.failed = Some("read");
        opened.completion.finish(Some(&Error::Session(
            crate::error::SessionError::RecordCorrupted,
        )));
    }
    assert_eq!(scheduler.projection().lead(), Some(1));
    // The setup health is still fast; it cannot clear a different failure class.
    scheduler.shared.health[0].probe_open();
    seed(&scheduler, 0, Duration::from_millis(1));
    assert_eq!(scheduler.projection().lead(), Some(1));
    assert_eq!(healthy_existing.family, AddressFamily::Ipv4);
    assert_eq!(
        scheduler.report()[0].health.failures,
        0,
        "session cost is not a setup breaker"
    );
}
