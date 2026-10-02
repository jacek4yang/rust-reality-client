//! Every outcome below is injected rather than hoped for.
//!
//! What is under test is what the race does when a path hangs, refuses,
//! black-holes or panics, and a network cannot be asked to provide those on
//! schedule. So the connector is a script: one stated outcome per address,
//! counted through a [`Ledger`] that records how many attempts were live at once,
//! which addresses were touched, in what order, and which of them ever finished.
//! The clock is tokio's paused one, which turns a 250 ms fallback delay and a 10 s
//! budget into microseconds of real time and no scheduler jitter.
//!
//! The two properties that get the most space are the asymmetric ones: that a
//! candidate cancelled by a winner is charged as slowness and never as a failure,
//! and that nothing is still running once the race has returned.

use std::collections::HashMap;
use std::error::Error as _;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::time::{self, Instant as Virtual};

use super::{
    AddressFamily, CONNECT_BUDGET, Dial, DialError, Environment, MAX_CANDIDATES, MAX_IN_FLIGHT,
    Tuning, bounded,
};
use crate::transport::family::DialPolicy;

/// Long enough that a hanging candidate can only leave the race by being
/// cancelled, never by answering.
const HANG: Duration = Duration::from_secs(3600);

/// One attempt's outcome, boxed so that every address can share a single future
/// type without the test suite acquiring a dependency for `BoxFuture`.
type Boxed = Pin<Box<dyn Future<Output = io::Result<SocketAddr>> + Send + 'static>>;

/// What one injected address does when it is dialed.
#[derive(Clone, Copy)]
enum Outcome {
    /// Establishes the moment it is polled.
    Answer,
    /// Never establishes; only cancellation ends it.
    Hang,
    /// Fails after a while, which is how a merely slow path looks.
    Stall(Duration),
    /// Fails like a family with no route: `ENETUNREACH`.
    Unroutable,
    /// Fails like a live path with nothing listening: `ECONNREFUSED`.
    Refused,
    /// Fails like a black hole, which proves nothing about the family.
    Silence,
    /// Panics on the first poll, the way a broken connector does.
    Panic,
}

impl Outcome {
    fn run(self, address: SocketAddr, ledger: &Ledger) -> Boxed {
        let ledger = ledger.clone();
        Box::pin(async move {
            // Counted on the first poll, not at construction: a candidate that is
            // planned but never started has not cost anything yet.
            let guard = ledger.enter(address);
            let outcome = match self {
                Self::Answer => {
                    ledger.answered.fetch_add(1, Ordering::Relaxed);
                    Ok(address)
                }
                Self::Hang => {
                    time::sleep(HANG).await;
                    Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "injected hang was never cancelled",
                    ))
                }
                Self::Stall(after) => {
                    time::sleep(after).await;
                    Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "injected stall, not a budget",
                    ))
                }
                Self::Unroutable => Err(io::Error::new(
                    ErrorKind::NetworkUnreachable,
                    "injected route failure",
                )),
                Self::Refused => Err(io::Error::new(
                    ErrorKind::ConnectionRefused,
                    "injected refusal",
                )),
                Self::Silence => Err(io::Error::new(ErrorKind::TimedOut, "injected timeout")),
                Self::Panic => panic!("injected connector panic"),
            };
            // The guard leaves with the attempt whether it finished or was
            // cancelled, which is what makes [`Ledger::live`] a measurement of
            // outstanding work rather than of started work.
            drop(guard);
            outcome
        })
    }
}

/// Counters describing what a race really did, not what it returned.
#[derive(Clone, Default)]
struct Ledger {
    started: Arc<AtomicUsize>,
    answered: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    order: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Ledger {
    fn enter(&self, address: SocketAddr) -> Attempt {
        self.started.fetch_add(1, Ordering::Relaxed);
        let running = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(running, Ordering::SeqCst);
        self.order.lock().expect("attempt order").push(address);
        Attempt {
            live: Arc::clone(&self.live),
        }
    }

    fn started(&self) -> usize {
        self.started.load(Ordering::Relaxed)
    }

    fn answered(&self) -> usize {
        self.answered.load(Ordering::Relaxed)
    }

    /// Attempts running right now. Anything above zero after a race has returned
    /// is a half-open socket at the destination and a task the process keeps
    /// forever.
    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    fn order(&self) -> Vec<SocketAddr> {
        self.order.lock().expect("attempt order").clone()
    }
}

/// One live attempt, so that cancellation is visible as a count going down.
struct Attempt {
    live: Arc<AtomicUsize>,
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A connector that scripts each address from `entries` and counts every attempt.
///
/// Addresses absent from the table answer at once, so a test only states the
/// addresses it cares about.
fn scripted(
    ledger: Ledger,
    entries: &[(SocketAddr, Outcome)],
) -> impl Fn(SocketAddr) -> Boxed + Clone + Send + Sync + 'static {
    let table: Arc<HashMap<SocketAddr, Outcome>> =
        Arc::new(entries.iter().copied().collect::<HashMap<_, _>>());
    move |address| {
        let outcome = table.get(&address).copied().unwrap_or(Outcome::Answer);
        outcome.run(address, &ledger)
    }
}

/// Both routes up, both families allowed, starting from `primary`.
fn dual_stack(primary: AddressFamily) -> Dial {
    Dial::new(
        Environment::with_routes_and_primary(DialPolicy::Auto, true, true, primary),
        Tuning::for_policy(DialPolicy::Auto),
    )
}

fn v4(index: u8) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(192, 0, 2, index).into(), 443)
}

fn v6(index: u8) -> SocketAddr {
    SocketAddr::new(
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, u16::from(index)).into(),
        443,
    )
}

#[tokio::test(start_paused = true)]
async fn a_live_ipv4_is_not_made_to_wait_for_the_family_that_hangs() {
    let dial = dual_stack(AddressFamily::Ipv4);
    let ledger = Ledger::default();
    let started_at = Virtual::now();
    let addresses = [v4(1), v6(1)];
    let connect = scripted(
        ledger.clone(),
        &[(v4(1), Outcome::Answer), (v6(1), Outcome::Hang)],
    );

    let winner = dial
        .race(&addresses, connect)
        .await
        .expect("the IPv4 candidate answers");

    assert_eq!(winner.address, v4(1));
    assert_eq!(winner.family, AddressFamily::Ipv4);
    assert_eq!(winner.value, v4(1));
    assert_eq!(
        ledger.started(),
        1,
        "the race ended before the fallback delay, so the IPv6 candidate should never \
         have been dialed at all"
    );
    assert!(
        started_at.elapsed() < dial.tuning().fallback_delay,
        "a working first family must not pay for the second family's head start"
    );
    assert!(
        !dial
            .environment()
            .is_penalized(AddressFamily::Ipv6, dial.tuning()),
        "an undialed family has proved nothing"
    );
}

#[tokio::test(start_paused = true)]
async fn a_candidate_cancelled_by_a_winner_is_slowness_evidence_never_a_failure() {
    let dial = dual_stack(AddressFamily::Ipv6);
    let addresses = [v6(1), v4(1)];
    let connect = scripted(
        Ledger::default(),
        &[(v6(1), Outcome::Hang), (v4(1), Outcome::Answer)],
    );

    for attempt in 1..=2 {
        let winner = dial
            .race(&addresses, connect.clone())
            .await
            .expect("IPv4 answers");
        assert_eq!(winner.value, v4(1));
        assert_eq!(
            dial.environment().primary(),
            AddressFamily::Ipv6,
            "the demotion takes three wins, not {attempt}"
        );
        assert!(
            !dial
                .environment()
                .is_penalized(AddressFamily::Ipv6, dial.tuning()),
            "a candidate cancelled while still in flight proved nothing about its \
             family, and charging it as a failure is how a proxy ends up refusing the \
             stack that was merely 30 ms behind"
        );
        assert!(
            dial.environment()
                .recent_latency(AddressFamily::Ipv6, dial.tuning())
                .is_none(),
            "the cancelled family was never measured, so it has no latency to remember"
        );
    }

    let winner = dial
        .race(&addresses, connect)
        .await
        .expect("IPv4 answers a third time");

    assert_eq!(winner.value, v4(1));
    assert_eq!(
        dial.environment().primary(),
        AddressFamily::Ipv4,
        "three wins against a still-pending primary is the weak signal that switches it"
    );
    assert!(
        !dial
            .environment()
            .is_penalized(AddressFamily::Ipv6, dial.tuning()),
        "switching on slowness leaves IPv6 dialable, which is the point: it may simply \
         have been the family that had not answered yet"
    );
}

#[tokio::test(start_paused = true)]
async fn one_family_is_dialed_in_order_and_never_two_at_once() {
    let dial = dual_stack(AddressFamily::Ipv4);
    let ledger = Ledger::default();
    let connect = scripted(
        ledger.clone(),
        &[
            (v4(3), Outcome::Refused),
            (v4(1), Outcome::Silence),
            (v4(2), Outcome::Answer),
        ],
    );

    let winner = dial
        .race(&[v4(3), v4(1), v4(2)], connect)
        .await
        .expect("the last candidate answers");

    assert_eq!(winner.address, v4(2));
    assert_eq!(
        ledger.order(),
        vec![v4(3), v4(1), v4(2)],
        "a single-family plan is walked in the order the plan put them in, not in \
         parallel: there is no other family to race, and duplicating attempts at one \
         destination multiplies SYNs for nothing"
    );
    assert_eq!(ledger.peak(), 1, "one attempt at a time");
    assert_eq!(ledger.started(), 3);
    assert_eq!(ledger.live(), 0);
    assert!(
        !dial
            .environment()
            .is_penalized(AddressFamily::Ipv4, dial.tuning()),
        "a refusal and a bare timeout are not route evidence"
    );
}

#[tokio::test(start_paused = true)]
async fn the_connect_budget_covers_the_whole_plan_not_one_candidate() {
    let dial = dual_stack(AddressFamily::Ipv4);
    let ledger = Ledger::default();
    // Each candidate would finish inside the budget on its own; two of them
    // together do not, and that has to be the plan's problem rather than each
    // candidate's, or a host with sixteen slow addresses would cost sixteen
    // timeouts.
    let most_of_the_budget = CONNECT_BUDGET / 2 + Duration::from_millis(1);
    let connect = scripted(
        ledger.clone(),
        &[
            (v4(1), Outcome::Stall(most_of_the_budget)),
            (v4(2), Outcome::Stall(most_of_the_budget)),
        ],
    );

    let error = dial
        .race(&[v4(1), v4(2)], connect)
        .await
        .expect_err("the shared budget runs out during the second candidate");

    assert!(
        matches!(error, DialError::TimedOut { budget } if budget == CONNECT_BUDGET),
        "the plan reports the budget that expired, not the injected stall: {error}"
    );
    assert_eq!(ledger.started(), 2, "both candidates were attempted");
    assert_eq!(ledger.live(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_race_that_runs_out_of_time_leaves_nothing_connected() {
    let dial = dual_stack(AddressFamily::Ipv6);
    let ledger = Ledger::default();
    let connect = scripted(
        ledger.clone(),
        &[(v6(1), Outcome::Hang), (v4(1), Outcome::Hang)],
    );

    let error = dial
        .race(&[v6(1), v4(1)], connect)
        .await
        .expect_err("nothing answers at all");

    assert!(
        matches!(error, DialError::TimedOut { .. }),
        "expected the budget to expire, got {error}"
    );
    assert_eq!(ledger.started(), MAX_IN_FLIGHT);
    assert_eq!(
        ledger.peak(),
        MAX_IN_FLIGHT,
        "two families reach each other inside the fallback delay and no more"
    );
    assert_eq!(ledger.answered(), 0);
    assert_eq!(
        ledger.live(),
        0,
        "an attempt still running after the caller gave up is a half-open socket at \
         the destination from a connection nobody will carry"
    );
}

#[tokio::test(start_paused = true)]
async fn a_plan_with_nothing_in_it_says_so_without_dialing() {
    let ledger = Ledger::default();
    let dial = dual_stack(AddressFamily::Ipv4);
    let error = dial
        .race(&[], scripted(ledger.clone(), &[]))
        .await
        .expect_err("the resolver answered with nothing");
    assert!(matches!(error, DialError::NoAddresses), "got {error}");

    // The dial policy is the only reason an address is ever dropped from a plan,
    // and when it leaves nothing behind that has to be said plainly rather than
    // dressed up as a connection failure.
    let v4_only = Dial::new(
        Environment::with_routes_and_primary(DialPolicy::Ipv4Only, true, true, AddressFamily::Ipv4),
        Tuning::for_policy(DialPolicy::Ipv4Only),
    );
    let addresses = [v6(1), v6(2)];
    let error = v4_only
        .race(&addresses, scripted(ledger.clone(), &[]))
        .await
        .expect_err("only IPv6 was resolved, and the policy refuses it");

    assert!(matches!(error, DialError::NoAddresses), "got {error}");
    assert_eq!(
        ledger.started(),
        0,
        "a plan this short must not touch the network at all"
    );
}

#[tokio::test(start_paused = true)]
async fn two_route_shaped_failures_move_the_next_race_to_the_other_family() {
    let dial = dual_stack(AddressFamily::Ipv4);
    let ledger = Ledger::default();
    let connect = scripted(
        ledger.clone(),
        &[(v4(1), Outcome::Unroutable), (v4(2), Outcome::Unroutable)],
    );

    let error = dial
        .race(&[v4(1), v4(2)], connect)
        .await
        .expect_err("neither candidate has a route");

    assert!(
        matches!(error, DialError::Failed { attempted, .. } if attempted == 2),
        "got {error}"
    );
    assert!(
        dial.environment()
            .is_penalized(AddressFamily::Ipv4, dial.tuning()),
        "two consecutive route-shaped errors are the threshold, and one is not"
    );
    assert_eq!(dial.environment().primary(), AddressFamily::Ipv6);
    assert_eq!(
        dial.plan(&[v4(1), v6(1)]),
        vec![v6(1), v4(1)],
        "the penalised family is still in the plan, just second"
    );
    assert_eq!(
        ledger.started(),
        2,
        "the strikes came from this race's own attempts, not from a guess"
    );
}

#[tokio::test(start_paused = true)]
async fn a_connector_that_panics_ends_the_race_instead_of_hanging_it() {
    // This test makes the default panic hook print once. That message is the
    // behaviour under test, not a failure of the suite.
    let dial = dual_stack(AddressFamily::Ipv4);
    let ledger = Ledger::default();
    let connect = scripted(
        ledger.clone(),
        &[(v4(1), Outcome::Panic), (v6(1), Outcome::Hang)],
    );

    let error = dial
        .race(&[v4(1), v6(1)], connect)
        .await
        .expect_err("the first attempt panics instead of connecting");

    assert!(
        matches!(error, DialError::Failed { attempted, .. } if attempted == 1),
        "a panic has to surface as a failure rather than as a timeout: {error}"
    );
    assert!(
        error.to_string().contains("attempt ended early"),
        "the cause has to be readable in the line an operator sees: {error}"
    );
    assert_eq!(
        ledger.live(),
        0,
        "the other candidate is aborted too: the loop can no longer trust the state it \
         uses to keep attempts bounded"
    );
}

#[test]
fn a_resolver_answer_is_cut_off_at_the_candidate_limit() {
    let mut pulled = 0_usize;
    let addresses = (1..=64_u8).map(|index| {
        pulled += 1;
        v4(index)
    });

    let kept = bounded(addresses);

    assert_eq!(kept.len(), MAX_CANDIDATES);
    assert_eq!(
        pulled, MAX_CANDIDATES,
        "the limit has to stop the walk, not trim a list that was already built"
    );
    assert_eq!(kept.first().copied(), Some(v4(1)));
}

#[test]
fn each_failure_says_what_it_knows() {
    let error = DialError::Failed {
        attempted: 2,
        error: io::Error::new(ErrorKind::ConnectionRefused, "nothing listening"),
    };
    assert_eq!(error.to_string(), "2 candidates failed: nothing listening");
    assert!(
        error.source().is_some(),
        "the refusal has to stay reachable for any caller that walks the cause chain"
    );

    let singular = DialError::Failed {
        attempted: 1,
        error: io::Error::new(ErrorKind::TimedOut, "quiet"),
    };
    assert_eq!(singular.to_string(), "1 candidate failed: quiet");

    let budget = DialError::TimedOut {
        budget: CONNECT_BUDGET,
    };
    assert_eq!(budget.to_string(), "connect budget of 10s expired");
    assert!(budget.source().is_none());
    assert_eq!(
        DialError::LookupTimedOut.to_string(),
        "name lookup did not answer within 5s"
    );
    assert_eq!(
        DialError::NoAddresses.to_string(),
        "no address this policy may dial"
    );
}

#[tokio::test]
async fn the_winner_leaves_with_the_socket_options_armed() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let accepted = tokio::spawn(async move {
        let (server, _peer) = listener.accept().await.expect("accept");
        server
    });
    let dial = Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    );

    let dialed = dial
        .connect_to(&[address])
        .await
        .expect("a loopback listener is dialable");

    assert_eq!(dialed.address, address);
    assert_eq!(dialed.family, AddressFamily::Ipv4);
    assert_eq!(dialed.value.peer_addr().expect("peer address"), address);
    // A fresh socket's `TCP_NODELAY` is off on every platform this client ships
    // on, so reading it back true is proof that `connect_to` tuned the winner
    // rather than handing the race result straight over. The keepalive half of
    // the same call is proven in `socket`'s tests, because Windows can set
    // keepalive but cannot read it back.
    assert!(dialed.value.nodelay().expect("TCP_NODELAY read"));
    assert!(
        dial.environment()
            .recent_latency(AddressFamily::Ipv4, dial.tuning())
            .is_some(),
        "the dial that worked is the measurement the next dial starts from"
    );

    let server = accepted.await.expect("accept task");
    drop(server);
}
