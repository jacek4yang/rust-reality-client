//! Turning one destination into one connection — the last moment where the client
//! still has a choice to make.
//!
//! Everything in this module happens *before* the local CONNECT is answered. Once
//! a socket leaves [`Dial`], the session it carries is bound to that path: v2.0.1
//! has no cross-node resume, so a byte already committed to a winner cannot be
//! moved, replayed, or duplicated elsewhere. That boundary is why the racing,
//! retrying, family-belief logic lives here and nowhere else in the client, and
//! why nothing below the inbound layer gets a second attempt at a destination it
//! has already started carrying traffic for.
//!
//! The shape of the race is v2.0.1's (`src/server/connector.rs:401-590`), because
//! that shape was chosen against real networks: one candidate starts
//! immediately, the alternate family starts [`Tuning::fallback_delay`] later, at
//! most [`MAX_IN_FLIGHT`] are ever in flight, and a candidate that fails frees its
//! slot at once rather than waiting out another delay. Two details of that loop
//! matter more than the rest:
//!
//! - A single-family plan is dialed **in order, not in parallel**. There is no
//!   other family to race, so parallel attempts would spend the same budget on
//!   duplicates and multiply the SYN count at one destination.
//! - A candidate that is still in flight when another wins is **cancelled**, and
//!   cancellation is recorded as weak slowness evidence
//!   ([`Environment::record_alternate_success`]), never as a failure of that
//!   family. Getting this backwards is how a proxy ends up penalising the stack
//!   that was merely 30 ms behind, and then refuses to use it.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{self, Instant as Timer};

use super::family::{AddressFamily, Environment, Tuning};
use super::socket;

/// How long a name lookup may take.
///
/// v2.0.1 `src/config/node/dns.rs:34` (`DEFAULT_DNS_TIMEOUT_MS`).
pub const DNS_BUDGET: Duration = Duration::from_secs(5);

/// How long one destination's whole establishment may take, across every
/// candidate it goes through.
///
/// v2.0.1 `src/config/node/outbound.rs:166` (`DEFAULT_HANDOFF_CONNECT_TIMEOUT_MS`).
/// One budget for the whole plan rather than one per candidate is what keeps a
/// host with sixteen addresses from costing sixteen timeouts.
pub const CONNECT_BUDGET: Duration = Duration::from_secs(10);

/// Candidates kept from one lookup.
///
/// A resolver answer is not trusted input: a misconfigured or hostile zone can
/// carry hundreds of records, and each one would otherwise become a plan slot, an
/// allocation, and a candidate dial. Sixteen is more addresses than any real
/// node has and less than any attack needs.
pub const MAX_CANDIDATES: usize = 16;

/// Remote candidates in flight at once.
///
/// Two reaches the other family within [`Tuning::fallback_delay`] of the first;
/// anything more is a fan-out, which is what this client is built to avoid.
const MAX_IN_FLIGHT: usize = 2;

/// Why one establishment did not happen.
#[derive(Debug)]
pub enum DialError {
    /// The node's hostname could not be resolved.
    Lookup(io::Error),
    /// Resolution did not answer inside [`DNS_BUDGET`].
    LookupTimedOut,
    /// Nothing was resolved, or nothing the dial policy may use.
    NoAddresses,
    /// [`CONNECT_BUDGET`] ran out before any candidate completed.
    TimedOut {
        /// The budget that expired, for the log line.
        budget: Duration,
    },
    /// Every candidate that was attempted failed, a connector ended by panicking,
    /// or the winner's socket could not be tuned.
    Failed {
        /// How many candidates were tried before giving up.
        attempted: usize,
        /// The last error seen, which is the one worth reporting.
        error: io::Error,
    },
}

impl fmt::Display for DialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(error) => write!(formatter, "name lookup failed: {error}"),
            Self::LookupTimedOut => {
                write!(
                    formatter,
                    "name lookup did not answer within {DNS_BUDGET:?}"
                )
            }
            Self::NoAddresses => write!(formatter, "no address this policy may dial"),
            Self::TimedOut { budget } => write!(formatter, "connect budget of {budget:?} expired"),
            Self::Failed { attempted, error } => write!(
                formatter,
                "{attempted} candidate{} failed: {error}",
                if *attempted == 1 { "" } else { "s" }
            ),
        }
    }
}

impl Error for DialError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lookup(error) | Self::Failed { error, .. } => Some(error),
            Self::LookupTimedOut | Self::NoAddresses | Self::TimedOut { .. } => None,
        }
    }
}

/// One established connection, and what choosing it learned.
#[derive(Debug)]
pub struct Dialed<T> {
    /// The value the connector produced.
    pub value: T,
    /// The address that answered.
    pub address: SocketAddr,
    /// The family the winner came from, so a caller can log the path without
    /// re-reading the socket.
    pub family: AddressFamily,
    /// Time from the winning attempt's first SYN to the established socket.
    pub latency: Duration,
}

/// Resolves, orders, races and tunes the candidate connections for one
/// destination.
///
/// One [`Dial`] is shared by every connection the process makes: the
/// [`Environment`] inside it is the whole point, since a dial that starts from
/// what the last dial learned is the difference between one slow path costing 250
/// ms once and costing it on every connection.
#[derive(Clone, Debug)]
pub struct Dial {
    environment: Environment,
    tuning: Tuning,
}

impl Dial {
    /// Binds a shared environment to one policy's timings.
    #[must_use]
    pub const fn new(environment: Environment, tuning: Tuning) -> Self {
        Self {
            environment,
            tuning,
        }
    }

    /// The shared family beliefs.
    #[must_use]
    pub const fn environment(&self) -> &Environment {
        &self.environment
    }

    /// The derived timings this dial races by.
    #[must_use]
    pub const fn tuning(&self) -> &Tuning {
        &self.tuning
    }

    /// Resolves a node hostname and dials it.
    ///
    /// # Errors
    ///
    /// See [`DialError`]. Every variant is a connection failure, not a
    /// configuration failure: by the time this is called the address was already
    /// accepted by `config`.
    pub async fn connect(&self, host: &str, port: u16) -> Result<Dialed<TcpStream>, DialError> {
        let addresses = self.resolve(host, port).await?;
        self.connect_to(&addresses).await
    }

    /// Dials an already-resolved destination.
    ///
    /// # Errors
    ///
    /// [`DialError::NoAddresses`] if nothing in `addresses` may be dialed,
    /// [`DialError::TimedOut`] if [`CONNECT_BUDGET`] runs out, and
    /// [`DialError::Failed`] if every candidate failed or the winner could not be
    /// given its socket options.
    pub async fn connect_to(
        &self,
        addresses: &[SocketAddr],
    ) -> Result<Dialed<TcpStream>, DialError> {
        // Re-observing routes belongs to the establishment, not to the racing
        // loop: keeping it here means [`Dial::race`] can be driven against a
        // stated route table, which is the only way the failure paths below are
        // provable rather than merely plausible.
        self.environment.refresh_routes(&self.tuning);
        let dialed = self.race(addresses, connect_socket).await?;
        // Armed before the caller can write a byte: the REALITY handshake is
        // sixteen record-sized bursts, and the keepalive clock counts from the
        // first silence rather than from whenever someone remembers to arm it.
        match socket::configure(&dialed.value) {
            Ok(()) => Ok(dialed),
            // A socket that cannot be tuned is dropped here, which closes it. A
            // tunnel whose peer can die silently without detection is worse than a
            // visible failure now, because the alternative is discovered as a
            // `Connection error` minutes later with the reason lost.
            Err(error) => Err(DialError::Failed {
                attempted: 1,
                error,
            }),
        }
    }

    /// Resolves under [`DNS_BUDGET`] and keeps at most [`MAX_CANDIDATES`] results.
    ///
    /// A timeout cannot cancel the lookup itself — `lookup_host` runs on a blocking
    /// thread that will finish whether or not anyone is waiting — so the bound that
    /// actually matters is the number of concurrent dials, which the inbound
    /// layer's admission limit holds down.
    ///
    /// # Errors
    ///
    /// [`DialError::LookupTimedOut`] if the resolver does not answer inside
    /// [`DNS_BUDGET`] and [`DialError::Lookup`] if it answers with a failure. An
    /// empty answer is `Ok(vec![])`, not an error: a name with no records is a
    /// resolution that worked, and the caller deciding what to dial with it is the
    /// one who knows whether that is a problem.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DialError> {
        match time::timeout(DNS_BUDGET, tokio::net::lookup_host((host, port))).await {
            Err(_elapsed) => Err(DialError::LookupTimedOut),
            Ok(Err(error)) => Err(DialError::Lookup(error)),
            Ok(Ok(addresses)) => Ok(bounded(addresses)),
        }
    }

    /// The order this dial would try `addresses` in, with nothing connected.
    ///
    /// `doctor` and `explain` read through this: an operator asking "why is the
    /// first byte slow" needs to see the plan, not infer it from traffic.
    #[must_use]
    pub fn plan(&self, addresses: &[SocketAddr]) -> Vec<SocketAddr> {
        self.environment.plan(addresses, &self.tuning)
    }

    /// Races a plan, generic over how a socket is made.
    ///
    /// The connector is a parameter rather than a call to `TcpStream::connect`
    /// because the failure paths this loop has to get right — a black-holed
    /// family, a refused destination, a candidate that never answers — are far
    /// easier to prove against injected outcomes than against a network that has
    /// to cooperate. It also does not re-observe routes, so a caller that states
    /// a route table gets exactly the behaviour that table describes.
    ///
    /// # Errors
    ///
    /// [`DialError::NoAddresses`] if the plan is empty, [`DialError::TimedOut`] if
    /// [`CONNECT_BUDGET`] runs out, and [`DialError::Failed`] with the last
    /// candidate's error if nothing that was attempted could be connected.
    pub async fn race<C, F, T>(
        &self,
        addresses: &[SocketAddr],
        connector: C,
    ) -> Result<Dialed<T>, DialError>
    where
        C: Fn(SocketAddr) -> F + Clone + Send + Sync + 'static,
        F: Future<Output = io::Result<T>> + Send + 'static,
        T: Send + 'static,
    {
        let ordered = self.environment.plan(addresses, &self.tuning);
        if ordered.is_empty() {
            return Err(DialError::NoAddresses);
        }
        if one_family(&ordered) {
            return self.dial_in_order(&ordered, connector).await;
        }
        self.race_families(&ordered, connector).await
    }

    /// One candidate after another, each inside the same budget.
    async fn dial_in_order<C, F, T>(
        &self,
        ordered: &[SocketAddr],
        connector: C,
    ) -> Result<Dialed<T>, DialError>
    where
        C: Fn(SocketAddr) -> F + Clone + Send + Sync + 'static,
        F: Future<Output = io::Result<T>> + Send,
        T: Send + 'static,
    {
        let deadline = Timer::now() + CONNECT_BUDGET;
        let mut attempted = 0;
        let mut last_error = None;
        for &address in ordered {
            let remaining = deadline.saturating_duration_since(Timer::now());
            if remaining.is_zero() {
                return Err(DialError::TimedOut {
                    budget: CONNECT_BUDGET,
                });
            }
            let family = AddressFamily::of(address.ip());
            let started = Instant::now();
            attempted += 1;
            match time::timeout(remaining, connector(address)).await {
                Ok(Ok(value)) => {
                    self.environment
                        .record_success(family, started.elapsed(), &self.tuning);
                    return Ok(Dialed {
                        value,
                        address,
                        family,
                        latency: started.elapsed(),
                    });
                }
                Ok(Err(error)) => {
                    self.environment
                        .record_connect_error(family, &error, &self.tuning);
                    last_error = Some(error);
                }
                Err(_elapsed) => {
                    return Err(DialError::TimedOut {
                        budget: CONNECT_BUDGET,
                    });
                }
            }
        }
        match last_error {
            Some(error) => Err(DialError::Failed { attempted, error }),
            None => Err(DialError::NoAddresses),
        }
    }

    /// Two families competing, second one starting a fallback delay behind the
    /// first and never more than [`MAX_IN_FLIGHT`] attempts in flight.
    async fn race_families<C, F, T>(
        &self,
        ordered: &[SocketAddr],
        connector: C,
    ) -> Result<Dialed<T>, DialError>
    where
        C: Fn(SocketAddr) -> F + Clone + Send + Sync + 'static,
        F: Future<Output = io::Result<T>> + Send + 'static,
        T: Send + 'static,
    {
        let deadline = Timer::now() + CONNECT_BUDGET;
        let mut tasks = JoinSet::new();
        let mut active: Vec<SocketAddr> = Vec::with_capacity(MAX_IN_FLIGHT);
        let mut next = 0;
        let mut launch_at = Timer::now();
        let mut attempted = 0;
        let mut last_error = None;

        loop {
            while next < ordered.len() && tasks.len() < MAX_IN_FLIGHT && Timer::now() >= launch_at {
                let address = ordered[next];
                next += 1;
                attempted += 1;
                active.push(address);
                let connect = connector.clone();
                tasks.spawn(async move {
                    let started = Instant::now();
                    match connect(address).await {
                        Ok(value) => Finished::Success {
                            address,
                            started,
                            value,
                        },
                        Err(error) => Finished::Failed { address, error },
                    }
                });
                launch_at = Timer::now() + self.tuning.fallback_delay;
            }
            if tasks.is_empty() {
                return Err(match last_error {
                    Some(error) => DialError::Failed { attempted, error },
                    None => DialError::NoAddresses,
                });
            }

            tokio::select! {
                () = time::sleep_until(deadline) => {
                    // Everything still in flight is closed before this returns, so a
                    // destination cannot accumulate half-open attempts from a
                    // connection the caller has already given up on.
                    drain(&mut tasks).await;
                    return Err(DialError::TimedOut { budget: CONNECT_BUDGET });
                }
                completed = tasks.join_next() => {
                    let Some(completed) = completed else {
                        continue;
                    };
                    let finished = match completed {
                        Ok(finished) => finished,
                        Err(error) => {
                            // A connector that panicked. Reported rather
                            // than swallowed: the other candidates are
                            // aborted too, because the state this loop trusts
                            // to keep them bounded is no longer trustworthy.
                            drain(&mut tasks).await;
                            return Err(DialError::Failed {
                                attempted,
                                error: io::Error::other(format!("attempt ended early: {error}")),
                            });
                        }
                    };
                    match finished {
                        Finished::Success {
                            address,
                            started,
                            value,
                        } => {
                            remove(&mut active, address);
                            let family = AddressFamily::of(address.ip());
                            let latency = started.elapsed();
                            self.environment
                                .record_success(family, latency, &self.tuning);
                            self.record_cancelled_rivals(&active, family);
                            drain(&mut tasks).await;
                            return Ok(Dialed {
                                value,
                                address,
                                family,
                                latency,
                            });
                        }
                        Finished::Failed { address, error } => {
                            remove(&mut active, address);
                            self.environment.record_connect_error(
                                AddressFamily::of(address.ip()),
                                &error,
                                &self.tuning,
                            );
                            last_error = Some(error);
                            // A failure frees its slot now. Waiting out another
                            // fallback delay before trying the next address is a
                            // quarter second of dead time on a plan that still has
                            // candidates, and a stalled dial is exactly what this
                            // layer exists to shorten.
                            launch_at = Timer::now();
                        }
                    }
                }
                // Waiting for the next launch slot while nothing has answered, so a
                // destination that hangs on the first family still reaches the
                // second one on time.
                () = time::sleep_until(launch_at),
                    if next < ordered.len() && tasks.len() < MAX_IN_FLIGHT => {}
            }
        }
    }

    /// What the still-in-flight rivals say, given that one of them lost a race
    /// rather than failing.
    fn record_cancelled_rivals(&self, active: &[SocketAddr], winner: AddressFamily) {
        for &address in active {
            let family = AddressFamily::of(address.ip());
            if family != winner {
                // Weak evidence only, and only against the winner being slow: a
                // cancelled candidate proved nothing except that it had not
                // answered yet.
                self.environment.record_alternate_success(winner, family);
            }
        }
    }
}

/// One attempt's outcome, kept together with what it says about a family.
enum Finished<T> {
    Success {
        address: SocketAddr,
        started: Instant,
        value: T,
    },
    Failed {
        address: SocketAddr,
        error: io::Error,
    },
}

async fn connect_socket(address: SocketAddr) -> io::Result<TcpStream> {
    TcpStream::connect(address).await
}

fn bounded<I: Iterator<Item = SocketAddr>>(addresses: I) -> Vec<SocketAddr> {
    // Stopping at the limit rather than collecting and truncating: the extra
    // records would have been allocated just to be thrown away.
    addresses.take(MAX_CANDIDATES).collect()
}

fn one_family(ordered: &[SocketAddr]) -> bool {
    let Some(first) = ordered.first() else {
        return true;
    };
    let family = AddressFamily::of(first.ip());
    ordered
        .iter()
        .all(|address| AddressFamily::of(address.ip()) == family)
}

fn remove(active: &mut Vec<SocketAddr>, address: SocketAddr) {
    if let Some(index) = active.iter().position(|waiting| *waiting == address) {
        active.swap_remove(index);
    }
}

/// Aborts every outstanding attempt and waits for each to really close.
async fn drain<T: Send + 'static>(tasks: &mut JoinSet<Finished<T>>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests;
