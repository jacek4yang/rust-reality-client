//! The process: what it listens on, what one local connection costs, and how it
//! stops.
//!
//! Everything below [`inbound`](crate::inbound) is a decision the layers already
//! made; this module's job is to make sure no answer gets lost. An
//! [`Outcome`](crate::inbound::socks5::Outcome) is only useful if somebody counts
//! it and logs it, so the accept loop is written as a funnel: one task per local
//! connection, and every task's last act is one call that adds to the counters and
//! emits one line. There is no path where a finished exchange is dropped, and that
//! is the whole reason this module exists.
//!
//! Two things are deliberately *not* decided here:
//!
//! * **Which node serves a connection.** The inbounds ask
//!   [`Establish`](crate::inbound::Establish) and the scheduler answers; by the
//!   time a connection reaches this loop the node is already chosen, and by the
//!   time the local client is told `succeeded` it is immutable.
//! * **What the limits are.** One [`Gate`](crate::inbound::Gate) is shared by both
//!   inbounds, so 256 local connections is a process-wide budget rather than 256
//!   per listener. A second, larger ceiling — [`MAX_PENDING_LOCAL`] — bounds only
//!   how many sockets may be *tracked* before admission, which is the part a local
//!   process can grow without ever touching a permit.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time;

use crate::config::{Config, Listen};
use crate::error::Error;
use crate::handoff::Handoff;
use crate::inbound::{Gate, http, socks5};
use crate::logging::{Level, Logger};
use crate::scheduler::Scheduler;
use crate::transport::{Dial, DialPolicy, Environment, Tuning};

/// How long a connection may take to wind down after a stop was requested.
///
/// This is a bound rather than a promise that every connection gets to finish: the
/// longest a single exchange can legitimately still be inside is a dial plus
/// [`FIRST_BYTE_BUDGET`](crate::handoff::FIRST_BYTE_BUDGET), which together are more
/// than ten seconds. Ten is roughly what a supervisor waits before it sends
/// `SIGKILL` anyway, so a connection that has not reported by then is cancelled and
/// counted in [`Report::unresolved`] rather than allowed to hold the process open.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// The most local sockets this loop will track at once.
///
/// [`MAX_LOCAL_CONNECTIONS`](crate::inbound::MAX_LOCAL_CONNECTIONS) bounds the
/// work; this bounds the *waiting*, which a local process can inflate by opening
/// sockets and then never sending a greeting. A parked task costs its own stack and
/// a descriptor, and the parked ones are not yet the admitted ones.
pub const MAX_PENDING_LOCAL: usize = 1024;

/// The first pause after a failed `accept`, doubled up to [`ACCEPT_BACKOFF_MAX`].
const ACCEPT_BACKOFF: Duration = Duration::from_millis(5);

/// The ceiling for that pause: long enough to stop a spin, short enough that a
/// descriptor which comes back is noticed at once.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_millis(1000);

/// The number of consecutive `accept` failures after which the log stops saying
/// `warn`, on the grounds that a fourth one is not a different problem.
const ACCEPT_NOISE: u32 = 4;

/// What a person at a terminal sends.
const INTERRUPT: &str = "interrupt";
/// What a supervisor sends, on the platforms that have the word.
#[cfg(unix)]
const TERMINATE: &str = "terminate";

/// What the process has done with local connections so far.
///
/// Counters rather than a log reader, so a soak test or `doctor` can ask the
/// running process instead of scraping its stderr.
#[derive(Default)]
struct Stats {
    accepted: AtomicU64,
    carried: AtomicU64,
    refused: AtomicU64,
    failed: AtomicU64,
    unresolved: AtomicU64,
}

impl Stats {
    fn report(&self) -> Report {
        Report {
            accepted: self.accepted.load(Ordering::Relaxed),
            carried: self.carried.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            unresolved: self.unresolved.load(Ordering::Relaxed),
        }
    }
}

/// Charges one connection to one counter.
///
/// A counter is bumped by the task that owns the connection, at the moment its
/// outcome is known, so a number in a [`Report`] always has a line behind it.
fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// What happened to the local connections of one run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Sockets accepted and handed a task.
    pub accepted: u64,
    /// Exchanges that confirmed a tunnel and then finished both directions.
    pub carried: u64,
    /// Exchanges the edge answered itself: a bad request, a refusal, a hang-up.
    pub refused: u64,
    /// Exchanges where a node was asked, or a tunnel was up, and something failed.
    pub failed: u64,
    /// Connections whose task never reported: cancelled during the shutdown grace,
    /// or panicked. A number above zero is a fact about this process rather than
    /// about the network, and it is the one entry in a report that should never
    /// grow.
    pub unresolved: u64,
}

/// Which edge a listener speaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Socks5,
    Http,
}

impl Kind {
    #[must_use]
    const fn label(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
        }
    }
}

/// One finished exchange, in the one shape this loop needs.
///
/// Both inbounds answer with their own `Outcome`, whose refusal code is a SOCKS5
/// reply byte in one and an HTTP status in the other. Folding them here is what lets
/// a single `record` call be the only consumer of an outcome: the compiler checks the
/// fold, so the fold cannot be skipped.
enum Finished {
    Carried {
        inbound: Kind,
        to_remote: u64,
        to_local: u64,
    },
    Refused {
        inbound: Kind,
        code: Option<u32>,
        reason: &'static str,
    },
    Failed {
        inbound: Kind,
        error: Error,
    },
}

impl From<socks5::Outcome> for Finished {
    fn from(outcome: socks5::Outcome) -> Self {
        match outcome {
            socks5::Outcome::Carried(bytes) => Self::Carried {
                inbound: Kind::Socks5,
                to_remote: bytes.to_remote,
                to_local: bytes.to_local,
            },
            socks5::Outcome::Refused { rep, reason } => Self::Refused {
                inbound: Kind::Socks5,
                code: rep.map(u32::from),
                reason,
            },
            socks5::Outcome::Failed(error) => Self::Failed {
                inbound: Kind::Socks5,
                error,
            },
        }
    }
}

impl From<http::Outcome> for Finished {
    fn from(outcome: http::Outcome) -> Self {
        match outcome {
            http::Outcome::Carried(bytes) => Self::Carried {
                inbound: Kind::Http,
                to_remote: bytes.to_remote,
                to_local: bytes.to_local,
            },
            http::Outcome::Refused { status, reason } => Self::Refused {
                inbound: Kind::Http,
                code: status.map(u32::from),
                reason,
            },
            http::Outcome::Failed(error) => Self::Failed {
                inbound: Kind::Http,
                error,
            },
        }
    }
}

impl Finished {
    /// Charges one connection to the counters and says one line about it.
    ///
    /// A carried connection is `debug`: it is the normal case, and a browser page
    /// load is fifty of them. A refusal is `info`, because an operator pointing an
    /// application at this proxy wants to see what the edge said no to. A failure is
    /// `warn` with the family and whose fault it is, which is the whole content of
    /// the answer to "why does this connection break".
    fn record(self, stats: &Stats, logger: &Logger, started: Instant) {
        match self {
            Self::Carried {
                inbound,
                to_remote,
                to_local,
            } => {
                bump(&stats.carried);
                logger
                    .event_at(Level::Debug, "carried")
                    .text("inbound", inbound.label())
                    .duration("elapsed", started.elapsed())
                    .count("toRemote", to_remote)
                    .count("toLocal", to_local)
                    .emit();
            }
            Self::Refused {
                inbound,
                code,
                reason,
            } => {
                bump(&stats.refused);
                let mut event = logger
                    .event_at(Level::Info, "refused")
                    .text("inbound", inbound.label())
                    .text("reason", reason);
                if let Some(code) = code {
                    event = event.count("code", u64::from(code));
                }
                event.emit();
            }
            Self::Failed { inbound, error } => {
                bump(&stats.failed);
                logger
                    .event_at(Level::Warn, "failed")
                    .text("inbound", inbound.label())
                    .failure("error", &error)
                    .duration("elapsed", started.elapsed())
                    .emit();
            }
        }
    }
}

/// The shared machinery behind both listeners.
///
/// Cloning is what the accept loop does per listener: the nodes, the limits and the
/// counters are all behind `Arc`s, so a clone is another handle on the same one
/// process.
#[derive(Clone)]
struct Service {
    gate: Gate,
    socks5: socks5::Proxy<Scheduler<Handoff>>,
    http: http::Proxy<Scheduler<Handoff>>,
    logger: Logger,
    stats: Arc<Stats>,
}

impl Service {
    /// Builds one scheduler over one dial, and both edges over that scheduler.
    ///
    /// The dial is built from what this machine's routes say rather than from a
    /// guess: which family answers is a fact about the network, and the two edges
    /// have to share one belief about it.
    fn new(config: &Config, logger: Logger) -> Self {
        let mode = DialPolicy::default();
        let dial = Dial::new(Environment::detect(mode), Tuning::for_policy(mode));
        let scheduler = Scheduler::from_config(config, &dial);
        let gate = Gate::default();
        Self {
            gate: gate.clone(),
            socks5: socks5::Proxy::new(scheduler.clone(), gate.clone()),
            http: http::Proxy::new(scheduler, gate),
            logger,
            stats: Arc::new(Stats::default()),
        }
    }

    /// Runs one listener until a stop is requested, then winds its connections down
    /// under [`SHUTDOWN_GRACE`].
    async fn accept(self, inbound: Inbound, mut stopping: watch::Receiver<bool>) {
        let mut connections = JoinSet::new();
        let mut backoff = ACCEPT_BACKOFF;
        let mut consecutive = 0;
        loop {
            let accepted = tokio::select! {
                biased;
                // `accept` is cancellation-safe, and `biased` polls the stop
                // request first, so a connection is never taken from the queue and
                // then dropped because somebody pressed `Ctrl-C` in the same
                // instant. A `watch` whose sender is gone means nobody is left who
                // can ask, which is the other way this loop has to end.
                changed = stopping.changed() => {
                    if changed.is_err() || *stopping.borrow_and_update() {
                        break;
                    }
                    continue;
                }
                result = inbound.listener.accept() => result,
            };
            match accepted {
                Ok((stream, peer)) => {
                    backoff = ACCEPT_BACKOFF;
                    consecutive = 0;
                    self.admit(&mut connections, inbound.kind, stream, peer);
                }
                Err(error) => {
                    consecutive += 1;
                    backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                    let level = if consecutive < ACCEPT_NOISE {
                        Level::Warn
                    } else {
                        Level::Error
                    };
                    self.note_accept_failure(
                        inbound.kind.label(),
                        &error.to_string(),
                        level,
                        backoff,
                    );
                    time::sleep(backoff).await;
                }
            }
        }
        // Stop accepting first, then give what is running the grace. Whatever is
        // still going past it is cancelled, and a cancelled task is precisely a
        // connection that never reported: `join_next` is cancellation-safe, so the
        // timeout below cannot lose one on its way out.
        if time::timeout(SHUTDOWN_GRACE, self.drain(&mut connections))
            .await
            .is_err()
        {
            connections.abort_all();
            self.drain(&mut connections).await;
        }
    }

    /// Reaps finished connection tasks until the set is empty, counting the ones
    /// that ended without recording an outcome.
    async fn drain(&self, connections: &mut JoinSet<()>) {
        while let Some(joined) = connections.join_next().await {
            if joined.is_err() {
                bump(&self.stats.unresolved);
            }
        }
    }

    /// Says one line about a failed `accept`, including how long the loop waits.
    ///
    /// The message comes from the operating system and quotes no credential: it
    /// names a descriptor, a limit or an address, and this process's own bind
    /// address is information the operator already has.
    fn note_accept_failure(
        &self,
        inbound: &'static str,
        reason: &str,
        level: Level,
        retry_in: Duration,
    ) {
        self.logger
            .event_at(level, "acceptFailed")
            .text("inbound", inbound)
            .text("reason", reason)
            .duration("retryIn", retry_in)
            .emit();
    }

    /// Hands one accepted socket to a task, or closes it on the spot.
    fn admit(
        &self,
        connections: &mut JoinSet<()>,
        kind: Kind,
        mut stream: TcpStream,
        peer: SocketAddr,
    ) {
        if connections.len() >= MAX_PENDING_LOCAL {
            bump(&self.stats.refused);
            self.logger
                .event_at(Level::Warn, "refused")
                .text("inbound", kind.label())
                .text("reason", "the pending local table is full")
                .emit();
            return;
        }
        // A proxy that adds a Nagle round trip to every small request looks like a
        // broken network, and the relay's cost is per-chunk copies either way.
        let _ = stream.set_nodelay(true);
        bump(&self.stats.accepted);
        self.logger
            .event_at(Level::Debug, "accepted")
            .text("inbound", kind.label())
            .text("peer", &peer.to_string())
            .emit();
        let service = self.clone();
        let bound = local_end(&stream);
        connections.spawn(async move {
            let started = Instant::now();
            let outcome = match kind {
                Kind::Socks5 => Finished::from(service.socks5.handle(&mut stream, bound).await),
                Kind::Http => Finished::from(service.http.handle(stream).await),
            };
            outcome.record(&service.stats, &service.logger, started);
        });
    }
}

impl fmt::Debug for Service {
    /// The shape of the machinery, never a node name or a destination.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Service")
            .field("connectionsAvailable", &self.gate.connections_available())
            .field("handshakesAvailable", &self.gate.handshakes_available())
            .field("level", &self.logger.level())
            .field("report", &self.stats.report())
            .finish_non_exhaustive()
    }
}

/// This process's end of the accepted socket, which is what SOCKS5 echoes back as
/// `BND.ADDR` and `BND.PORT`.
///
/// A socket this new always has a local address; the fallback exists so that the one
/// case where the kernel says otherwise costs a wrong echo rather than a process. No
/// client acts on `BND.PORT` for a `CONNECT`.
fn local_end(stream: &TcpStream) -> SocketAddr {
    stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
}

/// A listener this process holds.
struct Inbound {
    listener: TcpListener,
    address: SocketAddr,
    kind: Kind,
}

/// The running server: the listeners it holds, and the handle that stops them.
pub struct Server {
    service: Service,
    inbounds: Vec<Inbound>,
    shutdown: watch::Sender<bool>,
}

impl Server {
    /// Binds every address the configuration asks for.
    ///
    /// # Errors
    ///
    /// [`StartError::NothingToListen`] when both inbounds are disabled, and
    /// [`StartError::Bind`] for the first address that could not be taken — which
    /// is nearly always a port something else already holds.
    pub async fn start(config: &Config, logger: Logger) -> Result<Self, StartError> {
        let service = Service::new(config, logger);
        let mut inbounds = Vec::new();
        for (kind, asked) in planned(&config.listen) {
            let listener = TcpListener::bind(asked)
                .await
                .map_err(|error| bind_failed(asked, &error))?;
            // Report what the socket actually holds, so the log line and
            // `addresses()` describe the listener that exists rather than the one
            // that was asked for.
            let address = listener
                .local_addr()
                .map_err(|error| bind_failed(asked, &error))?;
            service
                .logger
                .event_at(Level::Info, "bound")
                .text("inbound", kind.label())
                .text("address", &address.to_string())
                .count(
                    "nodes",
                    u64::try_from(config.nodes.len()).unwrap_or(u64::MAX),
                )
                .emit();
            inbounds.push(Inbound {
                listener,
                address,
                kind,
            });
        }
        if inbounds.is_empty() {
            return Err(StartError::NothingToListen);
        }
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            service,
            inbounds,
            shutdown,
        })
    }

    /// Every address this process is listening on, as bound.
    #[must_use]
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.inbounds
            .iter()
            .map(|inbound| inbound.address)
            .collect()
    }

    /// The budget both edges share.
    #[must_use]
    pub const fn gate(&self) -> &Gate {
        &self.service.gate
    }

    /// What has been charged so far.
    #[must_use]
    pub fn report(&self) -> Report {
        self.service.stats.report()
    }

    /// A handle that asks this server to stop.
    ///
    /// The handle must outlive the call to [`Server::run`] for a stop to be
    /// possible at all; a dropped handle is not a stop request, it is the loss of
    /// one way to make it.
    #[must_use]
    pub fn shutdown(&self) -> Shutdown {
        Shutdown {
            sender: self.shutdown.clone(),
        }
    }

    /// Accepts until asked to stop, and returns the final tally.
    ///
    /// Each listener runs in its own task and owns its own connection set, so a
    /// stop request costs at most [`SHUTDOWN_GRACE`] and no single connection can
    /// hold the process open past that.
    pub async fn run(self) -> Report {
        let Self {
            service,
            inbounds,
            shutdown,
        } = self;
        let mut stopping = shutdown.subscribe();
        let mut listeners = JoinSet::new();
        for inbound in inbounds {
            listeners.spawn(service.clone().accept(inbound, stopping.clone()));
        }
        // The server's own sender stays alive until here, so the loops above can
        // only end on a real request: a server that nobody asked to stop keeps
        // serving, rather than reading a dropped handle as an order. The first
        // check is what makes a request made *before* this call count — a stop
        // asked for during startup is already latched, and this returns at once.
        loop {
            if *stopping.borrow_and_update() {
                break;
            }
            if stopping.changed().await.is_err() {
                // Unreachable while `shutdown` below is alive, and the honest
                // answer if that ever changes: a latch nobody can set is a server
                // nobody can stop, so wind down instead of waiting.
                break;
            }
        }
        drop(shutdown);
        while let Some(joined) = listeners.join_next().await {
            if let Err(error) = joined {
                service
                    .logger
                    .event_at(Level::Error, "listenerLost")
                    .text("reason", &error.to_string())
                    .emit();
            }
        }
        service.stats.report()
    }
}

impl fmt::Debug for Server {
    /// What this process holds and what it has done with it.
    ///
    /// The bound addresses are this process's own facts; node names are operator
    /// text and stay out, because a debug print should never be a way to copy a
    /// configuration into a bug report.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Server")
            .field("addresses", &self.addresses())
            .field("connectionsAvailable", &self.gate().connections_available())
            .field("handshakesAvailable", &self.gate().handshakes_available())
            .field("report", &self.report())
            .finish_non_exhaustive()
    }
}

/// A way to ask a running [`Server`] to stop.
///
/// Cheap to clone and safe to call from a signal handler task: the first request
/// wins and later ones change nothing.
#[derive(Clone, Debug)]
pub struct Shutdown {
    sender: watch::Sender<bool>,
}

impl Shutdown {
    /// Asks for a stop, without waiting for the running server to finish.
    ///
    /// `send_replace` rather than `send`, because `send` fails without storing the
    /// value when no receiver exists yet. A stop asked for during startup — a
    /// `Ctrl-C` that lands while the listeners are still being bound — would
    /// otherwise be discarded and the process would serve on, unkillable by the one
    /// command its supervisor knows.
    pub fn request(&self) {
        let _ = self.sender.send_replace(true);
    }

    /// Whether a stop has already been asked for.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        *self.sender.borrow()
    }
}

/// Which edges to bind, in the order the configuration declares them.
fn planned(listen: &Listen) -> Vec<(Kind, SocketAddr)> {
    let mut planned = Vec::with_capacity(2);
    if let Some(address) = listen.socks5 {
        planned.push((Kind::Socks5, address));
    }
    if let Some(address) = listen.http {
        planned.push((Kind::Http, address));
    }
    planned
}

/// One bind failure, phrased once for both the bind and the local-address path.
fn bind_failed(address: SocketAddr, error: &std::io::Error) -> StartError {
    StartError::Bind {
        address,
        reason: error.to_string(),
    }
}

/// Why a server could not start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartError {
    /// Both inbounds are disabled, so this process would have nothing to do.
    NothingToListen,
    /// An address could not be taken.
    Bind {
        /// The address that was asked for.
        address: SocketAddr,
        /// The operating system's own words.
        reason: String,
    },
}

impl fmt::Display for StartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingToListen => formatter.write_str(
                "both inbounds are disabled: [listen] needs socks5 or http to hold an address, \
                 and \"\" is what disables one",
            ),
            Self::Bind { address, reason } => write!(
                formatter,
                "cannot listen on {address}: {reason}. Something else usually already holds \
                 that port; stop it, or point [listen] at a different one. A second copy of \
                 this client cannot share a listener, and starting it anyway would only mean \
                 two processes disagreeing about which one answers",
            ),
        }
    }
}

impl std::error::Error for StartError {}

/// Waits for the operator to ask this process to stop, and says which word arrived.
///
/// `Ctrl-C` is what a person at a terminal sends and `SIGTERM` is what a supervisor
/// sends; here both mean the same thing. Where `SIGTERM` cannot be registered the
/// process keeps serving on the signals that *are* available: a client that cannot be
/// stopped by `SIGTERM` is a smaller outage than one that dies during its own
/// startup, which is why nothing below panics.
///
/// The returned word is for the log line only; nothing branches on it.
pub async fn await_stop_signal(logger: &Logger) -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => tokio::select! {
                _ = tokio::signal::ctrl_c() => INTERRUPT,
                _ = terminate.recv() => TERMINATE,
            },
            Err(error) => {
                logger
                    .event_at(Level::Warn, "signalUnavailable")
                    .text("signal", TERMINATE)
                    .text("reason", &error.to_string())
                    .emit();
                let _ = tokio::signal::ctrl_c().await;
                INTERRUPT
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = logger;
        let _ = tokio::signal::ctrl_c().await;
        INTERRUPT
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex, PoisonError};

    use super::*;
    use crate::config::parse;
    use crate::error::RejectReason;
    use crate::transport::Transferred;

    /// A sink that keeps whole lines, so a test reads what a log reader would.
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<String>>>);

    impl Lines {
        fn taken(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let text = String::from_utf8_lossy(bytes);
            let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            for piece in text.split_inclusive('\n') {
                held.push(piece.trim_end().to_owned());
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture() -> (Logger, Lines) {
        let lines = Lines::default();
        let logger = Logger::with_sink(Level::Debug, Arc::new(Mutex::new(lines.clone())));
        (logger, lines)
    }

    /// One node, on a port nothing listens on, with a key that decodes but cannot
    /// match a server: enough for the loop to be exercised without a network.
    fn one_node(port: u16) -> String {
        format!(
            r#"
[listen]
socks5 = "127.0.0.1:{port}"
http = ""

[[node]]
name = "closed"
address = "127.0.0.1"
port = 1
userId = "00000000-0000-4000-8000-000000000000"
[node.reality]
publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
serverName = "cover.example"
shortId = "01"
"#
        )
    }

    /// A port held only long enough to be named. The configuration grammar refuses
    /// a declared `:0`, because an operator who cannot tell which port was chosen
    /// cannot point an application at it either.
    async fn free_port() -> u16 {
        let probe = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral loopback port");
        probe
            .local_addr()
            .expect("a bound listener has an address")
            .port()
    }

    /// The fold has to carry both edges' refusal codes in one field, and a silent
    /// hang-up has to stay distinguishable from a code of zero.
    #[test]
    fn both_edges_fold_into_the_same_shape() {
        let carried = Finished::from(socks5::Outcome::Carried(Transferred {
            to_remote: 7,
            to_local: 11,
        }));
        let refused = Finished::from(http::Outcome::Refused {
            status: Some(405),
            reason: "not a CONNECT",
        });
        let silent = Finished::from(socks5::Outcome::Refused {
            rep: None,
            reason: "the client hung up before the request",
        });
        assert!(matches!(
            carried,
            Finished::Carried {
                inbound: Kind::Socks5,
                to_remote: 7,
                to_local: 11
            }
        ));
        assert!(matches!(
            refused,
            Finished::Refused {
                inbound: Kind::Http,
                code: Some(405),
                ..
            }
        ));
        assert!(matches!(
            silent,
            Finished::Refused {
                inbound: Kind::Socks5,
                code: None,
                ..
            }
        ));
    }

    /// One carried, one refused and one failed exchange charge three different
    /// counters, and the failed one says whose fault it is.
    #[test]
    fn recording_a_finished_connection_counts_and_says_it() {
        let (logger, lines) = capture();
        let stats = Stats::default();
        let started = Instant::now();
        Finished::from(socks5::Outcome::Carried(Transferred {
            to_remote: 3,
            to_local: 4,
        }))
        .record(&stats, &logger, started);
        Finished::from(http::Outcome::Refused {
            status: Some(502),
            reason: "the destination refused",
        })
        .record(&stats, &logger, started);
        Finished::from(socks5::Outcome::Failed(Error::Rejected(
            RejectReason::Forbidden,
        )))
        .record(&stats, &logger, started);

        assert_eq!(
            stats.report(),
            Report {
                accepted: 0,
                carried: 1,
                refused: 1,
                failed: 1,
                unresolved: 0,
            }
        );
        let written = lines.taken();
        assert_eq!(written.len(), 3);
        assert!(written[0].contains("\"carried\""), "{}", written[0]);
        assert!(written[0].contains("\"toLocal\":4"), "{}", written[0]);
        assert!(written[1].contains("\"refused\""), "{}", written[1]);
        assert!(written[1].contains("\"code\":502"), "{}", written[1]);
        assert!(written[2].contains("\"failed\""), "{}", written[2]);
        assert!(
            written[2].contains("\"family\":\"rejected\""),
            "the family is the part a scheduler is scored on: {}",
            written[2]
        );
    }

    /// An exchange killed by the caller is a local fact, and the log has to say so:
    /// that is the difference between a cancelled hedge and a dead node.
    #[test]
    fn a_cancelled_exchange_is_logged_as_this_processs_own() {
        let (logger, lines) = capture();
        let stats = Stats::default();
        Finished::from(socks5::Outcome::Failed(Error::Cancelled)).record(
            &stats,
            &logger,
            Instant::now(),
        );
        let written = lines.taken();
        assert_eq!(written.len(), 1);
        assert!(
            written[0].contains("\"family\":\"local\""),
            "{}",
            written[0]
        );
        assert!(
            written[0].contains("\"countsAgainstNode\":false"),
            "{}",
            written[0]
        );
    }

    #[test]
    fn a_disabled_pair_is_refused_before_anything_is_bound() {
        assert!(
            planned(&Listen {
                socks5: None,
                http: None
            })
            .is_empty()
        );
        let both = Listen {
            socks5: Some("127.0.0.1:1080".parse().expect("loopback port 1080")),
            http: Some("127.0.0.1:1081".parse().expect("loopback port 1081")),
        };
        let names: Vec<&str> = planned(&both)
            .iter()
            .map(|(kind, _)| kind.label())
            .collect();
        assert_eq!(names, vec!["socks5", "http"]);
    }

    /// The port-in-use wording is the first thing an operator reads, and the default
    /// SOCKS5 port is exactly where it lands for anyone already running a proxy
    /// there.
    #[test]
    fn a_bind_failure_names_the_port_and_the_way_out() {
        let error = StartError::Bind {
            address: "127.0.0.1:10808".parse().expect("the default port"),
            reason: "Address already in use".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("127.0.0.1:10808"), "{text}");
        assert!(text.contains("Address already in use"), "{text}");
        assert!(text.contains("[listen]"), "{text}");
        assert!(
            StartError::NothingToListen
                .to_string()
                .contains("both inbounds are disabled"),
            "the empty-listener answer explains the syntax that caused it"
        );
    }

    /// A stop request is a one-way latch: a second caller changes nothing, and a
    /// clone reaches the same latch as the handle that was set.
    #[tokio::test]
    async fn a_stop_request_latches_for_every_handle() {
        let (sender, mut receiver) = watch::channel(false);
        let first = Shutdown {
            sender: sender.clone(),
        };
        let second = Shutdown {
            sender: sender.clone(),
        };
        assert!(!first.is_requested());
        first.request();
        assert!(second.is_requested(), "the latch is shared, not per handle");
        second.request();
        assert!(*receiver.borrow_and_update());
        assert!(
            Shutdown { sender }.is_requested(),
            "a handle made from the same sender sees the same latch"
        );
    }

    /// A stop is a fact about the process, not a message to a listener: the request
    /// lands even when nothing has subscribed yet, which is the state a `Ctrl-C`
    /// during startup arrives in.
    #[tokio::test]
    async fn a_stop_asked_before_anything_is_listening_is_still_a_stop() {
        let (sender, gone) = watch::channel(false);
        drop(gone);
        let stop = Shutdown { sender };
        stop.request();
        assert!(
            stop.is_requested(),
            "a request nobody was listening for is still a request"
        );
    }

    /// The tracked table has to be wider than the admitted one, or a socket that is
    /// only waiting for a greeting would be refused before the limit it is supposed
    /// to protect has anything to say.
    #[test]
    fn the_tracked_table_is_wider_than_the_admitted_one() {
        let gate = Gate::default();
        assert!(
            MAX_PENDING_LOCAL > gate.connections_available(),
            "waiting is not the same as being served"
        );
        assert!(gate.handshakes_available() < gate.connections_available());
    }

    /// A server has to report the listener it actually holds, say one line about
    /// binding it, and then stop when asked without inventing any traffic.
    ///
    /// The request is made *before* [`Server::run`] is called, which is the ordering
    /// a `Ctrl-C` during startup produces: the latch has to survive having no
    /// listener attached to it yet, or the process would bind its ports, print its
    /// banner and then ignore the only signal its operator knows how to send.
    #[tokio::test]
    async fn a_server_binds_says_so_and_stops() {
        let port = free_port().await;
        let config = parse(&one_node(port)).expect("a single node on loopback");
        let (logger, lines) = capture();
        let server = Server::start(&config, logger)
            .await
            .expect("a freshly released loopback port");
        assert_eq!(
            server.addresses(),
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))],
            "the address an operator can point an application at"
        );
        assert_eq!(server.report(), Report::default(), "nothing yet");
        let written = lines.taken();
        assert!(
            written
                .iter()
                .any(|line| line.contains("\"bound\"") && line.contains("\"socks5\"")),
            "the bind is the first thing an operator should see: {written:?}"
        );
        server.shutdown().request();
        let stopped = time::timeout(SHUTDOWN_GRACE, server.run()).await;
        assert_eq!(
            stopped.expect("the latch was honoured, not lost"),
            Report::default(),
            "a server that was asked to stop before it served reports nothing"
        );
    }

    /// A file that disables both edges is a valid configuration and a useless
    /// process, and the answer has to name the syntax that caused it.
    #[tokio::test]
    async fn a_server_that_would_listen_on_nothing_refuses_to_start() {
        let text = one_node(10_808).replace("socks5 = \"127.0.0.1:10808\"", "socks5 = \"\"");
        let config = parse(&text).expect("both inbounds disabled is still a file");
        let (logger, _) = capture();
        assert_eq!(
            Server::start(&config, logger)
                .await
                .expect_err("nothing to listen on"),
            StartError::NothingToListen
        );
    }

    /// The empty report is what a run that served nothing looks like, and every
    /// counter is named in it: a reader has to be able to tell "zero" from
    /// "not measured".
    #[test]
    fn an_empty_report_names_every_counter() {
        assert_eq!(
            Report::default(),
            Report {
                accepted: 0,
                carried: 0,
                refused: 0,
                failed: 0,
                unresolved: 0,
            }
        );
        let text = format!("{:?}", Report::default());
        for counter in ["accepted", "carried", "refused", "failed", "unresolved"] {
            assert!(text.contains(counter), "{text}");
        }
    }
}
