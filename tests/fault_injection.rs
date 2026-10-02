//! What a local application is told when the rest of the client cannot deliver.
//!
//! This is the fault-injection matrix's first half: every failure the taxonomy can
//! name, driven through both inbounds with no server involved. A scripted
//! [`Establish`] replaces the whole remote path, so what is under test is exactly
//! the edge's promise — *a request is answered once, in the words the client speaks,
//! and the failure that caused it survives intact on the way to the scheduler*.
//!
//! Three properties are checked per scenario:
//!
//! **The application-visible answer.** The reply code and the status are what a
//! browser, `curl` or a Rust HTTP client branches on. A mapping that quietly folds
//! `0x04` into `0x01` sends a client retrying a name that will never resolve.
//!
//! **The failure itself.** The inbound must hand back the node's error unchanged.
//! Folding a wrong-key handshake into a general failure is how a healthy second node
//! stops being looked at: only the taxonomy knows which faults are worth a retry
//! elsewhere and which are the destination's own.
//!
//! **What came back when it was over.** Both gate slots are asserted on every path,
//! including the one where the caller walks away mid-attempt. A permit that leaks on
//! cancellation is a slow outage: after enough abandoned connections the edge refuses
//! work it is actually free to do.
//!
//! What this file deliberately cannot prove is anything after a success reply.
//! [`Establishment`] is pinned to a real `VisionSession<TcpStream>`, so an
//! established tunnel cannot be fabricated here — a fake session would be a fake
//! handshake, and a fake handshake proves nothing about a real server. Half-close,
//! an idle tunnel surviving NAT, a reset mid-download and a node restarting under a
//! live session are tested against unmodified v2.0.1 in `tests/interop_v201.rs`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::time;

use rust_reality_client::error::{
    DnsError, Error, HandshakeError, Limit, RejectReason, SessionError, TransportError,
};
use rust_reality_client::handoff::Established;
use rust_reality_client::inbound::http::{self, Proxy as HttpProxy};
use rust_reality_client::inbound::socks5::{self, Proxy as SocksProxy};
use rust_reality_client::inbound::{
    Establish, Establishment, Gate, MAX_CONCURRENT_HANDSHAKES, MAX_LOCAL_CONNECTIONS,
};
use rust_reality_client::protocol::vless::Destination;

/// The destination every scenario asks for, so a difference between two scenarios is
/// always the fault rather than the target.
const HOST: &str = "example.com";
/// The port paired with [`HOST`].
const PORT: u16 = 443;

/// This process's own end of the local connection, which `BND.ADDR` reports.
const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// The port [`LOOPBACK`] is bound to, chosen to be the address the CLI listens on.
const BOUND_PORT: u16 = 10808;

/// Roomier than any client can make a greeting or a `CONNECT` head, so a test's write
/// always lands before the exchange starts.
const CLIENT_ROOM: usize = 1024;

/// How long one exchange may take before the suite calls it stuck.
///
/// Every test runs on a mocked clock, so this costs nothing when the edge works and
/// turns a parked exchange into a failure instead of a hung CI job.
const EXCHANGE_BUDGET: Duration = Duration::from_secs(2);

/// How long the seam is given to still be running before the caller gives up on it.
const ABANDON_AFTER: Duration = Duration::from_millis(50);

/// This process's end of the connection, as the inbound is told it.
fn bound() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(LOOPBACK), BOUND_PORT)
}

/// Everything a finished exchange leaves behind to be judged.
struct Exchange {
    bytes: Vec<u8>,
    asked: Vec<(Destination, u16)>,
    free_connections: usize,
    free_handshakes: usize,
}

/// The node's side of a fault: one answer, forever.
enum Answer {
    /// Refuse with this error, as `Handoff::establish` would.
    Error(Error),
    /// Never resolve, as a node that is still being dialed looks from here.
    Pending,
}

/// A stand-in for the whole remote path that remembers what it was asked.
///
/// Cloning shares the log, which is the point: [`Proxy::new`] takes the seam by value,
/// and the test still has to find out whether a node was contacted at all.
#[derive(Clone)]
struct Scripted {
    answer: Arc<Answer>,
    asked: Arc<Mutex<Vec<(Destination, u16)>>>,
}

impl Scripted {
    /// A node that answers every request with this error.
    fn failing(error: Error) -> Self {
        Self::of(Answer::Error(error))
    }

    /// A node that is never ready.
    fn pending() -> Self {
        Self::of(Answer::Pending)
    }

    fn of(answer: Answer) -> Self {
        Self {
            answer: Arc::new(answer),
            asked: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// What this node was told to reach, in order.
    fn log(&self) -> Vec<(Destination, u16)> {
        self.asked
            .lock()
            .expect("the log is only poisoned by a panic elsewhere")
            .clone()
    }
}

impl Establish for Scripted {
    fn establish(&self, destination: Destination, port: u16) -> Establishment {
        self.asked
            .lock()
            .expect("the log is only poisoned by a panic elsewhere")
            .push((destination.clone(), port));
        match &*self.answer {
            Answer::Error(error) => {
                let error = error.clone();
                Box::pin(async move { Err(error) })
            }
            Answer::Pending => Box::pin(std::future::pending::<Result<Established, Error>>()),
        }
    }
}

/// One failure the taxonomy can name, and the two answers it owes the application.
struct Scenario {
    /// How the fault is spoken about in a log line.
    name: &'static str,
    /// What the node's side reports.
    error: Error,
    /// The SOCKS5 reply code a client reads.
    rep: u8,
    /// The HTTP status a client reads.
    status: u16,
    /// Whether this fault is evidence about the node.
    against_node: bool,
}

/// One row of the matrix. Writing the rows as calls rather than as literals keeps the
/// five things that matter about a fault — what it is, what each client is told, and
/// whether the node earned it — next to each other.
fn scenario(
    name: &'static str,
    error: Error,
    rep: u8,
    status: u16,
    against_node: bool,
) -> Scenario {
    Scenario {
        name,
        error,
        rep,
        status,
        against_node,
    }
}

/// The matrix: one scenario per arm of [`Error`], including the arms that must *not* be
/// charged to a server. Grouped by family, because a table of thirty-odd faults is past
/// what one screen can be checked against the taxonomy.
fn matrix() -> Vec<Scenario> {
    let mut rows = transport_rows();
    rows.extend(dns_rows());
    rows.extend(handshake_rows());
    rows.extend(rejection_rows());
    rows.extend(session_rows());
    rows.extend(policy_rows());
    rows
}

/// TCP did not connect, or stopped carrying what it had connected to.
fn transport_rows() -> Vec<Scenario> {
    let fault = |name, error: TransportError, rep, status, against_node| {
        scenario(name, Error::Transport(error), rep, status, against_node)
    };

    vec![
        fault(
            "the node refused the TCP connection",
            TransportError::Connect("connection refused".to_owned()),
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the node never answered the SYN",
            TransportError::Timeout,
            socks5::GENERAL_FAILURE,
            http::GATEWAY_TIMEOUT,
            true,
        ),
        fault(
            "a live tunnel's socket failed a system call",
            TransportError::Socket("timed out".to_owned()),
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the application hung up on us",
            TransportError::Local("connection reset".to_owned()),
            socks5::GENERAL_FAILURE,
            http::INTERNAL_SERVER_ERROR,
            false,
        ),
        fault(
            "a live tunnel's stream desynchronised",
            TransportError::BrokenPipe,
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
    ]
}

/// The name was never turned into an address.
fn dns_rows() -> Vec<Scenario> {
    let fault = |name, error: DnsError, rep, status, against_node| {
        scenario(name, Error::Dns(error), rep, status, against_node)
    };

    vec![
        fault(
            "the name resolves to nothing",
            DnsError::NoAddress,
            socks5::HOST_UNREACHABLE,
            http::BAD_GATEWAY,
            false,
        ),
        fault(
            "the resolver itself failed",
            DnsError::Lookup("server failure".to_owned()),
            socks5::HOST_UNREACHABLE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the resolver ran out of time",
            DnsError::Timeout,
            socks5::HOST_UNREACHABLE,
            http::GATEWAY_TIMEOUT,
            true,
        ),
    ]
}

/// REALITY did not complete, or completed against the wrong peer.
fn handshake_rows() -> Vec<Scenario> {
    let fault = |name, error: HandshakeError, rep, status, against_node| {
        scenario(name, Error::Handshake(error), rep, status, against_node)
    };

    vec![
        fault(
            "the handshake ran out of time",
            HandshakeError::Timeout,
            socks5::GENERAL_FAILURE,
            http::GATEWAY_TIMEOUT,
            true,
        ),
        fault(
            "the peer is not the configured REALITY server",
            HandshakeError::IdentityMismatch,
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the handshake transcript did not verify",
            HandshakeError::Verification,
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "a handshake message was malformed",
            HandshakeError::Protocol("no server hello"),
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the node closed the door mid-handshake",
            HandshakeError::UnexpectedEof,
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
    ]
}

/// The node authenticated TLS and then refused the VLESS request.
fn rejection_rows() -> Vec<Scenario> {
    let fault = |name, error: RejectReason, rep, status, against_node| {
        scenario(name, Error::Rejected(error), rep, status, against_node)
    };

    vec![
        fault(
            "the credentials were not accepted",
            RejectReason::Unauthorized,
            socks5::NOT_ALLOWED,
            http::FORBIDDEN,
            true,
        ),
        fault(
            "the node refused this destination",
            RejectReason::Forbidden,
            socks5::NOT_ALLOWED,
            http::FORBIDDEN,
            true,
        ),
        fault(
            "the node could not reach the destination",
            RejectReason::DestinationUnreachable,
            socks5::HOST_UNREACHABLE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the node answered with a status we cannot name",
            RejectReason::Other(2),
            socks5::CONNECTION_REFUSED,
            http::BAD_GATEWAY,
            true,
        ),
    ]
}

/// A tunnel that was up stopped being one, or could not be framed.
fn session_rows() -> Vec<Scenario> {
    let fault = |name, error: SessionError, rep, status, against_node| {
        scenario(name, Error::Session(error), rep, status, against_node)
    };

    vec![
        fault(
            "the node authenticated and then said nothing",
            SessionError::ClosedBeforeResponse,
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "a session record would not open",
            SessionError::RecordCorrupted,
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the traffic key reached its record ceiling",
            SessionError::KeyExhausted,
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "Vision framing could not be decoded",
            SessionError::Framing("shell length exceeds the payload"),
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "a record type that cannot carry data arrived",
            SessionError::UnexpectedContentType(22),
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the node sent a fatal alert",
            SessionError::PeerAlert {
                level: 2,
                description: 80,
            },
            socks5::GENERAL_FAILURE,
            http::BAD_GATEWAY,
            true,
        ),
        fault(
            "the destination does not fit the wire format",
            SessionError::RequestTooLong,
            socks5::GENERAL_FAILURE,
            http::INTERNAL_SERVER_ERROR,
            false,
        ),
        fault(
            "no entropy to pad a frame with",
            SessionError::Entropy,
            socks5::GENERAL_FAILURE,
            http::INTERNAL_SERVER_ERROR,
            false,
        ),
    ]
}

/// Nothing was wrong with the node: a local rule, a cancellation, or us.
fn policy_rows() -> Vec<Scenario> {
    vec![
        scenario(
            "every node is inside its breaker window",
            Error::Limit(Limit::Candidates),
            socks5::NOT_ALLOWED,
            http::SERVICE_UNAVAILABLE,
            false,
        ),
        scenario(
            "the handshake budget is spent",
            Error::Limit(Limit::Handshakes),
            socks5::NOT_ALLOWED,
            http::SERVICE_UNAVAILABLE,
            false,
        ),
        scenario(
            "the connection table is full",
            Error::Limit(Limit::LocalConnections),
            socks5::NOT_ALLOWED,
            http::SERVICE_UNAVAILABLE,
            false,
        ),
        scenario(
            "no probe slot is free",
            Error::Limit(Limit::Probes),
            socks5::NOT_ALLOWED,
            http::SERVICE_UNAVAILABLE,
            false,
        ),
        scenario(
            "the attempt was cancelled by us",
            Error::Cancelled,
            socks5::GENERAL_FAILURE,
            http::SERVICE_UNAVAILABLE,
            false,
        ),
        scenario(
            "the configuration cannot be run",
            Error::Config("no node is configured".to_owned()),
            socks5::GENERAL_FAILURE,
            http::INTERNAL_SERVER_ERROR,
            false,
        ),
        scenario(
            "an operating-system call failed",
            Error::Io("bad file descriptor".to_owned()),
            socks5::GENERAL_FAILURE,
            http::INTERNAL_SERVER_ERROR,
            true,
        ),
    ]
}

fn socks5_opening() -> Vec<u8> {
    let label = HOST
        .len()
        .try_into()
        .expect("a test's host name fits one length byte");
    let mut bytes = vec![socks5::VERSION, 1, socks5::NO_AUTH];
    // `[VER, CMD, RSV, ATYP]`, then the domain and the port: RFC 1928's request.
    bytes.extend_from_slice(&[socks5::VERSION, 0x01, 0x00, 0x03, label]);
    bytes.extend_from_slice(HOST.as_bytes());
    bytes.extend_from_slice(&PORT.to_be_bytes());
    bytes
}

/// The reply a SOCKS5 client parses: header, then this process's own address and port.
fn socks5_reply(rep: u8) -> Vec<u8> {
    let mut bytes = vec![socks5::VERSION, rep, 0x00, 0x01];
    bytes.extend_from_slice(&LOOPBACK.octets());
    bytes.extend_from_slice(&BOUND_PORT.to_be_bytes());
    bytes
}

/// The method selection followed by one reply, which is every byte a failing SOCKS5
/// exchange is allowed to write.
fn socks5_answer(rep: u8) -> Vec<u8> {
    let mut bytes = vec![socks5::VERSION, socks5::NO_AUTH];
    bytes.extend(socks5_reply(rep));
    bytes
}

/// The HTTP client's whole opening: one `CONNECT` head and nothing after it.
fn http_opening() -> Vec<u8> {
    format!("CONNECT {HOST}:{PORT} HTTP/1.1\r\nHost: {HOST}\r\n\r\n").into_bytes()
}

/// Everything a client left to read once the exchange is over.
async fn drain(client: &mut DuplexStream) -> Vec<u8> {
    let mut seen = Vec::new();
    client
        .read_to_end(&mut seen)
        .await
        .expect("the client can read what the inbound wrote");
    seen
}

/// Collects what a finished exchange proves, without judging the limits yet: a test
/// that started with a partly spent gate has to say which ceiling it means.
fn collect(gate: &Gate, node: &Scripted, bytes: Vec<u8>) -> Exchange {
    Exchange {
        bytes,
        asked: node.log(),
        free_connections: gate.connections_available(),
        free_handshakes: gate.handshakes_available(),
    }
}

/// The one destination every scenario asks for, as the seam should have received it.
fn expected_request() -> Vec<(Destination, u16)> {
    vec![(Destination::Domain(HOST.to_owned()), PORT)]
}

/// Drives one SOCKS5 exchange to its end against a node that answers `error`.
async fn over_socks5(error: &Error, gate: Gate) -> Exchange {
    let node = Scripted::failing(error.clone());
    let proxy = SocksProxy::new(node.clone(), gate);
    let (mut client, mut peer) = tokio::io::duplex(CLIENT_ROOM);
    client
        .write_all(&socks5_opening())
        .await
        .expect("a well-formed opening always fits the pipe");

    let outcome = time::timeout(EXCHANGE_BUDGET, proxy.handle(&mut peer, bound()))
        .await
        .expect("the exchange is decided, not parked");
    drop(peer);
    let bytes = drain(&mut client).await;

    assert_eq!(
        outcome,
        socks5::Outcome::Failed(error.clone()),
        "a SOCKS5 refusal must hand the node's own failure on unchanged"
    );
    collect(proxy.gate(), &node, bytes)
}

/// Drives one HTTP `CONNECT` exchange to its end against a node that answers `error`.
async fn over_http(error: &Error, gate: Gate) -> Exchange {
    let node = Scripted::failing(error.clone());
    let proxy = HttpProxy::new(node.clone(), gate);
    let (mut client, peer) = tokio::io::duplex(CLIENT_ROOM);
    client
        .write_all(&http_opening())
        .await
        .expect("a well-formed head always fits the pipe");

    let outcome = time::timeout(EXCHANGE_BUDGET, proxy.handle(peer))
        .await
        .expect("the exchange is decided, not parked");
    let bytes = drain(&mut client).await;

    assert_eq!(
        outcome,
        http::Outcome::Failed(error.clone()),
        "an HTTP refusal must hand the node's own failure on unchanged"
    );
    collect(proxy.gate(), &node, bytes)
}

#[tokio::test(start_paused = true)]
async fn every_failure_is_answered_in_both_languages() {
    for scenario in matrix() {
        let name = scenario.name;

        assert_eq!(
            socks5::reply_for(&scenario.error),
            scenario.rep,
            "{name}: the code this module maps is the one the matrix records"
        );
        assert_eq!(
            http::status_for(&scenario.error),
            scenario.status,
            "{name}: the status this module maps is the one the matrix records"
        );
        assert_eq!(
            scenario.error.classify().counts_against_node(),
            scenario.against_node,
            "{name}: whether the node earned this is the taxonomy's decision, not the answer's: {}",
            scenario.error
        );

        let socks = over_socks5(&scenario.error, Gate::default()).await;
        assert_eq!(
            socks.bytes,
            socks5_answer(scenario.rep),
            "{name}: a SOCKS5 client is given the method selection and exactly one reply, \
             and nothing of a tunnel it was never told about"
        );
        assert_eq!(
            socks.asked,
            expected_request(),
            "{name}: the node was asked for what the client named"
        );
        assert_eq!(
            socks.free_connections, MAX_LOCAL_CONNECTIONS,
            "{name}: the connection slot came back"
        );
        assert_eq!(
            socks.free_handshakes, MAX_CONCURRENT_HANDSHAKES,
            "{name}: the handshake slot came back, whether the node answered or not"
        );

        let http = over_http(&scenario.error, Gate::default()).await;
        let answer =
            String::from_utf8(http.bytes.clone()).expect("an HTTP answer is text and nothing else");
        assert!(
            answer.starts_with(&format!("HTTP/1.1 {} ", scenario.status)),
            "{name}: a client branches on the status number: {answer:?}"
        );
        assert!(
            answer.contains("Connection: close\r\n"),
            "{name}: a refused exchange ends, and says so: {answer:?}"
        );
        assert!(
            answer.ends_with("\r\n\r\n"),
            "{name}: the head is terminated, so no client hangs looking for a body: {answer:?}"
        );
        assert_eq!(
            http.asked,
            expected_request(),
            "{name}: the node was asked for what the client named"
        );
        assert_eq!(
            http.free_connections, MAX_LOCAL_CONNECTIONS,
            "{name}: the connection slot came back"
        );
        assert_eq!(
            http.free_handshakes, MAX_CONCURRENT_HANDSHAKES,
            "{name}: the handshake slot came back"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_full_connection_table_is_refused_before_a_node_is_asked() {
    let gate = Gate::new(1, MAX_CONCURRENT_HANDSHAKES);
    let held = gate.admit_connection().expect("one slot is free");
    let error = Error::Limit(Limit::LocalConnections);

    let socks = over_socks5(&error, gate.clone()).await;
    assert!(
        socks.asked.is_empty(),
        "the edge is full, so no node was contacted: {:?}",
        socks.asked
    );
    assert_eq!(
        socks.bytes,
        socks5_answer(socks5::NOT_ALLOWED),
        "a rule said no, which is the one answer that is not the node's fault"
    );
    assert_eq!(
        socks.free_connections, 0,
        "the refused exchange took no slot of its own, so only the held one is out"
    );
    assert_eq!(
        socks.free_handshakes, MAX_CONCURRENT_HANDSHAKES,
        "a connection refused at the gate never spent authentication capacity either"
    );

    let http = over_http(&error, gate).await;
    assert!(
        http.asked.is_empty(),
        "the edge is full, so no node was contacted: {:?}",
        http.asked
    );
    let answer = String::from_utf8(http.bytes).expect("an HTTP answer is text");
    assert!(
        answer.starts_with("HTTP/1.1 503 "),
        "a full table is this proxy being busy, not the destination failing: {answer:?}"
    );
    assert!(
        answer.contains("Retry-After: 1"),
        "a 503 has to say when to come back: {answer:?}"
    );
    assert_eq!(http.free_connections, 0, "and it leaked nothing");
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn a_saturated_handshake_budget_is_refused_before_a_node_is_asked() {
    let gate = Gate::new(MAX_LOCAL_CONNECTIONS, 1);
    let held = gate.admit_handshake().expect("one slot is free");
    let error = Error::Limit(Limit::Handshakes);

    let socks = over_socks5(&error, gate.clone()).await;
    assert!(
        socks.asked.is_empty(),
        "authentication is the scarce resource, and it was not spent: {:?}",
        socks.asked
    );
    assert_eq!(
        socks.bytes,
        socks5_answer(socks5::NOT_ALLOWED),
        "the client is told a rule stopped it, not that the destination is dead"
    );
    assert_eq!(
        socks.free_connections, MAX_LOCAL_CONNECTIONS,
        "the connection this exchange held came back to a full table"
    );
    assert_eq!(socks.free_handshakes, 0, "and only the held slot is out");

    let http = over_http(&error, gate).await;
    assert!(
        http.asked.is_empty(),
        "authentication is the scarce resource, and it was not spent: {:?}",
        http.asked
    );
    let answer = String::from_utf8(http.bytes).expect("an HTTP answer is text");
    assert!(
        answer.starts_with("HTTP/1.1 503 "),
        "a busy proxy is a 503, so a client's retry policy can tell it from a broken origin: \
         {answer:?}"
    );
    assert_eq!(http.free_handshakes, 0, "and it leaked nothing");
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn walking_away_mid_attempt_costs_nothing() {
    // A caller abandoning an exchange is the one fault that arrives from outside this
    // client's own control, and it is the only path here that never returns: the seam
    // stays dialing while the future holding it is dropped. What has to survive is the
    // arithmetic — both slots go back — and the client must be left without a reply,
    // because a reply is what promises a tunnel that this exchange no longer has.
    let node = Scripted::pending();
    let proxy = SocksProxy::new(node.clone(), Gate::default());
    let (mut client, mut peer) = tokio::io::duplex(CLIENT_ROOM);
    client
        .write_all(&socks5_opening())
        .await
        .expect("a well-formed opening always fits the pipe");

    let abandoned = time::timeout(ABANDON_AFTER, proxy.handle(&mut peer, bound())).await;
    assert!(
        abandoned.is_err(),
        "the exchange is still waiting on the node when the caller gives up"
    );
    drop(peer);
    let bytes = drain(&mut client).await;

    // Two bytes, and only ever two: the greeting's method selection, which a SOCKS5
    // client reads before anything else and which therefore cannot be withheld. The
    // ten-byte reply that would have named a tunnel never arrives.
    assert_eq!(
        bytes,
        vec![socks5::VERSION, socks5::NO_AUTH],
        "a cancelled exchange promised a method, never a connection"
    );
    assert_eq!(
        node.log(),
        expected_request(),
        "the node was asked, and the attempt was dropped rather than completed"
    );
    assert_eq!(
        proxy.gate().connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "the connection slot came back when the future was dropped"
    );
    assert_eq!(
        proxy.gate().handshakes_available(),
        MAX_CONCURRENT_HANDSHAKES,
        "so did the handshake slot, which is the one an abandoned authentication would leak"
    );
}

#[tokio::test(start_paused = true)]
async fn walking_away_from_http_costs_nothing_either() {
    let node = Scripted::pending();
    let proxy = HttpProxy::new(node.clone(), Gate::default());
    let (mut client, peer) = tokio::io::duplex(CLIENT_ROOM);
    client
        .write_all(&http_opening())
        .await
        .expect("a well-formed head always fits the pipe");

    let abandoned = time::timeout(ABANDON_AFTER, proxy.handle(peer)).await;
    assert!(
        abandoned.is_err(),
        "the exchange is still waiting on the node when the caller gives up"
    );
    let bytes = drain(&mut client).await;

    assert!(
        bytes.is_empty(),
        "no `200` is written for a tunnel nobody is left to carry: {bytes:?}"
    );
    assert_eq!(
        proxy.gate().connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "the connection slot came back"
    );
    assert_eq!(
        proxy.gate().handshakes_available(),
        MAX_CONCURRENT_HANDSHAKES,
        "and the handshake slot with it"
    );
}

#[tokio::test(start_paused = true)]
async fn a_head_too_large_is_refused_without_contacting_a_node() {
    // The bound is on bytes read, not on bytes the client promised, so a head that never
    // stops has to be refused mid-read. This is the one attacker-shaped fault the edge
    // can be handed before any destination exists.
    let node = Scripted::failing(Error::Cancelled);
    let proxy = HttpProxy::new(node.clone(), Gate::default());
    let (mut client, peer) = tokio::io::duplex(2 * http::MAX_HEAD_LEN);

    let mut head = b"CONNECT ".to_vec();
    head.extend(vec![b'a'; http::MAX_HEAD_LEN]);
    head.extend(b".example:443 HTTP/1.1\r\n\r\n");
    client
        .write_all(&head)
        .await
        .expect("an oversized head still fits the test's pipe");

    let outcome = time::timeout(EXCHANGE_BUDGET, proxy.handle(peer))
        .await
        .expect("the head is decided, not parked");
    let bytes = drain(&mut client).await;

    assert!(
        matches!(
            outcome,
            http::Outcome::Refused {
                status: Some(http::REQUEST_HEADER_FIELDS_TOO_LARGE),
                ..
            }
        ),
        "an oversized head is a refusal this proxy decided, not a node failure: {outcome:?}"
    );
    assert!(
        node.log().is_empty(),
        "a head this big never reached a destination, so no node was asked"
    );
    let answer = String::from_utf8(bytes).expect("an HTTP answer is text");
    assert!(
        answer.starts_with("HTTP/1.1 431 "),
        "431 is the status that means the head, not the origin: {answer:?}"
    );
    assert_eq!(proxy.gate().connections_available(), MAX_LOCAL_CONNECTIONS);
}

#[tokio::test(start_paused = true)]
async fn a_plain_get_is_told_which_method_exists() {
    let node = Scripted::failing(Error::Cancelled);
    let proxy = HttpProxy::new(node.clone(), Gate::default());
    let (mut client, peer) = tokio::io::duplex(CLIENT_ROOM);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("a request line always fits the pipe");

    let outcome = time::timeout(EXCHANGE_BUDGET, proxy.handle(peer))
        .await
        .expect("the head is decided, not parked");
    let bytes = drain(&mut client).await;

    assert!(
        matches!(
            outcome,
            http::Outcome::Refused {
                status: Some(http::METHOD_NOT_ALLOWED),
                ..
            }
        ),
        "a method this proxy does not have is a refusal, before a node is involved: {outcome:?}"
    );
    assert!(
        node.log().is_empty(),
        "forwarding a `GET` would mean answering on an origin's behalf, so no node was asked"
    );
    let answer = String::from_utf8(bytes).expect("an HTTP answer is text");
    assert!(
        answer.starts_with("HTTP/1.1 405 ") && answer.contains("Allow: CONNECT"),
        "a 405 must name the one method there is: {answer:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_client_that_stops_talking_is_refused_rather_than_parked() {
    // Both budgets are fifteen seconds of the client's own silence, which is the whole
    // point of putting a ceiling on them: a socket that connects and says nothing would
    // otherwise hold a task and a slot forever. On a mocked clock the budget is spent
    // without the suite waiting for it.
    let node = Scripted::failing(Error::Cancelled);
    let socks = SocksProxy::new(node.clone(), Gate::default());
    let (mut client, mut peer) = tokio::io::duplex(CLIENT_ROOM);
    let outcome = time::timeout(
        socks5::GREETING_BUDGET + EXCHANGE_BUDGET,
        socks.handle(&mut peer, bound()),
    )
    .await
    .expect("a silent greeting is refused once its own budget is spent");
    drop(peer);
    let bytes = drain(&mut client).await;

    assert!(
        matches!(outcome, socks5::Outcome::Refused { rep: None, .. }),
        "a client that never greeted is not owed a code it would misread: {outcome:?}"
    );
    assert!(
        bytes.is_empty(),
        "a refusal with no code writes nothing: {bytes:?}"
    );

    let http = HttpProxy::new(node, Gate::default());
    let (mut client, peer) = tokio::io::duplex(CLIENT_ROOM);
    let outcome = time::timeout(http::HEAD_BUDGET + EXCHANGE_BUDGET, http.handle(peer))
        .await
        .expect("a silent head is refused once its own budget is spent");
    let bytes = drain(&mut client).await;

    assert!(
        matches!(outcome, http::Outcome::Refused { status: None, .. }),
        "a client that goes away mid-head is not owed a status either: {outcome:?}"
    );
    assert!(
        bytes.is_empty(),
        "a refusal with no status writes nothing: {bytes:?}"
    );
    assert_eq!(
        socks.gate().connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "silence spent a budget, not a slot"
    );
    assert_eq!(
        http.gate().connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "silence spent a budget, not a slot"
    );
}
