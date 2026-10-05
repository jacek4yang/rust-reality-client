//! SOCKS5, the way a client needs it answered: greeting, one `CONNECT`, one reply.
//!
//! RFC 1928 is the wire format, and the checks a real client makes are the ones
//! this module is written to satisfy. Both are read from an implementation that
//! has to interoperate rather than from memory: the greeting, request and reply
//! layouts and the reply codes a client decodes are as `tokio-socks-0.5.3`
//! (`src/tcp/socks5.rs:310-500`) parses them, including its `consume_reply_address`,
//! which is what lets a client skip the bound address a proxy chooses to send.
//!
//! Three properties are deliberate.
//!
//! **Every read is bounded by its own statement.** A greeting can carry at most
//! 255 method bytes because one byte names them; a domain can carry at most 255
//! label bytes for the same reason. Both are read into fixed arrays sized from
//! the protocol, so no client — misbehaving or hostile — can make this inbound
//! allocate in proportion to what it sent.
//!
//! **A refusal says what the client can act on and nothing more.** The reply code
//! is SOCKS5's own vocabulary; the reason is a `&'static str` written here, never
//! the peer's bytes, so a log line cannot be made to say anything an application
//! chose.
//!
//! **Nothing is decided about nodes here.** Commands this client does not
//! implement (`BIND`, `UDP ASSOCIATE`) are answered with `0x07` after the request
//! is consumed in full, which leaves the stream at a message boundary for whoever
//! reads it next rather than half-parsed.
//!
//! The service half ([`Proxy`]) adds the one rule the codec cannot state: **a
//! request is answered exactly once.** [`Proxy::handle`] writes its reply — a
//! `0x00`, a refusal code, or nothing at all — and then does nothing but
//! [`carry`]. A `0x00` commits the destination to one
//! node's session, so from that byte onwards there is no retry, no replay and no
//! second server to choose; if the bytes stop, the client's own read is what tells
//! it.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time;

use crate::error::{Error, Limit, RejectReason};
use crate::handoff::{Established, FIRST_BYTE_BUDGET};
use crate::inbound::{Establish, Gate};
use crate::protocol::vless::Destination;
use crate::transport::relay::carry_observed;
use crate::transport::{Transferred, verdict};

/// Protocol version this inbound speaks, and the byte every conforming client
/// opens with (RFC 1928 `VER`).
pub const VERSION: u8 = 0x05;
/// The only method offered: plain, unauthenticated loopback (`AUTH` 0x00).
pub const NO_AUTH: u8 = 0x00;

/// Reply code: the request worked (`REP` 0x00).
pub const SUCCEEDED: u8 = 0x00;
/// Reply code: the proxy failed and has nothing more specific to say (0x01).
pub const GENERAL_FAILURE: u8 = 0x01;
/// Reply code: a rule, not the network, said no (0x02).
pub const NOT_ALLOWED: u8 = 0x02;
/// Reply code: the destination host could not be reached (0x04).
pub const HOST_UNREACHABLE: u8 = 0x04;
/// Reply code: the request was rejected, or the connection refused (0x05).
pub const CONNECTION_REFUSED: u8 = 0x05;
/// Reply code: this proxy does not implement that command (0x07).
pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
/// Reply code: this proxy does not implement that address type (0x08).
pub const ADDRESS_NOT_SUPPORTED: u8 = 0x08;
/// Method-selection answer: none of what the client offered is acceptable (0xFF).
pub const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

/// Command: open a tunnel to the requested destination.
const CONNECT: u8 = 0x01;
/// Command: listen for an inbound connection, which this client does not do.
const BIND: u8 = 0x02;
/// Command: relay datagrams, which is out of scope for a TCP-only v1.
const UDP_ASSOCIATE: u8 = 0x03;

/// Address type: four-byte IPv4 (`ATYP` 0x01).
const ATYP_IPV4: u8 = 0x01;
/// Address type: one-byte length, label, two-byte port (0x03).
const ATYP_DOMAIN: u8 = 0x03;
/// Address type: sixteen-byte IPv6 (0x04).
const ATYP_IPV6: u8 = 0x04;

/// The longest domain a request can name, which one length byte defines.
const MAX_DOMAIN_LEN: usize = 255;

/// A destination a local client asked to be connected to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// Host, kept in the form it arrived in: a literal stays a literal, so the
    /// node resolves only what the application said it should.
    pub destination: Destination,
    /// Port, which the wire carries after the address.
    pub port: u16,
}

/// A request this inbound will not act on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Answer with this reply code, then close.
    Reply {
        /// The code the client will read.
        rep: u8,
        /// What to log, chosen here rather than by the peer.
        reason: &'static str,
    },
    /// Close without answering a byte.
    HangUp {
        /// What to log.
        reason: &'static str,
    },
}

impl Refusal {
    /// The reply code, when there is one to send.
    #[must_use]
    pub const fn rep(&self) -> Option<u8> {
        match self {
            Self::Reply { rep, .. } => Some(*rep),
            Self::HangUp { .. } => None,
        }
    }

    /// Why, in the words this module chose.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Reply { reason, .. } | Self::HangUp { reason } => reason,
        }
    }
}

/// Reads the greeting and answers that no authentication is needed.
///
/// The greeting is `[VER, NMETHODS, METHODS…]` and the answer is the two-byte
/// method selection, so this is the only place a client can be told that the
/// proxy is a SOCKS5 proxy that wants no credentials. No username/password
/// negotiation (RFC 1929) is offered: this listener binds loopback, and a
/// second, weaker authentication layer inside a localhost socket protects
/// nothing.
///
/// # Errors
///
/// [`Refusal::HangUp`] when the version is not 5, when no methods are offered,
/// when the offered list does not include `0x00` — after the `0xFF` selection has
/// been written — or when the greeting stops arriving.
pub async fn negotiate<S>(stream: &mut S) -> Result<(), Refusal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0_u8; 2];
    fill(stream, &mut header).await?;
    let [VERSION, offered] = header else {
        return Err(hangup("not a SOCKS5 greeting"));
    };
    if offered == 0 {
        return Err(hangup("the greeting names no methods"));
    }

    // One fixed buffer, sized by the protocol rather than by the client: 255 is
    // the most a method count can name.
    let mut room = [0_u8; MAX_DOMAIN_LEN];
    let methods = &mut room[..usize::from(offered)];
    fill(stream, methods).await?;

    if !methods.contains(&NO_AUTH) {
        answer_methods(stream, NO_ACCEPTABLE_METHODS).await?;
        return Err(hangup("no acceptable methods"));
    }
    answer_methods(stream, NO_AUTH).await
}

/// Reads one request in full: header, address, and port.
///
/// The request is consumed even when the command is one this client does not
/// implement, which is what lets the reply be the last thing on the stream
/// instead of a refusal followed by the client's own unread bytes.
///
/// # Errors
///
/// [`Refusal::Reply`] for a command or address type that is not supported, for a
/// domain that is empty or not UTF-8, and for port `0`, which no destination can
/// be. [`Refusal::HangUp`] when the header is not a SOCKS5 request — a wrong
/// version or a non-zero reserved byte — or when the request stops arriving.
pub async fn read_request<S>(stream: &mut S) -> Result<Request, Refusal>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    fill(stream, &mut header).await?;
    let [VERSION, command, reserved, atyp] = header else {
        return Err(hangup("not a SOCKS5 request"));
    };
    if reserved != 0 {
        return Err(hangup("the reserved byte is not zero"));
    }

    let destination = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            fill(stream, &mut octets).await?;
            Destination::IPv4(octets)
        }
        ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            fill(stream, &mut octets).await?;
            Destination::IPv6(octets)
        }
        ATYP_DOMAIN => domain(stream).await?,
        _ => {
            return Err(refused(
                ADDRESS_NOT_SUPPORTED,
                "that address type is not supported",
            ));
        }
    };

    let mut port = [0_u8; 2];
    fill(stream, &mut port).await?;
    let port = u16::from_be_bytes(port);

    match command {
        CONNECT if port == 0 => Err(refused(GENERAL_FAILURE, "port 0 is not a destination")),
        CONNECT => Ok(Request { destination, port }),
        BIND => Err(refused(COMMAND_NOT_SUPPORTED, "BIND is not supported")),
        UDP_ASSOCIATE => Err(refused(
            COMMAND_NOT_SUPPORTED,
            "UDP ASSOCIATE is not supported",
        )),
        _ => Err(refused(
            COMMAND_NOT_SUPPORTED,
            "that command is not supported",
        )),
    }
}

/// Answers a request with the bound address this process owns.
///
/// `BND.ADDR` and `BND.PORT` describe the proxy's own end of the new connection,
/// and a client is entitled to ignore them (`tokio-socks` reads the reply header
/// and skips the address it is given). Reporting the local socket keeps the field
/// truthful: the address on the far side of this tunnel belongs to a node the
/// application has no business naming.
///
/// # Errors
///
/// [`Refusal::HangUp`] when the reply cannot be written, which means the client is
/// already gone.
pub async fn answer<S>(stream: &mut S, rep: u8, bound: SocketAddr) -> Result<(), Refusal>
where
    S: AsyncWrite + Unpin,
{
    let (reply, length) = encode(rep, bound);
    stream
        .write_all(&reply[..length])
        .await
        .map_err(|_| hangup("the reply did not reach the client"))?;
    stream
        .flush()
        .await
        .map_err(|_| hangup("the reply did not reach the client"))
}

/// Reads exactly `buffer` bytes, or refuses with the one reason this module has
/// for a truncated exchange.
async fn fill<S>(stream: &mut S, buffer: &mut [u8]) -> Result<(), Refusal>
where
    S: AsyncRead + Unpin,
{
    stream
        .read_exact(buffer)
        .await
        // `Ok` from `read_exact` means the buffer was filled; the count is the
        // buffer's own length, which this caller already knows.
        .map(drop)
        .map_err(|_| hangup("the request stopped arriving"))
}

/// One label byte, then that many label bytes, then nothing but the port.
async fn domain<S>(stream: &mut S) -> Result<Destination, Refusal>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 1];
    fill(stream, &mut length).await?;
    let length = usize::from(length[0]);
    if length == 0 {
        return Err(refused(
            GENERAL_FAILURE,
            "an empty domain is not a destination",
        ));
    }

    let mut label = [0_u8; MAX_DOMAIN_LEN];
    fill(stream, &mut label[..length]).await?;
    let host = String::from_utf8(label[..length].to_vec())
        .map_err(|_| refused(GENERAL_FAILURE, "a domain must be UTF-8"))?;
    Ok(Destination::Domain(host))
}

/// Writes the two-byte method selection.
async fn answer_methods<S>(stream: &mut S, chosen: u8) -> Result<(), Refusal>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, chosen])
        .await
        .map_err(|_| hangup("the greeting answer did not reach the client"))
}

/// Builds a reply: the header and bound address, plus how many of the twenty-two
/// written bytes are real — ten for an IPv4 bound address, twenty-two for IPv6.
fn encode(rep: u8, bound: SocketAddr) -> ([u8; 22], usize) {
    let mut reply = [0_u8; 22];
    match bound {
        SocketAddr::V4(address) => {
            reply[..4].copy_from_slice(&[VERSION, rep, 0, ATYP_IPV4]);
            reply[4..8].copy_from_slice(&address.ip().octets());
            reply[8..10].copy_from_slice(&address.port().to_be_bytes());
            (reply, 10)
        }
        SocketAddr::V6(address) => {
            reply[..4].copy_from_slice(&[VERSION, rep, 0, ATYP_IPV6]);
            reply[4..20].copy_from_slice(&address.ip().octets());
            reply[20..].copy_from_slice(&address.port().to_be_bytes());
            (reply, 22)
        }
    }
}

/// A refusal the client can be told about.
#[must_use]
const fn refused(rep: u8, reason: &'static str) -> Refusal {
    Refusal::Reply { rep, reason }
}

/// A refusal that is nothing but a closed socket.
#[must_use]
const fn hangup(reason: &'static str) -> Refusal {
    Refusal::HangUp { reason }
}

/// How long a local client may take to send its greeting.
///
/// [`FIRST_BYTE_BUDGET`] is upstream's bound on the first byte of a *forwarded*
/// request (v2.0.1 `src/config/node/outbound.rs:169`), and a SOCKS5 greeting is a
/// first byte too. The ceiling exists so that a client which connects and stops
/// talking holds a task for fifteen seconds instead of forever; it is spent before
/// any node is contacted, so it can never shorten what a node is given.
pub const GREETING_BUDGET: Duration = FIRST_BYTE_BUDGET;

/// How long a client may take to finish the request after its greeting was
/// answered.
///
/// The same bound as the greeting, applied apart: a client that sends
/// `[0x05, 0x01, 0x00]` and then stalls is a different failure from one that never
/// says hello, and each gets its own budget rather than sharing one across both
/// reads.
pub const REQUEST_BUDGET: Duration = FIRST_BYTE_BUDGET;

/// A SOCKS5 edge: what it can open tunnels to, and how many it will have at once.
///
/// Cloning is cheap — two `Arc`s — because every accepted connection needs its own
/// handle on the same shared state: the same nodes, the same limits, the same
/// beliefs about which address family answers.
pub struct Proxy<E: Establish> {
    establish: Arc<E>,
    gate: Arc<Gate>,
}

impl<E: Establish> Proxy<E> {
    /// Builds a service over one establishment seam and one set of limits.
    #[must_use]
    pub fn new(establish: E, gate: Gate) -> Self {
        Self {
            establish: Arc::new(establish),
            gate: Arc::new(gate),
        }
    }

    /// The limits this service enforces, for `doctor` and for tests.
    #[must_use]
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    /// Runs one local exchange to its end, answering the client as it goes.
    ///
    /// `bound` is this process's own end of the connection, which is what `BND.ADDR`
    /// and `BND.PORT` report. Every path out of here leaves the client told
    /// something — a reply code, or a socket with nothing on it — so what comes
    /// back is only for the log and the scheduler.
    pub async fn handle<S>(&self, stream: &mut S, bound: SocketAddr) -> Outcome
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // The greeting comes first, and that is a protocol requirement rather than
        // a preference: a client reads the two-byte method selection before it reads
        // anything else, so a refusal sent before it would be parsed as a method
        // this proxy chose. Greeting first means every answer from here on is a
        // well-formed reply, including the ones this edge refuses itself.
        if let Err(refusal) = greet(stream).await {
            return self.decline(stream, refusal, bound).await;
        }

        // Held for the whole exchange, relay included: the limit being enforced is
        // "how many local connections does this process carry", not "how many has
        // it looked at".
        let Some(connection) = self.gate.admit_connection() else {
            return self
                .fail(stream, bound, Error::Limit(Limit::LocalConnections))
                .await;
        };
        match read_request_under_budget(stream).await {
            Err(refusal) => self.decline(stream, refusal, bound).await,
            Ok(request) => self.tunnel(stream, bound, connection, request).await,
        }
    }

    /// The half of the exchange that involves a node.
    async fn tunnel<S>(
        &self,
        stream: &mut S,
        bound: SocketAddr,
        // Kept alive for the whole call, which is the connection's whole life: the
        // slot is released when this returns, not when authentication does.
        _connection: OwnedSemaphorePermit,
        request: Request,
    ) -> Outcome
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Some(handshake) = self.gate.admit_handshake() else {
            return self
                .fail(stream, bound, Error::Limit(Limit::Handshakes))
                .await;
        };
        let Request { destination, port } = request;
        let established = self.establish.establish(destination, port).await;
        // Authentication is over; a tunnel that then sits open for an hour is not
        // entitled to a slot another connection needs to get in.
        drop(handshake);

        match established {
            Err(error) => self.fail(stream, bound, error).await,
            Ok(Established {
                mut session,
                mut completion,
                ..
            }) => {
                completion.begin();
                // This reply is the last free choice in the exchange. From here the
                // session belongs to one node and one socket, so a stalled or reset
                // transfer is reported to the client as an ended connection rather
                // than quietly retried somewhere else.
                if let Err(refusal) = answer(stream, SUCCEEDED, bound).await {
                    // The client hung up between its request and this answer. The
                    // tunnel is dropped with `session`, which is the only honest
                    // cleanup left: nothing was told to anyone, so nothing has to
                    // be taken back.
                    return Outcome::refused(&refusal);
                }
                match carry_observed(stream, &mut session, &mut completion.progress).await {
                    Ok(transferred) => {
                        completion.downlink = match session.downlink() {
                            crate::transport::Downlink::Framed => "framed",
                            crate::transport::Downlink::Outer => "outer",
                            crate::transport::Downlink::Direct => "direct",
                        };
                        completion.finish(None);
                        Outcome::Carried(transferred)
                    }
                    Err(error) => {
                        let error = verdict(session.failure(), error);
                        completion.downlink = match session.downlink() {
                            crate::transport::Downlink::Framed => "framed",
                            crate::transport::Downlink::Outer => "outer",
                            crate::transport::Downlink::Direct => "direct",
                        };
                        completion.finish(Some(&error));
                        Outcome::Failed(error)
                    }
                }
            }
        }
    }

    /// Sends the reply code a codec refusal implies, and reports it.
    async fn decline<S>(&self, stream: &mut S, refusal: Refusal, bound: SocketAddr) -> Outcome
    where
        S: AsyncWrite + Unpin,
    {
        let outcome = Outcome::refused(&refusal);
        if let Some(rep) = refusal.rep() {
            // A client that has already gone cannot be told, and its absence is not
            // a second failure worth reporting over the first.
            let _ = answer(stream, rep, bound).await;
        }
        outcome
    }

    /// Sends the closest reply code SOCKS5 has for a taxonomy failure, and keeps the
    /// failure itself for the log.
    async fn fail<S>(&self, stream: &mut S, bound: SocketAddr, error: Error) -> Outcome
    where
        S: AsyncWrite + Unpin,
    {
        let rep = reply_for(&error);
        let _ = answer(stream, rep, bound).await;
        Outcome::Failed(error)
    }
}

impl<E: Establish> Clone for Proxy<E> {
    fn clone(&self) -> Self {
        Self {
            establish: Arc::clone(&self.establish),
            gate: Arc::clone(&self.gate),
        }
    }
}

impl<E: Establish> fmt::Debug for Proxy<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The seam is deliberately not printed: what it can reach is a set of nodes
        // whose identity is secret material.
        formatter
            .debug_struct("Proxy")
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

/// How one local exchange ended, in the forms a log line and a scheduler need.
#[derive(Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The tunnel was confirmed, carried bytes, and both directions finished.
    Carried(Transferred),
    /// The client was refused or hung up, and no node was ever asked about it.
    ///
    /// This half of the split is the one that keeps scoring honest: a malformed
    /// request, an unsupported command and a browser that closed the socket early
    /// are all local facts, and counting any of them against a server is how a
    /// healthy node gets circuit-broken by a typo.
    Refused {
        /// The reply code the client was given, or `None` for a silent hang-up.
        rep: Option<u8>,
        /// Why, in the words this module chose rather than the peer's.
        reason: &'static str,
    },
    /// A node was asked, or a tunnel was up, and something failed.
    ///
    /// [`Error::classify`] decides whether the node earned it; this type does not
    /// guess, which is what lets a local limit and a dead server stay apart on the
    /// way to the scheduler.
    Failed(Error),
}

impl Outcome {
    /// Reports a codec refusal, before the reply has been written.
    fn refused(refusal: &Refusal) -> Self {
        Self::Refused {
            rep: refusal.rep(),
            reason: refusal.reason(),
        }
    }
}

/// The reply code SOCKS5 has for this failure, chosen for what the client can do
/// about it rather than for what happened.
///
/// The mapping is lossy on purpose: RFC 1928 gives a client six words, and the
/// taxonomy has far more. Nothing is folded into a *more* actionable code than the
/// failure supports, which is why the local and node-shaped failures below all end
/// up on [`GENERAL_FAILURE`] — the client cannot fix any of them, and pretending
/// otherwise sends it retrying something that will not change.
#[must_use]
pub fn reply_for(error: &Error) -> u8 {
    match error {
        // A rule said no: this edge's limits, or the node's policy.
        Error::Limit(_) | Error::Rejected(RejectReason::Unauthorized | RejectReason::Forbidden) => {
            NOT_ALLOWED
        }
        // Nothing was reachable at that name. This is the one answer a client can
        // act on by asking for a different address.
        Error::Rejected(RejectReason::DestinationUnreachable) | Error::Dns(_) => HOST_UNREACHABLE,
        // The node refused with a status this protocol has no word for.
        Error::Rejected(RejectReason::Other(_)) => CONNECTION_REFUSED,
        // Everything else is this client, or the path to it, failing.
        Error::Config(_)
        | Error::Transport(_)
        | Error::Handshake(_)
        | Error::Session(_)
        | Error::Cancelled
        | Error::Io(_) => GENERAL_FAILURE,
    }
}

/// The greeting stage, under the budget for the bytes it waits for.
async fn greet<S>(stream: &mut S) -> Result<(), Refusal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    time::timeout(GREETING_BUDGET, negotiate(stream))
        .await
        .map_err(|_elapsed| hangup("the greeting did not arrive in time"))??;
    Ok(())
}

/// The request stage, under the budget for the bytes it waits for.
async fn read_request_under_budget<S>(stream: &mut S) -> Result<Request, Refusal>
where
    S: AsyncRead + Unpin,
{
    time::timeout(REQUEST_BUDGET, read_request(stream))
        .await
        .map_err(|_elapsed| hangup("the request did not arrive in time"))?
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::DuplexStream;
    use tokio::time;

    use crate::error::{DnsError, HandshakeError, SessionError, TransportError};
    use crate::inbound::{Establishment, MAX_LOCAL_CONNECTIONS};

    use super::*;

    /// A refusal reduced to the two things a test can act on.
    #[derive(Debug, Eq, PartialEq)]
    struct Answer {
        rep: Option<u8>,
        reason: &'static str,
    }

    impl From<Refusal> for Answer {
        fn from(refusal: Refusal) -> Self {
            Self {
                rep: refusal.rep(),
                reason: refusal.reason(),
            }
        }
    }

    /// Roomier than anything a client is allowed to send, so a test's write always
    /// lands without the codec having to read for it. What a test then judges is the
    /// codec's own decision, not a race between the two halves of a pipe.
    const CLIENT_ROOM: usize = 1024;

    /// How long one stage may take before the suite calls it stuck.
    ///
    /// A codec that waits on bytes a well-formed client never sent would otherwise
    /// park the test forever; the budget turns that into a failure, and every test
    /// here runs on a mocked clock, so the bound costs nothing when the codec works.
    const STAGE_BUDGET: Duration = Duration::from_secs(2);

    /// Everything the inbound wrote before it closed its own half.
    async fn drain(client: &mut DuplexStream) -> Vec<u8> {
        let mut seen = Vec::new();
        client
            .read_to_end(&mut seen)
            .await
            .expect("the client can read what the inbound wrote");
        seen
    }

    /// The greeting stage: what the inbound answered, and what it decided.
    ///
    /// The client's write half stays open the whole time, so a refusal cannot be
    /// mistaken for a socket the client hung up on.
    async fn greeting(sent: &[u8]) -> (Vec<u8>, Result<(), Refusal>) {
        let (mut client, mut peer) = tokio::io::duplex(CLIENT_ROOM);
        client
            .write_all(sent)
            .await
            .expect("a greeting always fits the pipe");
        let outcome = time::timeout(STAGE_BUDGET, negotiate(&mut peer))
            .await
            .expect("the greeting is decided, not parked");
        drop(peer);
        (drain(&mut client).await, outcome)
    }

    /// The request stage: what the inbound answered, and what it decided.
    async fn request(sent: &[u8]) -> (Vec<u8>, Result<Request, Refusal>) {
        let (mut client, mut peer) = tokio::io::duplex(CLIENT_ROOM);
        client
            .write_all(sent)
            .await
            .expect("a request always fits the pipe");
        let outcome = time::timeout(STAGE_BUDGET, read_request(&mut peer))
            .await
            .expect("the request is decided, not parked");
        drop(peer);
        (drain(&mut client).await, outcome)
    }

    /// A client that promises three methods, sends one, and then goes away: the
    /// shape of a half-written greeting, which has to end as a refusal rather than
    /// as a task parked on bytes that will never arrive.
    #[tokio::test(start_paused = true)]
    async fn a_greeting_that_stops_mid_list_is_refused_once_the_client_is_gone() {
        let (mut client, mut peer) = tokio::io::duplex(64);
        let refusal = tokio::join!(
            async move {
                client
                    .write_all(&[0x05, 0x03, 0x00])
                    .await
                    .expect("promise three methods, send one");
                client.flush().await.expect("flush");
                drop(client);
            },
            negotiate(&mut peer)
        )
        .1;
        assert_eq!(
            Answer::from(refusal.expect_err("an incomplete method list is not a greeting")),
            Answer {
                rep: None,
                reason: "the request stopped arriving"
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_reply_codes_are_the_numbers_the_client_reads() {
        // Every code this module answers with is RFC 1928's own number, in
        // particular the two a client can only guess at from the RFC table.
        assert_eq!((VERSION, NO_AUTH, NO_ACCEPTABLE_METHODS), (5, 0, 0xFF));
        assert_eq!(
            (
                GENERAL_FAILURE,
                NOT_ALLOWED,
                HOST_UNREACHABLE,
                CONNECTION_REFUSED,
                COMMAND_NOT_SUPPORTED,
                ADDRESS_NOT_SUPPORTED
            ),
            (1, 2, 4, 5, 7, 8)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_greeting_that_offers_no_authentication_is_answered_with_it() {
        let (seen, outcome) = greeting(&[0x05, 0x03, 0x02, 0x00, 0x01]).await;
        assert_eq!(seen, [VERSION, NO_AUTH], "no authentication is offered");
        assert!(outcome.is_ok(), "the greeting is accepted");
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_offers_only_gssapi_is_told_so_in_the_protocol_s_own_form() {
        let (seen, outcome) = greeting(&[0x05, 0x02, 0x01, 0x02]).await;
        assert_eq!(seen, [VERSION, NO_ACCEPTABLE_METHODS]);
        assert_eq!(
            Answer::from(outcome.expect_err("an unusable method list cannot be accepted")),
            Answer {
                rep: None,
                reason: "no acceptable methods"
            },
            "the selection answer is not a request reply"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_version_that_is_not_five_is_not_answered_at_all() {
        // SOCKS4 opens with 0x04 followed by a port; a proxy that answered it
        // would be guessing at what the client meant.
        let (seen, outcome) = greeting(&[0x04, 0x01, 0x00, 0x50]).await;
        assert!(seen.is_empty(), "nothing is written back: {seen:?}");
        assert_eq!(
            Answer::from(outcome.expect_err("a non-SOCKS5 peer is refused")),
            Answer {
                rep: None,
                reason: "not a SOCKS5 greeting"
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_greeting_naming_zero_methods_is_not_a_greeting() {
        let (seen, outcome) = greeting(&[0x05, 0x00]).await;
        assert!(
            seen.is_empty(),
            "a zero method count gets no answer: {seen:?}"
        );
        assert_eq!(
            Answer::from(outcome.expect_err("zero methods cannot be accepted")),
            Answer {
                rep: None,
                reason: "the greeting names no methods"
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_ipv4_connect_is_read_as_the_destination_it_names() {
        let (seen, outcome) =
            request(&[0x05, CONNECT, 0x00, ATYP_IPV4, 203, 0, 113, 1, 0x01, 0xbb]).await;
        assert!(seen.is_empty(), "a good request is not answered here");
        let request = outcome.expect("a well-formed IPv4 request");
        assert_eq!(request.destination, Destination::IPv4([203, 0, 113, 1]));
        assert_eq!(request.port, 443);
    }

    #[tokio::test(start_paused = true)]
    async fn an_ipv6_connect_keeps_all_sixteen_bytes() {
        let mut sent = vec![0x05_u8, CONNECT, 0x00, ATYP_IPV6];
        sent.extend(Ipv6Addr::LOCALHOST.octets());
        sent.extend(80_u16.to_be_bytes());
        let request = request(&sent).await.1.expect("a well-formed IPv6 request");
        assert_eq!(
            request.destination,
            Destination::IPv6(Ipv6Addr::LOCALHOST.octets())
        );
        assert_eq!(request.port, 80);
    }

    #[tokio::test(start_paused = true)]
    async fn a_domain_travels_as_a_domain_and_not_as_a_resolved_address() {
        let name = b"example.com";
        let length = u8::try_from(name.len()).expect("a real host name fits one label byte");
        let mut sent = vec![0x05_u8, CONNECT, 0x00, ATYP_DOMAIN, length];
        sent.extend(name);
        sent.extend(443_u16.to_be_bytes());
        let request = request(&sent)
            .await
            .1
            .expect("a well-formed domain request");
        assert_eq!(
            request.destination,
            Destination::Domain("example.com".to_owned()),
            "resolving here would let a local client pin a name the node should resolve"
        );
    }

    /// The longest label the format can name must be readable, because that is the
    /// bound the fixed buffer is sized to.
    #[tokio::test(start_paused = true)]
    async fn a_whole_255_byte_label_is_read_by_a_buffer_that_never_grows() {
        let longest = u8::try_from(MAX_DOMAIN_LEN).expect("the protocol bound fits one byte");
        let mut sent = vec![0x05_u8, CONNECT, 0x00, ATYP_DOMAIN, longest];
        sent.resize(sent.len() + usize::from(longest), b'a');
        sent.extend(443_u16.to_be_bytes());
        // A duplex smaller than the request still completes: the inbound consumes
        // in bounded pieces, so the client's write drains as the codec reads.
        let (mut client, mut peer) = tokio::io::duplex(64);
        let (request, ()) = tokio::join!(read_request(&mut peer), async {
            client.write_all(&sent).await.expect("write the request");
            client.flush().await.expect("flush");
        },);
        let Destination::Domain(host) = request.expect("the longest legal label").destination
        else {
            panic!("a label must stay a label");
        };
        assert_eq!(host.len(), MAX_DOMAIN_LEN);
        assert!(host.bytes().all(|byte| byte == b'a'));
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_or_non_utf_domain_is_refused_by_name() {
        let cases = [
            (
                vec![0x05_u8, CONNECT, 0x00, ATYP_DOMAIN, 0x00],
                "an empty domain is not a destination",
            ),
            (
                vec![0x05, CONNECT, 0x00, ATYP_DOMAIN, 0x01, 0xFF, 0x01, 0xbb],
                "a domain must be UTF-8",
            ),
        ];
        for (sent, reason) in cases {
            let (_, outcome) = request(&sent).await;
            assert_eq!(
                Answer::from(outcome.expect_err("an unusable domain must be refused")),
                Answer {
                    rep: Some(GENERAL_FAILURE),
                    reason
                }
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unknown_address_type_is_refused_by_name() {
        let (_, outcome) = request(&[0x05, CONNECT, 0x00, 0x05, 0x01, 0xbb]).await;
        assert_eq!(
            Answer::from(outcome.expect_err("ATYP 5 does not exist")),
            Answer {
                rep: Some(ADDRESS_NOT_SUPPORTED),
                reason: "that address type is not supported"
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_reserved_byte_that_is_not_zero_is_not_a_request() {
        let (_, outcome) =
            request(&[0x05, CONNECT, 0x01, ATYP_IPV4, 127, 0, 0, 1, 0x01, 0xbb]).await;
        assert_eq!(
            Answer::from(outcome.expect_err("RFC 1928 reserves that byte")),
            Answer {
                rep: None,
                reason: "the reserved byte is not zero"
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn port_zero_is_refused_before_a_node_is_bothered() {
        let (_, outcome) =
            request(&[0x05, CONNECT, 0x00, ATYP_IPV4, 203, 0, 113, 1, 0x00, 0x00]).await;
        assert_eq!(
            Answer::from(outcome.expect_err("port 0 is not a destination")),
            Answer {
                rep: Some(GENERAL_FAILURE),
                reason: "port 0 is not a destination"
            }
        );
    }

    /// `BIND` and `UDP ASSOCIATE` are refused *after* their address is read, so the
    /// next thing read is the next request rather than the middle of this one.
    #[tokio::test(start_paused = true)]
    async fn an_unsupported_command_is_refused_after_its_address_was_read() {
        let bind = [0x05_u8, BIND, 0x00, ATYP_IPV4, 203, 0, 113, 1, 0x01, 0xbb];
        let connect = [
            0x05_u8, CONNECT, 0x00, ATYP_IPV4, 198, 51, 100, 7, 0x01, 0xbb,
        ];
        let udp = [
            0x05_u8,
            UDP_ASSOCIATE,
            0x00,
            ATYP_IPV4,
            198,
            51,
            100,
            8,
            0x01,
            0xbb,
        ];
        for (command, sent) in [(BIND, bind.as_slice()), (UDP_ASSOCIATE, udp.as_slice())] {
            let (mut client, mut peer) = tokio::io::duplex(64);
            let ((), second) = tokio::join!(
                async {
                    client.write_all(sent).await.expect("send the command");
                    client
                        .write_all(&connect)
                        .await
                        .expect("send the request after it");
                    client.flush().await.expect("flush both");
                },
                async {
                    let refused = read_request(&mut peer).await.expect_err("out of scope");
                    let next = read_request(&mut peer)
                        .await
                        .expect("the next request parses");
                    (refused, next)
                },
            );
            assert_eq!(
                Answer::from(second.0),
                Answer {
                    rep: Some(COMMAND_NOT_SUPPORTED),
                    reason: if command == BIND {
                        "BIND is not supported"
                    } else {
                        "UDP ASSOCIATE is not supported"
                    }
                }
            );
            assert_eq!(
                second.1.destination,
                Destination::IPv4([198, 51, 100, 7]),
                "the refused request left no unread bytes of its own behind"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unknown_command_is_refused_by_name() {
        let (_, outcome) =
            request(&[0x05, 0x09, 0x00, ATYP_IPV4, 203, 0, 113, 1, 0x01, 0xbb]).await;
        assert_eq!(
            Answer::from(outcome.expect_err("command 9 is not assigned")),
            Answer {
                rep: Some(COMMAND_NOT_SUPPORTED),
                reason: "that command is not supported"
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_successful_reply_echoes_this_process_s_own_bound_address() {
        let bound = SocketAddr::from((Ipv4Addr::LOCALHOST, 10808));
        let (mut client, mut peer) = tokio::io::duplex(64);
        let (outcome, reply) = tokio::join!(answer(&mut peer, SUCCEEDED, bound), async {
            let mut reply = [0_u8; 10];
            client.read_exact(&mut reply).await.expect("read the reply");
            reply
        },);
        outcome.expect("the reply is written");
        assert_eq!(
            reply,
            [0x05, SUCCEEDED, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x2a, 0x38],
            "ten bytes, and the address is this process's own"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_ipv6_bound_address_is_answered_in_kind() {
        let bound = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 10808);
        let (mut client, mut peer) = tokio::io::duplex(64);
        let (outcome, reply) = tokio::join!(answer(&mut peer, HOST_UNREACHABLE, bound), async {
            let mut reply = [0_u8; 22];
            client.read_exact(&mut reply).await.expect("read the reply");
            reply
        },);
        outcome.expect("the reply is written");
        assert_eq!(&reply[..4], [VERSION, HOST_UNREACHABLE, 0x00, ATYP_IPV6]);
        assert_eq!(&reply[4..20], Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&reply[20..], 10808_u16.to_be_bytes());
    }

    /// A client that hung up before the answer is not a failure this inbound can
    /// report in SOCKS5's vocabulary, so it is reported as a closed socket rather
    /// than as a panic on a write nobody is reading.
    #[tokio::test(start_paused = true)]
    async fn a_reply_to_a_client_that_is_gone_is_a_hang_up_rather_than_a_panic() {
        let (client, mut peer) = tokio::io::duplex(64);
        drop(client);
        let outcome = answer(
            &mut peer,
            SUCCEEDED,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 10808)),
        )
        .await;
        assert_eq!(
            Answer::from(outcome.expect_err("writing to a closed client cannot succeed")),
            Answer {
                rep: None,
                reason: "the reply did not reach the client"
            }
        );
    }

    /// Counts how many times a seam was asked, which is how the tests below prove a
    /// refusal never reached a node.
    #[derive(Clone, Default)]
    struct Tally(Arc<AtomicUsize>);

    impl Tally {
        fn bump(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn seen(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// A stand-in for everything above the edge: it counts the ask and always
    /// answers with the same failure.
    ///
    /// It cannot answer with a tunnel, because a tunnel is an authenticated session
    /// with a real server — which is what `tests/interop_v201.rs` is for. What this
    /// covers is the part a fake can decide: what the client is told, and whether a
    /// node was contacted at all.
    struct Fake {
        seen: Tally,
        failure: Error,
    }

    impl Fake {
        fn refusing(seen: Tally, failure: Error) -> Self {
            Self { seen, failure }
        }
    }

    impl Establish for Fake {
        fn establish(&self, destination: Destination, port: u16) -> Establishment {
            self.seen.bump();
            drop((destination, port));
            let failure = self.failure.clone();
            Box::pin(async move { Err(failure) })
        }
    }

    /// Long past both stage budgets, so the codec's own decisions always win the
    /// race, and a service that truly parked would still fail rather than hang.
    const EXCHANGE_BUDGET: Duration = Duration::from_secs(60);

    /// A greeting and one `CONNECT`, exactly as a client sends them back to back.
    fn connect_to_ipv4() -> Vec<u8> {
        let mut sent = vec![VERSION, 0x01, NO_AUTH];
        sent.extend([
            VERSION, CONNECT, 0x00, ATYP_IPV4, 203, 0, 113, 1, 0x01, 0xbb,
        ]);
        sent
    }

    /// The code in the request reply. Two bytes of method selection come first, and
    /// then the reply carries its own version byte before the code: a client reads
    /// `[5, 0]` as "no authentication", then `[5, REP, 0, ATYP, …]` as the answer.
    fn rep_of(answered: &[u8]) -> Option<u8> {
        answered.get(3).copied()
    }

    /// One whole exchange, from the client's side of a pipe.
    async fn exchange<S: Establish>(proxy: &Proxy<S>, sent: &[u8]) -> (Vec<u8>, Outcome) {
        let bound = SocketAddr::from((Ipv4Addr::LOCALHOST, 10808));
        let (mut client, mut peer) = tokio::io::duplex(CLIENT_ROOM);
        client
            .write_all(sent)
            .await
            .expect("a whole exchange always fits the pipe");
        let outcome = time::timeout(EXCHANGE_BUDGET, proxy.handle(&mut peer, bound))
            .await
            .expect("the exchange is decided, not parked");
        drop(peer);
        (drain(&mut client).await, outcome)
    }

    /// A refusal is answered in SOCKS5's own vocabulary, and the node behind this
    /// edge is never asked about it.
    #[tokio::test(start_paused = true)]
    async fn an_unsupported_command_is_answered_without_reaching_a_node() {
        let seen = Tally::default();
        let proxy = Proxy::new(
            Fake::refusing(seen.clone(), Error::Cancelled),
            Gate::default(),
        );
        let mut sent = vec![VERSION, 0x01, NO_AUTH];
        sent.extend([VERSION, BIND, 0x00, ATYP_IPV4, 203, 0, 113, 1, 0x01, 0xbb]);
        let (reply, outcome) = exchange(&proxy, &sent).await;

        assert_eq!(
            rep_of(&reply),
            Some(COMMAND_NOT_SUPPORTED),
            "the client is told the command, not that the proxy broke: {reply:?}"
        );
        assert_eq!(
            seen.seen(),
            0,
            "a command this client does not implement cannot have been forwarded"
        );
        assert!(
            matches!(
                outcome,
                Outcome::Refused {
                    rep: Some(COMMAND_NOT_SUPPORTED),
                    ..
                }
            ),
            "{outcome:?}"
        );
    }

    /// The two local limits are reported as the rule they are, and neither one is
    /// paid for by contacting a node.
    #[tokio::test(start_paused = true)]
    async fn a_full_edge_refuses_without_bothering_a_node() {
        for (gate, limit) in [
            (Gate::new(0, 8), Limit::LocalConnections),
            (Gate::new(8, 0), Limit::Handshakes),
        ] {
            let seen = Tally::default();
            let proxy = Proxy::new(Fake::refusing(seen.clone(), Error::Cancelled), gate);
            let (reply, outcome) = exchange(&proxy, &connect_to_ipv4()).await;

            assert_eq!(
                reply.get(..2),
                Some(&[VERSION, NO_AUTH][..]),
                "{limit} is refused after a greeting was answered, so the reply \
                 below cannot be read as a method selection: {reply:?}"
            );
            assert_eq!(rep_of(&reply), Some(NOT_ALLOWED), "{limit}");
            assert_eq!(seen.seen(), 0, "{limit} is reached before a dial");
            assert!(
                matches!(&outcome, Outcome::Failed(error) if *error == Error::Limit(limit)),
                "{outcome:?}"
            );
        }
    }

    /// Each taxonomy failure gets the code a client can act on, and gets it after
    /// exactly one ask: the session that failed is never replayed somewhere else.
    #[tokio::test(start_paused = true)]
    async fn the_node_s_answer_becomes_the_code_the_client_reads() {
        let cases = [
            (
                Error::Rejected(RejectReason::DestinationUnreachable),
                HOST_UNREACHABLE,
            ),
            (Error::Rejected(RejectReason::Unauthorized), NOT_ALLOWED),
            (Error::Rejected(RejectReason::Forbidden), NOT_ALLOWED),
            (Error::Rejected(RejectReason::Other(4)), CONNECTION_REFUSED),
            (Error::Dns(DnsError::NoAddress), HOST_UNREACHABLE),
            (
                Error::Handshake(HandshakeError::IdentityMismatch),
                GENERAL_FAILURE,
            ),
            (Error::Transport(TransportError::Timeout), GENERAL_FAILURE),
        ];
        for (failure, rep) in cases {
            let seen = Tally::default();
            let proxy = Proxy::new(
                Fake::refusing(seen.clone(), failure.clone()),
                Gate::default(),
            );
            let (reply, outcome) = exchange(&proxy, &connect_to_ipv4()).await;

            assert_eq!(rep_of(&reply), Some(rep), "for {failure}");
            assert_eq!(seen.seen(), 1, "{failure} is asked about once");
            assert!(
                matches!(&outcome, Outcome::Failed(error) if *error == failure),
                "{outcome:?} keeps the taxonomy, not just the code"
            );
        }
    }

    /// A client that connects and never speaks is dropped once its own stage runs
    /// out, on a mocked clock, rather than holding a slot forever.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_says_nothing_is_hung_up_on_rather_than_waited_for() {
        let seen = Tally::default();
        let proxy = Proxy::new(
            Fake::refusing(seen.clone(), Error::Cancelled),
            Gate::default(),
        );
        let bound = SocketAddr::from((Ipv4Addr::LOCALHOST, 10808));
        let (client, mut peer) = tokio::io::duplex(CLIENT_ROOM);
        let outcome = proxy.handle(&mut peer, bound).await;

        assert!(
            matches!(&outcome,
                Outcome::Refused { rep: None, reason } if *reason == "the greeting did not arrive in time"
            ),
            "{outcome:?}"
        );
        assert_eq!(seen.seen(), 0);
        assert_eq!(
            proxy.gate().connections_available(),
            MAX_LOCAL_CONNECTIONS,
            "the slot came back with the exchange"
        );
        drop(client);
    }

    /// The greeting and the request have separate budgets, which is only visible
    /// when one of them is spent and the other is not: here the greeting *was*
    /// answered, and it is the request that never came.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_stops_after_its_greeting_is_hung_up_on_too() {
        let seen = Tally::default();
        let proxy = Proxy::new(
            Fake::refusing(seen.clone(), Error::Cancelled),
            Gate::default(),
        );
        let bound = SocketAddr::from((Ipv4Addr::LOCALHOST, 10808));
        let (mut client, mut peer) = tokio::io::duplex(CLIENT_ROOM);
        client
            .write_all(&[VERSION, 0x01, NO_AUTH])
            .await
            .expect("a greeting fits the pipe");
        let outcome = proxy.handle(&mut peer, bound).await;

        let mut answer = [0_u8; 2];
        client
            .read_exact(&mut answer)
            .await
            .expect("the greeting was answered");
        assert_eq!(answer, [VERSION, NO_AUTH]);
        assert!(
            matches!(&outcome,
                Outcome::Refused { rep: None, reason } if *reason == "the request did not arrive in time"
            ),
            "{outcome:?}"
        );
        assert_eq!(seen.seen(), 0, "an unanswered request never reached a node");
    }

    /// A limit, a policy refusal and a name with no address all mean something a
    /// node did not do, so the taxonomy says so and the codes keep that apart too.
    #[test]
    fn a_failure_that_is_this_side_s_own_is_not_reported_as_a_destination_problem() {
        assert_eq!(reply_for(&Error::Limit(Limit::Probes)), NOT_ALLOWED);
        assert_eq!(
            reply_for(&Error::Dns(DnsError::NoAddress)),
            HOST_UNREACHABLE,
            "the client is entitled to know nothing answered that name"
        );
        for failure in [
            Error::Config("no such node".to_owned()),
            Error::Cancelled,
            Error::Io("too many open files".to_owned()),
            Error::Session(SessionError::KeyExhausted),
            Error::Transport(TransportError::Connect("refused".to_owned())),
        ] {
            assert_eq!(
                reply_for(&failure),
                GENERAL_FAILURE,
                "{failure} is not something the client can fix"
            );
        }
    }
}
