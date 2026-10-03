//! HTTP `CONNECT`, which is what `HTTPS_PROXY=http://127.0.0.1:10809` asks for.
//!
//! A proxy that answers `CONNECT` is the difference between a library that happens
//! to support proxies and a machine where one exists: `curl`, `git`, `pip`, Node's
//! `fetch` and the Rust HTTP clients all speak it, and most of them refuse to speak
//! SOCKS5 when told `http://`. The request line is `CONNECT host:port HTTP/1.1`, the
//! answer is `200`, and everything after that answer is an opaque byte pipe — which
//! is why this inbound needs no HTTP semantics beyond the head. The tunnel either
//! opens or it does not; there is no body, no content negotiation, and no
//! re-attempting a request that failed.
//!
//! Three properties are deliberate.
//!
//! **The head is bounded by bytes and by time, and by nothing the client decides.**
//! A client may send a header block of any size it likes; [`MAX_HEAD_LEN`] is where
//! this proxy stops counting, and [`HEAD_BUDGET`] is how long it waits for the client
//! to finish. Both are enforced by the reader itself rather than checked afterwards,
//! so the bytes never reach a buffer this process has to keep.
//!
//! **Whatever arrives after the head belongs to the tunnel.** A client is allowed to
//! write its first application bytes before reading the answer, and an HTTP parser
//! that reads in blocks would swallow them. That is why [`Proxy::handle`] wraps the
//! stream in a [`BufReader`] and hands *that* to
//! [`carry`]: the bytes the parser over-read are still in
//! the buffer, and the relay drains them before touching the socket again.
//!
//! **`CONNECT` is the only method, and saying so costs one header.** Forwarding a
//! plain `GET` would mean rewriting request targets, maintaining `Via` and
//! `Forwarded`, and answering on behalf of an origin this client has no business
//! representing. A non-`CONNECT` method gets `405` and an `Allow` line naming the one
//! method there is.
//!
//! The service half ([`Proxy`]) adds the rule the whole crate is built on: **a `200`
//! is the moment the remote session becomes immutable.** [`Proxy::handle`] writes one
//! answer — a status line, or nothing — and then does nothing but [`carry`]. From
//! that `200` there is no retry, no replay
//! and no second server to choose; if the bytes stop, the client's own read is what
//! tells it.
//!
//! One HTTP courtesy is deliberately omitted: no `Proxy-Agent`. Upstreams answer
//! `CONNECT` by naming their own software, and a client that reaches a REALITY node
//! through this edge has good reason not to advertise which proxy it came through. It
//! tells the application nothing it can act on either.

use std::fmt;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time;

use crate::error::{
    DnsError, Error, HandshakeError, Limit, RejectReason, SessionError, TransportError,
};
use crate::handoff::{Established, FIRST_BYTE_BUDGET};
use crate::inbound::{Establish, Gate};
use crate::protocol::vless::Destination;
use crate::transport::relay::carry_observed;
use crate::transport::{Transferred, verdict};

/// Status: the tunnel is open, and the bytes after this line are the tunnel's.
pub const OK: u16 = 200;
/// Status: this proxy cannot tell what was asked (`400`).
pub const BAD_REQUEST: u16 = 400;
/// Status: a rule refused, and the rule is not the destination's (`403`).
pub const FORBIDDEN: u16 = 403;
/// Status: the request named a method this proxy does not implement (`405`).
pub const METHOD_NOT_ALLOWED: u16 = 405;
/// Status: the head is bigger than this proxy is willing to read (`431`).
pub const REQUEST_HEADER_FIELDS_TOO_LARGE: u16 = 431;
/// Status: this client failed, and the destination has nothing to answer for (`500`).
pub const INTERNAL_SERVER_ERROR: u16 = 500;
/// Status: the next hop was reached and did not serve (`502`).
pub const BAD_GATEWAY: u16 = 502;
/// Status: this proxy will not serve right now (`503`).
pub const SERVICE_UNAVAILABLE: u16 = 503;
/// Status: the next hop did not answer in time (`504`).
pub const GATEWAY_TIMEOUT: u16 = 504;
/// Status: the request line's version is not one this proxy speaks (`505`).
pub const HTTP_VERSION_NOT_SUPPORTED: u16 = 505;

/// The method this inbound implements, and the only one it will.
const CONNECT: &[u8] = b"CONNECT";

/// The most head bytes this proxy reads before refusing.
///
/// A real `CONNECT` head is one request line and a handful of fields: under 200
/// bytes for `curl`, under a kilobyte for a browser. Eight kilobytes is that with
/// room for an unusual client, and it is also the size of the buffer the head is read
/// through, so no single read can pass the bound before the bound is checked.
pub const MAX_HEAD_LEN: usize = 8 * 1024;

/// How long a client may take to send its head.
///
/// [`FIRST_BYTE_BUDGET`] is upstream's bound on the first byte of a *forwarded*
/// request (v2.0.1 `src/config/node/outbound.rs:169`), and a `CONNECT` head is that
/// first byte. The ceiling exists so that a client which connects and stops talking
/// holds a task for fifteen seconds instead of forever; it is spent before any node
/// is contacted, so it can never shorten what a node is given.
pub const HEAD_BUDGET: Duration = FIRST_BYTE_BUDGET;

/// The request-line version, kept so the answer can name a version the client
/// announced instead of one it never mentioned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// `HTTP/1.0`.
    One0,
    /// `HTTP/1.1`.
    One1,
}

impl Version {
    /// The version token as it appears on the wire.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::One0 => "HTTP/1.0",
            Self::One1 => "HTTP/1.1",
        }
    }
}

/// The version an answer uses when no request line got as far as naming one.
///
/// A status line has to carry a version, and naming the newest this proxy speaks is
/// the only choice left that is not a guess: the client's version is unknown, and
/// every client that leads with a malformed request reads `HTTP/1.1`.
const UNANNOUNCED: Version = Version::One1;

/// A destination a local client asked to be tunneled to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// Host, kept in the form it arrived in: a literal stays a literal, so the node
    /// resolves only what the application said it should.
    pub destination: Destination,
    /// Port, which the target carries after its last colon.
    pub port: u16,
    /// The version the request line named, which the answer echoes.
    pub version: Version,
}

/// A request this inbound will not act on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Answer with this status, then close.
    Reply {
        /// The status the client will read.
        status: u16,
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
    /// The status, when there is one to send.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Reply { status, .. } => Some(*status),
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

/// Reads the request line and the header block that follows it.
///
/// The bytes come back as the client sent them, terminators included, because
/// deciding what they mean is [`parse`]'s work and a test can judge that decision on
/// a literal rather than on a stream. Reading stops at the blank line that ends the
/// headers, and the tunnel's bytes stay in `reader` — which is the same buffer the
/// relay reads from afterwards, so nothing that arrived early is lost.
///
/// # Errors
///
/// [`Refusal::Reply`] with [`REQUEST_HEADER_FIELDS_TOO_LARGE`] when the head passes
/// [`MAX_HEAD_LEN`]. [`Refusal::HangUp`] when the client closes before the blank
/// line, or when the read itself fails.
pub async fn read_head<S>(reader: &mut BufReader<S>) -> Result<Vec<u8>, Refusal>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    loop {
        // One line per pass. How the stream chose to block the bytes says nothing
        // about where a line ends; only the newline does. The borrow of `reader` ends
        // with this block, which is what lets the bytes be released below.
        let (taken, done) = {
            let Ok(filled) = reader.fill_buf().await else {
                return Err(hangup("the head could not be read"));
            };
            if filled.is_empty() {
                return Err(hangup("the head did not finish before the client hung up"));
            }
            let line = match filled.iter().position(|byte| *byte == b'\n') {
                Some(newline) => &filled[..=newline],
                None => filled,
            };
            let blank = text(line).is_empty();
            if line.len() + head.len() > MAX_HEAD_LEN {
                return Err(refused(
                    REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "the head is larger than this proxy accepts",
                ));
            }
            if blank && head.is_empty() {
                // An empty line ahead of the request line carries no information, and
                // a recipient of a message stream is told to skip it (RFC 9110 §3.3)
                // rather than read it as the request.
                (line.len(), false)
            } else {
                head.extend_from_slice(line);
                (line.len(), blank)
            }
        };
        reader.consume(taken);
        if done {
            return Ok(head);
        }
    }
}

/// Decides what a head means.
///
/// The target is the authority the client wants reached, and nothing else: a `Host:`
/// field is ignored, because a tunnel is named by its target and a `Host:` that
/// disagrees with it is the client's problem rather than this proxy's guess. Header
/// fields are read only far enough to find the blank line, since no field in a
/// `CONNECT` head can change what opening a tunnel to the target means — the byte
/// bound that [`read_head`] enforces is what makes the block harmless.
///
/// # Errors
///
/// [`Refusal::Reply`] with [`METHOD_NOT_ALLOWED`] for any method other than
/// `CONNECT`; [`HTTP_VERSION_NOT_SUPPORTED`] for a version this proxy does not speak;
/// [`BAD_REQUEST`] for a request line that is not three fields, a target that names
/// no port or an unusable one, and a header block that never ends.
pub fn parse(head: &[u8]) -> Result<Request, Refusal> {
    let mut lines = head.split_inclusive(|byte: &u8| *byte == b'\n');
    let Some(line) = lines.next() else {
        return Err(refused(BAD_REQUEST, "a request line must come first"));
    };
    let request = request_line(text(line))?;
    for line in lines {
        if text(line).is_empty() {
            return Ok(request);
        }
    }
    Err(refused(BAD_REQUEST, "the header block is not terminated"))
}

/// Answers one request with the status line a client reads.
///
/// A `200` is the whole answer: no `Proxy-Agent`, no `Content-Length`, and no
/// `Connection: close`, because after this line the socket belongs to the tunnel and
/// an application's bytes are not an HTTP body. Every other status is followed by
/// `Connection: close`, which is the truth — this exchange ends here.
///
/// # Errors
///
/// [`Refusal::HangUp`] when the answer cannot be written, which means the client is
/// already gone.
pub async fn answer<S>(stream: &mut S, version: Version, status: u16) -> Result<(), Refusal>
where
    S: AsyncWrite + Unpin,
{
    let reply = encode(version, status);
    stream
        .write_all(&reply)
        .await
        .map_err(|_| hangup("the answer did not reach the client"))?;
    stream
        .flush()
        .await
        .map_err(|_| hangup("the answer did not reach the client"))
}

/// The request line: method, target, version, and nothing else.
fn request_line(line: &[u8]) -> Result<Request, Refusal> {
    let mut parts = line.splitn(3, |byte: &u8| *byte == b' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(refused(
            BAD_REQUEST,
            "the request line is not method, target and version",
        ));
    };

    // The method comes first, because it is the answer a client can use. A plain
    // `GET` carrying an unsupported version is worth reporting as a method this proxy
    // does not have, since changing the version would not get the request anywhere.
    if method != CONNECT {
        return Err(refused(METHOD_NOT_ALLOWED, "only CONNECT is supported"));
    }
    let version = match version {
        b"HTTP/1.1" => Version::One1,
        b"HTTP/1.0" => Version::One0,
        _ => {
            return Err(refused(
                HTTP_VERSION_NOT_SUPPORTED,
                "that HTTP version is not supported",
            ));
        }
    };
    let (destination, port) = authority(target)?;
    Ok(Request {
        destination,
        port,
        version,
    })
}

/// One authority-form target: host, colon, port.
///
/// Splitting on the *last* colon is what lets an IPv6 literal through — `[::1]:443`
/// is one address and one port — and the brackets are URL syntax rather than part of
/// the address, which [`Destination::parse`] strips.
fn authority(target: &[u8]) -> Result<(Destination, u16), Refusal> {
    let Ok(target) = str::from_utf8(target) else {
        return Err(refused(BAD_REQUEST, "the target is not text"));
    };
    let Some((host, port)) = target.rsplit_once(':') else {
        return Err(refused(BAD_REQUEST, "a CONNECT target must name a port"));
    };
    let Ok(port) = port.parse::<u16>() else {
        return Err(refused(BAD_REQUEST, "the target's port is not a number"));
    };
    let Some((destination, port)) = Destination::parse(host, port) else {
        return Err(refused(
            BAD_REQUEST,
            "the target is not an addressable host",
        ));
    };
    Ok((destination, port))
}

/// One line's content, without its terminator.
///
/// A bare `\n` is accepted as well as `\r\n`: this proxy has one method and one
/// answer, and nothing about a `CONNECT` head becomes ambiguous if a client wrote its
/// line endings with a single byte.
fn text(line: &[u8]) -> &[u8] {
    let line = match line.last() {
        Some(b'\n') => &line[..line.len() - 1],
        _ => line,
    };
    match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    }
}

/// Builds a status line and the fields that follow it.
fn encode(version: Version, status: u16) -> Vec<u8> {
    let mut reply = format!("{} {status} {}\r\n", version.label(), phrase(status));
    if status != OK {
        reply.push_str("Connection: close\r\n");
    }
    for field in fields(status) {
        reply.push_str(field);
        reply.push_str("\r\n");
    }
    reply.push_str("\r\n");
    reply.into_bytes()
}

/// The reason phrase for a status, from the registry HTTP itself uses.
///
/// A client is told to read the number and ignore the phrase (RFC 9110 §15.3), which
/// is precisely why the phrases here are the standard ones: a proxy inventing its own
/// reason text is a sentence no parser is obliged to understand.
const fn phrase(status: u16) -> &'static str {
    match status {
        OK => "Connection Established",
        BAD_REQUEST => "Bad Request",
        FORBIDDEN => "Forbidden",
        METHOD_NOT_ALLOWED => "Method Not Allowed",
        REQUEST_HEADER_FIELDS_TOO_LARGE => "Request Header Fields Too Large",
        INTERNAL_SERVER_ERROR => "Internal Server Error",
        BAD_GATEWAY => "Bad Gateway",
        SERVICE_UNAVAILABLE => "Service Unavailable",
        GATEWAY_TIMEOUT => "Gateway Timeout",
        HTTP_VERSION_NOT_SUPPORTED => "HTTP Version Not Supported",
        _ => "Failure",
    }
}

/// The fields a status must carry.
const fn fields(status: u16) -> &'static [&'static str] {
    match status {
        // RFC 9110 §15.5.6: a `405` response MUST name the methods that are allowed.
        METHOD_NOT_ALLOWED => &["Allow: CONNECT"],
        // RFC 9110 §15.6.4: a `503` response SHOULD say when to try again. One second
        // is a floor rather than a measurement: a slot frees as soon as the connection
        // holding it ends, which this proxy cannot predict.
        SERVICE_UNAVAILABLE => &["Retry-After: 1"],
        _ => &[],
    }
}

/// A refusal the client can be told about.
#[must_use]
const fn refused(status: u16, reason: &'static str) -> Refusal {
    Refusal::Reply { status, reason }
}

/// A refusal that is nothing but a closed socket.
#[must_use]
const fn hangup(reason: &'static str) -> Refusal {
    Refusal::HangUp { reason }
}

/// An HTTP `CONNECT` edge: what it can open tunnels to, and how many it will have at
/// once.
///
/// Cloning is cheap — two `Arc`s — because every accepted connection needs its own
/// handle on the same shared state: the same nodes, the same limits, the same beliefs
/// about which address family answers.
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
    /// The stream is taken by value and stays inside the [`BufReader`] the head is
    /// parsed from, because that reader is also where the client's first tunnel bytes
    /// may already be sitting. Every path out of here leaves the client told
    /// something — a status line, or a socket with nothing on it — so what comes back
    /// is only for the log and the scheduler.
    pub async fn handle<S>(&self, stream: S) -> Outcome
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut reader = BufReader::with_capacity(MAX_HEAD_LEN, stream);
        // Held for the whole exchange, relay included: the limit being enforced is
        // "how many local connections does this process carry", not "how many has it
        // looked at". Unlike SOCKS5, this edge can refuse before it has read a byte,
        // because a status line needs no greeting to have been accepted first.
        let Some(connection) = self.gate.admit_connection() else {
            return self
                .fail(
                    &mut reader,
                    UNANNOUNCED,
                    Error::Limit(Limit::LocalConnections),
                )
                .await;
        };
        let request = match head(&mut reader).await.and_then(|head| parse(&head)) {
            Ok(request) => request,
            Err(refusal) => return self.decline(&mut reader, refusal).await,
        };
        self.tunnel(reader, connection, request).await
    }

    /// The half of the exchange that involves a node.
    async fn tunnel<S>(
        &self,
        mut reader: BufReader<S>,
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
                .fail(
                    &mut reader,
                    request.version,
                    Error::Limit(Limit::Handshakes),
                )
                .await;
        };
        let Request {
            destination,
            port,
            version,
        } = request;
        let established = self.establish.establish(destination, port).await;
        // Authentication is over; a tunnel that then sits open for an hour is not
        // entitled to a slot another connection needs to get in.
        drop(handshake);

        match established {
            Err(error) => self.fail(&mut reader, version, error).await,
            Ok(Established {
                mut session,
                mut completion,
                ..
            }) => {
                completion.begin();
                // This answer is the last free choice in the exchange. From here the
                // session belongs to one node and one socket, so a stalled or reset
                // transfer is reported to the client as an ended connection rather than
                // quietly retried somewhere else.
                if let Err(refusal) = answer(&mut reader, version, OK).await {
                    // The client hung up between its request and this answer. The
                    // tunnel is dropped with `session`, which is the only honest
                    // cleanup left: nothing was told to anyone, so nothing has to be
                    // taken back.
                    return Outcome::refused(&refusal);
                }
                match carry_observed(&mut reader, &mut session, &mut completion.progress).await {
                    Ok(transferred) => {
                        completion.finish(None);
                        Outcome::Carried(transferred)
                    }
                    Err(error) => {
                        let error = verdict(session.failure(), error);
                        completion.finish(Some(&error));
                        Outcome::Failed(error)
                    }
                }
            }
        }
    }

    /// Sends the status a head refusal implies, and reports it.
    async fn decline<S>(&self, stream: &mut BufReader<S>, refusal: Refusal) -> Outcome
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let outcome = Outcome::refused(&refusal);
        if let Some(status) = refusal.status() {
            // A client that has already gone cannot be told, and its absence is not a
            // second failure worth reporting over the first. A refusal that reached
            // this point has no request version to echo, so the answer names the
            // newest this proxy speaks.
            let _ = answer(stream, UNANNOUNCED, status).await;
        }
        outcome
    }

    /// Sends the closest status HTTP has for a taxonomy failure, and keeps the failure
    /// itself for the log.
    async fn fail<S>(&self, stream: &mut BufReader<S>, version: Version, error: Error) -> Outcome
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let status = status_for(&error);
        let _ = answer(stream, version, status).await;
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
    /// request line, a plain `GET` and a browser that closed the socket early are all
    /// local facts, and counting any of them against a server is how a healthy node
    /// gets circuit-broken by a typo.
    Refused {
        /// The status the client was given, or `None` for a silent hang-up.
        status: Option<u16>,
        /// Why, in the words this module chose rather than the peer's.
        reason: &'static str,
    },
    /// A node was asked, or a tunnel was up, and something failed.
    ///
    /// [`Error::classify`] decides whether the node earned it; this type does not
    /// guess, which is what lets a local limit and a dead server stay apart on the way
    /// to the scheduler.
    Failed(Error),
}

impl Outcome {
    /// Reports a codec refusal, before the answer has been written.
    fn refused(refusal: &Refusal) -> Self {
        Self::Refused {
            status: refusal.status(),
            reason: refusal.reason(),
        }
    }
}

/// The status HTTP has for this failure, chosen for what the client can do about it
/// rather than for what happened.
///
/// HTTP gives a proxy better words than SOCKS5 does, and the useful one is the
/// distinction between who was at fault: `502` and `504` describe the destination's
/// side of this process, `500` describes this process, and `503` means the destination
/// was never asked. Folding a local limit into `502` would tell a client that its
/// server is broken, which is how a full connection table turns into a retry storm
/// against a node that is fine.
#[must_use]
pub fn status_for(error: &Error) -> u16 {
    match error {
        // This proxy is the thing that is full or busy, and nothing else.
        Error::Limit(_) | Error::Cancelled => SERVICE_UNAVAILABLE,
        // A budget ran out on the way to the destination, which is the one thing a
        // client's own retry is most likely to fix.
        Error::Dns(DnsError::Timeout)
        | Error::Transport(TransportError::Timeout)
        | Error::Handshake(HandshakeError::Timeout) => GATEWAY_TIMEOUT,
        // The request was legal HTTP and this client could not act on it: a
        // destination field too long for the wire format, no entropy to pad a frame
        // with, a configuration that cannot run, a broken local socket.
        Error::Config(_)
        | Error::Io(_)
        | Error::Transport(TransportError::Local(_))
        | Error::Session(SessionError::RequestTooLong | SessionError::Entropy) => {
            INTERNAL_SERVER_ERROR
        }
        // A rule said no, and the rule is not the destination's.
        Error::Rejected(RejectReason::Unauthorized | RejectReason::Forbidden) => FORBIDDEN,
        // The gateway was reached, or was not, the node refused, or a tunnel that was
        // up stopped being one. These are the statuses that describe the far side of
        // this process rather than this process, and a client's retry policy is
        // written against exactly that difference.
        Error::Dns(_)
        | Error::Transport(_)
        | Error::Handshake(_)
        | Error::Rejected(_)
        | Error::Session(_) => BAD_GATEWAY,
    }
}

/// The head stage, under the budget for the bytes it waits for.
async fn head<S>(reader: &mut BufReader<S>) -> Result<Vec<u8>, Refusal>
where
    S: AsyncRead + Unpin,
{
    time::timeout(HEAD_BUDGET, read_head(reader))
        .await
        .map_err(|_elapsed| hangup("the head did not arrive in time"))?
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, DuplexStream};
    use tokio::time;

    use crate::inbound::{Establishment, MAX_CONCURRENT_HANDSHAKES, MAX_LOCAL_CONNECTIONS};

    use super::*;

    /// A refusal reduced to the two things a test can act on.
    #[derive(Debug, Eq, PartialEq)]
    struct Answer {
        status: Option<u16>,
        reason: &'static str,
    }

    impl From<Refusal> for Answer {
        fn from(refusal: Refusal) -> Self {
            Self {
                status: refusal.status(),
                reason: refusal.reason(),
            }
        }
    }

    /// One request line, with the terminators a client would send around it.
    fn head_of(line: &str) -> Vec<u8> {
        format!("{line}\r\n\r\n").into_bytes()
    }

    /// Roomier than anything a client needs to send, so a test's write always lands
    /// without the reader having to ask for it. What a test then judges is the reader's
    /// own decision, not a race between the two halves of a pipe.
    const CLIENT_ROOM: usize = 32 * 1024;

    /// How long one stage may take before the suite calls it stuck.
    ///
    /// A reader that waits on bytes a well-formed client never sent would otherwise
    /// park the test forever; the budget turns that into a failure, and every test here
    /// runs on a mocked clock, so the bound costs nothing when the reader works.
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

    /// The head stage on its own, over a pipe with `sent` already written into it.
    async fn read(sent: &[u8]) -> (Vec<u8>, Result<Vec<u8>, Refusal>) {
        let (mut client, peer) = tokio::io::duplex(CLIENT_ROOM);
        client
            .write_all(sent)
            .await
            .expect("a head always fits the pipe");
        let mut reader = BufReader::with_capacity(MAX_HEAD_LEN, peer);
        let outcome = time::timeout(STAGE_BUDGET, read_head(&mut reader))
            .await
            .expect("the head is decided, not parked");
        drop(reader);
        (drain(&mut client).await, outcome)
    }

    /// A stand-in for everything above the edge: it counts the ask and always answers
    /// with the same failure.
    ///
    /// It cannot answer with a tunnel, because a tunnel is an authenticated session
    /// with a real server — which is what `tests/interop_v201.rs` is for. What this
    /// covers is the part a fake can decide: what the client is told, and whether a
    /// node was contacted at all.
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

    /// Long past the head budget, so the inbound's own decisions always win the race,
    /// and a service that truly parked would still fail rather than hang.
    const EXCHANGE_BUDGET: Duration = Duration::from_secs(60);

    /// One whole exchange, from the client's side of a pipe.
    ///
    /// `handle` takes the peer, so its return is also the close the client reads: the
    /// answer is buffered in the pipe by then, and drains without a second task.
    async fn exchange<S: Establish>(proxy: &Proxy<S>, sent: &[u8]) -> (Vec<u8>, Outcome) {
        let (mut client, peer) = tokio::io::duplex(CLIENT_ROOM);
        client
            .write_all(sent)
            .await
            .expect("a whole exchange always fits the pipe");
        let outcome = time::timeout(EXCHANGE_BUDGET, proxy.handle(peer))
            .await
            .expect("the exchange is decided, not parked");
        (drain(&mut client).await, outcome)
    }

    /// The status in an answer's first line, the way a client reads it.
    fn status_of(answered: &[u8]) -> Option<u16> {
        let text = str::from_utf8(answered).ok()?;
        // `HTTP/1.1 ` is nine bytes, and the three after it are the status.
        text.get(9..12)?.parse::<u16>().ok()
    }

    #[test]
    fn a_connect_is_read_as_the_destination_it_names() {
        let request = parse(&head_of("CONNECT example.com:443 HTTP/1.1"))
            .expect("a well-formed CONNECT is a request");
        assert_eq!(
            request.destination,
            Destination::Domain("example.com".to_owned())
        );
        assert_eq!(request.port, 443);
        assert_eq!(request.version, Version::One1);
    }

    #[test]
    fn an_ipv4_authority_stays_a_literal() {
        // A literal is not a name: the node must not be asked to resolve what the
        // application already spelled out.
        let request = parse(&head_of("CONNECT 203.0.113.1:8080 HTTP/1.0"))
            .expect("an IPv4 literal is a destination");
        assert_eq!(request.destination, Destination::IPv4([203, 0, 113, 1]));
        assert_eq!(request.port, 8080);
        assert_eq!(request.version, Version::One0);
    }

    #[test]
    fn a_bracketed_ipv6_authority_loses_its_brackets_and_keeps_its_port() {
        let request = parse(&head_of("CONNECT [::1]:443 HTTP/1.1"))
            .expect("an IPv6 literal is a destination");
        assert_eq!(
            request.destination,
            Destination::IPv6(std::net::Ipv6Addr::LOCALHOST.octets())
        );
        assert_eq!(request.port, 443);
    }

    #[test]
    fn headers_are_read_through_and_not_interpreted() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Connection: keep-alive\r\n\
                     User-Agent: something\r\nHost: elsewhere.invalid:8443\r\n\r\n";
        let request = parse(head).expect("fields do not have to mean anything");
        assert_eq!(
            request.destination,
            Destination::Domain("example.com".to_owned()),
            "a `Host:` field is not the tunnel's target"
        );
        assert_eq!(request.port, 443);
    }

    #[test]
    fn a_target_is_an_authority_and_not_a_url() {
        // An origin form is what a forward proxy is asked for, and this is a tunnel:
        // there is no path here to serve.
        for line in [
            "CONNECT http://example.com:80/ HTTP/1.1",
            "CONNECT //example.com:443 HTTP/1.1",
            "CONNECT example.com:443/ HTTP/1.1",
        ] {
            let answer =
                Answer::from(parse(&head_of(line)).expect_err("that target names no tunnel"));
            assert_eq!(answer.status, Some(BAD_REQUEST), "{line}");
        }
    }

    #[test]
    fn any_other_method_is_answered_with_the_one_there_is() {
        for line in [
            "GET http://example.com/ HTTP/1.1",
            "POST example.com:443 HTTP/1.1",
            "connect example.com:443 HTTP/1.1",
            "OPTIONS * HTTP/1.1",
        ] {
            let answer = Answer::from(parse(&head_of(line)).expect_err("only CONNECT is served"));
            assert_eq!(
                answer,
                Answer {
                    status: Some(METHOD_NOT_ALLOWED),
                    reason: "only CONNECT is supported",
                },
                "{line} is not CONNECT, and methods are case-sensitive"
            );
        }
        let answered = String::from_utf8(encode(Version::One1, METHOD_NOT_ALLOWED))
            .expect("an answer is ASCII");
        assert!(
            answered.contains("Allow: CONNECT\r\n"),
            "a 405 has to name the method that would have worked"
        );
    }

    #[test]
    fn a_target_without_a_port_is_not_a_destination() {
        let answer = Answer::from(
            parse(&head_of("CONNECT example.com HTTP/1.1"))
                .expect_err("a CONNECT target has to name a port"),
        );
        assert_eq!(
            answer,
            Answer {
                status: Some(BAD_REQUEST),
                reason: "a CONNECT target must name a port",
            }
        );
    }

    #[test]
    fn a_port_that_is_not_a_number_or_is_none_is_not_a_destination() {
        for line in [
            "CONNECT example.com:https HTTP/1.1",
            "CONNECT example.com: HTTP/1.1",
            "CONNECT example.com:0 HTTP/1.1",
            "CONNECT example.com:65536 HTTP/1.1",
            "CONNECT :443 HTTP/1.1",
        ] {
            let answer =
                Answer::from(parse(&head_of(line)).expect_err("that is not a destination"));
            assert_eq!(answer.status, Some(BAD_REQUEST), "{line}");
        }
    }

    #[test]
    fn a_request_line_that_is_not_three_fields_is_refused() {
        for line in ["CONNECT", "CONNECT example.com:443"] {
            let answer =
                Answer::from(parse(&head_of(line)).expect_err("that is not a request line"));
            assert_eq!(answer.status, Some(BAD_REQUEST), "{line}");
            assert_eq!(
                answer.reason, "the request line is not method, target and version",
                "{line}"
            );
        }
    }

    #[test]
    fn a_version_this_proxy_does_not_speak_is_said_so() {
        for line in [
            "CONNECT example.com:443 HTTP/2",
            "CONNECT example.com:443 HTTP/1.2",
            "CONNECT example.com:443 1.1",
        ] {
            let answer = Answer::from(parse(&head_of(line)).expect_err("this edge is HTTP/1"));
            assert_eq!(
                answer,
                Answer {
                    status: Some(HTTP_VERSION_NOT_SUPPORTED),
                    reason: "that HTTP version is not supported",
                },
                "{line}"
            );
        }
    }

    #[test]
    fn a_head_with_no_blank_line_is_not_a_head() {
        let answer = Answer::from(
            parse(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n")
                .expect_err("the header block never ended"),
        );
        assert_eq!(
            answer,
            Answer {
                status: Some(BAD_REQUEST),
                reason: "the header block is not terminated",
            }
        );
    }

    #[test]
    fn a_target_that_is_not_utf8_is_not_a_destination() {
        let mut head = b"CONNECT example.\xf4\x28\x80.com:443 HTTP/1.1".to_vec();
        head.extend_from_slice(b"\r\n\r\n");
        let answer = Answer::from(parse(&head).expect_err("a target has to be text"));
        assert_eq!(
            answer,
            Answer {
                status: Some(BAD_REQUEST),
                reason: "the target is not text",
            }
        );
    }

    #[test]
    fn bare_line_endings_are_read_like_their_crlf_forms() {
        let request = parse(b"CONNECT example.com:443 HTTP/1.1\n\n")
            .expect("a client that writes LF only is still asking for a tunnel");
        assert_eq!(request.port, 443);
    }

    #[test]
    fn the_success_answer_says_nothing_except_that_the_tunnel_is_open() {
        assert_eq!(
            encode(Version::One1, OK),
            b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec(),
            "no `Proxy-Agent`, no `Connection: close`, and no body to misread"
        );
        assert_eq!(
            encode(Version::One0, OK),
            b"HTTP/1.0 200 Connection Established\r\n\r\n".to_vec(),
            "a client that announced 1.0 is not handed a 1.1 answer"
        );
    }

    #[test]
    fn every_refusal_ends_the_connection_it_was_written_on() {
        for status in [
            BAD_REQUEST,
            FORBIDDEN,
            METHOD_NOT_ALLOWED,
            REQUEST_HEADER_FIELDS_TOO_LARGE,
            INTERNAL_SERVER_ERROR,
            BAD_GATEWAY,
            SERVICE_UNAVAILABLE,
            GATEWAY_TIMEOUT,
            HTTP_VERSION_NOT_SUPPORTED,
        ] {
            let answered =
                String::from_utf8(encode(Version::One1, status)).expect("an answer is ASCII");
            assert!(
                answered.contains("Connection: close\r\n"),
                "{status} is the last thing on this socket"
            );
            assert!(
                answered.ends_with("\r\n\r\n"),
                "{status} has no body, and says so by closing"
            );
            assert_eq!(status_of(answered.as_bytes()), Some(status));
        }
    }

    #[test]
    fn a_503_says_when_to_ask_again() {
        let answered = String::from_utf8(encode(Version::One1, SERVICE_UNAVAILABLE))
            .expect("an answer is ASCII");
        assert!(answered.contains("Retry-After: 1\r\n"));
    }

    #[test]
    fn an_answer_starts_with_the_status_a_client_reads_first() {
        assert_eq!(
            status_of(&encode(Version::One1, BAD_GATEWAY)),
            Some(BAD_GATEWAY)
        );
        assert_eq!(
            status_of(b"HTTP/1.1 50"),
            None,
            "a truncated answer names nothing"
        );
        assert_eq!(status_of(b""), None);
        assert_eq!(status_of(b"not http at all\r\n\r\n"), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_is_read_up_to_its_blank_line() {
        let sent = head_of("CONNECT example.com:443 HTTP/1.1");
        let (seen, outcome) = read(&sent).await;
        assert!(seen.is_empty(), "a reader writes nothing back: {seen:?}");
        assert_eq!(
            outcome.expect("one request line and a blank line is a head"),
            sent
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_blank_line_ahead_of_the_request_line_is_skipped() {
        let mut sent = b"\r\n\r\n".to_vec();
        sent.extend(head_of("CONNECT example.com:443 HTTP/1.1"));
        let (_, outcome) = read(&sent).await;
        let head = outcome.expect("an empty line before the request is not the request");
        assert_eq!(
            parse(&head)
                .expect("and the request line is still the first thing in the head")
                .port,
            443
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_bigger_than_the_bound_is_refused_rather_than_held() {
        // One line, no terminator, and more bytes than this proxy reads. The refusal
        // has to come from the reader's own bound rather than from the pipe running
        // dry, so every byte is written before the read starts.
        let mut sent = b"CONNECT example.com:443 HTTP/1.1\r\nX-Pad: ".to_vec();
        sent.extend(std::iter::repeat_n(b'x', 20 * 1024));
        let (seen, outcome) = read(&sent).await;
        assert!(
            seen.is_empty(),
            "a refusal is written by the caller: {seen:?}"
        );
        assert_eq!(
            Answer::from(outcome.expect_err("a 20 KiB field is not a head this proxy reads")),
            Answer {
                status: Some(REQUEST_HEADER_FIELDS_TOO_LARGE),
                reason: "the head is larger than this proxy accepts",
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_that_never_ends_is_refused_once_the_client_is_gone() {
        let (mut client, peer) = tokio::io::duplex(CLIENT_ROOM);
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n")
            .await
            .expect("a partial head fits the pipe");
        client.flush().await.expect("flush");
        drop(client);
        let mut reader = BufReader::with_capacity(MAX_HEAD_LEN, peer);
        assert_eq!(
            Answer::from(
                time::timeout(STAGE_BUDGET, read_head(&mut reader))
                    .await
                    .expect("the reader is decided, not parked")
                    .expect_err("an unterminated head is not a head")
            ),
            Answer {
                status: None,
                reason: "the head did not finish before the client hung up",
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_edge_answers_503_without_bothering_a_node() {
        for (gate, limit) in [
            (
                Gate::new(0, MAX_CONCURRENT_HANDSHAKES),
                Limit::LocalConnections,
            ),
            (Gate::new(MAX_LOCAL_CONNECTIONS, 0), Limit::Handshakes),
        ] {
            let seen = Tally::default();
            let proxy = Proxy::new(Fake::refusing(seen.clone(), Error::Limit(limit)), gate);
            let (answered, outcome) =
                exchange(&proxy, &head_of("CONNECT example.com:443 HTTP/1.1")).await;
            assert_eq!(status_of(&answered), Some(SERVICE_UNAVAILABLE), "{limit}");
            assert!(
                matches!(outcome, Outcome::Failed(Error::Limit(refused)) if refused == limit),
                "the failure the client was told about is the one logged: {outcome:?}"
            );
            assert_eq!(seen.seen(), 0, "{limit} asks no node for anything");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_malformed_head_is_answered_without_reaching_a_node() {
        let seen = Tally::default();
        let proxy = Proxy::new(
            Fake::refusing(seen.clone(), Error::Cancelled),
            Gate::default(),
        );
        let (answered, outcome) = exchange(&proxy, &head_of("GET example.com:443 HTTP/1.1")).await;
        assert_eq!(status_of(&answered), Some(METHOD_NOT_ALLOWED));
        assert_eq!(
            outcome,
            Outcome::Refused {
                status: Some(METHOD_NOT_ALLOWED),
                reason: "only CONNECT is supported",
            }
        );
        assert_eq!(
            seen.seen(),
            0,
            "no node was asked about a method it cannot serve"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_says_nothing_is_closed_after_its_budget() {
        let gate = Gate::default();
        let seen = Tally::default();
        let proxy = Proxy::new(Fake::refusing(seen.clone(), Error::Cancelled), gate.clone());
        let (client, peer) = tokio::io::duplex(CLIENT_ROOM);
        let outcome = time::timeout(EXCHANGE_BUDGET, proxy.handle(peer))
            .await
            .expect("a silent client is decided, not parked");
        drop(client);
        assert_eq!(
            outcome,
            Outcome::Refused {
                status: None,
                reason: "the head did not arrive in time",
            },
            "a client that never writes is told nothing, because nothing is known to answer"
        );
        assert_eq!(seen.seen(), 0);
        assert_eq!(
            gate.connections_available(),
            MAX_LOCAL_CONNECTIONS,
            "the budget released the connection slot"
        );
        assert_eq!(
            gate.handshakes_available(),
            MAX_CONCURRENT_HANDSHAKES,
            "and never took an authentication slot"
        );
    }

    #[test]
    fn the_status_a_client_reads_follows_who_was_at_fault() {
        // The families a client can act on: nobody was asked, the next hop was slow,
        // the next hop failed, and this proxy failed.
        assert_eq!(
            status_for(&Error::Limit(Limit::Probes)),
            SERVICE_UNAVAILABLE
        );
        assert_eq!(status_for(&Error::Cancelled), SERVICE_UNAVAILABLE);
        assert_eq!(
            status_for(&Error::Dns(DnsError::Timeout)),
            GATEWAY_TIMEOUT,
            "a name that did not resolve in time may resolve on a retry"
        );
        assert_eq!(
            status_for(&Error::Transport(TransportError::Timeout)),
            GATEWAY_TIMEOUT
        );
        assert_eq!(
            status_for(&Error::Handshake(HandshakeError::Timeout)),
            GATEWAY_TIMEOUT
        );
        assert_eq!(
            status_for(&Error::Rejected(RejectReason::Unauthorized)),
            FORBIDDEN,
            "a refusal is a refusal even when the reason is credentials"
        );
        assert_eq!(
            status_for(&Error::Rejected(RejectReason::DestinationUnreachable)),
            BAD_GATEWAY
        );
        assert_eq!(
            status_for(&Error::Transport(TransportError::Connect(
                "refused".to_owned()
            ))),
            BAD_GATEWAY
        );
        assert_eq!(
            status_for(&Error::Session(SessionError::RecordCorrupted)),
            BAD_GATEWAY
        );
        // And the failures that are this process's own, which must not be dressed up
        // as a destination problem.
        assert_eq!(
            status_for(&Error::Config("no nodes".to_owned())),
            INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            status_for(&Error::Io("out of memory".to_owned())),
            INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            status_for(&Error::Session(SessionError::Entropy)),
            INTERNAL_SERVER_ERROR,
            "no entropy is this proxy's failure, not the peer's"
        );
        assert_eq!(
            status_for(&Error::Transport(TransportError::Local(
                "the application's socket broke".to_owned()
            ))),
            INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn every_failure_the_taxonomy_has_a_word_for_gets_a_status() {
        let failures = [
            Error::Config(String::new()),
            Error::Dns(DnsError::Lookup(String::new())),
            Error::Dns(DnsError::NoAddress),
            Error::Dns(DnsError::Timeout),
            Error::Transport(TransportError::Connect(String::new())),
            Error::Transport(TransportError::Timeout),
            Error::Transport(TransportError::BrokenPipe),
            Error::Transport(TransportError::Socket(String::new())),
            Error::Transport(TransportError::Local(String::new())),
            Error::Handshake(HandshakeError::Timeout),
            Error::Handshake(HandshakeError::IdentityMismatch),
            Error::Handshake(HandshakeError::Verification),
            Error::Handshake(HandshakeError::Protocol("x")),
            Error::Handshake(HandshakeError::UnexpectedEof),
            Error::Rejected(RejectReason::Unauthorized),
            Error::Rejected(RejectReason::Forbidden),
            Error::Rejected(RejectReason::DestinationUnreachable),
            Error::Rejected(RejectReason::Other(418)),
            Error::Session(SessionError::ClosedBeforeResponse),
            Error::Session(SessionError::RequestTooLong),
            Error::Session(SessionError::RecordCorrupted),
            Error::Session(SessionError::KeyExhausted),
            Error::Session(SessionError::Framing("x")),
            Error::Session(SessionError::Entropy),
            Error::Session(SessionError::UnexpectedContentType(7)),
            Error::Session(SessionError::PeerAlert {
                level: 2,
                description: 1,
            }),
            Error::Limit(Limit::LocalConnections),
            Error::Limit(Limit::Handshakes),
            Error::Limit(Limit::Probes),
            Error::Limit(Limit::Candidates),
            Error::Cancelled,
            Error::Io(String::new()),
        ];
        let known = [
            BAD_REQUEST,
            FORBIDDEN,
            METHOD_NOT_ALLOWED,
            REQUEST_HEADER_FIELDS_TOO_LARGE,
            INTERNAL_SERVER_ERROR,
            BAD_GATEWAY,
            SERVICE_UNAVAILABLE,
            GATEWAY_TIMEOUT,
            HTTP_VERSION_NOT_SUPPORTED,
        ];
        for failure in &failures {
            let status = status_for(failure);
            assert!(
                known.contains(&status),
                "{failure} has to be reported in a status this module names: got {status}"
            );
            assert!(
                str::from_utf8(&encode(UNANNOUNCED, status))
                    .expect("an answer is ASCII")
                    .contains(&status.to_string()),
                "{status} has to be readable in the answer"
            );
        }
    }
}
