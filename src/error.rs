//! Crate-wide error taxonomy.
//!
//! Failure categories are deliberately asymmetric: the scheduler scores them
//! differently, because a cancelled hedge attempt or a local policy rejection
//! says nothing about a node's health.

use std::fmt;

/// Anything the client could not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Configuration was rejected before the runtime started.
    Config(String),
    /// DNS resolution failed or produced no usable address.
    Dns(DnsError),
    /// A TCP connection could not be established or was broken.
    Transport(TransportError),
    /// TLS/REALITY handshake did not complete against the expected server.
    Handshake(HandshakeError),
    /// The server accepted the TLS layer but rejected the VLESS request.
    Rejected(RejectReason),
    /// An established session stopped carrying data in a way the taxonomy
    /// recognises: see [`SessionError`].
    Session(SessionError),
    /// A local limit (connections, handshakes, probes, buffer) was reached.
    Limit(Limit),
    /// The attempt was cancelled by the caller, not by the network.
    Cancelled,
    /// An operating-system call failed with its own message.
    Io(String),
}

impl Error {
    /// Classifies the failure for the scheduler.
    ///
    /// Arms are grouped by what the node proved, not by which module reported
    /// the error: a name with no address and a local limit say nothing about
    /// the remote, while a socket that stops working does.
    #[must_use]
    pub fn classify(&self) -> Failure {
        match self {
            // Nothing was learned about the node: configuration and limits are
            // local policy, a name with no address never reached one, a
            // cancelled attempt was stopped by us rather than by a peer, a
            // request that could not be encoded or padded sent no byte at all,
            // and the socket that broke was the application's own.
            Self::Config(_)
            | Self::Limit(_)
            | Self::Cancelled
            | Self::Dns(DnsError::NoAddress)
            | Self::Transport(TransportError::Local(_))
            | Self::Session(SessionError::RequestTooLong | SessionError::Entropy) => Failure::Local,
            Self::Dns(_) => Failure::Dns,
            Self::Transport(TransportError::BrokenPipe | TransportError::Socket(_))
            | Self::Session(
                SessionError::RecordCorrupted
                | SessionError::KeyExhausted
                | SessionError::Framing(_)
                | SessionError::UnexpectedContentType(_)
                | SessionError::PeerAlert { .. },
            ) => Failure::Idle,
            Self::Transport(_) | Self::Io(_) => Failure::Connect,
            Self::Handshake(HandshakeError::Timeout) => Failure::Timeout,
            Self::Handshake(_) => Failure::Handshake,
            // A refusal is the node's answer; a node that completes TLS and then
            // drops the session without answering proved it is not serving
            // *this* request. Both are what the Rejected family scores.
            Self::Rejected(_) | Self::Session(SessionError::ClosedBeforeResponse) => {
                Failure::Rejected
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(formatter, "configuration error: {message}"),
            Self::Dns(error) => write!(formatter, "dns error: {error}"),
            Self::Transport(error) => write!(formatter, "transport error: {error}"),
            Self::Handshake(error) => write!(formatter, "handshake error: {error}"),
            Self::Rejected(reason) => write!(formatter, "request rejected: {reason}"),
            Self::Session(error) => write!(formatter, "session error: {error}"),
            Self::Limit(limit) => write!(formatter, "local limit reached: {limit}"),
            Self::Cancelled => formatter.write_str("operation cancelled"),
            Self::Io(message) => write!(formatter, "i/o error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// Scheduler-facing failure family. Members of one family are scored alike;
/// families are not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// Nothing was learned about the node.
    Local,
    /// Address resolution failed before any node was contacted.
    Dns,
    /// TCP did not connect in time.
    Connect,
    /// TCP connected but the attempt exceeded its budget.
    Timeout,
    /// The encrypted handshake did not complete cleanly.
    Handshake,
    /// The node answered but refused to serve this request.
    Rejected,
    /// An established session stopped carrying data.
    Idle,
}

impl Failure {
    /// Returns whether the family is evidence about the node itself.
    ///
    /// Cancelled hedge losers, local limits and configuration rejections are
    /// not node failures and must not lower a node's score.
    #[must_use]
    pub const fn counts_against_node(self) -> bool {
        !matches!(self, Self::Local)
    }
}

/// The family's own word, for a log field and for `explain`.
///
/// A failure is scored by family rather than by message, so the family is the part
/// an operator has to be able to grep: `family:"local"` says the node did nothing
/// wrong, which is the single most useful thing a line about a failed connection
/// can say.
impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local",
            Self::Dns => "dns",
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Handshake => "handshake",
            Self::Rejected => "rejected",
            Self::Idle => "idle",
        })
    }
}

/// DNS outcome categories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsError {
    /// The lookup itself failed.
    Lookup(String),
    /// The name resolved to no address at all.
    NoAddress,
    /// Resolution exceeded its budget.
    Timeout,
}

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(message) => write!(formatter, "lookup failed: {message}"),
            Self::NoAddress => formatter.write_str("name resolved to no address"),
            Self::Timeout => formatter.write_str("lookup timed out"),
        }
    }
}

/// TCP outcome categories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// Connect was refused or failed.
    Connect(String),
    /// Connect exceeded its budget.
    Timeout,
    /// An established socket broke while carrying a session.
    BrokenPipe,
    /// An established socket failed a system call, with the operating system's
    /// own message. Only a live tunnel reports this: reaching a node at all is
    /// [`Self::Connect`].
    Socket(String),
    /// The socket on the application's side of the relay broke, with the
    /// operating system's own message.
    ///
    /// The relay cannot say why: a browser killed mid-download, a local policy
    /// reset and a client that simply gave up all look the same from the near
    /// end. What none of them mean is that the node did anything, which is why
    /// this is [`Failure::Local`] and the [`Self::Socket`] an idle tunnel
    /// reports is not.
    Local(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(message) => write!(formatter, "connect failed: {message}"),
            Self::Timeout => formatter.write_str("connect timed out"),
            Self::BrokenPipe => formatter.write_str("connection broken"),
            Self::Socket(message) => write!(formatter, "socket error: {message}"),
            Self::Local(message) => write!(formatter, "local connection error: {message}"),
        }
    }
}

/// TLS/REALITY handshake outcome categories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeError {
    /// The handshake exceeded its budget.
    Timeout,
    /// The peer did not present the REALITY identity we are configured for.
    ///
    /// This is the signature of a wrong public key, a wrong short ID, a stale
    /// server name, or a server that fell back to its cover target.
    IdentityMismatch,
    /// REALITY authentication succeeded but the transcript did not verify.
    Verification,
    /// A handshake message was structurally invalid.
    Protocol(&'static str),
    /// The peer closed the connection mid-handshake.
    UnexpectedEof,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("handshake timed out"),
            Self::IdentityMismatch => {
                formatter.write_str("peer is not the configured REALITY server")
            }
            Self::Verification => formatter.write_str("handshake verification failed"),
            Self::Protocol(field) => write!(formatter, "malformed handshake: {field}"),
            Self::UnexpectedEof => formatter.write_str("peer closed during handshake"),
        }
    }
}

/// Server-side VLESS rejection reasons, decoded from the response status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    /// User not found, or its flow/short ID is not accepted.
    Unauthorized,
    /// The server refused this destination.
    Forbidden,
    /// The destination could not be reached from the server.
    DestinationUnreachable,
    /// The server gave a status we do not have a specific meaning for.
    Other(u16),
}

impl fmt::Display for RejectReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => formatter.write_str("credentials not accepted"),
            Self::Forbidden => formatter.write_str("destination forbidden"),
            Self::DestinationUnreachable => formatter.write_str("destination unreachable"),
            Self::Other(status) => write!(formatter, "server status {status}"),
        }
    }
}

/// What ended or corrupted a session that had already completed its handshake.
///
/// These are reported apart from [`HandshakeError`] because the node is already
/// authenticated by then: the question is no longer "is this our server" but
/// "did this tunnel stay up", which the scheduler scores differently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// The peer closed the connection before answering the VLESS request.
    ///
    /// A node that completes TLS and then drops the session without replying is
    /// either refusing these credentials or broken; both are reported apart from
    /// a handshake failure, and neither is claimed to be the other.
    ClosedBeforeResponse,
    /// The VLESS request could not be encoded, because a destination field was
    /// longer than its one-byte wire length.
    ///
    /// This is a property of the target, not of the node: no byte was sent.
    RequestTooLong,
    /// An encrypted record arrived that would not open under the session keys.
    ///
    /// On a live tunnel this means the stream was corrupted or desynchronised.
    RecordCorrupted,
    /// The traffic key reached its per-record ceiling.
    ///
    /// AES-GCM allows `2^24` records under one key, which a long bulk transfer
    /// can reach. Sealing further records would repeat a nonce, so the tunnel is
    /// ended instead.
    KeyExhausted,
    /// Vision framing could not be decoded.
    Framing(&'static str),
    /// Operating-system entropy was unavailable, so a frame could not be padded or
    /// an ephemeral key could not be generated.
    ///
    /// Padding lengths are drawn per frame, so this can surface long after a
    /// session started. It is reported apart from a framing error because the
    /// peer did nothing wrong.
    Entropy,
    /// A TLS record type that cannot appear in a completed session arrived.
    UnexpectedContentType(u8),
    /// The peer sent an alert that is not an orderly `close_notify`.
    PeerAlert {
        /// Alert level, 1 warning or 2 fatal.
        level: u8,
        /// Alert description.
        description: u8,
    },
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClosedBeforeResponse => {
                formatter.write_str("peer closed before answering the request")
            }
            Self::RequestTooLong => formatter.write_str("destination does not fit the wire format"),
            Self::RecordCorrupted => formatter.write_str("session record did not open"),
            Self::KeyExhausted => formatter.write_str("session traffic key exhausted"),
            Self::Framing(reason) => write!(formatter, "vision framing error: {reason}"),
            Self::Entropy => formatter.write_str("operating-system entropy unavailable"),
            Self::UnexpectedContentType(value) => {
                write!(formatter, "record type {value} cannot carry session data")
            }
            Self::PeerAlert { level, description } => write!(
                formatter,
                "peer alert level {level} description {description}"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

/// Local resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Limit {
    /// Too many concurrent local client connections.
    LocalConnections,
    /// Too many concurrent handshakes.
    Handshakes,
    /// Too many concurrent active probes.
    Probes,
    /// Nothing may be attempted for this connection right now: every configured
    /// node is inside its breaker window, and the one recovery attempt a cooling
    /// node is allowed is already in flight.
    Candidates,
}

impl fmt::Display for Limit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalConnections => formatter.write_str("local connection limit"),
            Self::Handshakes => formatter.write_str("handshake concurrency limit"),
            Self::Probes => formatter.write_str("probe concurrency limit"),
            Self::Candidates => formatter.write_str("no candidate may be tried right now"),
        }
    }
}

/// Convenience result alias for the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
