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
            Self::Config(_) | Self::Limit(_) | Self::Cancelled | Self::Dns(DnsError::NoAddress) => {
                Failure::Local
            }
            Self::Dns(_) => Failure::Dns,
            Self::Transport(TransportError::BrokenPipe) => Failure::Idle,
            Self::Transport(_) | Self::Io(_) => Failure::Connect,
            Self::Handshake(HandshakeError::Timeout) => Failure::Timeout,
            Self::Handshake(_) => Failure::Handshake,
            Self::Rejected(_) => Failure::Rejected,
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
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(message) => write!(formatter, "connect failed: {message}"),
            Self::Timeout => formatter.write_str("connect timed out"),
            Self::BrokenPipe => formatter.write_str("connection broken"),
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

/// Local resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Limit {
    /// Too many concurrent local client connections.
    LocalConnections,
    /// Too many concurrent handshakes.
    Handshakes,
    /// Too many concurrent active probes.
    Probes,
    /// Too many concurrent remote candidates for one logical connection.
    Candidates,
}

impl fmt::Display for Limit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalConnections => formatter.write_str("local connection limit"),
            Self::Handshakes => formatter.write_str("handshake concurrency limit"),
            Self::Probes => formatter.write_str("probe concurrency limit"),
            Self::Candidates => formatter.write_str("candidate concurrency limit"),
        }
    }
}

/// Convenience result alias for the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
