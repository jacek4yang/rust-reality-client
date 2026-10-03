//! Sockets: how a remote address is reached, tuned, and turned into a tunnel.
//!
//! [`session`] carries one proxied TCP session over an authenticated REALITY
//! handshake. [`socket`] applies the two options every one of those sockets
//! gets, on either side. [`family`] decides which address to try first and how
//! long to keep believing that. [`dial`] is where those beliefs are spent: it
//! resolves, races, and hands back one connected socket. [`relay`] moves the
//! application's bytes across that socket until both directions are done.

pub mod dial;
pub mod family;
pub mod relay;
pub mod session;
pub mod socket;

pub use dial::{CONNECT_BUDGET, DNS_BUDGET, Dial, DialError, Dialed, MAX_CANDIDATES};
pub use family::{AddressFamily, DialPolicy, Environment, FailureEvidence, Tuning};
pub use relay::{RELAY_BUFFER, Transferred, carry, verdict};
pub use session::{Downlink, VisionSession};
pub use socket::{KEEPALIVE_COUNT, KEEPALIVE_IDLE, KEEPALIVE_INTERVAL, configure};
