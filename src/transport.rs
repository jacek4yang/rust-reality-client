//! Sockets: how a remote address is reached, tuned, and turned into a tunnel.
//!
//! [`session`] carries one proxied TCP session over an authenticated REALITY
//! handshake. [`socket`] applies the two options every one of those sockets
//! gets, on either side.

pub mod session;
pub mod socket;

pub use session::VisionSession;
pub use socket::{KEEPALIVE_COUNT, KEEPALIVE_IDLE, KEEPALIVE_INTERVAL, configure};
