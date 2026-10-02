//! Sockets: how a remote address is reached, tuned, and turned into a tunnel.
//!
//! [`session`] carries one proxied TCP session over an authenticated REALITY
//! handshake. The remaining concerns of this layer — address selection, TCP
//! keepalive, and connect budgets — live beside it.

pub mod session;

pub use session::VisionSession;
