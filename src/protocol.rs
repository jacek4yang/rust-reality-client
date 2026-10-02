//! Wire-format protocols, kept free of I/O so they can be tested byte-exactly.
//!
//! Every constant, offset and length here is copied from the v2.0.1 server that
//! this client must interoperate with, or from the RFC that defines it; the
//! citations live in `docs/PROTOCOL.md`.

pub mod reality;
pub mod tls13;
pub mod vision;
pub mod vless;
