// Wire-format protocols, kept free of I/O so they can be tested byte-exactly.

//! The module boundaries are the ones the v2.0.1 server uses, so a byte that
//! differs is attributable to one layer rather than to the whole handshake.

pub mod tls13;
