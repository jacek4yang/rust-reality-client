//! The edge: what a local application speaks to this client.
//!
//! Applications do not speak VLESS, so this layer exists to translate. A browser
//! or a CLI tool offers SOCKS5 ([`socks5`]), and a `HTTPS_PROXY`-style
//! environment variable points at HTTP `CONNECT`. Both are parsed by hand rather
//! than pulled from a crate, because every byte at this edge is
//! attacker-controlled and the only bound that holds for sure is the one written
//! next to the read.
//!
//! No inbound chooses a node. By the time one of them answers, the selection is
//! already over: a `0x00` reply or an HTTP `200` is the moment the remote session
//! becomes immutable, and what follows is
//! [`carry`](crate::transport::carry) and nothing else.

pub mod socks5;
