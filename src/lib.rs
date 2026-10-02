//! # rust-reality-client
//!
//! A native Rust **VLESS + REALITY + `xtls-rprx-vision`** client that is
//! wire-compatible with the unmodified `rust-reality` v2.0.1 server.
//!
//! The crate is organised as a stack, and every layer below the relay is
//! protocol-exact rather than "close enough":
//!
//! | Layer | Module | Responsibility |
//! |---|---|---|
//! | Wire | `protocol::vless`, `protocol::vision`, `protocol::reality` | framing, padding, authentication |
//! | Route | `scheduler` | node selection, hedged dial, circuit breaking |
//! | Handoff | `handoff` | one node, one authenticated tunnel |
//! | Connect | `transport` | TCP, keepalive, half-close, relay |
//! | Edge | `inbound` | SOCKS5 and HTTP CONNECT |
//! | Host | `config`, `logging`, `error` | validation, redaction, failure taxonomy |
//!
//! See [`error`] for the failure taxonomy that keeps these layers honest about
//! what actually went wrong.
//!
//! ## The one hard rule
//!
//! v2.0.1 defines **no cross-node session-resume protocol**. An established
//! application connection cannot be moved from server A to server B. Node
//! choice, racing and retry are therefore legal **only while a connection is
//! being established** — before the local client is told the tunnel exists, and
//! before any application byte is committed to a winner. After a SOCKS5
//! success reply or an HTTP `200`, the remote session is immutable: this
//! client never silently replays, retries elsewhere, or duplicates bytes. When
//! the remote end fails, the local connection is closed honestly and the
//! application sees the failure.
//!
//! ## Secret handling
//!
//! UUIDs, keys, authenticators and short IDs never reach logs, `Debug` output,
//! or error strings. Traffic material is zeroized on drop, and every
//! attacker-controlled buffer has a fixed ceiling.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod config;
pub mod crypto;
pub mod entropy;
pub mod error;
pub mod handoff;
pub mod inbound;
pub mod protocol;
pub mod transport;
