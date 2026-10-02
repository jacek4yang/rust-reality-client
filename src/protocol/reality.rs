//! REALITY authentication and the TLS 1.3 continuation, client side.
//!
//! Everything in this module is derived from the v2.0.1 server's own parsing
//! and verification code, cited in `docs/PROTOCOL.md`. The client never
//! invents a byte: the authenticator layout, the offsets the server reads back,
//! and the certificate binding are all mirror images of server checks.

mod auth;
mod certificate;
mod handshake;
mod hello;
mod server_hello;

pub use auth::{AuthError, AuthKey, AuthPlaintext, CLIENT_VERSION};
pub use certificate::{CertificateError, parse_encrypted_extensions, verify_server_certificate};
pub use handshake::{Handshake, Negotiated, complete};
pub use hello::{ClientKeyAgreement, HelloError, HelloRecord, SharedSecret, build_client_hello};
pub use server_hello::{ServerHello, ServerHelloError};

/// Session ID length that carries a REALITY authenticator.
///
/// The server refuses to authenticate any other length.
pub const SESSION_ID_LEN: usize = 32;
/// Offset of the session ID inside a `ClientHello` carrying a 32-byte one.
pub const SESSION_ID_OFFSET: usize = 39;
/// TLS `NamedGroup` identifier for X25519.
pub const X25519_GROUP: u16 = 0x001d;
/// TLS `NamedGroup` identifier for the X25519MLKEM768 hybrid group.
pub const X25519_MLKEM768_GROUP: u16 = 0x11ec;
/// Complete hybrid client share length: encapsulation key then X25519 public key.
pub const X25519_MLKEM768_SHARE_LEN: usize =
    crate::crypto::MLKEM768_ENCAP_KEY_LEN + crate::crypto::X25519_PUBLIC_LEN;
/// The server's hard bound on one `ClientHello` handshake message.
pub const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;

/// A bounded cursor over one wire message.
///
/// Both hello parsers need exactly this, and every read is range-checked: no
/// offset taken from the network may address outside the message it came from.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Bytes left in this window.
    pub(crate) const fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Narrows to the next `len` bytes as an independent window.
    pub(crate) fn subreader(&mut self, len: usize) -> Option<Reader<'a>> {
        self.read(len).map(Reader::new)
    }

    /// Borrows the next `len` bytes, refusing to overrun the window.
    pub(crate) fn read(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(len)?;
        let bytes = self.data.get(self.position..end)?;
        self.position = end;
        Some(bytes)
    }

    pub(crate) fn skip(&mut self, len: usize) -> Option<()> {
        self.read(len).map(|_| ())
    }

    pub(crate) fn skip_remaining(&mut self) {
        self.position = self.data.len();
    }

    pub(crate) fn read_u8(&mut self) -> Option<u8> {
        Some(*self.read(1)?.first()?)
    }

    pub(crate) fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// A 24-bit length, which always fits `usize` on every supported target.
    pub(crate) fn read_u24(&mut self) -> Option<usize> {
        let bytes = self.read(3)?;
        Some(usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]))
    }
}
