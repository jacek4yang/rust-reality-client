//! The client's view of a TLS 1.3 `ServerHello`.
//!
//! Every check here mirrors a check the v2.0.1 server performs on *its* side of
//! the same message (`tls13/server_hello.rs:88-171`), because that code builds
//! the hello by patching a cover target's bytes: what the server will accept
//! from a cover is what a client must expect to receive. In particular the
//! echoed session ID must be byte-identical to the client's, which is the only
//! reason the authenticator survives the round trip.

use std::fmt;

use crate::crypto::MLKEM768_CIPHERTEXT_LEN;
use crate::error::{Error, HandshakeError};
use crate::protocol::reality::hello::HelloRecord;
use crate::protocol::reality::{self, X25519_GROUP, X25519_MLKEM768_GROUP};
use crate::protocol::tls13::CipherSuite;

/// Handshake type byte for `ServerHello`.
const HANDSHAKE_SERVER_HELLO: u8 = 2;
/// Legacy version field, always TLS 1.2 on the wire.
const LEGACY_TLS12: u16 = 0x0303;
/// `supported_versions` payload meaning TLS 1.3 was negotiated.
const TLS13_VERSION: u16 = 0x0304;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXTENSION_KEY_SHARE: u16 = 0x0033;
const EXTENSION_PRE_SHARED_KEY: u16 = 0x0029;
/// The bound the server places on one `ServerHello` message.
const MAX_SERVER_HELLO_BYTES: usize = 8 * 1024;
/// The server's bound on extension count in the same message.
const MAX_EXTENSIONS: usize = 64;
/// Standalone X25519 server share length.
const X25519_SHARE_LEN: usize = 32;
/// Hybrid server share length: ML-KEM ciphertext then X25519 public key.
const X25519_MLKEM768_SHARE_LEN: usize = MLKEM768_CIPHERTEXT_LEN + X25519_SHARE_LEN;

/// A `ServerHello` that is not a usable TLS 1.3 continuation of our hello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerHelloError {
    /// The message is shorter than its own declared lengths.
    Truncated,
    /// The message exceeds the bound the server places on one.
    TooLarge,
    /// A fixed field, vector, or extension frame is not exact.
    Malformed(&'static str),
    /// TLS 1.3 was not negotiated.
    UnsupportedVersion,
    /// The selected cipher suite is unsupported or was never offered.
    UnsupportedCipherSuite,
    /// The selected key-share group is unsupported, unoffered, or mis-sized.
    UnsupportedKeyShare,
    /// The server selected a pre-shared key, which no REALITY path may do.
    PreSharedKeySelected,
    /// The session ID was not echoed byte for byte.
    SessionIdMismatch,
}

impl fmt::Display for ServerHelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated ServerHello"),
            Self::TooLarge => formatter.write_str("ServerHello exceeds its bound"),
            Self::Malformed(field) => write!(formatter, "malformed ServerHello field {field}"),
            Self::UnsupportedVersion => formatter.write_str("server did not negotiate TLS 1.3"),
            Self::UnsupportedCipherSuite => {
                formatter.write_str("server selected an unoffered cipher suite")
            }
            Self::UnsupportedKeyShare => {
                formatter.write_str("server selected an invalid key share")
            }
            Self::PreSharedKeySelected => formatter.write_str("server selected a pre-shared key"),
            Self::SessionIdMismatch => formatter.write_str("server did not echo the session ID"),
        }
    }
}

impl std::error::Error for ServerHelloError {}

impl From<ServerHelloError> for Error {
    fn from(error: ServerHelloError) -> Self {
        match error {
            ServerHelloError::Malformed(field) => Self::Handshake(HandshakeError::Protocol(field)),
            other => Self::Handshake(HandshakeError::Protocol(match other {
                ServerHelloError::Truncated => "server hello truncated",
                ServerHelloError::TooLarge => "server hello too large",
                ServerHelloError::UnsupportedVersion => "server hello version",
                ServerHelloError::UnsupportedCipherSuite => "server hello cipher suite",
                ServerHelloError::UnsupportedKeyShare => "server hello key share",
                ServerHelloError::PreSharedKeySelected => "server hello pre-shared key",
                ServerHelloError::SessionIdMismatch => "server hello session id",
                ServerHelloError::Malformed(_) => "server hello",
            })),
        }
    }
}

/// A validated `ServerHello`, holding the exact bytes the transcript hashes.
pub struct ServerHello {
    message: Vec<u8>,
    suite: CipherSuite,
    key_share_group: u16,
    server_share: Vec<u8>,
}

impl ServerHello {
    /// Parses a `ServerHello` against the hello it replies to.
    ///
    /// # Errors
    ///
    /// Returns a [`ServerHelloError`] variant for every rejected field.
    pub fn parse(message: &[u8], hello: &HelloRecord) -> Result<Self, ServerHelloError> {
        if message.len() > MAX_SERVER_HELLO_BYTES {
            return Err(ServerHelloError::TooLarge);
        }
        let mut reader = reality::Reader::new(message);
        if reader.read_u8().ok_or(ServerHelloError::Truncated)? != HANDSHAKE_SERVER_HELLO {
            return Err(ServerHelloError::Malformed("handshake type"));
        }
        let declared = reader.read_u24().ok_or(ServerHelloError::Truncated)?;
        if declared != reader.remaining() {
            return Err(ServerHelloError::Malformed("declared length"));
        }
        if reader.read_u16().ok_or(ServerHelloError::Truncated)? != LEGACY_TLS12 {
            return Err(ServerHelloError::Malformed("legacy version"));
        }
        reader.skip(32).ok_or(ServerHelloError::Truncated)?;
        let session_id_len = usize::from(reader.read_u8().ok_or(ServerHelloError::Truncated)?);
        if session_id_len > 32 {
            return Err(ServerHelloError::Malformed("session id length"));
        }
        if !hello.matches_session_id(
            reader
                .read(session_id_len)
                .ok_or(ServerHelloError::Truncated)?,
        ) {
            return Err(ServerHelloError::SessionIdMismatch);
        }

        let suite_wire = reader.read_u16().ok_or(ServerHelloError::Truncated)?;
        let suite = CipherSuite::from_wire(suite_wire)
            .filter(|_| hello.cipher_offered(suite_wire))
            .ok_or(ServerHelloError::UnsupportedCipherSuite)?;
        if reader.read_u8().ok_or(ServerHelloError::Truncated)? != 0 {
            return Err(ServerHelloError::Malformed("compression method"));
        }

        let extensions_len = usize::from(reader.read_u16().ok_or(ServerHelloError::Truncated)?);
        let mut extensions = reader
            .subreader(extensions_len)
            .ok_or(ServerHelloError::Truncated)?;
        if !reader.is_empty() {
            return Err(ServerHelloError::Malformed("trailing bytes"));
        }
        let mut seen: Vec<u16> = Vec::new();
        let mut negotiated_tls13 = false;
        let mut key_share: Option<(u16, &[u8])> = None;
        while !extensions.is_empty() {
            if seen.len() >= MAX_EXTENSIONS {
                return Err(ServerHelloError::Malformed("extension count"));
            }
            let extension_type = extensions.read_u16().ok_or(ServerHelloError::Truncated)?;
            if seen.contains(&extension_type) {
                return Err(ServerHelloError::Malformed("duplicate extension"));
            }
            seen.push(extension_type);
            let body_len = usize::from(extensions.read_u16().ok_or(ServerHelloError::Truncated)?);
            let mut extension = extensions
                .subreader(body_len)
                .ok_or(ServerHelloError::Truncated)?;
            match extension_type {
                EXTENSION_SUPPORTED_VERSIONS => {
                    negotiated_tls13 =
                        extension.read_u16().ok_or(ServerHelloError::Truncated)? == TLS13_VERSION;
                }
                EXTENSION_KEY_SHARE => {
                    let group = extension.read_u16().ok_or(ServerHelloError::Truncated)?;
                    let exchange_len =
                        usize::from(extension.read_u16().ok_or(ServerHelloError::Truncated)?);
                    let exchange = extension
                        .read(exchange_len)
                        .ok_or(ServerHelloError::Truncated)?;
                    validate_key_share(group, exchange.len(), hello)?;
                    key_share = Some((group, exchange));
                }
                EXTENSION_PRE_SHARED_KEY => {
                    return Err(ServerHelloError::PreSharedKeySelected);
                }
                _ => extension.skip_remaining(),
            }
            if !extension.is_empty() {
                return Err(ServerHelloError::Malformed("extension length"));
            }
        }
        if !negotiated_tls13 {
            return Err(ServerHelloError::UnsupportedVersion);
        }
        let (key_share_group, exchange) = key_share.ok_or(ServerHelloError::UnsupportedKeyShare)?;
        Ok(Self {
            message: message.to_vec(),
            suite,
            key_share_group,
            server_share: exchange.to_vec(),
        })
    }

    /// The exact message bytes, which the transcript hashes unmodified.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// The negotiated cipher suite.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// The group the server selected for the TLS 1.3 agreement.
    #[must_use]
    pub const fn key_share_group(&self) -> u16 {
        self.key_share_group
    }

    /// The server's key exchange bytes, which the TLS agreement consumes.
    #[must_use]
    pub fn server_share(&self) -> &[u8] {
        &self.server_share
    }
}

impl fmt::Debug for ServerHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerHello")
            .field("suite", &self.suite)
            .field("key_share_group", &self.key_share_group)
            .field("message_len", &self.message.len())
            .finish_non_exhaustive()
    }
}

/// Rejects a group or share size the server would never produce.
fn validate_key_share(
    group: u16,
    exchange_len: usize,
    hello: &HelloRecord,
) -> Result<(), ServerHelloError> {
    let expected_len = match group {
        X25519_GROUP => X25519_SHARE_LEN,
        X25519_MLKEM768_GROUP => X25519_MLKEM768_SHARE_LEN,
        _ => return Err(ServerHelloError::UnsupportedKeyShare),
    };
    if exchange_len != expected_len || !hello.key_share_group_offered(group) {
        return Err(ServerHelloError::UnsupportedKeyShare);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::reality::auth::{AuthPlaintext, CLIENT_VERSION};
    use crate::protocol::reality::hello::{ClientKeyAgreement, build_client_hello};

    use super::*;

    fn hello() -> HelloRecord {
        let keys = ClientKeyAgreement::generate().expect("key agreement");
        let plaintext = AuthPlaintext {
            version: CLIENT_VERSION,
            time: 1_700_000_000,
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let (record, _key) = build_client_hello(
            "example.com",
            &[b"h2", b"http/1.1"],
            &keys,
            &[0x11; 32],
            plaintext,
        )
        .expect("client hello");
        record
    }

    /// One `ServerHello` extension frame.
    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(body.len())
                .expect("extension fits")
                .to_be_bytes(),
        );
        out.extend_from_slice(body);
        out
    }

    /// A `key_share` extension body, padded to the length it declares.
    fn key_share(group: u16, declared_len: usize) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&group.to_be_bytes());
        body.extend_from_slice(
            &u16::try_from(declared_len)
                .expect("share fits")
                .to_be_bytes(),
        );
        body.extend_from_slice(&vec![0xcd; declared_len]);
        body
    }

    /// Assembles a conforming `ServerHello` from its negotiable parts.
    fn server_hello(hello: &HelloRecord, suite: u16, extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&LEGACY_TLS12.to_be_bytes());
        body.extend_from_slice(&[0xab; 32]);
        body.push(32);
        body.extend_from_slice(hello.session_id());
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        let mut all = Vec::new();
        for item in extensions {
            all.extend_from_slice(item);
        }
        body.extend_from_slice(
            &u16::try_from(all.len())
                .expect("extensions fit")
                .to_be_bytes(),
        );
        body.extend_from_slice(&all);
        let mut message = vec![HANDSHAKE_SERVER_HELLO];
        let declared = u32::try_from(body.len()).expect("body fits");
        message.extend_from_slice(&declared.to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    /// A `supported_versions` extension claiming one version.
    fn supported_versions(version: u16) -> Vec<u8> {
        extension(EXTENSION_SUPPORTED_VERSIONS, &version.to_be_bytes())
    }

    fn negotiated(key_share: &[u8]) -> Vec<Vec<u8>> {
        vec![
            supported_versions(TLS13_VERSION),
            extension(EXTENSION_KEY_SHARE, key_share),
        ]
    }

    fn standard() -> Vec<Vec<u8>> {
        negotiated(&key_share(X25519_GROUP, X25519_SHARE_LEN))
    }

    #[test]
    fn accepts_a_conforming_x25519_hello() {
        let hello = hello();
        let bytes = server_hello(&hello, 0x1301, &standard());
        let parsed = ServerHello::parse(&bytes, &hello).expect("parse");
        assert_eq!(CipherSuite::Aes128GcmSha256, parsed.suite());
        assert_eq!(X25519_GROUP, parsed.key_share_group());
        assert_eq!(X25519_SHARE_LEN, parsed.server_share().len());
        assert_eq!(bytes, parsed.message());
    }

    #[test]
    fn accepts_the_hybrid_share_size() {
        let hello = hello();
        let bytes = server_hello(
            &hello,
            0x1302,
            &negotiated(&key_share(X25519_MLKEM768_GROUP, X25519_MLKEM768_SHARE_LEN)),
        );
        let parsed = ServerHello::parse(&bytes, &hello).expect("parse");
        assert_eq!(CipherSuite::Aes256GcmSha384, parsed.suite());
        assert_eq!(X25519_MLKEM768_SHARE_LEN, parsed.server_share().len());
    }

    #[test]
    fn rejects_a_session_id_that_is_not_echoed() {
        let hello = hello();
        let mut bytes = server_hello(&hello, 0x1301, &standard());
        // Header (4) + legacy version (2) + random (32) + length byte (1) is
        // where the echoed authenticator starts.
        bytes[39] ^= 0xff;
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::SessionIdMismatch)
        ));
    }

    #[test]
    fn rejects_a_non_tls13_negotiation() {
        let hello = hello();
        let bytes = server_hello(
            &hello,
            0x1301,
            &[
                supported_versions(0x0303),
                extension(
                    EXTENSION_KEY_SHARE,
                    &key_share(X25519_GROUP, X25519_SHARE_LEN),
                ),
            ],
        );
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::UnsupportedVersion)
        ));
    }

    #[test]
    fn rejects_a_missing_key_share_extension() {
        let hello = hello();
        let bytes = server_hello(&hello, 0x1301, &[supported_versions(TLS13_VERSION)]);
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::UnsupportedKeyShare)
        ));
    }

    #[test]
    fn rejects_a_selected_pre_shared_key() {
        let hello = hello();
        let mut extensions = standard();
        extensions.push(extension(EXTENSION_PRE_SHARED_KEY, &[0, 0]));
        let bytes = server_hello(&hello, 0x1301, &extensions);
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::PreSharedKeySelected)
        ));
    }

    #[test]
    fn rejects_a_mis_sized_key_share() {
        let hello = hello();
        let bytes = server_hello(&hello, 0x1301, &negotiated(&key_share(X25519_GROUP, 31)));
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::UnsupportedKeyShare)
        ));
    }

    #[test]
    fn rejects_an_unsupported_group() {
        let hello = hello();
        let bytes = server_hello(&hello, 0x1301, &negotiated(&key_share(0x0017, 65)));
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::UnsupportedKeyShare)
        ));
    }

    #[test]
    fn rejects_a_suite_that_was_never_offered() {
        let hello = hello();
        let bytes = server_hello(&hello, 0xc02f, &standard());
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::UnsupportedCipherSuite)
        ));
    }

    #[test]
    fn rejects_a_duplicate_extension() {
        let hello = hello();
        let bytes = server_hello(
            &hello,
            0x1301,
            &[
                supported_versions(TLS13_VERSION),
                supported_versions(TLS13_VERSION),
            ],
        );
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::Malformed("duplicate extension"))
        ));
    }

    #[test]
    fn rejects_a_truncated_message() {
        let hello = hello();
        assert!(matches!(
            ServerHello::parse(&[HANDSHAKE_SERVER_HELLO, 0, 0], &hello),
            Err(ServerHelloError::Truncated)
        ));
    }

    #[test]
    fn rejects_a_declared_length_that_does_not_match() {
        let hello = hello();
        let mut bytes = server_hello(&hello, 0x1301, &standard());
        bytes[3] ^= 1;
        assert!(matches!(
            ServerHello::parse(&bytes, &hello),
            Err(ServerHelloError::Malformed("declared length"))
        ));
    }

    #[test]
    fn diagnostics_render_no_key_material() {
        let hello = hello();
        let bytes = server_hello(&hello, 0x1301, &standard());
        let parsed = ServerHello::parse(&bytes, &hello).expect("parse");
        let rendered = format!("{parsed:?}");
        assert!(rendered.contains("ServerHello"));
        assert!(!rendered.contains("205"));
    }
}
