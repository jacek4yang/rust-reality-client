//! `ClientHello` construction, including the REALITY authenticator it carries.
//!
//! The message is assembled twice: first with a zeroed session ID, because the
//! server computes the AEAD additional data from exactly that form
//! (`client_hello.rs:343-350`); the resulting 32-byte ciphertext is then patched
//! into the session ID slot. Those offsets are the ones the server reads back,
//! so a layout change here must be matched by one there.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{EphemeralX25519, HybridMlkem, MLKEM768_CIPHERTEXT_LEN, X25519_PUBLIC_LEN};
use crate::entropy;
use crate::protocol::reality::auth::{AuthError, AuthKey, AuthPlaintext};
use crate::protocol::reality::{
    MAX_CLIENT_HELLO_BYTES, SESSION_ID_LEN, SESSION_ID_OFFSET, X25519_GROUP, X25519_MLKEM768_GROUP,
};

const LEGACY_VERSION: [u8; 2] = [3, 3];
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const RECORD_HEADER_LEN: usize = 5;
/// `supported_versions` body: a one-byte vector count, then TLS 1.3.
///
/// v2.0.1 requires that count to be even, at least two, and to cover the rest of
/// the body exactly, and refuses a hello that does not offer TLS 1.3
/// (`client_hello.rs:1375-1389`, `auth.rs:479`).
const SUPPORTED_VERSIONS_BODY: [u8; 3] = [2, 3, 4];

/// Every TLS 1.3 suite the server can present, offered in browser order.
///
/// The server mirrors the cipher its cover target selects and revalidates that
/// the client offered it (`server_hello.rs:114-116`), so an incomplete offer
/// turns an authenticated handshake into a cover fallback. The TLS 1.2 entries
/// only widen what a fallback cover can answer with.
const CIPHER_SUITES: [u16; 6] = [
    0x1301, // TLS 1.3 AES-128-GCM
    0x1302, // TLS 1.3 AES-256-GCM
    0x1303, // TLS 1.3 ChaCha20-Poly1305
    0xc02b, // ECDHE-ECDSA-AES-128-GCM
    0xc02f, // ECDHE-RSA-AES-128-GCM
    0xc030, // ECDHE-RSA-AES-256-GCM
];

/// Groups carried in the `key_share` extension, in the order `key_shares`
/// writes them.
///
/// These, not `SUPPORTED_GROUPS`, are what the server treats as offered: it
/// scans the shares actually present (`client_hello.rs:440-442`).
const KEY_SHARE_GROUPS: [u16; 2] = [X25519_MLKEM768_GROUP, X25519_GROUP];

/// Groups offered, hybrid first as current browsers do.
const SUPPORTED_GROUPS: [u16; 5] = [X25519_MLKEM768_GROUP, X25519_GROUP, 0x0017, 0x0018, 0x0019];

/// Signature algorithms, ending with the Ed25519 scheme `0x0807` that the
/// REALITY certificate is signed with.
const SIGNATURE_ALGORITHMS: [u16; 9] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0601, 0x0806, 0x0807,
];

/// A `ClientHello` could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloError {
    /// The presentation name is empty, over 253 bytes, or not ASCII.
    InvalidServerName,
    /// An ALPN protocol was empty or over 253 bytes.
    InvalidAlpn,
    /// The message would exceed the server's `ClientHello` bound or a TLS record.
    TooLarge,
    /// Entropy for the random field or an ephemeral key was unavailable.
    Entropy,
    /// A key agreement produced a non-contributory result.
    NonContributory,
    /// The authenticator could not be derived or sealed.
    Auth(AuthError),
}

impl fmt::Display for HelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServerName => formatter.write_str("invalid SNI presentation name"),
            Self::InvalidAlpn => formatter.write_str("invalid ALPN protocol identifier"),
            Self::TooLarge => formatter.write_str("ClientHello exceeds the server bound"),
            Self::Entropy => formatter.write_str("entropy unavailable"),
            Self::NonContributory => formatter.write_str("key agreement was non-contributory"),
            Self::Auth(error) => write!(formatter, "authenticator: {error}"),
        }
    }
}

impl std::error::Error for HelloError {}

impl From<AuthError> for HelloError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<HelloError> for crate::error::Error {
    fn from(error: HelloError) -> Self {
        use crate::error::HandshakeError;
        match error {
            // A name or an oversized message is a bad node entry, never a
            // network event.
            HelloError::InvalidServerName => {
                Self::Config("server name is not a valid SNI".to_owned())
            }
            HelloError::InvalidAlpn => {
                Self::Config("alpn protocol identifier is invalid".to_owned())
            }
            HelloError::TooLarge => {
                Self::Config("client hello exceeds the server bound".to_owned())
            }
            HelloError::Entropy => Self::Io("secure entropy unavailable".to_owned()),
            // The configured public key produced no shared secret, so it cannot
            // be the key this node publishes.
            HelloError::NonContributory => Self::Handshake(HandshakeError::IdentityMismatch),
            HelloError::Auth(AuthError::Crypto) => Self::Handshake(HandshakeError::Verification),
            HelloError::Auth(AuthError::OpenFailed) => {
                Self::Handshake(HandshakeError::IdentityMismatch)
            }
        }
    }
}

/// The TLS 1.3 `KeyExchange` value for the negotiated group.
///
/// Plain X25519 contributes 32 bytes; the hybrid group contributes the ML-KEM
/// secret followed by the X25519 secret, 64 bytes total, exactly as the
/// server's own key agreement produces (`handshake.rs:663-700`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SharedSecret {
    /// X25519 agreement output.
    X25519([u8; 32]),
    /// Hybrid agreement output: ML-KEM-768 secret then X25519 secret.
    Hybrid([u8; 64]),
}

impl SharedSecret {
    /// The bytes the key schedule extracts with.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::X25519(bytes) => bytes,
            Self::Hybrid(bytes) => bytes,
        }
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedSecret([REDACTED])")
    }
}

/// The ephemeral shares one `ClientHello` offers.
///
/// The standalone X25519 key does double duty: it is the REALITY authenticator
/// key agreement *and* the TLS share when the cover selects plain X25519. The
/// hybrid entry carries its own independent X25519 key plus an ML-KEM key, as
/// the server's own probe construction does (`client_hello.rs:518-552`).
pub struct ClientKeyAgreement {
    x25519: EphemeralX25519,
    hybrid_x25519: EphemeralX25519,
    hybrid_mlkem: HybridMlkem,
}

impl ClientKeyAgreement {
    /// Generates every share from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`HelloError::Entropy`] when entropy is unavailable.
    pub fn generate() -> Result<Self, HelloError> {
        Ok(Self {
            x25519: EphemeralX25519::generate().map_err(|_| HelloError::Entropy)?,
            hybrid_x25519: EphemeralX25519::generate().map_err(|_| HelloError::Entropy)?,
            hybrid_mlkem: HybridMlkem::generate().map_err(|_| HelloError::Entropy)?,
        })
    }

    /// Derives the REALITY authenticator key against the configured server.
    pub(crate) fn auth_key(
        &self,
        server_public_key: &[u8; X25519_PUBLIC_LEN],
        client_random: &[u8; 32],
    ) -> Result<AuthKey, HelloError> {
        let shared = self
            .x25519
            .agree(server_public_key)
            .ok_or(HelloError::NonContributory)?;
        Ok(AuthKey::derive(&shared, client_random)?)
    }

    /// Agrees the TLS 1.3 ECDHE secret for the group the server selected.
    ///
    /// Returns `None` for an unknown group or a share of the wrong shape,
    /// including one too short to split: no input length may panic here.
    pub(crate) fn tls_shared_secret(
        &self,
        group: u16,
        server_share: &[u8],
    ) -> Option<SharedSecret> {
        match group {
            X25519_GROUP => {
                let peer = <[u8; X25519_PUBLIC_LEN]>::try_from(server_share).ok()?;
                self.x25519
                    .agree(&peer)
                    .map(|secret| SharedSecret::X25519(*secret))
            }
            X25519_MLKEM768_GROUP => {
                let (ciphertext, peer_bytes) =
                    server_share.split_at_checked(MLKEM768_CIPHERTEXT_LEN)?;
                let peer = <[u8; X25519_PUBLIC_LEN]>::try_from(peer_bytes).ok()?;
                let mlkem = self.hybrid_mlkem.decapsulate(ciphertext)?;
                let x25519 = self.hybrid_x25519.agree(&peer)?;
                let mut bytes = [0_u8; 64];
                bytes[..32].copy_from_slice(&mlkem[..]);
                bytes[32..].copy_from_slice(&x25519[..]);
                Some(SharedSecret::Hybrid(bytes))
            }
            _ => None,
        }
    }

    /// The standalone X25519 public share.
    ///
    /// The server always authenticates against this key, even when it selects
    /// the hybrid group for TLS 1.3 (`client_hello.rs:peer_x25519`), so a peer
    /// that must reproduce the server side of the agreement needs it.
    #[must_use]
    pub const fn authentication_public_key(&self) -> &[u8; X25519_PUBLIC_LEN] {
        self.x25519.public_key()
    }

    /// Encodes both key shares for the `key_share` extension, hybrid first.
    ///
    /// The server reads the standalone X25519 share for authentication and the
    /// selected group's share for the TLS 1.3 agreement, and it requires the
    /// hybrid entry to be exactly the encapsulation key followed by the
    /// X25519 public key (`client_hello.rs:peer_x25519`,
    /// `handshake.rs:agree_key_share`).
    fn key_shares(&self) -> Result<(Vec<u8>, [u16; KEY_SHARE_GROUPS.len()]), HelloError> {
        let encap = self.hybrid_mlkem.encapsulation_key();
        let hybrid_public = self.hybrid_x25519.public_key();
        let standalone = self.x25519.public_key();
        let mut output =
            Vec::with_capacity(8 + encap.len() + hybrid_public.len() + standalone.len());
        output.extend_from_slice(&KEY_SHARE_GROUPS[0].to_be_bytes());
        push_u16(&mut output, encap.len() + hybrid_public.len())?;
        output.extend_from_slice(encap);
        output.extend_from_slice(hybrid_public);
        output.extend_from_slice(&KEY_SHARE_GROUPS[1].to_be_bytes());
        push_u16(&mut output, standalone.len())?;
        output.extend_from_slice(standalone);
        Ok((output, KEY_SHARE_GROUPS))
    }
}

impl fmt::Debug for ClientKeyAgreement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientKeyAgreement([REDACTED])")
    }
}

/// One constructed `ClientHello`, ready to write.
pub struct HelloRecord {
    message: Vec<u8>,
    record_length: u16,
    random: [u8; 32],
    session_id: [u8; SESSION_ID_LEN],
    key_share_groups: [u16; KEY_SHARE_GROUPS.len()],
}

impl HelloRecord {
    /// The exact handshake message bytes, which the transcript hashes.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// The message wrapped in one plaintext TLS record.
    #[must_use]
    pub fn record(&self) -> Vec<u8> {
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + self.message.len());
        record.extend_from_slice(&[CONTENT_TYPE_HANDSHAKE, 3, 3]);
        record.extend_from_slice(&self.record_length.to_be_bytes());
        record.extend_from_slice(&self.message);
        record
    }

    /// The 32-byte `ClientHello` random, source of the AEAD salt and nonce.
    #[must_use]
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// The REALITY authenticator bytes carried in the session ID.
    ///
    /// The server must echo these exact bytes in its `ServerHello`, so the
    /// caller compares them against the parsed hello rather than re-decrypting.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Whether the server echoed our session ID byte for byte.
    #[must_use]
    pub fn matches_session_id(&self, observed: &[u8]) -> bool {
        observed == self.session_id
    }

    /// Whether this hello offered a cipher suite, mirroring
    /// `ClientHello::cipher_offered` on the server.
    #[must_use]
    pub fn cipher_offered(&self, suite: u16) -> bool {
        CIPHER_SUITES.contains(&suite)
    }

    /// Whether this hello carried a share for a group.
    ///
    /// The server scans the `key_share` entries and pays no attention to
    /// `supported_groups`, so a group merely listed there is not one it may
    /// select (`client_hello.rs:440-442`).
    #[must_use]
    pub fn key_share_group_offered(&self, group: u16) -> bool {
        self.key_share_groups.contains(&group)
    }
}

impl fmt::Debug for HelloRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelloRecord")
            .field("message_len", &self.message.len())
            .finish_non_exhaustive()
    }
}

/// Builds a `ClientHello` carrying a valid REALITY authenticator.
///
/// `auth.time` must come from the clock whose skew the node tolerates; v2.0.1
/// defaults to 60 seconds (`config/node/reality.rs:49-57`).
///
/// # Errors
///
/// Returns [`HelloError`] for an invalid name, an oversized message, entropy
/// failure, or a non-contributory server key.
pub fn build_client_hello(
    server_name: &str,
    alpn: &[&[u8]],
    keys: &ClientKeyAgreement,
    server_public_key: &[u8; X25519_PUBLIC_LEN],
    auth: AuthPlaintext,
) -> Result<(HelloRecord, AuthKey), HelloError> {
    if server_name.is_empty() || server_name.len() > 253 || !server_name.is_ascii() {
        return Err(HelloError::InvalidServerName);
    }
    for protocol in alpn {
        if protocol.is_empty() || protocol.len() > 253 {
            return Err(HelloError::InvalidAlpn);
        }
    }

    let random = entropy::array::<32>().map_err(|_| HelloError::Entropy)?;
    let auth_key = keys.auth_key(server_public_key, &random)?;

    let (mut message, key_share_groups) = assemble(server_name, alpn, keys, &random)?;
    let session_id = auth_key.seal_session_id(&random, &message, auth)?;
    message
        .get_mut(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
        .ok_or(HelloError::TooLarge)?
        .copy_from_slice(&session_id);
    let record_length = u16::try_from(message.len()).map_err(|_| HelloError::TooLarge)?;
    Ok((
        HelloRecord {
            message,
            record_length,
            random,
            session_id,
            key_share_groups,
        },
        auth_key,
    ))
}

/// Assembles the message with the real random and a zeroed session ID.
///
/// Every vector is bounded before it is written, so a later `u16` or `u24`
/// cast cannot silently truncate.
fn assemble(
    server_name: &str,
    alpn: &[&[u8]],
    keys: &ClientKeyAgreement,
    random: &[u8; 32],
) -> Result<(Vec<u8>, [u16; KEY_SHARE_GROUPS.len()]), HelloError> {
    let mut extensions = Vec::new();
    let host = server_name.as_bytes();
    push_extension(&mut extensions, 0x0000, |body| {
        push_u16(body, 3 + host.len())?;
        body.push(0);
        push_u16(body, host.len())?;
        body.extend_from_slice(host);
        Ok(())
    })?;
    push_extension(&mut extensions, 0x000a, |body| {
        push_u16(body, SUPPORTED_GROUPS.len() * 2)?;
        for group in SUPPORTED_GROUPS {
            push_u16(body, usize::from(group))?;
        }
        Ok(())
    })?;
    push_extension(&mut extensions, 0x000d, |body| {
        push_u16(body, SIGNATURE_ALGORITHMS.len() * 2)?;
        for scheme in SIGNATURE_ALGORITHMS {
            push_u16(body, usize::from(scheme))?;
        }
        Ok(())
    })?;
    push_extension(&mut extensions, 0x0005, |body| {
        body.extend_from_slice(&[0, 0]);
        Ok(())
    })?;
    push_extension(&mut extensions, 0x0010, |body| {
        let list_len: usize = alpn.iter().map(|protocol| 1 + protocol.len()).sum();
        push_u16(body, list_len)?;
        for protocol in alpn {
            let length = u8::try_from(protocol.len()).map_err(|_| HelloError::TooLarge)?;
            body.push(length);
            body.extend_from_slice(protocol);
        }
        Ok(())
    })?;
    push_extension(&mut extensions, 0x2d00, |body| {
        body.extend_from_slice(&[1, 1]);
        Ok(())
    })?;
    push_extension(&mut extensions, 0x002b, |body| {
        body.extend_from_slice(&SUPPORTED_VERSIONS_BODY);
        Ok(())
    })?;
    let (entries, groups) = keys.key_shares()?;
    push_extension(&mut extensions, 0x0033, |body| {
        push_u16(body, entries.len())?;
        body.extend_from_slice(&entries);
        Ok(())
    })?;

    let suites_len = CIPHER_SUITES.len() * 2;
    // `legacy_version` 2 + `random` 32 + `session_id` length 1 + its 32 bytes,
    // then cipher suites as a `uint16` vector, compression methods as a *uint8*
    // vector, and extensions as a `uint16` vector.
    let body_len = 2 + 32 + 1 + SESSION_ID_LEN + 2 + suites_len + 1 + 1 + 2 + extensions.len();
    let message_len = body_len + 4;
    if message_len > MAX_CLIENT_HELLO_BYTES || message_len > u16::MAX.into() {
        return Err(HelloError::TooLarge);
    }

    let mut message = Vec::with_capacity(message_len);
    message.push(HANDSHAKE_CLIENT_HELLO);
    let length = u32::try_from(body_len).map_err(|_| HelloError::TooLarge)?;
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    message.extend_from_slice(&LEGACY_VERSION);
    message.extend_from_slice(random);
    message.push(u8::try_from(SESSION_ID_LEN).map_err(|_| HelloError::TooLarge)?);
    message.resize(message.len() + SESSION_ID_LEN, 0);
    push_u16(&mut message, suites_len)?;
    for suite in CIPHER_SUITES {
        push_u16(&mut message, usize::from(suite))?;
    }
    message.push(1);
    message.push(0);
    push_u16(&mut message, extensions.len())?;
    message.extend_from_slice(&extensions);
    if message.len() != message_len {
        return Err(HelloError::TooLarge);
    }
    Ok((message, groups))
}

/// Appends one extension header and body, refusing an oversized body.
fn push_extension(
    output: &mut Vec<u8>,
    extension_type: u16,
    write: impl FnOnce(&mut Vec<u8>) -> Result<(), HelloError>,
) -> Result<(), HelloError> {
    let mut body = Vec::new();
    write(&mut body)?;
    output.extend_from_slice(&extension_type.to_be_bytes());
    push_u16(output, body.len())?;
    output.extend_from_slice(&body);
    Ok(())
}

/// Appends a big-endian length, refusing a value a TLS vector cannot carry.
fn push_u16(output: &mut Vec<u8>, length: usize) -> Result<(), HelloError> {
    output.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| HelloError::TooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::reality::auth::CLIENT_VERSION;
    use crate::protocol::reality::{Reader, X25519_MLKEM768_SHARE_LEN};

    use super::*;

    const NAME: &str = "www.example.com";
    const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
    const SERVER_KEY: [u8; X25519_PUBLIC_LEN] = [0x11; X25519_PUBLIC_LEN];

    fn plaintext() -> AuthPlaintext {
        AuthPlaintext {
            version: CLIENT_VERSION,
            time: 1_700_000_000,
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    fn hello() -> (HelloRecord, ClientKeyAgreement, AuthKey) {
        let keys = ClientKeyAgreement::generate().expect("key agreement");
        build_client_hello(NAME, ALPN, &keys, &SERVER_KEY, plaintext())
            .map(|(record, auth_key)| (record, keys, auth_key))
            .expect("client hello")
    }

    /// Walks the fixed fields, then returns the suites and the extensions in
    /// wire order, mirroring the order the server's reader consumes them in.
    fn suites_and_extensions(message: &[u8]) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
        let mut reader = Reader::new(message);
        assert_eq!(Some(1), reader.read_u8(), "handshake type is client_hello");
        let declared = reader.read_u24().expect("message length");
        assert_eq!(
            declared,
            reader.remaining(),
            "the length covers the body exactly"
        );
        assert_eq!(
            Some(&[3, 3][..]),
            reader.read(2),
            "the legacy version claims TLS 1.2"
        );
        assert!(reader.skip(32).is_some(), "the random is 32 bytes");
        let length = reader.read_u8().expect("session id length");
        assert_eq!(
            SESSION_ID_LEN,
            usize::from(length),
            "only a 32-byte session id authenticates"
        );
        assert!(
            reader.skip(SESSION_ID_LEN).is_some(),
            "the session id window"
        );
        let mut suites = Vec::new();
        let suites_len = usize::from(reader.read_u16().expect("suites length"));
        let mut window = Reader::new(reader.read(suites_len).expect("suites"));
        while let Some(suite) = window.read_u16() {
            suites.push(suite);
        }
        assert_eq!(Some(1), reader.read_u8(), "one compression method");
        assert_eq!(Some(0), reader.read_u8(), "and it is null");
        let extensions_len = usize::from(reader.read_u16().expect("extensions length"));
        let mut extensions = Reader::new(reader.read(extensions_len).expect("extension bytes"));
        assert_eq!(None, reader.read_u8(), "no bytes follow the extensions");
        let mut found = Vec::new();
        while let Some(kind) = extensions.read_u16() {
            let length = usize::from(extensions.read_u16().expect("extension length"));
            found.push((kind, extensions.read(length).expect("body").to_vec()));
        }
        (suites, found)
    }

    fn extension(message: &[u8], kind: u16) -> Vec<u8> {
        suites_and_extensions(message)
            .1
            .into_iter()
            .find(|(found, _)| *found == kind)
            .unwrap_or_else(|| panic!("extension {kind:#06x} is missing"))
            .1
    }

    #[test]
    fn the_layout_matches_the_offsets_the_server_reads() {
        let (record, _, _) = hello();
        let message = record.message();
        assert_eq!(Some(&1), message.first());
        assert_eq!(
            SESSION_ID_LEN,
            usize::from(message[38]),
            "the length byte sits where the server looks"
        );
        assert_eq!(
            &record.random()[..],
            &message[6..38],
            "the random is the AEAD salt and nonce source"
        );
        assert_eq!(
            &record.session_id()[..],
            &message[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN],
            "the authenticator is patched in at the documented offset"
        );
    }

    #[test]
    fn the_authenticator_opens_against_the_zeroed_session_id_form() {
        let (record, _, auth_key) = hello();
        // The server rebuilds the additional data by zeroing the session ID in
        // place, so that buffer is the only one the authenticator can open.
        let mut aad = record.message().to_vec();
        aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        let opened = auth_key
            .open_session_id(record.random(), &aad, record.session_id())
            .expect("the server's reconstruction opens our authenticator");
        assert_eq!(plaintext(), opened);
    }

    #[test]
    fn a_different_configured_key_produces_an_unopenable_authenticator() {
        let keys = ClientKeyAgreement::generate().expect("key agreement");
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &SERVER_KEY, plaintext()).expect("client hello");
        let foreign = AuthKey::derive(&[0x22; 32], record.random()).expect("derive");
        let mut aad = record.message().to_vec();
        aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        assert!(
            foreign
                .open_session_id(record.random(), &aad, record.session_id())
                .is_err(),
            "a node without the configured private key cannot read the short id"
        );
    }

    #[test]
    fn every_suite_the_server_can_select_is_offered() {
        let (record, _, _) = hello();
        let (suites, _) = suites_and_extensions(record.message());
        assert_eq!(Vec::from(CIPHER_SUITES), suites);
        for suite in [0x1301_u16, 0x1302, 0x1303] {
            assert!(record.cipher_offered(suite), "{suite:#06x}");
        }
        assert!(
            !record.cipher_offered(0xc013),
            "a suite we never sent must not be claimed as offered"
        );
    }

    #[test]
    fn every_extension_appears_once_in_wire_order() {
        let (record, _, _) = hello();
        let kinds: Vec<u16> = suites_and_extensions(record.message())
            .1
            .iter()
            .map(|(kind, _)| *kind)
            .collect();
        assert_eq!(
            vec![
                0x0000, 0x000a, 0x000d, 0x0005, 0x0010, 0x2d00, 0x002b, 0x0033
            ],
            kinds
        );
    }

    #[test]
    fn the_server_name_extension_claims_one_host() {
        let (record, _, _) = hello();
        let body = extension(record.message(), 0x0000);
        let mut reader = Reader::new(&body);
        let list_len = usize::from(reader.read_u16().expect("list length"));
        assert_eq!(list_len, reader.remaining(), "one name and nothing else");
        assert_eq!(Some(0), reader.read_u8(), "host_name");
        let length = usize::from(reader.read_u16().expect("name length"));
        assert_eq!(NAME.as_bytes(), reader.read(length).expect("name"));
        assert!(reader.is_empty());
    }

    #[test]
    fn the_alpn_extension_offers_exactly_what_was_requested() {
        let (record, _, _) = hello();
        let body = extension(record.message(), 0x0010);
        let mut reader = Reader::new(&body);
        let list_len = usize::from(reader.read_u16().expect("list length"));
        let mut protocols = Vec::new();
        let mut window = Reader::new(reader.read(list_len).expect("protocol list"));
        while !window.is_empty() {
            let length = usize::from(window.read_u8().expect("protocol length"));
            protocols.push(window.read(length).expect("protocol").to_vec());
        }
        assert_eq!(vec![b"h2".to_vec(), b"http/1.1".to_vec()], protocols);
        assert!(reader.is_empty());
    }

    #[test]
    fn supported_versions_claims_only_tls_1_3() {
        let (record, _, _) = hello();
        assert_eq!(vec![2_u8, 3, 4], extension(record.message(), 0x002b));
    }

    #[test]
    fn both_key_shares_are_offered_at_their_wire_sizes() {
        let (record, keys, _) = hello();
        let body = extension(record.message(), 0x0033);
        let mut reader = Reader::new(&body);
        let list_len = usize::from(reader.read_u16().expect("list length"));
        assert_eq!(list_len, reader.remaining(), "no trailing bytes");
        let mut window = Reader::new(reader.read(list_len).expect("shares"));

        assert_eq!(
            Some(X25519_MLKEM768_GROUP),
            window.read_u16(),
            "hybrid first"
        );
        let length = usize::from(window.read_u16().expect("hybrid length"));
        assert_eq!(X25519_MLKEM768_SHARE_LEN, length);
        let mut expected = Vec::new();
        expected.extend_from_slice(keys.hybrid_mlkem.encapsulation_key());
        expected.extend_from_slice(keys.hybrid_x25519.public_key());
        assert_eq!(
            expected,
            window.read(length).expect("hybrid bytes"),
            "encapsulation key then x25519 public key, in that order"
        );

        assert_eq!(Some(X25519_GROUP), window.read_u16());
        let length = usize::from(window.read_u16().expect("share length"));
        assert_eq!(X25519_PUBLIC_LEN, length);
        assert_eq!(
            keys.authentication_public_key(),
            window.read(length).expect("share"),
            "the standalone share is the one the server authenticates"
        );
        assert!(window.is_empty(), "exactly two shares");
    }

    #[test]
    fn the_group_offered_list_matches_the_shares_carried() {
        let (record, _, _) = hello();
        let body = extension(record.message(), 0x000a);
        let mut reader = Reader::new(&body);
        let list_len = usize::from(reader.read_u16().expect("list length"));
        let mut window = Reader::new(reader.read(list_len).expect("groups"));
        let mut groups = Vec::new();
        while let Some(group) = window.read_u16() {
            groups.push(group);
        }
        assert_eq!(Vec::from(SUPPORTED_GROUPS), groups);
        assert!(record.key_share_group_offered(X25519_GROUP));
        assert!(record.key_share_group_offered(X25519_MLKEM768_GROUP));
        assert!(
            !record.key_share_group_offered(0x0017),
            "listed only for cover realism, never shared"
        );
    }

    #[test]
    fn the_record_wraps_the_message_in_a_plaintext_handshake_header() {
        let (record, _, _) = hello();
        let bytes = record.record();
        assert_eq!(Some(&[22_u8, 3, 3]), bytes.first_chunk::<3>());
        let declared = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        assert_eq!(record.message().len(), declared);
        assert_eq!(5 + declared, bytes.len());
    }

    #[test]
    fn each_build_draws_a_fresh_random_and_authenticator() {
        let (first, _, _) = hello();
        let (second, _, _) = hello();
        assert_ne!(first.random(), second.random());
        assert_ne!(first.session_id(), second.session_id());
    }

    #[test]
    fn the_echoed_session_id_must_match_byte_for_byte() {
        let (record, _, _) = hello();
        assert!(record.matches_session_id(record.session_id()));
        let mut observed = *record.session_id();
        observed[0] ^= 1;
        assert!(
            !record.matches_session_id(&observed),
            "a cover target that shrinks the session id is not our node"
        );
        assert!(
            !record.matches_session_id(&record.session_id()[..31]),
            "a truncated echo is not a match either"
        );
    }

    #[test]
    fn invalid_names_and_protocols_are_refused_before_any_crypto() {
        let keys = ClientKeyAgreement::generate().expect("key agreement");
        let long = "a".repeat(254);
        for name in ["", long.as_str()] {
            assert!(
                matches!(
                    build_client_hello(name, ALPN, &keys, &SERVER_KEY, plaintext()),
                    Err(HelloError::InvalidServerName)
                ),
                "{name:?}"
            );
        }
        assert!(matches!(
            build_client_hello(
                "www.ex\u{e4}mple.com",
                ALPN,
                &keys,
                &SERVER_KEY,
                plaintext()
            ),
            Err(HelloError::InvalidServerName)
        ));
        for protocol in [&b""[..], &[0_u8; 254][..]] {
            assert!(matches!(
                build_client_hello(NAME, &[protocol], &keys, &SERVER_KEY, plaintext()),
                Err(HelloError::InvalidAlpn)
            ));
        }
    }

    #[test]
    fn the_plain_agreement_rejects_a_non_contributory_share() {
        let (_, keys, _) = hello();
        assert!(keys.tls_shared_secret(X25519_GROUP, &[0_u8; 32]).is_none());
        let secret = keys
            .tls_shared_secret(X25519_GROUP, &[0x33; 32])
            .expect("contributory");
        assert_eq!(32, secret.as_bytes().len());
        assert!(
            keys.tls_shared_secret(X25519_GROUP, &[0x33; 31]).is_none(),
            "a short share must be refused, not paniced"
        );
    }

    #[test]
    fn the_hybrid_agreement_needs_the_exact_server_share_shape() {
        let (_, keys, _) = hello();
        assert!(
            keys.tls_shared_secret(X25519_MLKEM768_GROUP, &[0_u8; 1_119])
                .is_none(),
            "one byte short of ciphertext plus public key must be refused"
        );
        let share = [&[7_u8; MLKEM768_CIPHERTEXT_LEN][..], &[0x33; 32][..]].concat();
        let secret = keys
            .tls_shared_secret(X25519_MLKEM768_GROUP, &share)
            .expect("hybrid agreement");
        assert_eq!(
            64,
            secret.as_bytes().len(),
            "mlkem secret then x25519 secret"
        );
        assert!(keys.tls_shared_secret(0x0017, &[0_u8; 65]).is_none());
    }

    #[test]
    fn diagnostics_never_render_secret_material() {
        let (record, keys, auth_key) = hello();
        let rendered = format!("{record:?}");
        assert!(rendered.contains("message_len"), "{rendered}");
        assert!(!rendered.contains("session"), "{rendered}");
        assert_eq!("ClientKeyAgreement([REDACTED])", format!("{keys:?}"));
        assert_eq!("AuthKey([REDACTED])", format!("{auth_key:?}"));
        let secret = keys
            .tls_shared_secret(X25519_GROUP, &[0x33; 32])
            .expect("agreement");
        assert_eq!("SharedSecret([REDACTED])", format!("{secret:?}"));
    }
}
