//! `ClientHello` construction, including the REALITY authenticator it carries.
//!
//! The message is assembled twice: first with a zeroed session ID, because the
//! server computes the AEAD additional data from exactly that form
//! (`client_hello.rs:343-350`); the resulting 32-byte ciphertext is then patched
//! into the session ID slot. Those offsets are the ones the server reads back,
//! so a layout change here must be matched by one there.
//!
//! The shape around that fixed header comes from
//! [`crate::protocol::reality::fingerprint`]. The authenticator never enters
//! extension writing, so any profile order keeps the zeroed-AAD invariant.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{EphemeralX25519, HybridMlkem, MLKEM768_CIPHERTEXT_LEN, X25519_PUBLIC_LEN};
use crate::entropy;
use crate::protocol::reality::auth::{AuthError, AuthKey, AuthPlaintext};
use crate::protocol::reality::fingerprint::{
    HelloPlan, PlanError, Profile, ShareGroup, ShareMaterial,
};
use crate::protocol::reality::{
    MAX_CLIENT_HELLO_BYTES, SESSION_ID_LEN, SESSION_ID_OFFSET, X25519_GROUP, X25519_MLKEM768_GROUP,
};

const LEGACY_VERSION: [u8; 2] = [3, 3];
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const RECORD_HEADER_LEN: usize = 5;
/// A TLS record cannot carry more plaintext than this.
const MAX_TLS_RECORD: usize = 16_384;

/// A `ClientHello` could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloError {
    /// The presentation name is empty, over 253 bytes, or not ASCII.
    InvalidServerName,
    /// An ALPN protocol was empty or over 253 bytes.
    InvalidAlpn,
    /// The message would exceed the server's `ClientHello` bound or a TLS record.
    TooLarge,
    /// The selected profile is internally inconsistent.
    Profile(&'static str),
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
            Self::TooLarge => formatter.write_str("ClientHello exceeds the wire bound"),
            Self::Profile(reason) => write!(formatter, "ClientHello profile: {reason}"),
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

impl From<PlanError> for HelloError {
    fn from(error: PlanError) -> Self {
        match error {
            PlanError::TooLarge => Self::TooLarge,
            PlanError::MissingHybrid => {
                Self::Profile("hybrid key share requested but not generated")
            }
            PlanError::MissingEch => Self::Profile("ECH grease requested without a plan"),
        }
    }
}

impl From<HelloError> for crate::error::Error {
    fn from(error: HelloError) -> Self {
        use crate::error::HandshakeError;
        match error {
            HelloError::InvalidServerName => {
                Self::Config("server name is not a valid SNI".to_owned())
            }
            HelloError::InvalidAlpn => {
                Self::Config("alpn protocol identifier is invalid".to_owned())
            }
            HelloError::TooLarge => Self::Config("client hello exceeds the wire bound".to_owned()),
            HelloError::Profile(reason) => Self::Config(format!("client hello profile: {reason}")),
            HelloError::Entropy => Self::Io("secure entropy unavailable".to_owned()),
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
    hybrid_x25519: Option<EphemeralX25519>,
    hybrid_mlkem: Option<HybridMlkem>,
}

impl ClientKeyAgreement {
    /// Generates every share from operating-system entropy.
    ///
    /// Profiles that do not declare the hybrid group do not pay for an ML-KEM
    /// key generation.
    ///
    /// # Errors
    ///
    /// Returns [`HelloError::Entropy`] when entropy is unavailable.
    pub fn generate(needs_hybrid: bool) -> Result<Self, HelloError> {
        let x25519 = EphemeralX25519::generate().map_err(|_| HelloError::Entropy)?;
        let (hybrid_x25519, hybrid_mlkem) = if needs_hybrid {
            (
                Some(EphemeralX25519::generate().map_err(|_| HelloError::Entropy)?),
                Some(HybridMlkem::generate().map_err(|_| HelloError::Entropy)?),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            x25519,
            hybrid_x25519,
            hybrid_mlkem,
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
                let mlkem = self.hybrid_mlkem.as_ref()?.decapsulate(ciphertext)?;
                let x25519 = self.hybrid_x25519.as_ref()?.agree(&peer)?;
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

    /// The public material the profile serializer places into key shares.
    pub(crate) fn share_material(&self) -> ShareMaterial {
        let hybrid = match (&self.hybrid_mlkem, &self.hybrid_x25519) {
            (Some(mlkem), Some(x25519)) => {
                let encap = mlkem.encapsulation_key();
                let mut bytes = Vec::with_capacity(encap.len() + X25519_PUBLIC_LEN);
                bytes.extend_from_slice(encap);
                bytes.extend_from_slice(x25519.public_key());
                Some(bytes)
            }
            _ => None,
        };
        ShareMaterial {
            x25519: *self.x25519.public_key(),
            hybrid,
        }
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
    profile: &'static Profile,
    key_share_groups: Vec<u16>,
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
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// The profile this hello was built from.
    #[must_use]
    pub const fn profile(&self) -> &'static Profile {
        self.profile
    }

    /// The ALPN protocols actually written into the hello.
    #[must_use]
    pub fn alpn(&self) -> &[Vec<u8>] {
        self.profile.alpn()
    }

    /// Whether the server echoed our session ID byte for byte.
    #[must_use]
    pub fn matches_session_id(&self, observed: &[u8]) -> bool {
        observed == self.session_id
    }

    /// Whether this hello offered a cipher suite.
    #[must_use]
    pub fn cipher_offered(&self, suite: u16) -> bool {
        self.profile.ciphers.contains(&suite)
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
            .field("profile", &self.profile.name())
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
    profile: &'static Profile,
    keys: &ClientKeyAgreement,
    server_public_key: &[u8; X25519_PUBLIC_LEN],
    auth: AuthPlaintext,
) -> Result<(HelloRecord, AuthKey), HelloError> {
    if server_name.is_empty() || server_name.len() > 253 || !server_name.is_ascii() {
        return Err(HelloError::InvalidServerName);
    }
    for protocol in profile.alpn() {
        if protocol.is_empty() || protocol.len() > 253 {
            return Err(HelloError::InvalidAlpn);
        }
    }

    let random = entropy::array::<32>().map_err(|_| HelloError::Entropy)?;
    let auth_key = keys.auth_key(server_public_key, &random)?;

    let seed = entropy::array::<32>().map_err(|_| HelloError::Entropy)?;
    let plan = profile.plan_with_seed(seed);
    let (mut message, key_share_groups) =
        assemble(server_name, profile, &plan, &keys.share_material(), &random)?;
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
            profile,
            key_share_groups,
        },
        auth_key,
    ))
}

/// Assembles the message with the real random and a zeroed session ID.
fn assemble(
    server_name: &str,
    profile: &Profile,
    plan: &HelloPlan,
    shares: &ShareMaterial,
    random: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u16>), HelloError> {
    let extensions = plan.extensions(profile, server_name, shares)?;
    let ciphers: Vec<u16> = profile
        .ciphers
        .iter()
        .map(|suite| {
            if *suite == crate::protocol::reality::fingerprint::GREASE_PLACEHOLDER {
                plan.grease_cipher()
            } else {
                *suite
            }
        })
        .collect();

    let suites_len = ciphers.len() * 2;
    let body_len = 2
        + 32
        + 1
        + SESSION_ID_LEN
        + 2
        + suites_len
        + 1
        + profile.compression.len()
        + 2
        + extensions.len();
    let message_len = body_len + 4;
    if message_len > MAX_CLIENT_HELLO_BYTES || message_len > MAX_TLS_RECORD {
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
    for suite in ciphers {
        push_u16(&mut message, usize::from(suite))?;
    }
    message.push(u8::try_from(profile.compression.len()).map_err(|_| HelloError::TooLarge)?);
    message.extend_from_slice(&profile.compression);
    push_u16(&mut message, extensions.len())?;
    message.extend_from_slice(&extensions);
    if message.len() != message_len {
        return Err(HelloError::Profile(
            "serialized length disagrees with its plan",
        ));
    }

    let groups = profile
        .shares
        .iter()
        .filter_map(|share| match share {
            ShareGroup::X25519 => Some(X25519_GROUP),
            ShareGroup::Hybrid => Some(X25519_MLKEM768_GROUP),
            ShareGroup::Grease => None,
        })
        .collect();
    Ok((message, groups))
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
    use crate::protocol::reality::Reader;
    use crate::protocol::reality::auth::CLIENT_VERSION;
    use crate::protocol::reality::fingerprint::{Fingerprint, GREASE_PLACEHOLDER};
    use crate::protocol::reality::{SESSION_ID_OFFSET, X25519_MLKEM768_SHARE_LEN};

    use super::*;

    const NAME: &str = "www.example.com";
    const SERVER_KEY: [u8; X25519_PUBLIC_LEN] = [0x11; X25519_PUBLIC_LEN];

    fn plaintext() -> AuthPlaintext {
        AuthPlaintext {
            version: CLIENT_VERSION,
            time: 1_700_000_000,
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    fn profile() -> &'static Profile {
        Fingerprint::Chrome133.resolve([7; 32])
    }

    fn hello() -> (HelloRecord, ClientKeyAgreement, AuthKey) {
        let keys = ClientKeyAgreement::generate(true).expect("key agreement");
        build_client_hello(NAME, profile(), &keys, &SERVER_KEY, plaintext())
            .map(|(record, auth_key)| (record, keys, auth_key))
            .expect("client hello")
    }

    fn extensions(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut reader = Reader::new(message);
        assert_eq!(Some(1), reader.read_u8(), "handshake type is client_hello");
        let declared = reader.read_u24().expect("message length");
        assert_eq!(declared, reader.remaining());
        assert_eq!(Some(&[3, 3][..]), reader.read(2), "legacy version");
        assert!(reader.skip(32).is_some(), "random");
        let length = usize::from(reader.read_u8().expect("session id length"));
        assert_eq!(SESSION_ID_LEN, length);
        assert!(reader.skip(length).is_some());
        let suites_len = usize::from(reader.read_u16().expect("suites length"));
        assert!(reader.skip(suites_len).is_some());
        let compression = usize::from(reader.read_u8().expect("compression length"));
        assert!(reader.skip(compression).is_some());
        let extensions_len = usize::from(reader.read_u16().expect("extensions length"));
        let mut window = Reader::new(reader.read(extensions_len).expect("extensions"));
        let mut found = Vec::new();
        while let Some(kind) = window.read_u16() {
            let length = usize::from(window.read_u16().expect("extension length"));
            found.push((kind, window.read(length).expect("body").to_vec()));
        }
        found
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
        assert_eq!(&record.random()[..], &message[6..38]);
        assert_eq!(
            &record.session_id()[..],
            &message[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN],
            "the authenticator is patched at the documented offset"
        );
    }

    #[test]
    fn the_authenticator_opens_against_the_zeroed_session_id_form() {
        let (record, _, auth_key) = hello();
        let mut aad = record.message().to_vec();
        aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        let opened = auth_key
            .open_session_id(record.random(), &aad, record.session_id())
            .expect("the server's reconstruction opens our authenticator");
        assert_eq!(plaintext(), opened);
    }

    #[test]
    fn a_different_configured_key_produces_an_unopenable_authenticator() {
        let keys = ClientKeyAgreement::generate(true).expect("key agreement");
        let (record, _) =
            build_client_hello(NAME, profile(), &keys, &SERVER_KEY, plaintext()).expect("hello");
        let foreign = AuthKey::derive(&[0x22; 32], record.random()).expect("derive");
        let mut aad = record.message().to_vec();
        aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        assert!(
            foreign
                .open_session_id(record.random(), &aad, record.session_id())
                .is_err()
        );
    }

    #[test]
    fn every_tls13_suite_the_server_can_select_is_offered() {
        let (record, _, _) = hello();
        for suite in [0x1301_u16, 0x1302, 0x1303] {
            assert!(record.cipher_offered(suite), "{suite:#06x}");
        }
        assert!(!record.cipher_offered(0x00ff));
    }

    #[test]
    fn the_extensions_are_well_formed_and_unique() {
        let (record, _, _) = hello();
        let found = extensions(record.message());
        let mut kinds: Vec<u16> = found.iter().map(|(kind, _)| *kind).collect();
        let before = kinds.len();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(before, kinds.len(), "no duplicate extension type");
        assert!(found.iter().any(|(kind, _)| *kind == 0x0000), "SNI");
        assert!(found.iter().any(|(kind, _)| *kind == 0x0010), "ALPN");
        assert!(found.iter().any(|(kind, _)| *kind == 0x0033), "key_share");
        assert!(found.iter().any(|(kind, _)| *kind == 0x002b), "versions");
        assert!(
            found
                .iter()
                .any(|(kind, _)| *kind == GREASE_PLACEHOLDER || (*kind & 0x0f0f) == 0x0a0a),
            "a GREASE extension is present"
        );
    }

    #[test]
    fn the_offered_shares_include_the_authentication_key_and_hybrid() {
        let (record, keys, _) = hello();
        assert!(record.key_share_group_offered(X25519_GROUP));
        assert!(record.key_share_group_offered(X25519_MLKEM768_GROUP));
        let shares = extensions(record.message());
        let (_, body) = shares
            .iter()
            .find(|(kind, _)| *kind == 0x0033)
            .expect("key_share");
        let mut reader = Reader::new(body);
        let total = usize::from(reader.read_u16().expect("share list length"));
        assert_eq!(total, reader.remaining());
        let mut found = Vec::new();
        while !reader.is_empty() {
            let group = reader.read_u16().expect("group");
            let length = usize::from(reader.read_u16().expect("length"));
            let data = reader.read(length).expect("share").to_vec();
            found.push((group, data));
        }
        assert!(found.iter().any(|(group, data)| {
            *group == X25519_GROUP && data.as_slice() == keys.authentication_public_key()
        }));
        assert!(found.iter().any(|(group, data)| {
            *group == X25519_MLKEM768_GROUP && data.len() == X25519_MLKEM768_SHARE_LEN
        }));
    }

    #[test]
    fn the_alpn_extension_offers_the_profile_list() {
        let (record, _, _) = hello();
        let found = extensions(record.message());
        let (_, body) = found
            .iter()
            .find(|(kind, _)| *kind == 0x0010)
            .expect("ALPN");
        let mut reader = Reader::new(body);
        let total = usize::from(reader.read_u16().expect("ALPN length"));
        let mut list = Reader::new(reader.read(total).expect("ALPN list"));
        let mut protocols = Vec::new();
        while !list.is_empty() {
            let length = usize::from(list.read_u8().expect("protocol length"));
            protocols.push(list.read(length).expect("protocol").to_vec());
        }
        assert_eq!(record.alpn(), protocols.as_slice());
    }

    #[test]
    fn supported_versions_offer_tls13_with_grease() {
        let (record, _, _) = hello();
        let found = extensions(record.message());
        let (_, body) = found
            .iter()
            .find(|(kind, _)| *kind == 0x002b)
            .expect("versions");
        let mut reader = Reader::new(body);
        let length = usize::from(reader.read_u8().expect("versions length"));
        assert_eq!(length, reader.remaining());
        let mut versions = Vec::new();
        while let Some(version) = reader.read_u16() {
            versions.push(version);
        }
        assert!(versions.contains(&0x0304), "TLS 1.3 is offered");
        assert!(
            versions.iter().any(|version| (version & 0x0f0f) == 0x0a0a),
            "a GREASE version is present"
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
        assert!(declared <= MAX_TLS_RECORD);
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
        assert!(!record.matches_session_id(&observed));
        assert!(!record.matches_session_id(&record.session_id()[..31]));
    }

    #[test]
    fn invalid_names_are_refused_before_any_crypto() {
        let keys = ClientKeyAgreement::generate(true).expect("key agreement");
        let long = "a".repeat(254);
        for name in ["", long.as_str()] {
            assert!(matches!(
                build_client_hello(name, profile(), &keys, &SERVER_KEY, plaintext()),
                Err(HelloError::InvalidServerName)
            ));
        }
        assert!(matches!(
            build_client_hello(
                "www.ex\u{e4}mple.com",
                profile(),
                &keys,
                &SERVER_KEY,
                plaintext()
            ),
            Err(HelloError::InvalidServerName)
        ));
    }

    #[test]
    fn the_plain_agreement_rejects_a_non_contributory_share() {
        let (_, keys, _) = hello();
        assert!(keys.tls_shared_secret(X25519_GROUP, &[0_u8; 32]).is_none());
        let secret = keys
            .tls_shared_secret(X25519_GROUP, &[0x33; 32])
            .expect("contributory");
        assert_eq!(32, secret.as_bytes().len());
        assert!(keys.tls_shared_secret(X25519_GROUP, &[0x33; 31]).is_none());
    }

    #[test]
    fn the_hybrid_agreement_needs_the_exact_server_share_shape() {
        let (_, keys, _) = hello();
        assert!(
            keys.tls_shared_secret(X25519_MLKEM768_GROUP, &[0_u8; 1_119])
                .is_none()
        );
        let share = [&[7_u8; MLKEM768_CIPHERTEXT_LEN][..], &[0x33; 32][..]].concat();
        let secret = keys
            .tls_shared_secret(X25519_MLKEM768_GROUP, &share)
            .expect("hybrid agreement");
        assert_eq!(64, secret.as_bytes().len());
        assert!(keys.tls_shared_secret(0x0017, &[0_u8; 65]).is_none());
    }

    #[test]
    fn a_profile_without_hybrid_does_not_generate_one() {
        let profile = Fingerprint::Chrome120.resolve([3; 32]);
        let keys = ClientKeyAgreement::generate(profile.needs_hybrid()).expect("keys");
        let (record, _) =
            build_client_hello(NAME, profile, &keys, &SERVER_KEY, plaintext()).expect("hello");
        assert!(record.key_share_group_offered(X25519_GROUP));
        assert!(!record.key_share_group_offered(X25519_MLKEM768_GROUP));
        assert!(
            keys.tls_shared_secret(X25519_MLKEM768_GROUP, &[7_u8; X25519_MLKEM768_SHARE_LEN])
                .is_none()
        );
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
