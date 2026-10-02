//! The REALITY authenticator: the 32-byte session ID a `ClientHello` carries.
//!
//! Layout and derivation are the exact mirror of the server's checks in
//! `rust-reality` v2.0.1 `protocol/reality/auth.rs:100-125` and
//! `protocol/reality/client_hello.rs:343-369`:
//!
//! ```text
//! auth_key  = HKDF-Extract/Salt = client_random[0..20], IKM = ECDHE share,
//!             HKDF-Expand info = b"REALITY", L = 32
//! plaintext = [0..3] client version | [3] reserved 0 |
//!             [4..8] unix seconds   | [8..16] short ID, right zero padded
//! nonce     = client_random[20..32]
//! aad       = ClientHello message with the session ID zeroed
//! session   = AES-256-GCM(auth_key, nonce, aad, plaintext) = ciphertext || tag
//! ```

use std::fmt;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{AeadInOut, array::Array},
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::protocol::reality::SESSION_ID_LEN;

const AUTH_KEY_INFO: &[u8] = b"REALITY";
const AUTH_PLAINTEXT_LEN: usize = 16;
const GCM_TAG_LEN: usize = 16;
const NONCE_START: usize = 20;

/// The Xray-compatible client version advertised inside the authenticator.
///
/// v2.0.1 reads these three bytes and never acts on them
/// (`RealityAuthResult.client_version` has no consumer), so the value only has
/// to be plausible. It is the Xray-core release whose REALITY and Vision
/// behavior this client reproduces, which is also the honest claim.
pub const CLIENT_VERSION: [u8; 3] = [26, 7, 28];

/// The 16 bytes a client proves knowledge of the REALITY private key with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthPlaintext {
    /// Three-byte client version, advertised but not checked by v2.0.1.
    pub version: [u8; 3],
    /// Client Unix time, in seconds.
    pub time: u32,
    /// REALITY short ID, right zero padded to eight bytes by the server.
    pub short_id: [u8; 8],
}

impl AuthPlaintext {
    /// Encodes the authenticator plaintext.
    ///
    /// Byte 3 is the reserved position the server requires to be zero; it is
    /// not a caller-supplied field, so it cannot be set wrongly.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; AUTH_PLAINTEXT_LEN] {
        let time = self.time.to_be_bytes();
        [
            self.version[0],
            self.version[1],
            self.version[2],
            0,
            time[0],
            time[1],
            time[2],
            time[3],
            self.short_id[0],
            self.short_id[1],
            self.short_id[2],
            self.short_id[3],
            self.short_id[4],
            self.short_id[5],
            self.short_id[6],
            self.short_id[7],
        ]
    }
}

/// A REALITY authenticator could not be built or opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    /// The key derivation or AEAD primitive rejected its input.
    Crypto,
    /// The authenticator did not open, or opened into values the server would
    /// refuse.
    OpenFailed,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto => formatter.write_str("REALITY key derivation failed"),
            Self::OpenFailed => formatter.write_str("REALITY authenticator did not open"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The symmetric key both sides derive from the ECDHE shared secret.
///
/// Holding this key is what authentication proves, so it is zeroized on drop
/// and never rendered.
pub struct AuthKey([u8; 32]);

impl AuthKey {
    /// Derives the key from an X25519 shared secret and the `ClientHello` random.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Crypto`] if HKDF refuses its inputs, which cannot
    /// happen for the fixed sizes used here.
    pub fn derive(shared: &[u8; 32], client_random: &[u8; 32]) -> Result<Self, AuthError> {
        let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..NONCE_START]), shared);
        let mut bytes = Zeroizing::new([0_u8; 32]);
        hkdf.expand(AUTH_KEY_INFO, &mut bytes[..])
            .map_err(|_| AuthError::Crypto)?;
        Ok(Self(*bytes))
    }

    /// The key bytes, for the AEAD and for the certificate binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Builds the session ID for a `ClientHello` whose session ID is zeroed.
    ///
    /// `aad` must be the `ClientHello` handshake message with its 32-byte
    /// session ID set to zero — the same buffer the server reconstructs.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Crypto`] when the AEAD refuses its inputs.
    pub fn seal_session_id(
        &self,
        client_random: &[u8; 32],
        aad: &[u8],
        plaintext: AuthPlaintext,
    ) -> Result<[u8; SESSION_ID_LEN], AuthError> {
        let cipher = Aes256Gcm::new_from_slice(self.as_bytes()).map_err(|_| AuthError::Crypto)?;
        let nonce = Array(session_nonce(client_random));
        let mut body = Zeroizing::new(plaintext.to_bytes());
        let tag = cipher
            .encrypt_inout_detached(&nonce, aad, body.as_mut_slice().into())
            .map_err(|_| AuthError::Crypto)?;
        let mut session_id = [0_u8; SESSION_ID_LEN];
        session_id[..AUTH_PLAINTEXT_LEN].copy_from_slice(&body[..]);
        session_id[AUTH_PLAINTEXT_LEN..].copy_from_slice(&tag);
        Ok(session_id)
    }

    /// Recovers the authenticator plaintext from a session ID.
    ///
    /// Only used by tests and the `doctor` command, which replays a captured
    /// `ClientHello` against a configured key; the live handshake never reads a
    /// session ID.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::OpenFailed`] if the AEAD tag does not verify.
    pub fn open_session_id(
        &self,
        client_random: &[u8; 32],
        aad: &[u8],
        session_id: &[u8],
    ) -> Result<AuthPlaintext, AuthError> {
        let ciphertext: [u8; AUTH_PLAINTEXT_LEN] = session_id
            .get(..AUTH_PLAINTEXT_LEN)
            .ok_or(AuthError::OpenFailed)?
            .try_into()
            .map_err(|_| AuthError::OpenFailed)?;
        let tag: [u8; GCM_TAG_LEN] = session_id
            .get(AUTH_PLAINTEXT_LEN..)
            .ok_or(AuthError::OpenFailed)?
            .try_into()
            .map_err(|_| AuthError::OpenFailed)?;
        let cipher = Aes256Gcm::new_from_slice(self.as_bytes()).map_err(|_| AuthError::Crypto)?;
        let nonce = Array(session_nonce(client_random));
        let mut body = Zeroizing::new(ciphertext);
        cipher
            .decrypt_inout_detached(&nonce, aad, body.as_mut_slice().into(), &Array(tag))
            .map_err(|_| AuthError::OpenFailed)?;
        Ok(AuthPlaintext {
            version: [body[0], body[1], body[2]],
            time: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            short_id: body[8..AUTH_PLAINTEXT_LEN]
                .try_into()
                .map_err(|_| AuthError::OpenFailed)?,
        })
    }
}

impl Drop for AuthKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthKey([REDACTED])")
    }
}

/// The 12-byte AEAD nonce: the tail of the `ClientHello` random.
fn session_nonce(client_random: &[u8; 32]) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&client_random[NONCE_START..]);
    nonce
}

/// Compares the certificate binding without a timing signal.
pub(crate) fn binding_matches(expected: &[u8; 64], observed: &[u8]) -> bool {
    observed.len() == expected.len() && bool::from(expected.ct_eq(observed))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    fn plaintext() -> AuthPlaintext {
        AuthPlaintext {
            version: CLIENT_VERSION,
            time: 1_700_000_000,
            short_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        }
    }

    #[test]
    fn plaintext_layout_matches_the_server_read() {
        let bytes = plaintext().to_bytes();
        assert_eq!(CLIENT_VERSION, bytes[..3]);
        assert_eq!(0, bytes[3], "the reserved byte must be zero");
        assert_eq!(
            1_700_000_000_u32.to_be_bytes(),
            bytes[4..8],
            "time is big-endian unix seconds"
        );
        assert_eq!([1, 2, 3, 4, 5, 6, 7, 8], bytes[8..16]);
    }

    #[test]
    fn auth_key_matches_a_direct_hkdf_computation() {
        let shared = [0x11_u8; 32];
        let key = AuthKey::derive(&shared, &RANDOM).expect("derivation");
        let hkdf = Hkdf::<Sha256>::new(Some(&RANDOM[..20]), &shared);
        let mut expected = [0_u8; 32];
        hkdf.expand(b"REALITY", &mut expected).expect("expand");
        assert_eq!(expected, *key.as_bytes());
    }

    /// The fixture at v2.0.1 `protocol/reality/auth.rs:871-910` and the key its
    /// own test pins at `:643-645` with the comment "must match Xray's Go X25519
    /// and HKDF implementation". Carrying the same vector here makes this client
    /// answer to the same third-party oracle rather than to itself.
    #[test]
    fn auth_key_matches_the_xray_golden_vector() {
        let client = x25519_dalek::StaticSecret::from([0x22; 32]);
        let server = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x11; 32]));
        let shared = client.diffie_hellman(&server);
        let key = AuthKey::derive(shared.as_bytes(), &[0x33; 32]).expect("derivation");
        assert_eq!(
            [
                0x91, 0x3b, 0x3e, 0x74, 0x85, 0xc6, 0x7f, 0xb6, 0x77, 0xb4, 0xcc, 0x65, 0x90, 0x69,
                0x53, 0xc2, 0xf6, 0xa2, 0x3e, 0xb7, 0xb6, 0xe2, 0x4c, 0xf3, 0xd6, 0x90, 0x91, 0x00,
                0x4c, 0xcd, 0x5a, 0x9d,
            ],
            *key.as_bytes()
        );
    }

    #[test]
    fn a_different_client_random_derives_a_different_key() {
        let shared = [0x11_u8; 32];
        let first = AuthKey::derive(&shared, &RANDOM).expect("derivation");
        let second = AuthKey::derive(&shared, &[0x22_u8; 32]).expect("derivation");
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn the_session_id_round_trips_through_the_server_view() {
        let aad = b"a client hello with its session id zeroed";
        let key = AuthKey::derive(&[0x11_u8; 32], &RANDOM).expect("derivation");
        let session_id = key
            .seal_session_id(&RANDOM, aad, plaintext())
            .expect("seal");
        assert_eq!(SESSION_ID_LEN, session_id.len());
        let opened = key
            .open_session_id(&RANDOM, aad, &session_id)
            .expect("open");
        assert_eq!(plaintext(), opened);
    }

    #[test]
    fn the_aad_is_bound_so_a_edited_client_hello_does_not_open() {
        let key = AuthKey::derive(&[0x11_u8; 32], &RANDOM).expect("derivation");
        let session_id = key
            .seal_session_id(&RANDOM, b"original", plaintext())
            .expect("seal");
        assert!(
            key.open_session_id(&RANDOM, b"tampered", &session_id)
                .is_err()
        );
    }

    #[test]
    fn a_wrong_key_does_not_open() {
        let key = AuthKey::derive(&[0x11_u8; 32], &RANDOM).expect("derivation");
        let other = AuthKey::derive(&[0x22_u8; 32], &RANDOM).expect("derivation");
        let session_id = key
            .seal_session_id(&RANDOM, b"aad", plaintext())
            .expect("seal");
        assert!(other.open_session_id(&RANDOM, b"aad", &session_id).is_err());
    }

    #[test]
    fn truncated_session_ids_are_refused() {
        let key = AuthKey::derive(&[0x11_u8; 32], &RANDOM).expect("derivation");
        assert!(key.open_session_id(&RANDOM, b"aad", &[0_u8; 31]).is_err());
    }

    #[test]
    fn diagnostics_never_render_the_key() {
        let key = AuthKey::derive(&[0x11_u8; 32], &RANDOM).expect("derivation");
        assert_eq!("AuthKey([REDACTED])", format!("{key:?}"));
    }
}
