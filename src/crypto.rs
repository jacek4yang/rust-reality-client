//! Key agreement for the REALITY handshake, and the ownership rules around it.
//!
//! One handshake needs the client's X25519 secret **twice**: once against the
//! configured REALITY server public key to derive the authenticator key, and
//! once against the ephemeral share in the server's `ServerHello` for the TLS
//! 1.3 key schedule. Both agreements belong to the same connection, so the
//! wrapper exposes agreement by reference and is dropped when the handshake
//! ends. Reusing it beyond that is prevented by the handshake owning it.

use std::fmt;

use ml_kem::{DecapsulationKey768, Seed, kem::Decapsulate, kem::KeyExport, ml_kem_768::Ciphertext};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::entropy;

/// X25519 shared secret, erased wherever it is dropped.
pub type SharedSecret = Zeroizing<[u8; 32]>;

/// ML-KEM-768 shared secret, erased wherever it is dropped.
pub type MlkemSharedSecret = Zeroizing<[u8; 32]>;

/// Key generation could not obtain entropy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyError;

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secure key generation failed")
    }
}

impl std::error::Error for KeyError {}

/// One connection-scoped X25519 key pair.
pub struct EphemeralX25519 {
    secret: StaticSecret,
    public: [u8; 32],
}

impl EphemeralX25519 {
    /// Generates a key pair from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] when the entropy source is unavailable.
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = [0_u8; 32];
        entropy::fill(&mut bytes).map_err(|_| KeyError)?;
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self { secret, public })
    }

    /// The public share to place in the `ClientHello`.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// Agrees with a peer public key.
    ///
    /// Returns `None` for a non-contributory peer share, which every caller
    /// must treat as a failed handshake: an all-zero secret authenticates
    /// nothing.
    #[must_use]
    pub fn agree(&self, peer: &[u8; 32]) -> Option<SharedSecret> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
        shared
            .was_contributory()
            .then(|| Zeroizing::new(*shared.as_bytes()))
    }
}

impl fmt::Debug for EphemeralX25519 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralX25519")
            .field("public_key", &self.public)
            .finish_non_exhaustive()
    }
}

/// One connection-scoped ML-KEM-768 key pair for the hybrid group.
///
/// Unlike [`EphemeralX25519`] the decapsulation key is legitimately reusable
/// within the handshake, so agreement takes `&self` here too; the type is still
/// dropped with the connection.
pub struct HybridMlkem {
    decapsulation: DecapsulationKey768,
    encapsulation: [u8; MLKEM768_ENCAP_KEY_LEN],
}

/// X25519 public key bytes.
pub const X25519_PUBLIC_LEN: usize = 32;
/// ML-KEM-768 encapsulation key bytes in a hybrid client share.
pub const MLKEM768_ENCAP_KEY_LEN: usize = 1_184;
/// ML-KEM-768 ciphertext bytes at the head of a hybrid server share.
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;

impl HybridMlkem {
    /// Generates a key pair from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] when the entropy source is unavailable.
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = Seed::default();
        entropy::fill(seed.as_mut()).map_err(|_| KeyError)?;
        let decapsulation = DecapsulationKey768::from_seed(seed);
        let exported = decapsulation.encapsulation_key().to_bytes();
        let mut encapsulation = [0_u8; MLKEM768_ENCAP_KEY_LEN];
        encapsulation.copy_from_slice(exported.as_slice());
        Ok(Self {
            decapsulation,
            encapsulation,
        })
    }

    /// The encapsulation key to place in the hybrid client share.
    #[must_use]
    pub const fn encapsulation_key(&self) -> &[u8; MLKEM768_ENCAP_KEY_LEN] {
        &self.encapsulation
    }

    /// Decapsulates the server's hybrid share.
    ///
    /// # Errors
    ///
    /// Returns `None` when the input is not exactly one ML-KEM-768 ciphertext.
    #[must_use]
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Option<MlkemSharedSecret> {
        let array = Ciphertext::try_from(ciphertext).ok()?;
        let shared = self.decapsulation.decapsulate(&array);
        let mut output = Zeroizing::new([0_u8; 32]);
        output.copy_from_slice(shared.as_slice());
        Some(output)
    }
}

impl fmt::Debug for HybridMlkem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HybridMlkem([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_agreement_is_symmetric_and_contributory() {
        let client = EphemeralX25519::generate().expect("entropy");
        let server = EphemeralX25519::generate().expect("entropy");
        let from_client = client.agree(server.public_key()).expect("contributory");
        let from_server = server.agree(client.public_key()).expect("contributory");
        assert_eq!(*from_client, *from_server);
    }

    #[test]
    fn an_all_zero_peer_share_is_rejected() {
        let client = EphemeralX25519::generate().expect("entropy");
        assert!(client.agree(&[0_u8; 32]).is_none());
    }

    #[test]
    fn hybrid_share_round_trips_at_the_wire_sizes() {
        let key = HybridMlkem::generate().expect("entropy");
        assert_eq!(
            MLKEM768_ENCAP_KEY_LEN,
            key.encapsulation_key().len(),
            "the client share must be the exact length the server validates"
        );
        let server = HybridMlkem::generate().expect("entropy");
        assert_ne!(key.encapsulation_key(), server.encapsulation_key());
        assert_eq!(
            key.decapsulate(&[7_u8; MLKEM768_CIPHERTEXT_LEN])
                .map(|_| ()),
            Some(())
        );
        assert!(
            key.decapsulate(&[7_u8; MLKEM768_CIPHERTEXT_LEN - 1])
                .is_none()
        );
    }

    #[test]
    fn generated_keys_are_distinct() {
        let first = EphemeralX25519::generate().expect("entropy");
        let second = EphemeralX25519::generate().expect("entropy");
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn diagnostics_never_render_secret_material() {
        let key = EphemeralX25519::generate().expect("entropy");
        let rendered = format!("{key:?}");
        assert!(rendered.contains("public_key"), "{rendered}");
        let rendered = format!("{:?}", HybridMlkem::generate().expect("entropy"));
        assert!(rendered.contains("REDACTED"), "{rendered}");
    }
}
