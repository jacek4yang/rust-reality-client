//! TLS 1.3 record layer, key schedule and transcript hashing.
//!
//! RFC 8446 §7 (key schedule) and §5.2 (record protection), constrained to the
//! no-PSK path that REALITY uses. Byte-level decisions match rust-reality
//! v2.0.1 `src/protocol/reality/tls13/{keys,record}.rs`, which is the server
//! this client interoperates with; the RFC 8448 vectors in the tests pin the
//! derivation independently of that source.

use aes_gcm::{Aes128Gcm, Aes256Gcm, aead::AeadInOut};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

/// TLS 1.3 cipher suites this client can offer and negotiate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherSuite {
    /// `TLS_AES_128_GCM_SHA256`.
    Aes128GcmSha256,
    /// `TLS_AES_256_GCM_SHA384`.
    Aes256GcmSha384,
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// Converts an IANA wire identifier into a supported suite.
    #[must_use]
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    /// IANA wire identifier.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    /// Transcript and HKDF hash for this suite.
    #[must_use]
    pub const fn hash(self) -> HashAlgorithm {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => HashAlgorithm::Sha256,
            Self::Aes256GcmSha384 => HashAlgorithm::Sha384,
        }
    }

    /// AEAD key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

/// Hash algorithms used by the supported suites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
}

const MAX_HASH_BYTES: usize = 48;

impl HashAlgorithm {
    /// Digest output length.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn digest(self, messages: &[u8]) -> TranscriptHash {
        let mut bytes = [0_u8; MAX_HASH_BYTES];
        match self {
            Self::Sha256 => bytes[..32].copy_from_slice(&Sha256::digest(messages)),
            Self::Sha384 => bytes.copy_from_slice(&Sha384::digest(messages)),
        }
        TranscriptHash {
            algorithm: self,
            bytes,
        }
    }

    fn extract(self, salt: &[u8], input: &[u8]) -> [u8; MAX_HASH_BYTES] {
        let mut bytes = [0_u8; MAX_HASH_BYTES];
        match self {
            Self::Sha256 => {
                let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), input);
                bytes[..32].copy_from_slice(prk.as_slice());
            }
            Self::Sha384 => {
                let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), input);
                bytes.copy_from_slice(prk.as_slice());
            }
        }
        bytes
    }

    fn expand_label(
        self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> Result<(), KeyError> {
        let info = hkdf_label(label, context, output.len())?;
        match self {
            Self::Sha256 => Hkdf::<Sha256>::from_prk(secret)
                .map_err(|_| KeyError::Hkdf)?
                .expand(&info, output)
                .map_err(|_| KeyError::Hkdf),
            Self::Sha384 => Hkdf::<Sha384>::from_prk(secret)
                .map_err(|_| KeyError::Hkdf)?
                .expand(&info, output)
                .map_err(|_| KeyError::Hkdf),
        }
    }

    fn derive_secret(
        self,
        secret: &[u8],
        label: &[u8],
        transcript_hash: &TranscriptHash,
    ) -> Result<[u8; MAX_HASH_BYTES], KeyError> {
        if transcript_hash.algorithm != self {
            return Err(KeyError::HashMismatch);
        }
        let mut output = [0_u8; MAX_HASH_BYTES];
        self.expand_label(
            secret,
            label,
            transcript_hash.as_bytes(),
            &mut output[..self.output_len()],
        )?;
        Ok(output)
    }

    fn hmac(self, key: &[u8], input: &[u8]) -> Result<[u8; MAX_HASH_BYTES], KeyError> {
        let mut output = [0_u8; MAX_HASH_BYTES];
        match self {
            Self::Sha256 => {
                let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
                    .map_err(|_| KeyError::KeyLength)?;
                mac.update(input);
                output[..32].copy_from_slice(mac.finalize().into_bytes().as_slice());
            }
            Self::Sha384 => {
                let mut mac = <Hmac<Sha384> as hmac::KeyInit>::new_from_slice(key)
                    .map_err(|_| KeyError::KeyLength)?;
                mac.update(input);
                output.copy_from_slice(mac.finalize().into_bytes().as_slice());
            }
        }
        Ok(output)
    }
}

// `HkdfLabel.length` is a uint16; truncating it to one byte derives a wholly
// different key stream while still looking like valid HKDF output.
fn hkdf_label(label: &[u8], context: &[u8], output_len: usize) -> Result<Vec<u8>, KeyError> {
    const PREFIX: &[u8] = b"tls13 ";
    let full_len = u8::try_from(PREFIX.len() + label.len()).map_err(|_| KeyError::Label)?;
    let context_len = u8::try_from(context.len()).map_err(|_| KeyError::Label)?;
    let output_len = u16::try_from(output_len).map_err(|_| KeyError::Label)?;
    let mut full = Vec::with_capacity(4 + PREFIX.len() + label.len() + context.len());
    full.extend_from_slice(&output_len.to_be_bytes());
    full.push(full_len);
    full.extend_from_slice(PREFIX);
    full.extend_from_slice(label);
    full.push(context_len);
    full.extend_from_slice(context);
    Ok(full)
}

/// A transcript digest tagged with the algorithm that produced it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TranscriptHash {
    algorithm: HashAlgorithm,
    bytes: [u8; MAX_HASH_BYTES],
}

impl TranscriptHash {
    /// Imports a digest only when it has the exact length for `algorithm`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Length`] for a truncated or oversized digest.
    pub fn from_bytes(algorithm: HashAlgorithm, input: &[u8]) -> Result<Self, KeyError> {
        if input.len() != algorithm.output_len() {
            return Err(KeyError::Length);
        }
        let mut bytes = [0_u8; MAX_HASH_BYTES];
        bytes[..input.len()].copy_from_slice(input);
        Ok(Self { algorithm, bytes })
    }

    /// Digest algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Exactly the initialized digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.algorithm.output_len()]
    }
}

impl std::fmt::Debug for TranscriptHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TranscriptHash")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Incremental transcript hash.
#[derive(Clone)]
pub struct TranscriptHasher {
    algorithm: HashAlgorithm,
    state: State,
}

#[derive(Clone)]
enum State {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl TranscriptHasher {
    /// Starts an empty transcript for `algorithm`.
    #[must_use]
    pub fn new(algorithm: HashAlgorithm) -> Self {
        let state = match algorithm {
            HashAlgorithm::Sha256 => State::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => State::Sha384(Sha384::new()),
        };
        Self { algorithm, state }
    }

    /// Appends handshake message bytes.
    pub fn update(&mut self, message: &[u8]) {
        match &mut self.state {
            State::Sha256(state) => state.update(message),
            State::Sha384(state) => state.update(message),
        }
    }

    /// Finalizes a clone of the running state.
    #[must_use]
    pub fn snapshot(&self) -> TranscriptHash {
        let mut bytes = [0_u8; MAX_HASH_BYTES];
        match &self.state {
            State::Sha256(state) => bytes[..32].copy_from_slice(&state.clone().finalize()),
            State::Sha384(state) => bytes.copy_from_slice(&state.clone().finalize()),
        }
        TranscriptHash {
            algorithm: self.algorithm,
            bytes,
        }
    }
}

impl std::fmt::Debug for TranscriptHasher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TranscriptHasher")
            .field("algorithm", &self.algorithm)
            // The running state commits handshake bytes; it is never printable.
            .field("state", &"[REDACTED]")
            .finish()
    }
}

/// One direction's AEAD key and static IV.
pub struct TrafficKeys {
    key: [u8; 32],
    key_len: usize,
    iv: [u8; 12],
}

impl TrafficKeys {
    /// AEAD key bytes.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// Static AEAD IV; the per-record nonce is this value XOR the sequence
    /// number, big-endian in the trailing four bytes.
    #[must_use]
    pub const fn iv(&self) -> &[u8; 12] {
        &self.iv
    }
}

impl Drop for TrafficKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl std::fmt::Debug for TrafficKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrafficKeys")
            .field("key_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Traffic secret for one handshake stage and direction.
pub struct TrafficSecret {
    algorithm: HashAlgorithm,
    bytes: [u8; MAX_HASH_BYTES],
}

impl TrafficSecret {
    /// Secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.algorithm.output_len()]
    }
}

impl Drop for TrafficSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for TrafficSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrafficSecret")
            .field("secret", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Key-schedule failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyError {
    /// HKDF input or output length was invalid.
    Length,
    /// A secret did not belong to the negotiated hash.
    HashMismatch,
    /// A key of the wrong length was supplied to a primitive.
    KeyLength,
    /// HKDF or HMAC rejected its inputs.
    Hkdf,
    /// The HKDF label could not be encoded.
    Label,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TLS 1.3 key schedule failure")
    }
}

impl std::error::Error for KeyError {}

impl From<KeyError> for crate::error::Error {
    fn from(_: KeyError) -> Self {
        // Every variant is a failure of our own derivation against the
        // negotiated transcript, not a defect the peer can cause.
        Self::Handshake(crate::error::HandshakeError::Verification)
    }
}

/// No-PSK TLS 1.3 key schedule.
pub struct KeySchedule {
    suite: CipherSuite,
    master: [u8; MAX_HASH_BYTES],
    client_handshake: TrafficSecret,
    server_handshake: TrafficSecret,
}

impl KeySchedule {
    /// Derives the schedule from the ECDHE secret and the transcript through
    /// `ServerHello`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] for an unusable shared secret or a mismatched
    /// transcript digest.
    pub fn new(
        suite: CipherSuite,
        shared_secret: &[u8],
        through_server_hello: &TranscriptHash,
    ) -> Result<Self, KeyError> {
        if shared_secret.is_empty() || shared_secret.len() > 128 {
            return Err(KeyError::Length);
        }
        let hash = suite.hash();
        if through_server_hello.algorithm != hash {
            return Err(KeyError::HashMismatch);
        }
        let zeros = [0_u8; MAX_HASH_BYTES];
        let zero = &zeros[..hash.output_len()];
        let early = hash.extract(zero, zero);
        let empty = hash.digest(&[]);
        let derived_early = hash.derive_secret(&early, b"derived", &empty)?;
        let handshake = hash.extract(&derived_early[..hash.output_len()], shared_secret);
        let client_handshake = TrafficSecret {
            algorithm: hash,
            bytes: hash.derive_secret(&handshake, b"c hs traffic", through_server_hello)?,
        };
        let server_handshake = TrafficSecret {
            algorithm: hash,
            bytes: hash.derive_secret(&handshake, b"s hs traffic", through_server_hello)?,
        };
        let derived_handshake = hash.derive_secret(&handshake, b"derived", &empty)?;
        let master = hash.extract(&derived_handshake[..hash.output_len()], zero);
        Ok(Self {
            suite,
            master,
            client_handshake,
            server_handshake,
        })
    }

    /// Negotiated suite.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Client handshake traffic secret.
    #[must_use]
    pub const fn client_handshake_secret(&self) -> &TrafficSecret {
        &self.client_handshake
    }

    /// Server handshake traffic secret.
    #[must_use]
    pub const fn server_handshake_secret(&self) -> &TrafficSecret {
        &self.server_handshake
    }

    /// Derives one direction's AEAD key and IV from a traffic secret.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::HashMismatch`] if the secret came from another hash.
    pub fn traffic_keys(&self, secret: &TrafficSecret) -> Result<TrafficKeys, KeyError> {
        let hash = self.suite.hash();
        if secret.algorithm != hash {
            return Err(KeyError::HashMismatch);
        }
        let key_len = self.suite.key_len();
        let mut keys = TrafficKeys {
            key: [0_u8; 32],
            key_len,
            iv: [0_u8; 12],
        };
        hash.expand_label(secret.as_bytes(), b"key", &[], &mut keys.key[..key_len])?;
        hash.expand_label(secret.as_bytes(), b"iv", &[], &mut keys.iv)?;
        Ok(keys)
    }

    /// Computes TLS `Finished` verify data.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::HashMismatch`] for a foreign secret or digest.
    pub fn finished_verify_data(
        &self,
        secret: &TrafficSecret,
        transcript_hash: &TranscriptHash,
    ) -> Result<[u8; MAX_HASH_BYTES], KeyError> {
        let hash = self.suite.hash();
        if secret.algorithm != hash || transcript_hash.algorithm != hash {
            return Err(KeyError::HashMismatch);
        }
        let mut finished_key = [0_u8; MAX_HASH_BYTES];
        hash.expand_label(
            secret.as_bytes(),
            b"finished",
            &[],
            &mut finished_key[..hash.output_len()],
        )?;
        hash.hmac(
            &finished_key[..hash.output_len()],
            transcript_hash.as_bytes(),
        )
    }

    /// Derives application traffic secrets from the transcript through server
    /// `Finished`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::HashMismatch`] for a foreign digest.
    pub fn application_secrets(
        &self,
        through_server_finished: &TranscriptHash,
    ) -> Result<ApplicationSecrets, KeyError> {
        let hash = self.suite.hash();
        if through_server_finished.algorithm != hash {
            return Err(KeyError::HashMismatch);
        }
        Ok(ApplicationSecrets {
            client: TrafficSecret {
                algorithm: hash,
                bytes: hash.derive_secret(
                    &self.master,
                    b"c ap traffic",
                    through_server_finished,
                )?,
            },
            server: TrafficSecret {
                algorithm: hash,
                bytes: hash.derive_secret(
                    &self.master,
                    b"s ap traffic",
                    through_server_finished,
                )?,
            },
        })
    }
}

impl std::fmt::Debug for KeySchedule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeySchedule")
            .field("suite", &self.suite)
            .field("secrets", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Post-handshake traffic secrets, one per direction.
pub struct ApplicationSecrets {
    client: TrafficSecret,
    server: TrafficSecret,
}

impl ApplicationSecrets {
    /// Secret the client writes with.
    #[must_use]
    pub const fn client(&self) -> &TrafficSecret {
        &self.client
    }

    /// Secret the client reads with.
    #[must_use]
    pub const fn server(&self) -> &TrafficSecret {
        &self.server
    }
}

impl std::fmt::Debug for ApplicationSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApplicationSecrets")
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

/// Authenticated inner content type of a TLS 1.3 record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentType {
    /// Middlebox-compatibility change cipher spec.
    ChangeCipherSpec,
    /// TLS alert.
    Alert,
    /// Handshake message.
    Handshake,
    /// Application data.
    ApplicationData,
}

impl ContentType {
    /// The one-byte value this content type carries, either in a plaintext
    /// record header or as a TLS 1.3 record's inner type.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
        }
    }

    #[must_use]
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// Record-layer failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    /// Framing or length was outside the fixed TLS bounds.
    InvalidLength,
    /// The outer header was not an encrypted record.
    InvalidHeader,
    /// The AEAD tag did not authenticate.
    AuthenticationFailed,
    /// The decrypted inner content type is not valid in TLS 1.3.
    InvalidContentType,
    /// The plaintext was not complete.
    Incomplete,
    /// The traffic key reached its per-key record ceiling.
    KeyExhausted,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TLS 1.3 record processing failed")
    }
}

impl std::error::Error for RecordError {}

impl From<RecordError> for crate::error::Error {
    fn from(error: RecordError) -> Self {
        // Sealing failures are ours; opening failures are mapped by the caller,
        // which alone knows whether a bad tag means a foreign server or a
        // corrupt stream.
        Self::Handshake(crate::error::HandshakeError::Protocol(match error {
            RecordError::KeyExhausted => "record key exhausted",
            _ => "record layer",
        }))
    }
}

/// Maximum plaintext bytes in one record.
pub const MAX_PLAINTEXT_LEN: usize = 1 << 14;

/// Size of a TLS record header: type, legacy version, encrypted-body length.
pub const RECORD_HEADER_LEN: usize = 5;

const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const OUTER_APPLICATION_DATA: u8 = 23;
const MAX_INNER_PLAINTEXT_LEN: usize = MAX_PLAINTEXT_LEN + 1;
const MIN_ENCRYPTED_BODY_LEN: usize = TAG_LEN + 1;
const MAX_ENCRYPTED_BODY_LEN: usize = MAX_INNER_PLAINTEXT_LEN + TAG_LEN;
/// Wire size of the largest record TLS 1.3 allows. A reader that bounds its
/// buffer by this value can always hold one whole record.
pub const MAX_RECORD_WIRE_LEN: usize = RECORD_HEADER_LEN + MAX_ENCRYPTED_BODY_LEN;
const AES_GCM_RECORD_LIMIT: u64 = 1 << 24;

enum RecordCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl RecordCipher {
    fn new(suite: CipherSuite, key: &[u8]) -> Result<Self, RecordError> {
        use aes_gcm::aead::KeyInit;
        Ok(match suite {
            CipherSuite::Aes128GcmSha256 => {
                let cipher =
                    Aes128Gcm::new_from_slice(key).map_err(|_| RecordError::InvalidLength)?;
                Self::Aes128Gcm(Box::new(cipher))
            }
            CipherSuite::Aes256GcmSha384 => {
                let cipher =
                    Aes256Gcm::new_from_slice(key).map_err(|_| RecordError::InvalidLength)?;
                Self::Aes256Gcm(Box::new(cipher))
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| RecordError::InvalidLength)?;
                Self::ChaCha20Poly1305(Box::new(cipher))
            }
        })
    }

    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; TAG_LEN], RecordError> {
        use aes_gcm::aead::array::Array;
        // Each arm copies its own tag type into the fixed array; a `Vec` bridge
        // would allocate on every record.
        let mut output = [0_u8; TAG_LEN];
        match self {
            Self::Aes128Gcm(cipher) => {
                let tag = cipher
                    .encrypt_inout_detached(&Array(*nonce), aad, body.into())
                    .map_err(|_| RecordError::AuthenticationFailed)?;
                output.copy_from_slice(&tag);
            }
            Self::Aes256Gcm(cipher) => {
                let tag = cipher
                    .encrypt_inout_detached(&Array(*nonce), aad, body.into())
                    .map_err(|_| RecordError::AuthenticationFailed)?;
                output.copy_from_slice(&tag);
            }
            Self::ChaCha20Poly1305(cipher) => {
                let tag = cipher
                    .encrypt_inout_detached(&Array(*nonce), aad, body.into())
                    .map_err(|_| RecordError::AuthenticationFailed)?;
                output.copy_from_slice(&tag);
            }
        }
        Ok(output)
    }

    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<(), RecordError> {
        use aes_gcm::aead::array::Array;
        if body.len() < TAG_LEN {
            return Err(RecordError::InvalidLength);
        }
        let (ciphertext, tag) = body.split_at_mut(body.len() - TAG_LEN);
        let tag = *tag
            .first_chunk::<TAG_LEN>()
            .ok_or(RecordError::InvalidLength)?;
        match self {
            Self::Aes128Gcm(cipher) => {
                cipher.decrypt_inout_detached(&Array(*nonce), aad, ciphertext.into(), &Array(tag))
            }
            Self::Aes256Gcm(cipher) => {
                cipher.decrypt_inout_detached(&Array(*nonce), aad, ciphertext.into(), &Array(tag))
            }
            Self::ChaCha20Poly1305(cipher) => {
                cipher.decrypt_inout_detached(&Array(*nonce), aad, ciphertext.into(), &Array(tag))
            }
        }
        .map_err(|_| RecordError::AuthenticationFailed)
    }
}

/// One direction's TLS 1.3 record protection state.
///
/// Nonce-safety invariant: this type is the only nonce source (`iv XOR
/// sequence`), it is not `Clone`, and the sequence advances exactly once per
/// sealed or opened record.
pub struct RecordLayer {
    suite: CipherSuite,
    cipher: RecordCipher,
    iv: [u8; NONCE_LEN],
    sequence: u64,
}

impl RecordLayer {
    /// Consumes one direction's traffic keys.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::InvalidLength`] if the key length does not match
    /// the suite.
    pub fn new(suite: CipherSuite, keys: &TrafficKeys) -> Result<Self, RecordError> {
        if keys.key().len() != suite.key_len() {
            return Err(RecordError::InvalidLength);
        }
        let cipher = RecordCipher::new(suite, keys.key())?;
        Ok(Self {
            suite,
            cipher,
            iv: *keys.iv(),
            sequence: 0,
        })
    }

    /// Records sealed or opened so far.
    #[must_use]
    pub const fn records_used(&self) -> u64 {
        self.sequence
    }

    /// Wire size of one sealed record carrying `plaintext_len` payload bytes.
    #[must_use]
    pub const fn record_wire_len(plaintext_len: usize) -> usize {
        RECORD_HEADER_LEN + plaintext_len + 1 + TAG_LEN
    }

    /// Largest payload that still fits one record.
    #[must_use]
    pub const fn max_payload_len(&self) -> usize {
        MAX_PLAINTEXT_LEN
    }

    /// Seals one record, appending the wire bytes to `output`.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] for an oversized payload or a failed seal.
    pub fn seal(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        self.seal_with_padding(content_type, plaintext, 0, output)
    }

    /// Test-only view of the padded form, which only a server ever writes.
    #[cfg(test)]
    pub(crate) fn seal_padded(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        padding_len: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        self.seal_with_padding(content_type, plaintext, padding_len, output)
    }

    /// Seals one record whose payload is followed by `padding_len` zero bytes.
    ///
    /// A server uses this to re-seal its freshly generated handshake messages to
    /// the wire length the cover target was observed using
    /// (`tls13/handshake.rs:590-605`). The padding goes *after* the inner content
    /// type, which is what lets a reader find that type as the last non-zero byte
    /// of the decrypted region (`record.rs:643-655`). This client reads such
    /// records but never writes them.
    fn seal_with_padding(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        padding_len: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        self.ensure_available()?;
        let inner_len = plaintext
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(padding_len))
            .filter(|length| *length <= MAX_INNER_PLAINTEXT_LEN)
            .ok_or(RecordError::InvalidLength)?;
        let ciphertext_len = inner_len
            .checked_add(TAG_LEN)
            .and_then(|length| u16::try_from(length).ok())
            .ok_or(RecordError::InvalidLength)?;
        let header = [
            OUTER_APPLICATION_DATA,
            3,
            3,
            ciphertext_len.to_be_bytes()[0],
            ciphertext_len.to_be_bytes()[1],
        ];
        let start = output.len();
        output.reserve_exact(usize::from(ciphertext_len) + RECORD_HEADER_LEN);
        output.extend_from_slice(&header);
        output.extend_from_slice(plaintext);
        output.push(content_type.wire_value());
        output.resize(start + RECORD_HEADER_LEN + inner_len, 0);
        let body = &mut output[start + RECORD_HEADER_LEN..];
        let nonce = self.nonce();
        let tag = self.cipher.seal(&nonce, &header, body)?;
        output.extend_from_slice(&tag);
        self.advance()
    }

    /// Byte length of the encrypted body of a record carrying `plaintext_len`.
    #[must_use]
    pub const fn encrypted_body_len(plaintext_len: usize) -> usize {
        plaintext_len + 1 + TAG_LEN
    }

    /// Total wire length of the record that `header` declares, or `None` while
    /// fewer than [`RECORD_HEADER_LEN`] bytes have arrived.
    ///
    /// A stream reader needs this before it can wait for the rest of a record,
    /// and it must not invent its own bounds: a header is accepted here exactly
    /// when [`Self::open`] would accept it. That is what lets a tunnel report a
    /// desynchronised peer at the header, instead of waiting forever for bytes
    /// that will never complete or mistaking the defect for a bad tag.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::InvalidHeader`] for an outer type or version that
    /// carries no encrypted record, and [`RecordError::InvalidLength`] for a
    /// declared body outside the bounds one record can hold.
    pub fn record_len(header: &[u8]) -> Result<Option<usize>, RecordError> {
        if header.len() < RECORD_HEADER_LEN {
            return Ok(None);
        }
        if header[0] != OUTER_APPLICATION_DATA || header[1..3] != [3, 3] {
            return Err(RecordError::InvalidHeader);
        }
        let body = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if !(MIN_ENCRYPTED_BODY_LEN..=MAX_ENCRYPTED_BODY_LEN).contains(&body) {
            return Err(RecordError::InvalidLength);
        }
        Ok(Some(RECORD_HEADER_LEN + body))
    }

    /// Opens one complete record in place, returning its plaintext.
    ///
    /// The returned slice borrows `record`. A failed open leaves `record`
    /// unspecified; callers must not read it afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Incomplete`] when `record` is shorter than its
    /// declared length, and the corresponding variant for every other defect.
    pub fn open<'record>(
        &mut self,
        record: &'record mut [u8],
    ) -> Result<(ContentType, &'record [u8]), RecordError> {
        self.ensure_available()?;
        if record.len() < RECORD_HEADER_LEN {
            return Err(RecordError::Incomplete);
        }
        let header: [u8; RECORD_HEADER_LEN] = record[..RECORD_HEADER_LEN]
            .try_into()
            .map_err(|_| RecordError::InvalidLength)?;
        if header[0] != OUTER_APPLICATION_DATA || header[1..3] != [3, 3] {
            return Err(RecordError::InvalidHeader);
        }
        let ciphertext_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if !(MIN_ENCRYPTED_BODY_LEN..=MAX_ENCRYPTED_BODY_LEN).contains(&ciphertext_len) {
            return Err(RecordError::InvalidLength);
        }
        let expected = RECORD_HEADER_LEN + ciphertext_len;
        if record.len() < expected {
            return Err(RecordError::Incomplete);
        }
        let body = &mut record[RECORD_HEADER_LEN..expected];
        let nonce = self.nonce();
        self.cipher.open(&nonce, &header, body)?;
        self.advance()?;
        let encrypted_len = ciphertext_len - TAG_LEN;
        let plaintext_region = &body[..encrypted_len];
        let content_type_offset = plaintext_region
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or(RecordError::InvalidContentType)?;
        let content_type = ContentType::from_wire(plaintext_region[content_type_offset])
            .ok_or(RecordError::InvalidContentType)?;
        Ok((content_type, &plaintext_region[..content_type_offset]))
    }

    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = self.iv;
        for (nonce_byte, sequence_byte) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *nonce_byte ^= sequence_byte;
        }
        nonce
    }

    fn ensure_available(&self) -> Result<(), RecordError> {
        match self.suite {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => {
                if self.sequence < AES_GCM_RECORD_LIMIT {
                    Ok(())
                } else {
                    Err(RecordError::KeyExhausted)
                }
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                if self.sequence < u64::MAX {
                    Ok(())
                } else {
                    Err(RecordError::KeyExhausted)
                }
            }
        }
    }

    fn advance(&mut self) -> Result<(), RecordError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(RecordError::KeyExhausted)?;
        Ok(())
    }
}

impl std::fmt::Debug for RecordLayer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordLayer")
            .field("suite", &self.suite)
            .field("sequence", &self.sequence)
            .field("key_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApplicationSecrets, CipherSuite, ContentType, HashAlgorithm, KeySchedule,
        MAX_PLAINTEXT_LEN, RECORD_HEADER_LEN, RecordLayer, TranscriptHash, TranscriptHasher,
    };

    /// Decodes lowercase hex, ignoring the line continuations used in long
    /// vectors. Panics loudly: a malformed vector must never read as a
    /// protocol mismatch.
    fn hex(encoded: &str) -> Vec<u8> {
        let digits: Vec<u8> = encoded.bytes().filter(u8::is_ascii_hexdigit).collect();
        assert_eq!(digits.len() % 2, 0, "test hex must be whole bytes");
        assert!(
            !encoded
                .bytes()
                .any(|byte| byte.is_ascii_uppercase() && byte.is_ascii_hexdigit()),
            "test hex must be lowercase, so a stray digit cannot silently change a vector"
        );
        let nibble = |byte: u8| -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!("already filtered to lowercase hex digits"),
            }
        };
        digits
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn digest(algorithm: HashAlgorithm, encoded: &str) -> TranscriptHash {
        TranscriptHash::from_bytes(algorithm, &hex(encoded))
            .expect("test transcript has exact hash length")
    }

    fn traffic_secret(schedule: &KeySchedule, server: bool) -> &super::TrafficSecret {
        if server {
            schedule.server_handshake_secret()
        } else {
            schedule.client_handshake_secret()
        }
    }

    fn rfc8448() -> KeySchedule {
        let shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let transcript = TranscriptHash::from_bytes(
            HashAlgorithm::Sha256,
            &hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
        )
        .expect("RFC 8448 digest must import");
        KeySchedule::new(CipherSuite::Aes128GcmSha256, &shared, &transcript)
            .expect("RFC 8448 schedule must derive")
    }

    /// RFC 8448 §3 client/server handshake traffic secrets and the master
    /// secret, as pinned by the v2.0.1 server's own vector test.
    #[test]
    fn rfc8448_traffic_secrets_match_byte_for_byte() {
        let schedule = rfc8448();
        assert_eq!(
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"),
            schedule.client_handshake_secret().as_bytes()
        );
        assert_eq!(
            hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
            schedule.server_handshake_secret().as_bytes()
        );
    }

    #[test]
    fn rfc8448_handshake_traffic_keys_match_byte_for_byte() {
        let schedule = rfc8448();
        let client = schedule
            .traffic_keys(traffic_secret(&schedule, false))
            .expect("client keys");
        let server = schedule
            .traffic_keys(traffic_secret(&schedule, true))
            .expect("server keys");
        assert_eq!(hex("dbfaa693d1762c5b666af5d950258d01"), &client.key()[..16]);
        assert_eq!(hex("5bd3c71b836e0b76bb73265f"), &client.iv()[..]);
        assert_eq!(hex("3fce516009c21727d0f2e4e86ee403bc"), &server.key()[..16]);
        assert_eq!(hex("5d313eb2671276ee13000b30"), &server.iv()[..]);
        assert_eq!(16, client.key().len());
    }

    /// The Finished MAC is what authenticates the whole handshake, so its
    /// transcript input is the digest through *server* Finished, not through
    /// `ServerHello`.
    #[test]
    fn rfc8448_client_finished_verify_data_matches() {
        let schedule = rfc8448();
        let through_server_finished = digest(
            HashAlgorithm::Sha256,
            "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13",
        );
        let verify = schedule
            .finished_verify_data(traffic_secret(&schedule, false), &through_server_finished)
            .expect("verify data");
        assert_eq!(
            &verify[..32],
            hex("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61").as_slice()
        );
    }

    /// Application traffic keys come from the master secret and the same
    /// transcript; a schedule that only reaches the handshake stage cannot
    /// carry a real session.
    #[test]
    fn rfc8448_application_keys_match_byte_for_byte() {
        let schedule = rfc8448();
        let through_server_finished = digest(
            HashAlgorithm::Sha256,
            "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13",
        );
        let secrets = schedule
            .application_secrets(&through_server_finished)
            .expect("application secrets");
        let keys = schedule
            .traffic_keys(secrets.server())
            .expect("server keys");
        assert_eq!(hex("9f02283b6c9c07efc26bb9f2ac92e356"), &keys.key()[..16]);
        assert_eq!(hex("cf782b88dd83549aadf1e984"), &keys.iv()[..]);
    }

    #[test]
    fn rfc8448_client_finished_record_is_byte_exact() {
        let schedule = rfc8448();
        let keys = schedule
            .traffic_keys(traffic_secret(&schedule, false))
            .expect("keys");
        let mut records = RecordLayer::new(CipherSuite::Aes128GcmSha256, &keys)
            .expect("record state must initialize");
        let plaintext =
            hex("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");
        let mut wire = Vec::new();
        records
            .seal(ContentType::Handshake, &plaintext, &mut wire)
            .expect("finished must seal");
        assert_eq!(
            wire,
            hex(
                "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44\
                 d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546"
            )
        );
    }

    #[test]
    fn all_suites_round_trip_with_padding_and_sequence() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let transcript = suite.hash().digest(b"ClientHelloServerHello");
            let schedule = KeySchedule::new(suite, &[0x42; 32], &transcript).expect("schedule");
            let keys = schedule
                .traffic_keys(schedule.server_handshake_secret())
                .expect("keys");
            let (mut writer, mut reader) = (
                RecordLayer::new(suite, &keys).expect("writer"),
                RecordLayer::new(suite, &keys).expect("reader"),
            );
            for plaintext in [b"".as_slice(), b"interactive", &[0x42_u8; 16_384]] {
                let mut wire = Vec::new();
                writer
                    .seal(ContentType::ApplicationData, plaintext, &mut wire)
                    .expect("seal");
                let mut copy = wire.clone();
                let opened = reader.open(&mut copy).expect("open");
                assert_eq!(opened.0, ContentType::ApplicationData);
                assert_eq!(opened.1, plaintext);
            }
            assert_eq!(writer.records_used(), 3);
        }
    }

    #[test]
    fn tampering_and_reordering_are_rejected() {
        let transcript = HashAlgorithm::Sha256.digest(b"t");
        let schedule = KeySchedule::new(CipherSuite::Aes128GcmSha256, &[1; 32], &transcript)
            .expect("schedule");
        let keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .expect("keys");
        let (mut writer, mut reader) = (
            RecordLayer::new(CipherSuite::Aes128GcmSha256, &keys).expect("writer"),
            RecordLayer::new(CipherSuite::Aes128GcmSha256, &keys).expect("reader"),
        );
        let mut first = Vec::new();
        writer
            .seal(ContentType::Handshake, b"first", &mut first)
            .expect("seal");
        let mut second = Vec::new();
        writer
            .seal(ContentType::Handshake, b"second", &mut second)
            .expect("seal");
        let mut out_of_order = second.clone();
        assert!(
            reader
                .open(&mut out_of_order)
                .is_err_and(|error| { error == super::RecordError::AuthenticationFailed })
        );
        let mut tampered = first.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(reader.open(&mut tampered).is_err());
        let mut truncated = first.clone();
        truncated.pop();
        assert!(
            reader
                .open(&mut truncated)
                .is_err_and(|error| { error == super::RecordError::Incomplete })
        );
    }

    /// A tunnel waits on `record_len` before it calls `open`, so the two must
    /// agree: the total `record_len` promises is the record `open` then accepts,
    /// and a header `record_len` refuses is one `open` refuses for the same
    /// reason. That is what lets a session name a desynchronised peer at the
    /// header instead of waiting forever for bytes that can never complete, or
    /// mistaking the defect for a bad tag.
    #[test]
    fn record_len_promises_exactly_what_open_accepts() {
        let suite = CipherSuite::Aes256GcmSha384;
        let transcript = suite.hash().digest(b"flight");
        let schedule = KeySchedule::new(suite, &[9; 48], &transcript).expect("schedule");
        let keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .expect("keys");
        let (mut writer, mut reader) = (
            RecordLayer::new(suite, &keys).expect("writer"),
            RecordLayer::new(suite, &keys).expect("reader"),
        );
        for plaintext_len in [0_usize, 2, 1_000, MAX_PLAINTEXT_LEN] {
            let mut out = Vec::new();
            writer
                .seal(
                    ContentType::ApplicationData,
                    &vec![7_u8; plaintext_len],
                    &mut out,
                )
                .expect("seal");
            assert_eq!(RecordLayer::record_len(&out), Ok(Some(out.len())));
            for prefix in RECORD_HEADER_LEN..out.len() {
                assert_eq!(
                    RecordLayer::record_len(&out[..prefix]),
                    Ok(Some(out.len())),
                    "a partial buffer declares the same total"
                );
            }
            for prefix in 0..RECORD_HEADER_LEN {
                assert_eq!(
                    RecordLayer::record_len(&out[..prefix]),
                    Ok(None),
                    "no header is nothing to wait for"
                );
            }
            let (kind, opened) = reader.open(&mut out).expect("the promised record opens");
            assert_eq!(kind, ContentType::ApplicationData);
            assert_eq!(opened.len(), plaintext_len);
        }

        for header in [
            vec![22, 3, 3, 0, 17],      // a plaintext handshake record
            vec![23, 3, 2, 0, 17],      // a legacy version TLS 1.3 never writes
            vec![23, 3, 3, 0, 16],      // a body too short to hold type plus tag
            vec![23, 3, 3, 0xff, 0xff], // a body larger than one record can hold
        ] {
            let promised = RecordLayer::record_len(&header).expect_err("not a record header");
            let mut copy = header.clone();
            let refused = reader.open(&mut copy).expect_err("`open` agrees");
            assert_eq!(promised, refused, "{header:?}");
        }
    }

    #[test]
    fn incremental_transcript_equals_whole_digest() {
        let mut hasher = TranscriptHasher::new(HashAlgorithm::Sha384);
        hasher.update(b"aaa");
        let snapshot = hasher.snapshot();
        hasher.update(b"bbb");
        assert_eq!(snapshot.as_bytes().len(), 48);
        assert_eq!(hasher.snapshot(), HashAlgorithm::Sha384.digest(b"aaabbb"));
    }

    #[test]
    fn application_secrets_are_derivable_and_debug_is_redacted() {
        let transcript = HashAlgorithm::Sha256.digest(b"through-finished");
        let schedule = KeySchedule::new(CipherSuite::ChaCha20Poly1305Sha256, &[7; 32], &transcript)
            .expect("schedule");
        let ApplicationSecrets { .. } = schedule
            .application_secrets(&transcript)
            .expect("application secrets");
        let rendered = format!("{schedule:?}");
        assert!(rendered.contains("[REDACTED]"));
        let keys = schedule
            .traffic_keys(schedule.client_handshake_secret())
            .expect("keys");
        assert!(!format!("{keys:?}").contains("7777"));
    }

    #[test]
    fn schedules_reject_foreign_digests_and_empty_secrets() {
        let transcript = HashAlgorithm::Sha256.digest(b"x");
        assert!(
            KeySchedule::new(CipherSuite::Aes256GcmSha384, &[1; 32], &transcript)
                .is_err_and(|error| { error == super::KeyError::HashMismatch })
        );
        assert!(
            KeySchedule::new(CipherSuite::Aes128GcmSha256, &[], &transcript)
                .is_err_and(|error| { error == super::KeyError::Length })
        );
    }
}
