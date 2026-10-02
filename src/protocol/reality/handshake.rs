//! The client's TLS 1.3 continuation: the REALITY handshake state machine.
//!
//! This is the whole reason the authenticator exists. Once the server has
//! accepted our `ClientHello` it continues a textbook TLS 1.3 handshake whose key
//! schedule is bound to the ECDHE share we offered, so only a node holding the
//! configured REALITY private key can produce records that open under the
//! resulting handshake keys. Every failure below therefore means one of two
//! things, and they are reported differently: the peer is not our node
//! ([`crate::error::HandshakeError::IdentityMismatch`]), or our own transcript
//! bookkeeping disagrees with the peer's
//! ([`crate::error::HandshakeError::Verification`]).
//!
//! The server's flight has three observed shapes, all of which this code must
//! accept, because the shape is copied from whichever cover target answered
//! (`tls13/handshake.rs:417-455`):
//!
//! * one unpadded record holding all four messages,
//! * one padded record holding all four messages, or
//! * four padded records, one per message, optionally followed by one more
//!   record sealed under the *application* keys (`tls13/handshake.rs:503-510`).
//!
//! The third shape is why the state machine never reads past the server
//! `Finished`: that trailing record is not part of the handshake. It is a fake
//! New Session Ticket, and the server hands the *same* record layer that sealed
//! it to the tunnel (`tls13/handshake.rs:528`), so the record is an ordinary
//! empty `ApplicationData` record at the start of the application stream. A
//! client that swallowed it during the handshake would desynchronise every
//! sequence number in the tunnel; a client that opened it like any other record
//! stays in step whether or not it arrives.

use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, HandshakeError};
use crate::protocol::reality::auth::AuthKey;
use crate::protocol::reality::certificate::{
    finished_message, parse_encrypted_extensions, verify_certificate_signature, verify_finished,
    verify_server_certificate,
};
use crate::protocol::reality::hello::{ClientKeyAgreement, HelloRecord};
use crate::protocol::reality::server_hello::ServerHello;
use crate::protocol::tls13::{
    CipherSuite, ContentType, KeySchedule, MAX_PLAINTEXT_LEN, RecordLayer, TranscriptHasher,
};

/// The bound the server places on one flight's plaintext.
const MAX_FLIGHT_PLAINTEXT: usize = 16 * 1024;
/// A TLS record header.
const RECORD_HEADER_LEN: usize = 5;
/// An AEAD tag.
const TAG_LEN: usize = 16;
/// Outer content type of a plaintext alert record.
const OUTER_ALERT: u8 = 21;
/// Outer content type of a plaintext handshake record.
const OUTER_HANDSHAKE: u8 = 22;
/// Outer content type of a middlebox-compatibility record.
const OUTER_CHANGE_CIPHER_SPEC: u8 = 20;
/// Outer content type of an encrypted record.
const OUTER_APPLICATION_DATA: u8 = 23;
/// The one change cipher spec record the server accepts, byte for byte.
const CHANGE_CIPHER_SPEC_RECORD: [u8; 6] = [20, 3, 3, 0, 1, 1];
/// Largest encrypted record body the record layer will open.
const MAX_CIPHERTEXT_LEN: usize = MAX_PLAINTEXT_LEN + 1 + TAG_LEN;

/// What the TLS layer settled on, for logging and for the tunnel above it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Negotiated {
    /// The negotiated cipher suite.
    pub suite: CipherSuite,
    /// The ALPN the server claimed, if any.
    pub alpn: Option<Vec<u8>>,
    /// The key-share group the server selected.
    pub key_share_group: u16,
}

/// A completed REALITY handshake, holding both record directions.
pub struct Handshake {
    negotiated: Negotiated,
    server_records: RecordLayer,
    client_records: RecordLayer,
}

impl Handshake {
    /// What was negotiated.
    #[must_use]
    pub const fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// Splits the session into its two record directions.
    ///
    /// The tunnel above owns these: each one's sequence number advances once per
    /// record and must never be shared, reset, or duplicated.
    #[must_use]
    pub fn into_channels(self) -> (Negotiated, RecordLayer, RecordLayer) {
        (self.negotiated, self.server_records, self.client_records)
    }
}

#[cfg(test)]
impl Handshake {
    /// Assembles a completed handshake from two record directions.
    ///
    /// Production code reaches a `Handshake` only through [`complete`], which is
    /// the only place its keys are derived. A test above the handshake needs the
    /// same *type* — to drive a session against a peer that is just a key
    /// schedule — without standing up a whole REALITY server.
    pub(crate) fn from_record_layers(
        negotiated: Negotiated,
        server_records: RecordLayer,
        client_records: RecordLayer,
    ) -> Self {
        Self {
            negotiated,
            server_records,
            client_records,
        }
    }
}

impl fmt::Debug for Handshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Handshake")
            .field("negotiated", &self.negotiated)
            .field("traffic_keys", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Completes the TLS 1.3 continuation over a stream that already carries our
/// `ClientHello` record.
///
/// `offered_alpn` must be exactly the list the hello carried, because the
/// server's `EncryptedExtensions` may claim one of those protocols.
///
/// # Errors
///
/// Returns [`Error::Handshake`] for protocol, identity, and verification
/// failures, and [`Error::Io`] or a transport failure for socket errors.
#[allow(clippy::too_many_lines)]
pub async fn complete<S>(
    stream: &mut S,
    hello: &HelloRecord,
    keys: &ClientKeyAgreement,
    auth_key: &AuthKey,
    offered_alpn: &[&[u8]],
) -> Result<Handshake, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut scratch = Vec::with_capacity(RECORD_HEADER_LEN + MAX_CIPHERTEXT_LEN);
    let server_hello = read_server_hello(stream, hello, &mut scratch).await?;
    let shared_secret = keys
        .tls_shared_secret(server_hello.key_share_group(), server_hello.server_share())
        .ok_or({
            Error::Handshake(HandshakeError::Protocol(
                "key agreement was non-contributory",
            ))
        })?;

    let suite = server_hello.suite();
    let hash_len = suite.hash().output_len();
    let mut hasher = TranscriptHasher::new(suite.hash());
    hasher.update(hello.message());
    hasher.update(server_hello.message());
    let schedule = KeySchedule::new(suite, shared_secret.as_bytes(), &hasher.snapshot())?;
    let server_handshake_keys = schedule.traffic_keys(schedule.server_handshake_secret())?;
    let mut server_records = RecordLayer::new(suite, &server_handshake_keys)?;

    let mut flight = MessageBuffer::new();
    let encrypted_extensions =
        next_message(stream, &mut scratch, &mut server_records, &mut flight).await?;
    let alpn = parse_encrypted_extensions(&encrypted_extensions, offered_alpn)?;
    hasher.update(&encrypted_extensions);

    let certificate = next_message(stream, &mut scratch, &mut server_records, &mut flight).await?;
    let certificate_key = verify_server_certificate(&certificate, auth_key)?;
    hasher.update(&certificate);

    let certificate_verify =
        next_message(stream, &mut scratch, &mut server_records, &mut flight).await?;
    verify_certificate_signature(
        &certificate_verify,
        &certificate_key,
        hasher.snapshot().as_bytes(),
    )?;
    hasher.update(&certificate_verify);

    let server_finished =
        next_message(stream, &mut scratch, &mut server_records, &mut flight).await?;
    let expected =
        schedule.finished_verify_data(schedule.server_handshake_secret(), &hasher.snapshot())?;
    verify_finished(&server_finished, &expected[..hash_len])?;
    hasher.update(&server_finished);
    let through_server_finished = hasher.snapshot();

    let client_handshake_keys = schedule.traffic_keys(schedule.client_handshake_secret())?;
    let mut client_records = RecordLayer::new(suite, &client_handshake_keys)?;
    let client_finished = schedule
        .finished_verify_data(schedule.client_handshake_secret(), &through_server_finished)?;
    let finished = finished_message(&client_finished[..hash_len])?;

    // The server accepts our final flight with or without the compatibility
    // record (`tls13/handshake_read.rs:75-87`). Sending it is what a browser
    // does, so it is what cover traffic should look like.
    let mut response = Vec::with_capacity(
        CHANGE_CIPHER_SPEC_RECORD.len() + RecordLayer::record_wire_len(finished.len()),
    );
    response.extend_from_slice(&CHANGE_CIPHER_SPEC_RECORD);
    client_records.seal(ContentType::Handshake, &finished, &mut response)?;
    stream.write_all(&response).await.map_err(socket_failure)?;
    stream.flush().await.map_err(socket_failure)?;

    let application = schedule.application_secrets(&through_server_finished)?;
    let server_application_keys = schedule.traffic_keys(application.server())?;
    let client_application_keys = schedule.traffic_keys(application.client())?;
    Ok(Handshake {
        negotiated: Negotiated {
            suite,
            alpn,
            key_share_group: server_hello.key_share_group(),
        },
        server_records: RecordLayer::new(suite, &server_application_keys)?,
        client_records: RecordLayer::new(suite, &client_application_keys)?,
    })
}

/// Reads the plaintext record carrying the server's `ServerHello`.
async fn read_server_hello<S>(
    stream: &mut S,
    hello: &HelloRecord,
    scratch: &mut Vec<u8>,
) -> Result<ServerHello, Error>
where
    S: AsyncRead + Unpin,
{
    let outer = read_record(stream, scratch).await?;
    if outer != OUTER_HANDSHAKE {
        return Err(Error::Handshake(HandshakeError::Protocol(
            "server hello was not a plaintext handshake record",
        )));
    }
    // The record layer has no AAD-independent framing here: the ServerHello is
    // the only message in this record (`tls13/server_hello.rs:336-349`).
    let body =
        scratch
            .get(RECORD_HEADER_LEN..)
            .ok_or(Error::Handshake(HandshakeError::Protocol(
                "server hello record",
            )))?;
    ServerHello::parse(body, hello).map_err(Error::from)
}

/// Reads records until one complete handshake message is available.
///
/// Handshake messages never span records in this server's flight, but allowing
/// it keeps the state machine honest about what TLS permits.
async fn next_message<S>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    server_records: &mut RecordLayer,
    flight: &mut MessageBuffer,
) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(message) = flight.take_message() {
            return Ok(message);
        }
        let outer = read_record(stream, scratch).await?;
        match outer {
            OUTER_CHANGE_CIPHER_SPEC => {
                check_change_cipher_spec(&scratch[..])?;
            }
            OUTER_APPLICATION_DATA => {
                let (content_type, plaintext) =
                    server_records.open(&mut scratch[..]).map_err(|_| {
                        // Handshake keys come out of the REALITY key agreement, so
                        // a record that will not open under them was not produced
                        // by the node we configured.
                        Error::Handshake(HandshakeError::IdentityMismatch)
                    })?;
                if content_type != ContentType::Handshake {
                    return Err(Error::Handshake(HandshakeError::Protocol(
                        "encrypted record was not a handshake message",
                    )));
                }
                flight.push(plaintext)?;
            }
            _ => {
                return Err(Error::Handshake(HandshakeError::Protocol(
                    "unexpected record before server finished",
                )));
            }
        }
    }
}

/// Requires the compatibility record to be the one value TLS allows.
fn check_change_cipher_spec(record: &[u8]) -> Result<(), Error> {
    if record == CHANGE_CIPHER_SPEC_RECORD {
        Ok(())
    } else {
        Err(Error::Handshake(HandshakeError::Protocol(
            "invalid change cipher spec record",
        )))
    }
}

/// Reads exactly one TLS record into `scratch`, returning its outer type.
async fn read_record<S>(stream: &mut S, scratch: &mut Vec<u8>) -> Result<u8, Error>
where
    S: AsyncRead + Unpin,
{
    scratch.clear();
    scratch.resize(RECORD_HEADER_LEN, 0);
    stream
        .read_exact(&mut scratch[..])
        .await
        .map_err(socket_failure)?;
    let outer = *scratch
        .first()
        .ok_or(Error::Handshake(HandshakeError::Protocol(
            "record content type",
        )))?;
    if scratch.get(1..3) != Some(&[3, 3][..]) {
        return Err(Error::Handshake(HandshakeError::Protocol("record version")));
    }
    let body_len = usize::from(u16::from_be_bytes([scratch[3], scratch[4]]));
    let limit = match outer {
        OUTER_HANDSHAKE => MAX_PLAINTEXT_LEN,
        OUTER_CHANGE_CIPHER_SPEC => 1,
        OUTER_APPLICATION_DATA => MAX_CIPHERTEXT_LEN,
        // A cover target that rejects our hello says so in the clear, and that
        // distinction is what the scheduler needs: it is a refusal, not a
        // broken pipe.
        OUTER_ALERT => {
            return Err(Error::Handshake(HandshakeError::Protocol(
                "peer sent a plaintext alert",
            )));
        }
        _ => {
            return Err(Error::Handshake(HandshakeError::Protocol(
                "record content type",
            )));
        }
    };
    if body_len > limit {
        return Err(Error::Handshake(HandshakeError::Protocol("record length")));
    }
    scratch.resize(RECORD_HEADER_LEN + body_len, 0);
    stream
        .read_exact(&mut scratch[RECORD_HEADER_LEN..])
        .await
        .map_err(socket_failure)?;
    Ok(outer)
}

/// Maps a socket failure onto the handshake taxonomy.
// Used as a `map_err` callback, which hands over the error by value.
#[allow(clippy::needless_pass_by_value)]
fn socket_failure(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Handshake(HandshakeError::UnexpectedEof)
    } else {
        Error::Io(error.to_string())
    }
}

/// Accumulates flight plaintext and hands back whole handshake messages.
struct MessageBuffer {
    bytes: Vec<u8>,
}

impl MessageBuffer {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Appends one record's handshake plaintext, refusing to grow unbounded.
    fn push(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        self.bytes
            .len()
            .checked_add(plaintext.len())
            .filter(|total| *total <= MAX_FLIGHT_PLAINTEXT)
            .ok_or({
                Error::Handshake(HandshakeError::Protocol(
                    "handshake flight exceeds its bound",
                ))
            })?;
        self.bytes.reserve_exact(plaintext.len());
        self.bytes.extend_from_slice(plaintext);
        Ok(())
    }

    /// Consumes the next complete message, or returns `None` when more records
    /// are needed.
    fn take_message(&mut self) -> Option<Vec<u8>> {
        let header = self.bytes.first_chunk::<4>()?;
        let declared =
            usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
        let total = 4_usize.checked_add(declared)?;
        if declared == 0 || total > MAX_FLIGHT_PLAINTEXT || self.bytes.len() < total {
            return None;
        }
        Some(self.bytes.drain(..total).collect())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha512;

    use super::*;
    use crate::crypto::EphemeralX25519;
    use crate::protocol::reality::auth::{AuthPlaintext, CLIENT_VERSION};
    use crate::protocol::reality::certificate::{
        HANDSHAKE_CERTIFICATE, HANDSHAKE_CERTIFICATE_VERIFY, HANDSHAKE_ENCRYPTED_EXTENSIONS,
        HANDSHAKE_FINISHED,
    };
    use crate::protocol::reality::hello::build_client_hello;
    use crate::protocol::tls13::TrafficKeys;

    const NAME: &str = "www.example.com";
    const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
    const SUITE: CipherSuite = CipherSuite::Aes256GcmSha384;
    const CCS_LEN: usize = CHANGE_CIPHER_SPEC_RECORD.len();
    const HANDSHAKE_SERVER_HELLO: u8 = 2;

    /// One node's side of the handshake, so a test can play the server exactly
    /// the way `tls13/handshake.rs:330-531` does.
    struct Node {
        reality_key: EphemeralX25519,
        certificate_key: SigningKey,
    }

    impl Node {
        fn new() -> Self {
            Self {
                reality_key: EphemeralX25519::generate().expect("key"),
                certificate_key: SigningKey::from_bytes(&[0x07; 32]),
            }
        }

        /// The forged certificate recipe from `tls13/messages.rs:86-110`.
        fn forge_certificate(&self, auth_key: &AuthKey) -> Vec<u8> {
            let public = self.certificate_key.verifying_key().to_bytes();
            let mut der = crate::protocol::reality::certificate::CERTIFICATE_TEMPLATE.to_vec();
            der[72..104].copy_from_slice(&public);
            let mut mac =
                <Hmac<Sha512> as KeyInit>::new_from_slice(auth_key.as_bytes()).expect("hmac key");
            mac.update(&public);
            der[114..].copy_from_slice(&mac.finalize().into_bytes());
            der
        }
    }

    /// The key material the server half of a fixture holds, so a test can check
    /// what the client sent without reaching back into the schedule.
    struct Peer {
        /// Opens the client's `Finished`, sealed under handshake keys.
        from_client_handshake: TrafficKeys,
        /// Opens the client's application records.
        from_client: TrafficKeys,
        /// Seals application records the client must open.
        to_client: TrafficKeys,
        /// The exact `Finished` message the client has to produce.
        client_finished: Vec<u8>,
    }

    fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        let length = u32::try_from(body.len()).expect("body");
        out.extend_from_slice(&length.to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    fn empty_encrypted_extensions() -> Vec<u8> {
        handshake_message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &[0, 0])
    }

    fn alpn_encrypted_extensions(protocol: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(
            &u16::try_from(protocol.len() + 1)
                .expect("list")
                .to_be_bytes(),
        );
        inner.push(u8::try_from(protocol.len()).expect("protocol"));
        inner.extend_from_slice(protocol);
        let mut extension = Vec::new();
        extension.extend_from_slice(&0x0010_u16.to_be_bytes());
        extension.extend_from_slice(&u16::try_from(inner.len()).expect("extension").to_be_bytes());
        extension.extend_from_slice(&inner);
        let mut body = Vec::new();
        body.extend_from_slice(
            &u16::try_from(extension.len())
                .expect("extensions")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extension);
        handshake_message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &body)
    }

    fn certificate_message(der: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0);
        let entry = u32::try_from(der.len() + 3 + 2).expect("entry");
        body.extend_from_slice(&entry.to_be_bytes()[1..]);
        let length = u32::try_from(der.len()).expect("der");
        body.extend_from_slice(&length.to_be_bytes()[1..]);
        body.extend_from_slice(der);
        body.extend_from_slice(&[0, 0]);
        handshake_message(HANDSHAKE_CERTIFICATE, &body)
    }

    fn certificate_verify_message(signing: &SigningKey, transcript_hash: &[u8]) -> Vec<u8> {
        let mut signed = Vec::new();
        signed.resize(64, 0x20);
        signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed.push(0);
        signed.extend_from_slice(transcript_hash);
        let signature = signing.sign(&signed).to_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&0x0807_u16.to_be_bytes());
        body.extend_from_slice(
            &u16::try_from(signature.len())
                .expect("signature")
                .to_be_bytes(),
        );
        body.extend_from_slice(&signature);
        handshake_message(HANDSHAKE_CERTIFICATE_VERIFY, &body)
    }

    /// The `ServerHello` the server sends: our session ID echoed, our group
    /// selected, one fresh key share.
    fn server_hello_message(
        hello: &HelloRecord,
        suite: CipherSuite,
        group: u16,
        server_share: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x99; 32]);
        body.push(u8::try_from(hello.session_id().len()).expect("session id"));
        body.extend_from_slice(hello.session_id());
        body.extend_from_slice(&suite.wire_value().to_be_bytes());
        body.push(0);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x002b_u16.to_be_bytes());
        extensions.extend_from_slice(&[0, 2, 3, 4]);
        extensions.extend_from_slice(&0x0033_u16.to_be_bytes());
        let share_len = u16::try_from(server_share.len() + 4).expect("share");
        extensions.extend_from_slice(&share_len.to_be_bytes());
        extensions.extend_from_slice(&group.to_be_bytes());
        let exchange = u16::try_from(server_share.len()).expect("exchange");
        extensions.extend_from_slice(&exchange.to_be_bytes());
        extensions.extend_from_slice(server_share);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("extensions")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);
        handshake_message(HANDSHAKE_SERVER_HELLO, &body)
    }

    fn client_start(node: &Node) -> (HelloRecord, ClientKeyAgreement, AuthKey) {
        let keys = ClientKeyAgreement::generate().expect("key agreement");
        let plaintext = AuthPlaintext {
            version: CLIENT_VERSION,
            time: 1_700_000_000,
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        build_client_hello(NAME, ALPN, &keys, node.reality_key.public_key(), plaintext)
            .map(|(hello, auth_key)| (hello, keys, auth_key))
            .expect("client hello")
    }

    /// Plays the server half of a flight and returns the wire bytes plus the
    /// keys that half holds.
    ///
    /// `bound_to` is the authenticator key the certificate is bound to, which a
    /// test can make a foreign one to imitate a node we did not configure.
    fn build_flight(
        node: &Node,
        hello: &HelloRecord,
        keys: &ClientKeyAgreement,
        bound_to: &AuthKey,
        claim_alpn: Option<&[u8]>,
        positional: bool,
    ) -> (Vec<u8>, Peer) {
        // The server mirrors our standalone X25519 share for the plain group,
        // which is all this fixture needs; the hybrid path is covered at the
        // agreement layer by the `crypto` and `hello` tests.
        let server_tls_key = EphemeralX25519::generate().expect("tls key");
        let client_public = keys.authentication_public_key();
        let shared = server_tls_key.agree(client_public).expect("shared");
        let server_hello = server_hello_message(
            hello,
            SUITE,
            crate::protocol::reality::X25519_GROUP,
            server_tls_key.public_key(),
        );

        let mut hasher = TranscriptHasher::new(SUITE.hash());
        hasher.update(hello.message());
        hasher.update(&server_hello);
        let schedule = KeySchedule::new(SUITE, &shared[..], &hasher.snapshot()).expect("schedule");
        let handshake_keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .expect("handshake keys");

        let encrypted_extensions = match claim_alpn {
            Some(protocol) => alpn_encrypted_extensions(protocol),
            None => empty_encrypted_extensions(),
        };
        let certificate = certificate_message(&node.forge_certificate(bound_to));
        hasher.update(&encrypted_extensions);
        hasher.update(&certificate);
        let certificate_verify =
            certificate_verify_message(&node.certificate_key, hasher.snapshot().as_bytes());
        hasher.update(&certificate_verify);
        let finished_data = schedule
            .finished_verify_data(schedule.server_handshake_secret(), &hasher.snapshot())
            .expect("finished");
        let server_finished = handshake_message(
            HANDSHAKE_FINISHED,
            &finished_data[..SUITE.hash().output_len()],
        );
        hasher.update(&server_finished);
        let through_server_finished = hasher.snapshot();

        let expected_finished = schedule
            .finished_verify_data(schedule.client_handshake_secret(), &through_server_finished)
            .expect("client finished");
        let client_finished =
            finished_message(&expected_finished[..SUITE.hash().output_len()]).expect("build");

        let mut records = RecordLayer::new(SUITE, &handshake_keys).expect("record layer");
        let mut wire = vec![OUTER_HANDSHAKE, 3, 3];
        let hello_len = u16::try_from(server_hello.len()).expect("hello record");
        wire.extend_from_slice(&hello_len.to_be_bytes());
        wire.extend_from_slice(&server_hello);
        wire.extend_from_slice(&CHANGE_CIPHER_SPEC_RECORD);

        let messages = [
            encrypted_extensions.as_slice(),
            certificate.as_slice(),
            certificate_verify.as_slice(),
            server_finished.as_slice(),
        ];
        if positional {
            for message in messages {
                records
                    .seal(ContentType::Handshake, message, &mut wire)
                    .expect("seal");
            }
        } else {
            let mut plaintext = Vec::new();
            for message in messages {
                plaintext.extend_from_slice(message);
            }
            records
                .seal(ContentType::Handshake, &plaintext, &mut wire)
                .expect("seal");
        }
        let application = schedule
            .application_secrets(&through_server_finished)
            .expect("application secrets");
        (
            wire,
            Peer {
                from_client_handshake: schedule
                    .traffic_keys(schedule.client_handshake_secret())
                    .expect("client handshake keys"),
                from_client: schedule
                    .traffic_keys(application.client())
                    .expect("client keys"),
                to_client: schedule
                    .traffic_keys(application.server())
                    .expect("server keys"),
                client_finished,
            },
        )
    }

    /// The flight's total length once fully buffered, asserting the shape the
    /// server requires as the bytes arrive: one compatibility record, then one
    /// encrypted record and nothing else (`tls13/handshake_read.rs:75-100`).
    fn flight_complete(bytes: &[u8]) -> bool {
        if bytes.len() < CCS_LEN + RECORD_HEADER_LEN {
            return false;
        }
        assert_eq!(
            &CHANGE_CIPHER_SPEC_RECORD[..],
            &bytes[..CCS_LEN],
            "the client must send the exact compatibility record"
        );
        assert_eq!(
            OUTER_APPLICATION_DATA, bytes[CCS_LEN],
            "the client's finished must be encrypted"
        );
        let body = usize::from(u16::from_be_bytes([bytes[CCS_LEN + 3], bytes[CCS_LEN + 4]]));
        let total = CCS_LEN + RECORD_HEADER_LEN + body;
        if bytes.len() < total {
            return false;
        }
        assert_eq!(total, bytes.len(), "the flight ends with its one record");
        true
    }

    async fn collect_client_flight<R>(reader: &mut R) -> Vec<u8>
    where
        R: AsyncRead + Unpin,
    {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        while !flight_complete(&bytes) {
            let read = reader
                .read(&mut chunk)
                .await
                .expect("read the client flight");
            assert_ne!(0, read, "the client closed without sending its flight");
            bytes.extend_from_slice(&chunk[..read]);
        }
        bytes
    }

    /// Runs one full client handshake against a fixture server, with the whole
    /// server flight already buffered in the pipe.
    async fn exchange(positional: bool, claim_alpn: Option<&[u8]>) -> (Handshake, Vec<u8>, Peer) {
        let node = Node::new();
        let (hello, keys, auth_key) = client_start(&node);
        let (wire, peer) = build_flight(&node, &hello, &keys, &auth_key, claim_alpn, positional);
        let (mut client_stream, mut server_stream) = tokio::io::duplex(64 * 1024);
        server_stream.write_all(&wire).await.expect("flight fits");
        let handshake = complete(&mut client_stream, &hello, &keys, &auth_key, ALPN)
            .await
            .expect("handshake");
        let flight = collect_client_flight(&mut server_stream).await;
        (handshake, flight, peer)
    }

    /// Feeds a hostile server flight and returns the refusal it produced.
    async fn refused_by(
        wire: &[u8],
        hello: &HelloRecord,
        keys: &ClientKeyAgreement,
        auth_key: &AuthKey,
    ) -> Error {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(64 * 1024);
        server_stream.write_all(wire).await.expect("wire fits");
        // Closing the write side lets a client that needs more data see EOF
        // rather than hang.
        drop(server_stream);
        complete(&mut client_stream, hello, keys, auth_key, ALPN)
            .await
            .expect_err("the client must refuse this server")
    }

    #[tokio::test]
    async fn completes_a_coalesced_server_flight() {
        let (handshake, flight, peer) = exchange(false, Some(b"h2")).await;
        assert_eq!(SUITE, handshake.negotiated().suite);
        assert_eq!(Some(b"h2".to_vec()), handshake.negotiated().alpn.clone());
        assert_eq!(
            crate::protocol::reality::X25519_GROUP,
            handshake.negotiated().key_share_group
        );
        assert_eq!(&CHANGE_CIPHER_SPEC_RECORD[..], &flight[..CCS_LEN]);

        let mut buffer = flight[CCS_LEN..].to_vec();
        let mut opener = RecordLayer::new(SUITE, &peer.from_client_handshake).expect("layer");
        let (kind, plaintext) = opener.open(&mut buffer).expect("client finished record");
        assert_eq!(ContentType::Handshake, kind);
        assert_eq!(peer.client_finished, plaintext);
    }

    #[tokio::test]
    async fn completes_a_positional_server_flight() {
        let (handshake, _, _) = exchange(true, None).await;
        assert_eq!(None, handshake.negotiated().alpn);
    }

    /// The trap in `CoverHandshakeRecordShape::PositionalRecords`: the fake
    /// ticket is sealed by the very layer the server hands to the tunnel
    /// (`tls13/handshake.rs:406,503-510,528`), so the tunnel's first real record
    /// is already at sequence 1. Reading the ticket as one empty
    /// `ApplicationData` record is what keeps both sides in step.
    #[tokio::test]
    async fn a_fake_ticket_record_leaves_the_tunnel_in_step() {
        let node = Node::new();
        let (hello, keys, auth_key) = client_start(&node);
        let (mut wire, peer) = build_flight(&node, &hello, &keys, &auth_key, None, true);
        let mut tunnel = RecordLayer::new(SUITE, &peer.to_client).expect("tunnel layer");
        tunnel
            .seal_padded(ContentType::ApplicationData, &[], 117, &mut wire)
            .expect("fake ticket");

        let (mut client_stream, mut server_stream) = tokio::io::duplex(64 * 1024);
        server_stream.write_all(&wire).await.expect("flight fits");
        let handshake = complete(&mut client_stream, &hello, &keys, &auth_key, ALPN)
            .await
            .expect("handshake");
        collect_client_flight(&mut server_stream).await;

        let theirs: &[u8] = b"first real response";
        let mut sealed = Vec::new();
        tunnel
            .seal(ContentType::ApplicationData, theirs, &mut sealed)
            .expect("the server's first tunnel record");
        server_stream.write_all(&sealed).await.expect("fits");

        let (_, mut inbound, _) = handshake.into_channels();
        let mut scratch = Vec::new();
        assert_eq!(
            OUTER_APPLICATION_DATA,
            read_record(&mut client_stream, &mut scratch)
                .await
                .expect("ticket record")
        );
        let (kind, plaintext) = inbound.open(&mut scratch).expect("ticket opens");
        assert_eq!(ContentType::ApplicationData, kind);
        assert!(plaintext.is_empty(), "the fake ticket carries no payload");

        assert_eq!(
            OUTER_APPLICATION_DATA,
            read_record(&mut client_stream, &mut scratch)
                .await
                .expect("response record")
        );
        let (kind, plaintext) = inbound.open(&mut scratch).expect("response opens");
        assert_eq!(ContentType::ApplicationData, kind);
        assert_eq!(theirs, plaintext);
        assert_eq!(2, inbound.records_used());
    }

    #[tokio::test]
    async fn application_records_open_in_both_directions() -> Result<(), Error> {
        let (handshake, _, peer) = exchange(false, None).await;
        let (negotiated, mut inbound, mut outbound) = handshake.into_channels();
        assert_eq!(SUITE, negotiated.suite);

        let ours: &[u8] = b"vless request bytes";
        let mut sealed = Vec::new();
        outbound.seal(ContentType::ApplicationData, ours, &mut sealed)?;
        let mut server_side = RecordLayer::new(SUITE, &peer.from_client)?;
        let mut buffer = sealed;
        let (kind, plaintext) = server_side.open(&mut buffer)?;
        assert_eq!(ContentType::ApplicationData, kind);
        assert_eq!(ours, plaintext);

        let theirs: &[u8] = b"vless response bytes";
        let mut server_records = RecordLayer::new(SUITE, &peer.to_client)?;
        let mut sealed = Vec::new();
        server_records.seal(ContentType::ApplicationData, theirs, &mut sealed)?;
        let mut buffer = sealed;
        let (kind, plaintext) = inbound.open(&mut buffer)?;
        assert_eq!(ContentType::ApplicationData, kind);
        assert_eq!(theirs, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn a_certificate_bound_to_a_foreign_key_is_an_identity_failure() {
        let node = Node::new();
        let (hello, keys, auth_key) = client_start(&node);
        // A node that does not hold our configured private key derives a
        // different authenticator, so its certificate binds to something else.
        let foreign = AuthKey::derive(&[0x55; 32], hello.random()).expect("derive");
        let (wire, _) = build_flight(&node, &hello, &keys, &foreign, None, false);
        let error = refused_by(&wire, &hello, &keys, &auth_key).await;
        assert!(
            matches!(error, Error::Handshake(HandshakeError::IdentityMismatch)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_record_that_will_not_open_is_an_identity_failure() {
        let node = Node::new();
        let (hello, keys, auth_key) = client_start(&node);
        let (mut wire, _) = build_flight(&node, &hello, &keys, &auth_key, None, false);
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        let error = refused_by(&wire, &hello, &keys, &auth_key).await;
        assert!(
            matches!(error, Error::Handshake(HandshakeError::IdentityMismatch)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_plaintext_record_where_the_flight_is_expected_is_refused() {
        let node = Node::new();
        let (hello, keys, auth_key) = client_start(&node);
        let (mut wire, _) = build_flight(&node, &hello, &keys, &auth_key, None, false);
        // A plaintext handshake record smuggled into the encrypted part, in
        // place of the first sealed record. Appending it instead would leave it
        // unread, because the client stops at the server's `Finished`.
        let encrypted_from = wire
            .windows(CCS_LEN)
            .position(|window| window == &CHANGE_CIPHER_SPEC_RECORD[..])
            .expect("compatibility record")
            + CCS_LEN;
        wire.truncate(encrypted_from);
        wire.extend_from_slice(&[OUTER_HANDSHAKE, 3, 3, 0, 4, 8, 0, 0, 2, 0, 0]);
        let error = refused_by(&wire, &hello, &keys, &auth_key).await;
        assert!(
            matches!(
                error,
                Error::Handshake(HandshakeError::Protocol(
                    "unexpected record before server finished"
                ))
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_server_that_stops_mid_flight_is_reported_as_eof() {
        let node = Node::new();
        let (hello, keys, auth_key) = client_start(&node);
        let (wire, _) = build_flight(&node, &hello, &keys, &auth_key, None, false);
        let after_server_hello =
            RECORD_HEADER_LEN + usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let error = refused_by(&wire[..after_server_hello], &hello, &keys, &auth_key).await;
        assert!(
            matches!(error, Error::Handshake(HandshakeError::UnexpectedEof)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_server_hello_that_refuses_to_echo_the_session_id_is_refused() {
        let node = Node::new();
        let (hello, keys, auth_key) = client_start(&node);
        let (mut wire, _) = build_flight(&node, &hello, &keys, &auth_key, None, false);
        // The session ID begins after 5 record-header bytes, 4 handshake-header
        // bytes, the legacy version and the random field, plus the one length byte
        // that precedes it. A bit flip, not an assignment: the ID is the
        // authenticator, so writing a fixed byte would be a no-op in about one run
        // in 256 that already carried it, and the client would accept the hello.
        wire[5 + 4 + 2 + 32 + 1] ^= 0x80;
        let error = refused_by(&wire, &hello, &keys, &auth_key).await;
        assert!(
            matches!(
                error,
                Error::Handshake(HandshakeError::Protocol("server hello session id"))
            ),
            "{error}"
        );
    }

    #[test]
    fn message_buffer_yields_only_complete_messages() {
        let mut buffer = MessageBuffer::new();
        buffer.push(&[8, 0, 0, 2, 0, 0]).expect("push");
        assert_eq!(
            vec![8_u8, 0, 0, 2, 0, 0],
            buffer.take_message().expect("message")
        );
        assert!(buffer.take_message().is_none());

        let mut buffer = MessageBuffer::new();
        buffer.push(&[11, 0, 0, 4]).expect("push");
        assert!(
            buffer.take_message().is_none(),
            "an incomplete message waits"
        );
        buffer.push(&[0, 0, 0, 0]).expect("push");
        assert_eq!(8, buffer.take_message().expect("message").len());
    }

    #[test]
    fn message_buffer_refuses_to_grow_past_the_flight_bound() {
        let mut buffer = MessageBuffer::new();
        buffer
            .push(&vec![0_u8; MAX_FLIGHT_PLAINTEXT])
            .expect("push");
        assert!(buffer.push(&[1]).is_err());
    }

    #[test]
    fn a_message_claiming_more_than_the_bound_is_never_consumeable() {
        let mut buffer = MessageBuffer::new();
        buffer.push(&[11, 0xff, 0xff, 0xff]).expect("push");
        assert!(buffer.take_message().is_none());
    }

    #[test]
    fn the_compatibility_record_must_be_exact() {
        assert!(check_change_cipher_spec(&CHANGE_CIPHER_SPEC_RECORD).is_ok());
        let mut bent = CHANGE_CIPHER_SPEC_RECORD;
        bent[5] = 2;
        assert!(check_change_cipher_spec(&bent).is_err());
    }

    #[tokio::test]
    async fn reading_a_closed_stream_is_reported_as_eof() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server);
        let mut scratch = Vec::new();
        assert!(matches!(
            read_record(&mut client, &mut scratch).await,
            Err(Error::Handshake(HandshakeError::UnexpectedEof))
        ));
    }

    #[tokio::test]
    async fn a_plaintext_alert_is_reported_as_a_refusal() {
        let (mut client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[OUTER_ALERT, 3, 3, 0, 2, 2, 80])
            .await
            .expect("write");
        let mut scratch = Vec::new();
        assert!(matches!(
            read_record(&mut client, &mut scratch).await,
            Err(Error::Handshake(HandshakeError::Protocol(
                "peer sent a plaintext alert"
            )))
        ));
    }

    #[tokio::test]
    async fn a_record_with_an_unknown_outer_type_is_refused() {
        let (mut client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[25_u8, 3, 3, 0, 2, 2, 0])
            .await
            .expect("write");
        let mut scratch = Vec::new();
        assert!(matches!(
            read_record(&mut client, &mut scratch).await,
            Err(Error::Handshake(HandshakeError::Protocol(
                "record content type"
            )))
        ));
    }

    #[tokio::test]
    async fn a_record_with_a_foreign_version_is_refused() {
        let (mut client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&[22_u8, 3, 1, 0, 2, 1, 0])
            .await
            .expect("write");
        let mut scratch = Vec::new();
        assert!(matches!(
            read_record(&mut client, &mut scratch).await,
            Err(Error::Handshake(HandshakeError::Protocol("record version")))
        ));
    }

    #[tokio::test]
    async fn a_record_declaring_more_than_its_bound_is_refused() {
        let (mut client, mut server) = tokio::io::duplex(64);
        // One byte over the handshake bound. Dropping the peer afterwards means
        // a client that wrongly decided to read this body would see EOF instead
        // of the length refusal, so the test cannot hang or pass vacuously.
        server
            .write_all(&[22_u8, 3, 3, 0x40, 0x01])
            .await
            .expect("write");
        drop(server);
        let mut scratch = Vec::new();
        assert!(matches!(
            read_record(&mut client, &mut scratch).await,
            Err(Error::Handshake(HandshakeError::Protocol("record length")))
        ));
    }

    #[tokio::test]
    async fn diagnostics_never_render_traffic_keys() {
        let (handshake, _, _) = exchange(false, None).await;
        let rendered = format!("{handshake:?}");
        assert!(rendered.contains("REDACTED"), "{rendered}");
    }
}
