//! Interoperability gate against an unmodified `rust-reality` v2.0.1 server.
//!
//! These tests talk to a live node rather than to a fixture of our own making,
//! which is the only way to prove the `ClientHello` bytes are what the server
//! parses rather than what we assumed it parses. They are `#[ignore]`d because
//! they need the server, and the server needs a TLS 1.3 cover:
//!
//! ```text
//! scripts/interop/upstream-server.sh          # starts cover + echo + v2.0.1 entry
//! set -a; . target/interop/handoff.env; set +a
//! cargo test --test interop_v201 -- --ignored --test-threads=1
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rust_reality_client::protocol::reality::{
    AuthPlaintext, CLIENT_VERSION, ClientKeyAgreement, Handshake, Negotiated, X25519_GROUP,
    X25519_MLKEM768_GROUP, build_client_hello, complete,
};
use rust_reality_client::protocol::vless::Destination;
use rust_reality_client::transport::VisionSession;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
/// The three TLS 1.3 suites this client offers.
const OFFERED_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];
const READ_TIMEOUT: Duration = Duration::from_secs(10);

fn parameter(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is unset; source target/interop/handoff.env from the interop server")
    })
}

/// A REALITY public key: URL-safe unpadded base64 of exactly 32 bytes.
fn public_key() -> [u8; 32] {
    let encoded = parameter("RRC_INTEROP_PUBLIC_KEY");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encoded)
        .expect("server public key must be URL-safe unpadded base64");
    <[u8; 32]>::try_from(bytes).expect("server public key must be 32 bytes")
}

/// A configured short ID: two to sixteen even hexadecimal characters, which the
/// server right-pads to the eight bytes that travel on the wire.
fn short_id() -> [u8; 8] {
    let encoded = parameter("RRC_INTEROP_SHORT_ID");
    assert!(
        (2..=16).contains(&encoded.len()) && encoded.len() % 2 == 0,
        "short id must be 2 to 16 even hex characters"
    );
    let mut bytes = [0_u8; 8];
    for (index, chunk) in encoded.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).expect("hex is ascii");
        bytes[index] = u8::from_str_radix(text, 16).expect("short id must be hexadecimal");
    }
    bytes
}

/// The client's view of the clock, in the seconds-since-epoch the authenticator
/// carries. v2.0.1 accepts a symmetric window around its own time.
fn now_seconds() -> u32 {
    u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_secs(),
    )
    .expect("clock fits a u32 for another billion years")
}

/// The configured user id: 32 hexadecimal digits, dashes ignored.
fn user_id() -> [u8; 16] {
    let encoded = parameter("RRC_INTEROP_USER_ID");
    let hex: Vec<u8> = encoded.bytes().filter(|byte| *byte != b'-').collect();
    assert_eq!(hex.len(), 32, "user id must be 32 hexadecimal digits");
    let mut bytes = [0_u8; 16];
    for (index, chunk) in hex.chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).expect("hex is ascii");
        bytes[index] = u8::from_str_radix(text, 16).expect("user id must be hexadecimal");
    }
    bytes
}

/// The destination the node reaches for the session tests: a loopback echo it
/// dials through its `direct` route, so bytes come back from outside the tunnel
/// rather than from a fixture inside it.
fn echo_target() -> (Destination, u16) {
    let endpoint = parameter("RRC_INTEROP_ECHO");
    let (host, port) = endpoint.rsplit_once(':').expect("echo target is host:port");
    let port = port.parse().expect("echo port is a number");
    let (destination, port) = Destination::parse(host, port).expect("echo is a legal destination");
    (destination, port)
}

/// Opens one REALITY tunnel and hands back the live socket plus its handshake.
async fn tunnel() -> (TcpStream, Handshake) {
    let address = parameter("RRC_INTEROP_ADDR");
    let server_name = parameter("RRC_INTEROP_SERVER_NAME");
    let keys = ClientKeyAgreement::generate().expect("client key agreement");
    let auth = AuthPlaintext {
        version: CLIENT_VERSION,
        time: now_seconds(),
        short_id: short_id(),
    };
    let (hello, auth_key) =
        build_client_hello(&server_name, ALPN, &keys, &public_key(), auth).expect("client hello");

    let mut stream = TcpStream::connect(&address)
        .await
        .unwrap_or_else(|error| panic!("connecting to {address}: {error}"));
    stream
        .set_nodelay(true)
        .expect("nodelay on a local interop node");
    stream
        .write_all(&hello.record())
        .await
        .expect("write client hello");
    stream.flush().await.expect("flush client hello");

    let handshake = tokio::time::timeout(
        READ_TIMEOUT,
        complete(&mut stream, &hello, &keys, &auth_key, ALPN),
    )
    .await
    .expect("the server must answer inside the handshake budget")
    .unwrap_or_else(|error| panic!("REALITY handshake with v2.0.1 failed: {error}"));
    (stream, handshake)
}

/// Asserts that what the server settled on is something this client offered.
fn check_negotiated(negotiated: &Negotiated) {
    let suite = negotiated.suite.wire_value();
    assert!(
        OFFERED_SUITES.contains(&suite),
        "the server selected a suite we never offered: {suite:#06x}"
    );
    assert!(
        negotiated.key_share_group == X25519_GROUP
            || negotiated.key_share_group == X25519_MLKEM768_GROUP,
        "the server selected a group we never shared: {:#06x}",
        negotiated.key_share_group
    );
    if let Some(protocol) = &negotiated.alpn {
        let claimed: &[u8] = protocol;
        assert!(
            ALPN.contains(&claimed),
            "the server claimed an ALPN we never offered"
        );
    }
}

/// Performs one REALITY handshake and checks what the server negotiated.
async fn handshakes_once() {
    let (mut stream, handshake) = tunnel().await;
    check_negotiated(handshake.negotiated());
    drop(handshake);
    let _ = stream.shutdown().await;
}

#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server"]
async fn reality_handshake_completes_against_v201() {
    handshakes_once().await;
}

/// Five independent handshakes, each with fresh key material.
///
/// v2.0.1 keeps a replay cache, so a client that reused an authenticator would
/// be silently pushed to the cover. This is also the smallest sample that would
/// catch a regression where only the first connection of a process works.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server"]
async fn repeated_handshakes_all_complete() {
    for _attempt in 1..=5 {
        handshakes_once().await;
    }
}

/// An authenticator sealed against the wrong server key must not authenticate.
///
/// v2.0.1 answers a failed authentication by relaying to the cover, so the
/// client's own key agreement is the only thing that can reject it: the flight
/// arrives under keys that do not match ours. Error or timeout are both honest
/// outcomes; a completed handshake is not.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server"]
async fn a_foreign_key_agreement_does_not_authenticate() {
    let mut wrong = public_key();
    wrong[0] ^= 0x55;
    let address = parameter("RRC_INTEROP_ADDR");
    let server_name = parameter("RRC_INTEROP_SERVER_NAME");
    let keys = ClientKeyAgreement::generate().expect("client key agreement");
    let auth = AuthPlaintext {
        version: CLIENT_VERSION,
        time: now_seconds(),
        short_id: short_id(),
    };
    let Ok((hello, auth_key)) = build_client_hello(&server_name, ALPN, &keys, &wrong, auth) else {
        return;
    };
    let mut stream = TcpStream::connect(&address)
        .await
        .expect("connect to the interop node");
    stream
        .write_all(&hello.record())
        .await
        .expect("write client hello");
    stream.flush().await.expect("flush");
    let outcome = tokio::time::timeout(
        READ_TIMEOUT,
        complete(&mut stream, &hello, &keys, &auth_key, ALPN),
    )
    .await;
    assert!(
        !matches!(&outcome, Ok(Ok(_))),
        "a mismatched server key must never yield an authenticated session"
    );
}

/// Opens a session to the echo target and returns it, request already accepted.
async fn session_to_echo() -> VisionSession<TcpStream> {
    let (destination, port) = echo_target();
    let (stream, handshake) = tunnel().await;
    let outcome = tokio::time::timeout(
        READ_TIMEOUT,
        VisionSession::connect(stream, handshake, user_id(), &destination, port),
    )
    .await
    .expect("the node must accept the request inside the budget");
    outcome.unwrap_or_else(|error| panic!("Vision session to the echo failed: {error}"))
}

/// A Vision session that carries real bytes to a destination and back.
///
/// Everything before this proves the tunnel is authenticated; this proves the
/// tunnel is *useful*. v2.0.1 writes the `[0, 0]` response only after it has
/// connected to the destination, so `connect` returning is already half the
/// claim — the round trips prove the framed uplink, the node's switch to raw
/// bytes once its nested-TLS detector gives up on non-TLS traffic, and that no
/// byte was altered, duplicated or reordered across either layout.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn a_vision_session_carries_bytes_both_ways_through_v201() {
    let mut session = session_to_echo().await;

    // Small first: a failure here says the framing is wrong, not the buffers.
    let probe = b"reality vision round trip\n";
    session.write_all(probe).await.expect("write the probe");
    let mut echoed = vec![0_u8; probe.len()];
    tokio::time::timeout(READ_TIMEOUT, session.read_exact(&mut echoed))
        .await
        .expect("the echo must answer inside the budget")
        .expect("read the probe back");
    assert_eq!(echoed, probe);

    // Then enough bytes to cross many frames in both directions.
    let payload: Vec<u8> = (0..=250_u8)
        .collect::<Vec<_>>()
        .iter()
        .copied()
        .cycle()
        .take(200 * 1024)
        .collect();
    tokio::time::timeout(READ_TIMEOUT, session.write_all(&payload))
        .await
        .expect("the bulk write must finish inside the budget")
        .expect("write the bulk payload");
    let mut received = vec![0_u8; payload.len()];
    tokio::time::timeout(READ_TIMEOUT * 2, session.read_exact(&mut received))
        .await
        .expect("the bulk read must finish inside the budget")
        .expect("read the bulk payload back");
    assert_eq!(received, payload, "the tunnel altered or reordered bytes");
    if let Some(error) = session.failure() {
        panic!("the session reported a failure it survived: {error}");
    }
    let _ = session.shutdown().await;
}

/// Half-closing the uplink reaches the destination, and its EOF ends the tunnel.
///
/// The client seals an authenticated `close_notify` and nothing else
/// (`application_io.rs:994-1015`); the node reads that alert by its description
/// alone, flushes staged bytes and shuts its destination write half
/// (`server/vision.rs:1116-1125`), so the echo sees a real EOF. Draining then
/// terminates only if the node also closes the downlink it owns. A client that
/// sent a bare FIN, or dropped the tail behind it, hangs or truncates here.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn half_close_reaches_the_destination_and_ends_the_tunnel() {
    let mut session = session_to_echo().await;

    let tail = b"last word\n";
    session.write_all(tail).await.expect("write the tail");
    session
        .shutdown()
        .await
        .expect("half-close the uplink with an authenticated alert");

    let mut echoed = Vec::new();
    tokio::time::timeout(READ_TIMEOUT, session.read_to_end(&mut echoed))
        .await
        .expect("the node must close the downlink once the destination is closed")
        .expect("drain the downlink");
    assert_eq!(echoed, tail, "the bytes before a close must survive it");
    assert!(
        session.peer_closed(),
        "the node must end the downlink with an authenticated close_notify"
    );
    if let Some(error) = session.failure() {
        panic!("an orderly close is not a failure: {error}");
    }
}
