//! Interoperability gate against an unmodified `rust-reality` v2.0.1 server.
//!
//! These tests talk to a live node rather than to a fixture of our own making,
//! which is the only way to prove the `ClientHello` bytes are what the server
//! parses rather than what we assumed it parses. They are `#[ignore]`d because
//! they need the server, and the server needs a TLS 1.3 cover:
//!
//! ```text
//! scripts/interop/upstream-server.sh          # starts cover + v2.0.1 entry
//! set -a; . target/interop/handoff.env; set +a
//! cargo test --test interop_v201 -- --ignored --test-threads=1
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rust_reality_client::protocol::reality::{
    AuthPlaintext, CLIENT_VERSION, ClientKeyAgreement, X25519_GROUP, X25519_MLKEM768_GROUP,
    build_client_hello, complete,
};
use tokio::io::AsyncWriteExt as _;
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

/// Performs one REALITY handshake and reports what the server negotiated.
async fn handshakes_once() -> (u16, u16, Option<Vec<u8>>) {
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

    let negotiated = handshake.negotiated();
    let outcome = (
        negotiated.suite.wire_value(),
        negotiated.key_share_group,
        negotiated.alpn.clone(),
    );
    drop(handshake);
    let _ = stream.shutdown().await;
    outcome
}

#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server"]
async fn reality_handshake_completes_against_v201() {
    let (suite, group, alpn) = handshakes_once().await;
    assert!(
        OFFERED_SUITES.contains(&suite),
        "the server selected a suite we never offered: {suite:#06x}"
    );
    assert!(
        group == X25519_GROUP || group == X25519_MLKEM768_GROUP,
        "the server selected a group we never shared: {group:#06x}"
    );
    if let Some(protocol) = &alpn {
        let claimed: &[u8] = protocol;
        assert!(
            ALPN.contains(&claimed),
            "the server claimed an ALPN we never offered"
        );
    }
}

/// Five independent handshakes, each with fresh key material.
///
/// v2.0.1 keeps a replay cache, so a client that reused an authenticator would
/// be silently pushed to the cover. This is also the smallest sample that would
/// catch a regression where only the first connection of a process works.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server"]
async fn repeated_handshakes_all_complete() {
    for attempt in 1..=5 {
        let (suite, _group, _alpn) = handshakes_once().await;
        assert!(
            OFFERED_SUITES.contains(&suite),
            "attempt {attempt} did not negotiate an offered suite: {suite:#06x}"
        );
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
