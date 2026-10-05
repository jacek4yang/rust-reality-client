//! Interoperability gate against an unmodified `rust-reality` v2.0.1 server.
//!
//! These tests talk to a live node rather than to a fixture of our own making,
//! which is the only way to prove the `ClientHello` bytes are what the server
//! parses rather than what we assumed it parses. They are `#[ignore]`d because
//! they need the server, and the server needs a TLS 1.3 cover:
//!
//! ```text
//! scripts/interop/upstream-server.sh   # cover + echo + faults + TLS origins + v2.0.1 entry
//! set -a; . target/interop/handoff.env; set +a
//! cargo test --test interop_v201 -- --ignored --test-threads=1
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rust_reality_client::config;
use rust_reality_client::error::{Error, Failure, SessionError};
use rust_reality_client::handoff::{Established, FIRST_BYTE_BUDGET, Handoff};
use rust_reality_client::inbound::http;
use rust_reality_client::inbound::socks5::{Outcome, Proxy};
use rust_reality_client::inbound::{
    Establish, Establishment, Gate, MAX_CONCURRENT_HANDSHAKES, MAX_LOCAL_CONNECTIONS,
};
use rust_reality_client::protocol::reality::{
    AuthPlaintext, CLIENT_VERSION, ClientKeyAgreement, Handshake, Negotiated, X25519_GROUP,
    X25519_MLKEM768_GROUP, build_client_hello, complete,
};
use rust_reality_client::protocol::vless::Destination;
use rust_reality_client::scheduler::{Policy, Scheduler};
use rust_reality_client::transport::{
    AddressFamily, Applied, Dial, DialPolicy, Downlink, Environment, KEEPALIVE_COUNT,
    KEEPALIVE_INTERVAL, Transferred, Tuning, VisionSession, carry, configure, probe,
};
use socket2::SockRef;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
/// The three TLS 1.3 suites this client offers.
const OFFERED_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// A budget for work that includes a real handshake while other connections are
/// competing for the same node.
const LIVE_BUDGET: Duration = Duration::from_secs(30);
/// How long the fixture's `late` destination stays silent, which is the shape of
/// every slow server this client has to survive rather than a protocol constant.
const DESTINATION_DELAY: Duration = Duration::from_secs(3);
/// The earliest a round trip through that destination can honestly finish, less the
/// slack a measured wall clock is owed.
const DESTINATION_FLOOR: Duration = DESTINATION_DELAY.saturating_sub(Duration::from_millis(250));
/// The keepalive idle this client sets, and therefore the quiet an established
/// tunnel has to outlast before it can be called stable. Spelled from the crate's
/// own constant so this file cannot drift away from what the shipped sockets ask
/// for: a test that hard-codes thirty seconds passes on a client that changed it.
const KEEPALIVE_IDLE: Duration = rust_reality_client::transport::KEEPALIVE_IDLE;
/// The whole burst the `truncate` destination sends before it resets.
const DESTINATION_BURST: usize = 64 * 1024;
/// Concurrent local connections the storm test opens through one live node.
const STORM: usize = 24;
/// The soak window, unless `RRC_SOAK_SECONDS` says otherwise.
const DEFAULT_SOAK_SECONDS: u64 = 20;
/// Descriptors a soak window is allowed to be holding at the end that it was not
/// holding at the start.
///
/// The long-lived session and its node socket account for two of them; the rest is
/// the runtime's own pipes. Anything that scales with the connection count is a leak,
/// and a window of this size would show it many times over.
const DESCRIPTOR_SLACK: usize = 16;

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
    target("RRC_INTEROP_ECHO")
}

/// One of the fixture's loopback destinations, read the same way every time.
///
/// These are addresses the **node** dials, not this process, which is why they come
/// from the handoff file rather than from a listener in the test.
fn target(name: &str) -> (Destination, u16) {
    let endpoint = parameter(name);
    let (host, port) = endpoint.rsplit_once(':').expect("target is host:port");
    let port = port.parse().expect("target port is a number");
    Destination::parse(host, port).unwrap_or_else(|| panic!("{name} is not a legal destination"))
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
    // The client's own data-socket policy, called rather than re-typed here: a
    // harness that tuned its tunnel differently from the production dial path
    // would measure the harness, and an option the harness forgot would make any
    // later claim about options surviving a crossing false in the same way for
    // both the honest and the broken client.
    configure(&stream).unwrap_or_else(|error| panic!("tuning the tunnel to {address}: {error}"));
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
/// claim — the round trips prove the framed uplink, the node's `End` decision
/// once its nested-TLS detector gives up on traffic that is not TLS at all
/// (`server/vision.rs:1374-1390`), which stops framing but keeps sealing outer
/// records, and that no byte was altered, duplicated or reordered across either
/// layout. The two transitions are separate tests, not one: see
/// [`a_tls_1_3_destination_ends_framing_and_the_record_layer_too`].
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

/// A session quiet past its own keepalive window still carries bytes.
///
/// The wait is real wall time on purpose. `relay`'s own test parks a relay for
/// two hours on a mocked clock and can only show that *this client* arms no
/// read-idle timer; whether the connection survives the window its socket option
/// defines is a question about a kernel and a peer, so it is asked of a kernel and
/// a peer. The pause is the whole detection window — 30 s of silence, then three
/// probes ten seconds apart — plus five seconds of margin, which puts at least
/// three probes each way on the wire before anything is asked of the tunnel.
///
/// This is the measurement that separates the two mechanisms the brief insists on
/// keeping apart: an idle path that answers its probes is a live path, and the
/// age of a connection is not evidence about it.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and costs ~65 seconds"]
async fn a_session_quiet_past_its_keepalive_window_still_carries_bytes() {
    let mut session = session_to_echo().await;

    let before = b"before the quiet\n";
    session.write_all(before).await.expect("first write");
    let mut answered = vec![0_u8; before.len()];
    tokio::time::timeout(READ_TIMEOUT, session.read_exact(&mut answered))
        .await
        .expect("the echo answers before the quiet")
        .expect("read the first reply");
    assert_eq!(
        answered, before,
        "the session was working when it went quiet"
    );

    let window = KEEPALIVE_IDLE + KEEPALIVE_INTERVAL * KEEPALIVE_COUNT + Duration::from_secs(5);
    let started = Instant::now();
    tokio::time::sleep(window).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= window,
        "the quiet has to be real time, not a mocked clock: it lasted {elapsed:?}"
    );

    let after = b"after the quiet\n";
    session
        .write_all(after)
        .await
        .expect("write after the quiet");
    let mut still = vec![0_u8; after.len()];
    tokio::time::timeout(READ_TIMEOUT, session.read_exact(&mut still))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the tunnel went silent for {elapsed:?} and never answered again; \
                 a keepalive window is meant to detect a dead peer, not to end a \
                 quiet one"
            )
        })
        .expect("read the reply after the quiet");
    assert_eq!(
        still, after,
        "a session that stayed quiet for {elapsed:?} must still carry bytes"
    );
    if let Some(error) = session.failure() {
        panic!(
            "the quiet cost this session something: {error}\n\
             it was idle for {elapsed:?} against a {window:?} detection window"
        );
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

/// The relay over a real tunnel, including the half-close contract.
///
/// This is the production shape: [`establish`](Handoff::establish) on one side of
/// an application socket, a [`VisionSession`] on the other, and nothing between
/// them but [`carry`](rust_reality_client::transport::carry). The application
/// finishes sending first, which must reach the echo as an EOF *and* must not stop
/// the reply from coming back — the two properties the relay exists for, now
/// proven against the node's own close handling rather than against a socket of
/// our own making.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn the_relay_carries_and_half_closes_through_v201() {
    let dial = Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    );
    let handoff = Handoff::new(configured_node(), dial);
    let (destination, port) = echo_target();
    let Established { session, .. } =
        tokio::time::timeout(READ_TIMEOUT * 3, handoff.establish(&destination, port))
            .await
            .expect("establishment must finish inside the budget")
            .unwrap_or_else(|error| panic!("establishment through v2.0.1 failed: {error}"));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener for the application");
    let address = listener.local_addr().expect("local address");
    let mut app = TcpStream::connect(address)
        .await
        .unwrap_or_else(|error| panic!("connecting to the relay at {address}: {error}"));
    let (mut local, _) = listener.accept().await.expect("accept the application");

    let payload: Vec<u8> = (0..=250_u8)
        .collect::<Vec<_>>()
        .iter()
        .copied()
        .cycle()
        .take(40 * 1024)
        .collect();
    let moved = u64::try_from(payload.len()).expect("a test payload fits a u64");

    let relay = tokio::spawn(async move {
        let mut session = session;
        let counts = carry(&mut local, &mut session)
            .await
            .expect("the relay must end without an i/o error");
        (counts, session.failure())
    });

    app.write_all(&payload).await.expect("upload");
    app.shutdown()
        .await
        .expect("half-close the application side");
    let mut echoed = Vec::new();
    tokio::time::timeout(READ_TIMEOUT * 2, app.read_to_end(&mut echoed))
        .await
        .expect("the echo must return inside the budget")
        .expect("drain the application socket");
    assert_eq!(
        echoed, payload,
        "the relay altered, dropped or reordered bytes across the tunnel"
    );

    let (counts, learned) = relay.await.expect("the relay task finishes");
    assert_eq!(
        counts,
        Transferred {
            to_remote: moved,
            to_local: moved,
        },
        "and counted each direction as its own"
    );
    if let Some(error) = learned {
        panic!("the relay reported a failure it survived: {error}");
    }
}

/// The nested TLS client, as a child process pointed at this test's relay.
///
/// The application on the other side of the tunnel has to be a real TLS peer. A
/// client that keeps opening outer records after the node handed the direction
/// over raw does not hand us a byte to compare — it fails the peer's handshake,
/// and only OpenSSL can be the one to notice. The driver verifies the chain the
/// fixture's CA minted, checks the hostname, and walks the body byte for byte.
fn tls_driver(address: SocketAddr, expect_version: &str) -> tokio::process::Child {
    let python = std::env::var("RRC_INTEROP_PYTHON").unwrap_or_else(|_| "python3".to_string());
    tokio::process::Command::new(&python)
        .arg("scripts/interop/tls_client.py")
        .arg("--connect")
        .arg(address.to_string())
        .arg("--ca")
        .arg("target/interop/tls/ca.crt")
        .arg("--expect-version")
        .arg(expect_version)
        // Shorter than the relay's own budget on purpose: a tunnel that stops
        // delivering bytes must end with the peer's complaint in the report, not
        // with this test giving up on the peer.
        .arg("--timeout")
        .arg("20")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("starting {python} scripts/interop/tls_client.py: {error}"))
}

/// One `key=value` line from the driver's report.
fn report_field(report: &str, key: &str) -> u64 {
    let prefix = format!("{key}=");
    let line = report
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("the driver reported no {key}; its whole report was:\n{report}"));
    line[prefix.len()..]
        .parse()
        .unwrap_or_else(|error| panic!("{prefix} = {line:?} is not a number: {error}"))
}

/// What one nested handshake leaves behind, for the assertions to read.
///
/// Six separate things are being claimed about one crossing, and a tuple of six
/// positional values would make each claim's subject a matter of counting.
struct Crossing {
    /// Which transport state the downlink ended in: framed, outer-sealed, or raw.
    downlink: Downlink,
    /// The first failure the session latched, if any.
    failure: Option<Error>,
    /// What the production relay moved, per direction.
    counts: Transferred,
    /// The nested peer's own report, which is the verdict that matters.
    report: String,
    /// The tunnel socket's options, read back *before* the session took it.
    options_at_establishment: Applied,
    /// The same socket's options, read back *after* the crossing.
    options: Applied,
}

/// Carries one genuine nested TLS handshake through a live session and a live
/// node, and reports the shape the session's downlink ended up in.
///
/// The relay here is [`carry`], the same function the SOCKS5 and HTTP paths run,
/// so nothing about the transition is observed through a test-only reader.
///
/// The socket options are read twice off a second handle on the same socket,
/// taken before the session owns it: a Vision transition changes what the client
/// does with the socket, and if it ever replaced the socket to do it, the tuned
/// `TCP_NODELAY` and the armed probes would go with the old handle and the second
/// read would say so.
async fn nested_tls_handshake(origin: &str, expect_version: &str) -> Crossing {
    let (destination, port) = target(origin);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener for the nested client");
    let address = listener.local_addr().expect("local address");
    // Bound before the driver starts: its `connect` lands in the accept queue
    // while the tunnel is still being built, so there is nothing to race.
    let driver = tls_driver(address, expect_version);

    let (stream, handshake) = tunnel().await;
    let held = SockRef::from(&stream)
        .try_clone()
        .expect("a second handle on the tunnel socket");
    let options_at_establishment = probe(&held)
        .unwrap_or_else(|error| panic!("probe the tunnel socket as it is handed over: {error}"));
    let mut session = tokio::time::timeout(
        READ_TIMEOUT,
        VisionSession::connect(stream, handshake, user_id(), &destination, port),
    )
    .await
    .expect("the node must accept the request inside the budget")
    .unwrap_or_else(|error| panic!("Vision session to {origin} failed: {error}"));

    let (mut app, _) = tokio::time::timeout(READ_TIMEOUT, listener.accept())
        .await
        .expect("the driver must reach the relay inside the budget")
        .expect("accept the nested client");

    let carried = tokio::time::timeout(LIVE_BUDGET, carry(&mut app, &mut session)).await;
    let output = tokio::time::timeout(LIVE_BUDGET * 2, driver.wait_with_output())
        .await
        .expect("the driver must report inside its own budget")
        .expect("wait for the driver");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let latched = session
        .failure()
        .map_or_else(|| "nothing".to_string(), |error| error.to_string());
    let counts = match carried {
        Ok(Ok(counts)) => counts,
        Ok(Err(error)) => panic!(
            "the relay failed carrying a nested handshake: {error}\n\
             the session latched: {latched}\nthe driver said:\n{report}"
        ),
        Err(elapsed) => panic!(
            "the relay never finished inside the budget ({elapsed})\n\
             the session latched: {latched}\nthe driver said:\n{report}"
        ),
    };
    assert!(
        output.status.success(),
        "the nested handshake must succeed, and it is the claim this test makes.\n\
         the session latched: {latched}\nthe driver said:\n{report}"
    );
    let options = probe(&held).unwrap_or_else(|error| panic!("probe the tunnel socket: {error}"));
    Crossing {
        downlink: session.downlink(),
        failure: session.failure(),
        counts,
        report,
        options_at_establishment,
        options,
    }
}

/// The socket options every crossing must still show, whoever changed the mode.
///
/// Both transitions are handovers of the same five-tuple: the framing stops, or
/// the sealing stops, and in neither case is a new socket created. So the window
/// the dial layer armed is either still there or the transition replaced it, and
/// a session that quietly lost its probes would keep working right up until the
/// day it needed them.
///
/// The same read taken *before* the crossing is asserted too, and it is what makes
/// the claim above a claim rather than a tautology: without it, a tunnel that was
/// never tuned would fail nothing here, and the difference between "the client
/// arms keepalive and the transition keeps it" and "nobody ever armed it" would
/// fall out of the test instead of being measured.
fn assert_still_tuned(crossing: &Crossing, mode: &str) {
    assert!(
        crossing.options_at_establishment.keepalive && crossing.options_at_establishment.nodelay,
        "{mode}: the tunnel was never tuned, so the after-crossing reading says nothing \
         about the transition: {:?}",
        crossing.options_at_establishment
    );
    assert!(
        crossing.options.nodelay,
        "{mode}: the tunnel lost TCP_NODELAY at some point in the crossing: {:?}",
        crossing.options
    );
    assert!(
        crossing.options.keepalive,
        "{mode}: the tunnel lost its keepalive backstop at some point in the \
         crossing: {:?}",
        crossing.options
    );
    assert_eq!(
        crossing.options.retries,
        Some(KEEPALIVE_COUNT),
        "{mode}: the probe count on the tunnel is not the one this process ships"
    );
}

/// A TLS 1.3 destination: the node stops framing *and* stops sealing.
///
/// This is the case the brief calls decisive, because it is the case every long
/// lived WSS and SSE session is made of. The fixture's leaf is larger than one
/// 16 KiB record, so the origin's `Certificate` spans several
/// `application_data` records: the node classifies the `ServerHello` as TLS 1.3
/// and takes `Direct` at the first of them (`server/vision.rs:2156-2157`),
/// which leaves the rest of the handshake to travel as plaintext on a socket the
/// client is no longer allowed to decrypt (`:1411-1417`, `:1550-1558`). A client
/// that reads `Direct` as `End` opens those bytes as outer TLS records, fails
/// the AEAD, and loses the connection inside the application's own handshake —
/// which is why the verdict here is OpenSSL's, not a comparison we wrote.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its TLS origins"]
async fn a_tls_1_3_destination_ends_framing_and_the_record_layer_too() {
    let crossing = nested_tls_handshake("RRC_INTEROP_TLS13", "TLSv1.3").await;
    let report = crossing.report.as_str();

    assert!(
        report_field(&crossing.report, "leaf") > 16 * 1024,
        "the fixture leaf must exceed one TLS record, or the boundary would not \
         fall inside the handshake and this would prove much less:\n{report}"
    );
    assert_eq!(
        crossing.downlink,
        Downlink::Direct,
        "the session must have stopped opening records, not merely stopped framing:\n{report}"
    );
    assert_eq!(
        report_field(&crossing.report, "bytes"),
        64 * 1024,
        "and bytes kept flowing after the boundary, in the mode the transition left:\n{report}"
    );
    assert!(
        crossing.counts.to_local > 64 * 1024,
        "the flight and the body both came back down the tunnel, got {}",
        crossing.counts.to_local
    );
    assert!(
        crossing.counts.to_remote > 0,
        "and the client's own records reached the origin"
    );
    if let Some(error) = &crossing.failure {
        panic!("a handshake that completed is not a session failure: {error}");
    }
    assert_still_tuned(&crossing, "Direct");
}

/// A TLS 1.2 destination: framing ends, the record layer does not.
///
/// The other half of the same transition table. A non-1.3 `ServerHello` makes the
/// node write `End` (`server/vision.rs:2158`) and continue sealing outer records
/// whose plaintext is the origin's own TLS 1.2 record layer
/// (`DirectionState::Outer`, `:1842-1872`). Reading that stream as raw socket
/// bytes would hand the application ciphertext wrapped in ciphertext, so this is
/// not a compatibility nicety: it is the same state machine, opposite branch, and
/// the pair is what makes "stop framing" and "stop wrapping" one test each.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its TLS origins"]
async fn a_tls_1_2_destination_ends_framing_but_keeps_the_record_layer() {
    let crossing = nested_tls_handshake("RRC_INTEROP_TLS12", "TLSv1.2").await;
    let report = crossing.report.as_str();

    assert_eq!(
        crossing.downlink,
        Downlink::Outer,
        "a TLS 1.2 origin must leave the outer record layer standing:\n{report}"
    );
    assert_eq!(
        report_field(&crossing.report, "bytes"),
        64 * 1024,
        "and the framed-then-outer path must carry the whole body:\n{report}"
    );
    assert!(
        crossing.counts.to_local > 64 * 1024,
        "the flight and the body both came back down the tunnel, got {}",
        crossing.counts.to_local
    );
    if let Some(error) = &crossing.failure {
        panic!("a handshake that completed is not a session failure: {error}");
    }
    assert_still_tuned(&crossing, "Outer");
}

/// The live node, read through the client's own configuration validator.
///
/// Building it from a document rather than by hand keeps this a test of the shipped
/// path: what the handoff layer receives is exactly the `Node` an operator's file
/// produces, key encoding included.
fn configured_node() -> config::Node {
    let address = parameter("RRC_INTEROP_ADDR");
    let (host, port) = address
        .rsplit_once(':')
        .expect("the interop address carries a port");
    let port = port.parse::<u16>().expect("the interop port is a number");
    let text = format!(
        r#"[listen]
socks5 = "127.0.0.1:10808"
http = "127.0.0.1:10809"

[[node]]
name = "interop"
address = "{host}"
port = {port}
userId = "{}"
[node.reality]
publicKey = "{}"
shortId = "{}"
serverName = "{}"
"#,
        parameter("RRC_INTEROP_USER_ID"),
        parameter("RRC_INTEROP_PUBLIC_KEY"),
        parameter("RRC_INTEROP_SHORT_ID"),
        parameter("RRC_INTEROP_SERVER_NAME"),
    );
    let mut parsed = config::parse(&text)
        .unwrap_or_else(|error| panic!("the live node must be expressible as config: {error}"));
    parsed.nodes.remove(0)
}

/// The whole establishment path, end to end against v2.0.1.
///
/// This is the call an inbound will make: resolve, race candidates, authenticate the
/// peer as the configured REALITY server, send the VLESS request, and return a
/// session whose remote side already exists. The tests above prove the bytes; this
/// proves the composition — that the socket the dial layer hands over is the one the
/// handshake rides on, that the identity in a configuration file is the identity the
/// server accepts, and that what comes back carries timings worth trusting.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn the_handoff_layer_establishes_through_v201() {
    let dial = Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    );
    let handoff = Handoff::new(configured_node(), dial.clone());
    let (destination, port) = echo_target();

    let established = tokio::time::timeout(READ_TIMEOUT * 3, handoff.establish(&destination, port))
        .await
        .expect("establishment must finish inside the budget")
        .unwrap_or_else(|error| panic!("establishment through v2.0.1 failed: {error}"));

    check_negotiated(established.session.negotiated());
    assert_eq!(
        established.address.to_string(),
        parameter("RRC_INTEROP_ADDR"),
        "the winner must be the address the node was configured with"
    );
    assert_eq!(established.family, AddressFamily::Ipv4);
    assert!(
        established.connect_latency < FIRST_BYTE_BUDGET,
        "TCP to a local node cannot spend the whole first-byte budget: {:?}",
        established.connect_latency
    );
    assert!(
        established.total_latency >= established.connect_latency,
        "the whole call cannot be faster than the stage inside it"
    );

    // The shared beliefs, not a private copy: establishment is what teaches the
    // dial layer that this family works, and the next connection starts from it.
    assert!(
        dial.environment()
            .recent_latency(established.family, dial.tuning())
            .is_some(),
        "a winning connection must leave a latency the next dial can use"
    );
    assert!(
        !dial
            .environment()
            .is_penalized(established.family, dial.tuning()),
        "a node that answered cannot end up penalised for it"
    );

    let probe = b"established through the handoff layer\n";
    let mut session = established.session;
    session.write_all(probe).await.expect("write the probe");
    let mut echoed = vec![0_u8; probe.len()];
    tokio::time::timeout(READ_TIMEOUT, session.read_exact(&mut echoed))
        .await
        .expect("the echo must answer inside the budget")
        .expect("read the probe back");
    assert_eq!(echoed, probe);
}

/// Three establishments in a row over one dial, each through the full path.
///
/// v2.0.1 keeps a replay cache of authenticators, so a client that reused a
/// `ClientHello` would find its second connection silently served by the cover
/// target instead of the node. The handoff layer builds fresh key material per
/// attempt; this is the version of that claim a server can actually falsify.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn repeated_establishments_all_succeed_through_v201() {
    let dial = Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    );
    let (destination, port) = echo_target();

    for attempt in 1..=3 {
        let handoff = Handoff::new(configured_node(), dial.clone());
        let mut session =
            tokio::time::timeout(READ_TIMEOUT * 3, handoff.establish(&destination, port))
                .await
                .unwrap_or_else(|_| panic!("attempt {attempt} must finish inside the budget"))
                .unwrap_or_else(|error| panic!("attempt {attempt} must establish: {error}"))
                .session;

        let marker = format!("attempt {attempt}\n");
        session
            .write_all(marker.as_bytes())
            .await
            .expect("write the marker");
        let mut echoed = vec![0_u8; marker.len()];
        tokio::time::timeout(READ_TIMEOUT, session.read_exact(&mut echoed))
            .await
            .expect("the echo must answer inside the budget")
            .expect("read the marker back");
        assert_eq!(
            echoed,
            marker.as_bytes(),
            "attempt {attempt} did not reach the same destination"
        );
    }
}

/// One scheduler over two real nodes, the first of which cannot authenticate.
///
/// The wrong public key is the fault a client can be most sure of and least able to
/// see: the address answers, the port is open, the cover completes its own TLS — and
/// only the REALITY finish proves this is not the node. So every attempt against it
/// fails at the handshake, which is the family the breaker is owed, while the second
/// node keeps answering. The claim is the one the whole scheduler exists for: five
/// connections in a row, and not one of them is an error the application has to
/// handle.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn a_scheduler_routes_past_a_node_that_cannot_authenticate() {
    let dial = Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    );
    let live = configured_node();
    let mut broken = live.clone();
    broken.name = "broken".to_owned();
    broken.reality.public_key = [0x11; 32];

    let scheduler = Scheduler::new(
        vec![
            Handoff::new(broken, dial.clone()),
            Handoff::new(live, dial.clone()),
        ],
        vec!["broken".to_owned(), "live".to_owned()],
        Policy::default(),
    );
    let (destination, port) = echo_target();
    let mut asked = Vec::new();

    for attempt in 1..=5 {
        let mut session =
            tokio::time::timeout(READ_TIMEOUT * 3, scheduler.open(destination.clone(), port))
                .await
                .unwrap_or_else(|_| panic!("attempt {attempt} must finish inside the budget"))
                .unwrap_or_else(|error| panic!("attempt {attempt} must establish: {error}"))
                .session;

        check_negotiated(session.negotiated());
        let marker = format!("attempt {attempt}\n");
        session
            .write_all(marker.as_bytes())
            .await
            .expect("write the marker");
        let mut echoed = vec![0_u8; marker.len()];
        tokio::time::timeout(READ_TIMEOUT, session.read_exact(&mut echoed))
            .await
            .expect("the echo must answer inside the budget")
            .expect("read the marker back");
        assert_eq!(echoed, marker.as_bytes());

        let health = &scheduler.report()[0].health;
        asked.push(health.successes + health.failures + u64::from(health.hedge_losses));
    }

    let report = scheduler.report();
    assert_eq!(report[0].health.successes, 0, "it never authenticated");
    assert_eq!(
        report[1].health.successes, 5,
        "every connection was served, whichever node was asked first"
    );
    assert!(
        report[1].primary,
        "and the route ended on the node that answers: {report:?}"
    );
    // What moves the route is the measurement, not the refusal: the broken node spends a
    // handshake failing, so it never has a latency to claim, and the node that answers in
    // seventeen milliseconds takes the lead on the guards the plan sets. Once it has, the
    // broken node is not asked at all — which is the whole point, because being asked
    // costs this client a hedge delay on every connection.
    assert!(
        report[0]
            .health
            .last_failure
            .is_none_or(Failure::counts_against_node),
        "whatever it was charged was about the node: {:?}",
        report[0].health.last_failure
    );
    assert!(
        asked.windows(2).all(|pair| pair[1] >= pair[0]),
        "a node is only ever asked more, never forgiven backwards: {asked:?}"
    );
    assert_eq!(
        *asked.last().expect("five attempts were counted"),
        asked[1],
        "by the third connection the node that cannot authenticate stopped being asked: \
         {asked:?}"
    );
}

/// One real SOCKS5 exchange, end to end through an unmodified v2.0.1 node.
///
/// The client half is hand-written bytes rather than this crate's own codec,
/// because the claim being tested is about what an application sees: a greeting
/// answered as SOCKS5 answers it, a `CONNECT` accepted with a bound address that is
/// this process's own, and then the application's payload coming back through the
/// node. Everything between the reply and the bytes is the shipped path —
/// [`Proxy::handle`], [`Handoff`], and [`carry`](rust_reality_client::transport::carry).
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn a_socks5_connect_is_tunneled_through_v201() {
    let dial = Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    );
    let proxy = Proxy::new(Handoff::new(configured_node(), dial), Gate::default());
    let (destination, port) = echo_target();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener for the SOCKS5 client");
    let bound = listener.local_addr().expect("local address");
    let mut client = TcpStream::connect(bound)
        .await
        .unwrap_or_else(|error| panic!("connecting as a SOCKS5 client to {bound}: {error}"));
    let (mut served, _peer) = listener.accept().await.expect("accept the client");

    let exchange = tokio::spawn(async move { proxy.handle(&mut served, bound).await });

    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("send the greeting");
    client.flush().await.expect("flush the greeting");
    let mut selection = [0_u8; 2];
    tokio::time::timeout(READ_TIMEOUT, client.read_exact(&mut selection))
        .await
        .expect("the greeting is answered inside the budget")
        .expect("read the method selection");
    assert_eq!(
        selection,
        [0x05, 0x00],
        "a client is told which method it is speaking, in the field it reads"
    );

    client
        .write_all(&connect_request(&destination, port))
        .await
        .expect("send the CONNECT");
    client.flush().await.expect("flush the CONNECT");
    let mut reply = [0_u8; 10];
    tokio::time::timeout(READ_TIMEOUT * 3, client.read_exact(&mut reply))
        .await
        .expect("the node answers inside the budget")
        .expect("read the reply");
    assert_eq!(
        reply[..4],
        [0x05, 0x00, 0x00, 0x01],
        "version, success, reserved, then an IPv4 bound address"
    );
    assert_binds_to(&reply, bound);

    let probe = b"socks5 through an unmodified v2.0.1 node\n";
    client.write_all(probe).await.expect("send the payload");
    let mut echoed = vec![0_u8; probe.len()];
    tokio::time::timeout(READ_TIMEOUT, client.read_exact(&mut echoed))
        .await
        .expect("the echo answers inside the budget")
        .expect("read the payload back");
    assert_eq!(
        echoed, probe,
        "the tunnel altered or reordered application bytes"
    );

    client
        .shutdown()
        .await
        .expect("half-close from the application side");
    let outcome = tokio::time::timeout(READ_TIMEOUT, exchange)
        .await
        .expect("the exchange ends once both directions have")
        .expect("the serving task does not panic");
    let moved = u64::try_from(probe.len()).expect("a test payload fits a u64");
    assert_eq!(
        outcome,
        Outcome::Carried(Transferred {
            to_remote: moved,
            to_local: moved,
        }),
        "the exchange reports exactly what it carried, in each direction"
    );
}

/// One real HTTP `CONNECT` exchange, end to end through an unmodified v2.0.1 node.
///
/// Same rule as the SOCKS5 exchange above: the client half is hand-written bytes,
/// because the claim is about what an application sees. This one also proves the
/// property that decides how `src/inbound/http.rs` reads at all — the application's
/// first bytes are sent **before** the answer is read, in the same write, and they
/// still arrive. A head parser that read in blocks and threw away what it over-read
/// would echo nothing here, and the read would time out.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn an_http_connect_is_tunneled_through_v201() {
    let dial = Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    );
    let proxy = http::Proxy::new(Handoff::new(configured_node(), dial), Gate::default());
    let (destination, port) = echo_target();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener for the HTTP client");
    let bound = listener.local_addr().expect("local address");
    let mut client = TcpStream::connect(bound)
        .await
        .unwrap_or_else(|error| panic!("connecting as an HTTP client to {bound}: {error}"));
    let (served, _peer) = listener.accept().await.expect("accept the client");

    let exchange = tokio::spawn(async move { proxy.handle(served).await });

    let probe = b"CONNECT head and payload in one write\n";
    let mut sent = connect_head(&destination, port);
    sent.extend_from_slice(probe);
    client
        .write_all(&sent)
        .await
        .expect("send the head and the payload");
    client.flush().await.expect("flush both");

    let mut answer = [0_u8; ESTABLISHED.len()];
    tokio::time::timeout(READ_TIMEOUT * 3, client.read_exact(&mut answer))
        .await
        .expect("the node answers inside the budget")
        .expect("read the whole status line and its blank line");
    assert_eq!(
        &answer, ESTABLISHED,
        "a tunnel is confirmed with 200 and nothing else, so the payload is not read as a body"
    );

    let mut echoed = vec![0_u8; probe.len()];
    tokio::time::timeout(READ_TIMEOUT, client.read_exact(&mut echoed))
        .await
        .expect("the echo answers inside the budget")
        .expect("read the payload back");
    assert_eq!(
        echoed, probe,
        "the bytes sent ahead of the answer were lost"
    );

    client
        .shutdown()
        .await
        .expect("half-close from the application side");
    let outcome = tokio::time::timeout(READ_TIMEOUT, exchange)
        .await
        .expect("the exchange ends once both directions have")
        .expect("the serving task does not panic");
    let moved = u64::try_from(probe.len()).expect("a test payload fits a u64");
    assert_eq!(
        outcome,
        http::Outcome::Carried(Transferred {
            to_remote: moved,
            to_local: moved,
        }),
        "the exchange reports exactly what it carried, in each direction"
    );
}

/// The request body a SOCKS5 client sends for `CONNECT`, in the form its
/// destination requires.
fn connect_request(destination: &Destination, port: u16) -> Vec<u8> {
    let mut request = vec![0x05_u8, 0x01, 0x00];
    match destination {
        Destination::Domain(host) => {
            let length = u8::try_from(host.len()).expect("a real host name fits one byte");
            request.extend([0x03, length]);
            request.extend(host.as_bytes());
        }
        Destination::IPv4(octets) => {
            request.push(0x01);
            request.extend(octets);
        }
        Destination::IPv6(octets) => {
            request.push(0x04);
            request.extend(octets);
        }
    }
    request.extend(port.to_be_bytes());
    request
}

/// Checks the ten bytes after the greeting answer say this process's own socket,
/// which is the only address this client is entitled to report: what is on the far
/// side of the tunnel belongs to a node the application never named.
fn assert_binds_to(reply: &[u8], bound: SocketAddr) {
    let IpAddr::V4(address) = bound.ip() else {
        panic!("the listener was bound to loopback v4");
    };
    assert_eq!(reply[4..8], address.octets(), "BND.ADDR");
    assert_eq!(
        reply[8..10],
        bound.port().to_be_bytes(),
        "BND.PORT must be the port this listener owns, not the destination's"
    );
}

/// The exact answer a `CONNECT` on HTTP/1.1 is promised.
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// The head an HTTP client sends for `CONNECT`, with the target form its destination
/// requires — brackets for IPv6, because a colon inside an address is otherwise
/// ambiguous.
fn connect_head(destination: &Destination, port: u16) -> Vec<u8> {
    let host = match destination {
        Destination::Domain(host) => host.clone(),
        Destination::IPv4(octets) => Ipv4Addr::from(*octets).to_string(),
        Destination::IPv6(octets) => format!("[{}]", Ipv6Addr::from(*octets)),
    };
    format!("CONNECT {host}:{port} HTTP/1.1\r\n\r\n").into_bytes()
}

// ---------------------------------------------------------------------------
// The half of the matrix that only a live node can produce
// ---------------------------------------------------------------------------
//
// Everything above this line fails *before* the destination is involved, so a
// scripted seam can produce it. What follows happens beyond an authenticated
// session, where a fake would have to fabricate the very thing under test: the
// node's own connect to a destination, its relay of the destination's bytes, and
// the way it ends a tunnel when one of those goes wrong. The fixture therefore
// runs `fault_targets.py` on the node's own loopback, and each test below asserts
// what that arrangement actually produced.

/// A dial, built the way every shipped path builds it.
fn dial() -> Dial {
    Dial::new(
        Environment::detect(DialPolicy::Auto),
        Tuning::for_policy(DialPolicy::Auto),
    )
}

/// Opens one tunnel to a destination the **node** dials, through the shipped path.
async fn tunnel_to(name: &str) -> Result<Established, Error> {
    let (destination, port) = target(name);
    Handoff::new(configured_node(), dial())
        .establish(&destination, port)
        .await
}

/// Carries one marker through a live session and checks it comes back unchanged.
async fn round_trip(session: &mut VisionSession<TcpStream>, marker: &[u8]) {
    session
        .write_all(marker)
        .await
        .unwrap_or_else(|error| panic!("writing {marker:?} into a live tunnel: {error}"));
    let mut echoed = vec![0_u8; marker.len()];
    tokio::time::timeout(READ_TIMEOUT, session.read_exact(&mut echoed))
        .await
        .expect("the destination must answer inside the budget")
        .unwrap_or_else(|error| panic!("reading {marker:?} back: {error}"));
    assert_eq!(
        echoed, marker,
        "the tunnel altered or reordered application bytes"
    );
}

/// One local application socket, its bound address, and the task serving it.
///
/// The client half is written by hand in the tests that use this, because the claim
/// is always about what an application sees on its own socket.
async fn socks5_client<E: Establish>(
    proxy: &Proxy<E>,
) -> (TcpStream, SocketAddr, tokio::task::JoinHandle<Outcome>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener for the SOCKS5 client");
    let bound = listener.local_addr().expect("local address");
    let client = TcpStream::connect(bound)
        .await
        .unwrap_or_else(|error| panic!("connecting as a SOCKS5 client to {bound}: {error}"));
    let (mut served, _peer) = listener.accept().await.expect("accept the client");
    let proxy = proxy.clone();
    let exchange = tokio::spawn(async move { proxy.handle(&mut served, bound).await });
    (client, bound, exchange)
}

/// One complete SOCKS5 exchange against one of the fixture's destinations.
///
/// A failure anywhere in it panics rather than returning an error, which is what a
/// storm or a soak wants: an application-visible refusal is a test failure, not a
/// number to be tallied and explained afterwards.
async fn socks5_round_trip<E: Establish>(proxy: &Proxy<E>, name: &str) -> Outcome {
    let (destination, port) = target(name);
    let (mut client, bound, exchange) = socks5_client(proxy).await;

    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("send the greeting");
    let mut selection = [0_u8; 2];
    tokio::time::timeout(LIVE_BUDGET, client.read_exact(&mut selection))
        .await
        .expect("the greeting is answered inside the budget")
        .expect("read the method selection");
    assert_eq!(
        selection,
        [0x05, 0x00],
        "no method but the loopback one is offered"
    );

    client
        .write_all(&connect_request(&destination, port))
        .await
        .expect("send the CONNECT");
    let mut reply = [0_u8; 10];
    tokio::time::timeout(LIVE_BUDGET, client.read_exact(&mut reply))
        .await
        .expect("the node answers inside the budget")
        .expect("read the reply");
    assert_eq!(
        reply[..4],
        [0x05, 0x00, 0x00, 0x01],
        "a tunnel is confirmed with 0x00"
    );
    assert_binds_to(&reply, bound);

    let probe = b"round trip through a live node\n";
    client.write_all(probe).await.expect("send the payload");
    let mut echoed = vec![0_u8; probe.len()];
    tokio::time::timeout(READ_TIMEOUT, client.read_exact(&mut echoed))
        .await
        .expect("the destination answers inside the budget")
        .expect("read the payload back");
    assert_eq!(
        echoed, probe,
        "the tunnel altered or reordered application bytes"
    );

    client
        .shutdown()
        .await
        .expect("half-close from the application side");
    tokio::time::timeout(LIVE_BUDGET, exchange)
        .await
        .expect("the exchange ends once both directions have")
        .expect("the serving task does not panic")
}

/// Counts the tunnels a seam opens, while opening exactly what the real seam opens.
///
/// The immutability rule is a claim about *calls*: once a local client has been told
/// a session exists, nothing beyond it may cause another one. The only way to prove
/// that against a real node is to count.
#[derive(Clone)]
struct Counted {
    inner: Handoff,
    opens: Arc<AtomicUsize>,
}

impl Counted {
    /// Wraps the live handoff and hands back the counter it increments.
    fn new(inner: Handoff) -> (Self, Arc<AtomicUsize>) {
        let opens = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner,
                opens: Arc::clone(&opens),
            },
            opens,
        )
    }
}

impl Establish for Counted {
    fn establish(&self, destination: Destination, port: u16) -> Establishment {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let inner = self.inner.clone();
        Box::pin(async move { inner.establish(&destination, port).await })
    }
}

/// A destination that is not listening at all, as the node leaves it.
///
/// This is the failure an operator notices first and understands least: the tunnel
/// authenticated, so nothing is wrong with the node or the route, and yet no
/// connection can be made. v2.0.1 answers it by closing the tunnel without ever
/// writing a response header, which the client must read as silence in tens of
/// milliseconds rather than as a budget it has to wait out.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its fault targets"]
async fn a_destination_that_is_down_fails_fast_and_leaves_the_node_usable() {
    let started = Instant::now();
    let error = tunnel_to("RRC_INTEROP_CLOSED")
        .await
        .expect_err("nothing listens at that port, so no tunnel can honestly be promised");
    let took = started.elapsed();

    assert!(
        matches!(error, Error::Session(SessionError::ClosedBeforeResponse)),
        "v2.0.1 closes a tunnel whose destination refused, without answering: {error}"
    );
    assert!(
        took < FIRST_BYTE_BUDGET,
        "the node's own connect failed immediately, so the client must not sit out its \
         whole silence budget: {took:?}"
    );
    assert!(
        error.classify().counts_against_node(),
        "a node that closes every attempt before answering is a bad path, and no client \
         can tell that apart from a destination that was simply down"
    );

    // The verdict is about one destination, not about the node: the next connection
    // to a destination that exists must still be served.
    let mut session = tunnel_to("RRC_INTEROP_ECHO")
        .await
        .expect("the node must still serve a destination that is there")
        .session;
    round_trip(&mut session, b"the node is still usable\n").await;
}

/// A destination that accepts, says nothing, and closes.
///
/// The node has already promised the tunnel by the time this happens, so the only
/// honest answer left is the end of the stream. A client that turned this into an
/// error, or retried it elsewhere, would be reporting a fault of its own making.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its fault targets"]
async fn a_destination_that_hangs_up_without_a_word_arrives_as_an_end_of_stream() {
    let mut session = tunnel_to("RRC_INTEROP_DROP")
        .await
        .expect("the node reached the destination, so the tunnel was promised honestly")
        .session;

    let mut received = Vec::new();
    let read = tokio::time::timeout(READ_TIMEOUT, session.read_to_end(&mut received))
        .await
        .expect("the destination's close must reach the client inside the budget");
    let bytes = read.unwrap_or_else(|error| panic!("an orderly close is not an error: {error}"));

    assert_eq!(bytes, 0, "that destination never sent a byte");
    assert!(received.is_empty(), "the client may not invent a payload");
    assert!(
        session.peer_closed(),
        "the node ends the downlink with an authenticated close_notify"
    );
    assert!(
        session.failure().is_none(),
        "a destination that chose to stop talking is not a broken tunnel"
    );
}

/// A destination that resets instead of closing.
///
/// The same end, arriving as a reset rather than a `FIN`. It must not be mistaken
/// for an orderly close — an application that saw zero bytes and a clean end would
/// believe the transfer finished.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its fault targets"]
async fn a_destination_that_resets_reaches_the_application_as_a_failure() {
    let mut session = tunnel_to("RRC_INTEROP_RST")
        .await
        .expect("the node reached the destination before it reset")
        .session;

    // Whether the reset arrives before or after the client's first write is a race
    // between two directions of one tunnel, and the answer is the same either way.
    let _ = session.write_all(b"reset target\n").await;
    let mut received = Vec::new();
    let read = tokio::time::timeout(READ_TIMEOUT, session.read_to_end(&mut received))
        .await
        .expect("the reset must reach the client inside the budget");

    assert!(
        read.is_err(),
        "a reset cannot be read as an orderly close: {read:?}"
    );
    assert!(
        !session.peer_closed(),
        "there was no close_notify to wait for, so the tunnel ended by force"
    );
    assert!(
        session.failure().is_some(),
        "the failure is recorded for the log whatever the read happened to return"
    );
}

/// A download that dies partway, on a tunnel the application was told exists.
///
/// This is the live proof of the rule the whole crate is built on. The `0x00` reply
/// has been sent, bytes have arrived, and then the destination resets: nothing may
/// re-dial, replay, or quietly try a second tunnel to finish what the first one
/// started. So the seam is counted, and exactly one open is expected for one local
/// connection — the failure is handed to the application, not repaired.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its fault targets"]
async fn a_session_that_dies_mid_download_is_reported_and_never_retried() {
    let (counted, opens) = Counted::new(Handoff::new(configured_node(), dial()));
    let proxy = Proxy::new(counted, Gate::default());
    let (destination, port) = target("RRC_INTEROP_TRUNCATE");
    let (mut client, bound, exchange) = socks5_client(&proxy).await;

    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("send the greeting");
    let mut selection = [0_u8; 2];
    tokio::time::timeout(LIVE_BUDGET, client.read_exact(&mut selection))
        .await
        .expect("the greeting is answered inside the budget")
        .expect("read the method selection");
    assert_eq!(selection, [0x05, 0x00]);

    client
        .write_all(&connect_request(&destination, port))
        .await
        .expect("send the CONNECT");
    let mut reply = [0_u8; 10];
    tokio::time::timeout(LIVE_BUDGET, client.read_exact(&mut reply))
        .await
        .expect("the node answers inside the budget")
        .expect("read the reply");
    assert_eq!(
        reply[..4],
        [0x05, 0x00, 0x00, 0x01],
        "the tunnel is promised before the destination's trouble begins"
    );
    assert_binds_to(&reply, bound);

    // Only now does the application ask for anything, because the destination sends its
    // burst once it has a byte to answer — and dies partway through delivering it.
    client
        .write_all(b"send me the burst\n")
        .await
        .expect("send the request");

    let outcome = tokio::time::timeout(LIVE_BUDGET, exchange)
        .await
        .expect("the exchange ends once the tunnel does")
        .expect("the serving task does not panic");
    assert!(
        matches!(outcome, Outcome::Failed(_)),
        "a download that dies mid-flight is a failure the application sees, not a \
         silence and not a success: {outcome:?}"
    );

    // Whatever of the burst arrived is what the application keeps, and it cannot have
    // been more than the destination wrote: the client invents no bytes. Whether the
    // reset cut the tail or landed behind a burst that loopback had already copied into
    // the receiver's buffers is the operating system's business, so the count is
    // reported rather than pinned. What this connection is being tested on is that the
    // death reached the application and that nothing was re-dialled to hide it.
    let mut partial = Vec::new();
    let _ = client.read_to_end(&mut partial).await;
    assert!(
        partial.len() <= DESTINATION_BURST,
        "the application was handed {} bytes, more than the destination ever wrote",
        partial.len()
    );
    println!(
        "TRUNCATE: {} of {DESTINATION_BURST} burst bytes reached the application before \
         the reset, and the exchange still ended as a failure",
        partial.len()
    );

    assert_eq!(
        opens.load(Ordering::SeqCst),
        1,
        "one local connection, one tunnel: nothing was re-dialled to finish the download"
    );
    assert_eq!(
        proxy.gate().connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "and the failed exchange cost no capacity"
    );
    assert_eq!(
        proxy.gate().handshakes_available(),
        MAX_CONCURRENT_HANDSHAKES,
        "including the slot that authentication borrows"
    );
}

/// A destination that answers late, which is the ordinary case rather than a fault.
///
/// No userspace read-idle deadline may end a healthy authenticated connection, and
/// the destination's own slowness is exactly what such a deadline would kill. The
/// budget that applies here is the one for a node that never answers at all.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its fault targets"]
async fn a_destination_that_answers_late_is_not_torn_down() {
    let started = Instant::now();
    let mut session = tunnel_to("RRC_INTEROP_LATE")
        .await
        .expect("a slow destination is not a dead one")
        .session;

    let probe = b"answer whenever you can\n";
    session.write_all(probe).await.expect("write the probe");
    let mut echoed = vec![0_u8; probe.len() + 4];
    tokio::time::timeout(READ_TIMEOUT, session.read_exact(&mut echoed))
        .await
        .expect("the client must outwait the destination's own silence")
        .expect("read the reply");
    assert_eq!(&echoed[..4], b"LATE", "the destination's bytes come first");
    assert_eq!(&echoed[4..], probe);

    let took = started.elapsed();
    assert!(
        took >= DESTINATION_FLOOR,
        "the reply cannot arrive before the destination woke up: {took:?}"
    );
    assert!(
        took < FIRST_BYTE_BUDGET,
        "and waiting out a slow server must cost strictly less than the budget for a \
         node that never answers: {took:?}"
    );
}

/// The same tunnel, used again after more quiet than the keepalive idle.
///
/// NAT boxes drop an idle mapping well inside a minute, which is the whole reason
/// this client sets keepalive at all. The claim is the operator-facing one: a
/// connection held open for thirty-five seconds with nothing on it still carries
/// bytes, and the client did not need to re-establish anything to notice.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn an_idle_tunnel_survives_past_the_keepalive_idle() {
    let mut session = tunnel_to("RRC_INTEROP_ECHO")
        .await
        .expect("the tunnel is up before the quiet begins")
        .session;
    round_trip(&mut session, b"before the quiet\n").await;

    tokio::time::sleep(KEEPALIVE_IDLE + Duration::from_secs(5)).await;

    round_trip(&mut session, b"after the quiet\n").await;
    assert!(
        session.failure().is_none(),
        "a tunnel that answers after sitting idle was never broken"
    );
}

/// Twenty-four local connections at once, through one live node, over a scheduler
/// that is allowed to hedge.
///
/// The ceiling exists to be pressed: a localhost listener is not a trust boundary,
/// and the page load that opens thirty sockets is the normal case rather than an
/// attack. Every one of them must be answered, and none of them may cost the client
/// a slot it never gives back.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn a_storm_of_concurrent_connects_all_get_answered() {
    let node = configured_node();
    // A third node that cannot authenticate: a storm is when a client is most tempted
    // to route onto a broken path because it was the one that answered first somewhere.
    let mut broken = node.clone();
    broken.name = "broken".to_owned();
    broken.reality.public_key = [0x11; 32];
    let scheduler = Scheduler::new(
        vec![
            Handoff::new(node.clone(), dial()),
            Handoff::new(node, dial()),
            Handoff::new(broken, dial()),
        ],
        vec![
            "primary".to_owned(),
            "spare".to_owned(),
            "broken".to_owned(),
        ],
        Policy::default(),
    );
    let proxy = Proxy::new(scheduler.clone(), Gate::default());

    let mut tasks = Vec::with_capacity(STORM);
    for _connection in 0..STORM {
        let proxy = proxy.clone();
        tasks.push(tokio::spawn(async move {
            socks5_round_trip(&proxy, "RRC_INTEROP_ECHO").await
        }));
    }

    for task in tasks {
        match task.await.expect("a serving task does not panic") {
            Outcome::Carried(_) => {}
            other => panic!("a client with free capacity refused a local connection: {other:?}"),
        }
    }

    assert_eq!(
        proxy.gate().connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "every connection slot came back"
    );
    assert_eq!(
        proxy.gate().handshakes_available(),
        MAX_CONCURRENT_HANDSHAKES,
        "and so did every handshake slot, including the ones the hedge abandoned"
    );
    let report = scheduler.report();
    assert_eq!(
        report[2].health.successes, 0,
        "the node that cannot authenticate served nothing, however busy the client was"
    );
    let served: u64 = report.iter().map(|entry| entry.health.successes).sum();
    assert!(
        served >= u64::try_from(STORM).expect("a test count fits a u64"),
        "every connection was won by exactly one node, and a hedge that ran to \
         completion is counted too: {served}"
    );
    assert!(
        report[..2].iter().all(|entry| entry.health.failures == 0),
        "and none of it happened because a good node was charged for a bad one: {report:?}"
    );
}

/// How long the soak runs, which an operator may extend without editing a test.
fn soak_seconds() -> u64 {
    std::env::var("RRC_SOAK_SECONDS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(DEFAULT_SOAK_SECONDS)
}

/// The `p`th percentile of `samples` by nearest rank, which is the definition that
/// needs no floating point and no dependency.
///
/// Reported rather than asserted: what an operator reads off a soak is the shape of
/// the tail, and a test that failed because a machine had a slow moment is a test that
/// teaches nobody anything.
fn percentile(samples: &[Duration], percent: u64) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let ranked = &mut samples.to_vec();
    ranked.sort_unstable();
    let rank = (percent.saturating_mul(ranked.len() as u64))
        .div_ceil(100)
        .max(1);
    ranked[usize::try_from(rank - 1).unwrap_or(ranked.len() - 1)]
}

/// How many descriptors this process holds, where the kernel will say.
///
/// The one soak number that catches a connection that never closed: a session leaves
/// sockets behind, and a socket has a descriptor. Somewhere without `/proc` this is
/// `None` and the report prints `?` rather than a made-up zero.
fn descriptors() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc/self/fd")
            .map(std::iter::Iterator::count)
            .ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Resident memory in kilobytes, from the kernel's own accounting, and the thread
/// count beside it because both come out of the same file.
fn process_footprint() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/self/status").ok()?;
        let mut resident = None;
        let mut threads = None;
        for line in text.lines() {
            let Some((field, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match field {
                "VmRSS" => resident = value.split(' ').next()?.parse().ok(),
                "Threads" => threads = value.parse().ok(),
                _ => {}
            }
        }
        Some((resident?, threads?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// A sustained run, with the numbers an operator would ask for printed.
///
/// Attempts, successes and failures here are not tallied by the test: any
/// application-visible failure panics inside [`socks5_round_trip`], so reaching the
/// end of the window is itself the claim. What is checked at the end is the part a
/// soak exists to find — capacity that never came back, and a route that drifted off
/// the node that has been serving it.
#[tokio::test]
#[ignore = "requires a live rust-reality v2.0.1 server and its echo target"]
async fn a_soak_keeps_the_route_and_the_slots() {
    let window = Duration::from_secs(soak_seconds());
    let node = configured_node();
    let scheduler = Scheduler::new(
        vec![
            Handoff::new(node.clone(), dial()),
            Handoff::new(node, dial()),
        ],
        vec!["primary".to_owned(), "spare".to_owned()],
        Policy::default(),
    );
    let proxy = Proxy::new(scheduler.clone(), Gate::default());

    // One session held for the whole window, because a soak that only opens and
    // closes would never notice a long connection being dropped.
    let mut long_lived = tunnel_to("RRC_INTEROP_ECHO")
        .await
        .expect("the long-lived path is up before the window opens")
        .session;
    round_trip(&mut long_lived, b"soak opened\n").await;

    let started = Instant::now();
    let opened = descriptors();
    let before = process_footprint();
    let mut connections = 0_u64;
    let mut latencies: Vec<Duration> = Vec::new();
    let mut slowest = Duration::ZERO;
    let mut fastest = Duration::MAX;
    let mut bytes = 0_u64;
    while started.elapsed() < window {
        let attempt = Instant::now();
        match socks5_round_trip(&proxy, "RRC_INTEROP_ECHO").await {
            Outcome::Carried(moved) => bytes += moved.to_local,
            other => panic!("connection {connections} was not carried: {other:?}"),
        }
        let took = attempt.elapsed();
        fastest = fastest.min(took);
        slowest = slowest.max(took);
        latencies.push(took);
        connections += 1;
        if connections % 4 == 0 {
            round_trip(&mut long_lived, b"still here\n").await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let elapsed = started.elapsed();
    let closed = descriptors();
    let after = process_footprint();

    assert!(
        connections >= 5,
        "a window of {elapsed:?} must have carried real work, not one connection"
    );
    assert_eq!(
        proxy.gate().connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "{connections} connections in {elapsed:?} and the edge has every slot back"
    );
    assert_eq!(
        proxy.gate().handshakes_available(),
        MAX_CONCURRENT_HANDSHAKES,
        "the same for authentication, which is where a hedge leak would show up"
    );

    let report = scheduler.report();
    let primary = report
        .iter()
        .find(|entry| entry.primary)
        .expect("a scheduler that served connections has a primary");
    assert!(
        primary.health.successes > 0,
        "and it is the node that served them: {report:?}"
    );
    assert!(
        report.iter().all(|entry| entry.health.failures == 0),
        "no node was ever failed by this window: {report:?}"
    );

    // The leak question this window exists to answer. A tolerance rather than an
    // equality because the long-lived session, its node sockets and whatever the
    // runtime holds open are all alive at the sample; what must not happen is a
    // count that grows with the connections that ended.
    if let (Some(opened), Some(closed)) = (opened, closed) {
        assert!(
            closed <= opened + DESCRIPTOR_SLACK,
            "{connections} connections in {elapsed:?} left {closed} descriptors against \
             the {opened} this process held when the window opened"
        );
    }
    let hedges: u64 = report.iter().map(|entry| entry.health.hedges).sum();
    let wins: u64 = report.iter().map(|entry| entry.health.hedge_wins).sum();
    println!(
        "SOAK {elapsed:?}: {connections} connections, {bytes} bytes down, p50 {:?} \
         p95 {:?} p99 {:?} (fastest {fastest:?}, slowest {slowest:?}), hedged {hedges} \
         won {wins}, long-lived session still up, primary {} with {} successes and \
         {} failures",
        percentile(&latencies, 50),
        percentile(&latencies, 95),
        percentile(&latencies, 99),
        primary.name,
        primary.health.successes,
        primary.health.failures
    );
    match (opened, closed, before, after) {
        (Some(opened), Some(closed), Some((rss, threads)), Some((after_rss, after_threads))) => {
            println!(
                "SOAK footprint: descriptors {opened} -> {closed}, resident {rss} KiB -> \
                 {after_rss} KiB, threads {threads} -> {after_threads}"
            );
        }
        _ => println!("SOAK footprint: this platform does not report it"),
    }
}
