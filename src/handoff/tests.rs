//! Establishment under failure: what each way a peer can refuse to work is
//! called, and what the scheduler may therefore conclude from it.
//!
//! These drive the real path — resolve, connect, build a `ClientHello`, write it,
//! wait — against loopback peers that misbehave in exactly one way each. The
//! claims are ones only a live socket can settle: that silence is reported as
//! silence and never as a refusal, that a peer which hangs up mid-handshake is
//! handshake evidence rather than connect evidence, that a request which cannot be
//! encoded costs no connection at all, and that nothing is reused between attempts.
//!
//! The budget-shaped tests run on a paused clock, so fifteen seconds of silence is
//! observed rather than waited out.

use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{self, Instant as Timer};

use super::{
    FIRST_BYTE_BUDGET, Handoff, dial_failure, hello_failure, preflight, unix_seconds, write_failure,
};
use crate::config;
use crate::error::{Error, Failure, HandshakeError, SessionError};
use crate::protocol::reality::{CLIENT_VERSION, HelloError};
use crate::protocol::vless::Destination;
use crate::transport::{CONNECT_BUDGET, Dial, DialError, DialPolicy, Environment, Tuning};

/// A user id the fixture can name: it authenticates nothing on a loopback peer.
const USER: &str = "123e4567-e89b-12d3-a456-426614174000";

/// How long a misbehaving peer holds its end open while saying nothing.
const SILENCE: Duration = Duration::from_secs(3600);

/// A node pointing at loopback port `port`, read through the real validator.
///
/// Going through `config::parse` rather than building the struct by hand is
/// deliberate: the fixture has to be a configuration an operator could actually
/// write, or the test says nothing about the path a real one takes.
fn node(port: u16) -> config::Node {
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x09; 32]);
    let text = format!(
        r#"[listen]
socks5 = "127.0.0.1:10808"
http = "127.0.0.1:10809"

[[node]]
address = "127.0.0.1"
port = {port}
userId = "{USER}"
[node.reality]
publicKey = "{public_key}"
shortId = "abcd"
serverName = "www.example.com"
"#
    );
    let mut parsed = config::parse(&text).expect("the fixture must be a valid configuration");
    parsed.nodes.remove(0)
}

/// One handoff, with the same shared dial state a runtime would give it.
fn handoff(port: u16) -> Handoff {
    Handoff::new(
        node(port),
        Dial::new(
            Environment::detect(DialPolicy::Auto),
            Tuning::for_policy(DialPolicy::Auto),
        ),
    )
}

/// A peer that exists, so a node's `address:port` is a real destination.
async fn bound() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback test peer");
    let port = listener
        .local_addr()
        .expect("the test peer's own address")
        .port();
    (listener, port)
}

/// The destination every failure test asks for. It is never reached: whatever the
/// node does, or fails to do, happens first.
const TARGET: Destination = Destination::IPv4([192, 0, 2, 1]);

#[test]
fn a_dial_failure_is_scored_by_what_the_node_could_have_learned() {
    let refused = dial_failure(DialError::Failed {
        attempted: 2,
        error: io::Error::from(io::ErrorKind::ConnectionRefused),
    });
    let expired = dial_failure(DialError::TimedOut {
        budget: CONNECT_BUDGET,
    });
    let nothing = dial_failure(DialError::NoAddresses);

    // The node was contacted and either refused or never completed: both are its
    // own doing, and both belong in the family the scheduler dials down for.
    assert_eq!(refused.classify(), Failure::Connect);
    assert_eq!(expired.classify(), Failure::Connect);
    assert!(refused.classify().counts_against_node());
    assert!(expired.classify().counts_against_node());

    // A name with no address never reached a node at all, so no node may be marked
    // down for it. This is the one dial failure that is not evidence about a peer.
    assert_eq!(nothing.classify(), Failure::Local);
    assert!(
        !nothing.classify().counts_against_node(),
        "resolving to nothing must not be charged to a node: {nothing}"
    );

    assert_eq!(
        dial_failure(DialError::Lookup(io::Error::other(
            "the resolver had an error"
        )))
        .classify(),
        Failure::Dns
    );
    assert_eq!(
        dial_failure(DialError::LookupTimedOut).classify(),
        Failure::Dns,
        "a lookup that ran out of budget is still a lookup, not a dead node"
    );
}

#[test]
fn a_request_that_cannot_be_built_blames_nobody_but_us() {
    for error in [
        HelloError::InvalidServerName,
        HelloError::InvalidAlpn,
        HelloError::TooLarge,
        HelloError::NonContributory,
    ] {
        let mapped = hello_failure(error);
        assert_eq!(
            mapped.classify(),
            Failure::Local,
            "building failed with {error}, which sent no byte to any node"
        );
    }

    // Entropy is the operating system refusing, not the operator and not the peer.
    assert!(matches!(
        hello_failure(HelloError::Entropy),
        Error::Session(SessionError::Entropy)
    ));
    assert_eq!(
        hello_failure(HelloError::Entropy).classify(),
        Failure::Local
    );
}

#[test]
fn a_socket_that_closed_under_the_hello_is_a_handshake_failure() {
    for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::ConnectionReset] {
        let error = write_failure(io::Error::from(kind));
        assert_eq!(
            error.classify(),
            Failure::Handshake,
            "{kind:?} while handshaking"
        );
        assert!(
            matches!(error, Error::Handshake(HandshakeError::UnexpectedEof)),
            "a peer that closed must be reported as a handshake that did not finish"
        );
    }
    assert_eq!(
        write_failure(io::Error::from(io::ErrorKind::TimedOut)).classify(),
        Failure::Connect,
        "an operating-system failure that is not a closure is still an establishment failure"
    );
}

#[test]
fn a_destination_that_fits_the_wire_is_never_second_guessed() {
    assert!(preflight(&Destination::IPv4([203, 0, 113, 1])).is_ok());
    assert!(
        preflight(&Destination::IPv6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]))
        .is_ok()
    );
    assert!(preflight(&Destination::Domain("example.com".to_owned())).is_ok());
    assert!(preflight(&Destination::Domain("a".repeat(255))).is_ok());
}

#[test]
fn every_attempt_is_a_fresh_client_hello() {
    let handoff = handoff(443);
    let (first, _first_keys, _first_auth) = handoff.attempt().expect("a valid node builds a hello");
    let (second, _second_keys, _second_auth) = handoff
        .attempt()
        .expect("and builds it again for the next attempt");

    assert_ne!(
        first.random(),
        second.random(),
        "a repeated client_random repeats authenticator material the server tracks"
    );
    assert_ne!(
        first.record(),
        second.record(),
        "the hello message must be rebuilt for each attempt, never resent"
    );
}

#[test]
fn the_authenticator_carries_the_configured_identity_and_this_clock() {
    let handoff = handoff(443);
    let auth = handoff.authenticator();

    assert_eq!(CLIENT_VERSION, auth.version);
    assert_eq!(
        *node(443).reality.short_id(),
        auth.short_id,
        "the short ID selects which user the request is for, so it must be exactly what was configured"
    );

    let wall = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the test clock is after the epoch")
            .as_secs(),
    )
    .expect("the test clock fits a u32");
    // v2.0.1 compares this field against its own clock with a 60-second window, so
    // anything other than the current time is a rejected handshake waiting to
    // happen — and a rejection the node reports by serving its cover target, which
    // looks like reaching the wrong server.
    assert!(
        auth.time.abs_diff(wall) <= 2,
        "the authenticator must carry wall-clock time, got {} against {wall}",
        auth.time
    );
    assert_eq!(auth.time, unix_seconds());
}

#[tokio::test(start_paused = true)]
async fn an_impossible_destination_costs_no_connection() {
    let (listener, port) = bound().await;
    let error = handoff(port)
        .establish(&Destination::Domain("a".repeat(300)), 443)
        .await
        .expect_err("a domain longer than its one-byte length cannot be sent");

    assert!(
        matches!(error, Error::Session(SessionError::RequestTooLong)),
        "the encoder's own limit must be the reason given, got {error}"
    );
    assert_eq!(error.classify(), Failure::Local);
    assert!(
        !error.classify().counts_against_node(),
        "a request that could not be encoded says nothing about a node"
    );

    // Proving the claim rather than the wording: nothing reached the peer, because
    // the request was refused before a socket was opened for it.
    time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .expect_err("the peer must never have been contacted");
}

#[tokio::test]
async fn a_peer_that_hangs_up_mid_handshake_is_handshake_evidence() {
    let (listener, port) = bound().await;
    let peer = tokio::spawn(async move {
        let (stream, _address) = listener.accept().await.expect("accept");
        drop(stream);
    });

    let error = handoff(port)
        .establish(&TARGET, 443)
        .await
        .expect_err("a peer that closes the socket cannot complete a handshake");

    assert!(
        matches!(error, Error::Handshake(_)),
        "a hang-up during authentication is neither a connect failure nor a refusal: {error}"
    );
    assert_eq!(error.classify(), Failure::Handshake);
    assert!(error.classify().counts_against_node());
    peer.await
        .expect("the peer task finishes once it has closed the socket");
}

/// The handshake stage on its own, against a peer that never answers.
///
/// Driving [`Handoff::authenticate`] rather than [`Handoff::establish`] is what
/// makes the timing claim exact: the resolver's answer arrives on a blocking
/// thread, and on a paused clock the stages ahead of this one take mock time with
/// them, so an end-to-end measurement cannot pin one budget.
#[tokio::test(start_paused = true)]
async fn the_handshake_stage_spends_exactly_its_own_budget_on_silence() {
    let (listener, port) = bound().await;
    let peer = tokio::spawn(async move {
        let (stream, _address) = listener.accept().await.expect("accept");
        time::sleep(SILENCE).await;
        drop(stream);
    });
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect the silent peer");

    let began = Timer::now();
    let error = handoff(port)
        .authenticate(&mut stream)
        .await
        .expect_err("a peer that never answers must not be waited on forever");

    assert_eq!(
        began.elapsed(),
        FIRST_BYTE_BUDGET,
        "silence costs the first-byte budget and nothing else"
    );
    assert!(
        matches!(error, Error::Handshake(HandshakeError::Timeout)),
        "silence must be reported as silence, never as a refusal: {error}"
    );
    assert_eq!(error.classify(), Failure::Timeout);
    peer.abort();
}

#[tokio::test(start_paused = true)]
async fn a_silent_node_is_never_reported_as_a_refusal() {
    let (listener, port) = bound().await;
    let peer = tokio::spawn(async move {
        let (stream, _address) = listener.accept().await.expect("accept");
        // Connected and silent: what a REALITY node that fell back to its cover
        // target looks like from here, and the case upstream added
        // `firstByteTimeout` to notice at all.
        time::sleep(SILENCE).await;
        drop(stream);
    });

    let error = handoff(port)
        .establish(&TARGET, 443)
        .await
        .expect_err("a silent peer must not be waited on forever");

    assert!(
        matches!(error, Error::Handshake(HandshakeError::Timeout)),
        "a node that completed TLS and said nothing refused nothing: {error}"
    );
    assert_eq!(error.classify(), Failure::Timeout);
    peer.abort();
}
