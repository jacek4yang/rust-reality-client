//! The accept loop, driven the way an application drives it: a real socket on a
//! loopback port, a real protocol exchange, and a `Report` at the end.
//!
//! Unit tests in [`rust_reality_client::serve`] check the shapes that fold into
//! one another. What only a live run can show is the two claims the loop exists to
//! keep:
//!
//! * every socket it took is counted exactly once, including the ones it was
//!   still waiting on when it was told to stop, and
//! * a node failure is answered with the closest thing to the truth that the
//!   protocol has, and is then *filed as a node failure* rather than as a
//!   protocol refusal — which is what keeps a broken path out of the rotation.
//!
//! Nothing here reaches a real server. The one node in every configuration is
//! `127.0.0.1:1`, which refuses TCP on every machine this runs on, so the
//! establishment path is exercised end to end and always fails the same way.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex};

use rust_reality_client::config;
use rust_reality_client::inbound::socks5::{
    COMMAND_NOT_SUPPORTED, GENERAL_FAILURE, NO_AUTH, SUCCEEDED, VERSION,
};
use rust_reality_client::logging::{Level, Logger};
use rust_reality_client::serve::{Report, Server};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// A logger that writes nowhere, so a test failure names the test rather than a
/// wall of expected noise about a dead node.
fn quiet() -> Logger {
    Logger::with_sink(Level::Error, Arc::new(Mutex::new(std::io::sink())))
}

/// A port the operating system says is free.
///
/// A declared listen address may not be port `0` — that would hand the operator a
/// port they cannot learn — so a test has to ask for one and then use it.
async fn free_port() -> u16 {
    let probe = StdListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("an ephemeral port is always grantable on loopback");
    let port = probe
        .local_addr()
        .expect("a bound listener knows its address")
        .port();
    drop(probe);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    port
}

/// One dead node and both edges, on the ports the caller chose.
fn configuration(socks5: u16, http: u16) -> String {
    format!(
        r#"[listen]
socks5 = "127.0.0.1:{socks5}"
http = "127.0.0.1:{http}"

[[node]]
name = "dead"
address = "127.0.0.1"
port = 1
userId = "00000000-0000-4000-8000-000000000000"

[node.reality]
publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
shortId = "abcd"
serverName = "www.example.com"
"#
    )
}

/// Binds the two edges and hands back the running server with its stop handle.
async fn serve(socks5: u16, http: u16) -> Server {
    let parsed =
        config::parse(&configuration(socks5, http)).expect("the test configuration is valid");
    Server::start(&parsed, quiet())
        .await
        .expect("both ports were just reported free")
}

/// Runs a SOCKS5 `CONNECT` for an IPv4 target and returns the reply bytes, empty
/// if the proxy closed instead of answering.
async fn socks5_exchange(proxy: SocketAddr, command: u8, target: [u8; 4], port: u16) -> Vec<u8> {
    let mut stream = TcpStream::connect(proxy).await.expect("the listener is up");
    stream
        .write_all(&[VERSION, 1, NO_AUTH])
        .await
        .expect("the greeting goes out");
    stream.flush().await.expect("a greeting is not buffered");
    let mut selected = [0_u8; 2];
    stream
        .read_exact(&mut selected)
        .await
        .expect("the method selection comes before anything else");
    assert_eq!(
        selected,
        [VERSION, SUCCEEDED],
        "no authentication is offered and accepted"
    );
    let mut request = vec![VERSION, command, 0x00, 0x01];
    request.extend_from_slice(&target);
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .expect("the request goes out");
    stream.flush().await.expect("a request is not buffered");
    let mut reply = [0_u8; 22];
    let read = stream.read(&mut reply).await.unwrap_or(0);
    reply[..read].to_vec()
}

/// A node that refuses TCP is answered with a reply code and filed as a failure.
///
/// The distinction is the whole point of the accounting: `0x01` is what the
/// application sees, and the reason it sees it is recorded under `failed`, not
/// under `refused`, because `refused` is the counter for a request this edge
/// declined to act on at all. Folding the two together would tell the operator
/// that the local clients are misbehaving when the node is down.
#[tokio::test]
async fn a_dead_node_is_answered_and_filed_as_a_node_failure() {
    let socks5 = free_port().await;
    let http = free_port().await;
    let server = serve(socks5, http).await;
    let address = server.addresses()[0];
    let stop = server.shutdown();
    let running = tokio::spawn(server.run());

    let reply = socks5_exchange(address, 0x01, [203, 0, 113, 1], 80).await;
    assert_eq!(reply.len(), 10, "a SOCKS5 reply is a fixed five fields");
    assert_eq!(reply[0], VERSION, "the version echoes back");
    assert_eq!(
        reply[1], GENERAL_FAILURE,
        "a refused TCP connect has no better code, and inventing one would be a lie"
    );

    stop.request();
    let report = running.await.expect("the accept loop does not panic");
    assert_eq!(
        report,
        Report {
            accepted: 1,
            carried: 0,
            refused: 0,
            failed: 1,
            unresolved: 0,
        },
        "one socket in, one honest node failure out"
    );
}

/// A command this edge does not serve is declined before a node is asked anything.
#[tokio::test]
async fn a_command_this_edge_does_not_serve_is_declined_locally() {
    let socks5 = free_port().await;
    let http = free_port().await;
    let server = serve(socks5, http).await;
    let address = server.addresses()[0];
    let stop = server.shutdown();
    let running = tokio::spawn(server.run());

    // UDP ASSOCIATE, which v1 does not implement at all.
    let reply = socks5_exchange(address, 0x03, [203, 0, 113, 1], 80).await;
    assert_eq!(
        reply.get(1),
        Some(&COMMAND_NOT_SUPPORTED),
        "the one code that means 'this proxy does not do that', said before any dial"
    );

    stop.request();
    let report = running.await.expect("the accept loop does not panic");
    assert_eq!(
        report,
        Report {
            accepted: 1,
            carried: 0,
            refused: 1,
            failed: 0,
            unresolved: 0,
        },
        "a local decline is not evidence about a node"
    );
}

/// An HTTP client gets a status it can act on, and the failure is still filed
/// against the node.
#[tokio::test]
async fn a_dead_node_over_http_answers_a_status_and_fails_the_exchange() {
    let socks5 = free_port().await;
    let http = free_port().await;
    let server = serve(socks5, http).await;
    let addresses = server.addresses();
    assert_eq!(addresses.len(), 2, "both edges are enabled");
    let proxy = addresses[1];
    let stop = server.shutdown();
    let running = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(proxy)
        .await
        .expect("the HTTP edge is up");
    stream
        .write_all(b"CONNECT 203.0.113.1:80 HTTP/1.1\r\nHost: 203.0.113.1:80\r\n\r\n")
        .await
        .expect("the request goes out");
    stream.flush().await.expect("a request is not buffered");
    let mut head = [0_u8; 64];
    let read = stream.read(&mut head).await.expect("the proxy answers");
    let answer = String::from_utf8_lossy(&head[..read]).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 502"),
        "a gateway that could not reach the origin says 502, which is what a client \
         retries on: {answer}"
    );

    stop.request();
    let report = running.await.expect("the accept loop does not panic");
    assert_eq!(report.failed, 1, "the node failure is where it belongs");
    assert_eq!(report.carried, 0, "nothing was relayed");
    assert_eq!(report.accepted, 1, "one socket was taken");
}

/// A socket that was opened and never spoken on is still accounted for.
///
/// This is the claim [`Report::unresolved`] exists to keep: a connection task that
/// was cut off by shutdown is not silently dropped, because a run that ended with
/// tasks still in flight did not lose their outcomes. It costs the full
/// [`rust_reality_client::serve::SHUTDOWN_GRACE`] to prove, which is the price of
/// testing a bound rather than asserting a number.
#[tokio::test]
async fn a_socket_that_never_speaks_is_counted_as_unresolved() {
    let socks5 = free_port().await;
    let http = free_port().await;
    let server = serve(socks5, http).await;
    let address = server.addresses()[0];
    let stop = server.shutdown();
    let running = tokio::spawn(server.run());

    let silent = TcpStream::connect(address)
        .await
        .expect("the listener is up, and taking a socket is not the same as serving it");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    stop.request();
    let report = running.await.expect("the accept loop does not panic");
    assert_eq!(
        report,
        Report {
            accepted: 1,
            carried: 0,
            refused: 0,
            failed: 0,
            unresolved: 1,
        },
        "the socket was tracked, and it ended without an outcome of its own"
    );
    drop(silent);
}

/// The invariant an operator reads the report by: nothing is both counted and lost.
#[tokio::test]
async fn every_socket_taken_ends_up_in_exactly_one_counter() {
    let socks5 = free_port().await;
    let http = free_port().await;
    let server = serve(socks5, http).await;
    let address = server.addresses()[0];
    let stop = server.shutdown();
    let running = tokio::spawn(server.run());

    let first = socks5_exchange(address, 0x01, [203, 0, 113, 1], 80);
    let second = socks5_exchange(address, 0x03, [203, 0, 113, 1], 53);
    let (_, _) = tokio::join!(first, second);

    stop.request();
    let report = running.await.expect("the accept loop does not panic");
    assert_eq!(
        report.accepted,
        report.carried + report.refused + report.failed + report.unresolved,
        "{report:?}: a socket is either answered or reported as unfinished, never neither"
    );
    assert_eq!(report.accepted, 2, "both sockets were taken");
}

/// The addresses a server reports are the ones it was told to bind, in the order
/// the configuration declares them, and a run that was asked to stop before
/// anything arrived reports an empty table rather than a plausible-looking one.
#[tokio::test]
async fn a_binding_reports_the_addresses_it_was_given_in_order() {
    let socks5 = free_port().await;
    let http = free_port().await;
    let server = serve(socks5, http).await;
    let addresses = server.addresses();
    let expected: Vec<SocketAddr> = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks5),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), http),
    ];
    assert_eq!(
        addresses, expected,
        "socks5 is planned before http, and the ports are the ones declared"
    );
    assert_eq!(
        server.report(),
        Report::default(),
        "a server that has not run has served nothing"
    );
    assert!(
        server.gate().connections_available() > 0,
        "no socket is in flight, so every slot is free"
    );
    server.shutdown().request();
    let report = server.run().await;
    assert_eq!(report, Report::default(), "nothing arrived");
}
