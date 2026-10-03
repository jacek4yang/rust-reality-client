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
use rust_reality_client::inbound::{MAX_CONCURRENT_HANDSHAKES, MAX_LOCAL_CONNECTIONS};
use rust_reality_client::logging::{Level, Logger};
use rust_reality_client::serve::{MAX_PENDING_LOCAL, Report, Server};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{self, Duration};

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
            active: 0,
            panicked: 0,
            cancelled: 0,
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
            active: 0,
            panicked: 0,
            cancelled: 0,
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
            active: 0,
            panicked: 0,
            cancelled: 1,
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

/// Which edge a churn worker speaks.
#[derive(Clone, Copy)]
enum Edge {
    Socks5,
    Http,
}

/// A full SOCKS5 exchange that reports instead of asserting.
///
/// The tests below count answers across tens of thousands of sockets, so a helper
/// that panics on the eleven-thousandth one would report a lifecycle bug as a broken
/// assertion: what those tests claim is *how many* exchanges got an answer, and every
/// exchange has to be able to fail and be counted.
async fn socks5_answered(proxy: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect(proxy).await else {
        return false;
    };
    if stream.write_all(&[VERSION, 1, NO_AUTH]).await.is_err() {
        return false;
    }
    if stream.flush().await.is_err() {
        return false;
    }
    let mut selected = [0_u8; 2];
    if stream.read_exact(&mut selected).await.is_err() {
        return false;
    }
    if selected != [VERSION, SUCCEEDED] {
        return false;
    }
    let mut request = vec![VERSION, 0x01, 0x00, 0x01];
    request.extend_from_slice(&[203, 0, 113, 1]);
    request.extend_from_slice(&80_u16.to_be_bytes());
    if stream.write_all(&request).await.is_err() {
        return false;
    }
    if stream.flush().await.is_err() {
        return false;
    }
    let mut reply = [0_u8; 22];
    match stream.read(&mut reply).await {
        Ok(read) => read >= 2 && reply[0] == VERSION,
        Err(_) => false,
    }
}

/// A full HTTP `CONNECT` that reports instead of asserting.
async fn http_answered(proxy: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect(proxy).await else {
        return false;
    };
    let request = b"CONNECT 203.0.113.1:80 HTTP/1.1\r\nHost: 203.0.113.1:80\r\n\r\n";
    if stream.write_all(request).await.is_err() {
        return false;
    }
    if stream.flush().await.is_err() {
        return false;
    }
    let mut status = [0_u8; 9];
    match stream.read_exact(&mut status).await {
        Ok(_) => status == *b"HTTP/1.1 ",
        Err(_) => false,
    }
}

async fn answered(edge: Edge, proxy: SocketAddr) -> bool {
    match edge {
        Edge::Socks5 => socks5_answered(proxy).await,
        Edge::Http => http_answered(proxy).await,
    }
}

/// `total` exchanges, never more than `at_once` of them in flight, and how many of
/// them the edge answered.
///
/// The concurrency bound is the point of the shape: the connections are what an
/// ordinary browser tab finishes in an afternoon, and none of them is outstanding at
/// the same time as ten thousand others. A listener that cannot serve this is not
/// short of capacity, it is keeping a record of everything it ever served.
async fn churn(edge: Edge, proxy: SocketAddr, total: usize, at_once: usize) -> usize {
    let mut running = JoinSet::new();
    let mut started = 0;
    let mut served = 0;
    loop {
        while started < total && running.len() < at_once {
            started += 1;
            running.spawn(answered(edge, proxy));
        }
        let Some(done) = running.join_next().await else {
            break;
        };
        served += usize::from(done.expect("a churn worker does not panic"));
    }
    served
}

/// Greets a SOCKS5 listener and hands back the socket, without insisting the method
/// selection was a success.
///
/// Whether the selection says `0x00` or not is the *claim* some of these tests make;
/// a helper that asserted it would hide the answer it was supposed to reveal.
async fn greeted(proxy: SocketAddr) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await.ok()?;
    if stream.write_all(&[VERSION, 1, NO_AUTH]).await.is_err() {
        return None;
    }
    if stream.flush().await.is_err() {
        return None;
    }
    let mut selected = [0_u8; 2];
    if stream.read_exact(&mut selected).await.is_err() {
        return None;
    }
    Some(stream)
}

/// `count` sockets that greet and then wait, which is the shape of a connection that
/// is open and idle: once a tunnel is up, a WebSocket client asks for nothing until it
/// has something to say.
async fn park(proxy: SocketAddr, count: usize) -> Vec<TcpStream> {
    let mut parked = Vec::with_capacity(count);
    for index in 0..count {
        let stream = greeted(proxy)
            .await
            .unwrap_or_else(|| panic!("parked socket {index} was not greeted at all"));
        parked.push(stream);
    }
    parked
}

/// Asks an already-greeted socket to connect somewhere, and says whether it answered.
async fn request(stream: &mut TcpStream) -> bool {
    let mut request = vec![VERSION, 0x01, 0x00, 0x01];
    request.extend_from_slice(&[203, 0, 113, 1]);
    request.extend_from_slice(&80_u16.to_be_bytes());
    if stream.write_all(&request).await.is_err() {
        return false;
    }
    if stream.flush().await.is_err() {
        return false;
    }
    let mut reply = [0_u8; 22];
    match stream.read(&mut reply).await {
        Ok(read) => read >= 2 && reply[0] == VERSION,
        Err(_) => false,
    }
}

/// What the edge did with a socket that greeted and asked to be served.
enum Reception {
    /// It took the socket and answered it.
    Answered,
    /// It closed the socket without answering, which is what a refusal looks like
    /// from outside the process.
    TurnedAway,
    /// Neither happened inside the window: the socket is still queued in the kernel
    /// behind the ones this test opened before it.
    HasNotArrived,
}

/// One greeting, classified by how the edge responded to it.
async fn reception(proxy: SocketAddr, window: Duration) -> Reception {
    let Ok(mut stream) = TcpStream::connect(proxy).await else {
        return Reception::TurnedAway;
    };
    if stream.write_all(&[VERSION, 1, NO_AUTH]).await.is_err() {
        return Reception::TurnedAway;
    }
    let mut selected = [0_u8; 2];
    match time::timeout(window, stream.read_exact(&mut selected)).await {
        Err(_) => Reception::HasNotArrived,
        Ok(Err(_)) => Reception::TurnedAway,
        Ok(Ok(_)) => {
            if selected == [VERSION, SUCCEEDED] {
                Reception::Answered
            } else {
                Reception::TurnedAway
            }
        }
    }
}

/// Waits for the listener to answer a socket again.
///
/// This is a bound on a real property rather than a pause: a socket turned away
/// because the table was full has to become a served socket once the table drains, and
/// the only honest way to ask whether that happened is to keep asking until a deadline.
/// The deadline is what makes the test fail instead of hang.
async fn served_again(proxy: SocketAddr, within: Duration) {
    let started = time::Instant::now();
    let deadline = started + within;
    loop {
        match reception(proxy, Duration::from_millis(250)).await {
            Reception::Answered => return,
            Reception::TurnedAway | Reception::HasNotArrived => {
                assert!(
                    time::Instant::now() < deadline,
                    "the listener never served a socket again, {} ms after the table it \
                     was full on had emptied",
                    started.elapsed().as_millis()
                );
            }
        }
    }
}

/// Ten thousand completed connections through each real listener, without restarting
/// anything in between.
///
/// This is the defect this test exists for. The tracked-task table used to be the
/// size of the connection *history* rather than the size of the connections, because
/// a finished task stops costing anything only when somebody reaps it — and the accept
/// loop did not reap while it was serving. At the baseline commit the listener takes
/// about [`MAX_PENDING_LOCAL`] sockets in its lifetime and then refuses every socket
/// that arrives after them, which is what a long-running client does to itself on a
/// day with a lot of page loads.
///
/// Four claims, all of them about the production path:
///
/// * every one of the 20,000 exchanges is answered, so the ceiling is a ceiling on
///   connections at once and not on connections ever;
/// * the sockets that were open and idle while 4,000 of them completed still get to
///   finish their own request, so reaching the ceiling does not evict a stream;
/// * both semaphore budgets are whole again when the run ends, so every permit that
///   was taken came back on its own path;
/// * the counters still reconcile, with nothing panicked and nothing tracked.
///
/// The idle sockets are asked *during* the churn rather than after it, and that is a
/// property of the edge rather than a concession: a socket that has greeted but not yet
/// asked for a tunnel is held for [`rust_reality_client::inbound::socks5::REQUEST_BUDGET`]
/// on purpose, because a localhost listener must not be kept open by a client that
/// stopped talking. Parking one for the whole 16-second run would measure that
/// deadline, not the lifecycle.
#[tokio::test]
async fn ten_thousand_connections_per_edge_do_not_wedge_the_listener() {
    const CHURN: usize = 10_000;
    const BEFORE_KEEPERS: usize = 2_000;
    const AT_ONCE: usize = 32;
    const PARKED: usize = 16;
    const IDLE_KEEPERS: usize = 4;

    let socks5 = free_port().await;
    let http = free_port().await;
    let server = serve(socks5, http).await;
    let addresses = server.addresses();
    assert_eq!(addresses.len(), 2, "both edges are exercised");
    let gate = server.gate().clone();
    let stop = server.shutdown();
    let running = tokio::spawn(server.run());

    // Open and idle before the churn, so an eviction has something to evict.
    let mut parked = park(addresses[0], PARKED).await;
    let mut served_socks5 = churn(Edge::Socks5, addresses[0], BEFORE_KEEPERS, AT_ONCE).await;
    let mut served_http = churn(Edge::Http, addresses[1], BEFORE_KEEPERS, AT_ONCE).await;
    assert_eq!(
        served_socks5, BEFORE_KEEPERS,
        "the first four thousand are past the point where the old table was full"
    );
    assert_eq!(served_http, BEFORE_KEEPERS, "on both edges");

    for keeper in parked.iter_mut().take(IDLE_KEEPERS) {
        assert!(
            request(keeper).await,
            "a connection that was idle through {} others is still a connection",
            2 * BEFORE_KEEPERS
        );
    }

    served_socks5 += churn(Edge::Socks5, addresses[0], CHURN - BEFORE_KEEPERS, AT_ONCE).await;
    served_http += churn(Edge::Http, addresses[1], CHURN - BEFORE_KEEPERS, AT_ONCE).await;
    assert_eq!(
        served_socks5, CHURN,
        "every SOCKS5 exchange got a reply, including the ones after the lifetime \
         limit the old table kept"
    );
    assert_eq!(
        served_http, CHURN,
        "and the same through the HTTP edge, on the same process"
    );

    drop(parked);

    stop.request();
    let report = running.await.expect("the accept loop does not panic");
    assert_eq!(
        report.active, 0,
        "nothing is tracked once every task has ended: the gauge counts what is live, \
         not what ever happened"
    );
    assert_eq!(report.panicked, 0, "and none of them panicked");
    assert_eq!(
        report.accepted,
        u64::try_from(2 * CHURN + PARKED).unwrap_or(u64::MAX)
    );
    assert_eq!(
        report.carried, 0,
        "the only node in this configuration refuses TCP"
    );
    assert_eq!(
        report.accepted,
        report.carried + report.refused + report.failed + report.unresolved,
        "{report:?}: twenty thousand and four failures and twelve hang-ups, each in \
         exactly one counter"
    );
    assert_eq!(
        report.failed,
        u64::try_from(2 * CHURN + IDLE_KEEPERS).unwrap_or(u64::MAX),
        "every exchange that asked the node for a tunnel was answered with a failure \
         code, the four idle sockets included"
    );
    assert_eq!(
        report.refused,
        u64::try_from(PARKED - IDLE_KEEPERS).unwrap_or(u64::MAX),
        "the rest of the idle sockets hung up without asking for anything, which is a \
         refusal this edge settled by itself"
    );
    assert_eq!(
        gate.connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "every local-connection permit came back"
    );
    assert_eq!(
        gate.handshakes_available(),
        MAX_CONCURRENT_HANDSHAKES,
        "and every handshake permit with it"
    );
}

/// A listener that filled up and then emptied serves the next socket.
///
/// The two halves are the same bug seen from either side. First, [`MAX_PENDING_LOCAL`]
/// sockets greet and hang up: each one is a task that finishes, and the accept loop is
/// then left with nothing to do but wait for the next connection — the quiet period
/// that used to be where finished tasks piled up unnoticed. Second, a socket arrives
/// after the quiet, and has to be served.
///
/// A refusal here would be the same permanent refusal the churn test catches, only
/// reached by idling instead of by load, which is why the wait is bounded by a deadline
/// the test reports when it loses.
#[tokio::test]
async fn a_listener_serves_the_next_socket_after_a_quiet_period() {
    const HISTORY: usize = MAX_PENDING_LOCAL + 6;

    let socks5 = free_port().await;
    let http = free_port().await;
    let server = serve(socks5, http).await;
    let address = server.addresses()[0];
    let gate = server.gate().clone();
    let stop = server.shutdown();
    let running = tokio::spawn(server.run());

    let row = {
        let mut row = Vec::with_capacity(HISTORY);
        for index in 0..HISTORY {
            let stream = greeted(address)
                .await
                .unwrap_or_else(|| panic!("socket {index} of the quiet row was never taken"));
            row.push(stream);
        }
        row
    };
    drop(row);

    served_again(address, Duration::from_secs(20)).await;
    stop.request();
    let report = running.await.expect("the accept loop does not panic");
    assert_eq!(report.active, 0, "the row left nothing being tracked");
    assert_eq!(report.panicked, 0);
    assert!(
        report.accepted > u64::try_from(HISTORY).unwrap_or(u64::MAX),
        "{report:?}: the row and the probes that waited for it to drain are all sockets \
         this loop took"
    );
    assert_eq!(
        report.accepted,
        report.carried + report.refused + report.failed + report.unresolved,
        "{report:?}: and every one of them is in exactly one counter"
    );
    assert_eq!(
        gate.connections_available(),
        MAX_LOCAL_CONNECTIONS,
        "a socket that hung up returns its permit, and so does a row of them"
    );
}
