//! The two options every data socket gets, and the reasoning that stops there.
//!
//! v2.0.1 applies `TCP_NODELAY` plus a keepalive backstop to *both* the sockets
//! it accepts and the sockets it dials (`src/transport/tcp.rs:356-360`,
//! `src/server/connector.rs:119,150,174,334`), and sets nothing else: no buffer
//! sizes, no TTL, no TCP fast open, no priority. A client that diverges in
//! either direction is a client whose connections behave differently from the
//! server's under the same network, which is exactly the kind of asymmetry that
//! turns into an unexplained `Connection error` at 3 a.m.
//!
//! Keepalive exists for one failure the application cannot see: a peer that dies
//! without sending a FIN. Without probes, that connection sits in the tunnel
//! forever, holding a node slot and a local socket. The window below is
//! deliberately shorter than the server's own 120 s write-stall bound
//! (`src/server/io_activity.rs:13-14`) — 30 s of silence plus three probes ten
//! seconds apart detects in about 60 s — and it is a *detection* budget, not a
//! transfer cap: a healthy bulk session that keeps sending is never interrupted,
//! because the idle clock only runs while nothing moves.
//!
//! There is no userspace read timeout in this client, deliberately. Upstream
//! leaves reads on an authenticated session untimed
//! (`src/protocol/tls13/idle.rs:1-7`) because a long-lived download is not a
//! fault, and because a timer that fires on a quiet-but-live connection would
//! close a working tunnel and force a *new* handshake that can land on a
//! different node. Stability is served by letting the kernel probes make the
//! dead connections observable, not by inventing an application deadline.

use std::io;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};

/// Silence before the first keepalive probe.
///
/// v2.0.1 `src/transport/tcp.rs:261` (`KEEPALIVE_IDLE`).
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);

/// Gap between unanswered probes.
///
/// v2.0.1 `src/transport/tcp.rs:263` (`KEEPALIVE_INTERVAL`).
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Unanswered probes before the kernel calls the peer dead.
///
/// v2.0.1 `src/transport/tcp.rs:265` (`KEEPALIVE_COUNT`).
pub const KEEPALIVE_COUNT: u32 = 3;

/// The shortest window a socket option can actually carry.
///
/// v2.0.1 `rr-linux/src/socket.rs:127-132` clamps every timer to at least one
/// second: the options are whole seconds in a C `int`, and a sub-second value
/// would become zero, which the kernel rejects. Clamping rather than failing is
/// what keeps a misconfigured budget a slowdown instead of an error.
const MINIMUM_WINDOW: Duration = Duration::from_secs(1);

/// Anything this module can borrow a socket handle from.
///
/// The handle trait is platform-specific — `AsFd` on Unix, `AsSocket` on
/// Windows — so the bound is spelled once here and both the standard library's
/// `TcpStream` and Tokio's satisfy it without either appearing in a signature.
/// The blanket implementation below means no type can join this trait on its
/// own: it is exactly "holds a TCP socket".
#[cfg(unix)]
pub trait SocketHandle: std::os::fd::AsFd {}

/// Anything this module can borrow a socket handle from.
///
/// See the Unix declaration, which this mirrors on the other platform.
#[cfg(windows)]
pub trait SocketHandle: std::os::windows::io::AsSocket {}

#[cfg(unix)]
impl<T: std::os::fd::AsFd> SocketHandle for T {}

#[cfg(windows)]
impl<T: std::os::windows::io::AsSocket> SocketHandle for T {}

/// Applies the shared data-socket options: `TCP_NODELAY` plus keepalive.
///
/// Both are set before any byte is written, because a socket that negotiates a
/// REALITY handshake in sixteen record-sized bursts is the one place where
/// `TCP_NODELAY` earns its keep, and because keepalive timers count from the
/// first silence rather than from the moment someone remembers to arm them.
///
/// # Errors
///
/// Returns the OS error from either `setsockopt`, which for a live TCP socket
/// means the handle is already gone. Callers classify that as a connection
/// failure, not a configuration failure.
pub fn configure<S: SocketHandle>(stream: &S) -> io::Result<()> {
    let socket = SockRef::from(stream);
    socket.set_tcp_nodelay(true)?;
    socket.set_tcp_keepalive(&keepalive(
        KEEPALIVE_IDLE,
        KEEPALIVE_INTERVAL,
        KEEPALIVE_COUNT,
    ))
}

/// What a live socket reports back about the options [`configure`] asked for.
///
/// Calling `setsockopt` and knowing the kernel holds the value are different
/// claims, and only the second one is worth a sentence in an operations
/// document: a platform that silently ignores `TCP_KEEPCNT`, or a handle that
/// was replaced since the call, both leave a connection whose probes arrive on a
/// schedule nobody chose. The three window fields are `None` where the platform
/// has no way to answer at all — `TCP_KEEPIDLE` and `TCP_KEEPINTVL` are not
/// Windows options — so the absence is recorded rather than guessed at.
///
/// Nothing in the relay calls this. It is the read-back the tests and the
/// operator-facing diagnostics use, and it costs two or four `getsockopt` calls
/// per socket, once.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Applied {
    /// `TCP_NODELAY`.
    pub nodelay: bool,
    /// `SO_KEEPALIVE`, which is what makes the window below reachable at all.
    pub keepalive: bool,
    /// Silence before the first probe, where the platform exposes it.
    pub idle: Option<Duration>,
    /// Gap between unanswered probes, where the platform exposes it.
    pub interval: Option<Duration>,
    /// Unanswered probes before the kernel gives up, where the platform exposes
    /// it.
    pub retries: Option<u32>,
}

/// Reads the options back off a live socket.
///
/// # Errors
///
/// Returns the OS error from `getsockopt` on `TCP_NODELAY` or `SO_KEEPALIVE`,
/// which on a live TCP handle means the socket is gone. A platform that has no
/// spelling for one of the three window values is not an error; it is a `None`.
///
/// # Examples
///
/// ```no_run
/// use std::net::TcpStream;
///
/// use rust_reality_client::transport::socket::{Applied, configure, probe};
///
/// let stream = TcpStream::connect("127.0.0.1:80").expect("a socket to ask");
/// configure(&stream)?;
/// let applied: Applied = probe(&stream)?;
/// assert!(applied.nodelay && applied.keepalive);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn probe<S: SocketHandle>(stream: &S) -> io::Result<Applied> {
    let socket = SockRef::from(stream);
    let mut applied = Applied {
        nodelay: socket.tcp_nodelay()?,
        keepalive: socket.keepalive()?,
        ..Applied::default()
    };
    #[cfg(unix)]
    {
        applied.idle = socket.tcp_keepalive_time().ok();
        applied.interval = socket.tcp_keepalive_interval().ok();
    }
    applied.retries = socket.tcp_keepalive_retries().ok();
    Ok(applied)
}

/// Builds the keepalive request from the three knobs, clamped to what a kernel
/// can represent.
fn keepalive(idle: Duration, interval: Duration, count: u32) -> TcpKeepalive {
    TcpKeepalive::new()
        .with_time(whole_seconds(idle))
        .with_interval(whole_seconds(interval))
        .with_retries(count)
}

/// Rounds a window up to the whole second the socket option carries.
fn whole_seconds(duration: Duration) -> Duration {
    Duration::from_secs(duration.as_secs().max(MINIMUM_WINDOW.as_secs()))
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use super::*;

    #[test]
    fn the_window_is_the_60_seconds_the_server_outlives() {
        // Detection must precede the node's own 120 s write-stall bound, or the
        // client learns about a dead peer second and loses the race for the
        // reason.
        let detection = KEEPALIVE_IDLE + KEEPALIVE_INTERVAL * KEEPALIVE_COUNT;
        assert_eq!(KEEPALIVE_IDLE, Duration::from_secs(30));
        assert_eq!(KEEPALIVE_INTERVAL, Duration::from_secs(10));
        assert_eq!(KEEPALIVE_COUNT, 3);
        assert_eq!(detection, Duration::from_secs(60));
        assert!(
            detection < Duration::from_secs(120),
            "detection has to precede the stall bound"
        );
    }

    #[test]
    fn a_sub_second_window_becomes_one_second_rather_than_zero() {
        assert_eq!(whole_seconds(Duration::ZERO), Duration::from_secs(1));
        assert_eq!(
            whole_seconds(Duration::from_millis(999)),
            Duration::from_secs(1)
        );
        assert_eq!(
            whole_seconds(Duration::from_millis(1500)),
            Duration::from_secs(1)
        );
        assert_eq!(
            whole_seconds(Duration::from_secs(30)),
            Duration::from_secs(30)
        );
    }

    /// The options are set on a real socket, and a real kernel accepts them.
    ///
    /// `TCP_KEEPCNT` is the one spelling that has not always existed on Windows,
    /// so this is the evidence that the request as built is accepted here rather
    /// than a compile-time guess about what the platform supports.
    #[test]
    fn a_live_socket_accepts_both_options() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("local address");
        let client = TcpStream::connect(address).expect("connect to the test listener");
        let (server, _) = listener.accept().expect("accept");

        configure(&client).expect("a live TCP socket accepts nodelay and keepalive");
        configure(&server).expect("the same options on the accepted half");
        assert!(client.nodelay().expect("readable"), "nodelay set");
    }

    /// The kernel holds the window it was asked for, and says so when read back.
    ///
    /// Both halves of a real loopback connection are probed, because the option
    /// that matters for a long-lived session is the one on the socket nobody is
    /// watching: the accepted half, whose peer is an application that may simply
    /// stop existing. What each platform can answer is a fact about the platform,
    /// so each is pinned here by what this host actually returned rather than by
    /// what the man page for the other one says.
    #[test]
    fn the_window_reads_back_off_both_halves_of_a_live_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("local address");
        let client = TcpStream::connect(address).expect("connect to the test listener");
        let (server, _) = listener.accept().expect("accept");

        for (which, stream) in [("dialed", &client), ("accepted", &server)] {
            configure(stream).unwrap_or_else(|error| panic!("configure the {which} half: {error}"));
            let applied =
                probe(stream).unwrap_or_else(|error| panic!("probe the {which} half: {error}"));
            assert!(applied.nodelay, "{which}: TCP_NODELAY reads back on");
            assert!(applied.keepalive, "{which}: SO_KEEPALIVE reads back on");
            assert_eq!(
                applied.retries,
                Some(KEEPALIVE_COUNT),
                "{which}: TCP_KEEPCNT reads back as the count we asked for"
            );
            #[cfg(unix)]
            {
                assert_eq!(
                    applied.idle,
                    Some(KEEPALIVE_IDLE),
                    "{which}: TCP_KEEPIDLE reads back as the idle we asked for"
                );
                assert_eq!(
                    applied.interval,
                    Some(KEEPALIVE_INTERVAL),
                    "{which}: TCP_KEEPINTVL reads back as the interval we asked for"
                );
            }
            #[cfg(windows)]
            {
                // Windows has no `getsockopt` spelling for either one; the values
                // were set through `SIO_TCP_SET` and stay unread. An option that
                // becomes readable here would mean this test is now lying about
                // what the platform refuses to say, so the absence is asserted.
                assert_eq!(applied.idle, None, "{which}: no idle read-back exists here");
                assert_eq!(
                    applied.interval, None,
                    "{which}: no interval read-back exists here"
                );
            }
        }
    }

    /// A socket that was never configured says so, and a configured one changes
    /// the answer.
    ///
    /// The negative half is what makes the positive half a measurement: without
    /// it, an always-`true` read-back would look identical to a working
    /// `setsockopt`.
    #[test]
    fn an_unconfigured_socket_reads_back_as_unconfigured() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("local address");
        let client = TcpStream::connect(address).expect("connect to the test listener");
        let (server, _) = listener.accept().expect("accept");

        let before = probe(&client).expect("probe before configuring");
        assert!(!before.keepalive, "a fresh socket has no probes armed");
        configure(&client).expect("configure");
        let after = probe(&client).expect("probe after configuring");
        assert!(after.keepalive && after.nodelay, "and now it does");
        drop(server);
    }

    /// The dial layer holds a Tokio stream, which is a different type over the
    /// same handle.
    #[tokio::test]
    async fn the_async_socket_type_takes_the_same_options() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("local address");
        let client = TcpStream::connect(address).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        server
            .set_nonblocking(true)
            .expect("non-blocking for the reactor");
        let stream = tokio::net::TcpStream::from_std(server).expect("register with the reactor");

        configure(&stream).expect("a Tokio socket takes the same options");
        assert!(stream.nodelay().expect("readable"));
        drop(client);
    }
}
