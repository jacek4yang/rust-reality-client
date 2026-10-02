//! Carrying one proxied connection's bytes, in both directions, until both end.
//!
//! [`carry`] is the longest-lived loop in this client. It starts when a tunnel is
//! accepted and finishes when the application's connection is over, which for a
//! download is measured in minutes rather than milliseconds. Everything it gets
//! wrong reaches the user as a `Connection error`, so the three properties below
//! are the whole design, and each is inherited from evidence rather than
//! invented.
//!
//! **Graceful half-close.** When one side stops sending, the other has to see the
//! end of that stream instead of a hang, while the reverse direction keeps
//! flowing. [`copy_bidirectional_with_sizes`] is exactly that state machine: EOF
//! on a reader shuts down the corresponding writer and stops reading that
//! direction, and the copy completes once *both* directions have shut down
//! (`TransferState::Running` → `ShuttingDown` → `Done`,
//! `tokio-1.53.1/src/io/util/copy_bidirectional.rs`). On the tunnel side that
//! shutdown is the authenticated path, because
//! [`VisionSession`](crate::transport::session::VisionSession)'s
//! [`poll_shutdown`](tokio::io::AsyncWrite::poll_shutdown) seals a
//! `close_notify` record before the socket's FIN. A browser that finishes its
//! request is therefore answered with a TLS alert the node can verify rather than
//! with a bare reset.
//!
//! **No idle deadline.** Nothing in this module arms a timer. v2.0.1's relay says
//! why in its own words — "Quiet reads are not stalled writes. TCP keepalive and
//! peer FIN govern raw lifetime, including when only the other direction moves"
//! (`src/transport/tcp_relay.rs:735-736`) — and its `copy_direction` "constructs
//! no timer at all" when no stall window is configured
//! (`src/transport/tcp_relay.rs:715`). A deadline that fires on a quiet but
//! live connection would close a working tunnel and force a fresh handshake that
//! can land on a different node, which is the opposite of what this client is for;
//! [`configure`](crate::transport::socket::configure) makes the dead ones
//! observable instead.
//!
//! **A fixed cost per connection.** One [`RELAY_BUFFER`]-sized buffer per
//! direction, allocated when the copy starts and reused for every chunk, so a
//! relay holds 16 KiB regardless of how much it moves. That is the number the
//! inbound's connection limits multiply against.
//!
//! [`carry`] never moves a session. Which node a connection belongs to is
//! settled before the first byte flows (see [`handoff`](crate::handoff)); by the
//! time this module is running, the pair of sockets is the connection.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional_with_sizes};

use crate::error::{Error, TransportError};

/// Bytes one direction of a relay moves at a time.
///
/// This is the copy primitive's own default (`DEFAULT_BUF_SIZE`,
/// `tokio-1.53.1/src/io/util/mod.rs:88`) and the size v2.0.1 frames Vision at
/// (`VISION_FRAME_SIZE`, `src/protocol/vless/vision.rs:6`), so a relay chunk is
/// also a session record: nothing is buffered here that the tunnel would have
/// split anyway.
pub const RELAY_BUFFER: usize = 8 * 1024;

/// What one relay carried before both directions closed.
///
/// The two counts are kept apart because the asymmetry is the diagnosis: a
/// session that moved 4 MB down and 200 bytes up was a download, and one that
/// moved nothing either way was refused or broken early.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Transferred {
    /// Bytes from the local connection into the tunnel.
    pub to_remote: u64,
    /// Bytes from the tunnel back to the local connection.
    pub to_local: u64,
}

/// Copies both directions of a proxied connection until both have shut down.
///
/// `local` is the socket the application owns and `remote` is the tunnel, which
/// for this client is always a
/// [`VisionSession`](crate::transport::session::VisionSession): the session's
/// reads unseal records and its writes seal them, so the bytes copied here are
/// exactly the bytes the application asked to have carried.
///
/// # Errors
///
/// Returns the first error either direction hits. An orderly end — one side
/// finishes sending, the other drains and finishes too — is `Ok`, never an error.
/// A direction that fails ends the copy immediately rather than waiting for its
/// sibling, which is what keeps a dead application socket from leaving this
/// future parked forever.
///
/// The [`io::Error`] says which system call failed and nothing about which side
/// of the relay it was on; [`verdict`] recovers the taxonomy, given what the
/// session latched.
pub async fn carry<L, R>(local: &mut L, remote: &mut R) -> Result<Transferred, io::Error>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (to_remote, to_local) =
        copy_bidirectional_with_sizes(local, remote, RELAY_BUFFER, RELAY_BUFFER).await?;
    Ok(Transferred {
        to_remote,
        to_local,
    })
}

/// Decides what a failed relay means.
///
/// [`carry`] can only report an [`io::Error`], so the taxonomy comes from the one
/// piece of context that survives that boundary: whether the session had already
/// latched a reason.
/// [`VisionSession`](crate::transport::session::VisionSession) records the first
/// failure it sees — framing, alerts, and its socket's own read and write errors
/// alike — and hands it back through
/// [`failure`](crate::transport::session::VisionSession::failure) for exactly
/// this call. A session with something to say was involved, and its verdict is
/// the one reported; a session with nothing to say never touched the failure,
/// which leaves the application's socket as the only other one here.
///
/// The split is what keeps a killed browser from being scored as a broken node.
/// Nothing inflates a node's failures here and nothing hides a real one: the two
/// families [`Failure::Idle`](crate::error::Failure::Idle) and
/// [`Failure::Local`](crate::error::Failure::Local) differ precisely in whether
/// the node is the one that did something.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn verdict(learned: Option<Error>, error: io::Error) -> Error {
    learned.unwrap_or_else(|| Error::Transport(TransportError::Local(error.to_string())))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::yield_now;
    use tokio::time;

    use super::*;
    use crate::error::{Failure, SessionError};

    /// The four sockets of one proxied connection: an application and an origin
    /// at the two ends, and the halves the relay holds between them.
    ///
    /// Both halves are real loopback TCP rather than in-memory pipes because the
    /// properties under test are FIN, half-close and chunk boundaries, and a pipe
    /// that cannot express them would prove nothing about a socket that does.
    struct Bridge {
        app: TcpStream,
        local: TcpStream,
        remote: TcpStream,
        origin: TcpStream,
    }

    /// Wires a bridge up, relay unstarted.
    async fn bridge() -> Bridge {
        let local = accept_one().await;
        let remote = accept_one().await;
        Bridge {
            app: local.0,
            local: local.1,
            remote: remote.1,
            origin: remote.0,
        }
    }

    /// Connects one loopback pair and returns `(client, accepted)`.
    async fn accept_one() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("local address");
        let client = TcpStream::connect(address).await.expect("connect");
        let (accepted, _) = listener.accept().await.expect("accept");
        (client, accepted)
    }

    /// Sends `payload`, half-closes, then returns everything read back.
    async fn speak(stream: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
        stream.write_all(payload).await.expect("write");
        stream.shutdown().await.expect("half close");
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("read to end");
        got
    }

    /// A payload whose bytes vary, so a relay that dropped, duplicated or
    /// reordered anything shows up as a mismatch rather than as a passing test.
    fn payload(length: usize) -> Vec<u8> {
        const PATTERN: [u8; 7] = [0x00, 0x21, 0xFF, 0x7F, 0xFE, 0x0A, 0x5A];
        PATTERN.iter().cycle().take(length).copied().collect()
    }

    /// A bulk transfer crosses the relay's buffer without losing or reordering a
    /// byte in either direction, and each direction is counted on its own.
    #[tokio::test]
    async fn a_transfer_larger_than_the_buffer_arrives_whole_and_is_counted_apart() {
        let Bridge {
            mut app,
            mut local,
            mut remote,
            mut origin,
        } = bridge().await;
        let upload = payload(600);
        let download = payload(200_000);

        let (counts, from_app, from_origin) = tokio::join!(
            carry(&mut local, &mut remote),
            speak(&mut app, &upload),
            speak(&mut origin, &download),
        );

        assert_eq!(
            counts.expect("both directions closed orderly"),
            Transferred {
                to_remote: 600,
                to_local: 200_000,
            },
            "each direction counts the bytes it actually moved"
        );
        assert_eq!(from_app, download, "the reply survives intact");
        assert_eq!(from_origin, upload, "the request survives intact");
    }

    /// The half-close contract, in order.
    ///
    /// The origin only sees EOF because the relay forwarded the application's FIN,
    /// and the application only sees the reply because the relay let the reverse
    /// direction keep flowing *after* it forwarded that FIN. Both are consequences
    /// of one another here: a relay that closed the whole connection on the first
    /// EOF, or that stopped polling once a direction finished, deadlocks this test
    /// instead of passing it.
    #[tokio::test]
    async fn a_half_close_is_forwarded_without_cutting_the_reverse_direction() {
        let Bridge {
            mut app,
            mut local,
            mut remote,
            mut origin,
        } = bridge().await;

        let (counts, reply, request) = tokio::join!(
            carry(&mut local, &mut remote),
            async {
                app.write_all(b"ping").await.expect("request");
                app.shutdown().await.expect("half close");
                let mut got = [0_u8; 4];
                app.read_exact(&mut got).await.expect("reply still flows");
                got
            },
            async {
                let mut got = Vec::new();
                origin
                    .read_to_end(&mut got)
                    .await
                    .expect("the FIN arrives as an end of stream");
                origin.write_all(b"pong").await.expect("reply");
                origin.shutdown().await.expect("half close");
                got
            },
        );

        assert_eq!(request, b"ping", "the request crossed before the FIN");
        assert_eq!(reply, *b"pong", "the reply crossed after it");
        assert_eq!(
            counts.expect("both directions closed orderly"),
            Transferred {
                to_remote: 4,
                to_local: 4,
            }
        );
    }

    /// A direction that fails ends the copy while its sibling is still parked.
    ///
    /// This is the difference between an error and a hang for the most common
    /// real failure: the application is gone, so nothing will ever make the local
    /// read ready again, and a copy that waited for both directions would sit on
    /// it until the process exits.
    #[tokio::test]
    async fn a_failing_direction_ends_the_copy_without_waiting_for_its_sibling() {
        let Bridge {
            mut app, mut local, ..
        } = bridge().await;
        // Reads forever pending, writes as a reset tunnel: a peer that is gone
        // without having said anything.
        let mut dead = DeadTunnel;

        app.write_all(b"one more chunk").await.expect("write");
        let error = carry(&mut local, &mut dead)
            .await
            .expect_err("a reset destination cannot be copied into");

        assert_eq!(
            error.kind(),
            io::ErrorKind::ConnectionReset,
            "the copy returns the failure rather than parking on the other side"
        );
    }

    /// What the session already knew outranks what the copy could say.
    #[test]
    fn the_reason_the_session_latched_is_the_reason_reported() {
        let learned = Error::Session(SessionError::RecordCorrupted);
        let decided = verdict(
            Some(learned.clone()),
            io::Error::from(io::ErrorKind::UnexpectedEof),
        );

        assert_eq!(decided, learned, "the first failure wins");
        assert_eq!(decided.classify(), Failure::Idle);
        assert!(decided.classify().counts_against_node());
    }

    /// A session that latched nothing was not involved, so the node is not blamed.
    #[test]
    fn a_socket_that_failed_on_the_application_side_teaches_the_node_nothing() {
        let decided = verdict(None, io::Error::from(io::ErrorKind::ConnectionReset));

        assert!(
            matches!(
                &decided,
                Error::Transport(TransportError::Local(message))
                    if message.contains("connection reset")
            ),
            "the local family carries the socket's own words: {decided}"
        );
        assert_eq!(
            decided.classify(),
            Failure::Local,
            "a browser that was closed is not a node that failed"
        );
        assert!(!decided.classify().counts_against_node());
        assert!(
            decided
                .to_string()
                .contains("local connection error: connection reset"),
            "and it reads as the local side: {decided}"
        );
    }

    /// Two hours of silence is not a failure, and the tunnel is still there after it.
    ///
    /// The clock is mocked, so the wait costs no wall time; what is being asserted
    /// is that the relay task is still parked rather than finished, and that a byte
    /// written afterwards still crosses in both directions. This is the mandated
    /// "no userspace read-idle timeout for healthy authenticated connections" as
    /// behaviour rather than as prose.
    #[tokio::test(start_paused = true)]
    async fn a_quiet_tunnel_is_left_alone_for_as_long_as_it_stays_quiet() {
        let Bridge {
            mut app,
            mut local,
            mut origin,
            mut remote,
        } = bridge().await;
        let relay = tokio::spawn(async move { carry(&mut local, &mut remote).await });

        time::sleep(Duration::from_secs(2 * 60 * 60)).await;
        yield_now().await;
        assert!(
            !relay.is_finished(),
            "two hours of silence must not end a live tunnel"
        );

        app.write_all(b"still here").await.expect("write");
        let mut crossed = [0_u8; 10];
        origin.read_exact(&mut crossed).await.expect("request");
        origin.write_all(b"yes").await.expect("reply");
        let mut back = [0_u8; 3];
        app.read_exact(&mut back).await.expect("reply flows");
        assert_eq!(&back, b"yes", "and it still carries bytes");

        app.shutdown().await.expect("half close");
        origin.shutdown().await.expect("half close");
        assert_eq!(
            relay.await.expect("relay task").expect("orderly end"),
            Transferred {
                to_remote: 10,
                to_local: 3,
            }
        );
    }

    /// A tunnel that is connected, silent, and never going to answer.
    struct DeadTunnel;

    impl AsyncRead for DeadTunnel {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            _buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl AsyncWrite for DeadTunnel {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            _payload: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
