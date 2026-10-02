//! From one configured node to one live tunnel — the last moment a choice exists.
//!
//! [`Handoff`] is the whole of the establishment path: resolve the node's name,
//! connect a socket, authenticate it as *this* server, send the VLESS request, and
//! hand back a [`VisionSession`] that is already carrying a proxied connection. It
//! is also the outer bound of what this client is allowed to decide. v2.0.1 defines
//! no cross-node resume, so the instant [`VisionSession::connect`] returns `Ok`, the
//! destination is committed to that node and to that socket: nothing above this
//! module may retry, replay, or move it. Everything a hedge, a retry, or a failover
//! needs to do must therefore happen here, before the caller is told the tunnel
//! exists.
//!
//! Three properties the rest of the client depends on:
//!
//! * **A fresh identity per attempt.** Each call to [`Handoff::establish`] builds a
//!   new [`ClientKeyAgreement`] and therefore a new `ClientHello`. Reusing either
//!   one across attempts would repeat a key share and a `client_random` on the wire,
//!   which is both a fingerprint and, for REALITY, a replay of authenticator material
//!   the server tracks. So there is no place to cache a hello, and none is taken as
//!   an argument.
//! * **Nothing is spent on an impossible request.** A destination whose domain does
//!   not fit its one-byte wire length can never be sent, so [`Handoff::establish`]
//!   refuses it before opening a socket rather than paying a SYN and a full
//!   handshake for an error the encoder would raise anyway.
//! * **Budgets belong to the stage they bound.** [`crate::transport::CONNECT_BUDGET`]
//!   covers the whole candidate plan inside the dial layer; [`FIRST_BYTE_BUDGET`] is
//!   spent separately on the handshake and on the VLESS answer. A slow TCP connect
//!   therefore cannot eat the time the node needs to authenticate, and a node that
//!   authenticates but stays silent is reported as silence, not as a connect failure.
//!
//! What this module does *not* do: it adds no timeout of its own to a session that
//! has already been established. Once an [`Established`] is returned, only the
//! socket's own liveness decides whether the tunnel is up — see
//! [`crate::transport::socket`].

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::time;

use crate::config::Node;
use crate::error::{DnsError, Error, HandshakeError, SessionError, TransportError};
use crate::protocol::reality::{
    AuthKey, AuthPlaintext, CLIENT_VERSION, ClientKeyAgreement, Handshake, HelloError, HelloRecord,
    build_client_hello, complete,
};
use crate::protocol::vless::Destination;
use crate::transport::{AddressFamily, Dial, DialError, Dialed, VisionSession};

/// The ALPN protocols a REALITY client offers.
///
/// This is the list the live v2.0.1 interop gate negotiates against
/// (`tests/interop_v201.rs`), and the server may echo any one of it back or none:
/// it selects what its cover target supports, so offering a realistic pair is what
/// makes the handshake look like ordinary browser traffic. It is not a preference
/// the tunnel honours afterwards — nothing above this module speaks HTTP.
pub const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// How long one authenticated stage may stay silent before it is called a timeout.
///
/// v2.0.1 `src/config/node/outbound.rs:169`
/// (`DEFAULT_HANDOFF_FIRST_BYTE_TIMEOUT_MS`). Upstream applies that bound to the
/// first downlink byte after the request was written, which is how it notices a
/// *silent* rejection: a REALITY node that falls back to its cover target completes
/// the TLS layer and then never answers the VLESS request at all. The same ceiling
/// is applied here to each half of establishment, because each half ends in a byte
/// the client has to wait for: the server's first flight, then the `[0, 0]`
/// response.
///
/// Fifteen seconds is deliberately longer than [`crate::transport::CONNECT_BUDGET`]:
/// upstream's own note on the field says it must exceed the landing's authentication
/// and connect deadlines together, so that a slow-but-honest node is never reported
/// as a timeout while the budget that was actually spending itself belonged to
/// another stage.
pub const FIRST_BYTE_BUDGET: Duration = Duration::from_secs(15);

/// One node plus the shared dial state that reaches it.
///
/// The [`Dial`] is shared rather than owned, because the beliefs that make
/// establishment fast — which address family answers, which one is slow, what the
/// routes looked like last time — are process-wide. A handoff that started from
/// scratch would relearn the same broken path on every connection.
///
/// `Debug` is `Node`'s own redacting implementation: the user id is absent and the
/// short ID appears only as a length.
#[derive(Clone, Debug)]
pub struct Handoff {
    node: Node,
    dial: Dial,
}

impl Handoff {
    /// Binds one configured node to the dial state used across the process.
    #[must_use]
    pub fn new(node: Node, dial: Dial) -> Self {
        Self { node, dial }
    }

    /// The node this handoff serves, for logging and for the scheduler's bookkeeping.
    #[must_use]
    pub const fn node(&self) -> &Node {
        &self.node
    }

    /// Opens one tunnel to `destination`, from start to the node's acceptance.
    ///
    /// Returning `Ok` means the node answered the VLESS request, which v2.0.1 only
    /// does after it has connected to the destination itself. The returned
    /// [`Established`] is therefore a live path in both directions, and is the first
    /// point at which the answer "your connection is up" can honestly be given to a
    /// local client.
    ///
    /// Dropping the returned future anywhere inside this call abandons that node:
    /// the socket goes with it and nothing is marked as a failure of the peer. A
    /// caller that races several handoffs (the scheduler's hedge) relies on this, and
    /// on [`Dial`](crate::transport::Dial) recording a cancelled candidate as slowness
    /// rather than as a failure.
    ///
    /// # Errors
    ///
    /// Every failure is reported through [`Error`], whose [`Error::classify`] says
    /// whether the node was involved at all: resolution and policy-shaped failures
    /// come from the dial layer, handshake and silence failures from the TLS stage,
    /// and [`Error::Rejected`] only when the node actually refused. A destination that
    /// cannot be encoded is [`Error::Session(SessionError::RequestTooLong)`] and sends
    /// no byte whatsoever.
    pub async fn establish(
        &self,
        destination: &Destination,
        port: u16,
    ) -> Result<Established, Error> {
        preflight(destination)?;

        let started = Instant::now();
        let Dialed {
            value: mut stream,
            address,
            family,
            latency: connect_latency,
        } = self.dial_node().await?;

        let setup_started = Instant::now();
        let handshake = self.authenticate(&mut stream).await?;
        let answered = time::timeout(
            FIRST_BYTE_BUDGET,
            VisionSession::connect(stream, handshake, *self.node.user_id(), destination, port),
        )
        .await;
        let session = match answered {
            // The node completed TLS, took the VLESS request, and never said
            // whether it accepted. That is the silent rejection `firstByteTimeout`
            // exists to notice, and it is reported as silence rather than as the
            // refusal it may turn out to be.
            Err(_elapsed) => return Err(Error::Handshake(HandshakeError::Timeout)),
            Ok(result) => result?,
        };

        Ok(Established {
            session,
            address,
            family,
            connect_latency,
            setup_latency: setup_started.elapsed(),
            total_latency: started.elapsed(),
        })
    }

    /// Reaches the node and authenticates the TLS layer, without asking it to
    /// connect anywhere.
    ///
    /// This is what an active probe costs: a resolved dial, one `ClientHello`, and
    /// the server's first flight — then the socket closes without a VLESS request,
    /// so the node is never asked to reach a destination on our behalf. Anything
    /// cheaper (a bare TCP connect) proves only that something answers the port,
    /// which is not the question a cooling node raises; anything fuller (a real
    /// request) makes the probe a connection, and a probe that is a connection is
    /// just traffic with an extra step.
    ///
    /// What it proves and what it does not: a success means the address is
    /// reachable, the cover is intact, and this node's public key and short ID were
    /// accepted, because the server's verified finish is derived from that
    /// authentication. It says nothing about the user id, which travels only in the
    /// VLESS request, so a refusal that came from credentials is not cleared by a
    /// probe — see [`crate::scheduler::Fault::clears_on_probe`].
    ///
    /// Each probe is a fresh [`ClientKeyAgreement`], so no `client_random` and no
    /// key share is repeated on the wire. Nothing above this is reused: the socket
    /// is dropped here, which closes it, and the peer sees a connection that ended
    /// after the handshake — the same shape as a browser pool closing an idle
    /// keep-alive connection.
    ///
    /// # Errors
    ///
    /// The same taxonomy as [`Handoff::establish`], minus the request stage: dial
    /// failures from the resolution and racing, handshake and silence failures from
    /// authentication.
    pub async fn probe(&self) -> Result<Duration, Error> {
        let started = Instant::now();
        let Dialed {
            value: mut stream, ..
        } = self.dial_node().await?;
        self.authenticate(&mut stream).await?;
        // The dial layer has already folded the connect into the family's beliefs;
        // all that is left to report is how long the whole exchange took, which is
        // the number the scheduler folds into the node's.
        Ok(started.elapsed())
    }

    /// Resolves this node and races its candidates, mapping the dial layer's own
    /// error type into the crate taxonomy.
    async fn dial_node(&self) -> Result<Dialed<TcpStream>, Error> {
        let addresses = self
            .dial
            .resolve(&self.node.address, self.node.port)
            .await
            .map_err(dial_failure)?;
        self.dial.connect_to(&addresses).await.map_err(dial_failure)
    }

    /// Writes a freshly built `ClientHello` and completes the REALITY handshake over
    /// an already-connected socket.
    ///
    /// The whole stage sits inside one [`FIRST_BYTE_BUDGET`], which bounds both the
    /// write and the server's first flight: the socket is connected, so the question
    /// this stage answers is whether the peer is the configured server, and the only
    /// honest verdict on "it never said anything" is a timeout.
    async fn authenticate(&self, stream: &mut TcpStream) -> Result<Handshake, Error> {
        let (hello, keys, auth_key) = self.attempt()?;
        let outcome = time::timeout(FIRST_BYTE_BUDGET, async {
            let record = hello.record();
            stream.write_all(&record).await.map_err(write_failure)?;
            stream.flush().await.map_err(write_failure)?;
            complete(&mut *stream, &hello, &keys, &auth_key, ALPN).await
        })
        .await;

        match outcome {
            Err(_elapsed) => Err(Error::Handshake(HandshakeError::Timeout)),
            Ok(result) => result,
        }
    }

    /// Builds the one-attempt key agreement, authenticator and `ClientHello`.
    fn attempt(&self) -> Result<(HelloRecord, ClientKeyAgreement, AuthKey), Error> {
        let keys = ClientKeyAgreement::generate().map_err(hello_failure)?;
        let (hello, auth_key) = build_client_hello(
            &self.node.reality.server_name,
            ALPN,
            &keys,
            &self.node.reality.public_key,
            self.authenticator(),
        )
        .map_err(hello_failure)?;
        Ok((hello, keys, auth_key))
    }

    /// The authenticator plaintext for one attempt: the configured short ID, the
    /// advertised version, and this host's wall clock.
    ///
    /// The clock is not decoration. v2.0.1 reads it back and compares it to its own
    /// with `abs_diff` against `maxTimeDiff` (`protocol/reality/auth.rs:522-525`),
    /// whose default is 60 seconds (`config/node/reality.rs:50`). A host whose clock
    /// is off by more than that is not authenticated at all — and because the server
    /// routes an authentication failure to its cover target, the client sees a
    /// handshake that fails as if it had reached the wrong server. `doctor` reports
    /// clock skew for exactly that reason.
    fn authenticator(&self) -> AuthPlaintext {
        AuthPlaintext {
            version: CLIENT_VERSION,
            time: unix_seconds(),
            short_id: *self.node.reality.short_id(),
        }
    }
}

/// What one node answered, and what getting there cost.
///
/// The timing fields exist because stability work is decided on them: a node that
/// wins by 200 ms of connect time and one that wins by 200 ms of handshake time are
/// different problems, and the scheduler's hysteresis has to know which one it is
/// smoothing.
///
/// The session is a parameter so that the layer above can be tested against a pipe
/// instead of against a server: nothing outside [`crate::scheduler`] names the
/// argument, and the spelling `Established` used everywhere else is the real tunnel.
#[derive(Debug)]
pub struct Established<S = VisionSession<TcpStream>> {
    /// The live tunnel. Dropping it closes the path.
    pub session: S,
    /// The address that answered, which the resolver may have reordered and the race
    /// may have chosen over a faster-ordered candidate.
    pub address: SocketAddr,
    /// The family the winner came from.
    pub family: AddressFamily,
    /// Time from the winning attempt's first SYN to the established socket.
    pub connect_latency: Duration,
    /// Time spent authenticating and getting the VLESS answer.
    pub setup_latency: Duration,
    /// [`Handoff::establish`]'s whole duration, resolution included.
    pub total_latency: Duration,
}

/// Refuses a destination whose request header could never be encoded.
///
/// The domain is the only field with a one-byte length, so it is the only one that
/// can overflow; literals always fit. Checking it here rather than letting the
/// encoder find it means a request this client cannot write does not cost a
/// connection to a node.
fn preflight(destination: &Destination) -> Result<(), Error> {
    match destination {
        Destination::Domain(host) if u8::try_from(host.len()).is_err() => {
            Err(Error::Session(SessionError::RequestTooLong))
        }
        Destination::Domain(_) | Destination::IPv4(_) | Destination::IPv6(_) => Ok(()),
    }
}

/// Maps a dial failure onto the failure taxonomy.
///
/// The asymmetry is the point: a name that resolved to nothing never reached a node,
/// so it is scored as a local fact, while a plan that ran out of budget says the node
/// was unreachable and must count against it.
fn dial_failure(error: DialError) -> Error {
    match error {
        DialError::Lookup(inner) => Error::Dns(DnsError::Lookup(inner.to_string())),
        DialError::LookupTimedOut => Error::Dns(DnsError::Timeout),
        DialError::NoAddresses => Error::Dns(DnsError::NoAddress),
        DialError::TimedOut { .. } => Error::Transport(TransportError::Timeout),
        DialError::Failed { error, .. } => {
            Error::Transport(TransportError::Connect(error.to_string()))
        }
    }
}

/// Maps a failure to *build* the request onto the taxonomy.
///
/// None of these sent a byte, so none is evidence about a node: they are reported as
/// configuration or host problems. Entropy is the one exception because it is neither
/// — it is the operating system refusing to provide random bytes, which the session
/// layer already carries under the same meaning.
fn hello_failure(error: HelloError) -> Error {
    match error {
        HelloError::Entropy => Error::Session(SessionError::Entropy),
        other => Error::Config(other.to_string()),
    }
}

/// Maps a socket failure that happened while the `ClientHello` was going out.
///
/// A peer that closes the socket mid-handshake is the handshake failing, which is
/// what the server's own fallback path looks like from here; anything else is still
/// an establishment failure, not an idle-tunnel one.
// Used as a `map_err` callback, which hands over the error by value.
#[allow(clippy::needless_pass_by_value)]
fn write_failure(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof => Error::Handshake(HandshakeError::UnexpectedEof),
        _ => Error::Transport(TransportError::Connect(error.to_string())),
    }
}

/// This host's Unix time in seconds, as the authenticator needs it.
///
/// Saturating rather than falling over: the field is 32 bits, so it cannot express a
/// time past 2106, and a clock set before the epoch cannot express one at all. Both
/// cases send a value the node's skew check will reject, which surfaces as a failed
/// handshake with a message — the alternative, panicking in a network path, would
/// take every other tunnel down with it.
fn unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests;
