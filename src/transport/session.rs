//! One proxied TCP session carried by an established REALITY handshake.
//!
//! This is where `xtls-rprx-vision` meets the record layer, and the wire image is
//! the one the v2.0.1 server parses, not the one RFC 8446 suggests. Upstream
//! assembles both preambles the same way it reads them, so this module mirrors
//! its own writer against that reader:
//!
//! ```text
//! uplink   record 1 =  vless request ‖ frame[ uuid ‖ continue ‖ 0 content ‖ padding ]
//!          record n =  frame[ continue ‖ content ‖ padding ]
//! downlink record 1 =  [ 0, 0 ]       ‖ frame[ uuid ‖ continue ‖ 0 content ‖ padding ]
//!          record n =  frame[…]        …until the node stops framing, and then
//!                                       either verbatim records or a verbatim socket
//! ```
//!
//! Every line above is what the server itself does, not what a client is expected
//! to do: the response header and the opening frame are assembled together into
//! one plaintext (`server/vision.rs:1336-1352`), a record may carry several frames
//! (`:1431-1480`), and framing is a *byte stream* that survives any record
//! boundary (`protocol/vless/vision.rs:200-256`), so this module never assumes one
//! frame per record. The mirror on the client side is Xray-core's VLESS outbound,
//! which writes the request header and then an empty camouflage frame to pad it
//! out (`.upstream/xray/outbound.go:326-347`) and thereafter one frame per read;
//! v2.0.1 states what it expects to receive just as bluntly — "Xray's Vision
//! client emits one 8 KiB frame per record" (`server/vision.rs:1070-1073`).
//!
//! Three consequences drive the design:
//!
//! * An empty record is not special. The optional fake New Session Ticket arrives
//!   as one, and the server itself skips empty application records
//!   (`server/vision.rs:1131`); opening it like any other record is what keeps
//!   both sides' sequence numbers aligned.
//! * Half-close is a TLS alert, not a socket shutdown. v2.0.1 reads an inbound
//!   `close_notify` as the orderly end of the uplink, flushes what it has staged
//!   and half-closes the destination (`server/vision.rs:1114-1126`), while any
//!   other alert fails the direction (`:1127-1130`). That asymmetry is what lets a
//!   proxied `FIN` reach the destination without killing the reverse direction.
//! * Framing can stop early, and *which* command stopped it decides what the
//!   socket is made of afterwards. A node that gives up on classifying its
//!   destination — a TLS 1.2 origin, or one whose first eight records said
//!   nothing (`:2159`) — sends `End` and keeps sealing outer TLS records whose
//!   plaintext is payload (`server/vision.rs:1403-1409` with
//!   `relay_outer_downlink` at `:1842-1872`, which is `DirectionState::Outer` in
//!   the server's own vocabulary). A node that recognises a TLS 1.3 origin sends
//!   `Direct` at that origin's first `application_data` record
//!   (`:2156-2157`) and then replaces the TLS writer for the direction with the
//!   socket itself (`:1411-1417`, `:1550-1558`), so every later byte on the wire is
//!   the destination's own. The distinction is the difference between reading a
//!   record and reading the stream: [`Decoder`] reports which command ended the
//!   framing, and [`Downlink`] is what this session does about it. Conflating the
//!   two is not a cosmetic mistake — it opens raw payload as ciphertext, fails the
//!   AEAD in the middle of the application's handshake, and does it to exactly the
//!   TLS 1.3 destinations a long-lived WSS or SSE session is made of.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, SessionError, TransportError};
use crate::protocol::reality::{Handshake, Negotiated};
use crate::protocol::tls13::{
    ContentType, MAX_PLAINTEXT_LEN, MAX_RECORD_WIRE_LEN, RECORD_HEADER_LEN, RecordError,
    RecordLayer,
};
use crate::protocol::vision::{
    Command, DecodeError, Decoder, EncodeError, Encoder, FramePlan, Mode,
};
use crate::protocol::vless::{self, Destination, VISION_FLOW};

/// Size of the VLESS response header, which is the tunnel's readiness signal.
const RESPONSE_LEN: usize = 2;
/// Alert description the server reads as an orderly half-close
/// (`tls13/application_io.rs:13`).
const CLOSE_NOTIFY: u8 = 0;
/// The alert this client sends to end its own uplink: warning level, then
/// `close_notify`, exactly as `tls13/application_io.rs:1010-1013` seals it.
const CLOSE_NOTIFY_ALERT: [u8; 2] = [1, CLOSE_NOTIFY];

/// What the downlink's byte stream is, as distinct from what its frames are.
///
/// The node reaches one of these three states and never leaves it: the two
/// transitions that leave the first are the two terminating Vision commands, and
/// they differ in the transport rather than in the framing. Names follow the
/// server's own direction lifecycle (`crates/rr-session/src/vision.rs:27-47`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Downlink {
    /// Outer records are opened and their plaintext is Vision framing.
    Framed,
    /// Outer records are still opened and their plaintext is payload: the node
    /// sent `End` (`server/vision.rs:1403-1409`).
    Outer,
    /// The socket itself is the payload stream: the node authenticated a
    /// `Direct` boundary and gave up this direction's record layer
    /// (`server/vision.rs:1411-1417`, `:1550-1558`).
    Direct,
}

/// A Vision-over-TLS session, usable as one bidirectional byte stream.
///
/// One session is one TCP connection to one node. Dropping it abandons the
/// tunnel; [`AsyncWrite::poll_shutdown`] is what closes the uplink orderly.
///
/// Reads and writes are buffered by exactly one record in each direction:
/// [`MAX_RECORD_WIRE_LEN`] bytes of socket input plus one record's payload, and
/// one sealed record waiting for the socket. Once the downlink is
/// [`Downlink::Direct`] the read side holds nothing at all and copies the socket
/// straight to its caller, so nothing here grows with the transfer either way.
pub struct VisionSession<S> {
    stream: S,
    negotiated: Negotiated,
    inbound: RecordLayer,
    outbound: RecordLayer,
    encoder: Encoder,
    decoder: Decoder,
    downlink: Downlink,
    /// socket bytes that do not yet make up one whole record
    incoming: Vec<u8>,
    /// payload decoded out of `incoming` and not yet handed to the reader
    readable: Vec<u8>,
    readable_at: usize,
    /// sealed records the socket has not taken yet
    outgoing: Vec<u8>,
    /// the record plaintext being assembled
    frame: Vec<u8>,
    response: [u8; RESPONSE_LEN],
    response_at: usize,
    awaiting_response: bool,
    peer_closed: bool,
    local_closed: bool,
    failed: Option<Error>,
}

impl<S> VisionSession<S> {
    /// What the TLS layer settled on for this session.
    #[must_use]
    pub const fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// What the node's downlink is made of now.
    ///
    /// [`Downlink::Direct`] is the only state in which the session stops opening
    /// outer records, and it is reached by the node's choice, not this client's:
    /// the uplink keeps framing and sealing records whatever it says.
    #[must_use]
    pub const fn downlink(&self) -> Downlink {
        self.downlink
    }

    /// Whether the node has closed its downlink.
    #[must_use]
    pub const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// The sticky failure this session decided on, if any.
    ///
    /// [`AsyncRead`] and [`AsyncWrite`] can only report [`io::Error`], so the
    /// failure taxonomy is kept here for the relay to classify. The first failure
    /// wins: later ones are consequences of the same broken tunnel.
    #[must_use]
    pub fn failure(&self) -> Option<Error> {
        self.failed.clone()
    }
}

impl<S> VisionSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Sends the VLESS request and waits for the node to accept it.
    ///
    /// Returning `Ok` means the node answered `[0, 0]`, which v2.0.1 only does
    /// **after** it has connected to the destination (`protocol/vless/response.rs`,
    /// `server/vision.rs:650`). That is what makes this call the correctness
    /// boundary for hedged establishment: a candidate that gets here is a winner
    /// whose remote side exists.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rejected`] when the node refuses, [`Error::Session`] or
    /// [`Error::Transport`] when the stream it rides on breaks or desynchronises,
    /// and [`Error::Session(SessionError::RequestTooLong)`] when the destination
    /// does not fit the wire format, which sends nothing at all.
    pub async fn connect(
        stream: S,
        handshake: Handshake,
        user_id: [u8; 16],
        destination: &Destination,
        port: u16,
    ) -> Result<Self, Error> {
        let addons = vless::encode_addons(VISION_FLOW)
            .ok_or(Error::Session(SessionError::RequestTooLong))?;
        let request = vless::encode_request(&user_id, &addons, destination, port)
            .ok_or(Error::Session(SessionError::RequestTooLong))?;
        let (negotiated, inbound, outbound) = handshake.into_channels();
        let mut session = Self::from_channels(stream, negotiated, inbound, outbound, user_id)?;

        let preamble = session
            .encoder
            .plan(0, Command::Continue, true)
            .map_err(encoding_failure)?;
        session.begin_preamble(&request, preamble)?;
        session
            .encoder
            .assemble(&preamble, &[], &mut session.frame[request.len()..]);
        session.encoder.commit(&preamble);
        session.seal_frame(ContentType::ApplicationData)?;
        session.flush_uplink().await;
        if let Some(error) = session.failure() {
            return Err(error);
        }

        // The node's preamble can be preceded by the fake ticket record, so the
        // response is found by walking records, never by reading a fixed count.
        while session.awaiting_response {
            std::future::poll_fn(|context| session.poll_record(context)).await?;
        }
        Ok(session)
    }

    /// Reserves the first record's plaintext: request header, then frame.
    fn begin_preamble(&mut self, request: &[u8], preamble: FramePlan) -> Result<(), Error> {
        let total = request
            .len()
            .checked_add(preamble.wire_len())
            .filter(|total| *total <= MAX_PLAINTEXT_LEN)
            .ok_or(Error::Session(SessionError::RequestTooLong))?;
        self.frame.clear();
        self.frame.resize(total, 0);
        self.frame[..request.len()].copy_from_slice(request);
        Ok(())
    }

    fn from_channels(
        stream: S,
        negotiated: Negotiated,
        inbound: RecordLayer,
        outbound: RecordLayer,
        user_id: [u8; 16],
    ) -> Result<Self, Error> {
        Ok(Self {
            stream,
            negotiated,
            inbound,
            outbound,
            encoder: Encoder::new(user_id).map_err(encoding_failure)?,
            decoder: Decoder::new(user_id),
            downlink: Downlink::Framed,
            incoming: Vec::with_capacity(MAX_RECORD_WIRE_LEN),
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            outgoing: Vec::with_capacity(MAX_RECORD_WIRE_LEN),
            frame: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            response: [0; RESPONSE_LEN],
            response_at: 0,
            awaiting_response: true,
            peer_closed: false,
            local_closed: false,
            failed: None,
        })
    }

    /// Seals the assembled `frame` as one record and queues it.
    fn seal_frame(&mut self, content_type: ContentType) -> Result<(), Error> {
        let start = self.outgoing.len();
        match self
            .outbound
            .seal(content_type, &self.frame, &mut self.outgoing)
        {
            Ok(()) => Ok(()),
            Err(error) => {
                self.outgoing.truncate(start);
                Err(self.fail(record_failure(error)))
            }
        }
    }

    /// Drives every queued record into the socket, latching the first failure.
    async fn flush_uplink(&mut self) {
        if let Err(error) = std::future::poll_fn(|context| self.poll_flush_outgoing(context)).await
        {
            self.fail(error);
        }
    }

    fn poll_flush_outgoing(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Error>> {
        while !self.outgoing.is_empty() {
            // Bound the write to its own statement: taking the socket's result
            // inside `match` would keep `outgoing` borrowed across the arms,
            // which are the only places that shorten it.
            let written = Pin::new(&mut self.stream).poll_write(context, &self.outgoing);
            match written {
                // A zero-length write on an established socket is the way tokio
                // reports that the peer is gone.
                Poll::Ready(Ok(0)) => {
                    self.outgoing.clear();
                    return Poll::Ready(Err(
                        self.fail(Error::Transport(TransportError::BrokenPipe))
                    ));
                }
                Poll::Ready(Ok(count)) => {
                    self.outgoing.drain(..count);
                }
                Poll::Ready(Err(error)) => {
                    self.outgoing.clear();
                    return Poll::Ready(Err(self.fail(socket_failure(&error))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Opens the next buffered record, waiting until it has arrived whole.
    fn poll_record(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Error>> {
        loop {
            let wanted = match self.pending_record_len() {
                Ok(wanted) => wanted,
                Err(error) => return Poll::Ready(Err(self.fail(record_failure(error)))),
            };
            if self.incoming.len() >= wanted {
                return Poll::Ready(self.open_record(wanted));
            }
            match self.poll_fill(context, wanted) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => {
                    let error = if self.awaiting_response {
                        Error::Session(SessionError::ClosedBeforeResponse)
                    } else {
                        Error::Transport(TransportError::BrokenPipe)
                    };
                    return Poll::Ready(Err(self.fail(error)));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Reads the socket verbatim into the caller's buffer, which is all a `Direct`
    /// downlink has left to do: the node's bytes are the application's bytes, with
    /// no record layer and no Vision framing in front of them.
    ///
    /// `incoming` is not consulted and `readable` is not staged, because the
    /// boundary consumed the whole record that carried it — the node seals a
    /// `Direct` frame and then writes what its destination buffered behind it
    /// straight to the socket (`server/vision.rs:1550-1558`). Bytes already decoded
    /// out of that last record are delivered before this is ever reached: the
    /// caller drains `readable` first.
    ///
    /// Socket EOF is the end of the stream rather than a broken tunnel: the node's
    /// raw relay closes the direction on a zero-length read
    /// (`server/vision.rs:1653-1662`), and there is no `close_notify` left to wait
    /// for once the record layer is gone.
    fn poll_raw(
        &mut self,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.peer_closed {
            return Poll::Ready(Ok(()));
        }
        let outcome = Pin::new(&mut self.stream).poll_read(context, buffer);
        match outcome {
            Poll::Ready(Ok(())) => {
                if buffer.filled().is_empty() {
                    self.peer_closed = true;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                Poll::Ready(Err(into_io_error(&self.fail(socket_failure(&error)))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Total wire length of the record `incoming` is assembling.
    ///
    /// While even the fixed-size header is missing this is the header length, so
    /// the caller always has a positive target to read toward. The bound is
    /// [`RecordLayer::record_len`]'s, which means the header this reader waits for
    /// and the header the decryptor accepts cannot drift apart: a peer that
    /// declares an impossible length is reported at the header instead of being
    /// waited on forever or mistaken for a bad tag.
    ///
    /// # Errors
    ///
    /// Reports the defect in bytes that can never begin an encrypted record.
    fn pending_record_len(&self) -> Result<usize, RecordError> {
        Ok(RecordLayer::record_len(&self.incoming)?.unwrap_or(RECORD_HEADER_LEN))
    }

    /// Extends `incoming` toward `wanted`, the length of the record being built.
    ///
    /// `incoming` therefore never holds more than one record, which is the
    /// session's whole downlink bound: `MAX_RECORD_WIRE_LEN` bytes of socket input
    /// plus one record's payload in `readable`.
    ///
    /// `Ok(false)` is the socket's end of stream.
    fn poll_fill(&mut self, context: &mut Context<'_>, wanted: usize) -> Poll<Result<bool, Error>> {
        let start = self.incoming.len();
        self.incoming.resize(wanted, 0);
        // The length the socket filled is read out before `incoming` is touched
        // again, and the buffer is dropped at the end of the block, so a partial
        // or failed read cannot leave phantom bytes behind.
        let (outcome, filled) = {
            let Self {
                incoming, stream, ..
            } = self;
            let mut buffer = ReadBuf::new(&mut incoming[start..wanted]);
            let outcome = Pin::new(stream).poll_read(context, &mut buffer);
            (outcome, buffer.filled().len())
        };
        self.incoming.truncate(start + filled);
        match outcome {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(filled > 0)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(socket_failure(&error)))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Opens one whole buffered record and consumes it either way.
    ///
    /// Consuming on failure matters: the relay reads the latched error next, and
    /// a session that left the bytes in place would report the same defect again
    /// as if it were new.
    fn open_record(&mut self, len: usize) -> Result<(), Error> {
        let outcome = self.dispatch_record(len);
        self.incoming.drain(..len);
        outcome.map_err(|error| self.fail(error))
    }

    /// Decrypts the buffered record of `len` bytes and routes its plaintext.
    ///
    /// Only ever called while [`Downlink`] is not [`Downlink::Direct`]: a node that
    /// took the Direct transition sealed nothing more on this direction, so the
    /// bytes that follow are not a record and must not be opened as one.
    fn dispatch_record(&mut self, len: usize) -> Result<(), Error> {
        let Self {
            incoming,
            inbound,
            decoder,
            downlink,
            readable,
            response,
            response_at,
            awaiting_response,
            peer_closed,
            ..
        } = self;
        let (kind, plaintext) = inbound.open(&mut incoming[..len]).map_err(record_failure)?;
        match kind {
            ContentType::ApplicationData => {
                let mut framed = plaintext;
                if *awaiting_response {
                    let taken = (RESPONSE_LEN - *response_at).min(framed.len());
                    response[*response_at..*response_at + taken].copy_from_slice(&framed[..taken]);
                    *response_at += taken;
                    framed = &framed[taken..];
                    if *response_at == RESPONSE_LEN {
                        vless::validate_response(response.as_slice())?;
                        *awaiting_response = false;
                    }
                }
                if !framed.is_empty() {
                    // Whatever the decoder says afterwards is the node's decision
                    // about this direction, and it is final: `Raw` means the record
                    // layer in front of these plaintext bytes stays, `Direct` means
                    // the socket's next byte is the destination's.
                    *downlink = match decoder
                        .decode_append(framed, readable)
                        .map_err(framing_failure)?
                    {
                        Mode::Framed => *downlink,
                        Mode::Raw => Downlink::Outer,
                        Mode::Direct => Downlink::Direct,
                    };
                }
                Ok(())
            }
            ContentType::Alert => {
                // One record carries exactly one alert, as `open` just proved it
                // does for the node's own writer.
                let Ok([level, description]) = <[u8; 2]>::try_from(plaintext) else {
                    return Err(Error::Session(SessionError::RecordCorrupted));
                };
                // v2.0.1 keys the orderly end of a direction off the description
                // alone (`server/vision.rs:1114-1116`), so this does too.
                if description == CLOSE_NOTIFY {
                    *peer_closed = true;
                    return Ok(());
                }
                Err(Error::Session(SessionError::PeerAlert {
                    level,
                    description,
                }))
            }
            ContentType::ChangeCipherSpec | ContentType::Handshake => Err(Error::Session(
                SessionError::UnexpectedContentType(kind.wire_value()),
            )),
        }
    }

    /// Latches `error` as this session's, unless one is already latched, and
    /// hands it back for `return Err(self.fail(error))` sites.
    fn fail(&mut self, error: Error) -> Error {
        if self.failed.is_none() {
            self.failed = Some(error.clone());
        }
        error
    }
}

impl<S> fmt::Debug for VisionSession<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VisionSession")
            .field("suite", &self.negotiated.suite)
            // Byte counts, never bytes: the buffers hold decoded payload, which
            // belongs to the application and is not this client's to print.
            .field("incoming", &self.incoming.len())
            .field("readable", &self.readable.len())
            .field("outgoing", &self.outgoing.len())
            .field("awaiting_response", &self.awaiting_response)
            .field("downlink", &self.downlink)
            .field("peer_closed", &self.peer_closed)
            .field("local_closed", &self.local_closed)
            .field("failure", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<S> AsyncRead for VisionSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.failure() {
            return Poll::Ready(Err(into_io_error(&error)));
        }
        loop {
            if this.readable_at < this.readable.len() {
                let taken = (this.readable.len() - this.readable_at).min(buffer.remaining());
                if taken > 0 {
                    let start = this.readable_at;
                    buffer.put_slice(&this.readable[start..start + taken]);
                    this.readable_at = start + taken;
                }
                return Poll::Ready(Ok(()));
            }
            this.readable.clear();
            this.readable_at = 0;
            if this.downlink == Downlink::Direct {
                return this.poll_raw(context, buffer);
            }
            if this.peer_closed {
                return Poll::Ready(Ok(()));
            }
            match this.poll_record(context) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(into_io_error(&error))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for VisionSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Frames at most one `write` call's bytes into one Vision frame.
    ///
    /// One record in flight is the uplink bound: accepting more would buffer
    /// without limit and hide a stalled socket from the writer above.
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.failure() {
            return Poll::Ready(Err(into_io_error(&error)));
        }
        if this.local_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "this session's uplink is closed",
            )));
        }
        if !this.outgoing.is_empty() {
            match this.poll_flush_outgoing(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(into_io_error(&error))),
                Poll::Ready(Ok(())) => {}
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let taken = buf.len().min(this.encoder.max_content());
        let plan = match this.encoder.plan(taken, Command::Continue, true) {
            Ok(plan) => plan,
            Err(error) => {
                return Poll::Ready(Err(into_io_error(&this.fail(encoding_failure(error)))));
            }
        };
        this.frame.clear();
        this.frame.resize(plan.wire_len(), 0);
        this.encoder.assemble(&plan, &buf[..taken], &mut this.frame);
        this.encoder.commit(&plan);
        if let Err(error) = this.seal_frame(ContentType::ApplicationData) {
            return Poll::Ready(Err(into_io_error(&error)));
        }
        // Push the record at once. A proxy's writer may not sit on bytes until the
        // caller thinks to flush: `copy_bidirectional` only flushes each half when
        // it stops copying, and an HTTP request would never reach the node. A
        // `Pending` here is not a failure: the bytes are accepted, and the next
        // call drains them.
        if let Poll::Ready(Err(error)) = this.poll_flush_outgoing(context) {
            return Poll::Ready(Err(into_io_error(&error)));
        }
        Poll::Ready(Ok(taken))
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.failure() {
            return Poll::Ready(Err(into_io_error(&error)));
        }
        if !this.outgoing.is_empty() {
            match this.poll_flush_outgoing(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(into_io_error(&error))),
                Poll::Ready(Ok(())) => {}
            }
        }
        let flushed = Pin::new(&mut this.stream).poll_flush(context);
        flushed.map_err(|error| into_io_error(&this.fail(socket_failure(&error))))
    }

    /// Closes the uplink only, the way the node expects: an authenticated
    /// `close_notify`, then the socket's write half.
    ///
    /// v2.0.1 reads that alert as the orderly end of the uplink and half-closes
    /// the destination while keeping the downlink open
    /// (`server/vision.rs:1114-1126`). Sending the alert then shutting the socket
    /// down is exactly what `shutdown_tls_writer` does in the other direction
    /// (`tls13/application_io.rs:994-1015`), which is why this does both.
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.failure() {
            // A broken tunnel cannot deliver an alert, and claiming a clean
            // half-close that never arrived would be the worse lie.
            return Poll::Ready(Err(into_io_error(&error)));
        }
        if !this.local_closed {
            this.local_closed = true;
            this.frame.clear();
            this.frame.extend_from_slice(&CLOSE_NOTIFY_ALERT);
            if let Err(error) = this.seal_frame(ContentType::Alert) {
                return Poll::Ready(Err(into_io_error(&error)));
            }
        }
        match this.poll_flush_outgoing(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(into_io_error(&error))),
            Poll::Ready(Ok(())) => {
                let shutdown = Pin::new(&mut this.stream).poll_shutdown(context);
                shutdown.map_err(|error| into_io_error(&this.fail(socket_failure(&error))))
            }
        }
    }
}

/// Maps a record-layer failure onto the session taxonomy.
///
/// Only exhaustion is named apart, because it is a bound the session crossed
/// rather than a byte that went wrong: every other seal or open failure means the
/// stream no longer lines up with the keys, however it was noticed.
fn record_failure(error: RecordError) -> Error {
    match error {
        RecordError::KeyExhausted => Error::Session(SessionError::KeyExhausted),
        _ => Error::Session(SessionError::RecordCorrupted),
    }
}

/// Maps a framing failure onto the session taxonomy.
///
/// The decoder's own message is not carried: it quotes byte values the peer
/// chose, and the node's identity is not something to echo back.
fn framing_failure(error: DecodeError) -> Error {
    let reason = match error {
        DecodeError::UserIdMismatch => "user id",
        DecodeError::UnknownCommand(_) => "command",
        DecodeError::FrameTooLarge { .. } => "frame size",
        DecodeError::Failed => "decoder already failed",
    };
    Error::Session(SessionError::Framing(reason))
}

/// Maps an encoding failure onto the session taxonomy.
fn encoding_failure(error: EncodeError) -> Error {
    match error {
        EncodeError::ContentTooLarge { .. } | EncodeError::PaddingTooLarge(_) => {
            Error::Session(SessionError::Framing("frame plan"))
        }
        EncodeError::Finished => Error::Session(SessionError::Framing("encoder finished")),
        EncodeError::Entropy => Error::Session(SessionError::Entropy),
    }
}

/// Maps a socket failure on a session that is already established.
///
/// The OS message is kept because it distinguishes a reset from a timeout, but
/// the family is settled here: the tunnel existed, so what happened to it is an
/// idle failure, not a connect failure.
fn socket_failure(error: &io::Error) -> Error {
    Error::Transport(TransportError::Socket(error.to_string()))
}

/// Wraps the taxonomy in an [`io::Error`] that still carries it.
///
/// The relay hands this to the local client, and `into_io_error` is the only place
/// the two vocabularies meet; the original [`Error`] stays reachable through
/// [`std::io::Error::get_ref`] for the scheduler.
fn into_io_error(error: &Error) -> io::Error {
    let kind = match error {
        Error::Rejected(_) => io::ErrorKind::ConnectionRefused,
        Error::Session(SessionError::ClosedBeforeResponse) => io::ErrorKind::UnexpectedEof,
        Error::Session(SessionError::RequestTooLong) => io::ErrorKind::InvalidInput,
        Error::Session(_) => io::ErrorKind::InvalidData,
        Error::Transport(_) => io::ErrorKind::BrokenPipe,
        Error::Handshake(_) => io::ErrorKind::ConnectionReset,
        Error::Cancelled => io::ErrorKind::Interrupted,
        Error::Config(_) | Error::Limit(_) | Error::Dns(_) | Error::Io(_) => io::ErrorKind::Other,
    };
    io::Error::new(kind, error.clone())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::protocol::reality::X25519_GROUP;
    use crate::protocol::tls13::{CipherSuite, HashAlgorithm, KeySchedule, TranscriptHash};
    use crate::protocol::vision::Mode;

    const USER: [u8; 16] = [0x11; 16];
    const SUITE: CipherSuite = CipherSuite::Aes128GcmSha256;
    const TARGET: &str = "www.example.com";
    const PORT: u16 = 443;
    /// The largest payload a copy loop hands over at once, so a test that writes
    /// this much must be framed into more than one record.
    const BULK: usize = 10_000;

    fn destination() -> Destination {
        Destination::Domain(TARGET.to_owned())
    }

    /// The request bytes a session with these parameters puts on the wire.
    fn request_bytes() -> Vec<u8> {
        let addons = vless::encode_addons(VISION_FLOW).expect("flow fits its length field");
        vless::encode_request(&USER, &addons, &destination(), PORT).expect("destination fits")
    }

    /// Four record layers on one key schedule: two per direction, each starting at
    /// sequence 0, which is what two independent peers do.
    fn layers() -> (RecordLayer, RecordLayer, RecordLayer, RecordLayer) {
        let transcript = TranscriptHash::from_bytes(HashAlgorithm::Sha256, &[7; 32])
            .expect("a sha256 digest is 32 bytes");
        let schedule = KeySchedule::new(SUITE, &[0x42; 32], &transcript).expect("schedule");
        (
            layer(&schedule, true),
            layer(&schedule, true),
            layer(&schedule, false),
            layer(&schedule, false),
        )
    }

    fn layer(schedule: &KeySchedule, client: bool) -> RecordLayer {
        let secret = if client {
            schedule.client_handshake_secret()
        } else {
            schedule.server_handshake_secret()
        };
        let keys = schedule.traffic_keys(secret).expect("traffic keys");
        RecordLayer::new(SUITE, &keys).expect("record layer")
    }

    /// The node's side of one session: its socket half, both record directions and
    /// its own Vision framing state.
    struct Node {
        stream: DuplexStream,
        /// opens what the session seals
        uplink: RecordLayer,
        /// seals what the session opens
        downlink: RecordLayer,
        encoder: Encoder,
        decoder: Decoder,
    }

    impl Node {
        /// Seals one downlink record and hands it to the socket.
        async fn send(&mut self, kind: ContentType, plaintext: &[u8]) {
            let mut wire = Vec::new();
            self.downlink
                .seal(kind, plaintext, &mut wire)
                .expect("seal");
            self.stream.write_all(&wire).await.expect("write");
        }

        /// Writes bytes to the socket that are *not* a record of anything: what the
        /// node does to its own write half once it has taken the `Direct` transition
        /// (`server/vision.rs:1550-1558`, where `client.into_inner()` replaces the
        /// TLS writer with the socket).
        async fn send_raw(&mut self, bytes: &[u8]) {
            self.stream.write_all(bytes).await.expect("write");
        }

        /// The empty padded record v2.0.1 puts in front of its own preamble
        /// whenever it issued a fake New Session Ticket (`reality/handshake.rs`
        /// module doc, `tls13/handshake.rs:503-510`).
        async fn send_fake_ticket(&mut self) {
            let mut wire = Vec::new();
            self.downlink
                .seal_padded(ContentType::ApplicationData, &[], 117, &mut wire)
                .expect("seal");
            self.stream.write_all(&wire).await.expect("write");
        }

        /// The node's preamble, beginning at `response[skip..]`: the response
        /// bytes it still owes plus its opening camouflage frame, in one record
        /// exactly as `server/vision.rs:1336-1352` assembles it.
        async fn answer_from(&mut self, response: [u8; RESPONSE_LEN], skip: usize) {
            let plan = self
                .encoder
                .plan(0, Command::Continue, true)
                .expect("camouflage frame");
            let mut plaintext = response[skip..].to_vec();
            let start = plaintext.len();
            plaintext.resize(start + plan.wire_len(), 0);
            self.encoder.assemble(&plan, &[], &mut plaintext[start..]);
            self.encoder.commit(&plan);
            self.send(ContentType::ApplicationData, &plaintext).await;
        }

        async fn answer(&mut self, response: [u8; RESPONSE_LEN]) {
            self.answer_from(response, 0).await;
        }

        /// Frames `content` as one node downlink frame, in its own record.
        async fn frame(&mut self, content: &[u8], command: Command) {
            let plan = self
                .encoder
                .plan(content.len(), command, false)
                .expect("frame plan");
            let mut plaintext = vec![0_u8; plan.wire_len()];
            self.encoder.assemble(&plan, content, &mut plaintext);
            self.encoder.commit(&plan);
            self.send(ContentType::ApplicationData, &plaintext).await;
        }

        /// Frames `content` and puts `tail` behind it in the *same* record, which
        /// is what a record that carries more than one frame looks like
        /// (`server/vision.rs:1431-1480`). When `command` terminates framing,
        /// `tail` is payload that was authenticated inside the last sealed record.
        async fn frame_and_tail(&mut self, content: &[u8], command: Command, tail: &[u8]) {
            let plan = self
                .encoder
                .plan(content.len(), command, false)
                .expect("frame plan");
            let mut plaintext = vec![0_u8; plan.wire_len() + tail.len()];
            self.encoder
                .assemble(&plan, content, &mut plaintext[..plan.wire_len()]);
            plaintext[plan.wire_len()..].copy_from_slice(tail);
            self.encoder.commit(&plan);
            self.send(ContentType::ApplicationData, &plaintext).await;
        }

        /// Reads one whole record the session sealed and opens it as the node would.
        async fn receive(&mut self) -> (ContentType, Vec<u8>) {
            let mut header = [0_u8; RECORD_HEADER_LEN];
            self.stream.read_exact(&mut header).await.expect("header");
            let total = RecordLayer::record_len(&header)
                .expect("a node-readable header")
                .expect("a whole header declares its length");
            let mut record = header.to_vec();
            let mut body = vec![0_u8; total - RECORD_HEADER_LEN];
            self.stream
                .read_exact(&mut body)
                .await
                .expect("record body");
            record.extend_from_slice(&body);
            let (kind, plaintext) = self.uplink.open(&mut record).expect("open");
            (kind, plaintext.to_vec())
        }

        /// Consumes the session's opening record: its unframed request header, then
        /// the empty camouflage frame that shares the record with it. Returns that
        /// frame's bytes.
        async fn receive_preamble(&mut self, request: &[u8]) -> Vec<u8> {
            let (kind, plaintext) = self.receive().await;
            assert_eq!(kind, ContentType::ApplicationData);
            assert_eq!(&plaintext[..request.len()], request);
            let mut payload = Vec::new();
            self.decoder
                .decode_append(&plaintext[request.len()..], &mut payload)
                .expect("camouflage frame decodes");
            assert!(payload.is_empty(), "the opening frame carries no content");
            plaintext[request.len()..].to_vec()
        }

        /// The content of the session's next Vision frame.
        async fn receive_frame(&mut self) -> Vec<u8> {
            let (kind, plaintext) = self.receive().await;
            assert_eq!(kind, ContentType::ApplicationData);
            let mut payload = Vec::new();
            self.decoder
                .decode_append(&plaintext, &mut payload)
                .expect("frame decodes");
            payload
        }
    }

    /// A session joined to a node, before either has spoken.
    struct Harness {
        stream: DuplexStream,
        handshake: Handshake,
        node: Node,
    }

    fn harness() -> Harness {
        let (client_out, node_uplink, node_downlink, client_in) = layers();
        let (stream, node_stream) = tokio::io::duplex(1 << 20);
        Harness {
            stream,
            handshake: Handshake::from_record_layers(
                Negotiated {
                    suite: SUITE,
                    alpn: None,
                    key_share_group: X25519_GROUP,
                },
                client_in,
                client_out,
            ),
            node: Node {
                stream: node_stream,
                uplink: node_uplink,
                downlink: node_downlink,
                encoder: Encoder::new(USER).expect("node encoder"),
                decoder: Decoder::new(USER),
            },
        }
    }

    impl Harness {
        async fn connect(self) -> (VisionSession<DuplexStream>, Node) {
            let (stream, handshake, node) = self.into_parts();
            let session = VisionSession::connect(stream, handshake, USER, &destination(), PORT)
                .await
                .expect("the node answered");
            (session, node)
        }

        /// Takes the halves apart, so a test can drive the socket itself and still
        /// inspect the node after `connect` has consumed the client's half.
        fn into_parts(self) -> (DuplexStream, Handshake, Node) {
            (self.stream, self.handshake, self.node)
        }
    }

    /// A node that has answered and read the request, so the happy path needs no
    /// concurrency and its framing state is already in step.
    async fn answered() -> (VisionSession<DuplexStream>, Node) {
        let mut harness = harness();
        harness.node.answer([0, 0]).await;
        let (session, mut node) = harness.connect().await;
        node.receive_preamble(&request_bytes()).await;
        (session, node)
    }

    #[tokio::test]
    async fn connect_sends_the_request_and_its_camouflage_frame_in_one_record() {
        let mut harness = harness();
        harness.node.answer([0, 0]).await;
        let (session, mut node) = harness.connect().await;
        assert!(
            !session.awaiting_response,
            "an answer makes the tunnel ready"
        );

        let frame = node.receive_preamble(&request_bytes()).await;
        // The camouflage frame is the long-padded empty one: uuid, header, then
        // 900 to 1399 padding bytes.
        assert!(
            (21 + 900..21 + 1400).contains(&frame.len()),
            "frame is {} bytes",
            frame.len()
        );
        assert_eq!(frame[16], Command::Continue as u8);
        assert_eq!(&frame[17..19], &[0, 0], "the frame declares no content");
        let padding = usize::from(u16::from_be_bytes([frame[19], frame[20]]));
        assert_eq!(padding, frame.len() - 21, "padding is all the frame holds");
    }

    /// The fake ticket is an ordinary empty record that the client must neither
    /// consume as the response nor drop: skipping it silently is what keeps both
    /// sides' sequence numbers aligned.
    #[tokio::test]
    async fn an_empty_record_before_the_response_keeps_both_sides_in_step() {
        let mut harness = harness();
        harness.node.send_fake_ticket().await;
        harness.node.answer([0, 0]).await;
        let (mut session, mut node) = harness.connect().await;

        node.frame(b"first real payload", Command::Continue).await;
        let mut buffer = [0_u8; 64];
        let read = session.read(&mut buffer).await.expect("payload reads");
        assert_eq!(&buffer[..read], b"first real payload");
        assert_eq!(session.failure(), None);
    }

    #[tokio::test]
    async fn downlink_payload_arrives_across_frames_and_records() {
        let (mut session, mut node) = answered().await;
        node.frame(b"alpha", Command::Continue).await;
        node.frame(b"beta", Command::Continue).await;
        node.frame(b"gamma", Command::Continue).await;

        let mut received = Vec::new();
        let mut buffer = [0_u8; 8];
        while received.len() < 14 {
            let read = session.read(&mut buffer).await.expect("reads");
            received.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(received, b"alphabetagamma");
    }

    /// v2.0.1 stops framing the moment its nested-TLS classifier gives up: the
    /// `End` frame is the last framed byte of the stream, and every later record's
    /// plaintext is payload as-is (`server/vision.rs:1403-1409`, which advances the
    /// direction to `DirectionState::Outer` and keeps sealing through
    /// `relay_outer_downlink` at `:1842-1872`).
    #[tokio::test]
    async fn an_end_command_ends_framing_for_the_rest_of_the_stream() {
        let (mut session, mut node) = answered().await;
        node.frame(b"framed", Command::End).await;
        node.send(ContentType::ApplicationData, b"raw tail").await;

        let mut received = Vec::new();
        let mut buffer = [0_u8; 16];
        while received.len() < 14 {
            let read = session.read(&mut buffer).await.expect("reads");
            received.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(received, b"framedraw tail");
        assert_eq!(session.decoder.mode(), Mode::Raw);
        assert_eq!(
            session.downlink(),
            Downlink::Outer,
            "`End` ends framing and leaves the record layer standing"
        );
    }

    /// `Direct` is a different transition, and the difference is the transport, not
    /// the framing: the node authenticates the boundary, drops its TLS writer for
    /// that direction and writes the destination's bytes straight to the socket
    /// (`server/vision.rs:1411-1417`, then `:1550-1558`).
    ///
    /// This is the shape every TLS 1.3 destination produces — the node classifies
    /// the origin's `ServerHello`, then takes `Direct` at its first
    /// `application_data` record (`:2156-2157`) — so a client that reads the bytes
    /// after the boundary as outer records is not merely untidy: it opens raw
    /// payload as ciphertext, fails the AEAD, and kills the tunnel in the middle of
    /// the application's own handshake.
    #[tokio::test]
    async fn a_direct_command_ends_the_outer_record_layer_too() {
        let (mut session, mut node) = answered().await;
        node.frame(b"framed", Command::Direct).await;
        node.send_raw(b"raw tail").await;

        let mut received = Vec::new();
        let mut buffer = [0_u8; 16];
        while received.len() < 14 {
            let read = session.read(&mut buffer).await.expect("reads");
            received.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(
            received, b"framedraw tail",
            "the framed content and then the socket's own bytes, in order"
        );
        assert_eq!(
            session.downlink(),
            Downlink::Direct,
            "the session stopped opening records, not just decoding frames"
        );
        assert_eq!(
            session.decoder.mode(),
            Mode::Direct,
            "and it can still say which command told it to"
        );
        assert_eq!(
            session.failure(),
            None,
            "reading past a Direct boundary must not be a record failure"
        );
    }

    /// The boundary is a byte, not a record: everything the node sealed *up to and
    /// including* the `Direct` frame is delivered before one raw byte is read, and
    /// the part of that last record which fell behind the frame is payload like any
    /// other (`protocol/vless/vision.rs:247-251` hands the remainder of the
    /// fragment to the caller at the transition).
    ///
    /// A reader that flipped to raw mode when it saw the command byte, rather than
    /// when the frame was complete, would lose this record's padding accounting and
    /// deliver the tail twice or not at all.
    #[tokio::test]
    async fn a_direct_transition_delivers_its_own_record_before_the_socket() {
        let (mut session, mut node) = answered().await;
        node.frame_and_tail(b"head", Command::Direct, b"in-record")
            .await;
        node.send_raw(b"on-socket").await;

        let expected = b"headin-recordon-socket";
        let mut received = Vec::new();
        let mut buffer = [0_u8; 7];
        while received.len() < expected.len() {
            let read = session.read(&mut buffer).await.expect("reads");
            assert_ne!(
                read,
                0,
                "the stream has {} bytes and no end of it yet",
                expected.len()
            );
            received.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(
            received, expected,
            "sealed payload first, then the socket's, each byte exactly once"
        );
        assert_eq!(session.downlink(), Downlink::Direct);
    }

    /// The two transitions are independent per direction, and the *other* direction
    /// keeps its framing and its record layer: only `finish_downlink_direct` gives
    /// up the TLS writer, while the uplink reader stays in `relay_uplink_framed`
    /// and still reads outer records until an authenticated `close_notify`
    /// (`server/vision.rs:1114-1125`).
    ///
    /// A client that treated `Direct` as a session-wide property would stop framing
    /// its uplink here, and the node would fail the session on a plaintext read.
    #[tokio::test]
    async fn a_direct_downlink_leaves_the_uplink_framed_and_sealed() {
        let (mut session, mut node) = answered().await;
        node.frame(b"go", Command::Direct).await;
        node.send_raw(b"\x17\x03\x03\x00\x04ping").await;

        let expected = b"go\x17\x03\x03\x00\x04ping";
        let mut received = Vec::new();
        let mut buffer = [0_u8; 8];
        while received.len() < expected.len() {
            let read = session.read(&mut buffer).await.expect("reads");
            assert_ne!(
                read,
                0,
                "the raw downlink has {} bytes and no end of it yet",
                expected.len()
            );
            received.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(received, expected);

        session
            .write_all(b"still framed")
            .await
            .expect("the uplink still frames");
        assert_eq!(node.receive_frame().await, b"still framed");

        session
            .shutdown()
            .await
            .expect("the uplink still ends with an alert");
        let (kind, alert) = node.receive().await;
        assert_eq!(kind, ContentType::Alert);
        assert_eq!(alert, vec![1, 0]);
    }

    /// Past a Direct boundary the socket *is* the stream, so its end of stream is
    /// the end of the downlink: the node's raw relay closes the direction on a
    /// read of zero bytes (`server/vision.rs:1653-1662`, after
    /// `run_directional`). There is no outer `close_notify` left to wait for, and
    /// demanding one turns every completed WSS response into a broken pipe.
    #[tokio::test]
    async fn end_of_socket_after_a_direct_command_reads_as_end_of_stream() {
        let (mut session, mut node) = answered().await;
        node.frame(b"tail", Command::Direct).await;
        node.send_raw(b"last").await;
        node.stream.shutdown().await.expect("half close");

        let mut received = Vec::new();
        let mut buffer = [0_u8; 8];
        loop {
            let read = session
                .read(&mut buffer)
                .await
                .expect("a closed raw stream is not a failure");
            if read == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(received, b"taillast");
        assert!(session.peer_closed(), "the downlink ended");
        assert!(
            session.failure().is_none(),
            "EOF at a raw boundary is the end of the stream, not a broken tunnel"
        );
    }

    /// A refusal is the node's own answer, so it is reported as a rejection rather
    /// than as a broken stream.
    #[tokio::test]
    async fn a_refusal_is_reported_as_a_rejection() {
        let mut harness = harness();
        harness.node.answer([0, 1]).await;
        let (stream, handshake, _node) = harness.into_parts();
        let error = VisionSession::connect(stream, handshake, USER, &destination(), PORT)
            .await
            .expect_err("refused");
        assert!(matches!(error, Error::Rejected(_)), "{error}");
    }

    /// A node that completes TLS and then hangs up without answering is evidence
    /// about *this request*, which is what the Rejected family scores.
    #[tokio::test]
    async fn a_peer_that_closes_before_answering_is_reported_as_a_rejection() {
        let mut harness = harness();
        harness.node.stream.shutdown().await.expect("half close");
        let (stream, handshake, mut node) = harness.into_parts();
        let error = VisionSession::connect(stream, handshake, USER, &destination(), PORT)
            .await
            .expect_err("no response arrives");
        assert!(
            matches!(error, Error::Session(SessionError::ClosedBeforeResponse)),
            "{error}"
        );
        assert_eq!(error.classify(), crate::error::Failure::Rejected, "{error}");
        // The request itself still left, whole: closing the node's write half does
        // not undo the client's.
        node.receive_preamble(&request_bytes()).await;
    }

    #[tokio::test]
    async fn close_notify_from_the_node_reads_as_end_of_stream() {
        let (mut session, mut node) = answered().await;
        node.frame(b"tail", Command::Continue).await;
        node.send(ContentType::Alert, &[1, 0]).await;

        let mut received = Vec::new();
        let mut buffer = [0_u8; 8];
        loop {
            let read = session.read(&mut buffer).await.expect("reads");
            if read == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(received, b"tail");
        assert!(session.peer_closed());
        assert!(session.failure().is_none(), "a half close is not a failure");
    }

    #[tokio::test]
    async fn a_fatal_alert_fails_the_session() {
        let (mut session, mut node) = answered().await;
        node.send(ContentType::Alert, &[2, 40]).await;

        let mut buffer = [0_u8; 8];
        let error = session
            .read(&mut buffer)
            .await
            .expect_err("the node alerted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            session.failure(),
            Some(Error::Session(SessionError::PeerAlert {
                level: 2,
                description: 40,
            }))
        );
    }

    #[tokio::test]
    async fn uplink_bytes_reach_the_node_framed() {
        let (mut session, mut node) = answered().await;
        let pattern: Vec<u8> = (0..=250_u8).collect();
        let payload: Vec<u8> = pattern.iter().copied().cycle().take(BULK).collect();
        session.write_all(&payload).await.expect("writes");
        session.flush().await.expect("flushes");

        let mut received = Vec::new();
        while received.len() < payload.len() {
            received.extend(node.receive_frame().await);
        }
        assert_eq!(received, payload);
    }

    /// Half-close is the alert the node reads as a destination `FIN`, followed by
    /// our write half going away, which is exactly the two steps
    /// `shutdown_tls_writer` performs (`tls13/application_io.rs:994-1015`).
    #[tokio::test]
    async fn half_close_sends_the_alert_the_node_reads_as_a_fin() {
        let (mut session, mut node) = answered().await;
        session.write_all(b"goodbye").await.expect("writes");
        session.shutdown().await.expect("shuts down");

        assert_eq!(node.receive_frame().await, b"goodbye");
        let (kind, alert) = node.receive().await;
        assert_eq!(kind, ContentType::Alert);
        assert_eq!(alert, vec![1, 0]);

        session
            .write_all(b"late")
            .await
            .expect_err("the uplink is closed");
    }

    #[tokio::test]
    async fn a_header_that_is_not_an_encrypted_record_fails_the_session() {
        let (mut session, mut node) = answered().await;
        // A plaintext handshake record: the outer type of a TLS 1.3 record is
        // always application data, so anything else is a desynchronised stream.
        node.stream
            .write_all(&[22, 3, 3, 0, 5, 1, 2, 3, 4, 5])
            .await
            .expect("write");

        let mut buffer = [0_u8; 8];
        let error = session
            .read(&mut buffer)
            .await
            .expect_err("the header is not a record");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            session.failure(),
            Some(Error::Session(SessionError::RecordCorrupted))
        );
    }

    /// The session cannot be tricked into reporting an accepted request that never
    /// completed: the response is only validated once both bytes arrived, however
    /// the records are split, and the rest of the stream stays in step.
    #[tokio::test]
    async fn a_response_split_across_records_is_still_validated() {
        let mut harness = harness();
        harness.node.send(ContentType::ApplicationData, &[0]).await;
        harness.node.answer_from([0, 0], 1).await;
        let (mut session, mut node) = harness.connect().await;
        assert!(!session.awaiting_response);
        assert_eq!(session.response, [0, 0]);

        node.frame(b"after", Command::Continue).await;
        let mut buffer = [0_u8; 16];
        let read = session.read(&mut buffer).await.expect("reads");
        assert_eq!(&buffer[..read], b"after");
    }

    /// Every buffer a session holds is either key material, credentials or
    /// application payload, and none of it may be printable. A byte slice renders
    /// as a bracketed list, so a `Debug` output with no brackets prints counts
    /// only.
    #[tokio::test]
    async fn debug_output_carries_no_key_material_or_payload() {
        let (mut session, _node) = answered().await;
        session
            .write_all(b"application bytes")
            .await
            .expect("writes");
        let rendered = format!("{session:?}");
        assert!(rendered.contains("VisionSession"));
        assert!(!rendered.contains('['), "{rendered}");
    }
}
