# Protocol evidence — rust-reality `v2.0.1`

Normative source: `jacek4yang/rust-reality` tag `v2.0.1` = commit
`e3fc3dc36b931baec042074d6c88e928caf6941f`.
Interop oracle referenced by that repository: Xray-core `v26.7.28`
(commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`).

Every byte-level statement below is read from the v2.0.1 source, with the
file:line it came from. Nothing here is inferred from memory.

## Scope accepted by the public inbound

`src/protocol/vless/validate.rs:83-107` — a request is accepted only when all
of the following hold, checked after REALITY authentication:

| rule | source |
| --- | --- |
| request UUID == short-ID owner UUID | `validate.rs:90` |
| Addons field 1 (`flow`) == `"xtls-rprx-vision"` exactly | `validate.rs:94-97` |
| command == TCP (`0x01`) | `validate.rs:99` |
| destination present | `validate.rs:103` |

UDP, Mux, Reverse, plain VLESS, non-Vision flow: rejected. There is no
plaintext or WebSocket inbound, and no QUIC in this protocol stack.

## VLESS request header

`src/protocol/vless/decode.rs:153-205`

```text
version        u8   == 0                       (VERSION, types.rs:6)
user id        16 bytes (raw UUID bytes, no dashes)
addons length  u8
addons         addons length bytes
command        u8   == 0x01 (TCP)
port           u16  big endian
address type   u8   0x01 IPv4 | 0x02 domain | 0x03 IPv6
address        4 | 1+len+domain | 16 bytes
```

Domain length is `u8` (max 255) and must be non-zero; accepted characters are
`src/protocol/vless/decode.rs:317-320`:

```rust
byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_'
```

Addons is the Xray protobuf. The Vision flow encodes as
`0x0a, 0x10, "xtls-rprx-vision"` (field 1, wire type 2, length 16).
`src/protocol/vless/addons.rs:196-201` pins exactly this encoding.

## VLESS response header

`src/server/vision.rs:409-410` and `:650`

```text
version  u8 == 0
addons   u8 == 0     (length zero — the inbound never negotiates response addons)
```

The response is a fixed `[0x00, 0x00]`. There is no flow field echoed back.

## Ordering fact that drives hedging

`src/server/vision.rs:365-405`: the server performs routing and
`connect_session_resolved()` **before** writing the response header. If the
destination connection is refused the server shuts the TLS session down without
ever emitting `[0x00, 0x00]`.

Therefore "the VLESS response header arrived" means, end to end:

1. REALITY authenticated (server holds the private key),
2. VLESS request accepted (UUID + flow + destination valid),
3. the server reached the destination.

That is the readiness signal used to race candidates. The VLESS request header
itself is protocol control information, not application payload: the target is
fully known from the local CONNECT before any application byte exists, and no
application byte is committed to a candidate before it wins.

## REALITY authentication

`src/protocol/reality/auth.rs`

```text
client X25519 key pair            -> client_public (32 B)
shared   = X25519(client_private, server_public)            auth.rs:646-661
auth_key = HKDF-SHA256(salt = hello_random[0..20],
                       ikm  = shared,
                       info = b"REALITY", L = 32)           auth.rs:541-550
```

Authenticated plaintext, 16 bytes (`auth.rs:100-104`, verified at `:508-517`):

```text
[0..3]   client version, 3 raw bytes (Xray sends its 3-byte semver)
[3]      reserved, MUST be 0
[4..8]   unix seconds, u32 big endian
[8..16]  short ID, 8 bytes, hex-decoded and right zero padded
```

AEAD (`auth.rs:108-125`):

```text
key     = auth_key
nonce   = hello_random[20..32]                       client_hello.rs:354-369
aad     = ClientHello handshake message with the 32-byte session ID zeroed
plaintext = the 16 bytes above
session_id = ciphertext(16) || GCM tag(16)
```

`reality_aad()` (`client_hello.rs:345-350`) copies the raw handshake message and
zeroes the session-ID range in place. The raw message starts at the handshake
type byte, so the session ID occupies offsets 39..71 (`client_hello.rs:16-18`).

Server-side acceptance conditions (`auth.rs:474-535`):

- ClientHello offers TLS 1.3 via `supported_versions` (`:479`)
- SNI present and matches a configured server name (`:481-488`). Names default
  to the cover host (`src/config/node/reality.rs:68-74`), exact or one-label
  leftmost wildcard.
- an X25519 key share of exactly 32 bytes exists (`client_hello.rs:406-411`)
- the ECDH result is not the all-zero value (`auth.rs:496-498`)
- session ID is exactly 32 bytes (`auth.rs:500-505`)
- AEAD opens, reserved byte is zero, short ID resolves to a UUID
- `|now - client_time| <= max_time_diff_ms`, default **60 000 ms**
  (`reality.rs:49-57`)

## TLS 1.3 continuation

`src/protocol/reality/tls13/handshake.rs:330-531` (`build_server_flight_inner`)

- transcript = `client_hello.raw_message() || server_hello_message` — the real
  ClientHello **with** its non-zero REALITY session ID (`:361-362`, `:369-372`).
  The transcript is hashed incrementally, so a client that hashes the same byte
  ranges gets the same `Finished` (`:369-372`).
- key schedule = ordinary RFC 8446 no-PSK over the ECDHE shared secret
  (`keys.rs:468-506`, RFC 8448 vectors at `keys.rs:670-755`).
- hybrid group, when the cover selected `X25519MLKEM768` (`0x11ec`):
  server share = ML-KEM ciphertext(1088) || server X25519 public(32),
  shared secret = ml-kem shared(32) || x25519 shared(32) (`handshake.rs:663-700`).
  A client that offers only X25519 fails with `MissingClientKeyShare` whenever
  the live cover negotiates the hybrid group, so the client offers both.
- server flight: plaintext `ServerHello`, optional plaintext CCS, then
  EncryptedExtensions / Certificate / CertificateVerify / Finished sealed under
  the handshake keys, optionally followed by one fake New Session Ticket record
  sealed under the **application** keys (`:459-521`).
- client flight: an **exact** CCS record `[20 3 3 0 1 1]`
  (`server_hello.rs:353-355`, optional) followed by exactly one encrypted
  ClientFinished record; `tls13/handshake_read.rs:52-100` reads that and nothing
  else, so the client must not wait for anything after it has sent its flight.

### Record shapes and padding

`CoverHandshakeRecordShape` (`tls13/target_read.rs:49-63`) is copied from the
cover target that answered, so one node presents different shapes on different
days. The server re-seals *its own freshly generated* messages, zero-padding each
record to the cover's observed outer length:

```text
padding      = target_wire_len - (message_len + 22)     :580-588
overhead     = 5 header + 1 inner content type + 16 tag  record.rs:26
             = UNPADDED_RECORD_WIRE_OVERHEAD
inner region = payload || inner_content_type || 0x00 * padding   record.rs:412-460
```

Three shapes exist (`handshake.rs:418-455`):

| shape | records | notes |
| --- | --- | --- |
| `None` | one unpadded, coalesced | only `build_server_flight` (`:302`), which has no production caller |
| `Coalesced { wire_len }` | one padded, coalesced | cover's first encrypted record exceeded 512 bytes |
| `PositionalRecords { wire_lens: [4], nst_wire_len }` | four padded, one per message | plus an **optional** fifth record: the fake ticket |

Reading rules that follow from this:

- A message does **not** fill its record. The reader must frame messages by their
  own `u24` length inside the decrypted region and tolerate trailing zeros
  (`record.rs:643-655` finds the inner content type as the last non-zero byte).
- The fake ticket is an **empty `ApplicationData` record at sequence 0 of the
  application keys**. The same `Tls13RecordLayer` that sealed it becomes the
  tunnel's server-to-client direction (`:406`, `:503-510`, `:528`), so when it
  arrives the server's first tunnel record is already at sequence 1. A client
  therefore must *not* consume or discard it during the handshake: leaving it in
  the socket and opening it as an ordinary record keeps both sides in step
  whether or not it appears. Its arrival is timing-dependent, so the same cover
  yields 4 or 5 records on different connections.
- Application records are **never** padded (`application_io.rs:1030` passes
  `padding_len = 0`), which is why the last-non-zero-byte rule is lossless for
  payload data.
- `body_len == 0` is rejected, and `record.len()` must equal
  `5 + body_len` exactly (`application_io.rs:508-520`, `record.rs:616-645`).
- An inner content type of Alert carries a two-byte `[level, description]`
  (`application_io.rs:536-541`); `description == 0` is `close_notify` and the
  server treats it as an orderly half-close (`server/vision.rs:1116-1123`).
  Inner Handshake or CCS records after the handshake are errors
  (`application_io.rs:542-544`).
- Bounds: `MAX_PLAINTEXT_LEN = 1 << 14`, tag 16, outer content type 23, legacy
  version `{3,3}`; AES-GCM allows `1 << 24` records per key
  (`record.rs:16-27,665-676`).

### ALPN may be absent

`cover_compatible_alpn` (`handshake.rs:547-566`) drops a selected ALPN when the
EncryptedExtensions that claims it would not fit the cover's observed first
record slot — an `h2` claim needs 33 bytes and an OpenSSL-derived slot can be 28.
So `alpn = None` is an expected outcome of this cover class and the client must
accept it rather than treat it as a mismatch.

## REALITY server authentication (what proves the server is real)

`src/protocol/reality/tls13/messages.rs:85-110`

The server self-signs nothing it expects to be trusted. Instead a fixed 178-byte
X.509 template carries the per-process Ed25519 public key at offset **72**
(32 bytes) and, at offset **114**, a 64-byte value that is not a signature but

```text
HMAC-SHA512(key = auth_key, message = ed25519_public_key)
```

So the client authenticates the server by recomputing that HMAC with its own
`auth_key`. Only a party holding the REALITY private key can produce it, because
`auth_key` is derived from the REALITY private key and the client's public share.

`CertificateVerify` is a genuine Ed25519 signature over the RFC 8446
`64×0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || Transcript-Hash`
blob with scheme `0x0807` (`messages.rs:17,56,117-155`). Verifying it against the
same key the HMAC bound pins the transcript to that key, so this client verifies
both — strictly stronger than the HMAC alone, and satisfied by the unmodified
server.

## Vision (`xtls-rprx-vision`)

`src/protocol/vless/vision.rs`

Frame (`:413-427`):

```text
command        u8   0 = Continue, 1 = End, 2 = Direct
content length u16  big endian
padding length u16  big endian
content        content length bytes
padding        padding length zero bytes
```

The **first** frame of each direction is prefixed with the 16-byte UUID
(`:415-419`, decoder `:206-217`). Total frame wire length including the prefix
is capped at `VISION_FRAME_SIZE = 8192` (`:5`, `:265-272`).

Padding choice (`:554-570`), matching Xray's defaults:

```text
threshold = 900, long range = 500, long target = 900, short range = 256
if content_length < 900 && long_padding: rand(500) + 900 - content_length
else:                                    rand(256)
then min(candidate, largest value that still fits the frame cap)
```

`VisionMode` after a frame: `Continue` → still Framed, `End` → `Raw`, `Direct` →
`Direct` (`:305-316`). Both stop *framing*; they do not stop the same thing. After
`End` the outer TLS records continue and carry the destination's bytes as their
plaintext (`DirectionState::Outer` and `relay_outer_downlink`,
`src/server/vision.rs:1403-1409`, `:1842-1872`). After `Direct` the sender replaces
the TLS writer for that direction with the socket itself (`:1411-1417`,
`:1550-1558`), so every later byte on the wire is the destination's own and there
is no record left to open. Two transitions, two layouts, and one word each in this
repository: `Raw` is what the *decoder* has stopped doing, `Direct` is what the
*transport* has become.

### Uplink layout the server expects

`src/server/vision.rs:693-768` — the VLESS request header is **not** Vision
framed. The server decrypts application records, concatenates the plaintext and
parses the VLESS request from the front of that stream. Whatever bytes follow
the header in the same record are fed to `VisionDecoder` first
(`:1087-1101`). So the client writes:

```text
record plaintext = vless request header || vision frames...
```

This client always writes exactly one empty long-padded `Continue` frame behind
the header, which is Xray's own camouflage path: its outbound logs "Insert
padding with empty content to camouflage VLESS header" and writes an empty frame
when no first payload has arrived to coalesce with
(`.upstream/xray/outbound.go:343-349`). The server accepts either — it parses the
request off the front of the concatenated plaintext and hands the remainder to the
decoder — so the choice is purely a length-profile one: a bare request would make
the first record's size a protocol fingerprint, while the padded frame lands in
the same 900-to-1400-byte content band the downlink preamble uses.

### Downlink layout the server produces

`src/server/vision.rs:1336-1361` — the VLESS response header and the opening
Vision frame are assembled *once, inside one AEAD plaintext*: `plan(0, Continue,
long_padding = true)` sized with `checked_add` onto `response_header.len()`, then
`write_assembled` splits the destination at the response length, copies the
header and assembles the empty frame behind it. So the client's first record
after handshake carries `[0, 0]` and a padded empty `Continue` frame together,
and framing begins at plaintext byte 2.

### Continue / End / Direct decision

`src/server/vision.rs:2124-2210` — the sender inspects the payload for nested
TLS records:

```text
observe one complete nested record at a time
if undecided and record is a handshake record: parse ServerHello,
   decide TLS 1.3 vs 1.2 from it
TLS 1.3 and record is ApplicationData            -> Direct
TLS 1.2                                          -> End
undecided after 8 records                        -> End
otherwise                                        -> Continue
```

A non-TLS stream never yields `Record` classification: `NestedRead::Unframed`
produces a single `End` frame and then outer records whose plaintext is the stream
verbatim (`src/server/vision.rs:1374-1390`). The client's uplink runs the identical
detector over the bytes the local application sends.

Invariants this repository pins by test and this client must preserve: every
plaintext byte before a `Direct` frame is delivered in order, no byte is
duplicated or reordered at the transition, and post-boundary bytes already
buffered are drained ahead of the raw relay (`:1192-1207`).

### What the record boundary does not mean

Three facts the session layer depends on, none of which is visible from the
frame format alone:

- **An empty `ApplicationData` record carries nothing and must still be opened.**
  The server's uplink loop does `if record.is_empty() { continue; }`
  (`src/server/vision.rs:1131-1133`), and it sends the fake NewSessionTicket as an
  ordinary empty record. A client that *skips* such a record without decrypting it
  desynchronises its own sequence numbers from the server's, so every later record
  fails its tag. Opening and discarding is the only correct handling.
- **Frame boundaries and record boundaries are independent.** The server packs up
  to four frames into one maximum-sized outer record
  (`MAX_FRAMES_PER_OUTER_RECORD`, `src/server/vision.rs:1426-1489`), whereas
  *Xray's* client emits one 8 KiB frame per record — the server's own uplink
  comment says so outright (`:1070-1072`), which is why the server can stage four
  record payloads per destination write (`UPLINK_STAGE_CAPACITY`, `:1167-1170`).
  Only the preamble is guaranteed to be exactly one record. A decoder must walk
  the plaintext **stream**: one that assumes a frame per record misreads a packed
  downlink, while a sender is free to pack or not.
- **Half-close is an alert, not a FIN.** `shutdown_tls_writer` seals
  `[ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY]` (`= [1, 0]`) and only then shuts the
  transport writer (`src/protocol/reality/tls13/application_io.rs:994-1015`,
  constants at `:12-13`). The peer matches on the *description alone*: any alert
  whose description is `0` is an orderly end — flush staged bytes, reset the idle
  deadline, shut down the destination, settle `Closed`
  (`src/server/vision.rs:1116-1125`); any other alert settles `Failed`. A bare FIN
  at the TCP layer is not an orderly Vision end, and an unencrypted alert is not a
  thing this client may send.

`End` stays inside the framing loop: the server settles the downlink to `Outer` and
runs `relay_outer_downlink` on the same TLS writer, which seals verbatim records
until the destination reaches EOF and then sends close_notify
(`src/server/vision.rs:1403-1410`, `:1842-1872`). `Direct` returns
`DownlinkStep::Direct` and the caller performs the raw transfer
(`:1411-1416`); on the uplink the decoder reports `VisionMode::Direct` mid-record
and the remaining staged bytes are flushed before the handoff (`:1154-1160`). Both
commands end framing, and nothing after either is ever read as a Vision header
again. Only one of them ends the record layer, which is why this client keeps two
transport states rather than one (`Downlink::{Outer, Direct}`,
`src/transport/session.rs`): an `End` downlink is still a sequence of outer records
for these keys to open, while a `Direct` one is the destination's own stream — the
application's ciphertext, never ours to decrypt. Treating the pair as one state was
the defect that made a TLS 1.3 destination unreadable, and the two live tests
`a_tls_1_3_destination_ends_framing_and_the_record_layer_too` and
`a_tls_1_2_destination_ends_framing_but_keeps_the_record_layer` are what pins each
branch to a real node.

## Liveness

Upstream answers three different questions with three different mechanisms, and
the client keeps them apart for the same reason: the common way to break a
long-lived AI session is to answer one of them with another's timer. Bare paths
below are v2.0.1's, as everywhere in this file; the two places that cite this
repository say so in the sentence.

### What the node puts on a data socket

v2.0.1's `configure_accepted` applies `TCP_NODELAY` and the keepalive backstop to an
accepted stream (v2.0.1 `src/transport/tcp.rs:339-374`, whose own test reads
`SO_KEEPALIVE` back and asserts "accepted streams must arm keepalive"), and the same
three values — 30 s idle, 10 s between probes, 3 probes — are what every data socket
carries (v2.0.1 `docs/en/architecture.md` §1). This client keeps one copy of that
policy in `src/transport/socket.rs` (`KEEPALIVE_IDLE` at `:36`, `KEEPALIVE_INTERVAL`
at `:41`, `KEEPALIVE_COUNT` at `:46`, and a 1 s floor at `:54`/`:175` because a zero
`TCP_KEEPINTVL` is a different program, not a faster one) and applies it to both
halves of a carried connection: the dialled tunnel at `src/transport/dial.rs:205` and
the accepted local socket at `src/serve.rs:562`.

These are first-hop facts about the socket between this client and the node. A
keepalive answer from `LINE` says nothing about `LANDING` or about the AI service
behind it: the probe is answered by the peer's TCP stack, which is alive as long
as it has a socket, whether or not anything above it still works. End-to-end
health is only ever shown by the application's own bytes moving — including its
own WebSocket Ping/Pong, which this client carries as payload and never
generates.

### Reads after authentication are untimed, deliberately

`io_activity` states the design in its own first seven lines: a successful I/O
event is "one relaxed store, never a clock read, timer reset, allocation, or
wakeup", one coordinator samples the flag at window boundaries, "Writes have a
separate stall deadline" (`src/io_activity.rs:1-7`), and the window is
`SESSION_IDLE_WINDOW` = 300 s (`:17`). A *completely* idle session is therefore
reclaimed within two windows, while an asymmetric stream — the server still
writing, the client silent for ten minutes — never qualifies, which is what ADR
0030 exists for (`docs/en/architecture.md` §4). The TLS 1.3 layer spells out the
consequence: "Attaching session activity removes read-idle enforcement: either
direction can keep the connection alive, including while a TLS record is
incomplete… No timer is reset, allocated or polled for an authenticated read"
(`src/protocol/reality/tls13/idle.rs:1-8`).

So: quiet is not the same as broken, and connection age is not a failure signal.
This client arms no per-direction read-idle timeout, and its `carry`
(`src/transport/relay.rs`, this repository) constructs no timer at all — the shape
v2.0.1's own relay takes when the stall window is `None`
(v2.0.1 `src/transport/tcp_relay.rs:715`).

### A pending write is a separate, finite question

`WRITE_STALL_TIMEOUT` = 120 s (`src/io_activity.rs:13-14`) is described upstream
as a write-stall bound "unrelated to fallback". It is armed per chunk and shared
by that chunk's read and write, so "steady progress never times out, while a peer
that stalls for the whole window ends the direction with
`io::ErrorKind::TimedOut` instead of parking on its permit forever", and `None`
"constructs no timer at all" (`src/transport/tcp_relay.rs:709-715`). The
rationale for separating it from reads is in the same function's comment:
"Quiet reads are not stalled writes. TCP keepalive and peer FIN govern raw
lifetime, including when only the other direction moves" (`:735-736`).

This client does not arm that bound, and the choice is stated rather than implied:
the traffic it is tuned for includes a model streaming tokens into a socket the
application is reading slowly, where a bound picked for a synchronous request
would be the thing that ends a healthy transfer. What keeps that from becoming an
unbounded queue is not a timer — it is that this repository's copy loop
(`src/transport/relay.rs`, `RELAY_BUFFER`) has one fixed 8 KiB buffer per direction
and cannot read the next chunk until the current one is accepted, so a stalled
writer stops pulling and backpressure lands where TCP already handles it: the
source's socket receive buffer. What ends such a wait, if it ever does,
is the kernel's own budget for unacknowledged data (`tcp_retries2`, 13 to 30 minutes
at Linux's default of 15) rather than a deadline this program invented — and that is
the one case in this section this build did *not* measure: the runs behind it in
`docs/OPERATIONS.md` stall a peer for eight seconds and then resume it, which is what
ordinary backpressure looks like, not what a permanently unread peer looks like.

### Setup deadlines stay finite

None of the above applies before a session exists. Address resolution, the dial
race, REALITY authentication and the VLESS request/response all keep finite
bounds in this repository — `DNS_BUDGET` 5 s and `CONNECT_BUDGET` 10 s
(`src/transport/dial.rs:45`, `:53`), `FIRST_BYTE_BUDGET` 15 s
(`src/handoff.rs:78`) — because an unanswered setup question has no value in being
asked longer, and a stuck handshake that is not released is a slot that nobody
else can use.

## Tiny initial raw responses on the pinned server

`src/server/vision.rs:1936-1951` loops until `NESTED_TLS_HEADER_SIZE` (five bytes)
or destination EOF before classifying the first downlink. A destination sending
three bytes and waiting on an open socket can therefore deadlock an application
request/response exchange. Controlled three-byte echo probes timed out through
both the Rust client and stock Xray v26.9.9; the direct-origin control passed.
The application fixture exposes `--raw-probe-bytes 3` for reproduction. This is
an unchanged-server limitation, not evidence to silently pad/replay application
bytes or claim that switching entry nodes fixes it.
