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

`VisionMode` after a frame: `Continue` → still Framed, `End` → Raw,
`Direct` → Direct (`:305-316`). Framing stops; the outer TLS records continue,
carrying raw bytes verbatim.

### Uplink layout the server expects

`src/server/vision.rs:693-768` — the VLESS request header is **not** Vision
framed. The server decrypts application records, concatenates the plaintext and
parses the VLESS request from the front of that stream. Whatever bytes follow
the header in the same record are fed to `VisionDecoder` first
(`:1087-1101`). So the client writes:

```text
record plaintext = vless request header || vision frames...
```

### Downlink layout the server produces

`src/server/vision.rs:1336-1360` — response header, then an empty Vision
preamble frame (`plan(0, Continue, long_padding = true)`, UUID prefixed), then
content frames.

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
produces a single `End` frame and then raw bytes (`:1271-1289`). The client's
uplink runs the identical detector over the bytes the local application sends.

Invariants this repository pins by test and this client must preserve: every
plaintext byte before a `Direct` frame is delivered in order, no byte is
duplicated or reordered at the transition, and post-boundary bytes already
buffered are drained ahead of the raw relay (`:1192-1207`).

## Liveness

`docs/en/architecture.md` §1 and `src/transport/tcp.rs`: every data socket on
the server carries `SO_KEEPALIVE` with 30 s idle / 10 s interval / 3 probes.
Authenticated sessions have **no** read-idle timeout: the shared activity flag
is sampled every 5 minutes and only a *completely* idle session expires, so an
asymmetric SSE stream survives indefinitely (`architecture.md` §4, ADR 0030).
There is a separate 120 s pending-**write** stall deadline. The client mirrors
the keepalive baseline and must not impose a userspace read-idle timeout.
