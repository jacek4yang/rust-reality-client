# rust-reality-client

A native Rust client for **VLESS + REALITY + `xtls-rprx-vision`**, wire-compatible
with an unmodified [`rust-reality`](https://github.com/jacek4yang/rust-reality)
`v2.0.1` entry node. It exposes local SOCKS5 and HTTP CONNECT listeners and is
built around one goal: fewer `Connection error` events, fewer stalls, and no
route switching that TCP does not actually allow.

```bash
rust-reality-client generate --out client.toml   # writes a commented file with a real user id
$EDITOR client.toml                              # address, publicKey, shortId from your node
rust-reality-client check  --config client.toml  # every problem in the file, at once
rust-reality-client doctor --config client.toml  # is it reachable, and who is at fault if not
rust-reality-client run    --config client.toml  # SOCKS5 127.0.0.1:10808, HTTP 127.0.0.1:10809
```

No Xray process, no Go runtime, no shared library: one static-ish binary and one
TOML file. The server is not modified, configured differently, or restarted.

---

## 1. What `rust-reality-client` is

It is the client half of one narrow protocol stack, implemented from the upstream
source rather than from a wrapper:

```text
application ──▶ SOCKS5 or HTTP CONNECT (loopback)
                   │
                   ▼
             scheduler ── which node, right now
                   │
                   ▼
             handoff ──── TCP + Happy Eyeballs + TLS 1.3 + REALITY auth
                   │
                   ▼
             vless ────── one request, one response header
                   │
                   ▼
             vision ───── xtls-rprx-vision framing, then the Direct path
                   │
                   ▼
             relay ────── both directions, half-close, counted bytes
                   │
                   ▼
        unmodified rust-reality v2.0.1 ──▶ destination
```

It is a *proxy edge*, not a VPN: it terminates no traffic it is not asked to
carry, it holds no listener that was not configured, and it has no control
channel to anybody.

The migration it is meant to enable is client-side only:

```text
before:  Pi ─▶ Xray client ─▶ VLESS + REALITY + Vision ─▶ rust-reality v2.0.1
after:   Pi ─▶ rust-reality-client ─▶ VLESS + REALITY + Vision ─▶ rust-reality v2.0.1
```

## 2. Exact compatibility target

**`jacek4yang/rust-reality` tag `v2.0.1`, commit `e3fc3dc36b931baec042074d6c88e928caf6941f`**
— built from that commit with no patch applied, and the reference against which
the interop gate runs.

| Aspect | What this client implements |
| --- | --- |
| Transport | TCP only, one connection per session |
| Inbound accepted by the node | VLESS `TCP` + `flow: xtls-rprx-vision` |
| REALITY key groups | `X25519` (`0x001d`) and `X25519MLKEM768` (`0x11ec`) |
| Authentication | AES-256-GCM / ChaCha20-Poly1305 record AEAD, `REALITY` HKDF label, 16-byte plaintext, 20-byte nonce offset — as `v2.0.1` reads them |
| ALPN | offered, and tolerated when absent |
| Vision | `Continue` / `End` / `Direct` decision, 8 KiB frames, the padding distributions the server produces |
| Timestamp tolerance | the node's own `maxTimeDiffMs` default (60 000 ms) |
| UDP, MUX, `x25519` fingerprints, other flows | **not** implemented, because `v2.0.1` does not accept them |

Wire behaviour is derived from the upstream source and proven by tests, not from
memory: [`docs/PROTOCOL.md`](docs/PROTOCOL.md) records the exact upstream file
and line for each requirement, and `tests/interop_v201.rs` runs 22 live tests
against the real node (handshake, foreign-key rejection, a Vision round trip
through the echo target, half-close, both inbounds, the scheduler routing past a
node that cannot authenticate, five destination fault shapes, a nested TLS 1.2
and a nested TLS 1.3 destination with the record-layer transition each one
provokes, an idle tunnel held past the keepalive window, a session quiet past
that same window, a connect storm, and a soak).

`cargo test --locked --test interop_v201 -- --ignored --test-threads=1` is the
gate, and CI's `interop` job runs it against a node built from the commit above
on every push to `main`, every pull request, and every tag.

## 3. Architecture

One crate, `#![forbid(unsafe_code)]`, no plugin system, no dynamic loading, no
database, no web UI. The layers and their job:

| Layer | Module | Responsibility |
| --- | --- | --- |
| Edge | `inbound` | SOCKS5 and HTTP CONNECT parsing, every read bounded by its own stated length |
| Process | `serve` | listeners, one shared connection budget, accounting, shutdown |
| Handoff | `handoff` | one node, one authenticated tunnel |
| Connect | `transport` | DNS, Happy Eyeballs, racing, socket tuning, Vision session, relay |
| Choice | `scheduler` | which node, stickiness, hedging, breaker, health |
| Wire | `protocol` | VLESS framing, REALITY, TLS 1.3 records, Vision |
| Host | `config`, `logging`, `error` | validation, redaction, the failure taxonomy |

The layering exists to protect one boundary, stated in full in section 18:
**node choice is only possible before the application is told the tunnel
exists.** `Scheduler` sits above `Handoff` and below the inbounds precisely
because that is the one place a choice still exists. Once `Established` is
returned, the node is immutable for the life of that connection, and the code
has no type that could retry it elsewhere.

## 4. Installation

**From a release artifact.** Each release carries one archive per target, each
with the binary, this README, `examples/client.toml` and a `VERSION` file:

```text
rust-reality-client-<tag>-x86_64-gnu.tar.gz
rust-reality-client-<tag>-x86_64-musl.tar.gz
rust-reality-client-<tag>-aarch64-gnu.tar.gz
SHA256SUMS
```

```bash
sha256sum --check --strict SHA256SUMS
tar -xzf rust-reality-client-v0.1.0-x86_64-gnu.tar.gz
install -m 0755 rust-reality-client-*/rust-reality-client /usr/local/bin/
rust-reality-client --version
```

The archives are built with `--locked` on a toolchain pinned by exact patch
release, `codegen-units = 1`, `lto = "thin"`, symbols stripped, and tar
normalised (sorted, zeroed ownership, `gzip -n`) so that the published checksum
is a claim about a commit rather than about the time a runner finished.

**From source.** Rust 1.85 or newer (the declared `rust-version`, and CI checks
against it):

```bash
cargo build --release --locked
./target/release/rust-reality-client --version
```

`x86_64-unknown-linux-musl` builds statically against `musl-tools`; the aarch64
GNU cross build needs `gcc-aarch64-linux-gnu` and `libc6-dev-arm64-cross`. On a
Raspberry Pi OS of current vintage, the `aarch64-gnu` artifact is the one to use.

## 5. Configuration

```bash
rust-reality-client generate --out client.toml
```

`generate` draws a fresh UUID v4 from the OS CSPRNG rather than leaving you a
placeholder, because a copied user id is a silent collision with another node.
The shape:

```toml
[listen]
socks5 = "127.0.0.1:10808"       # "" disables this edge
http = "127.0.0.1:10809"
# allowRemote = false            # anything off loopback needs this set on purpose

[[node]]
name = "home-entry"
address = "www.example.com"
port = 443
userId = "…"                     # the node's user id: an authentication credential

[node.reality]
publicKey = "…"                  # URL-safe unpadded base64, exactly 32 bytes
shortId = "abcd"                 # 2–16 hex characters, even count
serverName = "www.example.com"   # the SNI the cover answers to
```

Rules the parser enforces, each with a message naming the path and never the
value:

* `[listen]` addresses must be numeric (`127.0.0.1:10808`, `[::1]:10808`) and
  the port may not be `0`.
* A non-loopback bind is refused unless `allowRemote = true`.
* `publicKey` must decode to exactly 32 bytes; `shortId` must be even-length hex
  of 2–16 characters; `userId` must be a canonical hyphenated UUID.
* `[[node]]` is an array of tables; at least one is required, and duplicates are
  reported rather than silently merged.
* Every problem in the file is reported in one pass, so `check` is a work list
  and not a lottery.
* Keys Xray uses (`pbk`, `sni`, `sid`, `fp`, `flow`) are refused with the
  equivalent in this grammar, because a migrated file is the most likely way to
  arrive here with a wrong shape.

Leaving `[listen]` out entirely gives the mandated `127.0.0.1:10808` /
`127.0.0.1:10809` pair.

## 6. SOCKS5 usage

`socks5://127.0.0.1:10808` — RFC 1928/1929, `CONNECT` only, `NO AUTH`, and
IPv4 / IPv6 / domain address types.

```bash
curl --socks5-hostname 127.0.0.1:10808 https://example.com/
curl -x socks5h://127.0.0.1:10808 https://example.com/
```

The edge answers `COMMAND_NOT_SUPPORTED` (0x07) for `BIND` and `UDP ASSOCIATE`
and never pretends otherwise, so a client that asked for UDP fails in the way it
was promised. `HOST_UNREACHABLE`, `CONNECTION_REFUSED`, `NOT_ALLOWED` and
`ADDRESS_NOT_SUPPORTED` map from the failure taxonomy in section 14; a domain
name longer than 255 bytes is a parse-time refusal rather than a truncation.

**`socks5h://` versus `socks5://` matters here.** With `socks5h://` (SOCKS5 with
remote DNS) the application sends the *domain*, and the node resolves it. With
plain `socks5://` the application resolves locally and sends an address, which
means your network's resolver learns every hostname you visit and the node
cannot do its own dual-stack selection. Use `socks5h://` / `--socks5-hostname`.

## 7. HTTP CONNECT usage

`http://127.0.0.1:10809` — an `HTTP/1.x` request line, then `CONNECT host:port`.

```bash
curl -x http://127.0.0.1:10809 https://example.com/
export HTTPS_PROXY=http://127.0.0.1:10809
```

Only `CONNECT` is served. Anything else gets a real status and a `Connection:
close`: `405` for another method, `400` for a malformed request line, `431` when
the head exceeds 8 KiB, `505` for a version this edge does not speak, `502` when
the node was asked and could not carry the connection, `503` when the process is
at its connection limit, `504` when the establishment budget ran out. A `200
Connection Established` head is the last thing this edge says about that
connection: after it, the tunnel is immutable (section 18).

`Proxy-Authorization` is not read, so a credential cannot arrive in a header this
process would then log.

## 8. Pi Agent usage

The recommended setup for an agent that mostly speaks HTTPS, on a Raspberry Pi
running this client beside it:

```bash
export HTTPS_PROXY=http://127.0.0.1:10809
export HTTP_PROXY=http://127.0.0.1:10809
export NO_PROXY=localhost,127.0.0.1
```

The HTTP CONNECT listener is the right default for an agent because nearly every
SDK, `curl`, `requests`, `fetch` and `pip` honour `HTTPS_PROXY`, whereas SOCKS5
support is patchier and `pip` does not read the SOCKS variables at all.

Where a tool does speak SOCKS5, prefer the remote-DNS spelling:

```bash
export ALL_PROXY=socks5h://127.0.0.1:10808
```

`socks5://` (without the `h`) resolves the hostname on the Pi before connecting.
That is the difference between your ISP's resolver learning every host the agent
touches and the node resolving it — and, on a network where the Pi's own resolver
is slow or IPv6-broken, it is also the difference between the agent stalling on
`getaddrinfo` and the node's dual-stack dial answering. Use `socks5h://` unless
a client cannot send a domain.

Keep `NO_PROXY` (or the client's own bypass list) pointed at loopback: an agent
that proxies its own health check through a tunnel and back is a way to write a
monitor that reports the network instead of the process.

## 9. Multi-node stability behavior

Several `[[node]]` entries are not a load balancer here. One node leads, the
others are alternates, and a node's standing comes from what it has been
measured doing rather than from its position in the file:

* **Every connection is timed in three parts** — the TCP connect, the
  authentication plus the VLESS answer, and the whole including resolution
  (`Established` in `src/handoff.rs`) — so a node that takes 400 ms to
  authenticate and 4 s to reach destinations is not scored as "slow".
* **Latency memory expires** after 300 s (`LATENCY_MEMORY`, the same value the
  node's own dial tuning uses). A measurement from five minutes ago is not a fact
  about this network now.
* **Health is an EWMA over seven samples** (`EWMA_HISTORY`), which makes one
  spectacularly bad connection a data point rather than a verdict.
* **A fault is charged to the party that caused it** (`Fault::of`):
  *node* (REALITY refused, handshake broke, the connect to it failed),
  *destination* (the site the application asked for was down — nothing moves a
  node's score), and *local* (this process's own limits, timeouts of its own
  making). The split is the whole answer to "why does this connection break".
* **A cancelled hedge loser is not a failed node.** A dropped future never
  settles, so the only thing it can record is the weak evidence that the winner
  was faster — and that has to happen three times in a row
  (`HEDGE_SWITCH_THRESHOLD`) before a route moves.

The bounds are process-wide and fixed: 256 concurrent local connections, 32
concurrent handshakes, 1024 tracked-but-not-yet-admitted sockets, 16 candidates
max from one resolution, 2 in-flight connects per destination, 2 hedged
candidates per logical connection, 16 concurrent hedge attempts, 4 active
probes.

## 10. Sticky routing

Every new connection starts from the sticky primary. Nothing is sent to a second
node merely because it was also configured.

An *elective* switch — one not forced by a failure — has to clear three bars:

1. the incumbent has been measured for at least `Policy::dwell` (default 30 s),
2. the alternate is faster by at least 25% of the incumbent's own pace
   (`MIN_IMPROVEMENT`), **and**
3. by at least 20 ms in absolute terms (`MIN_MARGIN`).

That is hysteresis, and its purpose is narrow and honest: two nodes whose
estimates cross back and forth every few seconds would otherwise move *every*
connection with each crossing, and each move means a new tunnel on a path nobody
has measured. The client switches when a node is broken and when a node is
*plain* worse; it does not switch because an estimate moved by 30 ms.

The cost of stickiness is stated plainly: one bad node can be reached by every
connection until it fails twice and the breaker opens. The hedge and the breaker
are what make that safe, rather than a smaller dwell.

## 11. Hedged dialing

Hedging is a second candidate started *late*, for the connection that is already
behind schedule — not a fan-out.

The delay is `2 ×` the primary's remembered pace, clamped into
`hedge_min`..`hedge_max`:

| Constant | Value | Why |
| --- | --- | --- |
| `HEDGE_MIN` | 150 ms | below this you hedge against your own jitter, and every page load pays for two authentications |
| `HEDGE_INITIAL` | 275 ms | the midpoint of the 250–300 ms band for a node with no measurement yet |
| `HEDGE_MAX` | 750 ms | past this the user has already decided the page is broken |
| `MAX_HEDGED_CANDIDATES` | 2 | a `Plan` cannot express more; "try every node" is not a state this type has |

What makes a hedge *safe* is one ordering fact about the node, recorded in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md#ordering-fact-that-drives-hedging):
`v2.0.1` performs routing and connects to the destination **before** it writes
the VLESS response header, and a refused destination shuts the TLS session down
without ever emitting it. So "the response header arrived" means, end to end:
REALITY authenticated, the request accepted, and the server reached the
destination. That is the readiness signal a candidate is judged on.

Two consequences, both load-bearing:

* The VLESS request header is protocol control information, not application
  payload. The destination is fully known from the local `CONNECT` before any
  application byte exists, so racing candidates replays nothing.
* **The winner's un-used sibling is cancelled and its socket closed before the
  application is answered.** A loser is not a connection that failed; it is a
  connection that was never needed, and `Health` is written where an attempt
  *settles*, not where a future is dropped.

After the answer, hedging is over forever for that connection: no byte is
replayed, no retry happens on another node, and no failure is hidden.

## 12. Circuit breaker

Two consecutive *charged* faults (`BREAKER_STRIKES`) open a node's breaker. Two
rather than one because a single failure is often the destination or a moment on
the path; one rather than three because the hedge already covered the connection
that saw it — the second fault is what tells you the first was not alone.

* The window starts at 2 s (`COOLDOWN`) and **doubles with each trip** up to 30 s
  (`COOLDOWN_MAX`): a node that is really gone costs one attempt per half minute
  instead of one per connection, and an operator who fixes a configuration
  mistake is not kept waiting by this client.
* One recovery attempt is allowed per window, held as a **lease on a deadline**
  (`RECOVERY_LEASE`, 2 s) rather than as a counter — a counter somebody forgets
  to release is a node that never comes back, which is exactly the class of bug a
  soak test is for.
* An **active probe** normally takes that attempt `PROBE_LEAD` (250 ms) before the
  window ends, so the node is measured warm at the moment the next connection
  could use it rather than being discovered then. A probe is a dial plus a REALITY
  handshake and **no VLESS request**: it costs the node no work toward any
  destination and costs this process one authentication. At most 4 run at once,
  process-wide, on nothing but the client's own curiosity.
* A node tripped by a **credentials refusal is never probed**, because a probe
  cannot test a user id and would fail forever.
* A node that is merely slower, with nothing failing, is demoted by lost races
  instead — three consecutive ones (`HEDGE_SWITCH_THRESHOLD`).

## 13. TCP keepalive

Every data socket gets `TCP_NODELAY` and kernel keepalive armed **before any byte
is written** — both halves of a carried connection, not just the node side, because
a peer that died without a FIN is just as invisible on the socket your application
owns as on the tunnel. The one policy lives in `src/transport/socket.rs` and is
applied by `src/transport/dial.rs:205` and `src/serve.rs:562`. Arming early matters
because a socket that negotiates a REALITY handshake in sixteen record-sized bursts
is exactly where `NODELAY` earns its keep, and because keepalive timers count from
the first silence rather than from whenever somebody remembers to arm them.

| Knob | Value |
| --- | --- |
| `KEEPALIVE_IDLE` | 30 s |
| `KEEPALIVE_INTERVAL` | 10 s |
| `KEEPALIVE_COUNT` | 3 probes |
| Detection of a silent blackhole | **59.1 s measured**, ~60 s of arithmetic |

The measured number is the first row of the six-run table in
[`docs/OPERATIONS.md`](docs/OPERATIONS.md): a path that stopped delivering anything,
with a read parked on it and no userspace timer anywhere in the relay, produced
`ETIMEDOUT` on both ends 59.1 s later. Sixty seconds is chosen to stay well inside
the node's own 120 s write-stall bound (`src/io_activity.rs:14` upstream), so this
client learns a peer is gone from its own socket rather than losing that race, and a
test asserts both the arithmetic and the inequality.

Tolerance is a separate number and it is not a duration. An outage that swallowed one
probe slot was survived; an outage that covered all three slots killed the session
**even after connectivity returned**, because both ends had already been told the
socket was dead. A socket that is *carrying* bytes is not subject to that at all — a
5 s outage in the middle of a 1 MiB write cost 6.5 s and the transfer completed on
retransmission alone. Deliberately absent:

* **A 60 s per-socket `TCP_USER_TIMEOUT` on Linux/Android.** Actual packet-loss
  experiments exposed the gap in keepalive-only handling when data is outstanding.
  The Linux control detected an idle blackhole in 60.99 s and a writing blackhole
  in 78.52 s, while 5/20/40 s transient outages recovered with byte-exact payloads.
  This is a kernel pending-data bound, not an application read-idle deadline or
  an exact sixty-second wall-clock promise. Windows retains keepalive; this
  pending-data bound is not claimed there. See [experiment evidence](docs/experiments/README.md).
* **No userspace read-idle timeout for healthy authenticated connections.** A quiet
  tunnel is a working tunnel. An idle SSE stream is left alone for as long as it
  stays quiet, and only the kernel probes decide whether it is alive.
* **No invented write-stall timer.** The copy loop holds one fixed 8 KiB buffer per
  direction and cannot pull the next chunk until the current one is accepted, so a
  peer that stops reading stops the flow instead of filling a queue. Acceptance into
  the local kernel's send buffer is *not* proof the peer got the bytes: 64 KiB was
  accepted in 0 ms and read 7994 ms later.

Half-close is forwarded, not truncated: a client's `FIN` reaches the destination
without cutting the reverse direction, and the node's `close_notify` reads as end of
stream rather than as an error. A WebSocket `Ping`, `Pong` or `Close` is payload to
this proxy — carried byte for byte, never generated on the application's behalf, and
never taken as proof that the service behind the node is healthy.

### Established-session feedback

The scheduler also receives one terminal observation per adopted session. Writer
acceptance counts survive errors and cancellation; they do not prove delivery.
Logs keep node index, family, setup/session age, direction/operation and cause,
without application content or credentials. Cancellation, local shutdown, normal
EOF and ambiguous remote resets do not become entry-node convictions.

Three tunnel-read protocol defects within five minutes add a bounded 500 ms
selection cost for thirty seconds. This never bans a route or affects a live
stream. Costs remain family-specific; a recently successful alternate family
is not charged. Unknown completion is not proof that an alternate family works.
A healthy bidirectional session lasting thirty seconds can clear its family's
cost; a handshake probe cannot. Late pre-recovery observations cannot re-poison
that recovery. This is not a detector of encrypted HTTP errors, provider rate
limits, or a cure for shared LANDING failures.

## 14. Diagnostics

```text
rust-reality-client check    --config PATH
rust-reality-client doctor   --config PATH [--node NAME]
rust-reality-client explain  <family>
rust-reality-client generate [--out PATH]
rust-reality-client run      --config PATH [-L LEVEL]
```

Exit codes everywhere: **0** ok, **1** the file, node or process is not sound,
**2** a usage error (`clap` itself: an unknown command, a missing value).

`check` prints every problem in the file with its path, plus a one-line summary
when the file is sound: `ok: 2 node(s), listening on 127.0.0.1:10808,
127.0.0.1:10809`, then per node `name: endpoint serverName=… shortId=N chars
publicKey=…`. The user id is never repeated back — it is the credential.

`doctor` answers "what is wrong" as a table of `PASS` / `WARN` / `FAIL` verdicts
(`check`, `listeners`, `keys`, `reach`, `clock`, …) with a machine-readable
summary line, `PASS|WARN|FAIL n checks: a pass, b warn, c fail`, so it can be
wired into a health check. Its honesty is the interesting part:

* A **successful** REALITY handshake proves the clocks agree to within the node's
  `maxTimeDiffMs` (60 s default), because authentication is time-windowed. That
  verdict is earned, not assumed.
* A **failed** handshake cannot be attributed. `doctor` says so: clock skew is
  indistinguishable from a wrong `publicKey` or `shortId`, because all three are
  answered by a silent relay to the cover. It reports `WARN` and names the three
  causes rather than picking one.
* A `DNS` or `connect` failure to reach the node is a `FAIL`. A refusal from this
  process's own limits is a `WARN` about this machine, not about the node.

`explain` turns a failure family into what to do about it:

```text
local      dns       connect      timeout
handshake  rejected  idle
```

Each says *whose* fault it is — which is the difference between "restart the
client" and "the site you asked for is down". `local` never counts against a
node; `connect` and `handshake` do.

The running process answers for itself too. On stop it prints

```text
stopped: 128 accepted, 121 carried, 4 refused, 3 failed, 0 unresolved
```

and the same five counters are available in-process from `Report`. `unresolved`
is the one that should never be above zero: it means a connection task was
cancelled during the shutdown grace, panicked, or otherwise failed to report.
Growth there is a fact about this process, not about the network.

## 15. Logs

One JSON object per line, on stderr, nothing else.

```json
{"timestampUnixMs":1760000000123,"level":"info","event":"bound","inbound":"socks5","address":"127.0.0.1:10808","nodes":2}
{"timestampUnixMs":1760000004567,"level":"debug","event":"accepted","inbound":"socks5","peer":"127.0.0.1:53211"}
{"timestampUnixMs":1760000005012,"level":"warn","event":"failed","inbound":"socks5","error":"transport error: connection refused","family":"connect","countsAgainstNode":true,"elapsed":742}
```

Levels: `error`, `warn`, `info`, `debug` (default `info`), selected with
`--log-level` / `-L`; a value outside that set is a usage error that prints the
accepted list rather than silently defaulting.

The vocabulary is small and each event has exactly one level:
`bound` (info), `accepted` / `carried` (debug), `refused` (info, or warn when it
is a limit being hit), `failed` (warn), `acceptFailed` (warn then error),
`listenerLost` (error), `signalUnavailable` (warn), `doctorProbe` (debug),
`stopping` / `stopped` (info). A carried connection is `debug` on purpose: a
browser page load is fifty of them, and a log that drowns the interesting lines
with the normal case has no operational value.

Never written, by construction rather than by scrubbing:

* node user ids (the credential) and private key material, ever;
* `shortId` beyond its character count;
* request payloads, destination URLs with credentials, or full destinations at
  `info` and above;
* anything derived from a rejected configuration value — `check` names the path
  and the rule, never the offending text, because the offending text is the
  secret.

`Debug` implementations across the crate follow the same rule: they print shapes,
counts and bound addresses, never node names or key material. There is no
telemetry, no update check, no crash reporter and no external control service —
the only outbound connections this process makes are to the nodes you configure.

## 16. systemd

[`examples/systemd/rust-reality-client.service`](examples/systemd/rust-reality-client.service)
is the unit, with its install commands in the header comment. The parts worth
reading before you change it:

* `User=`/`Group=` an unprivileged system account, `0640 root:rust-reality-client`
  on the file holding the user id.
* `KillSignal=SIGTERM`, `KillMode=control-group`, `TimeoutStopSec=15`. The process
  stops *gracefully*: it stops accepting, then gives running connections
  `SHUTDOWN_GRACE` (10 s) to finish, and anything still going past that is
  cancelled and counted in `unresolved`. Fifteen seconds leaves the graceful path
  room without letting a stuck connection hostage a shutdown.
* `Restart=on-failure` with `RestartSec=2s`: a node that is down is a reason to
  try again shortly, and a crash loop is not allowed to become a CPU spinner.
* Hardening: `NoNewPrivileges`, `CapabilityBoundingSet=` and `AmbientCapabilities=`
  empty (binding a port above 1024 needs neither), `ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`,
  `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictNamespaces`,
  `RestrictRealtime`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`,
  `LockPersonality`, `SystemCallFilter=@system-service` with
  `SystemCallErrorNumber=EPERM`, `SystemCallArchitectures=native`,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.

The address-family line is the one to check against your own host: those three
cover TCP to the node and C-library name resolution. If a name service on the
machine needs `AF_NETLINK`, add it explicitly rather than loosening the whole
list.

`journalctl -u rust-reality-client -o cat` gives you the JSON directly.

## 17. Security model

**Trust boundaries, in order of how much they are assumed against.**

1. *A local application talking to these listeners.* It controls every byte of a
   SOCKS5 request and an HTTP head, so every read is bounded by the length that
   request itself states: 8 KiB for an HTTP head, 255 bytes for a domain, 16
   candidates from one resolution, one TLS record's wire length as the ceiling on
   any session read (`MAX_RECORD_WIRE_LEN`, `src/protocol/tls13.rs:674`), and an
   8 KiB relay buffer in each direction. Greeting, request and head reads each
   carry their own deadline. Concurrent handshakes, local connections, hedged
   attempts and probes are separately capped, so a local process that opens
   sockets and never speaks can grow the tracked table to 1024 and no further —
   that is the ceiling on what one machine can make this process hold.
2. *The network path.* The node authenticates the client with REALITY and the
   client authenticates the node in return: the handshake's server
   authentication is checked, and a non-contributory X25519 result is refused
   before anything is sent. On-path parties see a TLS 1.3 session to a cover
   hostname. What REALITY does **not** do is hide volume, timing or the fact that
   a long connection exists, and it does not protect a stolen `userId`: that
   credential is bearer-only, hence `0640`, hence `umask 077`, hence never logged.
3. *This process's own memory.* `#![forbid(unsafe_code)]`, the crypto stack pinned
   to the same versions `v2.0.1` builds with (so wire behaviour cannot diverge
   through a primitive's backend choice), `zeroize` on secrets, no `unwrap`/
   `panic!` on any network path, and `unused_must_use = "deny"` plus clippy
   `pedantic` denied so a dropped `Result` is a build failure.
4. *Supply chain.* `Cargo.lock` is committed and every build and test command uses
   `--locked`. CI actions are pinned by full commit SHA and the toolchain by exact
   patch release. No floating branch or floating tag is used for anything.
   Nothing in this crate phones home.

**Localhost by default is a security property, not a convenience.** A listener on
`0.0.0.0` is an open relay to whoever can reach that port; this client refuses a
non-loopback bind unless `allowRemote = true` is written on purpose, and says why
in the refusal.

## 18. Limitations

> rust-reality v2.0.1 does not provide session migration. If an
> already-established remote TCP connection truly dies, rust-reality-client
> cannot transparently move that same stream to another node. Multi-node failover
> improves connection establishment and subsequent connections; it does not
> violate TCP semantics.

This is not a roadmap item and no release of this client will contradict it.
`v2.0.1` defines no cross-node resume; a live TCP stream identified by its four-
tuple and its sequence numbers cannot be moved between two servers without
breaking it. Anything that appeared to do so would be replaying bytes you did not
ask to have replayed — which for a non-idempotent request is a duplicate, not a
recovery.

So the guarantees are, exactly:

* After `SOCKS5` success or `HTTP 200 Connection Established`, **the remote
  session is immutable**: no silent replay, no retry on another server, no
  duplication to several servers.
* A remote failure **terminates the local connection honestly**, with the reason
  the relay got.
* All node selection and racing happens **during establishment only**, before the
  local application is told `CONNECT` succeeded and before application payload is
  committed to a winner.

Out of scope for v1, deliberately, and not "not yet":

* QUIC and HTTP/3 as a carrier.
* Custom session migration, and transparent migration of established TCP.
* UDP proxying (`UDP ASSOCIATE` is refused, as the protocol table says).
* TUN / transparent interception.
* MUX, and any multiplexing of streams over one tunnel.
* Other VLESS flows, and arbitrary protocol extensions.
* Any change to, or fork of, the server.
* Kernel or eBPF acceleration; multi-path packet duplication; speculative replay
  of application data; "seamless failover" of any kind.

Known rough edges worth naming:

* The pinned v2.0.1 server waits for five destination bytes (or EOF) when
  classifying the first downlink. A three-byte raw echo response on a connection
  that stays open stalls through both this client and stock Xray, but succeeds
  without the proxy. This server limitation is not fixed by changing clients;
  TLS/WSS/SSE acceptance does not establish arbitrary tiny raw-TCP behavior.

* A session that stays **quiet** through an outage covering all three probe slots —
  about 40 s of the armed 30/10/3 window — is lost even when the path heals inside a
  minute, because both ends' kernels have already been told the socket is dead
  (section 13). The earlier bulk experiment used a **5 s** outage, not the 40 s
  quiet-outage schedule: it cost 6.5 s and completed. Those are different cases.
  Raising the tolerance means raising `KEEPALIVE_COUNT` or `_INTERVAL`, which slows
  blackhole detection by the same amount, and that trade is measured rather than
  guessed at.
* One `userId` per node, because that is what the file shape describes.
* `doctor` cannot distinguish clock skew from a wrong key or short id on a failed
  handshake — it says so rather than guessing (section 14).
* Latency memory is 300 s, so a node that becomes good again after a longer
  outage is discovered by probe and breaker recovery rather than instantly.
* The soak and interop suites need a live node and an echo destination; they are
  `#[ignore]`d locally and run in CI against the pinned `v2.0.1` commit.
* Windows and macOS builds work and are tested in development, but the released
  artifacts are Linux `x86_64-gnu`, `x86_64-musl` and `aarch64-gnu`.

---

Further reading: [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire evidence with
upstream file and line citations, [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for
deployment and tuning, and
[`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) for what is claimed and the command
that proves each claim.

License: `MIT OR Apache-2.0`.
