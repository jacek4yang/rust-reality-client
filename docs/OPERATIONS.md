> Configuration update (development): JSON is primary. See
> [CONFIGURATION.md](CONFIGURATION.md). Existing TOML examples below remain
> valid with an explicit `--config client.toml`. Published v0.1.0 is unchanged.

# Operations

Everything here is written against the binary as it ships: one executable, two
loopback listeners, no control plane, no runtime dependency other than the operating
system's TLS-free socket layer. Where a number appears it is the number in the source,
not a suggestion, and the file that defines it is named.

* [What is running](#what-is-running)
* [Installing from a release](#installing-from-a-release)
* [First run](#first-run)
* [Configuration reference](#configuration-reference)
* [What is not configurable, and why](#what-is-not-configurable-and-why)
* [Logs](#logs)
* [systemd](#systemd)
* [Triage: why did this connection fail](#triage-why-did-this-connection-fail)
* [Tuning a node list that misbehaves](#tuning-a-node-list-that-misbehaves)
* [Long-lived connections and socket policy](#long-lived-connections-and-socket-policy)
* [Measuring a build: interop and soak](#measuring-a-build-interop-and-soak)
* [Upgrading and rolling back](#upgrading-and-rolling-back)
* [Application proxy settings](#application-proxy-settings)

## What is running

```text
rust-reality-client run --config client.toml
```

That process holds:

| What | Default | Defined in |
| --- | --- | --- |
| SOCKS5 listener | `127.0.0.1:10808` | `src/config.rs:26` |
| HTTP CONNECT listener | `127.0.0.1:10809` | `src/config.rs:28` |
| Local connections served at once | 256 | `src/inbound.rs:39` |
| Local connections queued before refusal | 1024 | `src/serve.rs:59` |
| REALITY authentications in flight, process-wide | 32 | `src/inbound.rs:48` |
| Second candidates (hedges) in flight, process-wide | 16 | `src/scheduler.rs` (`MAX_HEDGED_ATTEMPTS`) |
| Stop grace for live tunnels | 10 s | `src/serve.rs:51` |

It talks to exactly two kinds of peer: the nodes in your configuration, and the
destinations your applications asked for. It never contacts anything else — there is no
update check, no telemetry endpoint, no admin socket, and nothing that listens on a
non-loopback address unless you say so in the file.

Signals: `SIGTERM` and `SIGINT` on Unix, `SIGINT` (Ctrl-C) on Windows. Both ask for a
stop and then drain; there is no `SIGHUP` and no hot reload, because a proxy that
rereads its node list mid-connection would have to either drop connections or keep two
configs alive. **Restart to apply a configuration change.**

## Installing from a release

Artifacts are named `rust-reality-client-<version>-<name>.tar.gz`, where `<name>` is one
of `x86_64-gnu`, `x86_64-musl` or `aarch64-gnu` and `<version>` is `git describe` for the
commit that built it — a tag when built from a tag, which is what a release should be.
`SHA256SUMS` covers every archive in the run. A bundle holds the binary, `README.md`,
`examples/client.toml` and a `VERSION` file.

```sh
sha256sum --check --strict SHA256SUMS
tar -xzf rust-reality-client-v1.0.0-x86_64-gnu.tar.gz
sudo install -m 0755 rust-reality-client-v1.0.0-x86_64-gnu/rust-reality-client \
  /usr/local/bin/rust-reality-client
rust-reality-client --version
```

`--strict` means a stray file next to the sums fails the check rather than being
ignored. On macOS or Windows there is no CI-built artifact yet: build with
`cargo build --release --locked` (Rust 1.85 or newer) and treat `target/release/` as the
bundle.

## First run

Four commands, in this order. Each one is a gate on the next.

```sh
rust-reality-client generate --out client.toml     # draws a user id from OS entropy
$EDITOR client.toml                                # address, port, publicKey, shortId, serverName
rust-reality-client check --config client.toml     # every problem in the file, not the first
rust-reality-client doctor --config client.toml    # file, listeners, keys, reach, clock
rust-reality-client run --config client.toml
```

`generate` writes the commented template with one value you did not have to invent: the
user id. Paste the four REALITY values out of the server's own output — its
`reality` block for `publicKey`/`serverName`, and the `shortIds` entry for `shortId` —
and do not edit the id afterwards.

`check` exits **0** for a sound file and **2** for anything else, and prints one line per
problem with the exact TOML path. It will accept the template's placeholder key
(43 `A`s decodes to 32 zero bytes and is a syntactically valid key), so `check` passing
is not the end of the story; `doctor` is the one that names the placeholder as a
failure.

`doctor` prints `PASS` / `WARN` / `FAIL` rows and a summary line
`PASS|WARN|FAIL n checks: a pass, b warn, c fail`, exiting **0** with no `FAIL`, **1**
with one. It is safe to run against a node that is serving traffic: its probe is a dial
plus a REALITY handshake and no VLESS request, so the node authenticates it and never
opens a tunnel.

The exit codes everywhere: **0** ok, **1** the file, node or process is not sound,
**2** a usage error.

## Configuration reference

```toml
[listen]
socks5 = "127.0.0.1:10808"      # "" disables this inbound alone
http = "127.0.0.1:10809"        # "" disables this inbound alone
# allowRemote = false           # the only way to bind a non-loopback address

[[node]]
name = "home-entry"             # appears in logs and in doctor output
address = "www.example.com"     # host or IP literal, no port, no scheme
port = 443                      # the entry listener's port
userId = "…"                     # 32 hex digits, canonical UUID form

[node.reality]
publicKey = "…"                 # URL-safe unpadded base64, 43 chars, 32 bytes
shortId = "abcd"                # hex, 2–16 chars, even count
serverName = "www.example.com"  # one concrete ASCII DNS name, sent as SNI
```

Anything else in the file is a problem, named by path: an unknown key,
`[nodes]` instead of `[[node]]`, an `address` carrying a port, a `port` outside
1–65535, a `userId` that is not a hyphenated 36-character UUID, a missing
`[node.reality]` table (the answer is "this client speaks REALITY only"), a `publicKey`
with padding or whitespace or the wrong length, an odd-length or non-hex `shortId`, a
wildcard or IP-literal `serverName`, a non-loopback bind without `allowRemote`, and two
`[[node]]` blocks that name the same server *and* the same user (same address, port,
user id, short id and public key — that list offers no redundancy: one failure is both
failures).

`allowRemote` is deliberately not a default and deliberately not a per-address flag.
Setting it to `true` is the only way a non-loopback bind is accepted, because an open
relay attributes other people's traffic to *your* user id, and a proxy that selects nodes
holds the credentials that make that possible.

Order matters and is respected: the first `[[node]]` is the sticky primary until it
fails or is clearly beaten, exactly as `README.md` section 10 describes.

## What is not configurable, and why

There is no `[tuning]` table. Every behaviour that could plausibly go in one is a named
constant, because each of them is a bound on *how often this client changes its own
mind*, and an operator who changes one without the measurement behind it does not get a
more stable connection — they get a different failure. The names and values, all in
`src/scheduler.rs` and `src/transport/*`:

| Constant | Value | What it bounds |
| --- | --- | --- |
| `HEDGE_MIN` | 150 ms | shortest wait before a second node is tried |
| `HEDGE_INITIAL` | 275 ms | the same wait for a node never measured |
| `HEDGE_MAX` | 750 ms | longest wait anyone pays for a hedge |
| `MAX_HEDGED_CANDIDATES` | 2 | candidates per logical connection |
| `MAX_HEDGED_ATTEMPTS` | 16 | hedges process-wide |
| `MAX_ACTIVE_PROBES` | 4 | recovery probes process-wide |
| `BREAKER_STRIKES` | 2 | charged faults that open a node's breaker |
| `COOLDOWN` → `COOLDOWN_MAX` | 2 s → 30 s | the breaker window, doubling per trip |
| `PROBE_LEAD` | 250 ms | how early the recovery probe runs |
| `RECOVERY_LEASE` | 2 s | how long one attempt stays somebody's job |
| `HEDGE_SWITCH_THRESHOLD` | 3 | lost races that move a route with no fault |
| `MIN_DWELL` | 30 s | how long a route must hold before it may move again |
| `MIN_MARGIN` / `MIN_IMPROVEMENT` | 20 ms / 25 % | what an elective switch must clear |
| `LATENCY_MEMORY` | 300 s | how old a latency sample may be and still count |
| `DNS_BUDGET` / `CONNECT_BUDGET` | 5 s / 10 s | one resolution, one dial race |
| `MAX_CANDIDATES` / `MAX_IN_FLIGHT` | 16 / 2 | addresses per name, dials at once |
| `KEEPALIVE_IDLE` / `_INTERVAL` / `_COUNT` | 30 s / 10 s / 3 | the kernel probes on a node session |
| `FIRST_BYTE_BUDGET` | 15 s | what the application waits for a tunnel |
| `RELAY_BUFFER` / `MAX_HEAD_LEN` | 8 KiB / 8 KiB | per-direction copy, request head read |

If one of these genuinely needs to change for your network, change it in the source and
rebuild; the value you wrote in a file would have told you nothing about what it cost.

Linux/Android sockets request a 60 s `TCP_USER_TIMEOUT`, supported by the
controlled pending-data experiments below. There is no userspace read-idle
deadline for an authenticated session. See
[Long-lived connections and socket policy](#long-lived-connections-and-socket-policy).

## Logs

One JSON object per line to standard error. `--log-level` (`-L`) is `error`, `warn`,
`info` or `debug`; the default is `info`.

```json
{"timestampUnixMs":1759483200123,"level":"info","event":"refused","inbound":"socks5","reason":"BIND is not supported","code":7}
```

| Event | Level | When |
| --- | --- | --- |
| `bound` | info | a listener is open, after `Server::start` |
| `accepted` | debug | a local socket was handed a task |
| `carried` | debug | a tunnel confirmed and both directions finished |
| `refused` | info | the edge said no: a limit, a command it does not implement, a bad request. `warn` when it is the pending-local table being full |
| `failed` | warn | a connection died, with its family and whose fault it is |
| `acceptFailed` | warn, then error | `accept()` returned an error; the pause doubles from 5 ms to 1 s, and the fourth consecutive failure and every one after it is `error` rather than `warn` |
| `listenerLost` | error | a listener died and cannot be reopened |
| `signalUnavailable` | warn | `SIGTERM` could not be installed; `SIGINT` still works |
| `stopping` / `stopped` | info | a stop was asked, and what the run served |
| `doctorProbe` | debug | one `doctor` reach check that did not complete, with its family |

`-L debug` is what makes `carried` visible; a page load is dozens of them, so it is a
diagnostic mode and not a logging mode. At `info` the volume is one line per problem.

The `stopped` line is the run's whole answer, printed to standard output as well as
emitted as an event:

```text
stopped: 412 accepted, 396 carried, 12 refused, 4 failed, 0 unresolved
```

`unresolved` counts connections still live when the grace period ended — those are the
ones the drain could not finish, and a nonzero count after a 10 s grace is worth a look.

Never written, by construction rather than by filtering: user ids, private or symmetric
key material, passwords, whole URLs with credentials in them, the `shortId` value (only
its length appears), and any destination peer address beyond what `explain` prints for
the node itself. The node's `publicKey` is the one REALITY field that `check` and
`doctor` print in full: it is public by construction, and comparing it to the server's
own output is the first step in every handshake triage.

journald captures stderr with no configuration; with the unit in
`examples/systemd/` the useful invocations are:

```sh
journalctl -u rust-reality-client --since -1h -o cat | jq -c 'select(.event=="failed")'
journalctl -u rust-reality-client --since -1h -o cat | jq -r .event | sort | uniq -c
```

## systemd

`examples/systemd/rust-reality-client.service` is the unit this project is tested
against. The install sequence in its header comment is complete: copy the binary, create
the user, `generate` the file into `/etc/rust-reality-client/client.toml`, `chmod 0640`,
`chown root:rust-reality-client`, enable.

Points worth knowing before you edit it:

* `Restart=on-failure` with `RestartSec=2s`. A clean stop is not a failure, so a
  deliberate `systemctl stop` does not come back.
* `KillSignal=SIGTERM`, `KillMode=control-group`, `TimeoutStopSec=15`. Fifteen seconds
  of tolerance around a ten-second drain is what keeps a long download from being
  `SIGKILL`ed mid-byte.
* `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`. If a name service on your host
  needs netlink, add `AF_NETLINK` to that line rather than deleting it.
* `ProtectProc=invisible`, `ProcSubset=pid`, `MemoryDenyWriteExecute`,
  `CapabilityBoundingSet=` and the rest of the hardening set are known-compatible with
  this binary — it opens no other process, maps no executable memory and needs no
  capability, since binding a port above 1024 is not privileged.
* To change the config: edit the file, then `systemctl restart`. There is no reload
  signal (see [What is running](#what-is-running)).

```sh
systemctl restart rust-reality-client
systemctl status rust-reality-client --no-pager
journalctl -u rust-reality-client -b --since -5m -o cat
```

## Triage: why did this connection fail

Start with `rust-reality-client explain <family>`, which prints the family's meaning and
who it is about. The families are the ones in a `failed` line's `family` field:

| Family | Whose problem | First thing to check |
| --- | --- | --- |
| `local` | this machine | the listener limit, the file descriptor limit, the application's own proxy setting |
| `dns` | your resolver | `DNS_BUDGET` is 5 s; a name that fails here fails before any node is involved |
| `connect` | the path to the node | `doctor --node NAME`; a TCP connect that never completed is a route or firewall answer |
| `timeout` | the node's pace | `FIRST_BYTE_BUDGET` is 15 s; look at whether the destination was slow rather than the tunnel |
| `handshake` | REALITY parameters | `publicKey`, `shortId`, `serverName`, and the clock — all four are answered by a silent relay to the cover, which is why they look alike |
| `rejected` | the node's user list | the user id exists on that server, and its `shortIds` entry matches |
| `idle` | the path, after the fact | a kernel probe found no answer about 60 s after the last byte moved — see [Long-lived connections and socket policy](#long-lived-connections-and-socket-policy). Check NAT timeout and keepalive against your own network, not this client's defaults |

Three facts that make this shorter than it looks:

* A fault is charged to the party that caused it. A destination that was dead does not
  move a node's score at all, so a wall of `connect` errors pointing at one *domain*
  while `doctor` passes is a destination problem, not a node problem.
* Two charged faults open the breaker, and the hedge already covered the connection that
  saw the first one. A node that is genuinely down stops receiving new connections after
  two failures, not after twenty.
* `handshake` failures are the ones that need a second opinion. Run `doctor` and compare
  its `keys` rows against the server's own output; then check the clock, because
  REALITY authentication is time-windowed and a skew beyond the server's
  `maxTimeDiffMs` (60 s default) is answered exactly like a wrong key.

## Tuning a node list that misbehaves

Symptoms and what they mean, in terms of the behaviour actually implemented:

* **"It switches nodes too often."** It cannot: an elective switch needs `MIN_DWELL` of
  30 s since the last switch, plus 25 % and 20 ms of improvement, and a switch driven by
  lost races needs three of them and the same dwell window. If you are seeing switches
  every few seconds, something is *failing* twice and being charged, and the `failed`
  lines will name the family.
* **"It stays on a bad node."** That is stickiness working as designed and it is bounded
  by two strikes. A node that is slow but not broken is not a node that gets replaced by
  the hedge; it is a node that loses races, three times in a row, inside the dwell
  window. Compare `doctor`'s per-node latency against your own expectation.
* **"Every page is slow and nothing is broken."** Check whether you are on a path that
  black-holes one family: `MAX_IN_FLIGHT` is 2 and IPv6 is tried first when the system
  prefers it, so a dead IPv6 route costs one `CONNECT_BUDGET` slice once, not per
  connection.
* **"A node I fixed is still not being used."** The breaker window doubles per trip up
  to 30 s, and a tripped node is owed one probe 250 ms before its window ends. Wait one
  window. A node tripped by a credentials refusal is *never* probed, because a probe
  cannot test a user id — that one needs the config fixed and a restart.

## Long-lived connections and socket policy

The workload this client is built for is not a page load. An agent session is a
few hundred bytes out, then eleven minutes of the model thinking, then a long
stream back that arrives a few kilobytes at a time. Two of those three states look
exactly like a dead connection to anything that measures silence, so the
mechanisms that answer "is this still working" are kept apart deliberately.

### Four distinct mechanisms

| | The question it answers | Where | The bound |
| --- | --- | --- | --- |
| **A** | Did *setup* take too long — resolution, the dial race, REALITY authentication, the VLESS request and response? | `DNS_BUDGET`, `CONNECT_BUDGET` (`src/transport/dial.rs:45`, `:53`), `FIRST_BYTE_BUDGET` (`src/handoff.rs:78`) | 5 s, 10 s, 15 s. Finite, on purpose: an unanswered setup question gains nothing from being asked longer. |
| **B** | Is a socket still alive — the node's or the application's? | the kernel, armed by `configure` on both halves (`src/transport/socket.rs:90`) | 30 s of quiet, then 3 probes 10 s apart — about 60 s, and 59.1 s measured. Linux/Android also request per-socket `TCP_USER_TIMEOUT=60000`; no global `tcp_retries2` setting is changed. |
| **C** | Is a *write* stuck? | nothing: `carry` arms no timer (`src/transport/relay.rs`) | The buffer is fixed at 8 KiB per direction and the loop cannot pull the next chunk until the current one is accepted, so a stuck writer stops reading rather than queueing. On Linux/Android the per-socket pending-data timeout bounds this wait; observed application detection is about 61–79 s, not an exact deadline. Other platforms retain their kernel retransmission policy. |
| **D** | Is the *request* going well? | the application | Outside this proxy. A provider's own request deadline, its WebSocket Ping/Pong policy and its SSE keep-alive comments are the application's business; this client carries those bytes and does not manufacture them. |

What is *not* in the table is the point of the section: there is no per-direction
read-idle timeout, no maximum session age, and no lifetime cap on an established
tunnel. Quiet is not broken. A connection that has been up for six hours is not
more likely to be failing than one that opened a minute ago, and no code path here
treats those two states differently.

### "Applied" means the kernel said so

`configure` is a `setsockopt`; `probe` is the `getsockopt` that reads the answer
back (`src/transport/socket.rs:90`, `:149`). Tests and claims use the read-back,
not the call. The platform asymmetry is recorded instead of smoothed over: Linux
answers `TCP_KEEPIDLE`, `TCP_KEEPINTVL` and `TCP_KEEPCNT`, Windows has no spelling
for the first two, so an `Applied` off a Windows socket legitimately says
`idle=unread;interval=unread`. That is a fact about the API, not a setting that
failed — and `an_unconfigured_socket_reads_back_as_unconfigured` is what stops the
read-back from passing by coincidence, while
`the_window_reads_back_off_both_halves_of_a_live_connection` pins the pair on both
ends of a real connection and
`the_winner_leaves_with_the_socket_options_armed` pins the socket that *won* an
address race rather than the candidates that lost it.

The options also survive a Vision transition, because a transition is a change of
state on the same socket rather than a new socket. That is asserted, not assumed:
`tests/interop_v201.rs` reads the options off the tunnel *before* the session takes
it and again *after* a complete nested-TLS crossing, and requires the pair to be
equal and non-default. The before-crossing read is what makes the claim a claim —
without it, a tunnel that was never tuned in the first place would fail nothing.

### Measured: outage tolerance and blackhole detection are different numbers

Both were measured on one private point-to-point path in two network namespaces,
with `tc netem` dropping every packet in both directions (one direction alone would
leave the peer free to answer a probe with an RST, which is a different experiment).
Nothing outside the two namespaces is touched: no sysctl, no route, no firewall
rule, no interface on the host.

```sh
cargo build --locked --example keepalive_window
# needs root for `ip netns` and `tc`; RUN_SECONDS is the per-run hang guard
scripts/interop/keepalive_window.sh target/debug/examples/keepalive_window 240
```

The script reads the armed window out of the `src/transport/socket.rs` of the
checkout it lives in, so the schedule the runs below were measured against is the
shipped policy and not a private copy of it. When the binary under test was built
from a different tree — a WSL build copy, a release unpacked elsewhere — set
`RRC_SOCKET_SOURCE` to that tree's `src/transport/socket.rs`: without it the script
refuses to start rather than check a schedule against source the binary never
compiled.

The six runs, on Linux 6.6 with the shipped 30/10/3 window armed on both sockets:

| Run | What happened | Result |
| --- | --- | --- |
| `blackhole-park` | path down at +2 s, one parked read, never healed | `ETIMEDOUT` on both ends 59.1 s after the path went down |
| `outage-20s-one-probe-lost` | down 15–35 s, so the probe at +30 s was lost; read at +45 s | **alive** — the session was still usable |
| `outage-40s-three-probes-lost` | down 15–55 s, covering all three probe slots at 30, 40 and 50 s | the far end's kernel gave up at 60.98 s and the client's next write returned `ETIMEDOUT` on arrival at +70 s — **the session was dead even though the path had healed at 55 s** |
| `stalled-peer-acceptance` | 64 KiB pushed at a peer that had stopped reading for 8 s | accepted in **0 ms**, delivered **7994 ms** later, byte-identical |
| `stalled-peer-backpressure` | 1 MiB to the same peer | the write **stalled 7980 ms**, then everything arrived; the client's own buffer never grew |
| `outage-during-bulk` | 5 s outage *while* 1 MiB was in flight | the write cost 6515 ms and the transfer **completed** — retransmission, not keepalive, is what protected it |

**Historical keepalive-only interpretation (before the current user-timeout policy):**

* **Idle-blackhole detection is ~60 s, and it is the armed window, not a userspace
  timer.** The 59.1 s is 30 + 3 × 10 minus scheduling, and no timer exists in the
  relay to produce it. If you need a dead path noticed faster than that, the answer
  is the application's own heartbeat (mechanism D), not a shorter keepalive: the
  `outage-20s` and `outage-during-bulk` runs are connections a shorter window would
  have killed for no reason.
* **Outage tolerance is decided by which probe slots the outage covers, not by its
  length.** A 20 s blackout that swallowed one probe was survived; a 40 s blackout
  that covered all three was not, *even though the path came back*. That is the
  honest limit of this design and it is a property of the 30/10/3 window that
  v2.0.1 also uses: a session quiet through an outage that covers three consecutive
  probe slots is not rescued by anything in this client. A session that is
  *carrying* bytes is a different case — see `outage-during-bulk`.
* **Acceptance into a kernel send buffer is not delivery.** 64 KiB was "written" in
  0 ms and reached the peer eight seconds later. `write_all` returning means the
  local kernel holds the bytes; nothing in this stack reads that as a peer having
  seen them, and neither should you.
* **Backpressure is tolerated without an unbounded buffer.** The 1 MiB run is the
  evidence: the writer parked, the queue grew in the kernel's socket buffers and
  not in user space, and the payload arrived unchanged.

### Pending-data bound after the packet-loss experiment

The earlier decision to leave `TCP_USER_TIMEOUT` unarmed was superseded by a
real application-path failure: with 8 MiB queued and both directions blackholed,
keepalive-only clients did not notify their local applications during 100 seconds.
This was true for the pre-change client, its no-keepalive ablation and default
Xray v26.9.9. The result is right-censored, not a measured eventual timeout.

Linux/Android data sockets now request a per-socket 60 s `TCP_USER_TIMEOUT`.
The kernel value is read back in the socket regression tests. No global sysctl,
firewall, route, congestion setting or server configuration is changed. Socket
setup failure still refuses that connection instead of silently accepting an
untuned socket. Unsupported platforms, including Windows, retain their previous
keepalive policy and have no claimed equivalent pending-data bound.

The isolated Linux control preserved 5, 20 and 40 second outages, with every
8 MiB body byte-identical. Its permanent blackholes reached the application after
60.99 s idle and 78.52 s writing. The latter is an important qualification: the
configured timeout is checked by kernel retransmission/probe machinery, not a
precise sixty-second application timer. See the raw cases and workflow links in
[experiments](experiments/README.md). Longer outages may deliberately sacrifice
a connection; application retries remain the application's responsibility.

This does not impose a maximum session age or end-to-end response deadline.
Healthy quiet sockets continue to be acknowledged by their peer's TCP stack.
A responsive entry node with an unresponsive destination is a different failure
shape, and no successful first-hop keepalive claims the application is healthy.

### What a keepalive answer is evidence *of*

The probes are answered by the node's TCP stack. A successful probe therefore
proves that this client and `LINE` still have a path and a socket — nothing about
whether `LANDING` is up, and nothing about whether the AI service behind it will
accept the next request. End-to-end health is only ever demonstrated by the
application's own bytes moving: the request that got a response, the WebSocket Ping
that got a Pong. Those pass through here unopened and unchanged (see
[Long connections](ACCEPTANCE.md) in the acceptance list), and this client never
injects one of its own to make a dead session look alive.

### The hot path's fixed cost

* 8 KiB per direction (`RELAY_BUFFER`, `src/transport/relay.rs:57`), allocated once
  per connection by the copy loop and reused for every chunk. A relay holds 16 KiB
  regardless of how much it moves.
* A Vision session holds four buffers, each `Vec::with_capacity` at construction
  (`src/transport/session.rs:253-257`); the three `resize` calls in the same file
  only ever grow within that capacity.
* No allocation in the Vision codec's production path, no logging in
  `relay.rs`/`session.rs`/`vision.rs`, and no timer armed per chunk. These are
  grep-checkable rather than aspirational:
  `grep -n "logger\|log::\|tracing" src/transport/relay.rs src/transport/session.rs src/protocol/vision.rs`
  returns nothing.
* One task per connection on the shared multi-thread runtime, so a busy stream
  occupies a worker for a chunk rather than for a session, and there is no second
  runtime, queue or thread pool in front of it.

## Measuring a build: interop and soak

The gate that cannot be faked: an unmodified `rust-reality` v2.0.1 node, built from the
pinned commit, with the client's own test suite against it.

```sh
# 1. Build the server from the exact commit, unmodified.
git clone --quiet https://github.com/jacek4yang/rust-reality /tmp/v201
git -C /tmp/v201 checkout --detach e3fc3dc36b931baec042074d6c88e928caf6941f
cargo build --release --locked --manifest-path /tmp/v201/Cargo.toml --bin rust-reality

# 2. Start cover + echo + fault targets + TLS origins + entry node, and read the handoff.
INTEROP_BINARY=/tmp/v201/target/release/rust-reality scripts/interop/upstream-server.sh &
until [ -s target/interop/handoff.env ]; do sleep 0.5; done
set -a; . target/interop/handoff.env; set +a

# 3. Run the live suite. One thread, because the fixture shares one node.
export RRC_INTEROP_ADDR="$RRC_INTEROP_LOOPBACK"
export RRC_SOAK_SECONDS=120
cargo test --locked --test interop_v201 -- --ignored --test-threads=1 --nocapture
```

`upstream-server.sh` generates the node's keys and user id itself and hands them over in
`target/interop/handoff.env`, so the two halves never agree on secrets by hand. It also
starts the four destination-side fault shapes (`late`, `drop`, `rst`, `truncate`) and one
port nothing listens on, because a test cannot open a listener the node dials from.

And two nested-TLS origins, which is how the Vision transition gets proven rather than
asserted: `tls_chain.sh` mints a CA and a leaf larger than one 16 KiB record into
`target/interop/tls/`, and `tls_origins.py` serves that leaf over TLS 1.3 on
`RRC_INTEROP_TLS13` and over TLS 1.2 only on `RRC_INTEROP_TLS12`. The 1.3 origin's
`Certificate` therefore spans several `application_data` records, so the node takes
`Direct` *inside* the handshake, while the 1.2 origin takes `End` and must keep sealing.
`tls_client.py` is the application on the far side of the relay — a genuine TLS peer, so
the certificate verification and the AEAD that decide the claim are OpenSSL's, not ours
(`RRC_INTEROP_PYTHON` overrides the interpreter).

The soak's report is the line to read. This one is the actual output of the command
above, run on Linux against the pinned `v2.0.1` binary at the default 50 ms pacing
(`target/interop-linux.log`):

```text
SOAK 120.035904576s: 1074 connections, 33294 bytes down, p50 60.518341ms
  p95 63.541121ms p99 68.651451ms (fastest 56.452721ms, slowest 73.693634ms),
  hedged 0 won 0, long-lived session still up, primary primary with 1074 successes
  and 0 failures
SOAK footprint: descriptors 13 -> 13, resident 8044 KiB -> 8172 KiB, threads 2 -> 2
```

* **percentiles** are nearest-rank over every SOCKS5 setup round trip in the window —
  the number a user feels, since it is the time to "the tunnel exists", not the time to
  first byte of the response. `p99 / p50 = 1.13` is the shape a healthy single path has:
  the spread is the destination, not the node.
* **hedged / won** are the two counters in `Snapshot`: second candidates started over a
  leader still running, and how many of them this process adopted. `hedged 0` here is the
  healthy result, not a dead instrument: the delay is twice the leader's remembered pace
  clamped into `[150 ms, 750 ms]`, a 60 ms leader sits on the floor, and 150 ms of
  patience never expired before the leader answered. A soak that *does* hedge is the
  `late` fault shape in the same file. What the pair is for is the question "how often
  does hedging pay, in authentications spent", and `won 5 of 12` would be the answer that
  a hedge bought five connections out of a stall and spent seven for nothing. A *failed*
  leader replaced immediately is deliberately not in this count, because that is
  failover, not a hedge paying off.
* **descriptors** are read from `/proc/self/fd` before and after, and the test asserts a
  bound (`DESCRIPTOR_SLACK` = 16): a connection that never closed leaves a socket behind
  and would blow past it within a few dozen connections. 1074 connections returning the
  count to exactly itself is the point. `resident` and `threads` are printed, not
  asserted — allocator retention and the runtime's blocking pool both grow to a plateau
  and a bounded assertion on them would be a flaky test, not a leak check. Here the
  128 KiB of growth across a two-minute storm is retention, not a trend; the claim that
  would need a longer window is made by `repeated_establishments_all_succeed_through_v201`
  and by the assertion on the slots. Off Linux the line says the platform does not report
  it.

Everything else the suite covers, in `tests/interop_v201.rs`: the wire shapes the client
emits (ClientHello, agreement payloads, Vision record sizes), the Direct transition byte
for byte, half-close, the fault matrix through a live node, a 24-way storm that asserts
every slot comes back, and the sticky route under that load.

## Upgrading and rolling back

1. Verify the new artifact's checksum against the release's `SHA256SUMS` before
   installing, and `--strict` so a stray file fails the check.
2. `rust-reality-client --version` and `check` the *existing* file with the new binary.
   The configuration grammar is the compatibility surface, and a file that `check`s clean
   under both versions runs on both.
3. `systemctl restart` (or your supervisor's equivalent). Nothing else reloads a config.
4. `doctor` after the restart, not before: it measures the node from the process you are
   about to trust.
5. Roll back by reinstalling the previous binary. There is no state on disk to migrate —
   no database, no session store, nothing that survives a restart, because v2.0.1 offers
   no cross-node resume and this client does not pretend otherwise.

## Application proxy settings

For a browser or a single application, `socks5h://127.0.0.1:10808` (resolve remotely).
For anything that speaks HTTP proxy — `curl`, most language SDKs, `Pi Agent` —
`http://127.0.0.1:10809`, and expect `10809` to be the only port those tools can talk to:

```sh
export HTTPS_PROXY=http://127.0.0.1:10809
export HTTP_PROXY=http://127.0.0.1:10809
export NO_PROXY=localhost,127.0.0.1
```

`README.md` sections 6, 7 and 8 cover the same ground from the user's side, including when
`socks5h://` versus local DNS matters.

## Reproducing the additional application experiments

Use an isolated checkout and fresh fixture credentials. The pinned server must
be an unmodified build of commit `e3fc3dc36b931baec042074d6c88e928caf6941f`.

```sh
python3 -m venv target/soak-venv
target/soak-venv/bin/pip install websockets==15.0.1
INTEROP_BINARY=/absolute/path/to/rust-reality \
  target/soak-venv/bin/python scripts/interop/application_soak.py \
  --seconds 3600 --handoff --with-recovery --output target/acceptance
```

`--handoff` starts isolated LINE and LANDING processes. Both use the pinned
binary. The client-side Direct/Outer observations establish its Vision boundary;
LANDING's `downlink_direct` log field is not that client boundary. The harness
also verifies real TLS ClientHello bytes pipelined in the same write as HTTP
CONNECT or SOCKS greeting/CONNECT, fragmented WebSocket messages, endpoint
Ping/Pong and Close, sequential/hash-checked SSE, quiet intervals and churn.

At debug level the client emits a bounded resource snapshot every 30 seconds
and on drain: tracked active/high-water counts and remaining connection,
handshake, hedge and probe permits. `sessionFinished` records partial accepted
byte counts even on errors; it never logs their contents. `/proc` samples belong
to the actual client process. Thread count alone is not an async-task leak test.

`--seconds 86400` and `--seconds 259200` select opt-in 24/72-hour runs and create
longer-lived fixture certificates. Only an actually completed run is evidence.
Keep the source and binary hashes together with the report; do not mix different
Cargo worktrees under one target directory and assume the last executable was
rebuilt. Never upload generated fixture keys or entire `target/` directories.
