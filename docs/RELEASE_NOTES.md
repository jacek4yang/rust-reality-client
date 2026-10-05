# rust-reality-client v0.1.0

Acceptance: two independent continuous five-hour Linux package runs completed
on 2026-10-04. The maintainer approved this release standard on 2026-10-05.
This is not a completed 24-hour endurance qualification.

Native Rust VLESS + REALITY + Vision client for an unmodified rust-reality
v2.0.1 server. SOCKS5 and HTTP CONNECT listen on loopback by default.

## Reliability changes

- Bounded connection, handshake, probe and hedge budgets; conservative session
  feedback; resource counters and explicit terminal failures.
- Linux/Android TCP keepalive and per-socket pending-data timeout, with no
  application read-idle timer, automatic payload replay or session migration.
- Correct Direct/framed ReadBuf handling and pipelined nested TLS.
- Actual Linux package tests cover malformed inputs, incomplete request
  deadlines, admission pressure, descriptor exhaustion and bounded shutdown.

## Completed acceptance

[Five-hour workflow and original reports](https://github.com/jacek4yang/rust-reality-client/actions/runs/37196136866):

| Measurement | Linux x86_64 GNU | Linux x86_64 musl |
| --- | ---: | ---: |
| Continuous workload seconds | 18000.166 | 18000.371 |
| Short connections | 35,203 | 35,403 |
| Long WSS / SSE streams | 4 / 4 | 4 / 4 |
| WSS messages per stream | 2,740 | 2,740 |
| SSE events per stream | 89,868 | 89,882 |
| Injected origin resets / local cancellations | 600 / 600 | 600 / 600 |
| Explicit reconnects | 1,200 | 1,200 |
| Final active sessions / panics | 0 / 0 | 0 / 0 |
| Initial / drained file descriptors | 11 / 11 | 11 / 11 |

All four WSS streams closed normally. HTTP CONNECT and SOCKS5 were tested
with nested TLS 1.2 and 1.3, using the pinned unmodified server. Resource
permits returned in full. The 600 recorded failed sessions per platform are
expected injected resets, not unexplained failures. Exact binary hashes,
runtime source hashes and complete reports are committed under
`docs/experiments/release-{runtime,5h-*}`. Release builds additionally rerun
package smoke/adversity/recovery, interoperability and packet-fault gates.

The earlier 24-hour attempt was interrupted by its execution environment
after about four hours and has no final passing report; it is not combined
with these runs or counted as a completed test.

## Downloads

- Linux x86_64 musl: static executable, recommended for a portable Linux install.
- Linux x86_64 GNU and ARM64 GNU: require a compatible system C runtime.
- Windows x86_64: executable built with static CRT; no Rust installation needed.
- Verify SHA256SUMS before installing. Each bundle includes SOURCE_COMMIT,
  VERSION, both licenses, example configuration and operations instructions.

## Scope and remaining limits

This release supports TCP. Applications must reconnect after a terminated
session. The unchanged server can stall initial tiny raw TCP responses; the
same negative control reproduces through Xray. No general speed advantage over
Xray or theoretical performance limit is claimed. Windows core tests do not
establish the Linux pending-data timeout behavior on Windows. ARM64 artifacts
are cross-built; real ARM hardware, WAN/NAT, actual AI providers and independent
cryptographic review remain outside the completed acceptance scope.
