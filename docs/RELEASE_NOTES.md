# rust-reality-client v0.1.0

PENDING_ENDURANCE: this draft must be replaced with verified final run results
before the release gate will permit publication.

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
