# rust-reality-client v0.1.1

JSON-first configuration update for the unmodified rust-reality v2.0.1 server.
Existing TOML configurations remain supported. This is a new release, not a
replacement of the v0.1.0 downloads.

## Configuration

- Primary `client.json` uses Xray-style `inbounds` / `outbounds`, flat VLESS
  `settings`, and `streamSettings.realitySettings`.
- Canonical `publicKey`, `shortId`, `serverName`, and `method: "raw"`; `password`
  and `network: "tcp"` / `"raw"` are explicit aliases. Conflicting aliases fail.
- Duplicate JSON keys, unsupported Xray features, invalid credentials and unsafe
  listener bindings fail closed. This is not a full Xray configuration importer.
- No `--config`: prefer client.json; only absent JSON permits client.toml fallback.
- `generate --out client.json` writes JSON. `generate --format toml` preserves
  the legacy template. For an existing server, use its UUID rather than the new
  generated identity.
- `migrate --config client.toml --out client.json` preserves validated credentials,
  node order and listeners, refuses overwrites, and creates mode 0600 on Unix.
- Both JSON and TOML examples are included in all four download bundles.

[Configuration and migration guide](https://github.com/jacek4yang/rust-reality-client/blob/v0.1.1/docs/CONFIGURATION.md)

## Release qualification

This is a **configuration-update qualification, not a fresh five-hour run**.
The five-hour GNU/musl results remain evidence for v0.1.0 only; the v0.1.1
executables and dependencies differ and are not described as five-hour-tested.

A source gate verifies unchanged transport, protocol, scheduling and relay
files against v0.1.0. It permits only the reviewed configuration/CLI changes,
version bump and the four JSON-related dependency additions; all existing
locked dependencies remain identical. A complete exact-source hash manifest
prevents later changes from inheriting this qualification.

Publication requires fresh Linux/Windows regression tests, MSRV and strict
Clippy, current RustSec audit, 22 pinned-server interoperability tests, actual
JSON CLI WSS/SSE traffic with TLS1.2/1.3 on both local listeners, packet-fault and
Xray-control experiments, and tests of the exact new Linux download packages
under malformed-input, admission-pressure, descriptor-exhaustion, multi-entry
recovery and shutdown faults. Every download has a SHA256SUMS entry and its
SOURCE_COMMIT. Short regressions are not an endurance-duration substitute.

## Downloads

- Linux x86_64 musl: static executable, recommended for Mint and portable Linux use.
- Linux x86_64 GNU and ARM64 GNU: require a compatible system C runtime.
- Windows x86_64: static-CRT executable; no Rust installation required.

## Scope

TCP only. HTTP inbound is CONNECT-only; SOCKS5 is unauthenticated and loopback
by default. All outbounds participate in automatic node selection, unlike
Xray's first-outbound default. UDP, TUN, Mux, routing rules and fingerprint
emulation are unsupported. Applications must reconnect after terminated
sessions; no replay or established-session migration is claimed.

ARM64 is cross-built, not tested on physical ARM hardware. Real WAN/NAT and AI
provider traffic, independent cryptographic review and 24-hour endurance remain
outside the completed qualification. The unchanged server's tiny initial raw
response limitation remains; no superiority over Xray is asserted.
