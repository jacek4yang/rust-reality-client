# ClientHello fingerprints

This client does not send one hand-built hello. `[node.reality].fingerprint`
selects a browser shape whose cipher list, extension order, GREASE slots and
pseudo-extensions are transliterated from the same uTLS revision Xray-core
v26.7.28 pins. The REALITY authenticator is still the only thing that makes the
hello ours: a 32-byte session ID sealed over the hello's zeroed form.

## Source pin

The tables live in `src/protocol/reality/fingerprint/data.rs`. They come from
`github.com/refraction-networking/utls` at commit
`aa6edf4b11af82e110eea845bb2983d30138d651` (the version in Xray v26.7.28's
`go.mod`). No profile byte is written from memory.

| File | SHA-256 |
| --- | --- |
| `u_parrots.go` | `539e821a53eda1ab6acbfd1661d2ba0a9f8c87a27938709a85b7b69788971648` |
| `u_tls_extensions.go` | `2a087a02b64f4ae08bdb017ee3fa5a35a71063aad58c998ccb5adeb21030e7ab` |
| `u_conn.go` | `0f2ec1cd1b540d27f0cc81348a5bf9679a95ca36d02287fd157f36bae044e3ce` |
| `u_ech.go` | `3d77903ea0bb91203185bbc4e79b2e8d7b47b4faf760097eb0b79125814f819f` |
| `u_common.go` | `e42122a474d87d7b6ad959532c0e0f32e39a9514f714fa25a4a3f62d8113e545` |
| `cipher_suites.go` | `1e2881dc3fe81df91adee2fd3fc080b289d8b3bdbf410cbb52d16f9b10b3217b` |

`UTLS_COMMIT` in the source keeps the revision next to the data. The profile
constants are checked at compile time by the unit tests; the tables are not
generated at build time and the release binary has no network or Go dependency.

## Names

| Name | Target | Default |
| --- | --- | --- |
| `chrome` / `hellochrome_auto` | Chrome 133 | when `fingerprint` is omitted |
| `hellochrome_120` | Chrome 120 | |
| `hellochrome_131` | Chrome 131 | |
| `firefox` / `hellofirefox_auto` | Firefox 148 | |
| `hellofirefox_120` | Firefox 120 | |
| `safari` / `hellosafari_auto` | Safari 26.3 | |
| `ios` / `helloios_auto` | iOS 14 | |
| `helloios_13` | iOS 13 | |
| `edge` / `helloedge_auto` | Edge 85 | |
| `helloedge_106` | Edge 106 | |
| `hello360_11_0` | 360 Browser 11.0 | |
| `qq` / `helloqq_auto` | QQ 11.1 | |
| `random` | one of Xray's 11 modern profiles, once per process | |
| `randomized` | uTLS randomized capability set with ALPN | |
| `randomizednoalpn` | the same without ALPN | |

`random` and the randomized variants are resolved once per process. That is
deliberate: a new capability set per connection would churn the server's
bounded ClientHello-class cache instead of settling into a cover profile.

## What is reproduced

- Cipher suites, compression and the extension sequence from the pinned spec.
- SNI, ALPN, supported groups, signature algorithms, supported versions.
- GREASE cipher/group/version/extension slots, including Chrome's two
  GREASE extensions (the first empty, the second one zero byte).
- Chrome 120/131/133 extension shuffling, except the GREASE and padding
  positions, which uTLS treats as fixed.
- BoringSSL padding (`0x100..0x200` target) where the profile asks for it.
- ALPS (17513 or 17613), certificate compression, record-size-limit,
  delegated-credentials and the ECH **grease** body (Chrome: one suite and
  lengths 128/160/192/224; Firefox: two suites and length 223).
- A 32-byte session ID and the REALITY AEAD patch, exactly as Xray's REALITY
  client does. The authenticator never enters extension writing.

## Deliberate deviations

- **Firefox P-256 share is omitted.** The P-256 entry stays in
  `supported_groups`, but the server only accepts X25519 or X25519MLKEM768
  cover selections. Firefox's X25519 share is still first, so every other
  observable part of the shape is preserved.
- **Randomized specs are REALITY-viable.** TLS 1.3 and the X25519 share are
  forced, and P-256/P-384/P-521 shares are filtered. Xray's weights still drive
  the cipher/extension/ALPS choices. This is a bounded deviation, not a claim
  that the randomizer is byte-for-byte uTLS.
- No real ECH, no PSK/resumption, no session ticket contents. Grease bodies are
  filler and are never used as protocol state.

## Refused names

`android` / `helloandroid_11_okhttp` offer no TLS 1.3 key share; Xray's `360`
preset is the 7.5 shape, which also has no TLS 1.3 key share. `unsafe` is the Go
standard-library handshake, not a browser fingerprint. PSK/PQ and legacy
version names are outside this client's chosen modern set. Each is a startup
error that names the reason and, where one exists, the nearest usable name.
`fp` remains a refused key and points at `fingerprint`.

## Server consequence

An exact browser shape is not a guarantee that the node has a prebuilt cover
profile for it. v2.0.1 never rejects an unknown class: it falls back to the live
cover, which costs one extra cover RTT and may be learned later. Chrome-family
shapes are the class the server benchmarks; other shapes are correctness-safe
but not promised to hit a warm prebuilt class. The class cache is bounded, so do
not rotate profiles per connection.

## Configuration

```toml
[node.reality]
publicKey = "..."
shortId = "abcd"
serverName = "www.example.com"
fingerprint = "chrome"
```

## Evidence

Offline:

```sh
cargo test --locked
```

This covers every profile's cipher/extension invariants, the zeroed-AAD
authenticator round trip, Chrome's shuffle and GREASE positions, BoringSSL
padding, the Firefox P-256 omission, randomized stability over 1,000 seeds, and
the refusal diagnostics.

Live node (credentials remain in `target/interop/handoff.env`):

```sh
RRC_INTEROP_FINGERPRINT=chrome cargo test --test interop_v201 -- --ignored reality_handshake_
```

The `every_supported_fingerprint_authenticates` ignored test runs all 15
supported shapes against one node in one process. On the isolated v2.0.1
fixture it passed 15/15. A completed handshake proves that the shape reached the
REALITY path and negotiated a suite/group the hello offered; it does not prove
that a middlebox sees an ordinary browser, and no such claim is made here.
