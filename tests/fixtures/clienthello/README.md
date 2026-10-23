# Xray ClientHello captures

These fixtures are normalized summaries of real `ClientHello` records emitted by
unmodified Xray-core **v26.7.28** (commit `5ca6f4b`), release asset
`Xray-windows-64.zip`, `xray.exe` SHA-256
`1d9674327972a21afd4c906a7a72bb0856935aa9e0227c87f34f03d11a88bddf`.

Each profile was pointed at a loopback TCP tee with a REALITY outbound, a SOCKS
inbound, and a dummy UUID/public key. The tee captured the first TLS record and
the client was then allowed to fail; no live node, credential, or production
service was involved. The normalization removed the session ID, random, key
material, GREASE values, ECH payload and padding length. What remains is the
observable shape: cipher list, extension order, groups, signature algorithms,
versions, ALPN, key-share groups/lengths and the static extension bodies.

`tests/clienthello_fixtures.rs` builds our hello from the same profile name and
compares those fields on every normal test run. The Firefox fixtures retain the
P-256 share that our serializer deliberately omits; the test asserts that the
only difference is the documented omission.

The fixtures are source-controlled because regenerating them needs the Xray
binary, which is not a build dependency. The pinned uTLS revision and file
hashes are in `docs/FINGERPRINTS.md`; this directory is the independent byte
evidence that the pinned data was emitted by the real client, not only read from
its Go source.
