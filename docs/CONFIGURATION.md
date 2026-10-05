# JSON configuration for rust-reality-client

JSON is the primary configuration format for this change. The already-published
v0.1.0 remains TOML-based; use a build containing this change before migrating.
This is an Xray-style **subset**, tuned for the unmodified rust-reality v2.0.1
server, not a promise that arbitrary Xray files can run unchanged.

## First run

```sh
rust-reality-client generate --out client.json
# Edit server address, port, id, publicKey, shortId and serverName.
rust-reality-client check --config client.json
rust-reality-client doctor --config client.json
rust-reality-client run --config client.json
```

A complete example is [`examples/client.json`](../examples/client.json).
Generated UUIDs are new identities, not automatically registered users. For an
existing server, copy its user UUID and the short ID assigned to that user.
`address` is the entry host/IP without a scheme or port; `serverName` is the
server-accepted SNI and can be different. `publicKey` is the server's public
X25519 key, never its private key.

```json
{
  "inbounds": [
    { "tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks" },
    { "tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http" }
  ],
  "outbounds": [{
    "tag": "line-a",
    "protocol": "vless",
    "settings": {
      "address": "www.example.com",
      "port": 443,
      "id": "00000000-0000-4000-8000-000000000000",
      "encryption": "none",
      "flow": "xtls-rprx-vision"
    },
    "streamSettings": {
      "method": "raw",
      "security": "reality",
      "realitySettings": {
        "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "shortId": "abcd",
        "serverName": "www.example.com"
      }
    }
  }]
}
```

This example contains placeholders. `check` validates shape, not reachability;
`doctor` rejects the unfilled all-zero public-key template.

## Listener behavior

- Omitting `inbounds` keeps both loopback defaults (10808 SOCKS5, 10809 HTTP).
- When `inbounds` is present, only listed listeners are enabled. The array must
  be nonempty; at most one listener per protocol is currently supported.
- Omitted `listen` means `127.0.0.1`. IPv6 is written as `"::1"` with a separate
  numeric `port`; ports must be integers in 1..65535.
- SOCKS `settings` may contain only `auth: "noauth"` and `udp: false`; both are
  the defaults. HTTP settings may be omitted or `{}`. HTTP is CONNECT-only.
- Duplicate listener protocols, tags, or identical bind endpoints are rejected.
- Remote bind is refused unless top-level `allowRemote: true` explicitly opts
  in. There is no inbound password authentication: protect access externally.
- Keep the client running, and configure each application to use its local
  listener. No automatic system proxy, TUN, firewall or service changes occur.

## Node behavior and supported spellings

Every outbound enters the existing automatic-selection pool. To add a second
entry, duplicate the outbound object and change its tag and server credentials.
There is no first-outbound default route or user-configurable routing table.
Selection happens before a tunnel is established; a broken established stream
is not migrated or replayed. The application must reconnect.

| Field | Rule |
| --- | --- |
| `tag` | Optional label, defaults to node-N; outbound labels must be unique |
| `protocol` | Required `vless` |
| `settings.address` | Required hostname or IP, without scheme/port |
| `settings.port` | Required integer 1..65535 |
| `settings.id` | Required canonical hyphenated UUID, not Xray's custom-string IDs |
| `settings.encryption` | Omitted or `none`; no VLESS Encryption |
| `settings.flow` | Omitted or `xtls-rprx-vision`; Vision is always used |
| `streamSettings.method` | Omitted or `raw`; native TCP transport |
| `streamSettings.network` | Alternative to method: `tcp` or `raw` |
| `streamSettings.security` | Required `reality` |
| `realitySettings.publicKey` | Required 43-character URL-safe unpadded base64 key |
| `realitySettings.password` | Alternative spelling of publicKey, not another password |
| `realitySettings.shortId` | Required even-length hex string, 2..16 characters |
| `realitySettings.serverName` | Required concrete ASCII DNS name accepted by the server |

Use only one of `method`/`network`, and only one of `publicKey`/`password`.
Even identical values in both fields are rejected, rather than given an implicit
precedence. Fixed flow/encryption/transport defaults are conveniences of this
client; do not extrapolate them to Xray.

Unsupported fields fail closed: `routing`, `dns`, `log`, `mux`, `fingerprint`,
`sniffing`, non-REALITY security, WebSocket/gRPC transports, UDP, TUN and inbound
accounts are not silently ignored. Use `--log-level` for this client's logging.
WSS/gRPC **application traffic inside TCP tunnels** is distinct from configuring
WebSocket/gRPC as the proxy transport.

## Existing TOML and Xray migration

```sh
rust-reality-client migrate --config client.toml --out client.json
rust-reality-client check --config client.json
```

Migration validates before writing, preserves UUID/key/short ID/listeners and
node order, never changes the server, and refuses to overwrite an existing file
(including the source). Output has Unix mode 0600 on creation; Windows inherits
the directory ACL. No credentials are printed. Protect the resulting file and
do not commit it to a public repository. TOML with both listeners disabled has
no active JSON equivalent and is rejected during migration.

For Xray's old `settings.vnext[0].users[0]` shape, manually flatten the server's
address/port and user's id/encryption/flow into `settings`. One server/user per
outbound. Remove unsupported features only after deciding they are not needed;
this client does not import or emulate them. Diagnostics provide a flattening
hint and refuse the old structure.

Configuration lookup: explicit `--config` wins; otherwise use `./client.json`,
falling back to `./client.toml` only when JSON is absent. A broken/unreadable JSON
file is an error, not permission to silently use a different file. Explicit
`.json` and `.toml` extensions select that parser. Other extensions use content
detection. JSON accepts no comments, trailing commas or repeated keys at any
nesting level. Unknown fields are errors; their untrusted names and values are
not repeated in JSON diagnostics.

## Compatibility references

- [Xray flat VLESS settings](https://xtls.github.io/en/config/outbounds/vless.html)
- [Xray transport naming](https://xtls.github.io/en/config/transport.html)
- [Xray REALITY settings](https://xtls.github.io/en/config/transports/reality.html)
- [Xray first-outbound behavior](https://xtls.github.io/en/config/outbound.html)
- [rust-reality supported scope](https://github.com/jacek4yang/rust-reality#supported-scope)

This change preserves transport/session code. Nevertheless, changing runtime
source and dependencies invalidates the old v0.1.0 endurance qualification.
The stable-release gate must reject publication until matching new evidence is
recorded; short JSON interoperability tests are not a substitute for five hours.
