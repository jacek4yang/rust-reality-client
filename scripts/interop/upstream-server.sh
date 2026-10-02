#!/usr/bin/env bash
# Bring up an unmodified rust-reality v2.0.1 entry node for interop testing.
#
# Run this inside WSL/Linux with a prebuilt server binary. It writes a handoff
# JSON that the client-side interop test reads, so the two halves never have to
# agree on secrets by hand.
#
#   INTEROP_BINARY=/path/to/rust-reality scripts/interop/upstream-server.sh
#
# The script blocks until interrupted; the handoff file is removed on exit.
set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BINARY="${INTEROP_BINARY:?set INTEROP_BINARY to a v2.0.1 server binary}"
OUT_DIR="$REPO/target/interop"
COVER_PORT="${INTEROP_COVER_PORT:-44443}"
ENTRY_PORT="${INTEROP_ENTRY_PORT:-14443}"
# `true` reproduces what a production node does by default: the server keeps warm
# cover connections and prebuilt cover profiles, whose flight carries the cover's
# own certificate rather than a freshly forged one.
COVER_OPT="${INTEROP_COVER_OPTIMIZATION:-false}"

command -v python3 >/dev/null || { echo "python3 is required for the TLS 1.3 cover" >&2; exit 1; }
mkdir -p "$OUT_DIR"

# REALITY needs a cover that speaks TLS 1.3 over X25519. A loopback origin is
# enough: v2.0.1 mirrors the pre-authentication prefix to it and reads its
# flight, and it dials the cover for every connection, authenticated or not.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -keyout "$OUT_DIR/cover.key" -out "$OUT_DIR/cover.crt" 2>/dev/null
python3 "$REPO/scripts/interop/cover_tls13.py" \
  --accept "127.0.0.1:$COVER_PORT" \
  --cert "$OUT_DIR/cover.crt" --key "$OUT_DIR/cover.key" &
COVER_PID=$!

# Readiness of the cover is a completed connect, not a byte read: v2.0.1 hangs
# if a probe consumes the listener's output.
for _ in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/"$COVER_PORT") 2>/dev/null; then
    exec 3<&- 3>&-
    break
  fi
  sleep 0.1
done

PUB_JSON=$("$BINARY" generate x25519 --json)
PRIVATE_KEY=$(printf '%s' "$PUB_JSON" | sed -n 's/.*"privateKey"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
PUBLIC_KEY=$(printf '%s' "$PUB_JSON" | sed -n 's/.*"publicKey"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
USER_ID=$("$BINARY" generate uuid | tail -1 | tr -d '[:space:]')
SHORT_ID=$("$BINARY" generate short-id --bytes 8 | tail -1 | tr -d '[:space:]')

cat > "$OUT_DIR/server.json.in" <<JSON
{
  "role": "entry",
  "listeners": [{ "port": $ENTRY_PORT }],
  "reality": {
    "cover": "127.0.0.1:$COVER_PORT",
    "serverNames": ["localhost"],
    "privateKey": "PRIVATE_KEY",
    "coverOptimization": { "enabled": COVER_OPT }
  },
  "users": [{ "id": "USER_ID", "shortIds": ["SHORT_ID"] }],
  "routing": { "default": "direct" },
  "log": { "level": "debug" }
}
JSON

sed -e "s/PRIVATE_KEY/$PRIVATE_KEY/" \
    -e "s/USER_ID/$USER_ID/" \
    -e "s/SHORT_ID/$SHORT_ID/" \
    -e "s/COVER_OPT/$COVER_OPT/" \
    "$OUT_DIR/server.json.in" > "$OUT_DIR/server.json"

WSL_IP=$(hostname -I | awk '{print $1}')
# Plain key=value rather than JSON: the client crate has no JSON reader, and
# interop evidence should not depend on adding one.
cat > "$OUT_DIR/handoff.env" <<HANDOFF
RRC_INTEROP_ADDR=$WSL_IP:$ENTRY_PORT
RRC_INTEROP_LOOPBACK=127.0.0.1:$ENTRY_PORT
RRC_INTEROP_SERVER_NAME=localhost
RRC_INTEROP_PUBLIC_KEY=$PUBLIC_KEY
RRC_INTEROP_USER_ID=$USER_ID
RRC_INTEROP_SHORT_ID=$SHORT_ID
RRC_INTEROP_VERSION=$("$BINARY" --version | head -1 | tr -d '[:space:]')
HANDOFF

cleanup() {
  kill "${SERVER_PID:-}" "$COVER_PID" 2>/dev/null || true
  rm -f "$OUT_DIR/handoff.env"
}
trap cleanup EXIT INT TERM

echo "starting v2.0.1 entry on :$ENTRY_PORT with cover :$COVER_PORT" >&2
if [[ "${INTEROP_CHECK_ONLY:-0}" == "1" ]]; then
  # Proves the generated configuration is one the server accepts, without
  # needing the cover to be dialled.
  kill "$COVER_PID" 2>/dev/null || true
  trap - EXIT
  "$BINARY" check --config "$OUT_DIR/server.json"
  exit $?
fi

"$BINARY" run --config "$OUT_DIR/server.json" &
SERVER_PID=$!
wait "$SERVER_PID"
