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
ECHO_PORT="${INTEROP_ECHO_PORT:-14444}"
# The four fault shapes in `fault_targets.py`, plus one port nothing listens on.
LATE_PORT="${INTEROP_LATE_PORT:-14445}"
DROP_PORT="${INTEROP_DROP_PORT:-14446}"
RST_PORT="${INTEROP_RST_PORT:-14447}"
TRUNCATE_PORT="${INTEROP_TRUNCATE_PORT:-14448}"
CLOSED_PORT="${INTEROP_CLOSED_PORT:-14449}"
# The two TLS origins whose record layers make the node choose Vision `Direct`
# and Vision `End` respectively. Destinations the node dials, like the echo.
TLS13_PORT="${INTEROP_TLS13_PORT:-14450}"
TLS12_PORT="${INTEROP_TLS12_PORT:-14451}"
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

# Readiness of a listener is a completed connect, not a byte read: v2.0.1 hangs
# if a probe consumes the cover listener's output, and an echo that lost the probe
# byte would misroute the first session's data.
wait_for_port() {
  for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; then
      exec 3<&- 3>&-
      return 0
    fi
    sleep 0.1
  done
  echo "nothing listening on 127.0.0.1:$1" >&2
  return 1
}

wait_for_port "$COVER_PORT"

# A destination the node can reach and hand bytes to, so the session test can
# prove the path end to end rather than only that the tunnel opened.
python3 "$REPO/scripts/interop/echo_target.py" --accept "127.0.0.1:$ECHO_PORT" &
ECHO_PID=$!
wait_for_port "$ECHO_PORT"

# The destination-side fault shapes. They live here rather than in each test
# because a test cannot open a listener the node dials from: only WSL's own
# loopback is reachable from the server process. `$CLOSED_PORT` is deliberately
# left unlistened — that absence is the fault.
python3 "$REPO/scripts/interop/fault_targets.py" \
  --late "127.0.0.1:$LATE_PORT" \
  --drop "127.0.0.1:$DROP_PORT" \
  --rst "127.0.0.1:$RST_PORT" \
  --truncate "127.0.0.1:$TRUNCATE_PORT" &
FAULT_PID=$!
wait_for_port "$LATE_PORT"
wait_for_port "$DROP_PORT"
wait_for_port "$RST_PORT"
wait_for_port "$TRUNCATE_PORT"

# The two TLS origins Vision's transition depends on. A node classifies the
# *destination's* first ServerHello and then commits the direction to one of two
# shapes for the rest of the connection: TLS 1.3 ends framing at the origin's
# first `application_data` record and hands the socket over raw, TLS 1.2 ends
# framing but keeps sealing outer records. The leaf is minted larger than one
# 16 KiB TLS record so the 1.3 origin's `Certificate` spans several records and
# the boundary falls inside the handshake, which is where a client that confuses
# the two transitions loses the connection.
TLS_DIR="$OUT_DIR/tls"
bash "$REPO/scripts/interop/tls_chain.sh" "$TLS_DIR"
python3 "$REPO/scripts/interop/tls_origins.py" \
  --tls13 "127.0.0.1:$TLS13_PORT" \
  --tls12 "127.0.0.1:$TLS12_PORT" \
  --cert "$TLS_DIR/origin.crt" --key "$TLS_DIR/origin.key" &
ORIGINS_PID=$!
wait_for_port "$TLS13_PORT"
wait_for_port "$TLS12_PORT"

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
RRC_INTEROP_ECHO=127.0.0.1:$ECHO_PORT
RRC_INTEROP_LATE=127.0.0.1:$LATE_PORT
RRC_INTEROP_DROP=127.0.0.1:$DROP_PORT
RRC_INTEROP_RST=127.0.0.1:$RST_PORT
RRC_INTEROP_TRUNCATE=127.0.0.1:$TRUNCATE_PORT
RRC_INTEROP_CLOSED=127.0.0.1:$CLOSED_PORT
RRC_INTEROP_TLS13=127.0.0.1:$TLS13_PORT
RRC_INTEROP_TLS12=127.0.0.1:$TLS12_PORT
RRC_INTEROP_COVER_OPT=$COVER_OPT
RRC_INTEROP_VERSION=$("$BINARY" --version | head -1 | tr -d '[:space:]')
HANDOFF

cleanup() {
  kill "${SERVER_PID:-}" "${ECHO_PID:-}" "${FAULT_PID:-}" "${ORIGINS_PID:-}" "$COVER_PID" 2>/dev/null || true
  rm -f "$OUT_DIR/handoff.env"
}
trap cleanup EXIT INT TERM

echo "starting v2.0.1 entry on :$ENTRY_PORT with cover :$COVER_PORT and echo :$ECHO_PORT" >&2
if [[ "${INTEROP_CHECK_ONLY:-0}" == "1" ]]; then
  # Proves the generated configuration is one the server accepts, without
  # needing the cover to be dialled.
  kill "$COVER_PID" "${ECHO_PID:-}" "${FAULT_PID:-}" "${ORIGINS_PID:-}" 2>/dev/null || true
  trap - EXIT
  "$BINARY" check --config "$OUT_DIR/server.json"
  exit $?
fi

"$BINARY" run --config "$OUT_DIR/server.json" &
SERVER_PID=$!
wait "$SERVER_PID"
