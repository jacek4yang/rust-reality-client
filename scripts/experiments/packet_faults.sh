#!/usr/bin/env bash
# Isolated two-way packet loss. No host routes/firewall/sysctls are changed.
# Requires root and netns/netlink capability (GitHub-hosted Linux runner).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$(realpath "${1:?client binary}")"
IMPL="${2:?rust-current or xray}"
OUT="$(realpath -m "${3:?output directory}")"
CASE="${4:?idle-blackhole idle-transient write-blackhole write-transient}"
SERVER="$(realpath "${INTEROP_BINARY:?pinned rust-reality binary}")"
N="rrc-exp-$$"
C="${N}-c"; S="${N}-s"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  ip netns pids "$C" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns pids "$S" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$C" 2>/dev/null || true
  ip netns del "$S" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
mkdir -p "$OUT"
ip netns add "$C"; ip netns add "$S"
ip link add rrc-c type veth peer name rrc-s
ip link set rrc-c netns "$C"; ip link set rrc-s netns "$S"
ip -n "$C" link set lo up; ip -n "$S" link set lo up
ip -n "$C" addr add 10.144.10.1/24 dev rrc-c
ip -n "$S" addr add 10.144.10.2/24 dev rrc-s
ip -n "$C" link set rrc-c up; ip -n "$S" link set rrc-s up
ip netns exec "$S" env INTEROP_OUTPUT_DIR="$OUT/fixture" INTEROP_BINARY="$SERVER" \
  bash "$ROOT/scripts/interop/upstream-server.sh" >"$OUT/node.log" 2>&1 & PIDS+=("$!")
for _ in $(seq 1 120); do grep -q listener_started "$OUT/node.log" && break; sleep .5; done
grep -q listener_started "$OUT/node.log"
ip netns exec "$C" python3 "$ROOT/scripts/experiments/packet_fault.py" --binary "$BIN" --implementation "$IMPL" \
  --fixture "$OUT/fixture" --output "$OUT" --case "$CASE" >"$OUT/application.log" 2>&1 & APP=$!; PIDS+=("$APP")
for _ in $(seq 1 120); do [[ -f "$OUT/READY" ]] && break; sleep .25; done
[[ -f "$OUT/READY" ]]
ip netns exec "$C" tc qdisc add dev rrc-c root netem loss 100%
ip netns exec "$S" tc qdisc add dev rrc-s root netem loss 100%
touch "$OUT/DROPPED"
if [[ "$CASE" == *transient ]]; then
  sleep 5
  ip netns exec "$C" tc qdisc del dev rrc-c root
  ip netns exec "$S" tc qdisc del dev rrc-s root
  touch "$OUT/RESTORED"
fi
wait "$APP"
cat "$OUT/result.json"
