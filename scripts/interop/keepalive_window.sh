#!/usr/bin/env bash
# Measures the two things the keepalive policy is asked to keep apart.
#
#   1. idle-blackhole detection — a quiet, healthy connection whose path stops
#      carrying anything without saying so. How long until this client's *socket*
#      reports it, given the window `src/transport/socket.rs` arms?
#   2. transient-outage tolerance — an outage that ends. Does the connection
#      survive, and what decides it: the outage's length, or how many keepalive
#      probe slots the outage happens to cover?
#
# Both are properties of a schedule, so this script owns the schedule and the
# impairment, and `examples/keepalive_window.rs` owns only the socket and the
# clock that reports what the socket said. That program is tuned by the crate's
# own `configure()`, so the numbers below belong to the shipped policy rather than
# to a re-typed approximation of it.
#
# The impairment is a genuine two-way blackhole: `netem loss 100%` on the egress
# of both ends of a veth pair joining two private network namespaces. One
# direction alone would leave the peer free to answer with an RST, and a
# connection killed by a message from the other side is not a blackhole.
#
# Nothing here changes a global sysctl, a route, a firewall rule, or an interface
# outside those namespaces; the namespaces are deleted on every exit path, and the
# host's own connectivity is never involved.
#
# Needs root for `ip netns`, `veth` and `tc`:
#   wsl.exe -u root -e bash \
#     /mnt/d/Workspace/rust-reality-client/scripts/interop/keepalive_window.sh \
#     /mnt/d/Workspace/rust-reality-client/target/debug/examples/keepalive_window
set -euo pipefail

BIN="${1:?usage: keepalive_window.sh <path to keepalive_window> [per-run seconds]}"
RUN_SECONDS="${2:-240}"
OUT="${KEEPALIVE_WINDOW_OUT:-/tmp/keepalive-window}"

CLIENT_LINK=kw-c
SERVER_LINK=kw-s
# The address the near end dials, which is the far end's own: one pair of
# addresses on one veth, so nothing here depends on a route.
SERVER_ADDR=10.144.0.2:14400
NAMESPACE="kw$$"
CLIENT_NS="${NAMESPACE}c"
SERVER_NS="${NAMESPACE}s"
# The window under test, read off the source that ships it rather than repeated
# here, so the schedule below is checked against the policy and not against this
# script's private copy of it. The checkout is found from this file's own location,
# which is the only honest answer available — a copy of the script somewhere else
# reaches the tree it describes by no means of its own, and `RRC_SOCKET_SOURCE` is
# how such a copy names the tree it was copied out of. That escape hatch is not
# hypothetical: the binary under test is often built in a WSL copy, so the source
# it carries lives at `/home/.../src/transport/socket.rs` while this script still
# sits under `/mnt/d/...`, and reading the window from the wrong tree would check
# the schedule against a policy the binary does not hold.
SOCKET_SOURCE="${RRC_SOCKET_SOURCE:-$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)/src/transport/socket.rs}"
[[ -r "$SOCKET_SOURCE" ]] || {
  echo "cannot read $SOCKET_SOURCE — the window is read from the checkout this" >&2
  echo "  script lives in. Point RRC_SOCKET_SOURCE at the src/transport/socket.rs" >&2
  echo "  the binary under test was built from, to measure a tree other than this one." >&2
  exit 2
}

IDLE=$(sed -n 's/^pub const KEEPALIVE_IDLE: .*from_secs(\([0-9]\+\)).*/\1/p' "$SOCKET_SOURCE" | head -1)
INTERVAL=$(sed -n 's/^pub const KEEPALIVE_INTERVAL: .*from_secs(\([0-9]\+\)).*/\1/p' "$SOCKET_SOURCE" | head -1)
COUNT=$(sed -n 's/^pub const KEEPALIVE_COUNT:[^=]*=[^0-9]*\([0-9]\+\).*/\1/p' "$SOCKET_SOURCE" | head -1)

PIDS=()

# The fds this script opens on its children's fifos are deliberately left open:
# holding the write end is what stops an endpoint from seeing end-of-file the
# moment a command is delivered, and the kernel closes them with the script.
cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
  wait >/dev/null 2>&1 || true
  ip netns del "$CLIENT_NS" >/dev/null 2>&1 || true
  ip netns del "$SERVER_NS" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

require_tools() {
  local tool
  for tool in ip tc awk sed; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
  done
  [[ -x "$BIN" ]] || { echo "$BIN is not an executable" >&2; exit 2; }
  [[ -n "$IDLE" && -n "$INTERVAL" && -n "$COUNT" ]] || {
    echo "could not read the armed window out of $SOCKET_SOURCE" >&2
    exit 1
  }
}

# One veth pair, one namespace per end, addresses set, nothing impaired yet.
make_path() {
  ip netns del "$CLIENT_NS" >/dev/null 2>&1 || true
  ip netns del "$SERVER_NS" >/dev/null 2>&1 || true
  ip netns add "$CLIENT_NS"
  ip netns add "$SERVER_NS"
  ip link add "$CLIENT_LINK" type veth peer name "$SERVER_LINK"
  ip link set "$CLIENT_LINK" netns "$CLIENT_NS"
  ip link set "$SERVER_LINK" netns "$SERVER_NS"
  ip netns exec "$CLIENT_NS" ip addr add 10.144.0.1/24 dev "$CLIENT_LINK"
  ip netns exec "$CLIENT_NS" ip link set "$CLIENT_LINK" up
  ip netns exec "$CLIENT_NS" ip link set lo up
  ip netns exec "$SERVER_NS" ip addr add 10.144.0.2/24 dev "$SERVER_LINK"
  ip netns exec "$SERVER_NS" ip link set "$SERVER_LINK" up
  ip netns exec "$SERVER_NS" ip link set lo up
}

blackhole() {
  ip netns exec "$CLIENT_NS" tc qdisc replace dev "$CLIENT_LINK" root netem loss 100%
  ip netns exec "$SERVER_NS" tc qdisc replace dev "$SERVER_LINK" root netem loss 100%
}

# Idempotent, because the far end can only be told the run is over once its
# messages can travel again.
restore() {
  ip netns exec "$CLIENT_NS" tc qdisc del dev "$CLIENT_LINK" root >/dev/null 2>&1 || true
  ip netns exec "$SERVER_NS" tc qdisc del dev "$SERVER_LINK" root >/dev/null 2>&1 || true
}

# Starts one endpoint with both channels attached, keeping a writer open on its
# stdin so the process does not see end-of-file before the schedule says otherwise.
launch() {
  local out=$1 in=$2
  shift 2
  local fd
  exec {fd}<>"$in"
  COMMAND_FD=$fd
  (
    exec <&"$fd" >"$out"
    exec "$@"
  ) &
  PIDS+=("$!")
  exec {fd}<"$out"
  REPLY_FD=$fd
}

# Blocks for one line that starts with the event being waited on, and reports the
# ones it passed over. Fails the run rather than waiting on hope.
expect() {
  local want=$1 where=$2 line waited=0
  while true; do
    if ! IFS= read -r -t "$RUN_SECONDS" -u "$REPLY_FD" line; then
      echo "$where never printed '$want' inside ${RUN_SECONDS}s" >&2
      return 1
    fi
    waited=$((waited + 1))
    if [[ "$line" == "$want "* ]]; then
      echo "    $where: $line (after $((waited - 1)) other lines)"
      return 0
    fi
    echo "    $where: $line"
  done
}

# Waits for one child, killing it if it outstays the run.
await() {
  local pid=$1 label=$2 rc=0 watchdog
  ( sleep "$RUN_SECONDS" && kill -9 "$pid" >/dev/null 2>&1 ) &
  watchdog=$!
  wait "$pid" || rc=$?
  kill "$watchdog" >/dev/null 2>&1 || true
  wait "$watchdog" >/dev/null 2>&1 || true
  ((rc <= 128)) || { echo "    $label was killed after ${RUN_SECONDS}s" >&2; return 1; }
  return 0
}

field() {
  sed -n "s/^$1=//p" "$2" 2>/dev/null | head -1
}

# Milliseconds since the epoch, from bash itself.
#
# `date +%s%3N` is the usual spelling and is wrong here: this machine's `date` is
# uutils coreutils, which reads `%3N` as something other than three digits of
# fraction and returns a number that is neither seconds nor nanoseconds. The
# offsets this feeds are compared against a client-side clock, so a silently wrong
# unit would misreport every detection time by hours.
now_ms() {
  local micros=${EPOCHREALTIME/./}
  printf '%s' "$((micros / 1000))"
}

# A run's summary line: what happened, when, and how far behind the impairment.
report() {
  local name=$1 seconds_after=$2 role file outcome elapsed error
  printf '%-28s' "$name"
  for role in connect listen; do
    file="$OUT/$name/$role"
    outcome=$(field outcome "$file")
    elapsed=$(field elapsed_ms "$file")
    error=$(field error "$file")
    printf ' %s=%s@%sms' "$role" "${outcome:-missing}" "${elapsed:-?}"
    if [[ -n "$error" ]]; then printf ' (%s)' "${error:0:64}"; fi
  done
  printf '  %s\n' "$seconds_after"
}

# One measured run, all offsets in seconds after the client has proven the path.
#
#   $1 name        — directory and label
#   $2 listen-mode — echo | drain:SECS, the far end's behaviour
#   $3 command     — park | probe | bulk:<KiB>, what the near end is then asked for
#   $4 act-at      — when to issue that command
#   $5 apply-at    — when to blackhole the path, or -1 to leave it alone
#   $6 restore-at  — when to heal it again, or -1 to leave it down
scenario() {
  local name=$1 listen_mode=$2 command=$3 act_at=$4 apply_at=$5 restore_at=$6
  local dir="$OUT/$name" ready_at after="-" pid
  rm -rf "$dir"
  mkdir -p "$dir"
  mkfifo "$dir/listen-in" "$dir/listen-out" "$dir/connect-in" "$dir/connect-out"

  make_path

  # The listener binds and reports that before the client is started at all, so
  # nothing in the measurement races a bind.
  launch "$dir/listen-out" "$dir/listen-in" \
    ip netns exec "$SERVER_NS" "$BIN" listen "$SERVER_ADDR" "$dir/listen" "$listen_mode"
  expect listening "$name listener"
  local server_pid=${PIDS[-1]}

  launch "$dir/connect-out" "$dir/connect-in" \
    ip netns exec "$CLIENT_NS" "$BIN" connect "$SERVER_ADDR" "$dir/connect"
  expect ready "$name client"
  local client_pid=${PIDS[-1]}
  ready_at=$(now_ms)
  echo "  run $name: path proven, command '$command' at +${act_at}s, loss ${apply_at}..${restore_at}s"

  ( sleep "$act_at" && printf '%s\n' "$command" >&"$COMMAND_FD" ) &
  pid=$!
  PIDS+=("$pid")
  local schedule=""
  if [[ "$apply_at" != "-1" ]]; then
    (
      sleep "$apply_at"
      blackhole
      now_ms >"$dir/loss-at"
      echo "    $name: loss applied at +$(( ( $(now_ms) - ready_at ) / 1000 ))s"
      if [[ "$restore_at" != "-1" ]]; then
        sleep $((restore_at - apply_at))
        restore
        now_ms >"$dir/healed-at"
        echo "    $name: loss lifted at +$(( ( $(now_ms) - ready_at ) / 1000 ))s"
      fi
    ) &
    schedule=$!
    PIDS+=("$schedule")
  fi

  await "$client_pid" "$name client" || true
  restore
  if [[ -n "$schedule" ]]; then kill "$schedule" >/dev/null 2>&1 || true; fi
  await "$server_pid" "$name listener" || true

  # The clock that matters is measured against the instant the impairment went in,
  # not against the start of the run, so the two are reconciled here from the
  # timestamps the scheduler wrote rather than from a second sleep.
  local elapsed loss_at
  elapsed=$(field elapsed_ms "$dir/connect")
  loss_at=$(cat "$dir/loss-at" 2>/dev/null || true)
  if [[ -n "$elapsed" && -n "$loss_at" ]]; then
    after=$(awk -v e="$elapsed" -v l="$loss_at" -v r="$ready_at" \
      'BEGIN { printf "%.1fs after loss", e / 1000 - (l - r) / 1000 }')
  elif [[ -n "$elapsed" ]]; then
    after=$(awk -v e="$elapsed" 'BEGIN { printf "%.1fs from connect", e / 1000 }')
  fi
  echo "  the client saw: $(field at_establishment "$dir/connect") at setup," \
    "$(field at_finish "$dir/connect") at the end"
  report "$name" "$after"
}

main() {
  require_tools
  rm -rf "$OUT"
  mkdir -p "$OUT"
  echo "# armed window: idle=${IDLE}s interval=${INTERVAL}s probes=${COUNT}"
  echo "#   first probe at +${IDLE}s of quiet, probe ${COUNT} at +$((IDLE + INTERVAL * (COUNT - 1)))s, given up at ~+$((IDLE + INTERVAL * COUNT))s"
  echo "#   (the client arms these per socket; the kernel defaults this machine was"
  echo "#    installed with are neither read from nor written to by anything here)"
  echo
  printf '%-28s %s\n' "run" "outcome"

  # Each line is one scenario call, and `KEEPALIVE_WINDOW_ONLY` selects a subset
  # by substring: these runs are minutes apart from each other in wall time, and a
  # maintainer changing one line of the policy does not owe the whole set.
  local runs=(
    # The idle blackhole. `park` is exactly what the relay does with a quiet
    # tunnel: one read parked and no timer armed, so the only thing that can end
    # it is the kernel noticing the peer is gone.
    "blackhole-park echo park 0 2 -1"

    # An outage that ends, sized and placed to swallow one probe slot and no more.
    # Surviving is the point: this is the interruption a per-direction read-idle
    # timeout would have killed.
    "outage-20s-one-probe-lost echo probe 45 15 35"

    # The same connection with an outage long enough to cover all three probe
    # slots. What this run answers is how long the client took to give up, against
    # the window it armed.
    "outage-40s-three-probes-lost echo probe 70 15 55"

    # A live path with a peer that stops reading, and a push small enough to fit in
    # the window the peer advertised before it stopped: the bytes are accepted and
    # acknowledged and consumed by nobody, which is the difference between the
    # kernel and the remote application, measured.
    "stalled-peer-acceptance drain:8 bulk:64 0 -1 -1"

    # The same peer, with a push larger than its window. Here the write cannot be
    # accepted, and what is measured is that it waits rather than either failing or
    # buffering without bound — and that every byte still arrives in order.
    "stalled-peer-backpressure drain:8 bulk:1024 0 -1 -1"

    # A bulk transfer through a short outage, where retransmission alone is what
    # carries the connection over: the write is already in flight when the path
    # goes down, so no keepalive probe is involved at all, because data is moving.
    "outage-during-bulk echo bulk:1024 2 1 6"
  )
  local run parts
  for run in "${runs[@]}"; do
    if [[ -n "${KEEPALIVE_WINDOW_ONLY:-}" && "$run" != *"$KEEPALIVE_WINDOW_ONLY"* ]]; then
      continue
    fi
    read -r -a parts <<<"$run"
    scenario "${parts[@]}"
  done
}

main "$@"
