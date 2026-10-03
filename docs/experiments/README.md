# Production-hardening experiments

These files are observations, not a blanket production-readiness certificate.
All servers are unmodified rust-reality v2.0.1 at
`e3fc3dc36b931baec042074d6c88e928caf6941f`. No production hosts, private
credentials, paid APIs, or real user traffic are involved.

## Initial real packet-loss experiment

Source: checkpoint `3d3f8667db131927ef3d101e27d3bbfedc43f282`,
[run 37143493890](https://github.com/jacek4yang/rust-reality-client/actions/runs/37143493890).
`packet-initial.json` is the sanitized result object from that run's logs.
The run artifact additionally holds binary hashes, exact checkout and kernel.
Xray is official v26.9.9; its release ZIP SHA-256 is
`1eb9175d0f0a8f8149c9230a7fc5ae66ce332ed20a53155ce61fe62e3f58b7df`.

The controller applies two-way `tc netem loss 100%` to veth devices entirely
inside private namespaces. Clients and the actual pinned server are on opposite
sides. The transient cases restore both directions after five seconds. The
write cases send and verify 8 MiB through the proxy and server echo destination.

- Current client idle-blackhole detection reaches the application in 60.92 s.
- Disabling client keepalive removes that verdict within the 100 s observation
  window. Default Xray is also right-censored at 100 s in this case. This is a
  comparison of the tested defaults, not a claim Xray cannot be configured for
  a different bound.
- **All three writing-blackhole cases are right-censored at 100 s.** Keepalive
  alone does not establish a useful bound with unacknowledged data.
- All six transient cases recover; the 8 MiB bodies match byte for byte.
- `writer_observation: OSError` in censored cases was appended by the writer
  during deliberate cleanup; it is NOT evidence of network-failure detection.
  Later harness revisions snapshot this list before cleanup. The `detected`
  field comes from the application's observed read/EOF, not that list.

The workflow's green status means its specified assertions passed, including
transient recovery and result completeness. It does not turn censored cases
into successful detection. A per-socket user-timeout control is being tested
separately before any decision to change the shipped policy.

## Timing and ablations

- `scripts/experiments/compare.py`: two repetitions of
  baseline/current/Xray/Xray/current/baseline, with per-run raw latencies,
  process RSS/FD/CPU samples and verified TLS/WSS/SSE payloads.
- Freeze the harness checkout as well as the binaries. The confirmatory local
  series uses commit `3d3f8667` in a separate worktree. An earlier six-run series
  is exploratory only and retained separately.
- The local timing series has a fixed concurrent long-running reliability
  workload on a shared cloud host. It is loaded-loopback evidence; small
  millisecond differences cannot establish WAN superiority.
- `build_ablations.py` records each base revision, exact patch hash and binary
  hash. Variants are experimental and must not be released as production tools.
- `session_feedback.py` and `hedge_ablation.py` are controlled mechanism tests.
  Until an execution record is added, their existence is not a passed result.
- `application_soak.py --seconds 3600` is the real-time acceptance path. The
  24/72-hour modes are opt-in; do not claim them from shorter runs.

All generated keys/configurations remain under ignored `target/` paths. Do not
upload entire fixture directories as evidence.
