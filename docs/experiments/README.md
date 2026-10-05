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
into successful detection. The subsequently completed user-timeout controls below justify the current
Linux/Android per-socket policy. This initial result is retained as the negative baseline.

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

## Executed controlled comparisons (pre-timeout candidate)

The frozen harness commit is `3d3f8667`; runtime candidate code is `59cf467`.
The candidate binary SHA-256 is
`84890cbc6b1538f18acb87045f7bc5c32dd49547b6d0b8fad40adf9dcb8fe2df`.
`comparison-frozen.json.gz` preserves all twelve complete run reports, raw
round-trip samples, and actual-process resource samples. There are four runs
per arm, each 120 seconds. All payload/TLS/WSS/SSE assertions passed.

| Tested arm | Median of per-run P95 (ms) | Median of per-run P99 (ms) | Per-run P99 range (ms) | Maximum sampled RSS (KiB) |
|---|---:|---:|---:|---:|
| PR5 baseline | 1.770 | 3.150 | 2.519–3.827 | 4676 |
| Checkpoint candidate | 1.927 | 2.828 | 2.632–3.483 | 4760 |
| Official Xray v26.9.9 | 1.930 | 3.225 | 2.989–3.967 | 46680 |

The latency ranges overlap. These data do not establish a meaningful speed
advantage, and the low-RSS observation is limited to these binaries and workload.
The new mechanisms were not needed to rescue this healthy-path workload.

`session-cost-ablation.json` holds eight runs (ABBA twice) through one unchanged
server. The fast path intentionally corrupts authenticated post-establishment
records; the slower path forwards bytes unchanged. Each full candidate delivers
9/12 requests after three induced faults; each no-session-cost control delivers
0/12. An already-established healthy stream remains usable throughout. This
supports the narrow feedback mechanism, not a claim that a reset identifies LINE
or that changing entry nodes solves a shared LANDING outage.

`hedge-ablation.json` has sixteen fresh-client trials: two path conditions and
four repetitions per arm. Healthy leaders launch no spare in either arm. With
200 ms per bridge-read delay on the leader, the candidate launches one spare and
sets up in about 0.32 s; the no-hedge control takes about 0.80–1.00 s. The bridge
is userspace scheduling, not a physical RTT or packet-loss simulator. Payloads
match; no trial starts more than the bounded two candidates.

`acceptance-pre-timeout-60m.json.gz` is a completed 3600-second real-process mixed
workload: four long-lived WSS streams, four asymmetric SSE streams and 7066 short
connections. Each WSS stream carries 550 checked messages; each SSE stream has
17975 sequential checked events. This run predates the pending-data socket
policy and feedback-window review fixes; it is not substituted for the final
candidate's fresh soak.

## Pending-data control and negative findings

`timeout-control-first.json` contains all eight cases from
[run 37144735784](https://github.com/jacek4yang/rust-reality-client/actions/runs/37144735784).
The experimental source changes only the pending-data socket option on the
pre-policy candidate and verifies the kernel read-back. Its transport assertions
passed: all 5/20/40-second transient cases recover, idle blackhole detection is
60.99 s, writing blackhole detection 78.52 s. The job subsequently failed to write
its summary into a root-created directory. That collection bug is corrected;
the failed workflow is not relabeled green and the eight raw observations are
retained. The production proposal uses the tested option on Linux/Android only.

`tiny-response-controls.json` preserves a negative control: three-byte raw echo
passes directly, but times out through both tested clients and the fixed server.
Pinned `src/server/vision.rs:1936-1951` buffers five bytes or awaits EOF before
classifying the initial destination stream. TLS/WSS/SSE tests cannot certify
arbitrary tiny raw-TCP request/response protocols against that server.

## Final-runtime checks and aligned Xray policy

`session-cost-ablation-final.json` and `hedge-ablation-final.json` repeat the
mechanism trials on runtime commit `3068319`, binary
`f12942e3fad2a9938a14c3739748021a908236eab2e897a4d2c461145d20a5f6`.
The ablated controls are rebuilt from that same revision, changing one mechanism
at a time. Both trial sets passed again; these are not reused pre-policy binaries.

`additional-application-paths.json` records passed final-candidate IPv6-only,
IPv4-only entry reached by `localhost`, and actual LINE→LANDING paths. The
hostname test does not, by itself, prove a specific failed-IPv6 attempt order.
The Handoff cases verify separate route evidence and the Rust client's Direct/
Outer mode, because LANDING's relay log flag describes a different boundary.
Stock Xray also passed the Handoff application workload.

`timeout-control-confirmed.json` records the corrected green control job in
[run 37146738972](https://github.com/jacek4yang/rust-reality-client/actions/runs/37146738972).
All eight cases pass. The second writing-blackhole observation is 60.63 s, versus
78.52 s in the first run: kernel scheduling/retransmission state matters, and the
option is not an exact application deadline.

A fair interpretation must separate policy defaults from implementation. Xray's
[documented socket options](https://xtls.github.io/en/config/transports/sockopt.html)
can also set keepalive idle/interval and TCP user timeout. The additional
`xray-aligned-timers` CI job sets idle=30 s, interval=10 s and user timeout=60000 ms
on both edges, and repeats transient/blackhole cases twice. It does not assume
Xray will fail. Retry count remains Xray's setting; the explicit user timeout
bounds the comparison. `xray-aligned-timers.json` now records all eight passing cases from
[run 37148161890](https://github.com/jacek4yang/rust-reality-client/actions/runs/37148161890).
Both repetitions detect idle blackholes in 61.04–61.05 s and writing blackholes
in 78.53 s, and recover from the tested 40-second outages (8 MiB byte-exact for
writing cases). This reproduces the liveness benefit in Xray: it is a socket
policy benefit, not an exclusive Rust implementation advantage.


## Final frozen A/B and delivered-build checks

`comparison-final.json.gz` contains a second complete twelve-run series, frozen
at source/harness `3068319` and the final runtime binary hash above. The fixed
background workload is documented inside the report. Four 120-second runs per
arm all pass; the median of per-run tail measurements is:

| Arm | P95 ms | P99 ms | P99 range ms | Maximum sampled RSS KiB |
|---|---:|---:|---:|---:|
| PR5 baseline | 1.794 | 3.050 | 2.486–3.504 | 4676 |
| Final runtime | 1.819 | 3.136 | 2.445–3.731 | 4856 |
| Xray 26.9.9 | 1.838 | 2.652 | 2.512–3.125 | 46580 |

There is no demonstrated speed advantage. The candidate retains low measured
RSS in this workload while adding feedback and observability. These data do not
establish global memory efficiency, WAN reliability, or provider-API behavior.

Candidate artifacts from [run 37147589214](https://github.com/jacek4yang/rust-reality-client/actions/runs/37147589214)
were downloaded, checked against both the artifact ZIP digests and the generated
SHA256SUMS, then the GNU and musl x86_64 executables were actually exercised for
20 seconds each through LINE→LANDING, TLS/WSS/SSE, pipelining, origin reset and
explicit application reconnection. `artifact-runtime-smokes.json` holds these
reports. ARM64 is built and checksummed, not executed. These are CI candidate
artifacts, not a published release.

`quality-review-red.txt` and `quality-window-red.txt` preserve red-before review
regressions for stale evidence, unknown-family attribution and the bounded
strike window. The corresponding corrected tests are in `scheduler/quality.rs`.

Recovery is explicit: `--with-recovery` adds deliberate origin resets, local
transport cancellation, and new application connections. It does not migrate or
replay established sessions. `--terminate-node` adds a separate post-workload
SIGKILL of only the isolated fixture entry process and checks that the application
sees a terminal failure while the proxy remains alive.


`acceptance-final-healthy-60m.json.gz` records the completed final-runtime
LINE→LANDING healthy mix: 3600.163 s, 7056 short connections, four WSS streams
with 550 checked messages each, and four SSE streams with 17975 checked events
each. Quiet intervals are 65 s. After drain: active=0, all 256/32/4/16 permits
returned, failed=0, panicked=0, FD=11, peak sampled RSS=4872 KiB and client CPU
time=12.26 s. This run is a healthy/churn mix; the separate recovery-enabled
hour must be assessed from its own report.


## Deeper review: partial writes and ReadBuf boundaries

`readbuf-red.txt` reproduces two defects in the pre-correction implementation:
a zero-capacity Direct read can mark a live peer closed, and a zero-capacity
framed read can wait for network bytes unnecessarily. A third regression covers
EOF appended to a prefilled ReadBuf. These are API-boundary regressions, not
proof that they caused a particular production AI interruption.

The experimental transport retained an accepted-prefix cursor across partial writes.
That optimization was subsequently withdrawn, as documented below.
It does not repeatedly compact the unsent tail; buffer size, authentication,
ordering and backpressure remain unchanged. A partial/Pending/append/drain test
verifies no replay or omission even if shutdown appends behind a partial record.
`partial-write-cost.json` and `scripts/experiments/partial_write_cost.rs` isolate
the old/new buffer operations with matching checksums and an ABBA ordering.
The tiny-write cases remove substantial compaction work; the full-record case
has no compaction to remove. Microbenchmark speedups are not network speedups.

`scripts/experiments/bulk_profile.py` adds actual authenticated TLS1.2/TLS1.3
upload/download, single/four-stream byte/hash-checked transfers and client
CPU/RSS/FD samples. The direct-origin arm is a fixture control, not a theoretical
upper bound: proxy buffering changes aggregation/scheduling and the Python TLS
fixture can bottleneck. `--trace` is diagnostic-only and needs host ptrace
permission. This cloud host denies PTRACE_TRACEME, so no syscall-profile result
is claimed here.


### Cursor optimization not adopted

`bulk-profile-confirm.json.gz` records 128 real TLS transfer trials (four arms,
four repetitions, two TLS versions, upload/download, one/four connections).
`bulk-profile-aa.json.gz` uses the identical f12942e executable under both Rust
labels: median throughput ratios still span 0.913–1.131, exposing measurement
noise. `bulk-profile-cursor-ablation.json.gz` repeats128 trials with the ReadBuf
fix in both Rust arms and the cursor only in the candidate. Upload median ratios
are 0.865–0.938 while download ratios vary. All payload checks pass, but these
results do not justify adopting the cursor. The recommended runtime retains the
ReadBuf correctness fix and reverts the cursor; the patch is preserved as
`partial-write-cursor-experimental.patch`. No negative observation is discarded.

The isolated microbenchmark remains valid within its stated scope, but it does
not establish useful end-to-end speedup. `bulk-profile-before.json.gz` is labeled
exploratory (a short compile overlapped initial startup). The later trials freeze
binaries and harness, with their exact background workload recorded in each file.


## Recommended ReadBuf-only candidate

The runtime source at `3d829f8` retains the correctness fix, not the cursor. Its
local executable hash is e0a9d931913f8b4f060a14e4ed37b8b28d63cadd0c544a11091db757fe515a2e.
`comparison-readbuf-final.json.gz` preserves 12 frozen 120-second runs comparing this
candidate to f12942e and official Xray. All pass. Median per-run P95/P99(ms):
f12942e 1.710/3.389; ReadBuf-only 1.683/2.711; Xray 1.879/3.098. P99 ranges overlap:
2.340–3.620,2.292–3.609,2.362–3.695 respectively. No speed superiority is claimed.
Maximum sampled RSS (KiB) is 4788, 4784, 46684 for this narrow workload.

`readbuf-artifact-runtime-smokes.json` verifies the actual downloaded GNU/musl
packages from run 37153011410, including Handoff, application checks, explicit
recovery and entry SIGKILL. ARM64 is built/checksummed, not run on an ARM host.

`dependency-audit-441b97b.json` is the cargo-audit 0.22.2 report from
[run37155020728](https://github.com/jacek4yang/rust-reality-client/actions/runs/37155020728):
99 locked dependencies, zero known vulnerabilities and no warnings against
RustSec database commit ef6173cbc5c50ec8166f9a5b28f07834144373ee (1290 advisories).
The scan sets no ignored advisories. It is a dated known-advisory check, not an
independent cryptographic audit or proof that no unknown vulnerabilities exist.


## Completed final-candidate recovery hour

`acceptance-readbuf-final-60m.json.gz` is the final ReadBuf-only runtime's actual
**3600.381-second** LINE-to-LANDING mixed soak. It includes 7061 churn connections,
four WSS streams (550 checked messages each), four SSE streams (17976 sequential
checked events each), repeated 65-second quiet intervals, 120 origin resets,
120 local cancellations and 240 explicit new application connections.
After drain: active=0, all 256/32/4/16 permits returned, panicked=0, FD=11,
peak sampled RSS=5276 KiB and client CPU time=12.51 s. The failed counter is120,
matching the injected origin failures; these are not healthy-path regressions.

The older f12942e recovery hour is separately preserved in
`acceptance-final-recovery-60m.json.gz` (3600.340 seconds, 7052 churn connections).
The healthy f12942e hour and pre-timeout hour are also separate. Different
versions and overlapping runs must never be added into a claim of one continuous
multi-hour run of the final candidate. The interrupted cursor-candidate soak is
not a completed acceptance run.

## Release validation, 2026-10-04 (continuous endurance still running)

Runtime remains c1fdd8e; the musl package is the verified executable from CI
37156375539, SHA-256 bdcd48519ff7d5f66c52a1c39b182c54e97a0005dc6cc038f8c6639bb8f9bb32.

- `release-resource-musl.json`: 1000 correct malformed-input refusals; unfinished
  HTTP/SOCKS heads close in 15.00 s; 1150 connect attempts are bounded by the
  HTTP connection admission budget. Descriptor exhaustion is induced exclusively
  in a child with RLIMIT_NOFILE=128. An already established stream remains usable;
  after freeing pressure both inbounds establish new sessions. Two seconds under
  EMFILE consumes 0.00 sampled CPU seconds, avoiding an accept-error spin. SIGTERM
  while a session remains open takes 10.01–10.04 s; one expected cancellation is
  counted and all connection/handshake/probe/spare permits return.
- `release-multi-entry-musl.json`: two genuine pinned entry processes share one
  genuine pinned LANDING. Across three rounds, SIGSTOP on entry A forces new
  sessions to B in about 155 ms on loopback. Killing B produces an explicit
  terminal on its existing stream; the previously established A stream survives
  after A resumes. All 300 new application connections through the surviving
  entry are byte-exact. This is new-session recovery, not established-session
  migration, shared-LANDING redundancy, WAN timing or a provider retry test.
- Preliminary resource-harness assertions were corrected before accepting these
  runs: the first fast connect loop timed out before reaching pressure; a mixed
  HTTP/SOCKS attempt did not exercise the assumed 1024 tracking cap; HTTP actually
  admits 256 connections before reading a head. The final test checks that real
  admission budget. musl's EMFILE text differs from glibc; the check now uses
  the event plus OS error 24. No runtime change was needed for these corrections.
- `scripts/release/tests/test_gate.py` uses explicitly synthetic records to test
  rejection of absent/short/wrong-source evidence, leaked resources, draft notes
  and changed runtime files. These are seven release-logic unit tests, never
  reported as actual endurance tests.

The real 24-hour run began 2026-10-04 05:57 UTC. Its incremental progress is not a
pass. A completed report and unchanged-runtime manifest are mandatory before
publication. This section will be updated once that run terminates.
