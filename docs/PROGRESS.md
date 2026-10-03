# Production-hardening recovery record

Updated 2026-10-03 20:25 UTC. Recovery branch: `checkpoint/production-hardening`,
draft PR #6. Main and PR #5 remain unchanged. No merge, release or deployment.

Runtime source is `306831977aecbd026c5a68e9e907d356622a3455`; later changes are
fixtures, CI and evidence. Local tested executable SHA-256:
`f12942e3fad2a9938a14c3739748021a908236eab2e897a4d2c461145d20a5f6`.
Run `git rev-parse HEAD` after fetching to obtain this record's checkpoint SHA.

Completed: Linux 362 offline tests, fmt/strict Clippy/MSRV; final-source Linux and
Windows CI; pinned-server interop; final twelve-run A/B; session-cost and hedge
ablations; true packet-loss controls; matched-policy Xray; GNU/musl actual
artifact application smokes; IPv6, Handoff, pipelining and origin reset; actual
isolated entry SIGKILL reaches the application while the proxy remains alive.
See `docs/experiments/README.md` and the raw files linked there.

Completed healthy LINE-LANDING hour: 3600.163 s, 7056 short connections and
eight long streams; failed/panicked=0, active=0 and all permits returned.
In progress: mixed WSS/SSE/churn/quiet/reset/cancellation/reconnection hour
(started 19:44 UTC). Do not mark it passed without its complete report and drain.
The earlier pre-timeout hour is separately labeled, not substituted for these.

Next: await the recovery report, retain sanitized evidence, finish documentation and
final exact-commit CI, publish a focused review branch/PR without force-pushing
this recovery history. CI candidate artifact run: 37147589214. Packet controls:
37148161890. No stable release is authorized or claimed.

Limits: tiny initial raw replies stall in the unchanged server; Linux timeout
bound is not verified on Windows; no WAN/NAT/provider trial or 24/72h endurance.
Matched Xray settings reproduce the blackhole bound; A/B shows no speed advantage.

Recovery: `git fetch origin` then `git switch checkpoint/production-hardening`.
Generated fixture keys and all local runtime configurations stay ignored. The
committed scripts and sanitized reports are sufficient to rerun the experiments.


## Deeper optimization requested at 20:07 UTC

The prior runtime remains the reference. The new proposed runtime adds only a
ReadBuf boundary correction and a non-compacting outgoing-prefix cursor in
`src/transport/session.rs`. Binary SHA-256:
`dd7d0bc42db999195d602d30dc7615c9abe3330e4269694aa3b2dc476a77aaa6`.
366 offline tests and pinned1.98.1 Clippy pass. The earlier diagnostic red tests
used1.99.0; the production gates intentionally use the repository's pinned1.98.1.
Actual Handoff/reset/cancellation/entry-kill smoke passes; fresh mixed recovery
hour started20:23 UTC and is not yet claimed. Pinned-server interop: all22tests pass in124.43s; MSRV1.85 passes.

The buffer microbenchmark measures removed tail compaction only, not network
speed. A new real TLS bulk/CPU harness includes origin-only/current/Xray arms;
the origin-only result is not a theoretical upper bound. Local strace cannot run
because PTRACE_TRACEME is denied; no permission bypass was attempted. Do not use
traced timings as throughput comparisons. Before adopting performance claims,
freeze binaries/harness and repeat both bulk and interactive A/B without builds.


## 20:41 UTC decision after actual bulk controls

The cursor optimization is withdrawn from the recommended runtime. Its isolated
microbenchmark improves short partial-write compaction, but four-round real
transfer trials show negative upload differences; same-binary A/A also exposes
large shared-host variation. This is insufficient evidence to trade production
behavior for the optimization. Keep the exact experimental patch and all results.
The dd7d0bc recovery soak was deliberately interrupted after this decision and
must not be reported as a completed hour.

The recommended candidate now keeps only the three ReadBuf regressions/fix on
top of3068319. Previously built/pinned1.98.1 executable SHA-256:
`e0a9d931913f8b4f060a14e4ed37b8b28d63cadd0c544a11091db757fe515a2e`.
365 offline tests and Clippy had passed before the cursor experiment. A fresh
recovery-enabled3600s Handoff soak started20:41 UTC. Final interactive A/B,
pinned-server recheck, artifact build and exact final-commit CI remain due.


21:17 UTC: final e0a9d93 interactive A/B completed12/12; ranges overlap, no
speed-superiority claim. CI candidate artifacts3d829f8 from37153011410 pass
actual GNU/musl Handoff/reset/entry-kill smokes; ARM64 is build-only. The f12942e
recovery hour completed3600.340s with120resets/120cancellations/240reconnections;
this is retained separately. The e0a9d93 hour remains running until21:41UTC.
Local cargo-audit installation encountered an egress CONNECT403; no completed
local scan. The repository's read-only CI now includes a pinned official RustSec
scan; do not mark it passed until the actual job and report are verified.
