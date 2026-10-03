# Production-hardening recovery record

Updated 2026-10-03 19:51 UTC. Recovery branch: `checkpoint/production-hardening`,
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

In progress: exact-runtime healthy LINE-LANDING hour (started 19:04 UTC) and
mixed WSS/SSE/churn/quiet/reset/cancellation/reconnection hour (started 19:44 UTC).
Do not mark either passed without its complete report and drained resources.
The earlier pre-timeout hour is separately labeled, not substituted for these.

Next: await both reports, retain sanitized evidence, finish documentation and
final exact-commit CI, publish a focused review branch/PR without force-pushing
this recovery history. CI candidate artifact run: 37147589214. Packet controls:
37148161890. No stable release is authorized or claimed.

Limits: tiny initial raw replies stall in the unchanged server; Linux timeout
bound is not verified on Windows; no WAN/NAT/provider trial or 24/72h endurance.
Matched Xray settings reproduce the blackhole bound; A/B shows no speed advantage.

Recovery: `git fetch origin` then `git switch checkpoint/production-hardening`.
Generated fixture keys and all local runtime configurations stay ignored. The
committed scripts and sanitized reports are sufficient to rerun the experiments.
