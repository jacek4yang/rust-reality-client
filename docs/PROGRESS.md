# Production-hardening recovery record

Updated 2026-10-03 21:42 UTC. Recovery history: `checkpoint/production-hardening`,
draft PR #6. Main and PR #5 remain unchanged; no merge, release or deployment.

## Current recommendation

Runtime source: `3d829f898de19045c94f88be4552572f49059e07`.
Local tested executable SHA-256:
`e0a9d931913f8b4f060a14e4ed37b8b28d63cadd0c544a11091db757fe515a2e`.
The proposed final review preserves this runtime; only evidence, docs and CI
have changed afterward. `git diff 3d829f8 -- src Cargo.toml Cargo.lock` is empty.

## Completed gates

- 365 offline tests, fmt, strict Clippy, MSRV 1.85 and genuine pinned-server interop.
- Windows offline/Clippy/MSRV; Linux true packet-loss and aligned-Xray controls.
- Final 12-by-120-second interactive A/B; data intact, overlapping tail ranges.
- Feedback/hedge/timeout ablations, IPv6 and actual LINE-to-LANDING application paths.
- Final recovery-enabled real hour: 3600.381 seconds, 7061 churn, eight long streams,
  120 resets, 120 cancellations and 240 explicit reconnects; all resources drain.
- CI-built GNU/musl packages downloaded/checksummed and run; ARM64 build-only.
- RustSec audit: 99 dependencies, zero known vulnerabilities/warnings, no exclusions.

Raw sanitized evidence and commands are indexed in `docs/experiments/README.md`.
Candidate artifact run: 37153011410; audit/core CI: 37155020728.

## Measured decisions and limits

The partial-write cursor was withdrawn: its microbenchmark benefit did not justify
actual upload results. All negative controls and the patch are retained. The
cursor-candidate hour was deliberately interrupted, not claimed as a pass.
Matched Xray settings reproduce the blackhole bound; no speed superiority or
"theoretical limit" is claimed. The unchanged server stalls tiny initial raw
responses. Windows pending-data behavior, real WAN/NAT/provider trials and
24/72-hour endurance remain unverified.

## Review and rollout

Final review branch target: `fix/measured-session-hardening`, one commit based
on PR #5. Its exact-SHA checks and closing PR comment are the source of truth for
final CI/artifact status; this file cannot embed its own commit SHA. Preserve the
append-only recovery history. Merge, release and production rollout require a
separate decision; they are not implied by successful laboratory acceptance.

Recovery: `git fetch origin` then `git switch checkpoint/production-hardening`.
Generated fixture keys and local runtime configurations stay ignored. No user
computer, production node, port 10808/10809 or account credential was changed.

## Reopened release validation (2026-10-04)

The user requested deeper testing and a final Release. The repository and pinned
server were recovered from HTTPS after the temporary execution environment was
replaced. Previous committed evidence was preserved. No runtime source or
lockfile changes have been made in this phase.

A continuous 24-hour Handoff/recovery soak started at 2026-10-04 05:57 UTC, using
the downloaded and checksum-verified c1fdd8e musl CI executable (SHA-256
bdcd48519ff7d5f66c52a1c39b182c54e97a0005dc6cc038f8c6639bb8f9bb32).
Incremental progress is explicitly marked running, never passed. The completed
report must be committed separately before the release gate can pass.

New resource tests include malformed HTTP/SOCKS traffic, partial-head deadlines,
1150 simultaneous connection attempts, RLIMIT_NOFILE=128 on the isolated child,
continued established payload under pressure, new connections after recovery,
and a bounded SIGTERM grace with every permit returned. Initial test-harness
assumptions about the tracking cap and libc error strings were corrected; failed
preliminary reports are not acceptance passes.

Publication is gated on the continuous run, matching runtime file hashes, exact
version, all CI jobs, fresh packet faults and tests of packaged executables.
The final workflow is main-only. Confirmation to merge PR #5/#7 and release
preparation into main was requested in chat and is pending.

### Infrastructure interruption (2026-10-04 10:35 UTC)

The original 24-hour attempt lost its execution transport after the last sample
at 14573.938 s. Recovery of exec session 72330 timed out; there is no final report
or terminal exit receipt. This is NOT a completed endurance pass. The last
snapshot had 8 active healthy workload streams, 27 FDs, 3268 KiB RSS and no
panics; interrupted evidence is retained in `release-24h-interrupted.json`.
The previously announced next-day completion estimate is withdrawn.

Exact d2a6cce CI 37182730520 passed all 12 jobs, and packet run 37182344060 passed
all three. Downloaded raw package/audit evidence is retained separately.

A new GitHub-hosted five-hour GNU/musl package matrix provides a bounded run
with persistent remote results, within GitHub's six-hour job limit. It does not
satisfy the existing 24-hour release gate. The user was asked whether a clearly
scoped five-hour release standard is acceptable, or whether a continuously
available host must first complete 24 hours. That decision and merge approval
are pending; do not silently lower the publication gate.

## JSON-first configuration change (2026-10-05)

v0.1.0 was released at main `3cb7c5d` after the approved independent five-hour
GNU/musl qualification. This new feature branch does not modify that release.

- Primary JSON inbounds/outbounds schema, flat VLESS settings, REALITY publicKey
  and strict supported transport values. Legacy TOML and explicit migration stay.
- JSON duplicate keys, conflicting aliases, unknown/unsupported features, invalid
  credentials, non-loopback opt-in and listener conflicts are tested fail-closed.
- CLI defaults to client.json; only absent JSON permits legacy fallback. Migration
  preserves credentials and refuses replacement, using mode 0600 on Unix.
- Local strict Clippy and 386 offline/unit/CLI/doc regressions pass. The actual CLI
  JSON application fixture covers both listener families, TLS 1.2/1.3 WSS/SSE,
  injected failures, reconnects and resource drain. Exact final CI is pending.
- Stable publication intentionally remains blocked by the v0.1.0 runtime manifest:
  a new runtime/dependency set needs fresh matching qualification. No release,
  merge, or five-hour evidence for this change is claimed.

## Authorized JSON maintenance release (2026-10-05)

PR #9 merged into main at `93034af`. The user then explicitly requested the JSON
change in the final downloadable release. v0.1.1 uses a clearly disclosed
configuration-update qualification: unchanged transport/scheduler/protocol
source, narrowly reviewed configuration/CLI changes and JSON dependency additions,
fresh full CI plus actual package regressions. It does not reuse v0.1.0 binary
hashes or claim a new five-hour run. Publication and artifact verification are
pending at this preparation checkpoint.
