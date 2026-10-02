# Acceptance

Every box below is one line of the release checklist, the command that either fills it
or fails to, and the output that command actually produced. Two boxes stay open and say
why. Nothing here is a promise about a future run: a box is checked because a log file in
`target/` holds the line quoted under it.

Two conventions make the results comparable:

* **Tree under test.** `fa0214f` plus the changes this file is part of — the hedge
  counters, the soak measurements, the `Direct` test, the README and the two documents
  beside it. Nothing on the wire changed between `fa0214f` and the runs quoted here, and
  the live suites were re-run from that content after it was committed, at `d25d8cf`,
  which is also the commit the artifact below was packaged from. `git describe` on a clean
  checkout of a tagged commit yields the tag, which is what a release bundle should be
  named after.
* **The node.** An unmodified `rust-reality` at
  `e3fc3dc36b931baec042074d6c88e928caf6941f` (tag `v2.0.1`), built with `--locked` by
  `scripts/interop/upstream-server.sh`. `git -C .upstream/rust-reality status --porcelain`
  is empty, which is the difference between "we tested against v2.0.1" and "we tested
  against a server we edited until our client passed".

The three hosts the commands were run on:

| Where | What | Toolchain |
| --- | --- | --- |
| Windows 10 x64 (`D:\Workspace\rust-reality-client`) | the repository, the local suite, one live interop run | rustc/cargo 1.98.1 MSVC |
| WSL2 Ubuntu, kernel 6.18.33.1 (`/home/jacek/rrclient`) | a build copy of the same tree: Linux checks, the live interop run with the `/proc` measurements, the release artifact | rustc/cargo 1.98.0 GNU |
| The same WSL2 VM | the `v2.0.1` node and the fault targets, listening on `127.0.0.1:14443`…`:14449` | `rust-reality 2.0.1` |

---

## Build and shape

- [x] **1. Standalone Rust repository.**

  ```sh
  grep -n "path *=\|\[patch" Cargo.toml; git ls-files | wc -l
  ```

  No `path` dependencies and no `[patch]`: the client depends only on crates.io
  versions, so `cargo build` works from a clone with nothing else present. 53 tracked
  files, no vendored server code — `.upstream/` is gitignored and is used only by the
  interop fixture and the protocol notes.

- [x] **2. No Xray process at runtime.**

  ```sh
  grep -rn "process::Command\|std::process\|Child" src/
  ```

  One hit: `use std::process::ExitCode` in `src/main.rs:25`. The client never spawns a
  process; it is one binary holding two listeners. The live runs below talk to a
  `rust-reality` node, not to Xray, and no Xray binary is referenced by any script in
  `scripts/`.

- [x] **3. No Go runtime.**

  ```sh
  ldd target/x86_64-unknown-linux-gnu/release/rust-reality-client
  ```

  ```text
  linux-vdso.so.1
  libgcc_s.so.1 => /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
  libm.so.6 => /usr/lib/x86_64-linux-gnu/libm.so.6
  libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6
  /lib64/ld-linux-x86-64.so.2
  ```

  That is the entire dependency list of the shipped binary, and `Cargo.toml` has 18
  dependencies, all of them Rust crates. There is no `build.rs`, so nothing is compiled
  from another language at build time either.

- [x] **4. The `rust-reality` server is unmodified.**

  ```sh
  git -C .upstream/rust-reality rev-parse HEAD
  git -C .upstream/rust-reality status --porcelain
  ```

  ```text
  e3fc3dc36b931baec042074d6c88e928caf6941f
  (no output)
  ```

  Detached at the pinned commit, clean tree, and `scripts/interop/upstream-server.sh`
  builds it with `cargo build --release --locked --bin rust-reality`. The protocol
  differences this client had to accommodate are recorded in `docs/PROTOCOL.md` with
  upstream file and line citations rather than patched into the server.

## Wire compatibility

- [x] **5. Exact `v2.0.1` interoperability passes.**

  ```sh
  # Linux, against the node above; full log in target/interop-linux.log
  set -a && . ./target/interop/handoff.env && set +a
  export RRC_INTEROP_ADDR="$RRC_INTEROP_LOOPBACK" RRC_SOAK_SECONDS=120
  cargo test --offline --test interop_v201 -- --ignored --test-threads=1 --nocapture
  ```

  ```text
  test result: ok. 19 passed; 0 failed; 0 ignored; … finished in 159.24s
  ```

  And the same suite from Windows against the same node over the WSL NAT address
  (`RRC_INTEROP_ADDR=172.30.96.85:14443`, log in `target/interop-windows.log`):

  ```text
  test result: ok. 19 passed; 0 failed; … finished in 99.38s
  ```

  Nineteen live connections-shapes: handshake, Vision both directions, half-close, the
  fault matrix, keepalive-idle, the storm and the soak. Two platforms, one node, no
  test skipped or loosened between them.

- [x] **6. SOCKS5 TCP works.** `a_socks5_connect_is_tunneled_through_v201` — greeting,
  `CONNECT`, the bound address in the reply is the address the node actually reached,
  then a round trip through the tunnel.

- [x] **7. HTTP CONNECT works.** `an_http_connect_is_tunneled_through_v201`, plus the
  non-`CONNECT` methods and the oversized head handled by `tests/fault_injection.rs` and
  the raw-SOCKS5-shape tests in `tests/fuzz_smoke.rs`.

- [x] **8. REALITY authentication is native Rust.**
  `reality_handshake_completes_against_v201`, `repeated_handshakes_all_complete` (16 fresh
  `ClientHello`s), `a_foreign_key_agreement_does_not_authenticate`, and in
  `src/protocol/reality/` the 70 unit tests over hello, certificate, server-hello,
  handshake and auth. `auth_key_matches_the_xray_golden_vector` pins the key derivation
  against the Xray oracle (`v26.7.28`) rather than against itself, and
  `Cargo.toml` sets `unsafe_code = "forbid"`.

- [x] **9. VLESS is native Rust.** `src/protocol/vless.rs` (8 tests) and
  `connect_sends_the_request_and_its_camouflage_frame_in_one_record` in
  `src/transport/session.rs`, which asserts the request and its first Vision frame share
  one AEAD plaintext — the shape `docs/PROTOCOL.md` §"Downlink layout the server
  produces" derives from `src/server/vision.rs:1336-1361`.

- [x] **10. Vision is native Rust.** `src/protocol/vision.rs` (12 tests: the first frame's
  user id, padding bands, the frame-size bound, arbitrary fragment sizes across a 40 KiB
  stream, `wrong_user_id_is_rejected_and_latches`, `arbitrary_bytes_never_panic`) plus the
  live `a_vision_session_carries_bytes_both_ways_through_v201`.

- [x] **11. The `Direct` transition is byte-correct.**
  `direct_command_ends_framing_without_reordering_the_bytes_around_it` feeds one plaintext
  containing a `Continue` frame, a `Direct` frame and raw bytes behind it, and asserts
  they leave in that order with the decoder in `Mode::Raw` — the three invariants
  `docs/PROTOCOL.md` §"Continue / End / Direct decision" says must hold, including the one
  a per-frame test cannot see: the tail that arrived in the same buffer.
  `terminating_command_ends_framing_for_the_rest_of_the_stream` covers `End`, and
  `Command::End | Command::Direct => Mode::Raw` is one arm in `src/protocol/vision.rs:545`.

## Long connections

- [x] **12. A long asymmetric stream survives the idle periods it will really see.**

  ```sh
  cargo test --offline --test interop_v201 -- --ignored an_idle_tunnel
  ```

  `an_idle_tunnel_survives_past_the_keepalive_idle` holds a live tunnel quiet for
  `KEEPALIVE_IDLE + 5 s` (35 s), then round-trips both ways and asserts
  `session.failure().is_none()`. On the client side the pair is
  `a_quiet_tunnel_is_left_alone_for_as_long_as_it_stays_quiet` (`src/transport/relay.rs`,
  no idle timer exists to fire) and
  `a_transfer_larger_than_the_buffer_arrives_whole_and_is_counted_apart`, which is the
  asymmetric shape: one direction far larger than `RELAY_BUFFER`. In the soak below, a
  session opened before the window is still alive after 1063 other connections came and
  went.

- [x] **13. TCP half-close is correct.** `half_close_sends_the_alert_the_node_reads_as_a_fin`
  and `close_notify_from_the_node_reads_as_end_of_stream` (`src/transport/session.rs`),
  `a_half_close_is_forwarded_without_cutting_the_reverse_direction`
  (`src/transport/relay.rs`), and live in both directions:
  `half_close_reaches_the_destination_and_ends_the_tunnel` and
  `a_destination_that_hangs_up_without_a_word_arrives_as_an_end_of_stream`.

## Multi-node behavior

- [x] **14. Node selection is not random.**
  `the_first_connection_leads_with_the_first_configured_node` pins the starting choice, and
  `diagnostics_name_the_node_and_nothing_else` pins what a decision is allowed to say.
  `grep -rn "entropy\|getrandom" src/scheduler* src/transport/family*` returns nothing:
  the only entropy in the client goes into `ClientHello` random bytes, session keys and
  Vision padding, never into which node or address is tried.

- [x] **15. The sticky primary works.** `the_dwell_window_holds_the_route_still`, and the
  live evidence is the soak's own line: one named node served every one of 1063
  connections in 120 s while a second configured node existed (`primary primary with 1063
  successes and 0 failures`).

- [x] **16. Hysteresis prevents flapping.** Six tests, one per rule that has to hold a
  route still:
  `a_challenger_takes_the_lead_on_both_a_margin_and_a_percentage` (20 ms *and* 25 %),
  `the_dwell_window_holds_the_route_still` (30 s),
  `a_cooling_winner_cannot_take_the_lead_by_default`,
  `a_slower_family_loses_primary_status_only_after_repeated_alternate_wins` (three lost
  races), and `one_fast_connection_does_not_erase_a_pattern` /
  `the_ewma_is_seven_parts_history` (the estimate moves 2/9 at a time).

- [x] **17. The circuit breaker works.**
  `the_breaker_window_is_the_outage_length_it_earned` (2 s, doubling to 30 s),
  `an_opened_tunnel_pays_off_the_breaker`,
  `a_probe_returns_a_cooling_node_to_service`,
  `a_failing_probe_re_trips_the_node_at_once`,
  `only_a_trip_a_probe_can_answer_is_probed` and
  `a_credentials_refusal_is_never_probed` (a probe cannot test a user id),
  `one_lease_bounds_the_recovery_attempts` and `the_probe_budget_bounds_the_curiosity`.
  Live: `a_scheduler_routes_past_a_node_that_cannot_authenticate` connects through a node
  whose credentials are wrong and a node whose are right, and the wrong one is not
  retried into a hole.

- [x] **18. Hedged dialing is delayed, not simultaneous.**
  `the_hedge_delay_follows_the_leader_and_stays_in_the_band` (twice the leader's estimate,
  clamped to `[150 ms, 750 ms]`, with `hedge_initial` for the unmeasured first connection),
  `a_fast_lead_is_never_given_company` (a 5 ms leader gets no challenger at all),
  `one_configured_node_is_never_hedged`, and `a_late_lead_is_replaced_by_its_challenger`
  for the case the delay exists to catch. The measured consequence is in the soak line:
  `hedged 0` over 1063 connections on a healthy path — hedging costs nothing when nothing
  is late.

- [x] **19. A losing hedge is cancelled safely.** `a_late_lead_is_replaced_by_its_challenger`
  asserts the abandoned leader is scored as a lost race (`hedge_losses`) rather than a
  failure, `walking_away_mid_attempt_costs_nothing`
  (`tests/fault_injection.rs`) drops a client while an attempt is in flight, and live the
  24-way storm asserts
  *"and so did every handshake slot, including the ones the hedge abandoned"* — all
  `MAX_LOCAL_CONNECTIONS` back.

- [x] **20. IPv4/IPv6 fallback works.** 26 tests in `src/transport/family/tests.rs`:
  `losing_the_primary_route_switches_family_immediately`,
  `the_first_usable_ipv4_is_not_queued_behind_a_fourth_attempt_at_ipv6`,
  `one_route_failure_is_not_enough_to_demote_a_family`,
  `a_policy_that_excludes_a_family_penalises_it_forever`,
  `a_demoted_family_gets_one_probe_per_window_however_many_dials_are_open`,
  `successful_recovery_restores_configured_preference_with_hysteresis`.
  `src/transport/dial/tests.rs` adds `the_winner_leaves_with_the_socket_options_armed` and
  the candidate cap. This box is asserted against a modelled route table, not a live
  dual-stack outage: a machine whose IPv6 breaks halfway is not something the fixture can
  provide, and the README does not claim otherwise.

- [x] **21. Keepalive is configured.** `src/transport/socket.rs` (4 tests) sets
  `SO_KEEPALIVE` with `KEEPALIVE_IDLE` 30 s, `KEEPALIVE_INTERVAL` 10 s and 3 probes on the
  node-facing socket, and `the_winner_leaves_with_the_socket_options_armed` pins that the
  socket handed on still carries them. The live 35-second idle test above is the point of
  the setting: the tunnel is still there after longer than a NAT mapping would have lasted.

- [x] **22. No fake migration of an established TCP session.**
  `a_session_that_dies_mid_download_is_reported_and_never_retried` is this box. The
  destination resets *after* bytes have flowed, and the assertions are that the
  application sees `Outcome::Failed(_)` and that `opens == 1`:

  ```text
  TRUNCATE: 65536 of 65536 burst bytes reached the application before the reset,
  and the exchange still ended as a failure          (Linux)
  TRUNCATE: 5 of 65536 burst bytes reached the application before the reset,
  and the exchange still ended as a failure          (Windows)
  ```

  The count differs because the operating system's buffering differs — how much of a
  completed burst a reset can no longer retract is not a protocol fact, and the test
  reports it instead of asserting an accident. What is asserted on both platforms is that
  nothing re-dialled to hide the death, and that the failed exchange gave its slot back.
  `src/serve.rs:17` states the rule the code follows: after the local client is told
  `succeeded`, the session is immutable.

## Diagnostics and logs

- [x] **23. Logs are secret-safe.** Six tests aimed at the strings themselves:
  `the_message_never_carries_credential_material` and
  `a_line_carries_the_server_keys_and_the_fields_in_order` (`src/logging.rs`),
  `diagnostics_never_render_the_key` (`src/protocol/reality/auth.rs`),
  `debug_output_carries_no_key_material_or_payload` (`src/transport/session.rs`, which
  pins `Debug` as well as the log line),
  `no_diagnostic_echoes_the_user_id_it_was_given` and
  `the_public_key_is_named_because_it_is_not_a_secret` (`tests/cli.rs`, which run the
  built binary and read its stdout). What `check` and `doctor` do print is the node name,
  endpoint, SNI, `publicKey` and the short id's **character count**
  (`shortId={n} chars`, `src/main.rs:220`) — the public key and the selector are
  server-side values that identify a REALITY identity rather than a client, and the count
  is what tells an operator their `shortId` is empty without echoing a value that is
  someone else's. The `userId` is printed by nothing.

- [x] **24. `check`, `doctor` and `explain` work.** `tests/cli.rs` (17 tests) executes the
  binary as a process for each: `the_generated_template_is_a_valid_configuration`,
  `a_broken_file_reports_every_problem_it_has`, `a_short_id_is_reported_as_a_length`,
  `a_syntax_error_gives_a_position_and_no_value`, `a_named_bind_address_is_refused_and_the_numeric_shape_is_shown`,
  `doctor_fails_on_the_placeholder_key_it_shipped_with`,
  `explain_answers_for_every_family_and_refuses_anything_else`,
  `run_binds_what_the_configuration_declares_and_stays_up`, `the_version_is_the_package_version`.
  Exit codes are the contract: 0 OK, 1 broken, 2 wrong invocation.

## Failure handling

- [x] **25. Fault-injection tests pass.**

  ```sh
  cargo test --offline --test fault_injection --test fuzz_smoke
  ```

  ```text
  test result: ok. 8 passed; 0 failed
  test result: ok. 4 passed; 0 failed
  ```

  `every_failure_is_answered_in_both_languages` walks the whole taxonomy — DNS, connect,
  handshake, rejection, session, policy — through both inbound edges and asserts each one
  reaches the application with a reason and each one's `countsAgainstNode` matches the
  party at fault. The fuzz smoke drives mutated greetings, requests and HTTP heads through
  the parsers with no fixture at all.

- [x] **26. A soak shows no descriptor, task or memory leak.**

  ```sh
  cargo test --offline --test interop_v201 -- --ignored --test-threads=1 --nocapture
  ```

  ```text
  SOAK 120.097172739s: 1063 connections, 32953 bytes down, p50 60.804906ms
    p95 64.80683ms p99 68.64482ms (fastest 58.553713ms, slowest 76.725247ms),
    hedged 0 won 0, long-lived session still up, primary primary with 1063
    successes and 0 failures
  SOAK footprint: descriptors 13 -> 13, resident 7864 KiB -> 7992 KiB, threads 2 -> 2
  ```

  1063 tunnels in two minutes against a live node: the descriptor count read out of
  `/proc/self/fd` is identical before and after (the test asserts `DESCRIPTOR_SLACK` = 16),
  the thread count does not move, and the resident set grows 128 KiB across the window.
  The 60-second Windows run is `754 connections … 754 successes and 0 failures`. Task
  leak: `every_socket_taken_ends_up_in_exactly_one_counter` (`tests/serve.rs`) and the
  storm test's slot assertion cover the accounting that a thread count alone cannot.

## The repository's own gates

- [x] **27. Formatting is clean.** `cargo fmt --check --all` → exit 0.

- [x] **28. Lints are clean.**

  ```sh
  cargo clippy --offline --all-targets -- -D warnings
  ```

  Exit 0 with `clippy::all` and `clippy::pedantic` both `deny` in `Cargo.toml`, after
  touching every changed file so the result is a fresh check and not a cache hit. The same
  command is CI's, with `--locked`.

- [x] **29. The tests are green.**

  ```sh
  cargo test --offline --no-fail-fast
  ```

  ```text
  unittests src\lib.rs      … 300 passed; 0 failed
  tests\cli.rs              … 17 passed; 0 failed
  tests\fault_injection.rs  … 8 passed; 0 failed
  tests\fuzz_smoke.rs       … 4 passed; 0 failed
  tests\serve.rs            … 6 passed; 0 failed
  tests\interop_v201.rs     … 19 ignored (they need a live node; see box 5)
  test result: ok.          … 0 failed
  ```

  335 offline tests, and the 19 that cannot run offline run in box 5 on two platforms.
  `cargo +1.85.0 check --offline --all-targets` — the declared MSRV — also exits 0, on
  Windows and on Linux.

- [ ] **30. CI is green.** **Not claimed.** `.github/workflows/ci.yml` defines six jobs —
  `lint`, `test`, `msrv`, `interop`, `artifacts`, `checksums` — and both workflow files
  parse (`python -c "yaml.safe_load(...)"` → 6 and 4 top-level keys). What is *not*
  available is a run: this repository has no remote, so `gh` has nothing to query and no
  Actions run exists to point at. Each job's commands were instead executed by hand, on
  both platforms, and are boxes 5, 26, 27, 28, 29 and 32. The `interop` job's own steps
  are the same commands as box 5, so the first push to a remote will either reproduce
  them or fail visibly.

## Delivery

- [x] **31. The README is complete.** `README.md` is 634 lines and covers the eighteen
  required topics as numbered sections, in order: what it is (1), the exact compatibility
  target (2), architecture (3), installation (4), configuration (5), SOCKS5 (6), HTTP
  CONNECT (7), Pi Agent (8), multi-node stability (9), sticky routing (10), hedged dialing
  (11), the circuit breaker (12), keepalive (13), diagnostics (14), logs (15), systemd
  (16), the security model (17) and limitations (18). Section 18 carries the migration
  limitation verbatim, and section 8 shows `HTTPS_PROXY=http://127.0.0.1:10809` with the
  `socks5h://` versus local-DNS explanation. Every constant quoted in it was read out of
  the source it cites; the numbers in the security model are `file:line` references,
  because a README that rounds a bound is how an operator ends up trusting the wrong one.

- [x] **32. The release job's steps produce artifacts.** The `artifacts` job was executed
  by hand on Linux, with the same `cargo build --release --locked --target …`, the same
  staging layout and the same `tar --sort=name --mtime=@0 --owner=0 --group=0
  --numeric-owner | gzip -n` invocation that CI uses:

  ```text
  VERSION=d25d8cf
  === BUILD x86_64-gnu
      Finished `release` profile [optimized] target(s) in 0.10s
  SKIP x86_64-musl: target x86_64-unknown-linux-musl is not installed here
  SKIP aarch64-gnu: target aarch64-unknown-linux-gnu is not installed here
  rust-reality-client-d25d8cf-x86_64-gnu/
  rust-reality-client-d25d8cf-x86_64-gnu/README.md
  rust-reality-client-d25d8cf-x86_64-gnu/VERSION
  rust-reality-client-d25d8cf-x86_64-gnu/client.toml
  rust-reality-client-d25d8cf-x86_64-gnu/rust-reality-client
  ```

  The `0.10s` is a cache hit, and it is the useful part of the output: this step was run
  once before, from the same content at `fa0214f-dirty`, where the compile took 19.81 s and
  produced a 932 334-byte archive. Committing the documents changed nothing but the version
  string, so the release binary was reused and the archive changed by exactly one byte.

  The staged binary runs (`rust-reality-client 0.1.0`, exit 0), the archive is 932 333
  bytes around a 1 934 488-byte stripped binary, and the tar listing is byte-stable
  because the ownership, mtime and gzip name are zeroed. **The other two
  matrix rows are not executed here**: the WSL user space has no `musl-gcc` and no
  `aarch64-linux-gnu-gcc`, and installing them needs `sudo`, which this session does not
  have. Their CI rows carry `packages: musl-tools` and
  `packages: gcc-aarch64-linux-gnu libc6-dev-arm64-cross` with
  `linker: aarch64-linux-gnu-gcc`, which is what `ubuntu-24.04` provides; that is a
  reasoned claim, not a measured one, and it is the reason this box says "steps" rather
  than "workflow".

- [x] **33. `SHA256SUMS` is generated and verifies.**

  ```text
  96481cc82b6d4b0c84aa93c20e7b22a42fd3675a95791ca80abccc4c647381c1  rust-reality-client-d25d8cf-x86_64-gnu.tar.gz
  === VERIFY
  rust-reality-client-d25d8cf-x86_64-gnu.tar.gz: OK
  ```

  `sha256sum --check --strict SHA256SUMS` exits 0 — `--strict`, so a listed file that is
  missing or a stray file that is not fails the check rather than being ignored. The
  `checksums` job runs the same two commands over the three downloaded artifacts.

---

## What this file does not establish

* That the workflow has ever been run by GitHub. It has not; there is no remote. Boxes 30
  and 32 mark that line precisely, and it is the only line between this repository and a
  tag someone can install.
* That a real-world dual-stack outage or a real NAT box was involved. Box 20 is a modelled
  route table; box 12 and box 21 use the client's own keepalive timer against a live node,
  which is the closest thing to a NAT that a fixture can be.
* That the fault matrix covers more than the seven failure families the taxonomy has. It
  covers exactly those seven, both inbound edges, and a live node for four destination
  shapes.
* Anything about QUIC, HTTP/3, UDP, TUN, MUX or session migration. `v2.0.1` has no
  cross-node resume, so no box here claims one; see README §18.
