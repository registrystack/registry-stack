# Adapter Delivery Plan

Status: active, 2026-10-30. Companion to `CONCEPT.md`: the concept is the
product contract; this file decomposes its section 14 into parallel
workstreams with definitions of done. On any conflict, `CONCEPT.md` wins.

## Rules every agent works under

Every brief carries these rules by reference; they are not optional.

1. Do NOT spawn subagents (do not use the Agent tool).
2. Worktree: `/Users/jeremi/orca/workspaces/registry-stack/live-adapter`.
    Absolute paths only; never `cd`. First command: verify
    `git -C /Users/jeremi/orca/workspaces/registry-stack/live-adapter
    --no-optional-locks rev-parse HEAD` equals the SHA in your brief; if it
    differs, stop and report.
3. Never push, merge, rebase, tag, reset, stash, `checkout --`, or clean.
    Commit with plain `git commit -m ...`: this machine's commit-msg hook
    appends the DCO `Signed-off-by` trailer automatically. Never type that
    trailer yourself and never set author or committer to an agent. After
    your first commit, run
    `git --no-optional-locks log -1 --format=%B | rg 'Signed-off-by'` and
    confirm exactly one such line; if there is none, amend with
    `git commit --amend --no-edit -s`. Conventional subjects, imperative
    mood: `feat(adapter):`, `test(adapter):`, `chore(adapter):`, or the
    owning area's prefix (`feat(platform):` for `products/platform`,
    `crates/registry-platform-*`).
4. Delete nothing outside `products/adapter/scratch/<your-stream>/`. Treat
    modified and untracked files you did not create as another session's
    work; never revert or reformat them.
5. Cargo always runs as:
   `CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo ...`
   Never clean a target directory another agent builds in. Concurrent
   cargo runs serialize on the target lock; wait, never kill.
6. Shared files (root `Cargo.toml`, `deny.toml`, `rust-toolchain.toml`,
   root `AGENTS.md`, `.github/**`) change only in Wave 0 or by the
   integration stream at a wave boundary. If your stream needs a change
   there mid-wave, stop and report it instead of editing.
7. TDD: write the failing test first; write only enough code to pass;
   refactor while green. Test output must be clean; errors that are
   expected are captured and asserted on, never printed past.
8. Verification floor, reported verbatim with failures included:
   `cargo fmt --check`; `cargo clippy -p <owned crates> --all-targets --
   -D warnings`; `cargo test -p <owned crates> --locked`.
9. Report what landed and what did not. No stubs of promised behavior; if
   scope must shrink, the report says so, not the silence.
10. Never log secrets or environment dumps. All adapter diagnostics are
    value-free (`adapter.*` codes, CFG-SEC-3).

## Wave model

Waves run sequentially; streams inside a wave run in parallel on disjoint
paths and commit their own work. The integration stream closes each wave
set; an Opus review agent closes each increment. HEAD SHAs are captured at
wave launch and carried in every brief.

## Increment 0 (detailed)

### Wave 0, stream S0: scaffold (single, serial)

Owns: `crates/registry-adapter{,-core,-ctl}/` skeletons (real module roots,
no placeholder logic), root `Cargo.toml` workspace members,
`products/adapter/AGENTS.md` (routing guide: names `CONCEPT.md`, this plan,
the gates), `products/adapter/scripts/check-contracts.sh` v0 (fmt + clippy
+ test over the adapter crates), root `AGENTS.md` repository-map and
routing rows, CI registration through `.github/scripts/ci_changes.py`.

DoD:
- Workspace `cargo check --workspace --all-targets` green with the three
  crates present.
- `python3 .github/scripts/test_ci_changes.py` green (the `--help` run is
  not the check; the test file is).
- `check-contracts.sh` exits 0 from a clean shell; `shellcheck` and
  `shfmt -d` clean on it.
- Root `AGENTS.md` routes `registry-adapter*` to `products/adapter/AGENTS.md`.

### Wave 1 (parallel)

**A1, core model**, owns `crates/registry-adapter-core/**`:
profile, pack, project, and call-plan AST types (every step kind and
budget from `CONCEPT.md` 8.3; every kind from section 12), problem codes,
and the pure authoring checks: binding resolution totality, budget bounds,
`iterate` policy presence, digest-pin shape, envelope-name validity, plan
reference resolution (CFG-ID-4 shape, on parsed values; this crate does no
file I/O).

DoD: accept/reject unit tests for every check, asserting `adapter.*` codes
(not prose); verification floor green; dependencies stay minimal (serde and
platform types only where the model needs them).

**A2, platform token**, owns `products/platform/**`:
`Adapter` envelope prefix and `adapter.*` diagnostic token in
CONFIG-CONVENTIONS.md (CFG-ENV-2, CFG-ENV-3, CFG-DIAG-3) and the five
format kinds in `config-formats.yaml`, plus whatever the platform's
registry regenerates; follow `products/platform/AGENTS.md` for its checks.

DoD: the platform product's own gates green; the five kinds registered;
conventions tables carry the new rows.

### Wave 2 (parallel; needs A1's commit)

**B1, check tooling**, owns `crates/registry-adapterctl/**` (plus a read
layer in core where pure): `adapterctl check` (envelope, digest pinning,
reference resolution, budgets, script seams precompiled through
`registry-platform-script`), committed generated schemas under
`products/adapter/schemas/`, the fixture-replay harness (golden transcripts
including multi-step and paginated sequences), the clap tree with
`registry-cli-docs --write` catalog regeneration.

DoD: check accepts the good corpus and refuses every bad corpus member with
the exact code; schema drift gate green; CLI catalog snapshot test green.

**B2, authored artifacts**, owns
`products/adapter/{profiles,packs,examples,fixtures}/**`:
`breg-records` v1 profile; `dhis2-tracker` read pack (operations,
declarative maps, one script seam in its own digest-pinned file, a
pagination plan, code maps); an example project; the fixture corpus with
upstream-version provenance on every fixture.

DoD: envelopes correct per A2's registration; no inline scripts; every
fixture carries provenance; corpus participates in the platform value-free
marker once B1 wires it.

### Wave 3, integration (single stream)

Owns cross-cutting wiring only: `check-contracts.sh` gains schema drift,
fixture replay, and corpus participation; reconciles B1/B2 drift; ticks the
Increment 0 checklist below; updates the `CONCEPT.md` status line.

DoD: `products/adapter/scripts/check-contracts.sh` green from a clean
shell; clippy and fmt over the adapter crates green; the report lists every
gate result verbatim.

### Review gate (Opus agent, after each increment)

Verify the section-13 items that exist so far; adversarial pass: flip a
fixture byte, unpin a digest, exceed a declared budget in a test, confirm
the tests fail and the diagnostics carry no values. Findings only; fixes
return to the owning streams.

## Increment 1 (streams; briefs detailed at launch)

- **P1, platform upstream layer**, owns `crates/registry-platform-httputil/**`
  only: the read-class redelivery executor (attempts, backoff, bounded
  jitter 0.1 to 0.3, matching by upstream error class; `CONCEPT.md` 8.4
  retry row) and the circuit breaker module (CLOSED/OPEN/HALF_OPEN,
  failure-rate threshold over a window, single-probe half-open admission).
  Additive API; zero Evidence crate changes; Evidence adopting these is a
  recorded follow-up candidate, not this stream's work.
- **C1, plan interpreter**, owns `registry-adapter/src/plans/**` plus the
  in-process upstream double (fault injection: timeout, reset, 5xx storm,
  malformed JSON, oversized body, slow trickle, redirect attempt, duplicate
  and drifting pages).
- **C2, facade HTTP**, owns `registry-adapter/src/{http,auth}/**`:
  `registry-platform-httpsec` server side, OIDC caller authentication,
  access profiles, routes for bound operations only.
- **C3, journal**, owns `registry-adapter/src/journal/**`: PostgreSQL
  migrations and audit rows (metadata, digests, outcomes; no bodies),
  `postgres-test` suite on a disposable database.
- **C4, compile**, owns `adapterctl compile`: per-deployment OpenAPI
  emission, byte-stable, drift-gated; Record v1 shape checked against
  `products/breg/generated/` goldens.
- Integration: dhis2-tracker reads end to end over the double; contract
  tests (13.5); property tests (13.4) in the default suite.

## Increment 2 (outline)

Write plans under `stopOnFirstFailure`; the idempotency journal and replay
(evaluate `registry-platform-dispatch`'s idempotency-key recipe under the
two-system rule first; adopt it or record why not); DHIS2 import-summary
mapping, partial-acceptance 409 with counts only, conflict fixtures;
`test-postgres.sh`; the writes' property tests from 13.4.

## Increment 3 (outline)

The `graphql` envelope executor (ladder rung 1, mechanism only); the
`opencrvs` pack, reads first, then writes (draft, declare); fixtures with
provenance; gates extended to the new pack.

## Platform improvement rules

- Mechanism moves up into platform crates; product logic never does.
- Additions are additive; consuming products' served behavior is frozen.
  Evidence's adoption of new shared pieces is a later decision on
  Evidence's schedule, never adapter scope.
- Candidates register: httputil redelivery and breaker (Increment 1,
  needed); dispatch idempotency-key recipe (Increment 2, evaluate first);
  script JSON-to-Rhai conversion helpers (when mapping seams need them).

## Brief template

```
Stream: <id>, Increment <n>, Wave <m>
Worktree: /Users/jeremi/orca/workspaces/registry-stack/live-adapter
Expected HEAD: <sha captured at launch>
You own these paths (create or edit only these): <paths>
Read first: products/adapter/CONCEPT.md sections <s>; this plan's rules
and your stream DoD.
Task: <one-paragraph scope>
Rules: the ten rules in products/adapter/DELIVERY-PLAN.md "Rules every
agent works under", all of them.
DoD: <stream DoD, copied>
Report: what landed, what did not, gate output verbatim, any shared-file
need you stopped on.
```

## Launch checklist (per wave)

1. Capture the wave's base HEAD SHA; confirm stream ownership paths are
   disjoint.
2. Instantiate briefs from the template; S0-style single streams do not
   need parallel verification.
3. After the wave: integration stream verifies, commits reconciliations.
4. After the increment: review gate, then Jeremi reviews the branch before
   any PR.

## Increment acceptance (what Jeremi runs)

Increment 0, from the worktree root:

1. `products/adapter/scripts/check-contracts.sh` exits 0.
2. `CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo run --locked -p registry-adapterctl -- check <example-project-path>` exits 0 with a value-free report; the integration report names the exact path and arguments.
3. `git --no-optional-locks log --oneline origin/main..HEAD` shows conventional subjects, and every commit body carries exactly one DCO trailer.
4. `rg -n 'registry-adapter' AGENTS.md` shows the routing row.

Each later increment's acceptance commands are added here at its launch,
before its streams start, in the same runnable form.

Increment 1, from the worktree root (all must exit 0):

1. `products/adapter/scripts/check-contracts.sh` (now includes the
   contract tests of 13.5 and property tests of 13.4).
2. `CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter` (double-driven end-to-end reads included).
3. `... cargo run --locked -p registry-adapterctl -- compile <example-project-path>` emits `openapi.json` into the built package; a second run is byte-identical.

Increment 2:

1. `products/adapter/scripts/test-postgres.sh` exits 0 on a disposable
   database (journal, idempotency replay, step-failure replay).
2. Increment 1's commands still pass, including the write fixtures in
   `check-contracts.sh` fixture replay.

Increment 3:

1. `check-contracts.sh` replays the `opencrvs` fixture suite with
   provenance, green.
2. `... cargo run --locked -p registry-adapterctl -- check <opencrvs-example-path>` exits 0.

Global (CONCEPT.md section 14): the same engine serves both packs' example
projects; `adapterctl check` is green on every maintained pack; every gate
in 13.1 exists and is green; the review-gate report from each increment is
recorded under `products/adapter/reviews/`.

## Increment checklist

- [ ] Increment 0
- [ ] Increment 1
- [ ] Increment 2
- [ ] Increment 3
