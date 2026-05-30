# Commons Release Cleanup Plan

Date: 2026-05-30

## Definition Of Done

This work is complete only when every criterion below is verified:

- `registry-platform` is on `main`, `git status --short --branch` prints `## main...origin/main`, and `cargo test --workspace --all-features` passes.
- `registry-relay`, `registry-notary`, and `registry-manifest` each contain a documented compatibility command in the repo that owns it.
- A clean `registry-relay` branch passes its compatibility command against sibling `../registry-platform`.
- A clean `registry-notary` branch passes its compatibility command against sibling `../registry-platform`.
- `registry-manifest` passes its documented workspace or consumer compatibility command.
- `registry-lab` contains `just commons-check`, and the command runs Platform, Manifest, Relay, Notary, and selected Lab smoke checks.
- Platform APIs used by both Relay and Notary have named safe profiles or builders, and standard app flows no longer manually fill low-level security structs such as `TokenVerifierConfig` token-type fields.
- `registry-lab` uses sibling source dirs during development and updates vendor pins only after source repos are committed.
- `git diff -- registry-lab/vendor` contains no product-code hotfix that is absent from the owning source repo.
- Each wave has a code-review checkpoint recorded before the next wave starts.

## Wave 1: Consumer Compatibility Baseline

Goal: restore a clean, releasable state after the Platform merge.

Checklist:

- Isolate Platform compatibility patches in `registry-relay`.
- Isolate Platform compatibility patches in `registry-notary`.
- Keep unrelated route, docs, and demo changes out of these PRs.
- Add or preserve focused tests for keyed audit-chain verification.
- Add or preserve focused tests for strict OIDC token `typ`.
- Add or preserve Notary tests for OID4VCI nonce replay.
- Add or preserve Notary wiring for `ProofValidationPolicy.forbidden_holder_keys`.

Definition of done:

- Clean `registry-relay` branch passes `cargo check --all-features`.
- Clean `registry-notary` branch passes `cargo check -p registry-notary-server --all-features`.
- PRs contain only compatibility and security-wiring changes.
- No Lab vendor pins are changed in this wave.

Review checkpoint:

- Review only consumer compatibility diffs.
- Do not approve if unrelated route, docs, demo, or generated-file churn is mixed in.

## Wave 2: Compatibility Scripts

Goal: make Platform consumer breakage impossible to miss.

Checklist:

- Add `registry-relay/scripts/check-platform-compat.sh`.
- Add `registry-notary/scripts/check-platform-compat.sh`.
- Default both scripts to sibling `../registry-platform`.
- Fail clearly if the sibling Platform path is missing.
- Document each command in the owning repo.
- Add a lightweight `registry-manifest` compatibility note or script, based on actual consumer needs.

Definition of done:

- Relay compatibility script passes from a clean checkout.
- Notary compatibility script passes from a clean checkout.
- Each script exits nonzero on missing Platform path.
- Commands are CI-ready and documented.

Review checkpoint:

- Review scripts for portability, clear failure output, and absence of hidden local-state assumptions.

## Wave 3: Lab Release Gate

Goal: make one command answer whether the commons release set is coherent.

Checklist:

- Add `just commons-check` in `registry-lab`.
- Run `cargo test --workspace --all-features` in `registry-platform`.
- Run `cargo test --workspace` in `registry-manifest`.
- Run Relay's Platform compatibility script.
- Run Notary's Platform compatibility script.
- Run selected Lab smoke checks, at minimum `relay-zitadel` and `notary-redis`.
- Use sibling source dirs by default.

Definition of done:

- `just commons-check` runs from `registry-lab`.
- It reports which repo and command failed.
- It does not modify generated files, vendor pins, or demo outputs.
- It passes against clean source branches for the release set.

Review checkpoint:

- Review command output and runtime assumptions.
- Do not approve if success depends on undocumented services, secrets, or generated local files.

## Wave 4: Platform API Cleanup

Goal: reduce app-side security plumbing.

Checklist:

- Add OIDC profiles or builders for Relay access-token verification.
- Add OIDC profiles or builders for Notary self-attestation verification.
- Add OIDC profiles or builders for Notary federation request verification.
- Add audit pipeline helpers for production keyed chains from env.
- Add audit pipeline helpers for explicit dev-only unkeyed mode.
- Add an OID4VCI proof and nonce helper for credential endpoints.
- Keep low-level primitives available for advanced use.
- Migrate Relay and Notary to the named profiles where behavior is shared.

Definition of done:

- Relay no longer manually fills low-level OIDC token-type fields for standard flows.
- Notary no longer manually fills low-level OIDC token-type fields for standard flows.
- Audit chain wiring is centralized or materially thinner in both apps.
- Focused Platform tests cover every new profile.
- Relay and Notary compatibility scripts still pass.

Review checkpoint:

- Review API shape before broad migration.
- Reject profiles that only rename old config bags without reducing app-side decisions.

## Wave 5: Manifest Alignment

Goal: treat `registry-manifest` as the second shared kernel.

Checklist:

- Document `registry-manifest` as the contract and schema kernel.
- Document Relay and Notary manifest usage.
- Identify duplicated manifest validation or rendering logic in Relay and Notary.
- Add named validation modes only where reuse is real.
- Add a manifest compatibility check when a real consumer contract exists.

Definition of done:

- Manifest has a clear consumer check or a documented reason it is not yet needed.
- Relay and Notary manifest use is documented.
- No speculative abstraction is added without a real consumer.

Review checkpoint:

- Review Manifest boundaries separately from Platform security boundaries.

## Wave 6: Lab Pin Update

Goal: make Lab reflect the blessed release set.

Checklist:

- After Platform, Manifest, Relay, and Notary PRs land, update Lab vendor or submodule pins.
- Run `just commons-check`.
- Run release smoke checks needed for demos.
- Confirm no product-code patch exists only under `registry-lab/vendor`.

Definition of done:

- Lab pins match committed source repos.
- `just commons-check` passes.
- Demo smoke checks pass or have documented external-service blockers.
- Lab contains no source-only hotfixes.

Review checkpoint:

- Final release-readiness review checks source repo commits, Lab pins, command output, and remaining risks.

## Execution Order

1. Land Relay and Notary compatibility PRs.
2. Add compatibility scripts.
3. Add Lab `commons-check`.
4. Clean up Platform APIs with named profiles and builders.
5. Align Manifest as the contract kernel.
6. Update Lab pins and run release checks.

## Implementation Plan

### Wave A: Compatibility PRs

Parallel workers:

- Worker Relay: isolate Platform compatibility changes in `registry-relay`.
- Worker Notary: isolate Platform compatibility changes in `registry-notary`.

Checklist:

- Update only the minimum files needed for Platform API compatibility.
- Add or preserve focused tests for keyed audit chains, strict OIDC `typ`, and Notary nonce replay.
- Run `cargo check --all-features` in Relay.
- Run `cargo check -p registry-notary-server --all-features` in Notary.

Wave A done when:

- Both checks pass on clean branches.
- Diffs contain no unrelated route, docs, demo, generated, or Lab vendor changes.
- Review checkpoint A approves both PRs before Wave B starts.

### Wave B: Compatibility Commands

Parallel workers:

- Worker Relay: add and document `scripts/check-platform-compat.sh`.
- Worker Notary: add and document `scripts/check-platform-compat.sh`.
- Worker Manifest: document or add the Manifest compatibility command.

Checklist:

- Commands default to sibling `../registry-platform` where applicable.
- Commands fail nonzero when required sibling repos are missing.
- Commands print the repo and failed command.

Wave B done when:

- Relay command passes from a clean Relay checkout.
- Notary command passes from a clean Notary checkout.
- Manifest command passes from a clean Manifest checkout.
- Review checkpoint B approves script behavior and documentation.

### Wave C: Lab Gate

Parallel workers:

- Worker Lab: add `just commons-check`.
- Worker Verify: run the command and capture failures.

Checklist:

- `commons-check` runs Platform tests, Manifest tests, Relay compatibility, Notary compatibility, `relay-zitadel`, and `notary-redis`.
- The command does not edit vendor pins, generated files, or demo outputs.

Wave C done when:

- `just commons-check` passes or lists only documented external-service blockers.
- Review checkpoint C validates command output and environment assumptions.

### Wave D: Platform Profiles

Parallel workers:

- Worker OIDC: add named verifier profiles and tests.
- Worker Audit: add audit pipeline/profile helpers and tests.
- Worker OID4VCI: add credential-endpoint proof and nonce helper and tests.

Checklist:

- Migrate Relay and Notary standard flows to the new profiles.
- Keep low-level primitives available for advanced use.
- Run Platform tests and both consumer compatibility commands.

Wave D done when:

- Platform tests pass.
- Relay and Notary compatibility commands pass.
- App code no longer hand-fills standard OIDC token-type fields.
- Review checkpoint D approves API shape before broad use is marked done.

### Wave E: Manifest And Lab Pins

Parallel workers:

- Worker Manifest: document kernel role and consumer contract.
- Worker Lab: update vendor or submodule pins after source PRs merge.
- Worker Verify: run final release checks.

Checklist:

- Add Manifest consumer checks only where there is a real consumer contract.
- Update Lab pins to committed Platform, Manifest, Relay, and Notary revisions.
- Run `just commons-check`.

Wave E done when:

- Lab pins match source repo commits.
- `just commons-check` passes.
- `registry-lab/vendor` contains no source-only hotfixes.
- Final review checkpoint approves source commits, Lab pins, command output, and remaining risks.
