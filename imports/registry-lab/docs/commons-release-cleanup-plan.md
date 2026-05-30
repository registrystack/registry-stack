# Commons Release Cleanup Plan

Date: 2026-05-30

## Definition Of Done

This work is complete only when every criterion below is verified:

- `registry-platform` exposes tested named profiles or helpers for shared OIDC, audit, OID4VCI, and security-boundary flows used by Relay and Notary.
- `registry-relay` and `registry-notary` compile against sibling `../registry-platform` from clean branches and no longer hand-fill low-level OIDC token-type fields for standard app flows.
- `registry-relay` and `registry-notary` each provide a documented `scripts/check-platform-compat.sh` command that defaults to sibling `../registry-platform`, fails clearly when it is missing, and runs at least one focused security test.
- `registry-manifest` is documented as the contract and schema kernel and provides a documented contract-kernel check against real Lab consumer manifests.
- `registry-lab` provides `just commons-check`, and it runs Platform, Manifest, Relay, Notary, and selected Lab smoke checks from sibling source dirs by default.
- Focused tests prove strict OIDC `typ` handling, keyed audit-chain bootstrap from persisted tails, OID4VCI nonce replay rejection, and credential-endpoint holder-key separation.
- Source repos contain all product-code changes before Lab vendor pins or generated outputs move.
- `git diff -- registry-lab/vendor` contains no product-code hotfix that is absent from the owning source repo.
- Every changed repo has either passing verification or a recorded external-service blocker with the exact command and failure reason.
- Each wave has a code-review checkpoint completed before the next dependent wave is marked done.

## Scope Boundaries

- Keep Platform security helpers, Relay migration, Notary migration, Manifest kernel checks, and Lab release gates as separate review surfaces.
- Do not mix unrelated route, demo, generated, SDK, or vendor churn into the security cleanup waves.
- Keep low-level Platform primitives available for advanced callers, but standard app flows should use named profiles or helpers.
- Lab may use sibling source dirs during development; Lab pins move only after source repo changes are committed and reviewed.

## Implementation Plan

- [ ] Wave 1: Platform profiles in parallel.
  - Workers: OIDC profile worker, audit profile worker, OID4VCI helper worker.
  - Deliver: named verifier profiles for Relay access tokens, Notary access tokens, and Notary federation JWTs; production keyed and explicit dev-only audit profiles; credential-endpoint proof and nonce helper.
  - Done when: focused Platform tests for OIDC profiles, audit profiles, and OID4VCI helpers pass.
  - Review checkpoint: API-shape review confirms helpers remove app-side security decisions rather than only renaming config bags.

- [ ] Wave 2: Relay and Notary migration in parallel.
  - Workers: Relay worker owns Relay migration and `scripts/check-platform-compat.sh`; Notary worker owns Notary migration and `scripts/check-platform-compat.sh`.
  - Deliver: standard OIDC, audit, and OID4VCI app flows use Platform profiles or helpers.
  - Done when: `REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform scripts/check-platform-compat.sh` passes in both Relay and Notary, and each script runs required focused tests.
  - Review checkpoint: Relay and Notary diffs are reviewed separately before either app is marked done.

- [ ] Wave 3: Manifest kernel in parallel with Wave 2 review.
  - Worker: Manifest worker owns docs and `scripts/check-contract-kernel.sh`.
  - Deliver: Manifest is documented as the reusable contract and schema kernel and validates real Lab consumer manifests.
  - Done when: `scripts/check-contract-kernel.sh ../registry-lab/config/static-metadata/metadata.yaml ../registry-lab/config/relay/*.metadata.yaml` passes from `registry-manifest` and exits nonzero on invalid consumer manifests.
  - Review checkpoint: Manifest boundaries are reviewed separately from Platform security boundaries.

- [ ] Wave 4: Lab release gate after Waves 2 and 3 pass review.
  - Worker: Lab worker owns `scripts/commons-check.sh` and `just commons-check`; verification worker runs it from a clean Lab checkout.
  - Deliver: one Lab command runs Platform tests, Manifest kernel check, Relay compatibility, Notary compatibility, `relay-zitadel`, and `notary-redis` using sibling source dirs.
  - Done when: `just commons-check` prints the repo and command being run, passes without editing vendor pins, generated metadata, demo output, or committed fixtures, or lists only documented external-service blockers.
  - Review checkpoint: command output and environment assumptions are reviewed before Lab is marked release-ready.

- [ ] Wave 5: Final release review and Lab pins.
  - Workers: reviewer worker performs final diff review; parent agent runs final verification and owns integration decisions.
  - Deliver: source repo commits are reviewed first, then Lab vendor or submodule pins update to those committed revisions.
  - Done when: final verification output is recorded, Lab pins match source repo commits, `just commons-check` passes or has only named external blockers, and no feature is marked complete without tests passing.
  - Review checkpoint: final release-readiness review validates source commits, Lab pins, command output, dirty-worktree status, and remaining risks.
