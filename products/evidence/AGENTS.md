# Evidence agent guidance

Read the repository-root `AGENTS.md` first. Before changing Evidence, read these
files completely in order:

1. `products/evidence/CONCEPT.md`
2. `products/evidence/IMPLEMENTATION.md`
3. `products/evidence/SOURCE-TESTING.md`
4. `products/evidence/OPERATOR-CONTRACT.md`
5. `products/evidence/reference/request-adapter/ADAPTER-API.md`
6. `products/evidence/reference/request-adapter/deployment-projects/CONFIG.md`
7. `products/evidence/reference/request-adapter/deployment-projects/FIXTURES.md`

Read the normative files relevant to the change under `contracts/` and the
code-generated JSON Schema and OpenAPI artifacts under `generated/` after those
four product-level contracts. Generated artifacts must be reproduced with
`scripts/check-contracts.sh` and never hand-edited.

## Product boundary

Evidence Version 1 is one `registry-evidence` crate, one `evidence` binary, one
process, and one operator-controlled trust domain. It is independent from
Registry Notary and must not depend on or copy abstractions from
`registry-notary*`. It also does not depend on Registry Manifest,
`registry-platform-pdp`, `registry-platform-oid4vci`,
`registry-platform-replay`, or `registry-platform-sts`.

The runtime depends on the portable `registry-evidence-verifier` library, which
owns the response formats, the Evidence payload contract, and relying-party
verification so client tooling can verify a signed response without the runtime.
The verifier library sits beside the runtime and is not a second runtime; its
source is covered by the same source-product and domain neutrality checks.

`registry-evidence-client` is adopter tooling beside the runtime, like
`registry-evidencectl`. It requests assertions over the public HTTP contract and
links `registry-evidence-verifier` for every verification decision, so it
re-implements no part of evaluation, signing, or verification. It sits outside
the frozen Version 1 runtime contract, and its source is covered by the same
source-product and domain neutrality checks. `registry-evidence-client-node` is
a thin napi-rs binding over `registry-evidence-client` for Node.js callers, and
carries the same neutrality checks. `registry-evidence-client-py` is the same
binding pattern for Python callers, via PyO3, and carries the same neutrality
checks.

Selected `registry-platform-*` primitives may be reused only when their existing
contracts fit Evidence directly. The approved candidates are audit, crypto,
OIDC, HTTP security, testing, and the `registry-platform-sdjwt` serialization
primitive used solely by the SD-JWT VC response format. Shared-crate changes
are separate platform work and require the platform guidance and
affected-consumer gates.

Production behavior must stay source-product and assertion-case neutral:

- no DHIS2 or OpenCRVS module, dependency, feature, public configuration field,
  route, CLI option, public contract variant, or production branch;
- no adult, age, residence, licence, parentage, personal-name-part, national
  identifier, or jurisdiction-specific Rust domain type or operation;
- no broad candidate retrieval, scoring, fuzzy matching, normalization,
  transliteration, phonetics, or candidate selection; a reviewed derivation
  may perform an exact deterministic comparison between an independently
  authorized selector and complete facts from one uniquely resolved
  authoritative record;
- no future-profile stub, placeholder schema, module, feature, extension hook,
  or empty API.

The four acceptance definitions are coequal. Every phase preserves all four,
and completion means every Definition of Done row passes on one revision.

## Trust boundary

Governed configuration, Rhai scripts, schemas, codelists, and fixtures are one
trusted, immutable, startup-only bundle. A separate closed runtime file owns
only process-local listener, filesystem, audit-storage, secret-mount, signer
transport and pinned version, and TLS trust bindings and cannot override the
bundle or governed active public key. Rust owns authentication,
authorization, selector validation and minimization, credentials, fixed
networking, path/header authority, response projection, script capabilities
and limits, output validation, evidence construction, signing, and audit. Rhai
owns only bounded query/body preparation, extraction, and
requirement-specific derivation through the approved closed ABIs.

Before code that touches authentication, authorization, disclosure, audit,
configuration trust, signing, source credentials, or selectors, apply the
`enforcing-security-invariants` guidance. For every affected invariant, record:

- the threat;
- the Rust enforcement point;
- the focused negative test that pins it.

Principal derivation uses only the configured claim and denies if it is absent.
Caller values never create authority. Missing, extra, mistyped, oversized,
unauthorized, or wrong-origin selector values fail before credential
acquisition or source access. Access audit is durably accepted before source
access. Disclosure audit is durably accepted after signing and before release.
Signing and audit failures are fail-closed.

Never commit, log, snapshot, pass on a command line, or place in an error:
credentials, tokens, live responses, raw selector values, per-field hashes of
low-entropy selectors, source values, Supported Values, demo-subject
identifiers, or human login and two-factor details.

## Phase discipline and commands

Run commands from the monorepo root unless a command says otherwise. Commands
for a later phase are required interfaces to add in that phase and are not
claims that an unimplemented command currently exists.

Phase 0, approved documentation and contracts:

```sh
git diff --check -- products/evidence
git diff -- products/evidence
```

Phase 1 and every later package exit:

```sh
cargo fmt --check
cargo check --locked -p registry-evidence --all-targets
cargo test --locked -p registry-evidence
cargo clippy -p registry-evidence --all-targets -- -D warnings
```

Phase 2 source boundary, after the package gate:

```sh
cargo test --locked -p registry-evidence --test source_contracts
products/evidence/scripts/check-source-neutrality.sh
```

Phase 3 reruns the package and source-boundary gates and adds focused negative
tests for every authentication, authority, audit, signing, and privacy
invariant changed in that phase. A phase cannot exit with an unnamed or
unmapped security invariant.

Phase 4 generated public contracts, after the package gate:

```sh
products/evidence/scripts/check-contracts.sh
products/evidence/scripts/check-source-neutrality.sh
```

Phase 5 optional public-demo smoke tests run only after the deterministic
package and source-contract suite passes:

```sh
cargo test --locked -p registry-evidence
cargo test --locked -p registry-evidence --test live_sources dhis2 -- --ignored
cargo test --locked -p registry-evidence --test live_sources opencrvs -- --ignored
```

The live commands are read-only, local, non-gating, and must skip when approved
selectors or securely stored credentials are unavailable. Follow
`SOURCE-TESTING.md`; do not improvise credentials, selectors, or broader
queries.

Phase 6 final gate:

```sh
cargo fmt --check
cargo metadata --locked --format-version 1
cargo check --locked --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
products/evidence/scripts/check-contracts.sh
products/evidence/scripts/check-source-neutrality.sh
products/evidence/scripts/check-verifier-portability.sh
```

Use the repository Cargo wrapper if one is added. Otherwise, in Codex-managed
worktrees set `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`, and
`CARGO_PROFILE_TEST_DEBUG=0` for Cargo check, test, and Clippy commands, as
required by the root guidance.

## Completion review

Before claiming a phase complete, review the whole phase diff against its exit
gate, the security invariant matrix, all four acceptance definitions, the
source-product-neutrality boundary, and the non-goals in `CONCEPT.md` sections
4 and 15. Report commands run, results, skipped commands with exact reasons,
changed files, and remaining risks. Do not weaken a pinning test to make a gate
pass.
