# Platform guidance

This guide covers `registry-platform-*` crates and `products/platform`.
Platform owns shared primitives. Each consuming product owns its complete
authorization, configuration, disclosure, durable state, and audit-release
contract. Reuse a primitive when its semantics fit; do not move product policy
into the platform just to remove superficially similar code.

Platform also owns [the configuration conventions](CONFIG-CONVENTIONS.md),
the rules every product's configuration formats follow, and the shared reader
and gates that enforce them. A change to a rule changes its gate in the same
change.

Read the changed crate's README and public API, then identify actual consumers
through Cargo dependencies. Current versions, dependency ownership, and feature
gates come from the monorepo Cargo manifests and CI, not older standalone
release examples.

Preserve these shared boundaries:

- Configuration parsing and environment expansion report errors without
  exposing values. Products still validate their own complete closed model.
- Crypto and canonical JSON have single owners. Preserve exact algorithm,
  key-shape, identifier, and canonical-byte rules; do not add a second hashing
  or signing interpretation in a consumer.
- Outbound HTTP validates targets and resolved addresses, bounds reads and
  work, and applies the chosen redirect/proxy policy. Structured URL building
  prevents data from changing path or query authority. Explicit deployment
  policies determine the allowed network boundary.
- Secret-bearing types redact diagnostics and keep key custody and zeroization
  guarantees. Follow [secret-provider readiness](docs/secret-provider-readiness.md)
  for signer/secret integrations and [audit reference hashing](docs/audit-reference-hashing.md)
  for identifier correlation.
- Audit primitives provide minimized, fail-closed records with keyed
  references; products decide which operations require durable acceptance
  before source access or release. The local file carries no hash chain, so
  only shipping it to append-only storage proves completeness.
- SQLite is bounded and read-only. Shared OIDC helpers verify tokens but do
  not replace each product's principal, claim, scope, or authority rules.

## Audit writer

Review `registry-platform-audit`'s file writer against this contract:

- It creates a missing audit directory owner-only, except below a
  world-writable, non-sticky ancestor, where it refuses and says to create the
  directory owned by the service user, mode 0700. Every refusal names its fix.
- Sealed segments are `<path>.<sequence>`. `<path>.seq` records the next
  sequence at open and before each rotation, so numbering continues across
  restarts even after a shipper removed every sealed segment.
- A shipper may copy and remove sealed segments while the writer runs.
  Retention deletes the oldest expired ones and never the active file, a lock,
  or another stream's active file; a failed deletion is logged, not fatal.
- An entry is acknowledged only after the file is synced, and every open syncs
  the directory before its first acknowledgement.
- A torn final line is moved at open to the owner-only side file
  `<path>.torn`, synced before the active file is truncated to its last
  complete line; an existing side file holding other bytes is never
  overwritten. The log names the side file and byte count, never the bytes.
- A configured path ending in a companion suffix (`.lock`, `.seq`, `.seq.tmp`,
  `.torn`, `.<8 digits>`) is refused; `AuditSegments` is the one reading of
  that namespace for writer and inspection tooling alike.
- A delivery terminal whose commit cannot be read back is answered
  `WorkerInterrupted` with the `Unknown` disposition, never a guessed state.
- A review fix adds no configuration key or companion file unless the defect
  cannot be fixed without one.

Keep APIs small enough for products and adopters to compose directly, with
safe defaults and explicit exceptional policies. Test a changed primitive
through a realistic consumer so an invariant does not accidentally require
duplicated configuration, a new daemon, or a product-specific adapter.

Run focused `cargo test --locked -p <changed-crate>` and relevant consumer
tests that can expose a changed assumption. Add a negative test when changing
a trust boundary. Shared feature or dependency changes also require applicable
all-feature checks selected by `.github/workflows/ci.yml` and
`.github/scripts/ci_changes.py`; a selected PR matrix is not a claim that every
workspace package ran.

Use `products/platform/scripts/check-hygiene-alignment.sh` for shared
lint/format templates and `cargo deny check` for dependency or advisory policy
changes. Run `products/platform/scripts/check-config-conformance.py
--check-generated` after changing a shared runtime configuration block or a
runtime that reads `runtime.yaml` through `RuntimeConfigLoader`. Coverage and fuzz definitions live in CI and
[fuzz/README.md](fuzz/README.md). Run the affected gate locally when changing it
or when CI cannot supply the required proof; routine edits do not require a
new full-workspace assurance exercise.
