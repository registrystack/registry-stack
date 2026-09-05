# Platform guidance

This guide covers `registry-platform-*` crates and `products/platform`.
Platform owns shared primitives. Each consuming product owns its complete
authorization, configuration, disclosure, durable state, and audit-release
contract. Reuse a primitive when its semantics fit; do not move product policy
into the platform just to remove superficially similar code.

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
- Audit primitives provide integrity and minimized records; products decide
  which operations require durable acceptance before source access or release.
  Local chain consistency alone does not prove complete remote retention.
- SQLite is bounded and read-only. Shared OIDC helpers verify tokens but do
  not replace each product's principal, claim, scope, or authority rules.

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
changes. Coverage and fuzz definitions live in CI and
[fuzz/README.md](fuzz/README.md). Run the affected gate locally when changing it
or when CI cannot supply the required proof; routine edits do not require a
new full-workspace assurance exercise.
