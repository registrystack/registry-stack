# Manifest guidance

This guide covers `registry-manifest-core`, `registry-manifest-cli`, and
`products/manifest`.

Manifest owns the portable metadata model, validation, compilation, prefix
expansion, and standards-facing renderers. `registry-manifest-core` remains
independent of service runtimes, row access, authentication, audit, secrets,
HTTP serving, and CLI frameworks. The CLI owns file handling and static
publication. Relay and BReg own caller authorization and safe publication
projections; Manifest metadata grants no runtime access.

Use the [core README](../../crates/registry-manifest-core/README.md),
[reference](docs/reference.md), and affected compiler/renderer tests for model
changes; use the [CLI README](../../crates/registry-manifest-cli/README.md)
for commands and publication. Profile descriptors under `profiles/` are
non-normative examples until their stated source review is complete. Do not
turn a fixture into a claim of external conformance or hardcode its domain.

A metadata change may affect source types, validation, compilation,
cross-references, relevant renderers, CLI fixtures, and consuming product
projections. Update affected surfaces and verify their agreement.
Preserve deterministic bytes and digest meanings; artifact hashes describe
integrity, not issuer trust. Keep vocabulary expansion and standards rendering
in their existing owner rather than reproducing them in product crates.
Prefer portable metadata that existing institutional tools can consume without
running another Registry Stack service.

Run focused checks from the monorepo root:

```sh
cargo test --locked -p registry-manifest-core
cargo test --locked -p registry-manifest-cli
cargo run --locked -p registry-manifest-cli -- validate-profiles products/manifest/profiles
```

Renderer changes need representative golden-output coverage. Shared model
changes also need affected Relay or BReg publication checks. The broader
`products/manifest/scripts/check-contract-kernel.sh` runs a workspace suite;
use it when that breadth is justified. External ITB/SEMIC validation is opt-in
under [its documented claim boundary](docs/itb-semic-validation.md).
