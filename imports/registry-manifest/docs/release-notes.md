# Release Notes

## 0.1.2

- `publish` now writes `.well-known/api-catalog` and `.well-known/registry-manifest.json` inside `--out` by default. Pass `--site-root <dir>` to write discovery files under a separate site root when the metadata bundle is a sibling of the site root.
- Migrated YAML parsing from the unmaintained `serde_yml` / `libyml` to `serde_yaml_ng`.
- Replaced four `.expect(...)` calls in the publish path with explicit error returns.
- Raised CLI integration-test coverage above 80% (publish error paths, render flag and lookup errors, validate-profiles descriptor and fixture diagnostics).
- Downgraded three OGC Records collection renderer helpers to crate-private until Registry Relay or another consumer wires them up.
- Added `rust-toolchain.toml`, `clippy.toml`, `deny.toml`, workspace-level `[workspace.dependencies]` deduplication, crate keywords/categories, and SECURITY.md dependency-advisory posture.
- CI now runs `cargo audit`, `cargo deny check`, `cargo llvm-cov` (≥ 80%), and `gitleaks` on every push.

## 0.1.1

- Added CPSV-AP renderer, federated evaluation manifest schema, and API catalog discovery publication.

## 0.1.0

- Cut Registry Manifest into an independent Cargo workspace with `registry-manifest-core` and `registry-manifest-cli`.
- Added portable metadata validation, renderer tests, CLI tests, profile fixture validation, and static publication commands.
- Added repository bootstrap files: Apache-2.0 license, security policy, CODEOWNERS, Dependabot, and GitHub Actions CI.

Known non-goals for this cut:

- No Registry Relay HTTP route hosting, caller scoping, runtime binding validation, audit sinks, or authorization policy.
- No Evidence Server claim computation, disclosure policy, credential issuance, service runtime, or OpenAPI generation.
- No official OpenCRVS, OpenSPP, OpenIMIS, or SP DCI profile claims until profile examples are reviewed against official artifacts or maintainer feedback.
