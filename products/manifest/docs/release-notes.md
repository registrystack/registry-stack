# Release Notes

## 0.2.1

- Added governed Evidence Gateway metadata validation, including evidence-pack
  binding metadata, policy metadata, shared ODRL/PDP terms, and optional
  evidence-offering `attestation_id`.
- Hardened ITB SEMIC smoke validation for standards profile checks.
- Updated documentation for the beta-3 manifest surface with release-pinned
  owner-source links.
- Kept the workspace crates unpublished; beta-3 consumers pin the exact source
  SHA rather than a crates.io artifact.

## 0.2.0

- Added manifest format markers (`manifest_format` and
  `manifest_format_version`) to make validated manifests identify their format
  contract.
- Rejected unknown runtime-only manifest keys at parse time without requiring
  `deny_unknown_fields`.
- Added federation JWKS URI metadata, metadata package digests, federated
  evaluation manifest schema support, CPSV-AP manifest contracts, and API
  catalog discovery publication.
- Added a contract-kernel check script for CI and documented the manifest
  extension policy.
- Kept manifest format markers out of standards-body profile documents.
- Resolved manifest paths before checkout in the publish flow to avoid path
  confusion.
- Propagated the Registry Notary rename through manifest field names and
  documentation.
- Changed `publish` output scoping so discovery files are written under `--out`
  by default, with `--site-root` available for split site roots.
- Hardened validation and publishing with stricter field validation and tighter
  type constraints.
- Fixed filtered metadata codelist pruning, profile marker injection, JWKS URI
  documentation, CLI examples, and witness-validation CI.

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
