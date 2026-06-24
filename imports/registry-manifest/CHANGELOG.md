# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-06-21

### Added

- Governed Evidence Gateway metadata validation, including evidence-pack binding
  metadata, policy metadata, shared ODRL/PDP terms, and optional
  evidence-offering `attestation_id`.
- ITB SEMIC smoke validation hardening for standards profile checks.

### Changed

- Documentation now reflects the beta-3 manifest surface and uses release-pinned
  owner-source links.

### Release Notes

- The workspace crates remain `publish = false`; beta-3 consumers pin the exact
  source SHA rather than a crates.io artifact.

## [0.2.0] - 2026-06-12

### Added

- **Manifest format version markers** (`manifest_format` and `manifest_format_version` fields) written into validated manifests, making the format contract machine-readable (PR #14, issue #12).
- **Runtime-only key rejection**: unknown keys in manifests are now rejected at parse time without requiring `deny_unknown_fields` in serde; keys that would only be meaningful at runtime are flagged explicitly (PR #18, issue #16).
- **Federation JWKS URI** field permitted in metadata manifests, enabling cross-registry identity federation (commit `2d3b605`).
- **Metadata package digests** recorded in validated output manifests (commit `d2fe36a`).
- **Federated evaluation manifest schema** (commit `450b7e3`).
- **CPSV-AP manifest contract** for CPSV-AP service catalog interoperability (commit `3b33657`).
- **API catalog discovery** published via `publish` subcommand (commit `9be4f82`).
- **Contract kernel check** script (`scripts/check-contract-kernel.sh`) for CI gate use (PR #5).
- **Manifest extension policy** documented in `docs/reference.md`; rules for permitted vs. prohibited manifest extensions codified (PR #18, issue #16).

### Changed

- **Manifest markers kept out of standards profiles**: format version markers are injected only into the registry manifest output, never into standards-body profile documents (PR #14, issue #12).
- **Manifest paths resolved before repo checkout** in the publish flow to prevent path confusion on clone (PR #5, commit `29c019b`).
- **Registry Notary rename propagated** throughout manifest field names and documentation (PR #3).
- **CLI `publish` now scopes output to `--out` by default**; `--site-root` added for multi-tenant deployments (commit `8c8e45b`).
- **Hardened manifest validation and publishing**: stricter field validation, tighter type constraints, and additional security-audit-driven checks introduced across core and CLI (PR #4).
- **OGC Records helpers narrowed**: previously public but unused helpers in the core crate are now crate-private (commit `a998689`).
- **`serde_yml` replaced by `serde_yaml_ng`** to track the maintained fork (commit `7dc0b90`).

### Fixed

- **Filtered metadata codelists pruned correctly**: codelists excluded by a filter profile were still appearing in rendered output; they are now removed (PR #10, commit `a893511`).
- **Standards profile documents no longer receive manifest markers** injected during the validation pass (PR #14, issue #12).
- **JWKS URI documentation corrected** in `docs/reference.md` (PR #14, issue #13).
- **CLI reference and validate/render examples corrected** in documentation (commit `a2e648a`, issue #9).
- **Registry witness validation and audit CI** repaired after the 0.1.2 audit batch (PR #2, commit `016489e`).

## [0.1.2]

See release tag `v0.1.2`.
