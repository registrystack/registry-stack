# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Documented the ordering and authority semantics of `fields[].concepts` in the
  Registry Manifest reference: the first entry is the generated property
  identifier rendered as SHACL `sh:path` and JSON Schema `x-concept-uri`, every
  entry is preserved in author order in catalog JSON, and an empty list falls
  back to a deterministic manifest URI. The reference also records what a
  concept reference does not do: it asserts no mapping between concepts, grants
  no access and triggers no safeguard, is not validated against the vocabulary
  it names, and is never resolved.
- Added `fixtures/semantic-concepts/aligned-person-concepts.metadata.yaml`, a
  non-normative example that binds one field to a PublicSchema term and to an EU
  SEMIC Core Person Vocabulary term without asserting equivalence, alongside a
  field with no concept and a field with one concept.

Generated output is unchanged. The tests added with this entry pin the existing
behavior.

## [0.26.1] - 2026-09-04

### Changed

- Registry Manifest has no user-visible format or rendering changes in this
  release.

## [0.26.0] - 2026-09-03

### Added

- Added optional canonical dataset IRIs and deliberate dataset release versions,
  plus first-class distributions linked to exactly one dataset and optionally
  to a serving data service, access URL, download URL, media type, format,
  title, description, and canonical IRI.
- DCAT output now renders declared `dcat:Distribution` resources,
  `dcat:distribution`, `dcat:accessService`, access and download URLs, media
  type, format, and `dcat:version` relationships.

### Compatibility

- Existing manifests that omit the new fields keep their exact typed canonical
  bytes and `source_manifest_digest`. An absent or empty top-level
  `distributions` collection is omitted before canonicalization.

### Changed

- BREAKING: every authored `data_services[]` entry must now list at least one
  existing dataset in `serves_datasets`. Add the datasets exposed by each
  service before validating or republishing an older manifest whose data
  service omitted this relationship.

## [0.25.0] - 2026-08-22

- No user-visible Registry Manifest format changes.

## [0.24.0] - 2026-08-21

- No user-visible Registry Manifest format changes.

## [0.23.0] - 2026-08-20

- No user-visible Registry Manifest format changes.

## [0.22.0] - 2026-08-14

- No user-visible Registry Manifest format changes.

## [0.21.0] - 2026-08-13

- No user-visible Registry Manifest format changes.

## [0.20.1] - 2026-08-12

- No user-visible Registry Manifest format changes.

## [0.20.0] - 2026-08-12

- BREAKING: `registry-manifest/v1` no longer reserves the `registry_relay`
  vocabulary prefix or expands it to the retired Registry Relay V1 namespace.
  Replace those compact identifiers with absolute IRIs, or declare
  `vocabularies.registry_relay` with an institution-owned active HTTP(S)
  namespace, then validate and republish the rendered metadata.

## [0.19.0] - 2026-08-11

- No user-visible Registry Manifest format changes.

## [0.18.0] - 2026-08-09

- No user-visible Registry Manifest changes.

## [0.17.0] - 2026-08-07

- BREAKING: `registry-manifest/v1` no longer accepts the top-level
  `federation` block after Registry Notary's retirement. Remove that block
  before validating with v0.17.0 or later. `access.kind` is now an open
  vocabulary, and the retired `registry-notary` kind no longer receives
  product-specific validation.

## [0.16.3] - 2026-08-01

- No user-visible Registry Manifest changes. The v0.16.2 workflow stopped at
  an unpublished draft before public image promotion. Install v0.16.3.

## [0.16.2] - 2026-08-01

- No user-visible Registry Manifest changes. This release fixes forward from
  the v0.16.1 tag workflow, which stopped after creating an unpublished empty
  draft. Install v0.16.2; no final v0.16.1 images, assets, or documentation
  were published.

## [0.16.1] - 2026-08-01

- No user-visible Registry Manifest changes. This release fixes forward from
  the v0.16.0 tag workflow, which failed before any job or public write.
  Install v0.16.1; no final v0.16.0 images, assets, or documentation were
  published.

## [0.16.0] - 2026-08-01

- No user-visible Registry Manifest changes.

## [0.15.2] - 2026-07-28

- No user-visible Registry Manifest changes. This release fixes forward from
  the incomplete v0.15.1 publication.

## [0.15.1] - 2026-07-28

- No user-visible Registry Manifest changes. This release fixes forward from
  the failed v0.15.0 publication workflow.

## [0.15.0] - 2026-07-28

- No user-visible Registry Manifest changes.

## [0.13.0] - 2026-07-25

- No user-visible Registry Manifest changes.

## [0.12.2] - 2026-07-20

- No user-visible Registry Manifest changes. This release fixes forward from
  the incomplete v0.12.1 publication.

## [0.12.1] - 2026-07-20

- No user-visible Registry Manifest changes. This release fixes forward from
  the incomplete v0.12.0 publication.

## [0.12.0] - 2026-07-19

- No user-visible Registry Manifest changes.

## [0.11.0] - 2026-07-18

- No user-visible Registry Manifest changes.

## [0.10.0] - 2026-07-17

### Changed

- BREAKING: source-manifest and policy digests now use the shared RFC 8785
  canonical JSON implementation. Object names are ordered by UTF-16 code units
  and numbers use ECMAScript finite binary64 serialization; integer values that
  cannot be represented exactly are rejected. Digests can therefore change for
  manifests containing numeric values or non-ASCII object names even when the
  semantic manifest is unchanged.

### Release Notes

- Regenerate and republish rendered metadata and every digest-bound artifact
  with the v0.10.0 toolchain. Do not carry a v0.9.0 manifest or policy digest
  into a v0.10.0 project. Encode exact identifiers outside the safe binary64
  integer range as strings.
- Registry Manifest remains unpublished on crates.io. Consumers of the v0.10.0
  stack must pin the v0.10.0 Registry Stack source ref.

## [0.9.0] - 2026-07-10

### Added

- Added standalone fuzz workspaces for metadata-manifest YAML and rendered
  artifact JSON, with seed corpora and nightly smoke execution.

### Changed

- BREAKING: metadata manifests now reject unknown keys at every supported
  object boundary. Extensions must use the documented extension points instead
  of relying on silently ignored fields.
- A present but unsupported core `schema_version` now fails validation rather
  than being accepted as though it were the current schema.

### Fixed

- Exposed the Manifest CLI implementation through its library entry point so
  the CLI binary and fuzz targets exercise the same parsing and validation
  path.

### Release Notes

- Registry Manifest remains unpublished on crates.io. Consumers of the v0.9.0
  stack must pin the v0.9.0 source ref and migrate any ad hoc unknown keys to
  documented extension fields before validation.

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
