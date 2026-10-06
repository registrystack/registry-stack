# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- BREAKING: the multi-word values a metadata manifest authors are spelled in
  kebab-case (CFG-NAME-2): the ten multi-word `required_gates` words, the
  `allowed_outputs` word, `access_rights`, `update_frequency`, `status`, and
  the fulfillment modes. The old spelling is refused and the refusal names the
  new word. Migration: see `release/notes/config-conventions/manifest.md`.
- BREAKING: an entity that repeats a relationship `name`, or lists the same
  `identifiers` item twice, is refused with `config.duplicate-id` at the
  repetition. Both were accepted before: the later relationship shadowed the
  earlier one in the rendered IRIs. Migration: rename or remove the duplicate.
- BREAKING: `registry-manifest` reads a metadata manifest and a profile
  descriptor through the shared Registry Stack YAML reader, and reports every
  finding in the shared shape: `error[code] file:line:col /pointer`, the
  message, `next:` with the fix, and a summary line. It printed the first
  failure as one line. A finding names its member by JSON Pointer, line, and
  column, and never repeats a configured value. Migration: a script that
  matched the previous line should match the diagnostic code instead.
- BREAKING: the finding codes are renamed. A manifest refused by
  `registry_manifest_core::validate_manifest` reports one code per condition
  instead of `metadata.manifest.validation_failed`, from
  `manifest.metadata.duplicate-value`, `unknown-reference`, `missing-member`,
  `empty-value`, `invalid-id`, `invalid-url`, `invalid-iri`,
  `invalid-vocabulary-prefix`, `invalid-digest`, `policy-hash-mismatch`,
  `policy-not-canonicalizable`, `too-many-items`, `unsupported`, and
  `invalid-value`. A repeated id in `profiles`, `evaluation_profiles`,
  `requirements`, `evidence_types`, `authorities`, `public_services`,
  `data_services`, `distributions`, `forms`, `datasets`, or `codelists` is
  refused while the manifest is read, with `config.duplicate-id` at the
  copy's `id`. A repeated id the reader does not catch (an ecosystem binding's
  id and version, and the ids and names nested inside a dataset, form,
  requirement, or public service) answers `config.duplicate-id` too, at the
  copy's `id` or `name`; `duplicate-value` remains for every other repeated
  value. `registry_manifest_core::ValidationCondition::DuplicateId` is the new
  condition. Migration: a script that matched `manifest.metadata.duplicate-value`
  for a repeated id matches `config.duplicate-id`. The others:

  | Before | Now |
  |---|---|
  | `metadata.manifest.version_unsupported` | `manifest.metadata.unsupported-version` |
  | `metadata.profile.runtime_key_present`, or `metadata.manifest.parse_failed` naming runtime-only keys | `manifest.metadata.runtime-only-key` |
  | `metadata.manifest.parse_failed` naming secret-bearing keys | `manifest.metadata.secret-bearing-key` |
  | `metadata.manifest.file_not_found` | `manifest.metadata.missing-file` (exit 3) |
  | `metadata.manifest.parse_failed`, `metadata.profile.parse_failed`, `metadata.profile.fixture_parse_failed` | `yaml.syntax`, `config.unknown-key`, `yaml.duplicate-key`, or another reader code |
  | `metadata.manifest.too_large`, `metadata.profile.too_large` | `yaml.too-large` |
  | `metadata.manifest.aliases_unsupported`, `metadata.profile.aliases_unsupported` | `yaml.anchor`, `yaml.alias` |
  | `metadata.profile.version_unsupported` | `config.unknown-variant` at `/schema_version` |
  | `metadata.profile.id_missing` | `config.missing-key` or `config.invalid-value` at `/profile/id` |
  | `metadata.profile.version_missing` | `config.missing-key` or `manifest.profile.empty-value` at `/profile/version` |
  | `metadata.profile.supported_input_artifacts_missing`, `conformance_checks_missing`, `fixtures_missing` | `manifest.profile.empty-list` |
  | `metadata.profile.id_mismatch` | `manifest.profile.id-mismatch` |
  | `metadata.profile.descriptor_missing` | `manifest.profile.no-descriptors` |
  | `metadata.profile.directory_read_failed` | `manifest.profile.missing-directory`, `not-a-directory`, or `unreadable` (exit 3) |
  | `metadata.profile.fixture_missing` | `manifest.profile.missing-fixture`, or `manifest.profile.unreadable` (exit 3) |
  | `metadata.profile.file_not_found` | `manifest.profile.unreadable` (exit 3) |
  | `metadata.profile.claim_missing`, `required_concept_missing`, `identifier_missing`, `cardinality_mismatch`, `codelist_mismatch` | `manifest.profile.claim-missing`, `required-concept-missing`, `identifier-missing`, `cardinality-mismatch`, `codelist-mismatch` |

  `manifest.profile.fixture-path-escapes` and `manifest.profile.invalid-range`
  are new refusals of a fixture path outside the profile directory (written
  with `..` segments, or reached through a link that resolves outside it) and
  a cardinality whose minimum exceeds its maximum. Migration: match the codes
  in the right-hand column.
- BREAKING: exit codes follow the shared check contract. `validate` and
  `validate-profiles` exit 0 when nothing is refused, 1 when something is (or
  a warning is reported under `--deny-warnings`), 2 on a usage error, and 3
  when an input cannot be read; `render` and `publish` exit 1, 2, or 3 the
  same way. Every failure exited 1. Migration: treat exit 2 as a wrong
  command line and exit 3 as a missing or unreadable file.
- BREAKING: a manifest or descriptor refuses an explicit `null`
  (`config.null-value`) and `${...}` in text
  (`config.substitution-not-allowed`). Migration: delete a member written as
  `null`, and write text without `${`.
- BREAKING: a profile descriptor is read as a closed model, as a metadata
  manifest already was. It refuses a key it does not model
  (`config.unknown-key`), where it ignored one; it needs `schema_version`,
  `profile.id`, `profile.version`, `supported_input_artifacts`,
  `conformance_checks`, and `fixtures` (`config.missing-key`), where each
  defaulted to empty; `profile.id` is a local identifier, `upstream_url` a
  URL, each cardinality bound 0 or 1, a conformance check's `severity`
  `error` or `warning`, and a fixture's `expect` `valid`. Migration: delete
  `generator_command: null` from each `profile.yaml`, and correct each
  member a diagnostic names.
- A manifest or descriptor may hold up to 1 MiB; the bound was 64 KiB.
- `validate` and `validate-profiles` take `--format json`, which writes one
  `ManifestCtlReport` document on standard output
  (`products/manifest/examples/ctl-report/validate.json`), and
  `--deny-warnings`. `validate-profiles` warns with
  `manifest.profile.unlisted-file` about a YAML file under the profiles
  directory that is neither a descriptor nor a listed fixture.
- JSON Schemas for the metadata manifest and the profile descriptor are
  generated from the types the command line reads and published under
  `products/manifest/schemas`. `editors/configure.py manifest` maps them to
  the selected document and every `profile.yaml` below the project.
- BREAKING: `registry-manifest-core` no longer exports `render_entity_shacl`.
  Its only consumer was Registry Relay. Render the whole manifest with
  `render_shacl` instead.

## [0.39.0] - 2026-10-06

- `registry-manifest --version` prints the build version. Registry Manifest
  has no other user-visible change in this release.

## [0.38.0] - 2026-10-01

- Registry Manifest has no user-visible changes in this release.

## [0.37.0] - 2026-09-29

- Registry Manifest has no user-visible changes in this release.

## [0.36.0] - 2026-09-29

- Registry Manifest has no user-visible changes in this release.

## [0.35.0] - 2026-09-28

- Registry Manifest has no user-visible changes in this release.

## [0.34.0] - 2026-09-25

- Registry Manifest has no user-visible changes in this release.

## [0.33.0] - 2026-09-22

- Registry Manifest has no user-visible changes in this release.

## [0.32.0] - 2026-09-15

- Registry Manifest has no user-visible changes in this release.

## [0.31.0] - 2026-09-13

- Registry Manifest has no user-visible changes in this release.

## [0.30.0] - 2026-09-12

- Registry Manifest has no user-visible changes in this release.

## [0.29.0] - 2026-09-10

- Registry Manifest has no user-visible changes in this release.

## [0.28.0] - 2026-09-09

### Changed

- `datasets[].entities[].fields[].concepts` now refuses a term listed twice.
  Entries are compared after prefix expansion, so a CURIE and the absolute IRI
  it expands to are one entry, as are two prefixes bound to one namespace. Per
  RFC 3987 the comparison also folds the scheme and host, so two spellings that
  differ only there name one term, while path, query, and fragment case still
  separates two terms. The diagnostic names the expanded IRI and the position of
  the first occurrence.

### Compatibility

- Concept comparison folds case inside the comparison key only. Renderers
  publish the spelling the manifest was authored with, so a manifest that still
  validates keeps its exact typed canonical bytes and `source_manifest_digest`.
  A manifest that named one concept twice on a field now fails validation;
  remove the repeated entry before validating or republishing.

## [0.27.0] - 2026-09-07

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
