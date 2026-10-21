# Release Notes

## Unreleased

## 0.43.0

- BREAKING: metadata display fields, profile names and descriptions, and
  unsupported-mapping explanations reject prohibited display controls and
  Unicode noncharacters. Supported multilingual shaping and direction marks
  remain valid. Remove the prohibited character from the reported field.
- BREAKING: checked definition namespaces reject identifiers differing only
  by `-` versus `_`. Rename one definition and update its references.
  Equivalent peer labels produce warnings, or refusals with `--deny-warnings`.
  Run metadata and profile validation before upgrading. See
  [the shared upgrade notes](../../../release/notes/v0.43.0.md#authored-text-and-identifier-checks).

## 0.42.0

- Registry Manifest has no user-visible changes in this release.

## 0.41.0

- Registry Manifest has no user-visible changes in this release.

## 0.40.0

- BREAKING: Registry Manifest reads metadata manifests and profile descriptors
  through the shared configuration reader. Refusals report every finding by
  diagnostic code, JSON Pointer, line, and column, without repeating configured
  values. Update automation to match diagnostic codes instead of message text.
- BREAKING: `validate`, `validate-profiles`, `render`, and `publish` distinguish
  refused input (exit 1), usage errors (exit 2), and unreadable input (exit 3).
  Update scripts that treated every failure as exit 1. The two validation
  commands accept `--format json` and `--deny-warnings`.
- BREAKING: explicit `null`, `${...}`, unknown profile keys, invalid profile
  members, and fixture paths that escape the profile directory are refused.
  Remove null and unknown members, supply required profile fields, write
  literal values, and keep fixtures inside their profile directory.
- BREAKING: repeated relationship names and repeated entity `identifiers`
  items are refused with `config.duplicate-id`. Rename or remove the repeated
  item. Other duplicate identifiers also use `config.duplicate-id`; update
  callers that matched `manifest.metadata.duplicate-value` for them.
- BREAKING: authored multi-word values use kebab-case without aliases. Rewrite
  the ten multi-word `required_gates` values, `minimized-json`, `non-public`,
  `as-needed`, `under-development`, and the fulfillment modes using the complete
  old-to-new table in
  [the Manifest migration notes](../../../release/notes/config-conventions/manifest.md).
- BREAKING: the Rust library removes `render_entity_shacl`, whose only
  maintained consumer was Registry Relay. Use `render_shacl` over the whole
  manifest instead.
- Metadata and profile envelopes remain `registry-manifest/v1` and
  `registry-manifest-profile/v1`. Their file bound grows from 64 KiB to 1 MiB.
  Generated reader schemas and editor mappings are available, and
  `validate-profiles` warns about YAML files no descriptor or fixture lists.

The [complete Manifest migration notes](../../../release/notes/config-conventions/manifest.md)
include every configuration change, exact replacement value, and diagnostic
code mapping. The [product changelog](../CHANGELOG.md) also records Rust API
changes.

## 0.39.0

- `registry-manifest --version` prints the build version. Registry Manifest
  has no other user-visible change in this release.

## 0.38.0

- Registry Manifest has no user-visible changes in this release.

## 0.37.0

- Registry Manifest has no user-visible changes in this release.

## 0.36.0

- Registry Manifest has no user-visible changes in this release.

## 0.35.0

- Registry Manifest has no user-visible changes in this release.

## 0.34.0

- Registry Manifest has no user-visible changes in this release.

## 0.33.0

- Registry Manifest has no user-visible changes in this release.

## 0.32.0

- Registry Manifest has no user-visible changes in this release.

## 0.31.0

- Registry Manifest has no user-visible changes in this release.

## 0.30.0

- Registry Manifest has no user-visible changes in this release.

## 0.29.0

- Registry Manifest has no user-visible changes in this release.

## 0.28.0

- A field may no longer list one semantic concept twice. Two entries name one
  term when they expand to the same IRI, or when they differ only in the
  case-insensitive parts of that IRI, its scheme and host. Path, query, and
  fragment case still separates two terms. Remove the repeated entry before
  validating or republishing. Rendered output still publishes the spelling the
  manifest was authored with, so a manifest that still validates keeps its
  `source_manifest_digest`.

## 0.27.0

- Documented the order and authority of `fields[].concepts`: the first entry
  supplies the generated property identifier, while the catalog preserves
  every entry in author order. An empty list uses a deterministic manifest URI.
- Added a semantic-concepts example without asserting equivalence between the
  referenced vocabularies. Generated output is unchanged.

## 0.26.1

- Registry Manifest has no user-visible format or rendering changes in this
  release.

## 0.26.0

- BREAKING: every `data_services[]` entry must list at least one existing
  dataset in `serves_datasets`. Add the datasets exposed by each service before
  validating or republishing an older manifest that omitted this relationship.
- Datasets may declare a canonical IRI and a deliberate release version.
  Manifests may also declare first-class distributions linked to exactly one
  dataset and, optionally, to a serving data service or HTTP(S) access or
  download URL.
- DCAT output renders declared distributions, access services, media types,
  formats, and dataset versions. A distribution that names an access service
  must belong to a dataset that service lists in `serves_datasets`.
- Existing manifests that omit the additive dataset and distribution fields
  keep their exact typed canonical bytes and `source_manifest_digest`. An
  absent or empty `distributions` collection is canonically equivalent.

## 0.25.0

- Registry Manifest has no user-visible format changes in this release.

## 0.24.0

- Registry Manifest has no user-visible format changes in this release.

## 0.23.0

- Registry Manifest has no user-visible format changes in this release.

## 0.22.0

- Registry Manifest has no user-visible format changes in this release.

## 0.21.0

- Registry Manifest has no user-visible format changes in this release.

## 0.20.1

- Registry Manifest has no user-visible format changes in this release.

## 0.20.0

- BREAKING: `registry-manifest/v1` no longer reserves or expands the
  `registry_relay` vocabulary prefix. Replace affected compact identifiers
  with absolute IRIs, or declare `vocabularies.registry_relay` with an
  institution-owned active HTTP(S) namespace, then validate and republish the
  rendered metadata.

## 0.19.0

- Registry Manifest has no user-visible format changes in this release.

## 0.18.0

- Registry Manifest has no user-visible changes in this release.

## 0.17.0

- BREAKING: `registry-manifest/v1` no longer accepts the top-level
  `federation` block after Registry Notary's retirement. Remove the block
  before validation. `access.kind` is now open, and the retired
  `registry-notary` kind no longer receives product-specific validation.

## 0.16.3

- Registry Manifest has no user-visible changes relative to v0.16.2. That
  workflow stopped at an unpublished draft before public image promotion, so
  install only v0.16.3.

## 0.16.2

- Registry Manifest has no user-visible changes relative to the v0.16.0 and
  v0.16.1 candidates. The immutable v0.16.1 tag workflow stopped after
  creating an unpublished empty draft, so install only v0.16.2. No final
  v0.16.1 images, assets, or documentation were published.

## 0.16.1

- Registry Manifest has no user-visible changes relative to the v0.16.0
  candidate. The immutable v0.16.0 tag workflow failed before any job or public
  write, so install only v0.16.1. No final v0.16.0 images, assets, or
  documentation were published.

## 0.16.0

- Registry Manifest has no user-visible changes in this release.

## 0.15.2

- Registry Manifest has no user-visible changes. This release fixes forward
  from the incomplete v0.15.1 publication.

## 0.15.1

- Registry Manifest has no user-visible changes. This release fixes forward
  from the failed v0.15.0 publication workflow.

## 0.15.0

- Registry Manifest has no user-visible changes in this release.

## 0.13.0

- Registry Manifest has no user-visible changes in this release.

## 0.12.2

- No user-visible Registry Manifest changes. This release fixes forward from
  the incomplete v0.12.1 publication.

## 0.12.1

- No user-visible Registry Manifest changes. This release fixes forward from
  the incomplete v0.12.0 publication.

## 0.12.0

- No user-visible Registry Manifest changes.

## 0.11.0

- Registry Manifest has no user-visible changes in this release.

## 0.10.0

- BREAKING: source-manifest and policy digests now use Registry Stack's shared
  RFC 8785 canonical JSON implementation. UTF-16 object-name ordering and
  ECMAScript binary64 number serialization can change digests for manifests
  containing numeric values or non-ASCII object names. Integers that are not
  exactly representable as binary64 are rejected instead of rounded.
- Regenerate and republish rendered metadata and all digest-bound artifacts
  with the v0.10.0 CLI. Do not copy a v0.9.0 digest into a v0.10.0 project.
  Represent exact identifiers outside the binary64 integer contract as
  strings.
- Workspace crates remain unpublished; pin the v0.10.0 Registry Stack source
  ref.

## 0.9.0

- BREAKING: metadata manifests reject unknown keys throughout the supported
  format. Move non-standard data into documented extension points before
  validation.
- Present but unsupported core `schema_version` values now fail validation.
- Added metadata-YAML and rendered-artifact fuzz targets with nightly smoke
  coverage.
- The CLI binary and fuzz targets now share the same library parsing and
  validation implementation.
- Workspace crates remain unpublished; pin the v0.9.0 RegistryStack source ref.

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
