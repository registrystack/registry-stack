# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `registryctl init --from`, `test`, `check`, and `build` provide a strict
  project-owned authoring workflow for bounded HTTP, DHIS2 Tracker, OpenCRVS,
  and fixture-backed OpenSPP integrations. The compiler produces deterministic,
  closed Relay and Notary Config Bundle v1 inputs, verifies them with the exact
  product startup compilers, and supports explicitly verified signed baselines
  for independent claim, integration, service-policy, and operator-security
  review classification.
- Advanced `script` authoring is available only through explicit
  operator-security enablement and the release-gated isolated worker. Ordinary
  starters remain declarative and do not depend on Rhai.
- Generated project inputs include exact signed-DCI, immutable snapshot, and
  multi-profile/multi-purpose journeys, plus deterministic operational and
  redacted secret-consumer descriptors for Relay and Notary. Snapshot physical
  mappings remain private and shared compatible profiles reuse one immutable
  materialization slot.
- Tagged `records_api` services compile strict logical records definitions and
  private environment entity bindings into Relay's existing governed records
  model. A Snapshot integration references the same logical entity, so one
  immutable local materialization serves records and evidence while retaining
  principal-bound filters, projection, cursor pagination, relationships,
  aggregates, metadata, and configured OGC or SP DCI adapters.
- Exact consultation selectors now accept one to four required, typed,
  canonical components across bounded HTTP, unified DCI exact predicates, and
  Snapshot. The compiler emits canonical exact-AND artifacts and validates
  full-date inputs, complete fixture and request mappings, and injective private
  physical bindings before source access. Authored input names use Relay's exact
  64-byte lower-snake wire grammar, values are bounded to 256 bytes, and regex
  patterns are bounded to 1024 bytes before generated product compilation.
- Bounded HTTP credential interfaces now include reviewed API-key header and
  query modes. Names remain fixed public integration configuration, values
  remain environment-only secret references, query credentials require an
  operator-security review, and sensitive header names or query collisions are
  rejected.
- The fixture-backed `fhir-r4-coverage-active` golden journey replaces the
  retained sidecar path with two fixed FHIR R4 searches, strict resource
  projection, composite Patient selection, bounded ambiguity handling, and
  malformed, wrong-resource, oversized, OperationOutcome, and pagination-link
  negative vectors.
- OpenCRVS and DHIS2 golden workspaces now expose the approved age-band claims
  derived from explicit caller-supplied full dates while preserving the listed
  direct outputs, predicates, disclosure modes, and credential claim allow-lists.
- Project reports separate semantic digest changes from required review
  classes and identify safe actual fixture failure codes without disclosing
  fixture values.
- Offline project fixtures compile an internal authority-free product artifact
  closure and reuse Relay's closed decoders and typed normalization plus
  Notary's static authentication, pre-source policy gates, CEL worker, claim
  evaluation, and disclosure behavior. Exact OpenCRVS fixtures use public RSA
  JWKS material and precomputed RS256 DCI envelopes; they remain deterministic
  codec evidence rather than live interoperability evidence.

### Security

- Project authoring rejects unknown fields, symlinks, path traversal, secret
  values in authored environment bindings, caller-selected source requests,
  implicit live environments, and direct live registry access. Governed live
  tests contact only the configured Notary evaluation endpoint and refuse
  production environments.
- Governed live tests require complete Relay readiness, an exact expected
  claim result, and source-backed provenance. Private binding references are
  independently revalidated against their raw SHA-256 and typed artifact hash
  before generated Relay startup validation.
- Fixed request headers use a closed non-credential allow-list, named
  environment-backed secrets are complete in deployment descriptors, and
  implementation-only Rhai probes are unavailable from project fixture YAML.

### Fixed

- Signed product-bundle baseline review records now bind the exact verified baseline manifest,
  prior per-class review digests, and current per-class review digests or
  explicit nulls. Compiler-version changes require all review classes even
  when authored semantics also change.
- Disclosure-only changes are classified directionally: narrowing requires
  claim review, widening requires service-policy review, and incomparable
  changes require both.
- Sandboxed Rhai release enablement is keyed only by the implementation-owned
  authoring and worker contract. Source product and version remain review and
  provenance metadata and cannot select a capability or executor.
- Governed live validation resolves globally unique claims across every
  evidence service sharing the requested purpose instead of selecting the
  first service by map order.

## [0.9.0] - 2026-07-10

### Added

- Release distributions now include a strict, versioned registryctl image lock
  that binds the release source and exact Relay and Notary image digests. Project
  generation fails before mutation when the matching lock is missing or invalid.

### Changed

- **BREAKING: project files are now strictly validated.** `schema_version` is
  required and must be `registryctl/v1`; missing or unsupported versions and
  unknown project keys are rejected. When a Notary block is present,
  `notary.source` must be `registry_data_api`, `relay`,
  `fhir_source_adapter_sidecar`, or `opencrvs_dci`.
- The installer checksum-verifies and installs the registryctl binary and image
  lock together. Existing generated projects still start from their stored image
  pins without consulting the lock.

### Fixed

- Generated local Relay and Notary configs now declare `deployment.profile: local`,
  preserving fail-closed profile validation while allowing new projects to start.
- Aggregated doctor JSON now preserves each product report's optional
  `audit_shipping` section and validates it against
  `registryctl.validation.report.v1`.
- Generated project image pins now come from tag-built release evidence instead
  of digests compiled into registryctl, closing the stale-pin failure tracked in
  GH#278 without using mutable image tags or live registry lookup.

## [0.8.4] - 2026-07-04

### Added

- `registryctl init notary <dir> --source-kind fhir-sidecar` - scaffold a standalone Notary
  project pointing at an existing FHIR source-adapter sidecar, with a starter
  `patient-record-exists` claim and generated smoke request target.
- `registryctl restart` - stop and start the local Compose project in one command so
  edits to `relay/config.yaml` or `notary/config.yaml` take effect; a plain `start`
  leaves an already-running container unchanged.

### Changed

- Install script (`install.sh`) downloads the raw per-platform `registryctl` binary from
  the stack release, verifies it against the release `SHA256SUMS`, and falls back to a
  source-install hint on platforms without a published binary. The stack release publishes
  binaries for Linux x86_64, Linux arm64, and macOS arm64.
- BREAKING: Generated Relay and Notary projects no longer write
  `fingerprint.commitment` in YAML.
  Generated configs reference fingerprint env vars only; local raw keys and matching
  fingerprint values remain in `secrets/local.env`.
- The generated benefits sample now uses a richer three-sheet workbook
  (`Households`, `Persons`, `Applications`) and a broader Bruno collection covering
  discovery, row reads, relationship expansion, purpose-header failures, and aggregates.
- The generated Relay sample config now includes focused YAML comments that explain auth
  fingerprints, source tables, public entities, relationships, filters, and aggregates.
- `registryctl init relay <dir>` no longer generates a duplicate split `relay/metadata.yaml`
  manifest for the local sample; Relay derives standards metadata from `relay/config.yaml`
  unless a project explicitly opts into split metadata.

### Fixed

- The generated Relay sample no longer binds `person.id` to the API-key principal id,
  which made the Bruno "Read sample people" request return an empty result set.

## [0.1.0] - 2026-06-12

First tagged release of the `registryctl` CLI for Registry Commons.

### Added

- `registryctl init relay <dir>` - scaffold a local Relay-backed spreadsheet API project with a
  sample benefits workbook, Docker Compose file, project manifest, generated credentials, and a
  Bruno API collection.
- `registryctl init notary <dir>` - scaffold a standalone Notary project pointing at an existing
  Registry Data API source.
- `registryctl add notary --from local-relay` - add a Notary product to an existing Relay project.
- `registryctl start / stop / status / open / logs` - manage the local Compose project lifecycle
  and surface Relay and Notary API URLs.
- `registryctl smoke` - run built-in local smoke checks against the Relay API and write results to
  `output/smoke-results.json`.
- `registryctl notary smoke / open` - run smoke checks against the Notary API and open its docs.
- `registryctl openfn import` - import an OpenFn workflow URL or exported YAML into a Registry
  Notary OpenFn sidecar manifest, with topology validation, adaptor pin enforcement, per-item and
  native batch modes, and an optional Notary config snippet.
- `registryctl openfn convert` - convert a locally exported OpenFn project YAML into a sidecar
  manifest (lower-level variant of `import` without the OpenFn API fetch step).
- `registryctl bruno generate / open / run` - generate, open, and run the optional Bruno API
  collection for the local project.
- Digest-pinned container images for `registry-relay` and `registry-notary` to guarantee
  reproducible local environments.
- Credential generation using `ed25519-dalek` and `registry-platform-authcommon`; fingerprint
  commitments are verified at `start` and `smoke` time to catch accidental config drift.
- Install script (`install.sh`) for Linux x86_64, Linux aarch64, and macOS aarch64 without
  requiring a source checkout.

### Dependencies

- Pinned `registry-platform-authcommon` to the `v0.2.0` tag (was tracking `main`), ensuring a
  stable shared-library ABI for the release. (Closes issue #4, PR #15.)
