# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed

- Smoke reports now carry the `registryctl.smoke.v1` schema version and are
  validated against a committed JSON Schema.

### Removed

- Removed the hidden `registryctl init spreadsheet-api` compatibility alias.
  Use `registryctl init relay` for the local spreadsheet tutorial or
  `registryctl init --from` for Registry Stack project authoring.

## [0.12.0] - 2026-07-19

### Changed

- Interactive report commands now print concise human-readable results by
  default. This covers project initialization, Notary add-on setup, offline
  tests, checks, editor setup, builds, doctor validation, Config Bundle
  operations, and trust-anchor operations. Add `--format json` for versioned
  machine-readable reports. Artifact and protocol streams keep their existing
  formats.
- The DHIS2 Tracker starter now keeps Relay normalization, reusable child-health
  evidence claims, and consuming programme actions separate. Its offline
  fixtures preserve positive, negative, unknown, no-match, and source-failure
  semantics. Snapshot and custom-system goldens now model reusable evidence
  instead of computing programme eligibility in Registry Notary.
- Registryctl now uses the workspace-pinned `serde_norway` YAML parser and
  serializer, consistent with the supported configuration boundary used by
  Relay and Notary.

### Fixed

- `registryctl init` now stages starter editor setup before publication and
  rejects non-UTF-8 JSON destinations before invoking an initializer, avoiding
  partial projects on either failure path.

## [0.11.0] - 2026-07-18

### Added

- `registryctl check` now returns a bounded typed authoring diagnostic
  list for invalid projects. Human and JSON output use the same stable codes,
  project-relative files, safe locations, schema hints, causes, suggestions,
  and remediation. Independent files are checked in deterministic order. Safe
  missing declared references aggregate, while unsafe paths, symlinks,
  oversized files, and inspection failures remain terminal.
- Project consultation inputs now accept the stable
  `request.target.attributes.<stable-name>` authoring mapping for bounded
  string, boolean, and integer integration inputs. The committed project JSON
  Schema and maintained DHIS2 offline journey cover the same closed grammar.
  Target attributes are caller-supplied request context, not authenticated
  identifiers.
- `registryctl init --from` now installs deterministic project-local JSON Schemas and VS Code and
  Zed workspace mappings. `registryctl authoring editor` verifies or safely refreshes the same
  version-matched setup for an existing project.
- `registryctl authoring language-server` now provides bounded cross-file definitions, references,
  symbols, and reference diagnostics for Registry Stack project YAML. Optional, source-installable
  developer previews for VS Code and Zed launch the same server alongside their existing YAML
  language servers. They are not marketplace extensions or release artifacts; generated editor
  schema setup remains the stable beta path for YAML validation, completion, hover, and formatting.
- `registryctl add notary` extends the generated local benefits project with
  an editable, registry-backed Notary evaluation tutorial and a private
  compiler-pinned Relay consultation. This local journey evaluates claim
  results only; it does not issue a credential or prove wallet or OID4VCI
  interoperability.
- `registryctl init --from` continues to expose exactly five public starters:
  HTTP, DHIS2 Tracker, OpenCRVS DCI, FHIR R4, and exact snapshot. A committed
  catalog now drives documentation and tests for additional maintained and
  conformance workspaces without turning them into public starters.

### Removed

- BREAKING: project authoring no longer accepts credential profiles or OID4VCI
  configurations that select source-free claims. Credential capability now
  requires registry-backed claim evidence from an exact compiler-pinned Relay
  consultation; source-free claims remain available only for evaluation when
  no credential profile selects them.

## [0.10.0] - 2026-07-17

### Added

- `registryctl init --from`, `test`, `check`, and `build` provide a strict
  Registry Stack project authoring workflow for product-neutral `http`,
  `script`, and `snapshot` integrations. Maintained HTTP, DHIS2 Tracker,
  OpenCRVS DCI, FHIR R4, and snapshot starters exercise the same contract. The
  compiler produces deterministic,
  closed Relay and Notary Config Bundle v1 inputs, verifies them with the exact
  product startup compilers, and supports explicitly verified signed baselines
  for independent claim, integration, service-policy, and operator-security
  review classification.
- Environment authoring can set the existing bounded Notary CEL worker memory
  ceiling, and changes to that operator-controlled limit require an
  operator-security review.
- Notary-to-Relay authoring separates the Relay's public catalog origin from
  the deployment-internal connection URL, so colocated production pairs can
  use an explicit loopback path without publishing that path to integrators.
- `script` authoring uses the release-gated isolated Rhai worker, fixed source
  authority, bounded host calls, and a hash-covered static local module
  closure. Script availability never depends on source product or version and
  does not require an unreleased environment feature switch.
- Generated project inputs include exact signed-DCI, immutable snapshot, and
  multi-profile/multi-purpose journeys, plus deterministic operational and
  redacted secret-consumer descriptors for Relay and Notary. Snapshot physical
  mappings remain private and shared compatible profiles reuse one immutable
  materialization slot.
- Tagged `records_api` services compile strict logical entity definitions and
  private environment entity bindings into Relay's existing governed records
  model. A `snapshot` integration references the same logical entity, so one
  immutable local materialization serves records and evidence while retaining
  principal-bound filters, projection, cursor pagination, relationships,
  aggregates, metadata, and configured OGC or SP DCI adapters.
- Records services can author bounded, entity-owned attribute-release profiles.
  The compiler fixes subject cardinality to exactly one, permits claims and CEL
  only over explicitly projected fields, keeps source metadata disabled, binds
  each profile to one permitted purpose and distinct entity release scope, and
  limits private response caching to one hour.
- Consultations accept one to eight required selector inputs and up to sixteen
  typed inputs in total across HTTP, script, signed DCI, and snapshot. The
  compiler enforces the scalar JSON Schema subset, a 4096-byte canonical
  selector aggregate, complete fixture and request mappings, and injective
  private physical bindings before source access. Authored input names use
  Relay's exact 64-byte lower-snake wire grammar.
- Bounded HTTP credential interfaces now include reviewed API-key header and
  query modes. Names remain fixed public integration configuration, values
  remain environment-only secret references, query credentials require an
  operator-security review, and sensitive header names or query collisions are
  rejected.
- The fixture-backed `fhir-r4-coverage-active` journey replaces the retained
  sidecar path with bounded script-selected FHIR R4 reads, the reusable
  `protocol.fhir.parse_searchset` helper, same-origin pagination, minimized
  projection, and composite Patient selection.
- OpenCRVS and DHIS2 golden workspaces now expose the approved age-band claims
  derived from explicit caller-supplied full dates while preserving the listed
  direct outputs, predicates, disclosure modes, and credential claim allow-lists.
- Project reports separate semantic digest changes from required review
  classes and identify safe actual fixture failure codes without disclosing
  fixture values.
- Offline project fixtures bind ordered canonical request interactions to
  synthetic responses, compile an internal authority-free product artifact
  closure, and reuse Relay's closed decoders and typed normalization plus
  Notary's static authentication, pre-source policy gates, CEL worker, claim
  evaluation, and disclosure behavior. Exact OpenCRVS fixtures use public RSA
  JWKS material and precomputed RS256 DCI envelopes; they remain deterministic
  codec evidence rather than live interoperability evidence. Platform-generic
  malformed, boundedness, timeout, authorization-before-source, and
  minimization negatives are derived instead of copied into every project.

### Changed

- BREAKING: adopters must reauthor generated deployments around the strict
  `registry-stack.yaml` project contract and regenerate Relay and Notary
  product inputs with `init --from`, `test`, `check`, and `build`. v0.9.0
  generated source and product configuration is not upgraded in place. Install
  registryctl v0.10.0 together with its matching image lock before rebuilding
  and reviewing the generated closure.
- Notary state authoring emits one typed PostgreSQL backend, a secret-consumer
  reference, and only explicit deployment choices. Runtime pool and timeout
  defaults are no longer copied into generated implementer configuration.

### Removed

- BREAKING: removed the direct-source commands `registryctl init notary`,
  `registryctl add notary`, `registryctl notary smoke`,
  `registryctl notary open`, `registryctl openfn import`, and
  `registryctl openfn convert`. There are no compatibility aliases. Reauthor
  supported source integration through the product-neutral `http`, `script`,
  or `snapshot` contract and use governed `test --live` only through the
  deployed Notary endpoint.

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

- Project review output now reports human-readable semantic changes while the
  separate private approval state binds the verified baseline and generated
  closure digests. It does not model external reviewer identities or approval
  records. A compiler-version change is reported independently even when an
  authored semantic change occurs in the same build.
- Disclosure-only changes are classified directionally: narrowing requires
  claim review, widening requires service-policy review, and incomparable
  changes require both.
- Script capability enablement is keyed only by the implementation-owned
  authoring and Rhai worker contract. Source product and version remain review and
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
