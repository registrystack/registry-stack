# Evidence And Metadata Repository Split Spec

Status: draft, consistency-reviewed

Date: 2026-05-23

## Summary

Split the portable metadata crates and the Evidence Server crates out of
`registry_relay` into their own repositories now, before any compatibility
promises exist. Registry Metadata should model, validate, and render
standards-facing registry metadata for Relay and non-Relay systems such as
OpenCRVS, OpenSPP, OpenIMIS, and SP DCI deployments. Registry Relay should
publish and scope metadata, expose source registry surfaces, and execute
Relay-owned evidence-offering verification. Evidence Server should compute
claims, enforce disclosure policy, render evidence artifacts, and issue
credentials.

This is a clean cut, not a compatibility migration. No external production
users depend on the current embedded Evidence Server routes, metadata crate
layout, or mixed Relay workspace structure. Implementation should optimize for
the right ownership boundary instead of preserving temporary in-workspace
integration.

## Goals

- Move portable registry metadata code into a standalone repository.
- Make metadata validation and rendering usable without running Registry Relay.
- Support non-Relay consumers that need to generate or expose metadata for
  civil registration, social protection, insurance, SP DCI, or similar
  registries.
- Move Evidence Server product code into a standalone repository.
- Make Evidence Server runnable as its own process.
- Remove embedded Evidence Server hosting from Registry Relay.
- Keep Registry Relay focused on metadata publication and scoping,
  Relay-owned evidence-offering verification, and source registry access
  surfaces.
- Keep initial auth and audit contracts inside Evidence Server until a second
  concrete consumer exists.
- Preserve a working local demo where Registry Relay publishes offerings and
  Evidence Server computes claims.
- Keep the split small enough that each repository can build, test, and release
  independently.

## Non-Goals

- Do not preserve the embedded `/claims/*`, `/evidence/render`, or
  `/credentials/issue` route hosting inside Registry Relay.
- Do not keep `registry-metadata-core` and `registry-metadata-cli` inside the
  Registry Relay repository after the metadata split is accepted.
- Do not create a broad shared platform library for all auth, audit, config,
  HTTP, and observability behavior.
- Do not make Evidence Server depend on Registry Relay types, configuration,
  query engines, metadata compilers, or audit sinks.
- Do not move Registry Metadata into the Evidence Server repo. Evidence
  offerings are portable registry metadata plus Relay-owned publication and
  execution surfaces.
- Do not make Registry Metadata depend on Registry Relay, Evidence Server,
  OpenCRVS, OpenSPP, OpenIMIS, DataFusion, Postgres, Axum, auth, audit, or
  runtime row access.
- Do not implement OpenCRVS, OpenSPP, OpenIMIS, or SP DCI business logic in the
  metadata core. Initial ecosystem support is examples, profile data,
  validators, and golden fixtures.
- Do not publish crates to crates.io as a prerequisite. Git dependencies or
  workspace-local path dependencies during transition are acceptable.
- Do not keep the Relay-owned re-export and adapter surface solely to avoid
  touching call sites.

## Product Boundary

### Registry Metadata Owns

- Portable metadata manifest schema and validation.
- Compiled metadata model.
- Vocabulary prefix expansion and syntactic IRI normalization.
- Pure renderers for:
  - catalog JSON;
  - DCAT and DCAT-AP/BRegDCAT-AP JSON-LD;
  - SHACL;
  - JSON Schema Draft 2020-12;
  - link-free OGC API Records record bodies;
  - evidence-offering metadata.
- A CLI for validating manifests and rendering static metadata artifacts.
- Ecosystem profile examples and golden fixtures for non-Relay consumers such
  as OpenCRVS, OpenSPP, OpenIMIS, and SP DCI.

Registry Metadata does not own HTTP route authorization, live row access,
source ingestion, Evidence Server claim computation, audit sinks, or service
runtime behavior.

### Registry Relay Owns

- Metadata HTTP publication, caller scoping, caching, and response headers.
- Relay runtime binding validation between operational config and compiled
  metadata.
- Source registry access surfaces.
- Relay operational config and runtime behavior.
- Evidence-offering discovery routes:
  - `GET /metadata/evidence-offerings`
  - `GET /metadata/evidence-offerings/{offering_id}`
- Relay-native evidence-offering verification route:
  - `POST /evidence-offerings/{offering_id}/verifications`
- `POST /datasets/{dataset_id}/{entity}/verify` and related legacy routes
  already return `legacy_removed` and are asserted absent from Relay OpenAPI by
  existing tests. The split does not change them.
- Relay auth middleware and Relay route authorization.
- Relay audit sinks and Relay audit event mapping.
- Optional source registry APIs that Evidence Server may consume over HTTP.
- A two-process demo that shows Relay metadata pointing at an external Evidence
  Server.

### Evidence Server Owns

- Claim definition model.
- Evidence Server config loading and validation.
- Claim evaluation.
- Claim dependency evaluation.
- Source connector traits.
- Generic DCI and Registry Data API source connectors, where they do not depend
  on Relay internals.
- Disclosure policy.
- Claim result views.
- Renderers:
  - canonical claim result JSON;
  - CCCEV-aligned JSON-LD;
  - SD-JWT VC credential output.
- Credential issuance.
- Evidence Server auth middleware and claim/disclosure authorization.
- Evidence Server audit event model and event emission.
- Evidence Server OpenAPI and examples.
- Evidence Server binary startup, server binding, shutdown, logging, and config
  file loading.
- Evidence Server tests, fixtures, and demos.

## Target Repository Shape

Create two new repositories:

### Registry Metadata Repository

Tentative name: `registry-metadata`.

Recommended layout:

```text
registry-metadata/
  Cargo.toml
  crates/
    registry-metadata-core/
    registry-metadata-cli/
  profiles/
    opencrvs/
    openspp/
    openimis/
    spdci/
  examples/
  docs/
  tests/
```

Keep `profiles/` as data, fixtures, validators, and examples unless at least
two consumers justify a Rust abstraction. Profile examples must be reviewed
against official artifacts or maintainer feedback before they are described as
real OpenCRVS, OpenSPP, OpenIMIS, or SP DCI profiles.

### Evidence Server Repository

Tentative name: `evidence-server`.

Recommended layout:

```text
evidence-server/
  Cargo.toml
  crates/
    evidence-core/
    evidence-server/
    evidence-server-bin/
  docs/
  demo/
  tests/
```

`evidence-server-bin` may be named `evidence-server` if the package naming is
kept unambiguous. The important point is that the repository ships a real
binary process, not only reusable libraries.

### Repository Bootstrap

Each new repository must include:

- Apache-2.0 `LICENSE`.
- `SECURITY.md` with vulnerability reporting instructions.
- `CODEOWNERS` or the organization's equivalent ownership file.
- Dependabot configuration for Cargo dependencies and GitHub Actions.
- GitHub Actions CI for format, lint, tests, OpenAPI generation where relevant,
  and build.
- Initial `0.1.0` tag after the first accepted cut.
- Release notes describing the split and any known non-goals.

Evidence Server must keep `utoipa` as the OpenAPI generator unless Wave 0
records a reviewed replacement.

## Crate Responsibilities

### `registry-metadata-core`

Owns portable metadata contracts:

- `MetadataManifest`.
- `CompiledMetadata`.
- metadata validation and compilation.
- compact IRI prefix expansion.
- catalog, dataset, entity, field, codelist, requirement, evidence type,
  evidence offering, policy, and profile metadata.
- pure metadata renderers.
- golden tests for renderer stability.

`registry-metadata-core` must not depend on Registry Relay, Evidence Server,
Axum, DataFusion, Postgres, auth, audit, observability, runtime row access,
secret handling, `utoipa`, or `clap`.

### `registry-metadata-cli`

Owns command-line metadata workflows:

- validate metadata manifests;
- render individual artifacts;
- publish a static metadata directory;
- validate profile examples where profile validators exist.

`registry-metadata-cli` depends on `registry-metadata-core`; it must not depend
on Registry Relay or Evidence Server.

### `evidence-core`

Owns stable domain contracts:

- `EvidenceConfig` and nested config model.
- `ClaimDefinition`.
- `ClaimResult`.
- `ClaimResultView`.
- `EvidenceArtifact`.
- request and response types.
- disclosure enums.
- source connector traits and shared value types if they are independent of
  HTTP clients and service assembly.
- shared Evidence Server error codes.
- Evidence Server principal and low-level auth value types.
- Evidence Server audit event contracts and redaction helpers.
- SD-JWT VC primitive types and helpers that do not require service state.

`evidence-core` must not depend on Axum, Registry Relay, Relay metadata crates,
Relay config, or Relay auth.

### `evidence-server`

Owns service behavior:

- Axum router.
- runtime evaluation engine.
- renderer implementations.
- credential issuance wiring.
- source connector implementations that need HTTP clients, auth headers,
  retries, or service config.
- in-memory evaluation store or other service runtime state.
- Evidence Server API error mapping.
- OpenAPI generation.
- Evidence Server audit event emission points.

`evidence-server` may depend on `evidence-core`. It must not depend on
Registry Relay.

### `evidence-server-bin`

Owns process startup:

- CLI arguments.
- config file loading.
- environment variable resolution.
- server bind address and shutdown.
- logging and tracing setup.
- auth provider initialization.
- audit sink initialization.
- HTTP client setup.

The binary must be enough to run the Evidence Server without Registry Relay.

Do not create a separate `evidence-auth-audit-core` crate in the initial cut.
Today the only clearly shared Evidence type is `EvidencePrincipal`. Put
Evidence Server principal, scope, audit event, decision, correlation id, and
redaction contracts in `evidence-core`. Extract a separate shared crate only
after Registry Relay or another service consumes the same contracts without
service-specific policy.

## Registry Relay Changes

Remove from Registry Relay:

- workspace members:
  - `crates/registry-metadata-core`;
  - `crates/registry-metadata-cli`;
  - `crates/evidence-core`;
  - `crates/evidence-server`.
- path dependencies on local metadata and evidence crates.
- embedded Evidence Server route hosting in `src/api/evidence.rs`.
- the Relay-owned re-export and adapter surface in `src/evidence/mod.rs`.
- the Relay-specific Evidence Server adapter in
  `src/evidence/registry_relay.rs`.
- claim computation code that exists only for Evidence Server behavior.
- Evidence Server demo scripts and fixtures that no longer exercise Relay.

Keep or add in Registry Relay:

- a dependency on the external Registry Metadata repo.
- Relay-owned loading of metadata manifests through `registry-metadata-core`.
- Relay-owned runtime binding validation between `Config`, `EntityRegistry`,
  and `CompiledMetadata`.
- evidence-offering discovery routes.
- config support for access routes of kind `evidence-server`.
- docs that explain Relay advertises Evidence Server endpoints but does not
  compute Evidence Server claims.
- a demo where Relay and Evidence Server run as separate processes.

If Relay needs a source adapter for Evidence Server, prefer an HTTP boundary:
Evidence Server calls Relay's Registry Data API or DCI-compatible endpoints.
Avoid linking Relay as a library into Evidence Server.

## Auth Boundary

Evidence Server authorization is claim and disclosure oriented. Registry Relay
authorization is dataset, entity, route, and metadata oriented. These policies
must remain separate.

Shared auth code should be limited to:

- identity representation;
- scope string parsing;
- scope matching primitives;
- auth error categories;
- optional token claim structs if both services use the same input format.

For the initial cut, these contracts live in `evidence-core`, not a separate
shared crate.

Registry Relay owns:

- API key auth as configured by Relay.
- OIDC handling as configured by Relay.
- Relay scope names such as dataset metadata, rows, aggregate, verify, and
  evidence offering access.
- Relay route middleware.

Evidence Server owns:

- client authentication for Evidence Server APIs.
- initial API key and bearer-token authentication for the standalone binary.
- claim-level authorization.
- disclosure-profile authorization.
- credential issuance authorization.
- purpose and audience checks.
- release authorization checks when a profile requires them.

OIDC/JWKS discovery and cache reuse from Relay is a follow-up unless explicitly
chosen before Wave 2. The first standalone binary must nevertheless have a
clear fail-closed auth posture; "demo-only unauthenticated" is not acceptable
for the split Definition Of Done.

## Audit Boundary

Evidence Server should emit audit events using a stable event schema from
`evidence-core`, but it should not rely on Relay's audit sink implementation.

Evidence Server audit events must include enough information to answer:

- who requested the evaluation;
- which claims were requested;
- which subject reference was used;
- which disclosure profile was requested and granted;
- whether evaluation succeeded, failed, or was denied;
- which source connector types were used;
- which credential profile was used, if any;
- correlation, idempotency, and evaluation identifiers;
- redacted error category when applicable.

Registry Relay audit events must remain focused on Relay routes and metadata or
source access. Relay may log that it served metadata pointing to an Evidence
Server, but it should not log claim computation details unless it was acting as
the source registry for that computation.

## Dependency Strategy

The new Registry Metadata and Evidence Server repos may initially depend on
sibling repositories using Git dependencies or local development overrides.
Registry Relay should consume Registry Metadata as an external dependency after
the metadata cut. Evidence Server should not depend on Registry Relay; it may
depend on Registry Metadata only if it needs portable discovery metadata types
or examples, not for claim computation.

The current `cel-mapper-core` path dependency must be resolved before the split
starts. Default decision: keep CEL enabled in the new Evidence Server binary,
push the latest `cel-mapper-core` changes to its published repository, and
consume `cel-mapper-core` by tagged Git revision or release. A different
decision must be recorded before Wave 2 begins.

Do not copy PublicSchema-specific mapping behavior into Evidence Server. CEL
support should expose expression evaluation semantics only, not PublicSchema
mapping documents, output writers, or ETL concepts.

## Pre-Start Decision Register

Implementation must not start until this register is complete. Each decision
must record the final value, owner, review link, and resolution date.

| Decision | Default Or Current State | Owner | Resolved By |
| --- | --- | --- | --- |
| Registry Metadata repository name | Resolved: `registry-metadata` | Integration Lead | Wave 0 exit |
| Evidence Server repository name | Resolved: `evidence-server` | Integration Lead | Wave 0 exit |
| Repository visibility | Resolved: `registry-metadata` and `evidence-server` are public GitHub repositories under `jeremi` | Integration Lead | Release publication |
| Git dependency URL policy | Resolved: Relay consumes `registry-metadata-core` from `https://github.com/jeremi/registry-metadata` tag `v0.1.0`; Relay and Evidence Server consume `cel-mapper-core` from `https://github.com/PublicSchema/cel-mapping` tag `cel-mapper-core-v0.1.0` | Integration Lead | Release publication |
| Split sequence | Resolved: Registry Metadata first, then Evidence Server atomic cut | Integration Lead | Wave 0 exit |
| CEL dependency strategy | Resolved: CEL remains enabled by default and `cel-mapper-core` is pinned to published tag `cel-mapper-core-v0.1.0` | Worker C | Release publication |
| Evidence Server auth posture | Resolved: API key plus bearer token validation; OIDC/JWKS discovery is explicit follow-up | Worker C | Wave 2 exit |
| Evidence Server audit sink posture | Resolved: JSONL file sink plus structured stdout sink, both redacted and tested; unknown sink values fail startup | Worker C | Wave 2 exit |
| Canonical two-process demo | Resolved: Relay source registry on `127.0.0.1:4256`, Evidence Server on `127.0.0.1:4255`, discovery via Relay metadata, claim evaluation/render/SD-JWT through Evidence Server | Worker D | Wave 3 exit |
| Legacy dataset/entity verification route | Already removed: `POST /datasets/{dataset_id}/{entity}/verify` returns `legacy_removed` and is asserted absent from Relay OpenAPI by `tests/api_docs.rs` and `src/api/openapi.rs:2887` | Worker B | Recorded, verify in Wave 2 |
| Relay evidence-offering verification route | Stays in Relay: `POST /evidence-offerings/{offering_id}/verifications` | Worker B | Recorded, verify in Wave 2 |
| Repository bootstrap | Resolved: Apache-2.0 license, `SECURITY.md`, `CODEOWNERS`, Dependabot for Cargo and GitHub Actions, GitHub Actions CI, release notes, GitHub remotes, and pushed `v0.1.0` tags | Integration Lead | Wave 1 for Registry Metadata, Wave 2 for Evidence Server |
| OpenAPI generator | Resolved: Evidence Server owns `cargo run -p evidence-server-bin -- openapi` output backed by `utoipa::openapi::OpenApi` | Worker C | Wave 2 exit |

## Migration Plan

### Wave 0: Prepare The Repository Cuts

- Confirm no external users require embedded Evidence Server routes.
- Confirm no external users require the current in-repo metadata crate layout.
- Identify all files currently owned by Registry Metadata behavior.
- Identify all files currently owned by Evidence Server behavior.
- Confirm the latest `cel-mapper-core` changes are pushed to its published
  repository and identify the tag or release Evidence Server will consume.
- Complete the Pre-Start Decision Register.
- Freeze unrelated Relay metadata and evidence changes while extraction is in
  progress.

Exit criteria:

- Metadata and Evidence Server file ownership lists are reviewed.
- Repository naming, visibility, dependency strategy, auth posture, audit sink
  posture, split sequence, and legacy route state are recorded.
- `cel-mapper-core` has a published tag or release recorded for Evidence
  Server consumption.
- Dirty working tree changes are either committed, stashed, or intentionally
  carried into the split.

### Wave 1: Registry Metadata Repository Cut

- Create the new Registry Metadata Cargo workspace.
- Move `crates/registry-metadata-core`.
- Move `crates/registry-metadata-cli`.
- Move metadata docs, examples, golden fixtures, and CLI tests.
- Add initial `profiles/` and `examples/` directories for non-Relay consumers.
- Add CI commands for format, lint, test, and build.
- Add README with validate, render, and static publish instructions.
- Add repository bootstrap files: Apache-2.0 `LICENSE`, `SECURITY.md`,
  `CODEOWNERS`, Dependabot configuration, GitHub Actions CI, release notes, and
  initial `0.1.0` tag after acceptance.
- Convert Registry Relay to depend on Registry Metadata externally.
- Remove local metadata crates from the Registry Relay workspace.
- Keep Relay metadata HTTP routes, caller scoping, response headers, runtime
  binding validation, OpenAPI route assembly, and OGC HTTP routing in Relay.

Exit criteria:

- Registry Metadata README names the exact format, lint, unit, CLI, golden,
  and build commands.
- Those Registry Metadata commands pass from a clean checkout.
- `registry-metadata` CLI validates and renders demo metadata manifests.
- Registry Relay full-workspace verification passes while consuming Registry
  Metadata as an external dependency, including metadata, OGC Records, OpenAPI,
  config, demo-config, and still-local evidence crate tests.
- Local Registry Metadata workspace entries and path dependencies are removed
  from Registry Relay.
- Reviewers confirm `registry-metadata-core` has no dependency on Registry
  Relay, Evidence Server, Axum, auth, audit, DataFusion, Postgres, or runtime
  row access.

### Wave 2: Evidence Server Atomic Repository Cut

- Create the new Cargo workspace.
- Move `crates/evidence-core`.
- Move `crates/evidence-server`.
- Add the Evidence Server binary.
- Move Evidence Server docs, config examples, fixtures, and tests.
- Add CI commands for format, lint, test, and build.
- Add README with local run instructions.
- Add repository bootstrap files: Apache-2.0 `LICENSE`, `SECURITY.md`,
  `CODEOWNERS`, Dependabot configuration, GitHub Actions CI, release notes, and
  initial `0.1.0` tag after acceptance.
- Implement the standalone binary's chosen auth posture.
- Implement the standalone binary's chosen audit sinks.
- Move Evidence Server principal, scope, audit event, decision, correlation,
  and redaction contracts into `evidence-core`.
- Keep Evidence Server authorization policy local to Evidence Server.
- Remove Evidence Server crates from Relay workspace members.
- Remove embedded Evidence Server API hosting from Relay.
- Remove the Relay-owned re-export and adapter surface in `src/evidence/mod.rs`.
- Delete `src/evidence/registry_relay.rs` entirely.
- Remove Evidence Server config validation from Relay except fields needed to
  publish or validate evidence-offering metadata.
- Preserve `Config.evidence_verification` for Relay-owned evidence-offering
  verification rate limits.
- Remove `Config.evidence` from Relay unless a temporary compatibility read is
  explicitly required and tested as ignored.
- Keep evidence-offering metadata routes and tests.
- Update Relay docs to point to the external Evidence Server repo.

Exit criteria:

- Evidence Server README names the exact format, lint, unit, API integration,
  audit redaction, credential, OpenAPI, and build commands.
- Those Evidence Server commands pass from a clean checkout.
- Evidence Server binary starts from documented demo config with fail-closed
  auth enabled.
- Evidence Server audit sinks write redacted events.
- No crate in the new Evidence Server repo imports Registry Relay code.
- Registry Relay format, lint, metadata, evidence-offering, OpenAPI, config,
  and demo-config checks pass without local Evidence Server crates.
- Relay evidence-offering metadata still renders Evidence Server access routes.
- Relay has no claim computation dependency on Evidence Server internals.

### Wave 3: Two-Process Demo

- Run Registry Relay as the metadata publisher and source registry.
- Run Evidence Server as the claim computation service.
- Render the same metadata manifest statically with the Registry Metadata CLI.
- Configure Relay evidence offerings with external Evidence Server access
  routes.
- Configure Evidence Server to consume Relay source APIs or DCI-compatible
  endpoints.
- Update demo scripts and README.

Exit criteria:

- Demo starts both processes from documented commands.
- Registry Metadata CLI renders the demo metadata artifacts from the same
  manifest Relay publishes.
- Caller can discover an evidence offering through Relay.
- Caller can evaluate a claim through Evidence Server.
- Evidence Server emits audit events for evaluation.
- Relay emits audit events for its own metadata and source API requests.

### Wave 4: Optional Shared Library Extraction

This wave is optional and must not block the initial split.

- Extract a shared auth/audit crate only if Registry Relay or another service
  consumes the same Evidence Server contracts without importing service policy.
- Keep route middleware, OIDC/JWKS provider implementation, audit sinks, Relay
  scope policy, and Evidence Server claim/disclosure policy out of the shared
  crate.

Exit criteria:

- At least two repositories consume the shared crate.
- The shared crate has no Axum middleware, no audit sink implementation, and no
  service-specific authorization policy.

## Definition Of Done

The split is done only when every item below is satisfied from clean checkouts
of the final repositories. "Works locally with path overrides" is not enough
unless the override workflow is the documented development workflow and CI also
uses it.

### Repository Ownership

- The final Registry Metadata repository name and visibility are recorded in
  the split decision log.
- The final Evidence Server repository name and visibility are recorded in the
  split decision log.
- Registry Metadata has its own Cargo workspace, README, CI workflow, release
  notes entry, and ownership file if the organization uses one.
- Evidence Server has its own Cargo workspace, README, CI workflow, release
  notes entry, and ownership file if the organization uses one.
- Registry Metadata and Evidence Server each include Apache-2.0 `LICENSE`,
  `SECURITY.md`, `CODEOWNERS` or equivalent, Dependabot configuration for Cargo
  and GitHub Actions, GitHub Actions CI, and an initial `0.1.0` tag after the
  accepted cut.
- Registry Relay no longer has workspace members at:
  - `crates/registry-metadata-core`;
  - `crates/registry-metadata-cli`;
  - `crates/evidence-core`;
  - `crates/evidence-server`.
- Registry Relay manifests and lockfiles contain no local path dependency to
  those removed crates.
- Registry Relay consumes Registry Metadata through the agreed external Git,
  release, or documented local-development dependency.
- Evidence Server does not import Registry Relay crates, modules, config types,
  auth types, audit sinks, source adapters, or runtime row access.
- Registry Metadata does not import Registry Relay, Evidence Server, Axum,
  DataFusion, Postgres, auth, audit, secret handling, observability, or runtime
  row access.
- Any Evidence Server dependency on Registry Metadata is recorded in the
  decision log and limited to portable discovery metadata, examples, or static
  documentation generation. Claim evaluation must not require Registry Metadata.

### Registry Metadata Acceptance

- `registry-metadata-core` owns only portable metadata contracts,
  compilation, validation, and pure renderers.
- `registry-metadata-cli` owns only command-line validation, rendering, and
  static publication workflows.
- The Registry Metadata README names the exact commands for:
  - formatting;
  - linting;
  - unit tests;
  - CLI tests;
  - golden renderer tests;
  - workspace build.
- Those commands pass in CI and from a clean checkout.
- Golden renderer coverage exists and passes for catalog JSON, DCAT,
  BRegDCAT-AP, SHACL, JSON Schema, OGC API Records record bodies, and
  evidence-offering metadata.
- OpenCRVS, OpenSPP, OpenIMIS, and SP DCI examples are either validated
  against reviewed artifacts or clearly marked illustrative in filenames,
  README text, and generated docs.
- No Registry Metadata doc claims to implement OpenCRVS, OpenSPP, OpenIMIS, or
  SP DCI business semantics.

### Registry Relay Acceptance

- Registry Relay owns metadata HTTP publication, caller scoping, response
  headers, route auth, runtime binding validation, and operational OpenAPI
  assembly.
- Registry Relay still exposes and tests:
  - `GET /metadata/evidence-offerings`;
  - `GET /metadata/evidence-offerings/{offering_id}`;
  - `POST /evidence-offerings/{offering_id}/verifications`.
- Registry Relay no longer hosts Evidence Server API routes:
  - `GET /.well-known/evidence-service`;
  - `GET /.well-known/evidence/jwks.json`;
  - `GET /claims`;
  - `GET /claims/{claim_id}`;
  - `GET /formats`;
  - `POST /claims/evaluate`;
  - `POST /claims/batch-evaluate`;
  - `POST /evidence/render`;
  - `POST /credentials/issue`.
- Registry Relay OpenAPI does not document embedded Evidence Server routes.
- Legacy `POST /datasets/{dataset_id}/{entity}/verify` behavior remains
  unchanged: it returns `legacy_removed` and is asserted absent from Relay
  OpenAPI.
- `Config.evidence_verification` remains Relay-owned and tested for Relay
  evidence-offering verification rate limits.
- `Config.evidence` is removed from Relay or explicitly tested as ignored,
  according to the recorded pre-start decision.
- `src/evidence/registry_relay.rs` is deleted entirely.
- Relay docs state that Relay advertises Evidence Server access routes and may
  act as a source registry, but does not compute Evidence Server claims.

### Evidence Server Acceptance

- Evidence Server has a runnable binary that starts without Registry Relay
  process state.
- The binary owns CLI arguments, config file loading, environment variable
  resolution, bind address, shutdown, logging, tracing, HTTP client setup, auth
  provider initialization, and audit sink initialization.
- The first binary has fail-closed auth enabled from documented config. The
  default accepted posture is API key plus bearer-token validation unless Wave
  0 records a different posture.
- OIDC/JWKS discovery is either implemented and tested in Evidence Server or
  explicitly recorded as follow-up work. It must not be silently inherited from
  Registry Relay.
- Evidence Server owns and tests its API routes:
  - `GET /.well-known/evidence-service`;
  - `GET /.well-known/evidence/jwks.json`;
  - `GET /claims`;
  - `GET /claims/{claim_id}`;
  - `GET /formats`;
  - `POST /claims/evaluate`;
  - `POST /claims/batch-evaluate`;
  - `POST /evidence/render`;
  - `POST /credentials/issue`.
- Evidence Server claim, disclosure, and credential authorization remain local
  to Evidence Server.
- Evidence Server can evaluate at least one claim through a configured source
  connector over HTTP without linking Registry Relay as a library.
- Evidence Server owns its OpenAPI output and named OpenAPI generation command,
  using `utoipa` unless the decision register records a reviewed replacement.
- CEL is enabled by default in the standalone Evidence Server binary unless
  Wave 0 records another decision.
- Evidence Server consumes `cel-mapper-core` by the agreed tagged Git revision
  or release, not by an unportable sibling path.

### Auth And Audit Acceptance

- Evidence Server principal, scope, auth error, audit event, decision,
  correlation id, and redaction contracts live in `evidence-core` for the
  initial cut.
- No `evidence-auth-audit-core` or equivalent shared crate exists unless the
  optional Wave 4 shared-library extraction has passed.
- Tests cover denied Evidence Server access for missing principal, missing
  claim scope, unauthorized disclosure profile, and unauthorized credential
  profile.
- Relay route authorization remains in Relay.
- Relay audit sinks remain in Relay.
- Evidence Server owns its JSONL file sink, structured stdout sink, or the
  alternate sinks recorded in Wave 0.
- Evidence Server audit tests assert emitted events exclude raw source records,
  unrestricted subject data, credential secrets, bearer tokens, API keys, and
  private keys.
- The two-process demo produces separate Relay and Evidence Server audit event
  streams.

### Tests And Verification

- Registry Metadata CI passes the README-named format, lint, test, golden, CLI,
  and build commands.
- Evidence Server CI passes the README-named format, lint, test, API
  integration, audit redaction, OpenAPI, credential, and build commands.
- Registry Relay CI passes after consuming external Registry Metadata and after
  removing local Evidence Server crates.
- Evidence Server API integration coverage migrated or rewritten from
  `tests/evidence_api.rs` passes in the Evidence Server repo.
- Evidence Server DCI and two-source coverage migrated or rewritten from
  `tests/evidence_dci_http_source.rs` and
  `tests/evidence_two_relay_dci.rs` passes in the Evidence Server repo.
- Registry Relay tests covering metadata, evidence offerings, config, and
  OpenAPI pass, including coverage migrated or retained from:
  - `tests/entity_routes.rs`;
  - `tests/third_party_verification.rs`;
  - `tests/catalog_entity.rs`;
  - `tests/api_docs.rs`;
  - `tests/demo_configs_load.rs`.
- `tests/demo_configs_load.rs` is split if needed so Relay runtime config
  checks remain in Relay, Registry Metadata manifest checks move to Registry
  Metadata, and Evidence Server config checks move to Evidence Server.
- The two-process smoke test passes from clean checkouts using documented
  commands only.
- All verification commands and their results are recorded in the final split
  review.

### Documentation And Cleanup

- Registry Metadata docs describe the portable model and CLI workflows.
- Evidence Server docs describe standalone config, auth, audit, APIs, OpenAPI
  generation, and source connector setup.
- Relay docs describe external Evidence Server access routes and Relay-owned
  metadata publication.
- No doc claims Registry Relay computes Evidence Server claims.
- Old in-workspace Evidence Server notes are updated, moved, or marked
  historical.
- Obsolete Relay modules that only bridged embedded Evidence Server routes are
  deleted.
- Obsolete demo outputs are removed or regenerated in the owning repository.
- No unrelated Relay files are reformatted or changed as part of the split.
- No secret values are committed in demo configs, logs, fixtures, docs, or test
  snapshots.

### Review Evidence

- Every wave has a design review note, code review approval, and completion
  review note.
- Each completion review maps changed files to this Definition Of Done.
- Every `blocked` item lists an owner, reason, and decision needed.
- No item is marked done if it has only a happy-path implementation, unreviewed
  docs, skipped tests without justification, or manual-only setup.

## Risks And Decisions To Track

### CEL Runtime Packaging

Risk: Evidence Server could accidentally change CEL from enabled-by-default to
disabled-by-default, or could drift from the reviewed CEL runtime.

Decision: keep CEL enabled in the standalone binary, push the latest
`cel-mapper-core` changes to its published repository, and pin
`cel-mapper-core` by tagged Git revision or release. The accepted cut pins
`cel-mapper-core-v0.1.0`. Tests must cover the default binary feature set so a
CEL default flip is caught.

### Shared Auth Scope Creep

Risk: A shared auth library becomes a hidden monolith and forces Evidence
Server to inherit Relay semantics.

Decision: do not create a shared auth/audit crate in the initial cut. Keep
Evidence Server contracts in `evidence-core`; extract a shared crate only after
there is a second real consumer.

### Standalone Binary Under-Specification

Risk: "add the binary" hides work currently supplied by Relay: config loading,
environment resolution, auth providers, audit sinks, observability, HTTP client
setup, and shutdown.

Decision: Wave 2 is not done until the binary starts from documented config,
enforces the chosen fail-closed auth posture, emits redacted audit events, and
passes its integration tests without Relay process state.

### Metadata Profile Overreach

Risk: Registry Metadata starts claiming OpenCRVS, OpenSPP, OpenIMIS, or SP DCI
support based on illustrative examples rather than reviewed artifacts.

Decision: ecosystem profile examples remain non-normative until validated
against official artifacts or maintainer feedback. Core owns portable metadata
primitives and renderers, not application business semantics.

### Demo Coupling

Risk: The demo passes only because Evidence Server and Relay are still wired
together inside one process.

Decision: the acceptance demo must run two processes and communicate over HTTP.

### Audit Sink Duplication

Risk: Relay and Evidence Server duplicate file or JSONL audit sink code.

Decision: tolerate boring duplication until both services prove the sink
contract is identical. Extract only after the split is working.

### Evidence Metadata Semantics

Risk: Evidence Server starts owning evidence-offering metadata and blurs the
Relay boundary.

Decision: Registry Metadata owns the portable evidence-offering metadata model.
Relay owns HTTP publication and caller scoping for that metadata. Evidence
Server may publish its own service document and claim catalogue, but not Relay
catalogue metadata.

## Parallel Implementation Plan

The work should be done in waves with one integration lead and parallel
workers. Workers may run at the same time only when their write surfaces are
disjoint. Each worker owns a reviewable change set, focused tests, docs for the
surface they touched, and a completion note that lists verification results.

The worker waves below are the execution decomposition of the Migration Plan
waves above. They do not define a second schedule.

No wave closes on intent. A wave closes only after the code, docs, tests,
deleted behavior, dependency graph, and review evidence satisfy that wave's
exit criteria.

### Team Roles

Integration Lead owns:

- the decision log;
- cross-repository dependency direction;
- wave branch coordination;
- final merge order;
- the Definition Of Done checklist;
- review assignment and completion review.

Worker A owns Registry Metadata extraction.

Worker B owns Registry Relay metadata integration and Relay cleanup.

Worker C owns Evidence Server extraction, binary, auth, and audit.

Worker D owns tests, demos, OpenAPI, docs, and verification evidence.

Workers may pair when a boundary crosses repositories, but one worker remains
the named owner for each file set.

### Review Cadence

Every wave requires these reviews:

1. Design review before implementation starts. This review confirms ownership,
   dependency direction, route behavior, config ownership, and the tests that
   will prove the wave.
2. Mid-wave boundary review after the first compiling slice. This review checks
   for accidental coupling, premature shared libraries, unclear auth or audit
   posture, and missing deletion work.
3. Code review before merge. This review checks correctness, security,
   deleted embedded behavior, docs, tests, and generated artifacts.
4. Completion review after verification. This review maps the wave result to
   the Definition Of Done and records pass, blocked, or not applicable for each
   relevant item.

A review may not approve a wave with untested route behavior, undocumented
config behavior, skipped deletion work, or a partial implementation marked as
done.

### Wave 0 Worker Decomposition: Inventory, Decisions, And Review Harness

Goal: make the split executable before files move.

Parallel work:

- Worker A classifies all Registry Metadata files, docs, tests, profile
  examples, golden fixtures, and CLI behavior.
- Worker B inventories Relay metadata integration points in `src/api/metadata.rs`,
  `src/api/ogc/records.rs`, `src/config/loader.rs`, and
  `src/config/validate.rs`.
- Worker C classifies all Evidence Server files, including `crates/evidence-core`,
  `crates/evidence-server`, `crates/evidence-server/src/api.rs`, and the full
  `src/evidence/registry_relay.rs` adapter surface that Wave 2 will delete
  from Relay.
- Worker D maps tests and demos to their target repositories, including
  `tests/evidence_api.rs`, `tests/evidence_dci_http_source.rs`,
  `tests/evidence_two_relay_dci.rs`, `tests/entity_routes.rs`,
  `tests/catalog_entity.rs`, `tests/api_docs.rs`, and
  `tests/demo_configs_load.rs`.

Integration Lead records:

- final repository names and visibility;
- Git dependency URL policy;
- split order;
- CEL dependency strategy, including the published `cel-mapper-core` tag or
  release Evidence Server will consume;
- Evidence Server auth posture;
- Evidence Server audit sink posture;
- canonical two-process demo;
- legacy dataset/entity verification route state;
- exact verification commands for each repository.

Wave 0 worker exit criteria:

- every source file, test, fixture, doc, and demo touched by the split has one
  owner: Registry Metadata, Registry Relay, Evidence Server, delete, or
  historical docs;
- the Pre-Start Decision Register is complete;
- the Definition Of Done checklist exists and is reviewable;
- unresolved ownership conflicts are listed as blockers with owners;
- design review is complete.

### Wave 1 Worker Decomposition: Registry Metadata Repository Cut

Goal: make Registry Metadata independently useful for Relay and non-Relay
consumers.

Parallel work:

- Worker A creates the Registry Metadata repository, moves
  `registry-metadata-core`, moves `registry-metadata-cli`, adds the README,
  moves metadata docs, moves golden fixtures, and adds profile/example
  directories for OpenCRVS, OpenSPP, OpenIMIS, and SP DCI.
- Worker A adds Registry Metadata repository bootstrap files: Apache-2.0
  `LICENSE`, `SECURITY.md`, `CODEOWNERS`, Dependabot configuration, GitHub
  Actions CI, release notes, and initial `0.1.0` tag after acceptance.
- Worker B converts Registry Relay to consume Registry Metadata through the
  agreed dependency, removes local metadata workspace members, and keeps Relay
  HTTP publication, caller scoping, runtime binding validation, OGC routing,
  and OpenAPI route assembly in Relay.
- Worker D ports or rewrites Registry Metadata unit tests, CLI tests, golden
  renderer tests, and relevant Relay metadata tests.

Wave 1 worker review gates:

- Mid-wave boundary review confirms `registry-metadata-core` has no Relay,
  Evidence Server, Axum, auth, audit, DataFusion, Postgres, or runtime row
  access dependency.
- Code review confirms examples are either validated or clearly illustrative.
- Completion review confirms the README-named Registry Metadata verification
  commands pass outside Relay.
- Completion review confirms the README-named Registry Relay verification
  commands pass while consuming external Registry Metadata.
- Completion review confirms old Relay metadata path dependencies and workspace
  entries are gone.

Wave 1 worker required verification:

- Registry Metadata format, lint, unit, CLI, golden, and build commands pass.
- README-named Relay full-workspace verification commands pass against the
  external dependency, including metadata, OGC Records, OpenAPI, config, demo
  config, and still-local evidence crate tests.

### Wave 2 Worker Decomposition: Evidence Server Atomic Cut

Goal: move Evidence Server and remove embedded Evidence Server behavior from
Relay in one reviewed cut.

Parallel work:

- Worker C creates the Evidence Server repository, moves `evidence-core`, moves
  `evidence-server`, adds the standalone binary package, and places principal,
  scope, audit event, decision, correlation id, and redaction contracts in
  `evidence-core`.
- Worker C adds Evidence Server repository bootstrap files: Apache-2.0
  `LICENSE`, `SECURITY.md`, `CODEOWNERS`, Dependabot configuration, GitHub
  Actions CI, release notes, and initial `0.1.0` tag after acceptance.
- Worker C implements binary startup: CLI arguments, config file loading,
  environment variable resolution, API key and bearer auth, audit sinks,
  logging, tracing, HTTP client setup, bind address, and shutdown.
- Worker B removes local Evidence Server path dependencies and workspace
  members from Relay, removes embedded Evidence Server route hosting, removes
  the Relay-owned re-export and adapter surface, and deletes
  `src/evidence/registry_relay.rs` entirely.
- Worker B preserves Relay-owned `Config.evidence_verification`, removes or
  ignores `Config.evidence` according to the decision log, and keeps
  `POST /evidence-offerings/{offering_id}/verifications` in Relay.
- Worker D ports or rewrites Evidence Server API, DCI, two-source, credential,
  audit redaction, OpenAPI, and runtime tests.
- Worker D updates Relay docs, Evidence Server docs, config examples, and
  OpenAPI generation instructions.

Wave 2 worker review gates:

- Mid-wave boundary review confirms no `evidence-auth-audit-core` or equivalent
  shared crate was introduced.
- Mid-wave boundary review confirms Evidence Server does not import Relay code.
- Code review confirms Relay no longer hosts Evidence Server routes and no
  longer computes Evidence Server claims.
- Code review confirms Evidence Server auth is fail-closed and audit output is
  redacted.
- Completion review confirms the README-named Evidence Server verification
  commands pass outside Relay.
- Completion review confirms the README-named Registry Relay verification
  commands pass without local Evidence Server crates.
- Completion review confirms the `Config.evidence_verification` versus
  `Config.evidence` decision is implemented and tested.

Wave 2 worker required verification:

- Evidence Server format, lint, unit, API integration, audit redaction,
  credential, OpenAPI, and build commands pass.
- Evidence Server binary starts from documented demo config with fail-closed
  auth.
- Relay metadata, evidence-offering, OpenAPI, config, and demo-config tests
  pass without local Evidence Server crates.

### Wave 3 Worker Decomposition: Two-Process Acceptance Demo

Goal: prove the split behaves like a product boundary, not only a crate move.

Parallel work:

- Worker A ensures the canonical demo manifest can be rendered by the Registry
  Metadata CLI.
- Worker B configures Relay as metadata publisher and source registry, with
  Evidence Server access routes published through evidence-offering metadata.
- Worker C configures Evidence Server to consume Relay source APIs or
  DCI-compatible endpoints over HTTP.
- Worker D writes or updates the smoke test and README commands for startup,
  discovery, evaluation, rendering, audit inspection, and shutdown.

Wave 3 worker review gates:

- Code review confirms the demo uses two processes and HTTP communication.
- Code review confirms the demo does not rely on local path-only setup unless
  that setup is the documented development workflow.
- Completion review confirms reviewers can reproduce startup, discovery,
  evaluation, rendering, audit inspection, and shutdown from clean checkouts.

Wave 3 worker required verification:

- Registry Metadata CLI output and Relay-published metadata match for the
  canonical demo manifest where both surfaces render the same artifact.
- Caller discovers an evidence offering through Relay.
- Caller evaluates the related claim through Evidence Server.
- Relay emits only Relay metadata or source API audit events.
- Evidence Server emits claim evaluation and credential audit events.
- The two-process smoke test passes from clean checkouts.

### Wave 4 Worker Decomposition: Optional Shared Auth Or Audit Library

Goal: extract shared contracts only if the finished split proves they are
actually shared.

This wave is not required for initial acceptance.

Parallel work:

- Worker C proves at least two repositories need the same auth or audit
  contracts and lists the exact types to extract.
- Worker B confirms Relay would consume those contracts without inheriting
  Evidence Server policy.
- Worker D adds focused tests proving the shared crate contains no middleware,
  OIDC/JWKS provider, audit sink, route policy, claim policy, or disclosure
  policy.

Wave 4 worker review gates:

- Design review confirms the extraction has at least two real consumers.
- Code review confirms no service-specific policy leaked into the shared crate.
- Completion review confirms all consuming repositories pass their documented
  verification commands.

### Final Acceptance

The split is accepted only when:

- every Definition Of Done item is marked `done`;
- every non-optional wave review gate has passed;
- all three repositories pass their documented verification commands from clean
  checkouts;
- the two-process demo passes from clean checkouts;
- reviewers confirm no premature shared auth/audit crate exists unless optional
  Wave 4 passed;
- reviewers confirm Registry Metadata has no Relay or Evidence Server runtime
  dependency;
- reviewers confirm Evidence Server has no Registry Relay dependency;
- the final completion review records commands run, results, skipped checks
  with reasons, residual risks, and follow-up issues.
