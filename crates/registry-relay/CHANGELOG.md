# Changelog

## Unreleased

- Relay now publishes a reproducible, product-owned Draft 2020-12 schema for
  the complete runtime configuration. `registry-relay schema --format json`
  prints the committed artifact byte for byte, and local CI checks schema drift,
  maintained runtime fixtures, strict nested and tagged shapes, and exact
  bidirectional configuration-reference key paths. Schema and runtime parsing
  now share bounded listener-address and duration string grammars, integer
  widths have explicit JSON Schema bounds, and environment references reflect
  their consumer-specific runtime invariants.
- BREAKING: configuration `${VAR}` expansion now rejects environment variables
  that are unset or empty. `${VAR:-fallback}` uses its fallback for either
  state, `${VAR:-}` explicitly expands to empty, and `${VAR:?message}` reports
  its message for either state. Whitespace-only values remain non-empty.
- Relay now permanently reports `/ready` as unavailable with
  `audit.chain.inconsistent` after detecting a retained-chain verification
  failure or a write-time foreign append. Transient audit I/O failures retain
  their existing request-level policy and do not poison readiness.

## 0.10.0 - 2026-07-17

### Added

- Relay's restart-only consultation compiler now accepts the three
  product-neutral authored capabilities: one-request `http`, reviewed Rhai
  `script`, and immutable `snapshot`. Signed DCI and FHIR R4 behavior are
  reusable protocol facilities within `script`, not product-specific executor
  kinds. Every integration retains fixed source authority, closed typed
  outputs, bounded calls and bytes, Relay-owned credentials, and the existing
  authorization and audit gates.
- Immutable snapshot profiles now keep physical provider, table, key, and
  projection mappings in private bindings. Compatible profiles share one
  immutable materialization slot while readiness remains isolated per profile.
- Rhai scripts execute in fresh, environment-scrubbed child processes. The
  worker receives only typed inputs and the reviewed source authority, can use
  only the bounded `source` and `protocol` host facilities compiled for that
  integration, and returns a closed typed output map under fixed resource
  limits. Production activation is Linux-only and caps the worker address space
  at 128 MiB so the configured memory and process isolation are enforced by the
  operating system; non-Linux hosts retain only offline, authority-free
  conformance checks. Release images install the dedicated
  `registry-relay-rhai-worker` beside `registry-relay`. Standalone deployments
  must install both release assets in the same directory under those canonical
  executable names.
- Relay now owns the authority-free project fixture decoder. It compiles exact
  pinned profiles and reuses the production closed JSON, signed DCI,
  SnapshotExact, and Script paths while accepting only bounded source
  observations. Match results release only validated outputs; no-match and
  ambiguity release no output map.
- BREAKING: Relay now exposes restart-only, OIDC-protected
  `/v1/consultations/{profile_id}` and
  `/v1/consultations/{profile_id}/execute` APIs for the exact configured
  authorized OIDC workload. Every request binds the active generated
  `contract_hash` before source access. Generic HTTP, script, signed-DCI,
  FHIR, and snapshot journeys execute behind PostgreSQL quota, audit,
  dispatch-fence, and publication guarantees. Source product and tested-version
  metadata record interoperability evidence and never select behavior.
  Requests use one to eight required exact selector components, up to sixteen
  typed inputs in total, and a
  contract-enforced `Data-Purpose`; this remains one subject, not a subject
  batch. Public results use the closed `match`, `no_match`, or `ambiguous`
  envelope and the stable failure taxonomy, including
  `409 consultation.batch_child_conflict` for conflicting durable batch-child
  replay. The child identity stays private to Notary and Relay and is omitted
  from the public OpenAPI contract. Configuration and artifacts are
  restart-only, source and state-plane secrets remain environment-backed, and
  no generic proxy or caller-selected source operation is exposed.
- `registry-relay consultation bootstrap-state` installs or attests the
  Relay-owned PostgreSQL 16 through 18 consultation state plane before the
  first replica starts. It binds the schema, isolated owner/runtime/keyring
  roles, lifecycle settings, and audit-pseudonym key epoch without giving the
  serving process migration or key-maintenance credentials.

### Changed

- BREAKING: consultation acquisition schemas now preserve full dates as the
  typed `date` shape instead of encoding them as ten-byte strings. This changes
  typed artifact and contract hashes for profiles with date fields. Regenerate
  the public contract, integration pack, private binding, and Notary
  expectation, then deploy the matching Relay and Notary generation together.
- Private consultation-binding references now pin both canonical raw SHA-256
  and the domain-separated typed artifact hash. Startup verifies both before
  compilation. Legacy product-name inference for OAuth, JWKS, and DCI has been
  removed in favor of explicit reviewed primitives and codecs.
- Snapshot projection and response serialization derive Presence facts from
  the consultation outcome rather than requiring a physical presence column,
  keeping shared materializations and offline evidence on the same path.
- The maintained DHIS2 2.41.9 enrollment-status profile now uses a reviewed
  10-second absolute source deadline. The previous 5-second contract failed
  closed against the authorized integration instance before a terminal result.
  Notary now gives the complete internal service hop one fixed,
  non-configurable 25-second deadline. Consultation-enabled Relay requires its
  outer `server.request_timeout` to be greater than 25 seconds; Registry-backed
  Notary requires at least 30 seconds to preserve a five-second listener
  reserve. The profile remains one-shot, bounded, and retry-free, with all
  contract, pack, binding, and operator pins regenerated.
- The maintained OpenCRVS journey uses one 20-second absolute source deadline
  for its fresh OAuth token, fixed-origin JWKS, and signed DCI search sequence.
  All three calls share that one fence, retain an individual 10-second
  destination ceiling, remain retry-free, and fit inside the fixed 25-second
  Notary service hop.
- Consultation-state backup and restore is a whole-database, quiesced
  operation. Preserve the release, role provisioning, bootstrap inputs,
  audit-pseudonym key material, and lifecycle settings with the dump; restore
  into an empty isolated database and rerun `consultation bootstrap-state` with
  the same inputs before readiness. A snapshot that may predate acknowledged
  traffic remains quarantined until its durable consultation, quota, dispatch,
  materialization, and pseudonym state is reconciled.

## 0.9.0 - 2026-07-10

### Added

- Accepted boots are now loud about reduced posture: warn logs identify
  waiver-suppressed deployment gate findings and expired waivers, and a
  boot-time operational audit record (`deployment.gate_waived`) is written per
  waived gate.
- Local, in-process auth-failure throttle (`auth.failure_throttle`), disabled
  by default. When enabled, repeated authentication failures from one client
  address within a configured window return a stable 429
  (`auth.rate_limited`) with a `Retry-After` header before the auth provider
  runs. This is a backstop behind ingress rate limiting, not a replacement
  for it; see `docs/configuration.md` for the deployment posture.
- `deployment.evidence.audit_offhost_shipping` attestation and the
  `relay.audit.retention_local_only` deployment gate: a local rotating `file`
  audit sink without a declared off-host shipping attestation now warns under
  `production` and refuses startup under `evidence_grade`, surfacing and
  blocking the declared local-only retention risk. `stdout` and `syslog` sinks
  are exempt.
- `registry-relay audit quarantine --config <path> --reason <text>
  --operator <id>`: offline recovery for a corrupt or forked audit chain
  (#196). The corrupt file set is archived to `<name>.corrupt-<ts>` (never
  deleted), a fresh chain starts whose first record is a hash-linked
  `audit.chain.break` event chained onto the last verifiable tail. Recovery
  refuses to run while a live server holds the audit writer lock.
- Startup now eagerly verifies the retained audit chain when the `file` sink
  is configured. On an inconsistent chain the process stays up but `/ready`
  returns `503` with the stable code `audit.chain.inconsistent` until an
  operator runs `registry-relay audit quarantine`.
- `registry-relay doctor`'s JSON report now carries an `audit_shipping`
  object (`sink_type`, `shipping_target_configured`, `shipping_target`) when
  the config parses, mirroring the posture `audit` shipping fields.
- `deployment.evidence.audit_ack_cursor_path` and
  `deployment.evidence.audit_ack_max_age_secs` config fields: point Relay at
  the local state file an off-host audit shipper writes on each successful
  hand-off (`registry.audit.ack_cursor.v1`), and set how old the cursor's
  `acked_at` timestamp may get before it reads as stale (defaults to 900s).
  Config load rejects `audit_ack_max_age_secs` set without
  `audit_ack_cursor_path`, and rejects `audit_ack_cursor_path` set on a local
  `file` audit sink that has not declared `audit_offhost_shipping`; a
  `stdout`/`syslog` sink may carry a cursor without that declaration.
- Two new deployment gates read the ack cursor's observed health:
  `relay.audit.shipping_unverified` (a shipping target is configured but no
  ack cursor is configured; `finding_warn` under `production`,
  `startup_fail` under `evidence_grade`, unbound under `hosted_lab`) and
  `relay.audit.shipping_stale` (a cursor is configured but its observed
  health is not `ok`, including a watermark that differs from the live keyed
  chain tail; `finding_error` under `production`, `readiness_fail`
  (non-waivable) under `evidence_grade`, unbound under `hosted_lab`).
- `registry-relay doctor`'s `audit_shipping` object and the admin `posture.audit`
  block both gain `shipping_health` (`ok`, `stale`, `missing`, `invalid`,
  `unverified`, or `null`) and `shipping_observed_at` (an RFC3339 timestamp, or
  `null`), the observed freshness of off-host audit shipping read from the ack
  cursor. Both are `null` whenever `shipping_target_configured` is `false`.
  Runtime `ok` requires a fresh cursor bound to the current keyed chain tail;
  offline doctor output remains `unverified` because it has no live chain to
  bind. Tail equality establishes a zero local backlog for the trusted
  shipper's claim, not cryptographic proof of remote receipt.
- Runtime cursor reads use one blocking worker with a 500 ms deadline. A slow
  or stalled cursor filesystem fails readiness without blocking async request
  workers or accumulating additional blocked cursor readers. The cursor must
  be a regular file of at most 16 KiB and must be replaced atomically by the
  shipper.
- A signed-bundle boot writes `config.bundle_accepted` before the service begins
  serving. Evidence-grade readiness remains `503` until the independent shipper
  acknowledges that new tail. Offline `registry-relay doctor` cannot perform
  live tail binding, so a fresh cursor remains `unverified` and the offline
  evidence-grade check reports the hard shipping gate.

### Changed

- BREAKING: `deployment.profile` is required and must be one of `local`,
  `hosted_lab`, `production`, or `evidence_grade`. Relay does not infer a
  profile and refuses startup when it is absent. Add the explicit profile that
  matches the deployment before upgrading.
- BREAKING: The TUF-era `/admin/v1/config/verify`,
  `/admin/v1/config/dry-run`, and `/admin/v1/config/apply` endpoints are
  removed, as is the CLI `config apply-bundle` command. First run
  `registryctl bundle verify` for stateless signature and binding verification,
  then place the signed Registry Config Bundle v1 on the Relay node. For a
  genuinely absent, version-specific antirollback state path, start Relay with
  `--initialize-state`; that boot verifies the bundle and initializes state.
  Relay's read-only `config verify-bundle` command remains, but it requires
  accepted state to exist, so use it only for later candidate validation and
  restarts. Replace retired TUF-era fields inside `config_trust` with the
  current Config Bundle v1 trust fields; strict parsing rejects the old
  schema. There is no hot-apply path. Back up
  `config_trust.antirollback_state_path` before upgrading and keep
  release-specific restore sets. Before rollback, restore the antirollback
  state matching that release. Never delete or reinitialize state to force an
  older bundle to load.
- BREAKING: `audit.include_health: true` now includes `/healthz` only.
  `/ready` is always excluded because appending a readiness audit record after
  its zero-backlog comparison would invalidate the next readiness probe.
  Evidence consumers must capture the readiness response, authenticated
  posture, and acknowledgement cursor instead of expecting a `/ready` audit
  record.

- BREAKING: Governed reads now ignore `x-registry-subject-ref`,
  `x-registry-relationship`, `x-registry-on-behalf-of`, and
  `x-registry-credential-format`, and
  `x-registry-source-observed-at-unix-seconds` unless the authenticated
  principal has the corresponding exact value-bound scope:
  `registry:trust:subject_ref:<value>`,
  `registry:trust:relationship:<value>`,
  `registry:trust:on_behalf_of:<value>`,
  `registry:trust:requested_credential_format:<value>`, or
  `registry:trust:source_observed_at_unix_seconds:<value>`. These optional
  trust-context fields are scope-gated before policy evaluation. Audit records
  retain ordinary route scopes in `scopes_used`, replace each value-bearing
  trust scope with a field-bound
  `registry:trust:<field>:hmac-sha256:<digest>` handle under the deployment
  audit key, and record authenticated trust-context field names in
  `pdp_trust_provenance` without their values.
- BREAKING: Removed Relay-local credential issuance before 1.0. Relay no
  longer accepts `provenance` or entity `publicschema` config, no longer serves
  `/.well-known/did.json`, `/schemas/{claim_type}/{version}`, or
  `/contexts/{vocab}/{version}`, and no longer returns `application/vc+jwt`.
  Use Registry Notary for credential issuance and verification.
- The beta `attribute-release` API and `attribute_release_profiles` config
  surface are now behind the off-by-default `attribute-release` Cargo feature.
  The 1.0 default build no longer serves or advertises those routes.
- The committed OpenAPI artifact is generated from the default build shape and
  now includes the admin listener's table-specific ingest reload route.
- The rotating `file` audit sink now takes a process-lifetime advisory
  single-writer lock on `<path>.lock`, and each append verifies the on-disk
  tail before writing. A second Relay process pointed at the same audit file
  fails at startup instead of silently interleaving writes and forking the
  hash chain, and a write that would extend a diverged chain fails closed.
- BREAKING: A deployment waiver naming a hard gate (a gate whose severity
  under the active profile is `readiness_fail` or `startup_fail`) now fails
  config load instead of being silently accepted and ignored at evaluation,
  with a per-gate remediation message; there is no config-level override for
  a non-waivable gate. This aligns Relay with Notary, where `readiness_fail`
  gates were already non-waivable. Under `evidence_grade`,
  `relay.audit.retention_local_only` is `startup_fail`. Also newly
  non-waivable: `relay.admin.public_exposure` and `relay.audit.sink_missing`
  under `production` (`readiness_fail` there), and
  `relay.oidc.client_allowlist_empty` and `relay.audit.best_effort` under
  `evidence_grade` (`readiness_fail` there). Migration: remove the waiver and
  fix the condition instead (bind the admin listener to a loopback address,
  configure a durable audit sink, populate `auth.oidc.allowed_clients`, set
  `audit.write_policy` to a durability-first policy, or, for
  `relay.audit.retention_local_only`, ship audit events off-host and declare
  `deployment.evidence.audit_offhost_shipping: true` or switch to a
  `stdout`/`syslog` sink). An `evidence_grade` deployment must also configure
  `deployment.evidence.audit_ack_cursor_path` for every sink type.

## 0.8.4 - 2026-07-04

### Added

- `registry-relay --version` and `registry-relay -V` output so the Relay binary
  matches the stack's user-facing version command convention, ignoring any
  trailing arguments to mirror the clap-based binaries.

### Changed

- BREAKING: API-key fingerprint config no longer accepts `fingerprint.commitment`.
  Remove that field from Relay YAML.
  Config should keep `fingerprint.provider` with `fingerprint.name` or `fingerprint.path`;
  the referenced env var or file must contain `sha256:<64 lowercase hex chars>`.

## 0.4.0 - 2026-06-21

### Added

- Governed identity attribute release profiles for Evidence Gateway and
  cross-registry attribute-release scenarios.
- A config-schema command and shared config-report output alignment with the
  beta-3 Platform config contracts.

### Changed

- Advanced the Crosswalk input to the `0.2.0` release ref used by the beta-3
  train.
- Advanced Registry Platform to `0.3.1` and Registry Manifest to `0.2.1` for
  the beta-3 train.
- Updated Relay operational docs and API description text to match the current
  beta-3 surface.

### Security

- Default audit write failures to fail-closed; `availability_first` is now an
  explicit best-effort opt-out.
- Fail closed when source size is unknown.
- Cap CSV column and cell counts, cap SP DCI search-request item fan-out, and
  bound OGC EDR area geometry scans.
- Redact URL userinfo and hard secret markers in config explanation output.

## 0.3.0 - 2026-06-13

### Added

- **Deployment profile gates, posture findings, and audit write policy** (#128–#130,
  PR #136): profile-aware gates, deployment posture findings, and a configurable
  audit write policy (`availability_first` default, `fail_closed`). A `doctor`
  command reports gate status (PR #137).
- **Durable break-glass approvals** (#138, PR #140): emergency approvals backed by a
  durable multi-approver store; the default tier emits the emergency posture block
  without reason or identity material.

### Security

- Fail and redact `doctor` readiness-gate findings; preflight fail-closed admin
  mutations; authorize admin JSON before parsing; and harden static-metadata server
  concurrency (PR #143).

### Fixed

- Release pipeline: verify release tag ancestry via the compare API (PR #122);
  neutralize a local-dev `ld64.lld` override in macOS binary builds (PR #123);
  set `GH_REPO` so the release publish job resolves the repository (PR #125);
  and bind the release-ancestry check to the protected `main` SHA (PR #142).
- Strengthen non-Unix file ETags; prefer the curated manifest for the base DCAT;
  and preserve `=` in perf env exports and the active shell in the perf gate check
  (PR #143).

## 0.2.0 - 2026-06-12

### Changed

- BREAKING: Aggregate and StatDCAT responses adopt SDMX/StatDCAT-aligned
  vocabulary throughout. The aggregate payload renames `data` -> `observations`,
  `schema` -> `structure`, and `indicator` -> `measures`; aggregates negotiate an
  SDMX-JSON 2.1 representation
  (`Accept: application/vnd.sdmx.data+json;version=2.1` / `?f=sdmx-json`); and
  DCAT advertises a separate distribution per visible aggregate representation
  (#83).
- BREAKING: `/metrics` on the admin listener now requires authentication with
  the `registry_relay:metrics_read` scope. Previously the route was served
  unauthenticated on the admin socket. Existing Prometheus scrapers must
  present a credential carrying that scope.
- BREAKING: Health and readiness response bodies changed shape.
  `/healthz` (and the liveness route) previously returned `{"status":"ok"}`;
  it now returns `{"status":"ok","checks":{"total":...,"ok":...,"failed":...}}`.
  `/ready` previously included `"counts":{"ready":N}` in the 200 body; that
  field is replaced by the same `checks` structure.
- ProblemDetails error bodies now always include a `request_id` field
  (a server-minted ULID; client-supplied `x-request-id` headers are stripped
  before processing). The OpenAPI `ProblemDetails` schema marks `request_id`
  required.
- Renamed OIDC config fields to the shared Registry service convention:
  `auth.oidc.audience` -> `auth.oidc.audiences`,
  `auth.oidc.algorithms` -> `auth.oidc.allowed_algorithms`, and
  `auth.oidc.token_types` -> `auth.oidc.allowed_token_types`. Old names fail
  config load with an error naming the replacement.
- Added `${VAR}` / `${VAR:-default}` / `${VAR:?message}` expansion,
  `--env-file` / `REGISTRY_RELAY_ENV_FILE`, and `--bind` /
  `REGISTRY_RELAY_BIND` support. The bind override applies after YAML
  validation; `server.bind` remains required in config.
- BREAKING: Aggregate responses now use `observations`, `structure`, and
  `measures` as the public vocabulary. `/metadata` remains a deprecated alias
  for aggregate `/structure`, and `indicators` remains a deprecated request
  alias where accepted.
- BREAKING: Measure discovery responses now spell the unit-multiplier field
  `unit_multiplier`, matching the aggregate list and structure responses. The
  previous `unit_mult` key on `/v1/datasets/{dataset_id}/measures` and
  `/v1/datasets/{dataset_id}/measures/{measure_id}` is removed.
- BREAKING: The aggregate `disclosure_control` block now reports suppression
  counts only under `suppressed_observations`. The duplicate `suppressed_rows`
  key is removed from both the native aggregate JSON responses and the OGC EDR
  GeoJSON responses.
- BREAKING: Aggregate JSON responses now include an `alternate` link pointing
  at the SDMX representation (`?f=sdmx-json`, type
  `application/vnd.sdmx.data+json;version=2.1`) alongside the existing `self`
  and `describedby` links.
- Aggregate queries now support CSV and SDMX JSON 2.1 representations, including
  `Accept: text/csv` and `Accept: application/vnd.sdmx.data+json;version=2.1`.
  Truncated aggregate results carry an explicit completeness signal.
- DCAT aggregate distributions now advertise each visible aggregate
  representation separately, including OGC EDR `/area` links for configured
  spatial aggregates when the `ogcapi-edr` feature is enabled.
- `/.well-known/api-catalog` is now served publicly, without authentication,
  per RFC 9727 (#120, closes #86).
- Live config apply now compares config sections semantically rather than by
  byte-for-byte text, so equivalent reorderings no longer force a restart (#115,
  #52).
- The file-watch signer now derives content identity from a SHA-256 hash of the
  key file, detecting same-mtime key replacements that the previous mtime check
  missed (#116, #54).

### Added

- API-key commitment generator CLI for minting reviewed key commitments without
  exposing raw keys (#103, #80).
- OpenAPI contract gate: the runtime OpenAPI document is committed as an artifact
  and CI fails on undocumented drift, with `oasdiff` breaking-change detection
  and a `redocly lint` lint gate (#104, #112).
- Performance gate: CI enforces relay perf thresholds and runs a k6 perf smoke,
  with the `pull_request` perf-smoke trigger restored (#101, #109, #113).
- Governed runtime configuration apply, Trust Ops posture endpoint, and listener
  topology capability reporting (#51, #49, #61).

### Security

- Image supply-chain hardening: distroless release image, signed and verified
  release publishing, SHA-pinned workflow actions, and reviewed advisory ratchet
  gates (#100, #41, #44, #38).
- Admin auth extractors tightened and admin route hygiene enforced (#102).
- OpenAPI auth surface aligned: the docs shell now declares `security: []` and
  the API-key header casing is normalized to lowercase `x-api-key` (#112, #65,
  closes #110).
- Security headers (including CSP) are emitted from both the demo static
  metadata server and relay responses, with end-to-end pins (#118, #87, #88).

### Fixed

- Route-metrics classification corrected: `measures`/`dimensions` route patterns
  classify as dataset routes, and the unmounted verify/aggregate-POST routes are
  no longer classified or advertised (#117, #111, #79, #78).

## 0.1.0 - 2026-05-16

Initial V1 release of `registry-relay`, a controlled, read-only registry relay for publishing protected, entity-shaped APIs over local CSV, XLSX, and Parquet sources.

### Included

- Config-driven datasets, private storage tables, public domain entities, field projection, relationships, required filters, and scope-separated metadata, row, aggregate, evidence-verification, and admin capabilities.
- API-key authentication with SHA-256 fingerprints supplied through environment variables. Raw keys never appear in config.
- Entity collection, record, relationship, schema, evidence-offering metadata, and configured aggregate endpoints with per-entity authorization and purpose-header enforcement.
- Catalog, DCAT-AP JSON-LD, embedded SHACL shape metadata, best-effort OpenAPI 3.1 generation, and the local `/docs` Scalar API reference shell.
- Startup ingest, refresh loops, manual table reload, readiness reporting, source size guards, and local-file metadata captured from opened file handles.
- JSON operational logging and JSONL audit sinks for stdout, file, and syslog, with optional hash chaining and redacted sensitive query values.
- Container build support, operations documentation, demo configuration/data, Bruno demo requests, and focused integration/security regression tests.

### Deferred

- Remaining hardening work is tracked through normal issues and release planning, not shipped review notes.
