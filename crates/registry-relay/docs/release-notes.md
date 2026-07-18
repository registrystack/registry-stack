# Release Notes

## Unreleased

## 0.11.0

- BREAKING: Configuration `${VAR}` expansion now rejects environment variables
  that are unset or empty. `${VAR:-fallback}` uses its fallback for either
  state, `${VAR:-}` explicitly expands to empty, and `${VAR:?message}` reports
  its message for either state. Whitespace-only values remain non-empty.
- Relay permanently marks public readiness unavailable with the stable
  `audit.chain.inconsistent` code after retained-audit-chain verification or
  write-time fork detection. Transient audit I/O failures do not change
  readiness.
- Relay reports bounded authoring diagnostics for unknown or incorrectly
  called Script host functions, including the first call location and closest
  valid signatures. Diagnostic output does not include authored argument
  values.
- Sending both `Authorization` and `x-api-key` now fails before credential
  parsing with `auth.multiple_credentials`. The response and audit outcome do
  not disclose whether either candidate credential was valid.

## 0.10.0

- Registry Stack project authoring now compiles product-neutral `http`, `script`, and `snapshot`
  integrations. Source product and version labels are interoperability evidence only. They never
  select a Relay executor or enable Rhai. The unreleased country-named authoring API and its
  compatibility aliases are removed.
- The `http` capability performs one bounded request and projects a closed typed output map while
  ignoring unselected upstream fields. The `script` capability runs one reviewed Rhai adapter with
  the interactive `source.path`, `source.get`, `source.post_json`, and `source.post_form` host API.
  Every source request is checked against the same-origin method and path authority before Relay
  resolves credentials or dispatches it.
- Rhai source responses expose bounded JSON or text plus explicitly selected safe headers.
  Returned absolute links can be followed only after same-origin canonicalization and the ordinary
  path, method, header, request, response, call, and deadline checks. Scripts use
  `result.match`, `result.no_match`, `result.ambiguous`, or a fixed failure constructor rather than
  selecting named declarative operations.
- Script consultations default to five source calls and cannot exceed sixteen. Relay commits each
  complete credential-free request effect before dispatch and consumes a durable ordinal permit.
  A crash, cancellation, takeover, or lost acknowledgement cannot replay a dispatched ordinal.
- Snapshot integrations perform exact lookups against an entity-owned immutable materialization.
  The same entity may be exposed through a records service, but records publication is optional and
  keeps its own access, purpose, projection, filter, and pagination policy.
- Production Rhai activation is Linux-only because Relay requires the
  Linux process memory, process-count, and no-new-privileges sandbox in addition
  to engine and IPC limits. Offline script compilation and fixture conformance
  remain available on other platforms without source or credential authority.
  The worker address-space hard maximum is 128 MiB. Release images install the
  dedicated `registry-relay-rhai-worker` beside `registry-relay`; standalone
  deployments must install both release assets in the same directory under
  those canonical executable names.
- Project fixture runs now compile and execute through Relay-owned closed
  decoders for HTTP, script, and exact snapshot integrations.
  Fixtures cannot supply a destination, credential, callback, or worker
  command, and no-match or ambiguous outcomes disclose no output map.
- A consultation request carries one to sixteen typed scalar inputs, including
  one to eight non-null selectors for one subject. The route exposes one active
  contract per profile id and every execution pins its exact `contract_hash`.
  `match` returns only the profile's closed typed output map, while `no_match`
  and `ambiguous` omit `outputs`. Registry-backed batch retries use a
  private Notary-to-Relay child identity; that header is not part of the public
  OpenAPI contract, and conflicting durable reuse returns
  `409 consultation.batch_child_conflict`.
- BREAKING: consultation inputs declared as `date` now remain typed dates
  instead of ten-byte strings. This changes typed artifact and
  `contract_hash` values for affected profiles. Regenerate the public
  contract, integration pack, private binding, and Notary expectation, then
  deploy the matching Relay and Notary generation together.
- Consultation execution requires a separately owned PostgreSQL 16 through 18
  state plane. A DBA provisions the database and isolated migration, owner,
  runtime, keyring-maintenance, and keyring-reader roles, then runs
  `registry-relay consultation bootstrap-state` before starting the first
  replica. Serving replicas receive only the runtime credential.
- Back up the complete consultation database only after quiescing writers, and
  retain its release, role provisioning, bootstrap inputs, lifecycle settings,
  and audit-pseudonym key material. Restore into an empty isolated database,
  rerun `consultation bootstrap-state` with the same inputs, and require a
  complete readiness attestation before traffic. Keep any potentially stale
  restore quarantined until acknowledged durable state is reconciled.
- Maintained DHIS2 and OpenCRVS profiles now fit their complete multi-call work
  inside fixed absolute deadlines. Notary uses a fixed 25-second internal
  service hop, so consultation-enabled Relay requires
  `server.request_timeout` greater than 25 seconds and Registry-backed Notary
  requires at least 30 seconds.
- `contract_hash` is the single public content identity for one active profile contract. Lower-level
  build and binding digests remain internal. Product Config Bundle input directories remain
  separate; a signed project-level deployment root that binds Relay and Notary submanifests is
  future work.

## 0.9.0

- BREAKING: Relay-local credential issuance and its `provenance` and entity
  `publicschema` configuration are removed. Deploy credential issuance and
  verification through Registry Notary.
- BREAKING: `deployment.profile` is required and must be one of `local`,
  `hosted_lab`, `production`, or `evidence_grade`. Relay refuses startup when
  it is absent instead of inferring a profile.
- BREAKING: the TUF-era `/admin/v1/config/verify`,
  `/admin/v1/config/dry-run`, and `/admin/v1/config/apply` endpoints are
  removed, as is the CLI `config apply-bundle` command. First run
  `registryctl bundle verify` for stateless signature and binding verification,
  then place the signed Registry Config Bundle v1 on the Relay node. For a
  genuinely absent, version-specific antirollback state path, start Relay with
  `--initialize-state`; that boot verifies the bundle and initializes state.
  Relay's read-only `config verify-bundle` command remains, but it requires
  accepted state to exist, so use it only for later candidate validation and
  restarts. Replace retired TUF-era fields inside `config_trust` with current
  Config Bundle v1 trust fields because strict parsing rejects the old schema.
  Hot apply is not supported. Back up
  `config_trust.antirollback_state_path` before upgrading and keep
  release-specific restore sets. Before rollback, restore the antirollback
  state matching that release. Never delete or reinitialize state to force an
  older bundle to load.
- BREAKING: governed reads honor `x-registry-subject-ref`,
  `x-registry-relationship`, `x-registry-on-behalf-of`, and
  `x-registry-credential-format`, and
  `x-registry-source-observed-at-unix-seconds` only when the authenticated
  principal carries the corresponding exact value-bound scope:
  `registry:trust:subject_ref:<value>`,
  `registry:trust:relationship:<value>`,
  `registry:trust:on_behalf_of:<value>`,
  `registry:trust:requested_credential_format:<value>`, or
  `registry:trust:source_observed_at_unix_seconds:<value>`. Without that scope,
  the header is treated as absent before policy evaluation.
- BREAKING: hard deployment gates cannot be waived. Production and
  evidence-grade operators must correct the failing condition, configure
  off-host audit shipping, and provide a fresh acknowledgement cursor where
  required.
- The beta attribute-release API is excluded from default builds and requires
  the `attribute-release` Cargo feature.
- The committed OpenAPI artifact now matches the default build and no longer
  advertises the feature-gated OGC API or SP DCI routes. Deployments using
  those routes must enable the matching Cargo features and publish an OpenAPI
  document generated from that build.
- Added local authentication-failure throttling, retained-chain verification
  and quarantine recovery, audit-shipping health, and generated config-bundle
  acceptance evidence.
- BREAKING: `audit.include_health: true` includes `/healthz` only. `/ready` is
  always excluded because logging readiness would invalidate the next
  zero-backlog comparison. Evidence consumers must capture the readiness
  response, authenticated posture, and acknowledgement cursor instead of
  expecting a `/ready` audit record.

## 0.8.4

- Added `registry-relay --version` and `registry-relay -V` output, matching the stack's
  version command convention.
- BREAKING: API-key fingerprint config no longer accepts `fingerprint.commitment`. Remove
  that field from Relay YAML. Config must keep `fingerprint.provider` with
  `fingerprint.name` or `fingerprint.path`, and the referenced env var or file must
  contain `sha256:<64 lowercase hex chars>`.

## 0.4.0

- Added governed identity attribute release profiles for Evidence Gateway and
  cross-registry attribute-release scenarios.
- Added a config-schema command and shared config-report output, aligned with the
  beta-3 Platform config contracts.
- Advanced the Crosswalk input to 0.2.0, Registry Platform to 0.3.1, and Registry
  Manifest to 0.2.1, the versions used by the 0.4.0 release.
- Updated Relay operational docs and API description text alongside the release.
- BREAKING: Audit write failures now default to fail-closed. `availability_first` is
  an explicit best-effort opt-out.
- Fail closed when source size is unknown.
- Capped CSV column and cell counts, capped SP DCI search-request item fan-out, and
  bounded OGC EDR area geometry scans.
- Redacted URL userinfo and hard secret markers in config explanation output.

## 0.3.0

- Added deployment profile gates, deployment posture findings, and a configurable
  audit write policy (`availability_first` default, `fail_closed`). A `doctor`
  command reports gate status.
- Added durable break-glass approvals: emergency approvals backed by a durable
  multi-approver store. The default tier emits the emergency posture block without
  reason or identity material.
- Fail and redact `doctor` readiness-gate findings; preflight fail-closed admin
  mutations; authorize admin JSON before parsing; harden static-metadata server
  concurrency.
- Fixed release-pipeline ancestry verification and several build and environment
  issues, including non-Unix file ETags, curated manifest preference for the base
  DCAT, and preserved `=` handling in perf env exports.

## 0.2.0

- BREAKING: Aggregate and StatDCAT responses adopt SDMX/StatDCAT-aligned
  vocabulary throughout. The aggregate payload renames `data` to `observations`,
  `schema` to `structure`, and `indicator` to `measures`. Aggregates can negotiate
  an SDMX-JSON 2.1 representation (`Accept: application/vnd.sdmx.data+json;version=2.1`
  or `?f=sdmx-json`), and DCAT advertises a separate distribution per visible
  aggregate representation. `/metadata` remains a deprecated alias for aggregate
  `/structure`, and `indicators` remains a deprecated request alias where accepted.
- BREAKING: `/metrics` on the admin listener now requires authentication with the
  `registry_relay:metrics_read` scope. The route was previously served
  unauthenticated on the admin socket. Existing Prometheus scrapers must present a
  credential carrying that scope.
- BREAKING: Health and readiness response bodies changed shape. `/healthz` (and the
  liveness route) previously returned `{"status":"ok"}`; it now returns
  `{"status":"ok","checks":{"total":...,"ok":...,"failed":...}}`. `/ready`
  previously included `"counts":{"ready":N}` in the 200 body; that field is
  replaced by the same `checks` structure.
- BREAKING: Measure discovery responses spell the unit-multiplier field
  `unit_multiplier`, matching the aggregate list and structure responses. The
  previous `unit_mult` key on `/v1/datasets/{dataset_id}/measures` and
  `/v1/datasets/{dataset_id}/measures/{measure_id}` is removed.
- BREAKING: The aggregate `disclosure_control` block reports suppression counts
  only under `suppressed_observations`. The duplicate `suppressed_rows` key is
  removed from both the native aggregate JSON responses and the OGC EDR GeoJSON
  responses.
- BREAKING: Aggregate JSON responses now include an `alternate` link pointing at
  the SDMX representation, alongside the existing `self` and `describedby` links.
- ProblemDetails error bodies now always include a `request_id` field (a
  server-minted ULID; client-supplied `x-request-id` headers are stripped before
  processing). The OpenAPI `ProblemDetails` schema marks `request_id` required.
- Renamed OIDC config fields to the shared Registry service convention:
  `auth.oidc.audience` to `auth.oidc.audiences`, `auth.oidc.algorithms` to
  `auth.oidc.allowed_algorithms`, and `auth.oidc.token_types` to
  `auth.oidc.allowed_token_types`. Old names fail config load with an error naming
  the replacement.
- Added `${VAR}`, `${VAR:-default}`, and `${VAR:?message}` expansion,
  `--env-file` and `REGISTRY_RELAY_ENV_FILE`, and `--bind` and
  `REGISTRY_RELAY_BIND` support. The bind override applies after YAML validation;
  `server.bind` remains required in config.
- Aggregate queries now support CSV and SDMX JSON 2.1 representations, including
  `Accept: text/csv` and `Accept: application/vnd.sdmx.data+json;version=2.1`.
  Truncated aggregate results carry an explicit completeness signal.
- DCAT aggregate distributions now advertise each visible aggregate representation
  separately, including OGC EDR `/area` links for configured spatial aggregates
  when the `ogcapi-edr` feature is enabled.
- `/.well-known/api-catalog` is now served publicly, without authentication, per
  RFC 9727.
- Live config apply now compares config sections semantically rather than
  byte-for-byte, so equivalent reorderings no longer force a restart.
- The file-watch signer now derives content identity from a SHA-256 hash of the
  key file, detecting same-mtime key replacements that the previous mtime check
  missed.
- Added an API-key commitment generator CLI for minting reviewed key commitments
  without exposing raw keys.
- Added an OpenAPI contract gate: the runtime OpenAPI document is committed as an
  artifact, and CI fails on undocumented drift, with `oasdiff` breaking-change
  detection and a `redocly lint` gate.
- Added a performance gate: CI enforces relay perf thresholds and runs a k6 perf
  smoke test.
- Added governed runtime configuration apply, an operations posture endpoint, and
  listener topology capability reporting.
- Image supply-chain hardening: distroless release image, signed and verified
  release publishing, SHA-pinned workflow actions, and reviewed advisory ratchet
  gates.
- Tightened admin auth extractors and enforced admin route hygiene.
- Aligned the OpenAPI auth surface: the docs shell declares `security: []`, and
  the API-key header casing is normalized to lowercase `x-api-key`.
- Security headers, including CSP, are emitted from both the demo static metadata
  server and relay responses, with end-to-end pins.
- Route-metrics classification corrected: `measures` and `dimensions` route
  patterns classify as dataset routes, and the unmounted verify and
  aggregate-POST routes are no longer classified or advertised.

## 0.1.0

Initial V1 release of `registry-relay`, a controlled, read-only registry relay for
publishing protected, entity-shaped APIs over local CSV, XLSX, and Parquet sources.

- Added config-driven datasets, private storage tables, public domain entities,
  field projection, relationships, required filters, and scope-separated metadata,
  row, aggregate, evidence-verification, and admin capabilities.
- Added API-key authentication with SHA-256 fingerprints supplied through
  environment variables. Raw keys never appear in config.
- Added entity collection, record, relationship, schema, evidence-offering
  metadata, and configured aggregate endpoints with per-entity authorization and
  purpose-header enforcement.
- Added catalog, DCAT-AP JSON-LD, embedded SHACL shape metadata, best-effort
  OpenAPI 3.1 generation, and the local `/docs` Scalar API reference shell.
- Added startup ingest, refresh loops, manual table reload, readiness reporting,
  source size guards, and local-file metadata captured from opened file handles.
- Added JSON operational logging and JSONL audit sinks for stdout, file, and
  syslog, with optional hash chaining and redacted sensitive query values.
- Added container build support, operations documentation, demo
  configuration/data, Bruno demo requests, and focused integration/security
  regression tests.

Known limits:

- Registry Relay does not execute claim or evidence verification. Evidence offerings are discovery records for Registry Notary.
- Admin reload reloads runtime resources, not `config.yaml`; config and keyring changes require a restart or rolling deploy.
- Row-level authorization is not available. Use dataset/entity scopes, required filters, purpose headers, explicit field projections, and audit redaction.
- `sensitive: true` controls audit redaction only; it does not hide fields from authorized API responses.
- Registry Relay does not issue response credentials or host DID documents. Use Registry Notary for credential issuance and verification.
- The static OpenAPI artifact is an abstract contract. Deployments fetch `/openapi.json` for their concrete dataset/entity shape. The route is auth-gated by default unless `server.openapi_requires_auth` is disabled for demos or controlled tooling.
