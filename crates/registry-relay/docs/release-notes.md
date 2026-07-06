# Release Notes

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
- Advanced the Crosswalk input, Registry Platform, and Registry Manifest to the
  versions used by the beta-3 train.
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
- Added governed runtime configuration apply, a Trust Ops posture endpoint, and
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

Deferred: remaining hardening work is tracked through normal issues and release
planning, not shipped release notes.

Known limits:

- Registry Relay does not execute claim or evidence verification. Evidence offerings are discovery records for Registry Notary.
- Admin reload reloads runtime resources, not `config.yaml`; config and keyring changes require a restart or rolling deploy.
- Row-level authorization is not available. Use dataset/entity scopes, required filters, purpose headers, explicit field projections, and audit redaction.
- `sensitive: true` controls audit redaction only; it does not hide fields from authorized API responses.
- Remote signing backends for signed response credentials are reserved for future work; V1 supports local software Ed25519 signing (config key `provenance`).
- The static OpenAPI artifact is an abstract contract. Deployments fetch `/openapi.json` for their concrete dataset/entity shape. The route is auth-gated by default unless `server.openapi_requires_auth` is disabled for demos or controlled tooling.
