# Changelog

## Unreleased

### Added

- Boot is now loud about reduced posture: warn logs for waiver-suppressed
  deployment gate findings, expired waivers, and an undeclared deployment
  profile, plus a boot-time operational audit record (`deployment.gate_waived`)
  per waived gate.
- Local, in-process auth-failure throttle (`auth.failure_throttle`), disabled
  by default. When enabled, repeated authentication failures from one client
  address within a configured window return a stable 429
  (`auth.rate_limited`) with a `Retry-After` header before the auth provider
  runs. This is a backstop behind ingress rate limiting, not a replacement
  for it; see `docs/configuration.md` for the deployment posture.
- `deployment.evidence.audit_offhost_shipping` attestation and the
  `relay.audit.retention_local_only` deployment gate: a local rotating `file`
  audit sink without a declared off-host shipping attestation now raises a
  posture finding (warn under `production`, error under `evidence_grade`) so
  an attacker with host access cannot silently destroy audit evidence.
  `stdout` and `syslog` sinks are exempt. The gate is waivable.
- `registry-relay audit quarantine --config <path> --reason <text>
  --operator <id>`: offline recovery for a corrupt or forked audit chain
  (#196). The corrupt file set is archived to `<name>.corrupt-<ts>` (never
  deleted), a fresh chain starts whose first record is a hash-linked
  `audit.chain.break` event chained onto the last verifiable tail, and a
  local `<path>.anchor.json` records the trusted start hash as operator
  evidence. Recovery refuses to run while a live server holds the audit
  writer lock.
- Startup now eagerly verifies the retained audit chain when the `file` sink
  is configured. On an inconsistent chain the process stays up but `/ready`
  returns `503` with the stable code `audit.chain.inconsistent` until an
  operator runs `registry-relay audit quarantine`.

### Changed

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
