# Changelog

## Unreleased

### Changed

- Renamed OIDC config fields to the shared Registry service convention:
  `auth.oidc.audience` -> `auth.oidc.audiences`,
  `auth.oidc.algorithms` -> `auth.oidc.allowed_algorithms`, and
  `auth.oidc.token_types` -> `auth.oidc.allowed_token_types`. Old names fail
  config load with an error naming the replacement.
- Added `${VAR}` / `${VAR:-default}` / `${VAR:?message}` expansion,
  `--env-file` / `REGISTRY_RELAY_ENV_FILE`, and `--bind` /
  `REGISTRY_RELAY_BIND` support. The bind override applies after YAML
  validation; `server.bind` remains required in config.

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
