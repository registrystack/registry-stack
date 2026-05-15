# Changelog

## 1.0.0 - 2026-05-15

Initial V1 release of `data_gate`, a controlled, read-only data gateway for publishing protected, entity-shaped APIs over local CSV, XLSX, and Parquet sources.

### Included

- Config-driven datasets, private storage tables, public domain entities, field projection, relationships, required filters, and scope-separated metadata, row, aggregate, verify, and admin capabilities, with bulk-export scopes reserved for the V1.x contract.
- API-key authentication with Argon2id PHC hashes supplied through environment variables.
- Entity collection, record, relationship, schema, verify, and configured aggregate endpoints with per-entity authorization and purpose-header enforcement.
- Catalog, DCAT-AP JSON-LD, embedded SHACL shape metadata, and best-effort OpenAPI 3.1 generation.
- Startup ingest, refresh loops, manual table reload, readiness reporting, source size guards, and local-file metadata captured from opened file handles.
- JSON operational logging and JSONL audit sinks for stdout, file, and syslog, with optional hash chaining and redacted sensitive query values.
- Container build support, operations documentation, demo configuration/data, Bruno demo requests, and focused integration/security regression tests.

### Deferred

- Registry-wide `POST /admin/reload` remains reserved and returns `501 admin.reload_unavailable`.
- Bulk export endpoints are contract-locked for V1.x and are not implemented in 1.0.0.
- Remaining hardening backlog is tracked in `docs/security-review-2026-05-15.md`.
