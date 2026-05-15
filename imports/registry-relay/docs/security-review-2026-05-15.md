# Data Gate Security Review

Date: 2026-05-15

Scope: review of the current `data_gate` working tree, including the uncommitted changes present at review time. The review focused on authorization and scope isolation, disclosure controls, API input validation, audit integrity, secret handling, dependency and supply-chain controls, file ingestion, cache/reload races, and security-relevant test coverage.

Reviewer setup: local Codex review and verification.

## Executive Summary

No immediate authentication bypass or cross-dataset metadata leak was found in the current tree. The review identified two high-priority operational risks, audit hash-chain advancement after delegated sink failure and pre-decode buffering of oversized CSV/Parquet sources. Both were remediated before this release-readiness pass completed.

The core scope model is in materially better shape than the earlier Wave 2/Wave 3 feedback: catalog, OpenAPI, dataset summaries, entity schema, row, verify, relationship, and aggregate surfaces all gate on per-entity scopes or filtered metadata visibility. Focused tests for catalog filtering, verify isolation, and entity route behavior pass.

Remediation status after this review:

- Addressed: audit chain state now advances only after the delegated sink write succeeds, with a fail-once sink regression test.
- Addressed: CSV, XLSX, and Parquet now share a pre-decode source-size guard through `server.max_source_file_bytes`; XLSX also keeps `server.xlsx_max_file_bytes`.
- Addressed: local file open now stats the opened handle so the size and ETag snapshot matches the bytes decoded.
- Addressed: production HTTP composition strips client-supplied `x-request-id` before minting the server-owned request id.
- Addressed: `allowed_expansions` validation now rejects unknown relationships even when an entity declares no relationships.
- Addressed: entity reads now build queries from a versioned table-provider snapshot, so rows, ETags, verify `ingest_version`, and cursor versions come from the same table state even during reload.
- Still open: keyed audit redaction hashes, query/header length caps, production audit sink startup policy, and the release decision around unfiltered personal-data collections.

## Findings

### High: Audit Chain Can Become Unverifiable After Sink Write Failure

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/chain.rs:75`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/chain.rs:118`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/mod.rs:501`

`ChainState::wrap_envelope` advances `last_hash` before the chained envelope is written to the delegated sink. If `inner.write()` fails, the next successful audit record will use a `prev_hash` pointing to a record that was never persisted. The middleware logs and swallows audit write failures, which is correct for request availability, but it means the stored JSONL chain can later fail verification.

Impact: audit integrity degradation. This does not expose data or bypass authorization, but it weakens the tamper-evidence property of the audit log during transient sink failures.

Recommendation: advance `last_hash` only after the delegated sink write succeeds. Add a regression test with a sink that fails once, then succeeds, and verify the persisted lines still form a valid chain.

### High: CSV and Parquet Ingestion Have No File-Size Guard Before Full Buffering

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/format/csv.rs:63`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/format/parquet.rs:72`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/mod.rs:241`

The XLSX path enforces `server.xlsx_max_file_bytes` before decode, but CSV and Parquet decoders read the full source into memory. A large configured local file can exhaust memory during startup, refresh, or admin reload.

Impact: denial of service from an oversized configured source. In V1 the source is local and operator-controlled, so this is primarily an operational safety issue, but it is still security-relevant for a gateway serving sensitive data.

Recommendation: introduce a format-neutral `max_source_file_bytes` or per-format limits, enforce known `SourceMetadata.size_bytes` before decode for every format, and add streaming/range-reader follow-up work for CSV and Parquet. Add focused tests for oversized CSV, Parquet, and XLSX.

### Medium: Local File Stat/Open Race Can Bypass Size and Change-Token Assumptions

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/source/local_file.rs:104`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/source/local_file.rs:109`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/mod.rs:241`

`LocalFileSource::open` stats the path, then opens it separately. If the configured source path is replaceable between those calls, the metadata used for the size guard and change token can describe a different file than the bytes decoded.

Impact: a local actor able to replace the configured source path can bypass the XLSX pre-decode size guard and make readiness metadata inaccurate.

Recommendation: open first, then read metadata from the opened file handle. Where practical, reject symlink-sensitive deployments or document source directory ownership requirements.

### Medium: Reload/Table Swap Can Serve New Data Under Old Validators

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/mod.rs:329`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/mod.rs:333`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:164`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:233`

Refresh replaces the DataFusion table provider before readiness is updated to the new ULID. Entity handlers read `ingest_version` before executing the query and use it for ETags and cursor validation. A request in the narrow swap window can query new data while computing validators from the old ingest version, including returning `304 Not Modified` for changed data.

Impact: stale cache validation and cursor semantics during reload. This is unlikely to leak unauthorized data, but it can break correctness guarantees clients rely on.

Recommendation: make the table provider and ingest version a single atomic query snapshot, or update readiness before making the new provider visible and ensure queries select provider by ingest version. Add a stress test that loops reloads while issuing conditional GETs.

### Medium: Audit Request IDs Are Client-Spoofable

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/mod.rs:398`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/server.rs:228`

The audit middleware adopts any non-empty incoming `x-request-id`. Clients can choose colliding, misleading, or non-ULID request IDs that are then used in audit records and response correlation.

Impact: audit correlation integrity risk. This is not an authentication bypass.

Recommendation: accept an upstream request ID only from trusted proxies, or validate it as a ULID and mint a fresh internal audit ID when invalid. Consider recording both `external_request_id` and server-minted `request_id`.

### Low: Sensitive Audit Value Hashes Are Deterministic and Unkeyed

File:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/redact.rs:78`

Sensitive query values are stored as `sha256(field || NUL || value)`. This avoids storing raw PII, but low-entropy identifiers are dictionary-recoverable if audit logs leak.

Impact: limited disclosure risk from leaked audit logs, especially for small identifier spaces.

Recommendation: use keyed HMAC with an audit-only secret if lookup-capable hashes are required. Rotate and protect that key like other audit secrets.

### Low: `allowed_expansions` Validation Misses Entities With No Relationships

File:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/config/validate.rs:836`

The `allowed_expansions` validation runs inside the loop over `entity.relationships`. An entity with no relationships but non-empty `allowed_expansions` can pass startup validation and fail only at runtime.

Impact: misconfiguration slips past startup validation. Runtime access checks still reject the expansion, so this is not an access bypass.

Recommendation: move the `allowed_expansions` validation outside the relationship loop and add a regression test for an entity with zero relationships and one allowed expansion.

## Positive Findings

- API-key verification uses Argon2id PHC strings and does not log raw credentials.
- Protected data-plane routes are mounted behind auth, while `/health` and `/ready` are intentionally unauthenticated.
- Catalog, DCAT-AP, OpenAPI, datasets, and entity schema surfaces filter by metadata scope rather than granting a full catalog to any metadata token.
- Verify routes use `verify_scope`, require the exposed primary-key query parameter, reject extra parameters, and return the ingest version.
- `?expand=` and nested relationship endpoints independently check host and target read scopes and purpose-header requirements.
- The gateway does not expose raw SQL to API consumers.
- Filter execution uses DataFusion expressions, not string-concatenated SQL.
- The configured XLSX size guard is enforced before XLSX decode.
- Parquet CPU-bound decode work runs in `spawn_blocking`.
- Audit query redaction includes configured sensitive entity fields and generic secret-bearing query names.
- `~/.cargo/bin/cargo-deny check advisories bans licenses sources` currently completes with no advisory, ban, license, or source failures.

## Hardening Backlog

- Add URI, query-string, and request-header length limits. The 1 MiB body limit does not constrain large GET query strings, cursors, `fields`, `expand`, or filter values.
- Consider failing startup when a configured file audit sink cannot initialize instead of falling back to stdout in production deployments.
- Add security regression tests for audit chain write failure, CSV/Parquet size guards, local-file stat/open race, reload ETag race, request-ID validation, and zero-relationship `allowed_expansions`.
- Decide whether unfiltered entity collections should be allowed by default for all personal datasets. The current `required_filters` addition can enforce subject-keyed access where configured, but it is opt-in per entity.
- Track the accepted `serde_yml` unmaintained advisory exception. It is explicitly ignored in `deny.toml`, so the risk is documented but still real.

## Verification Performed

Commands run locally:

```text
just fmt-check
just lint
just test
just build
just deny
```

Results:

- `just fmt-check`: passed, with stable-rust warnings about `imports_granularity`.
- `just lint`: passed.
- `just test`: passed.
- `just build`: passed and produced the optimized release binary.
- `just deny`: passed. It emitted warnings about unmatched license allowances and duplicate crate versions, but final status was `advisories ok, bans ok, licenses ok, sources ok`.

Additional checks reported by the independent reviewer:

```text
cargo test --all-features
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo tree -d
```

Reported result:

- `cargo test --all-features`: passed.
- `cargo fmt --all -- --check`: passed, with stable-rust warnings about `imports_granularity`.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `cargo tree -d`: completed for duplicate dependency inspection.

Tooling note: an older `cargo-deny 0.14.2` on PATH may fail to parse `Unicode-3.0` in `deny.toml`. The local `just` recipes now prefer `~/.cargo/bin/cargo-deny` when present; `cargo-deny 0.19.6` completed successfully.
