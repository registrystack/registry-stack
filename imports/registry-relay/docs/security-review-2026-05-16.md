# Data Gate Security Review (Red Team)

Date: 2026-05-16

Scope: follow-up red-team pass on the working tree, building on the prior review at `docs/security-review-2026-05-15.md`. Five parallel reviewers covered auth/authz/scope, query/filter/DoS, audit integrity/redaction, config/secrets/error disclosure, and file/format parsers + ingest cache. Findings below are deduped and prioritized; the three highest-impact items were spot-verified against current source before this document was written.

Reviewer setup: parallel code-review subagents, each briefed to find NEW issues beyond the 2026-05-15 review and to verify the items marked "Addressed".

## Executive Summary

Three new findings rise to the top:

- `POST /admin/reload` ships with no scope check at all (`reload_unavailable` stub), where the sibling `reload_table` correctly gates on `admin` scope. A latent privilege gap that becomes a real escalation as soon as registry-wide reload is wired up.
- The pagination cursor is unsigned hex-encoded JSON. Clients can forge the `position` field; `validate_cursor` checks every other field but not `position`. Within-entity pagination integrity is broken, and the cursor leaks the active filter set and `ingest_version` in cleartext.
- `FileSink` (and to a lesser degree `StdoutSink`) executes synchronous blocking I/O on the tokio runtime without `spawn_blocking`. Under audit-heavy load the runtime stalls.

Two of the three previously "Addressed" file/format remediations are partial: the pre-decode size guard caps on-disk bytes but does not bound decompressed expansion (XLSX, Parquet); and the stat/open race was fixed in `LocalFileSource::open` but `LocalFileSource::metadata` still path-stats, leaving the mtime polling loop on the original race.

Beyond those, a cluster of medium-severity issues relate to audit completeness (path PK leakage, unredacted `x-data-purpose`, syslog datagram truncation), config validation gaps (Argon2 minimums, CORS `*` literal, unknown-field swallow on `AuditConfig`), and DoS hardening (no filter-count cap, no cache content integrity check).

## Spot-Verified Findings

### Critical: Admin Reload-All Has No Auth or Scope Check

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/admin.rs:75`

`reload_all` is mounted on `POST /admin/reload` and unconditionally returns `reload_unavailable(...)` (501) without calling `require_admin_scope` or even checking that a principal is present. The sibling `reload_table` at line 57 correctly gates on `admin` scope. Today the impact is limited because `reload_all` is a stub, but the route is live on the protected router, so the moment registry-wide reload is implemented behind this handler, any authenticated principal (read-only or metadata-only key) can trigger it. Even now, the route confirms its own existence to any authenticated caller, which is reconnaissance.

Recommendation: invoke `require_admin_scope(principal)?` (the same check used by `reload_table`) as the first line of `reload_all`, before returning the unavailable response. Add an `admin.rs` test asserting 403 for a non-admin principal on this route.

### High: Pagination Cursor Is Unsigned Hex JSON; `position` Field Is Client-Forgeable

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:1111`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:1124`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:1130`

`encode_cursor` serializes `PageCursor` to JSON and hex-encodes it; `decode_cursor` reverses that. There is no MAC, signature, or encryption. `validate_cursor` checks `version`, `dataset_id`, `entity`, `relationship`, `filters`, and `ingest_version`, but it does not check `position`. A client can decode a legitimate cursor, modify `position` (the after-primary-key seek value), re-encode, and replay. Because `validate_cursor` does pin `filters`, this is not a cross-scope data leak: it is a pagination-integrity issue (skip pages, rewind pages, replay) and a cleartext disclosure of the active filter set and `ingest_version` to anyone holding a cursor. If primary keys are themselves sensitive identifiers, the cursor encodes them as plaintext too.

Recommendation: HMAC the cursor bytes with a server-side audit-only secret before hex-encoding. Verify the HMAC before any field is trusted. AEAD (ChaCha20Poly1305) is an alternative if cursor confidentiality is wanted.

### High: `FileSink::write` Performs Blocking I/O on the Tokio Runtime

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/file.rs:114`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/stdout.rs:43`

`FileSink::write` is `async`-signatured but its body is pure blocking I/O: `std::sync::Mutex::lock`, `fs::metadata`, `OpenOptions::open`, `write_all`, `flush`, and on rotation a chain of `fs::rename` calls. None of this is wrapped in `tokio::task::spawn_blocking`. Under a burst of concurrent requests, every audit write stalls a tokio worker thread for the duration of the syscall and any rotation. With tokio's default worker count (number of CPUs), a sustained burst saturates the runtime and starves request dispatch.

`StdoutSink` has the same shape and acknowledges this in a code comment that dismisses `spawn_blocking` as "overkill". The dismissal is wrong in production deployments where `tracing`'s `fmt` subscriber and `StdoutSink` share the same global stdout lock; a slow stdout pipe (back-pressure from a log collector) blocks both.

Recommendation: wrap the body of `write_line` in `tokio::task::spawn_blocking`. Apply the same to `StdoutSink::write`, or route audit to a dedicated fd that does not share a lock with tracing.

## Format and Cache Findings

### High: XLSX Decompression Bomb (`max_*_file_bytes` Guards Compressed Size Only)

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/format/xlsx.rs:69`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/mod.rs:260`

Both `xlsx_max_file_bytes` and the new `max_source_file_bytes` are enforced against on-disk size. calamine decompresses the XLSX ZIP internally with no decompressed budget and loads the full sheet range into an in-memory `Range<Data>` before `decode_xlsx` builds Arrow arrays. A valid XLSX with a single 1 KB shared string referenced two million times compresses to 1-2 MB on disk and expands to multiple GB in memory.

Recommendation: cap `worksheet_range.get_size()` (cells = rows * cols) before iterating, and add a separate decompressed-byte budget. Reject the file if either limit is exceeded.

### High: Parquet Footer Metadata Bomb

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/format/parquet.rs:82`

`ParquetRecordBatchReaderBuilder::try_new` parses the Parquet footer eagerly. Footer key-value metadata and per-column statistics can carry arbitrary byte blobs while remaining a valid Parquet file. A 5 MB on-disk file with a 4 MB footer (3000 columns each with 1 MB min/max statistics) allocates ~3 GB before any row group is read, which bypasses the on-disk `max_source_file_bytes` guard.

Recommendation: pre-parse the footer length from the last 8 bytes and reject files with a footer over a configured cap (e.g., 32 MB). After `try_new`, also bound `schema_descr().num_columns()` and the sum of per-column statistics sizes.

This finding was not end-to-end reproduced; suggest a focused test before applying a fix to confirm the allocation behavior of the pinned `parquet` crate version.

### Medium: `LocalFileSource::metadata` Still Path-Stats; Mtime Poller Is on the Original Race

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/source/local_file.rs:117`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/refresh.rs:109`

The 2026-05-15 review's TOCTOU fix touched `LocalFileSource::open`, which now stats the opened handle. `LocalFileSource::metadata` (used by the mtime polling loop in `refresh.rs:109`) still calls `tokio::fs::metadata(&self.canonical_path)` and follows symlinks. A local actor that can replace the configured path between the metadata poll and the next ingest open can decouple the ETag the poller sees from the file that subsequently gets ingested.

Recommendation: in `metadata`, open the file and call `file.metadata().await`, mirroring the `open` fix. Or document a source-directory ownership invariant and validate it on startup.

### Medium: Cache Path Traversal via `DatasetId` / `ResourceId`

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/cache.rs:50`

`CacheLayout::dir` joins `root.join(dataset.as_str()).join(resource.as_str())`. `PathBuf::join` does not sanitize components; a value containing `..` escapes the cache root. Whether this is exploitable depends on the input validation applied during `DatasetId`/`ResourceId` deserialization in `src/config/mod.rs`. If those types only accept `[A-Za-z0-9_-]`, this is closed by construction; if they accept arbitrary YAML strings, it is exploitable through config.

Recommendation: verify the ID validators reject `/`, `\`, and `..`. Independently, after the `join`, assert that the resulting path is a descendant of `self.root` (canonicalize and compare prefixes).

### Medium: Cache Files Have No Content Integrity Check

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/cache.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/ingest/mod.rs` (cached-table registration)

Cache files are written atomically via temp-rename. There is no SHA over the Parquet content and no verification on read. If another process or a bug overwrites a `<ULID>.parquet` file after the rename, DataFusion silently serves the corrupted or replaced content. For a personal-data gateway, undetected cache corruption directly affects query results.

Recommendation: compute SHA-256 over the file immediately after `write_atomic`, persist a sidecar (e.g., `<ULID>.parquet.sha256`), and verify before registering the file with `ListingTable`.

### Medium: CSV Single-Quoted-Field Allocation

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/format/csv.rs:186`

A CSV at the boundary of `max_source_file_bytes` (e.g., 256 MB) can be a single quoted field with no closing quote. `csv::Reader` will buffer the entire file before producing a record. The column-count check then rejects it, but the memory and CPU were already spent. Not a crash; an amplifier for sustained DoS.

Recommendation: cap rows or bytes consumed inside the CSV iteration loop, and short-circuit when a single field exceeds a per-field byte budget.

## Audit Findings

### Medium: Path Segments With PK Values Are Audited Verbatim

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/mod.rs:482`

`AuditRecord.path` is the raw URL path. For `GET /datasets/X/individuals/IND-001234`, the PK lands in audit logs in cleartext. The `QueryRedactor` covers query parameters, not path segments, so the sensitive-value hashing machinery is bypassed for any identifier carried in the path.

Recommendation: store a path template alongside the matched parameters, or hash PK segments using the same `sensitive_value_hash` mechanism when the entity's PK is configured sensitive.

### Medium: `x-data-purpose` Header Is Echoed Unredacted With No Length Cap

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/mod.rs:515`

`extract_purpose` reads `x-data-purpose` verbatim into `AuditRecord.purpose` with no validation, allowlist, or length cap. A client paste error (token in the purpose header) lands unredacted in audit logs.

Recommendation: cap at 512 chars and log a warning on truncation; optionally validate against a configured allowlist of purpose strings.

### Medium: Syslog Datagram Truncation Silently Drops Records

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/syslog.rs:51`

`send_datagram` sends the full JSONL envelope as one Unix datagram. `/dev/log` typically caps at 8-64 KB. On `EMSGSIZE` the error becomes `AuditError::Io`, which the middleware logs and swallows (`audit/mod.rs:501`), so the record is silently dropped. Long query strings (still uncapped per the prior backlog) can deterministically defeat audit on this sink.

Recommendation: measure the serialized line length before `send_to`; if it exceeds a configurable limit, truncate `query_params` or fall back to a summary record. Consider `SOCK_STREAM` to `/dev/log` where available.

### Low: Hash-Chain Canonicalization Is JSON-Bytes-Fragile

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/audit/chain.rs:257`

The verifier re-parses each JSONL line into `serde_json::Value`, removes `record_hash` and `prev_hash`, and re-serializes to compute the hash input. Key ordering (insertion-preserved via `IndexMap`) and any future float-typed field would change the bytes. Any log-shipper that runs `jq` or normalizes key order across the chain will break verification. No active exploit today (no float fields), but the property is load-bearing for future changes.

Recommendation: switch to a canonical encoding (sorted-key JSON or CBOR) for the hash input. Until then, document explicitly that the JSONL must not be re-serialized between write and verify.

### Low: Chain Regression Test Does Not Verify the Chain

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/tests/audit_redaction_chain.rs:182`

`chaining_sink_does_not_advance_hash_after_failed_write` asserts `prev_hash.is_none()` on the record after the failed write, but never calls `verify_chain_lines` across subsequent persisted records. A regression that set `prev_hash` to the dead record's hash would still pass.

Recommendation: extend the test to write three records (fail, succeed, succeed) and run `verify_chain_lines` on records 2 and 3.

## Config and Disclosure Findings

### High: `/ready` Leaks Dataset and Entity Names to Unauthenticated Callers

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/health.rs:55`

`/ready` is intentionally public for LB probing. When the service is not ready, the 503 body includes `failed_resources`, `not_ready_resources`, and `unresolved_entities` arrays containing `dataset_id`, `resource_id`, and entity names. An unauthenticated attacker can enumerate the configured catalog during any startup or post-reload failure window before brute-forcing API keys.

Recommendation: drop detail arrays from the public response; keep only the high-level `code`/`detail` strings. Expose detail behind an authenticated `/admin/status` endpoint.

### High: Argon2 PHC Validation Accepts Trivially Weak Parameters

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/config/validate.rs:285`

`is_argon2id_phc` is a structural check (prefix `$argon2id$`, at least five `$`-delimited segments). It does not parse `m`, `t`, or `p`. A hash like `$argon2id$v=19$m=1,t=1,p=1$<salt>$<hash>` passes validation and is then accepted as a configured key. Argon2 with `m=1, t=1` is computationally trivial to brute-force.

Recommendation: after the structural check, parse the PHC with `argon2::PasswordHash::new` and enforce minimums (OWASP baseline: `m >= 19456`, `t >= 2`). Fail startup hard if any configured key falls below the minimum.

### Medium: CORS Config Accepts `*` as a Literal Origin

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/server.rs:303`

`build_cors_layer` passes config strings to `AllowOrigin::list`. `HeaderValue::from_str("*")` succeeds, so an operator who sets `allowed_origins: ["*"]` gets a wildcard reflected on every preflight. There is no separate `AllowCredentials` layer to amplify the issue, but it still enables any-origin cross-origin reads of sensitive data.

Recommendation: validate each `cors.allowed_origins` entry in `validate_server` as `scheme://host[:port]` (no path, no query, no wildcard). Reject `*` explicitly.

### Medium: `AuditConfig` Silently Swallows Unknown YAML Fields

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/config/mod.rs:152`

The serde limitation around `#[serde(flatten)]` and internally-tagged enums precludes `deny_unknown_fields` on `AuditConfig`. A typo such as `includ_health: true` is silently ignored, breaking the "typos surface as `config.parse_error`" invariant the module-level doc claims.

Recommendation: deserialize via a manual `Visitor` (or via `serde_json::Value`/`BTreeMap`) that extracts the known fields and rejects anything else. Document the trade-off explicitly if the workaround is deferred.

### Medium: File Audit Sink Falls Back to Stdout Silently on Init Failure

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/main.rs:265`

When the configured `sink: file` path is unwritable, `build_audit_sink` logs a warning and substitutes `StdoutSink`. The gateway then starts and serves traffic with what appears to be a working audit sink; in deployments that discard stdout, audit records are lost. The prior review's hardening backlog already named this; restating here because in a data-governance context silent audit loss is a compliance defect.

Recommendation: in production, fail startup when the configured file sink cannot initialize. Gate any fallback behind an explicit `audit.allow_sink_fallback: true` config.

### Medium: Aliased `tables` / `resources` Can Share a Source Path

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/config/mod.rs:238`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/config/validate.rs:110`

ID-uniqueness is enforced across the merged `tables` + `resources` iterator, but nothing checks that two distinct IDs point at the same `SourceConfig::File.path`. Two entities with different scope requirements can be defined over the same underlying data; the less-restricted entity then acts as a side channel for the stricter one.

Recommendation: warn or error on duplicate source paths within a dataset. Consider also emitting a deprecation warning when the `resources` alias is used in new config.

## Query and DoS Findings

### Medium: `required_filters` Is a Presence Check, Not a Value Bind

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:208`

The enforcement is `required_filters.iter().any(|r| r == &f.field)`: pass if any filter on a required field name is present, regardless of operator or value. A client with the `In` operator allowed on a required field can pass `subject_id.in=a,b,c,...` (capped at 100) and mass-enumerate. The intent reads as "scope to the caller's subject"; the implementation reads as "ensure they typed the field name."

Recommendation: document the gap clearly. If subject isolation is needed, bind required-filter values to a principal claim (e.g., `subject_id == auth_token.sub`). At minimum, restrict required fields to `Eq` only.

### Medium: No Cap on Filter-Parameter Count Per Request

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:929`

`collection_query_from_params` accumulates filters with no per-request cap. URL length is also uncapped (existing backlog). 10,000 distinct filter parameters produce a chain of 10,000 `Filter` nodes in the DataFusion logical plan; planning cost scales with that chain.

Recommendation: cap filter count at ~20 per request. Pair with the URL-length cap from the prior backlog.

### Medium: `between` Values Typed as Strings; Range Validation Compares Lexicographically

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:1223`

`parse_filter_value` wraps each piece of a `between` payload as `Value::String`. `validate_range_order` then compares strings: `?age.between=9,10` fails with `InvalidRange` because `"9" > "10"` lexicographically. `?age.between=09,10` succeeds. ISO dates work by coincidence.

Recommendation: try numeric parse before falling back to strings, so the resulting `Value` carries the correct JSON type and range validation does the right comparison.

### Medium: `validate_entity_aggregates` Does Not Verify Dotted `group_by` Targets

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/config/validate.rs:757`

A `group_by` entry of `"related.field_name"` passes startup validation when the prefix is in `join_names`, but `field_name` is not checked against the related entity's exposed fields. Runtime returns `FilterError::UnknownField` only when the aggregate is first invoked.

Recommendation: at config-validation time, resolve the relationship's target entity and verify the field name appears in its exposed fields.

### Low: `If-None-Match: *` Returns 304 Without Reading Rows

Files:

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/data_gate/src/api/entity.rs:793`

HTTP-correct per spec, but a one-request "does data exist" oracle: a client can confirm that a given filter has rows without paying for or auditing a row read. Probably acceptable; flagging for awareness.

## Remediation Verification (Items From 2026-05-15 Review)

| Item | Verdict |
|---|---|
| Audit chain advance after sink-write success | Complete. `ChainingSink::write` (`audit/chain.rs:108-127`) only advances `state.last_hash` after the inner write succeeds via `?`. The regression test exists. |
| `x-request-id` stripped before server-minted ID | Complete. `strip_untrusted_request_id` runs as the outermost layer (`server.rs:228-239`) before `SetRequestIdLayer`. |
| `allowed_expansions` validates entities with zero relationships | Complete. The check now runs before the relationship loop (`config/validate.rs:807-821`); a regression test is still missing. |
| CSV/Parquet/XLSX pre-decode size guard | Partial. The guard at `ingest/mod.rs:246-271` enforces on-disk bytes only. Decompression amplification remains exploitable for XLSX (calamine) and Parquet (footer metadata), per findings above. |
| Local-file stat/open race | Partial. `open` is fixed; `metadata` still path-stats and is used by the mtime polling loop in `refresh.rs:109`. |
| Reload/table-swap atomic snapshot | Mostly complete for entity reads. `execute_entity_query` uses a single `table_snapshot` covering provider and `ingest_ulid`. One residual inconsistency: `entity_schema` ETags are still derived from the `readiness` watch channel via `ingest_version_for_entity`, independent of any query snapshot. Low impact (schema documents do not carry row data) but flagged as a correctness gap. |

## Hardening Backlog

Carried over from 2026-05-15 and confirmed still open:

- URI, query-string, and request-header length limits.
- Production-mode failure on file-audit-sink init error (this review's finding above).
- Keyed audit redaction hashes.
- `serde_yml` unmaintained advisory exception (documented in `deny.toml`).
- Unfiltered personal-data collection policy decision.

Newly added by this review:

- Per-request filter-parameter count cap.
- Cap on decompressed source size for XLSX and Parquet, plus a cell or row-count budget for XLSX.
- Footer-size cap for Parquet before constructing the record-batch reader.
- Content-hash sidecar for cache files and verification on read.
- Audit path-segment redaction for entity primary keys.
- Length cap (and optional allowlist) for the `x-data-purpose` header.
- Pre-send size check on the syslog datagram sink with a truncation strategy.
- Argon2 PHC parameter minimums enforced at config-load time.
- CORS origin syntax validation (reject `*` and malformed entries).
- Verification that `DatasetId` / `ResourceId` deserialization rejects `..`, `/`, and `\`.
- Duplicate-source-path detection across the merged `tables` + `resources` set within a dataset.
- Canonical encoding (or documented invariant) for the audit chain hash input.
- Extension of the chain regression test to call `verify_chain_lines` on persisted records after a failed write.

## Suggested Order of Operations

1. Add `require_admin_scope` to `reload_all` (one line, prevents a future privilege escalation).
2. Wrap `FileSink::write` (and `StdoutSink::write`) in `spawn_blocking`.
3. Cap filter-parameter count and URL length (cheap DoS hardening).
4. HMAC the pagination cursor (small surgical change; closes a real integrity gap).
5. Reproduce the XLSX and Parquet decompression bombs with focused tests, then apply the corresponding caps.
6. Bundle audit changes (path-segment redaction, purpose cap, syslog size guard) since they touch the audit record shape.

## Verification Performed

Spot-verified by reading current source:

- `src/api/admin.rs:75-77`
- `src/api/entity.rs:1111-1133`
- `src/audit/file.rs:42-118`

Other findings rely on subagent reads; the most allocation-sensitive ones (Parquet footer bomb in particular) should be confirmed with a focused test before fix work.
