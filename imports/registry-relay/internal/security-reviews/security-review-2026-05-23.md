# Security Review, 2026-05-23

Targeted security review of `registry-relay` at commit state of 2026-05-23.

## Scope and Methodology

The review covered seven independent surfaces, each delegated to a focused
code-review agent that consulted the matching technique checklists in
[Anthropic Cybersecurity Skills](https://github.com/anthropic-experimental/cybersecurity-skills).
Each agent reported confidence-filtered findings only (high confidence,
material risk). The seven streams were:

1. AuthZ scope enforcement (BOLA / BFLA / scope binding).
2. JWT, OIDC, and Verifiable Credential signing crypto.
3. Outbound HTTP surface (SSRF).
4. Input parsing and injection (DataFusion, XLSX, Postgres, paths).
5. HTTP hardening (headers, CORS, TLS, public surface).
6. Container image and CI/CD supply chain.
7. Audit subsystem integrity and PII handling.

Surfaces intentionally out of scope for this pass: cryptographic protocols
underlying SPDCI, OGC API Records / Features payload encoding helpers, and
performance harness code.

## Triage decisions, 2026-05-23

The remediation goal is "secure enough for production" without adding
unnecessary architecture or compliance machinery. We will prioritise fixes
that close reachable auth, data exposure, and browser-token risks with small,
local changes.

**Production-readiness tranche:**

1. **F1 OIDC SSRF hardening.** High value, low complexity. Do first.
2. **F2 dataset-bound entity scopes.** High value, low complexity. Do first.
3. **F6 fail closed when the entity registry extension is absent.** Medium
   value, low complexity. Pair with F2.
4. **F8 hash audit primary keys.** High value when primary keys may be
   identity-bearing. Do before production data.
5. **F3 baseline headers and `/docs` CSP.** High value, moderate complexity
   because the docs shell uses inline script/style and stores an API key in
   browser storage. Implement pragmatically; do not build a full docs app.

**Important but separate:**

- **F4 supply chain.** Valuable, but split into small CI PRs: first workflow
  permissions, action SHA pins, Docker digest pins, Dependabot Docker, and an
  image scan; add SBOM/signing once image publishing is stable.
- **F5 audit chain persistence.** Worthwhile if tamper-evident audit is a
  production promise. Keep it small by seeding chain state from the previous
  file hash; do not build a ledger subsystem.
- **F10 syslog hardening.** Defer unless syslog is a production destination.

**Corrections to the original severity notes:**

- **F14 should be reworded.** `tower-http` 0.6 `CorsLayer::new()` sends no
  `Access-Control-Allow-Methods` or `Access-Control-Allow-Headers` by default.
  The current issue is lack of explicit preflight policy / browser
  interoperability, not permissive defaults.
- **F7 is real but not "immortal token" risk.** `exp` is validated. Future
  `iat` mainly breaks issuance-time and audit assumptions.

## Implementation progress, 2026-05-23

This report was moved from `docs/security-review-2026-05-23.md` to
`internal/security-reviews/security-review-2026-05-23.md` so it is no longer
part of the published documentation tree.

The production-readiness tranche is implemented in the local working tree:

- **F1:** completed in `src/auth/oidc/fetcher.rs`. OIDC discovery and JWKS
  fetches no longer follow redirects, reject remote `http://` URLs, allow
  localhost HTTP for development, and validate the discovered `jwks_uri`
  before it is used. The dev-mode allowlist was subsequently tightened
  (second pass) so it accepts only literal `localhost` and parsed loopback
  IPs (`127.0.0.0/8`, `::1`, IPv4-mapped loopback). RFC1918, link-local
  `169.254/16`, and the IPv4-mapped metadata target `::ffff:169.254.169.254`
  are now rejected.
- **F2:** completed in `src/config/validate.rs`. Entity access scopes are
  validated at config load against the enclosing dataset id while preserving
  the existing entity-specific suffix convention, for example
  `social_registry:individual:metadata`.
- **F3:** completed in `src/server.rs` and `src/api/docs.rs`. Responses now
  get baseline browser hardening headers, and the docs HTML / Scalar bundle
  get route-local CSP headers. The docs shell still uses `localStorage` for
  its bearer token, but CSP reduces script injection risk without replacing
  the docs app. Second-pass changes: `Cross-Origin-Resource-Policy` is now
  emitted conditionally as `cross-origin` only when the response carries an
  `Access-Control-Allow-Origin` echo (so the configured CORS allowlist
  actually works in browsers that send `Cross-Origin-Embedder-Policy`),
  otherwise it stays `same-origin`. The docs CSP test now asserts the
  `script-src` directive does NOT contain `'unsafe-inline'`. HSTS remains
  intentionally unset: TLS is terminated upstream and adding HSTS at the
  app would risk pinning HTTP-only operators into a broken state. This
  decision is captured in a code comment.
- **F6:** completed in `src/api/entity.rs`. Entity collection, record, and
  relationship handlers now fail closed when the `EntityRegistry` extension
  is absent instead of skipping read-scope checks.
- **F8:** completed in `src/audit/mod.rs` and `src/audit/redact.rs`. Audit
  `primary_key` values are context-bound SHA-256 hashes, and single-record
  path IDs are redacted in audit paths while relationship and entity
  metadata remain available. Second-pass change: hashing now uses
  `HMAC-SHA256` with a per-deployment secret loaded from the env var named
  by `audit.hash_secret_env` in config, falling back to unkeyed SHA-256
  when the env var is unset (development convenience, logged as a startup
  warning). Production deployments where the primary-key domain is small
  enough to be rainbow-table-attacked (national IDs, phone numbers, MSISDNs)
  must set `audit.hash_secret_env` and supply at least 32 bytes of secret
  material in that env var. Keyed records are tagged with the prefix
  `hmac-sha256:`; unkeyed records keep the existing `sha256:` prefix.

Verification completed:

- `cargo test fetcher --lib`
- `cargo test --test audit_record`
- `cargo test --test audit_redaction_chain`
- `cargo test --test config_entities entity_access_scopes_must_be_bound_to_enclosing_dataset`
- `cargo test --test entity_routes entity_read_routes_fail_closed_when_registry_extension_is_missing`
- `cargo test --test provenance_issuance_endpoints`
- `cargo fmt --all -- --check`
- `git diff --check`
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`

Second-pass verification (F1 loopback tightening, F3 conditional CORP /
HSTS rationale, F8 HMAC keying):

- `cargo test --all-features --lib auth::oidc::fetcher` (13 tests, all pass)
- `cargo test --all-features --lib audit::` (8 tests, all pass)
- `cargo test --all-features --lib api::docs` (6 tests, all pass)
- `cargo test --all-features --lib server::` (9 tests, all pass)
- `cargo test --all-features --test audit_record --test config_entities --test entity_routes --test provenance_issuance_endpoints`
- `cargo test --all-features --test audit_redaction_chain`
- `cargo clippy --all-targets --all-features -- -D warnings` (clean)

## Decision and status register, 2026-05-23

| ID | Decision | Status | Notes / next action |
|----|----------|--------|---------------------|
| F1 | Production blocker | Done | OIDC discovery and JWKS fetches are scheme-checked, redirect-free, and validate discovered `jwks_uri`. Dev-mode HTTP allowlist accepts only literal `localhost` and parsed loopback IPs; RFC1918, link-local, and IPv4-mapped metadata targets are refused. |
| F2 | Production blocker | Done | Entity access scopes must be bound to the enclosing dataset id at config load. |
| F3 | Production tranche | Done | Baseline headers and docs CSP landed. CORP is emitted as `cross-origin` only when the response carries an `Access-Control-Allow-Origin` echo, so the configured CORS allowlist works under browser COEP. Docs CSP is asserted to exclude `'unsafe-inline'` in `script-src`. HSTS intentionally not emitted; TLS terminates upstream. The docs shell still stores the bearer token in `localStorage`; accepted for the operator docs surface. |
| F4 | Separate CI hardening | Deferred | Split into small CI/image PRs: workflow permissions, action SHA pins, Docker digest pins, image scan, then SBOM/signing. |
| F5 | Conditional production requirement | Deferred | Do only if tamper-evident audit chaining is a production promise; seed `ChainingSink` from the previous file hash. |
| F6 | Production tranche | Done | Entity read handlers fail closed when `EntityRegistry` state is absent. |
| F7 | Hygiene | Deferred | Add bounded `iat` validation when touching OIDC validation next. Not an immortal-token issue because `exp` is validated. |
| F8 | Production tranche | Done | Audit primary keys are context-bound hashes and single-record path IDs are redacted. Hashing uses `HMAC-SHA256` with a per-deployment secret from `audit.hash_secret_env` (records tagged `hmac-sha256:`). Falls back to unkeyed SHA-256 with a startup warning when the env var is unset (dev convenience); production deployments with small-keyspace identifiers must configure the secret. |
| F9 | Hygiene | Deferred | Pin file audit sink permissions to 0600 or 0640. |
| F10 | Conditional | Deferred | Only needed if syslog is a production audit destination. |
| F11 | Hygiene | Deferred | Normalize or bound `Data-Purpose` before recording. |
| F12 | Hygiene | Deferred | Consider whether hiding dataset existence is required for the deployment model. |
| F13 | Hygiene | Deferred | Consider reducing unauthenticated `/ready` inventory detail. |
| F14 | Reworded finding | Deferred | Current CORS default is deny-by-omission; remaining work is explicit preflight policy for interoperability. |
| F15 | Hygiene | Deferred | Add base-directory constraints for file sources if local file configs are operator-supplied. |
| F16 | Hygiene | Deferred | Move XLSX cell cap earlier if hostile compressed files are in scope. |
| F17 | Supply-chain hygiene | Deferred | Pin git dependencies to commit SHAs after dependency owner review. |
| F18 | Supply-chain hygiene | Deferred | Resolve `version` / `tag` mismatch on `registry-manifest-core`. |
| F19 | Informational | Deferred | Use `Zeroizing` around temporary signer key material where practical. |

## Punch list (severity-ordered)

| ID | Severity | Area | One-line summary |
|----|----------|------|-------------------|
| F1 | Critical | OIDC SSRF | JWKS / discovery fetch is unbounded by scheme, redirect target, or post-discovery URL. |
| F2 | High | AuthZ | Per-entity scopes are not validated to carry the enclosing `dataset.id` prefix. |
| F3 | High | HTTP hardening | No security response headers; `/docs` has no CSP and holds a bearer token in `localStorage`. |
| F4 | High | Supply chain | Base images and GitHub Actions are pinned to mutable tags; no image scan, SBOM, signing, secret scanning, or workflow `permissions:`. |
| F5 | High | Audit | Hash-chained audit log does not persist `last_hash` across process restart; the chain restarts from genesis on each boot. |
| F6 | Medium | AuthZ | Three entity handlers silently skip the read-scope check when the `EntityRegistry` extension is absent. |
| F7 | Medium | OIDC | JWT `iat` claim is not validated; future-dated tokens pass. |
| F8 | Medium | Audit | `primary_key` is recorded verbatim in audit records; for social registries this often carries PII. |
| F9 | Low | Audit | File audit sink does not pin permissions to 0600/0640. |
| F10 | Low | Audit | Syslog sink lacks RFC 5424 framing, TLS, and length cap. |
| F11 | Low | Audit | `Data-Purpose` header value is recorded verbatim with no length or character normalization. |
| F12 | Low | AuthZ | `/datasets/{id}` returns different status codes for "missing" vs "no scope"; enables enumeration. |
| F13 | Low | HTTP hardening | `/ready` 200 body lists every configured `dataset_id` / `resource_id` to unauth callers. |
| F14 | Low | HTTP hardening | CORS preflight methods / headers / max-age are not made explicit; this is interop hardening, not a permissive-default flaw. |
| F15 | Low | Config | File-source paths are not constrained to a base directory; `path: ../../etc/passwd` is accepted. |
| F16 | Low | Parsing | XLSX cell-count cap fires post-materialization; protected only by compressed-size cap. |
| F17 | Low | Supply chain | Two git dependencies pinned by tag, not commit SHA; mitigated today by `Cargo.lock` + `--locked`. |
| F18 | Low | Supply chain | `Cargo.toml:77` has a `version` / `tag` mismatch on `registry-manifest-core`. |
| F19 | Info | Crypto | Software signer's Ed25519 seed bytes (`d_bytes`, PKCS8 buffer) are not wrapped in `Zeroizing`; `jsonwebtoken::EncodingKey` does not zeroize. |

## Detailed findings

### F1 (Critical). SSRF surface in OIDC fetcher

Three related defects in the outbound HTTP path compound into a working
SSRF chain:

- **No redirect policy.** `src/auth/oidc/fetcher.rs:129-135` builds the
  `reqwest::Client` with no `.redirect(...)` call. `reqwest` 0.12 defaults
  to following up to 10 redirects.
- **`https_only` not set.** Same call site; the client will follow a 30x
  to `http://attacker/...` without complaint.
- **`jwks_uri` from the discovery document is not re-validated.**
  `src/auth/oidc/fetcher.rs:86-89` stores `jwks_uri` verbatim after
  parsing the discovery response. `validate_discovery_document_bytes`
  checks only body size and the `issuer` claim. A compromised IdP, a
  poisoned DNS resolver, or an in-path attacker can return
  `"jwks_uri": "http://169.254.169.254/..."` and the relay will populate
  its trusted JWKS cache from cloud metadata.
- **`is_https_or_localhost` accepts loopback variants but no other private
  ranges.** `src/config/validate.rs:1345-1354` does not block RFC1918,
  link-local (`169.254/16`), IPv4-mapped IPv6, or alternate loopback
  forms; DNS rebinding between startup and the next JWKS refresh is
  unmitigated.

**Effect:** the RS256-pinned token chain can be defeated by an attacker
who controls or impersonates the IdP host, by replacing the JWKS the
relay trusts.

**Fix:** at the `reqwest::ClientBuilder` site, add:

```rust
.https_only(true)
.redirect(reqwest::redirect::Policy::none())
```

In `validate_discovery_document_bytes`, apply the same
`is_https_or_localhost` check (or stricter, HTTPS-only) to `jwks_uri`
before returning it. Add a regression test asserting a 302 to
`http://...` is refused and a discovery document with a non-HTTPS
`jwks_uri` is rejected.

### F2 (High). Per-entity scopes are not dataset-bound at config load

`src/config/validate.rs:1356-1426`. `validate_scopes` enforces the
`<dataset_id>:<level>` shape on API-key scopes and on
`entity.access.evidence_verification_scope`, but **never validates**
`metadata_scope`, `aggregate_scope`, or `read_scope`. Those three fields
are free-form strings read from YAML and compared verbatim at handler
time (see `src/api/entity.rs:721`, `src/api/aggregates.rs:69,130`,
`src/api/datasets.rs:161`). A config author can declare the same
`read_scope: "rows"` (or any non-prefixed string) on entities in
different datasets, and a key carrying that scope will read both.

The handler layer trusts the YAML to encode the dataset binding. Nothing
at startup enforces the invariant.

**Fix:** extend `validate_scopes` to walk every entity and require each
of `metadata_scope`, `aggregate_scope`, `read_scope`,
`evidence_verification_scope` to begin with the enclosing `dataset.id`
followed by `:`, and to be non-empty.

### F3 (High). No security response headers; `/docs` has no CSP

`src/server.rs` middleware stack and `src/api/docs.rs`. None of
`Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`,
`X-Frame-Options`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
`Cross-Origin-Resource-Policy`, or `Strict-Transport-Security` are
emitted on any route. The `set-header` feature of `tower-http` is
already compiled in but unused. `docs.rs:55` explicitly acknowledges the
CSP gap.

`/docs` stores the bearer token under `localStorage` key
`registry-relay.api_key` and re-reads it on every page load. Without
CSP, any XSS surface inside the vendored Scalar shell or in the embedded
HTML exfiltrates the token to an arbitrary origin.

**Fix:** add a global `SetResponseHeaderLayer` to the router with
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`X-Frame-Options: DENY`, and a permissive baseline
`Permissions-Policy`. Serve a strict CSP on `/docs`:

```
default-src 'none';
script-src 'self';
style-src 'self' 'unsafe-inline';
connect-src 'self';
img-src 'self' data:;
frame-ancestors 'none';
base-uri 'none';
form-action 'none'
```

Inline bootstrap script in the Scalar shell either needs to move to a
`src=`-loaded file or carry a per-response nonce.

### F4 (High). Container and CI/CD supply chain

Compound finding across `Dockerfile`, `Dockerfile.demo`, the three
workflow files, and `.github/dependabot.yml`:

1. **Base images not pinned by digest** (`Dockerfile:3,16`,
   `Dockerfile.demo:3,16`). `rust:1-bookworm` and `debian:bookworm-slim`
   are mutable tags. Append `@sha256:<digest>` to each.
2. **GitHub Actions pinned to major-version tags, not commit SHAs**
   across all three workflow files. The defensive comment in `ci.yml`
   asserting tag pinning is "equivalent" to SHA pinning is incorrect:
   tags can be force-pushed, and the `tj-actions/changed-files` incident
   (March 2025) plus `reviewdog/action-setup` compromise both exploited
   this. Dependabot bumps versions but does not protect against
   in-place tag re-pointing.
3. **No `permissions:` block on any workflow.** Default `GITHUB_TOKEN`
   carries write-level scopes. Add `permissions: { contents: read }` at
   the top of each workflow.
4. **No Trivy / Grype image scan** in CI.
5. **No SBOM emission** (`syft` or `trivy --format cyclonedx`).
   EU CRA and EO 14028 expect SBOM availability for gov-facing
   deliveries.
6. **No cosign / Sigstore image signing.** Keyless signing with the
   workflow's OIDC token is zero-infrastructure.
7. **No secret scanning** (`gitleaks`) in CI. The project uses SHA-256
   hex hashes as API-key fingerprints; a committed hash in a fixture or
   `.env.example` would not be caught by GitHub's built-in scanners.
8. **Dependabot does not cover the Docker ecosystem.** Add a `docker`
   entry pointing at `/`.
9. **No HEALTHCHECK in the production Dockerfile.**

### F5 (High). Audit chain does not survive process restart

`src/audit/chain.rs:87-99`. `ChainState::new()` initialises with
`last_hash = None`. No code path reads the last chain hash from the
file before starting. On every restart the chain silently resets to
genesis (`prev_hash: null` on the first record), defeating cross-restart
tamper evidence.

**Fix:** on `FileSink` startup, read the last line of the audit file,
extract `record_hash`, and seed `ChainingSink` from it. Persist
`last_hash` alongside any rotation marker so log rotation does not break
the chain. Add a regression test that asserts a restart of `FileSink`
produces a record whose `prev_hash` equals the previous run's last
`record_hash`.

**Triage note:** the chain state is owned by `ChainingSink`, not `FileSink`.
The production fix should expose a small way to seed `ChainingSink` from a
previous hash, with file-log discovery as one source of that seed.

### F6 (Medium). Entity scope check is skipped when registry extension is absent

`src/api/entity.rs:213, 276-302, 441-466, 552-599`. Each handler wraps
the read-scope check in `if let Some(Extension(registry)) = registry.as_ref()`.
If the `EntityRegistry` extension is missing while the
`EntityQueryEngine` extension is present, the scope check is silently
skipped and `read_collection` / `read_record` / `read_relationship_page`
run on an authenticated-but-unauthorised principal.

Production wiring (`build_app_with_entity_query`) installs both
extensions together, so the bug is not currently reachable. It is a
defence-in-depth gap: the next builder that wires query without
registry, or any test path mounted into prod by accident, silently
disables authorisation on three high-sensitivity endpoints.

**Fix:** replace the `if let Some(...)` branch with an early-return
`query_unavailable` (the same pattern the missing-`EntityQueryEngine`
branch uses on line 304). Or extract a
`require_entity_and_scope(...)` helper that errors when registry is
absent.

### F7 (Medium). JWT `iat` not validated

`src/auth/oidc/provider.rs:215-224`. `jsonwebtoken` 10 validates `exp`,
`nbf`, `aud`, `iss`, `sub` but does not validate `iat`. The provider
does not implement a post-decode check. A token with `iat` in the year
2099 is accepted as long as `exp` is in the future and `nbf` is in the
past. The risk is downstream: audit assumptions about issuance time can
be wrong. This does not make tokens immortal because `exp` is still
validated.

**Fix:** after `decode`, parse `iat` from `claims.extra` (or via a typed
field) and reject if `iat > now + leeway`. Add a test mirroring
`expired_token_is_rejected_as_token_expired`.

### F8 (Medium). Audit `primary_key` is recorded verbatim

`src/audit/mod.rs:196-197, 799-804`. `AuditContextExt.primary_key` is
set to the raw URL path segment when a request resolves to a single
record. For social registries the primary key is often a national
identifier, a household composite, or a child identifier carrying PII.
The audit record stores the identifier in `primary_key` directly. The
project's stated audit policy (per the `AuditRecord` doc comment) logs
"entity_id, dataset_id, scopes, fields_returned", but does not flag
`primary_key` as requiring the same hashing path that claim values
already use.

**Fix:** either apply `sensitive_value_hash("primary_key", &value)`
before storing, or document in the type's doc comment that primary keys
are always opaque surrogates and add a config-time check that flags
identity-bearing primary keys.

### F9, F10, F11 (Low). Audit hygiene

- **F9** (`src/audit/file.rs:32-36`): `OpenOptions::new().create(true)...`
  inherits the process umask. Apply
  `std::os::unix::fs::PermissionsExt::set_mode(0o600)` (behind
  `#[cfg(unix)]`) after `create(true)` opens a new file.
- **F10** (`src/audit/syslog.rs:51-58`): the syslog sink sends raw JSONL
  over a Unix datagram with no RFC 5424 priority header, no TCP/TLS
  option, no length cap, and no truncation. Records over the socket's
  message size (typically 8 KB) get `EMSGSIZE` and are silently
  dropped after a log line. Add a hard ceiling and a `truncated: true`
  marker, or use a TCP transport for production deployments.
- **F11** (`src/audit/mod.rs:620-626`): `extract_purpose` records the
  `Data-Purpose` header value verbatim. Normalise to a whitelist or cap
  length and strip newlines before storing.

### F12 (Low). Dataset enumeration via differing error codes

`src/api/datasets.rs:124-151`. `/datasets/{id}` returns `404
schema.unknown_dataset` for a missing dataset and `403
auth.scope_denied` when the dataset exists but the caller has no
`metadata_scope` on it. The metadata `evidence_offering` handler
already collapses 403 into 404 for exactly this reason
(`src/api/metadata.rs:202`); `dataset` does not.

**Fix:** collapse the "exists but no scope" branch into the
`UnknownDataset` response so the unauthorised caller cannot enumerate
dataset ids.

### F13 (Low). `/ready` leaks resource inventory

`src/api/health.rs:58-63`. The 200 body lists every configured
`dataset_id` and `resource_id`. An unauthenticated caller can inventory
the catalogue. The 503 body only carries counts, which is fine.

**Fix:** drop `dataset_id` / `resource_id` from the public 200 body;
either return `{"status":"ok"}` only, or move the detailed body behind
the admin listener.

### F14 (Low). CORS preflight policy is implicit

`src/server.rs:565-590`. `build_cors_layer` calls only
`.allow_origin(...)`. In `tower-http` 0.6, `CorsLayer::new()` sends no
`Access-Control-Allow-Methods` or `Access-Control-Allow-Headers` by
default, so the original note about permissive defaults was incorrect.
The remaining issue is that deployments with configured origins do not
publish an explicit narrow preflight policy or preflight cache duration.
`allow_credentials` is correctly unset.

**Fix:**

```rust
.allow_methods([Method::GET, Method::POST, Method::OPTIONS])
.allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
.max_age(Duration::from_secs(600))
```

### F15 (Low). File source paths not constrained to a base directory

`src/config/validate.rs:1699-1703` and `src/source/local_file.rs:36`.
Validation only rejects empty paths. `LocalFileSource::new` calls
`std::fs::canonicalize` (resolves `..` and symlinks) but does not
prefix-check the resolved path. An operator who writes
`path: ../../etc/passwd` will cause the gateway to read and try to
parse that file at startup. Config-only attack surface; relevant for
insider threat and supply-chain scenarios.

**Fix:** in `validate_resources`, join each `path` against the config
file's parent directory, canonicalise, and require the result to stay
within an allowed root (the config-file parent by default, or an
explicit `allowed_source_roots`).

### F16 (Low). XLSX cap fires post-materialisation

`src/format/xlsx.rs:119-149`. The two-pass design checks declared
dimension first, then actual size. A lying `<dimension>` element passes
the first gate; the full `Range` allocation happens before the second
check fires. The compressed-size cap (`xlsx_max_file_bytes`, default
256 MB) is the real defence. Document the decompression amplification
ratio and consider tightening the default.

### F17, F18 (Low). Git dependency hygiene

- **F17** (`Cargo.toml:72, 77`): `cel-mapper-core` and
  `registry-manifest-core` are pinned by `tag`, which is mutable in
  GitHub. Mitigated today by `Cargo.lock` + the Dockerfile's
  `--locked` build. Pin `rev = "<commit-sha>"` alongside `tag` so a
  later `cargo update` cannot silently follow a re-pointed tag.
- **F18** (`Cargo.toml:77`): `registry-manifest-core` declares
  `version = "0.1.1"` but `tag = "v0.1.2"`. Cargo does not enforce the
  `version` field on git deps, so this is misleading rather than
  broken.

### F19 (Info). Software signer leaves private key bytes outside `Zeroizing`

`src/provenance/signers/software.rs:174` and surrounding. The raw env
var is wrapped in `Zeroizing<String>`, which is correct. The decoded
seed `d_bytes` and the PKCS#8 buffer handed to `EncodingKey::from_ed_der`
are plain `Vec<u8>`. `jsonwebtoken::EncodingKey` does not zeroize on
drop (acknowledged in the comment at lines 283-285). Private-key bytes
persist in heap allocations beyond the lifetime of the zeroising env
wrapper.

The threat model is process memory disclosure (core dump, debugger,
container memory snapshot). Wrapping `d_bytes` and the PKCS#8 buffer in
`Zeroizing<Vec<u8>>` is cheap and closes the gap up to the unavoidable
`EncodingKey` copy.

## Confirmed solid

Items that were checked and found correct, listed so the next reviewer
does not redo them:

- Algorithm allowlist on JWT verification is enforced from config; the
  verifier sets `validation.algorithms = vec![header.alg]` only after
  matching `header.alg` against the configured allowlist. `none` and
  `HS*` cannot be configured.
- RS256 / HS256 confusion is closed because `HS*` is not constructible
  in `OidcAlgorithm` and `DecodingKey::from_jwk` binds key family to
  `kty`.
- `aud`, `iss`, `exp`, `nbf` checked; leeway bounded at 5 minutes by
  config validation.
- API-key path: SHA-256 fingerprint of a high-entropy raw key in env;
  `subtle::ConstantTimeEq` on the comparison; `Zeroizing` on the raw
  env value. Env read once at startup.
- JWKS cache refresh is single-flight (Tokio mutex), rate-limited on
  unknown `kid` (default 30 s, configurable). Discovery `issuer` claim
  is cross-checked.
- DataFusion path has no caller-influenced SQL string construction;
  filter predicates are built via `col()` and `lit()`.
- Postgres-sourced queries: identifiers validated by strict
  `is_valid_postgres_identifier`; `quote_ident` correctly escapes;
  configured queries run with session-level
  `default_transaction_read_only = on` (structural enforcement, not
  just lexical).
- VC `jti` is `urn:uuid:{v4}` from OS RNG; collision-resistant; not
  caller-induced.
- `/openapi.json` is auth-gated.
- Problem Details error bodies do not leak paths, secrets, stack
  traces, or row data (see `src/error.rs:526-528`).
- No `Server` header emitted by the application; Axum / hyper do not
  inject one by default.
- `tracing` spans in `observability.rs` explicitly exclude PII (see the
  module's own doc comment).
- Audit `vc.issued` event records issuance metadata (`iss`, `kid`,
  `jti`, `claim_type`, `subject`, `iat`, `nbf`, `exp`) but never the VC
  body.
- `request_id` is correlated between audit records and operational
  logs.
- `.dockerignore` correctly excludes `target/`, tests, secrets.
- Multi-stage Dockerfile; non-root `registry_relay` user; `apt-get`
  cache cleared in the final layer; layer cache ordering correct for
  Rust dependency builds.

## Coverage gaps

The reviewing agents reported these files as skimmed only or not
reached during this pass:

- `src/api/openapi.rs:200-end` (document construction beyond the auth
  gate; only the gate was reviewed).
- `src/api/spdci.rs:350-end` (envelope construction helpers and
  matcher code).
- `src/api/ogc/features.rs:700-end` (link and encoding helpers).
- `src/api/ogc/records.rs:1-280, 360-end` (router and helpers; only
  the filter / auth boundary was reviewed).
- `src/query/mod.rs:280-789` (SQL / DataFusion construction beyond the
  filter-allowlist and projection paths).
- `src/api/provenance_issuance.rs` (referenced from entity / aggregates
  record paths; not in the stated scope for the JWT review).
- Most of `src/error.rs` (only the response-serialisation surface was
  reviewed).

Performance harness, perf k6 scenarios, and benches were not in scope.

## Remaining remediation order

The first production tranche is complete: **F1, F2, F3, F6, and F8** are
implemented and verified in the local working tree.

1. **F4** as separate CI-only PRs. Start with workflow permissions,
   action SHA pins, Docker digest pins, Dependabot Docker, and Trivy.
   Add SBOM and cosign when the image publishing path is stable.
2. **F5** only if tamper-evident audit chaining is part of the production
   promise. Keep the implementation to seeding `ChainingSink` from the
   previous file hash.
3. **F7, F9, F11-F13, F15, F17-F19** as focused hygiene fixes. Most are
   small and useful, but they should not distract from shipping the verified
   production tranche.
4. **F10** only when syslog is a real production sink. Otherwise defer.

## Methodology notes for the next pass

Each review stream returned a coverage section; future reviews should
either re-use the same partitioning (so coverage is comparable
across passes) or explicitly extend coverage into the gap list above.
The skill files under `third_party/Anthropic-Cybersecurity-Skills/skills/`
were used as technique checklists; the most directly applicable for this
codebase are:

- `testing-api-for-broken-object-level-authorization`
- `exploiting-broken-function-level-authorization`
- `detecting-broken-object-property-level-authorization`
- `testing-api-security-with-owasp-top-10`
- `testing-jwt-token-security`
- `exploiting-jwt-algorithm-confusion-attack`
- `performing-jwt-none-algorithm-attack`
- `implementing-jwt-signing-and-verification`
- `performing-cryptographic-audit-of-application`
- `implementing-digital-signatures-with-ed25519`
- `exploiting-server-side-request-forgery`
- `performing-blind-ssrf-exploitation`
- `exploiting-sql-injection-vulnerabilities`
- `performing-second-order-sql-injection`
- `testing-for-xxe-injection-vulnerabilities`
- `performing-directory-traversal-testing`
- `performing-security-headers-audit`
- `testing-cors-misconfiguration`
- `performing-clickjacking-attack-test`
- `performing-container-image-hardening`
- `hardening-docker-containers-for-production`
- `implementing-container-image-minimal-base-with-distroless`
- `securing-github-actions-workflows`
- `analyzing-sbom-for-supply-chain-vulnerabilities`
- `implementing-secret-scanning-with-gitleaks`
- `scanning-docker-images-with-trivy`
- `implementing-image-provenance-verification-with-cosign`
- `detecting-supply-chain-attacks-in-ci-cd`
- `implementing-log-integrity-with-blockchain`
- `analyzing-api-gateway-access-logs`
- `building-detection-rules-with-sigma`
- `implementing-syslog-centralization-with-rsyslog`
