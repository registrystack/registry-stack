# Security Principles

These are the house rules encoded by `registry-platform`. Consumer apps should cite the relevant principle when they adopt, extend, or intentionally defer a platform primitive.

## 1. Fail Closed By Default

Security APIs must return `Result` for missing policy, malformed config, absent secrets, unsupported algorithms, and impossible verification states. Empty allowlists deny unless the API explicitly documents an any-client mode, such as OIDC `allowed_clients = []`.

Examples:

- `AuditKeyHasher::from_env` errors when the secret is absent or invalid.
- Static auth accepts `hash_env` fingerprints only; plaintext token loading is a migration blocker.
- OIDC allowlist matching uses `azp` first, then `client_id`; `sub` is never an authentication allowlist fallback.

## 2. Redact Secrets In Debug Output

Any type that can hold bearer tokens, private JWK fields, audit HMAC secrets, API keys, SD-JWT signing material, or decoded credential secrets must use manual `Debug` or derive-safe wrappers. Tests should assert redaction for key structs because accidental `#[derive(Debug)]` regressions are easy to miss in review.

## 3. Zeroize Key Material Where It Matters

Private signing keys and plaintext credentials should zeroize on drop when they live in owned process memory. Shared long-lived secrets may use `Arc<[u8]>` only with an explicit rationale, as with `AuditHashSecret`, where cloning a zeroizing buffer would otherwise create confusing ownership semantics.

## 4. Size-Cap Untrusted I/O

Every inbound and outbound body read must have a byte cap. Defaults should be small and documented, with 1 MiB as the baseline for registry metadata, OIDC discovery, JWKS, and API request bodies unless the caller proves a larger cap is needed.

## 5. Make Crypto Payloads Deterministic

Protocol-bound payloads need byte-stable representations. Sort sets before hashing or signing, use JCS canonicalization where JSON byte equality matters, and let issuers generate identifiers such as `credential_id`, `jti`, and `sub_ref` when those values participate in verification invariants.

## 6. Deny Risky Outbound Fetches

Outbound clients deny redirects by default and validate URLs with `FetchUrlPolicy` before fetching. Production policy allows HTTPS only and denies localhost, RFC1918, link-local, IPv4-mapped loopback, and cloud metadata addresses. Development policy allows plain HTTP only for hosts that resolve to loopback.

DNS hostnames must be validated after resolution. Callers must not bypass policy by resolving hostnames themselves and feeding socket addresses directly to an HTTP client.

## 7. Build URLs With Structured APIs

Never concatenate untrusted path segments into URLs. Use `url::append_path_segments` or an equivalent structured builder so path separators, `..`, percent encoding, and query delimiters cannot change the request target.

## 8. Bound Expensive Work

CPU-heavy crypto and evaluation work should run on bounded worker paths, usually `spawn_blocking` plus a wall-clock timeout. Parsing, canonicalization, verification, and redaction should reject pathological inputs early enough that one request cannot monopolize the runtime.

## 9. Make Security Events Tamper Evident

`registry-platform-audit` provides the tamper-evident primitive: `AuditEnvelope`, `ChainState`, the JSONL sinks, and the HMAC redaction helpers. Consumer applications (Registry Relay, Registry Notary, and other services) are responsible for routing their security-relevant events through it, including auth failures, admin reloads, OIDC verifier changes, policy bypasses, SD-JWT issuance, holder-proof validation failures, config reload outcomes, and outbound fetch denials.

Platform crates outside `audit` deliberately do not take a hard dependency on `audit`. They surface security-relevant outcomes as `Result` types and structured errors so consumers can choose how to emit them. A consumer audit confirms wiring; absence of wiring inside a platform primitive is not a platform defect.

PII-bearing identifiers must be hashed or redacted before envelope construction. Use keyed HMAC hashing in operator-facing environments; `unkeyed_dev_only()` is only for local fixtures and tests.

Audit chain verification (`registry_platform_audit::verify_chain`) is a consistency check over the retained records. It detects edits, insertions, reordering, and deletions of interior records inside that set, but it does not detect removal of trailing records, deletion of leading retained records, or a malicious actor replacing the full retained log set with a new internally consistent chain. Completeness is an off-host shipping guarantee, not a property local verification can establish: ship audit records to a log aggregator, SIEM, or other store outside the host, and declare `deployment.evidence.audit_offhost_shipping`. Evidence-grade Relay and Notary deployments refuse startup when a local `file` or `jsonl` sink is used without that declaration. `deployment.evidence.audit_ack_cursor_path` adds an observed freshness signal on top of that declared attestation: it points at a local state file the shipper writes on each successful hand-off (the `registry.audit.ack_cursor.v1` contract in `registry-platform-ops`), and `registry_platform_ops::evaluate_ack_health` reports whether that cursor is still fresh. It is a liveness check on the shipping path, not a completeness proof.

## 10. Keep Workspace Hygiene Canonical

`clippy.toml`, `rustfmt.toml`, and `deny.toml` in consumer repos come from `registry-platform/templates/`. Consumer CI must run `scripts/check-hygiene-alignment.sh` so lint, formatting, dependency license policy, and advisory posture do not drift.

## Telemetry Convention For v0.1.0

There is no telemetry crate in v0.1.0. Until one exists, consumers should use stable, low-cardinality field names for security logs: `request_id`, `principal_id_hash`, `auth_mode`, `issuer`, `client_id`, `azp`, `scope`, `policy`, `decision`, `audit_envelope_id`, and `error_code`. Logs must not include bearer tokens, raw API keys, private key material, full SD-JWTs, or unredacted subject identifiers.
