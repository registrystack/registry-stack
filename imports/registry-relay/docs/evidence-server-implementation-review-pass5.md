# Evidence Server Implementation Review — Pass 5

Historical note: this review predates the repository split. Paths such as
`src/api/evidence.rs`, `src/evidence/registry_relay.rs`, and
`crates/evidence-*` refer to the former embedded Registry Relay implementation.
Current Evidence Server code lives in the sibling `../evidence-server`
repository.

**Date:** 2026-05-22
**Reviewer:** Claude (multi-agent synthesis)
**Spec:** `docs/evidence-server-spec.md`
**Prior passes:** `evidence-server-implementation-review-pass3.md`, `evidence-server-implementation-review-pass4.md`

## TL;DR

CI is green for the first time across the review series. Clippy passes cleanly, and the previously-failing `evidence_dci_source_bindings_must_reference_named_spdci_registry` test now passes (the fixture was corrected; the validator was already right). Net DoD progress since pass-4 is real but modest: **72 of 90 line items DONE (80%)**, up from 69/90 (77%).

The developer's claim of "95%+ ready" is still **not defensible**. Eight DoD items remain fully or partially OPEN, including one HIGH severity finding (H2: only `did:jwk` holder binding actually works) that has been carried over from pass-3 unchanged. A new architectural regression has appeared: the env-var leak previously isolated to `crates/evidence-core/src/sd_jwt.rs` has now been replicated into `src/evidence/registry_relay.rs`.

## CI status (independently verified)

| Check | Pass-4 | Pass-5 |
|---|---|---|
| `cargo fmt --all -- --check` | warn (nightly opts) | warn (nightly opts) |
| `cargo build --workspace --all-features` | OK | OK |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | **FAIL (6 errors)** | **OK** |
| `cargo test --workspace --all-features` | **FAIL (1 test)** | **OK** |
| `cargo test -p registry_relay --test evidence_api` | OK (78 tests) | OK (81 tests) |

## What got fixed since pass-4

Each item below was verified by reading the cited code, not inferred.

1. **Q2 — Clippy errors (all 6).**
   - `src/config/validate.rs:762` now has `#[allow(clippy::too_many_arguments)]` above `validate_evidence_bound_field`.
   - `src/config/mod.rs:94` uses `#[derive(Debug, Clone, Default, Deserialize)]` on `EvidenceVerificationConfig`; manual `Default` impl removed.
   - `src/api/evidence.rs` lines 58, 69, 97, 342: `useless_conversion` patterns removed.

2. **Workspace test regression — `evidence_dci_source_bindings_must_reference_named_spdci_registry`.**
   - At `tests/config_loader.rs:1071-1106`. Test now passes because the fixture (`dci_evidence_body` / `dci_standards_body`) was made internally consistent. Validator logic at `src/config/validate.rs:360-419` was correct all along; the test fixture had mismatched field names. Sound fix.

3. **NEW-1 — Atomicity of credential issuance vs. PoP replay ledger.**
   - At `src/api/evidence.rs:430`: `sd_jwt::issue` is now called **before** `record_holder_proof` at lines 434-437. Signing failures no longer consume the `jti` from the replay ledger.
   - **Gap:** no regression test was added. There is no test in `tests/evidence_api.rs` that forces an `issue` failure and then re-uses the same `jti` successfully on the next attempt.

4. **M2 — Discovery endpoints required auth.**
   - `service_document` at `src/api/evidence.rs:52-61`: now guards `if principal.is_none() { return 401 }`.
   - `list_formats` at `src/api/evidence.rs:138-153`: same guard.
   - Test `discovery_requires_authentication` at `tests/evidence_api.rs:710-719` asserts 401 on `/.well-known/evidence-service`, `/claims`, `/formats`.

5. **H7 (partial) — Idempotency record TTL and sweep.**
   - `IdempotencyRecord` at `crates/evidence-server/src/runtime.rs:59-64` now has `expires_at: OffsetDateTime`.
   - `insert_idempotent_batch` at runtime.rs:153-170 sets `expires_at = now + 15 minutes`.
   - `idempotent_batch` at runtime.rs:132-151 sweeps with `records.retain(|_, r| r.expires_at > now)`.
   - `evaluations` map is also swept on each `insert`.

6. **Cap. #19 — CEL `meta` binding populated.**
   - `cel_meta(...)` at runtime.rs:929-955 returns a CEL `Value::Map` containing `service_id`, `api_version`, `claim.{id, version, subject_type}`, and `sources` (map keyed by binding name).
   - Tested at `tests/evidence_api.rs:845-856` via the `farmer-meta-service` fixture (`tests/evidence_api.rs:371-396`).

7. **Cap. #18 / Cap. #19 — CEL undeclared-field rejection.**
   - `expression_has_undeclared_references` at runtime.rs:725-783, with `source_path_is_undeclared` at runtime.rs:818-835, walks the CEL AST and cross-checks each `source.<binding>.<path>` reference against the declared binding bag.
   - Tested at `tests/evidence_api.rs:986-997` via the `farmer-unknown-source-field` fixture (`tests/evidence_api.rs:397-422`).

## What is still open, by severity

### HIGH

**H2 — Only `did:jwk` holder bindings actually work.**
- `src/api/evidence.rs:597-606` still hardcodes the `did:jwk:` prefix when extracting the holder key, and `crates/evidence-core/src/config.rs:299,310` accepts `allowed_did_methods` as arbitrary strings with no enforcement that the resolver supports them.
- Operationally, configuring `allowed_did_methods = ["did:key"]` will be accepted at boot and then 500 (or silently mis-resolve) at issuance. This is the same finding from pass-3 (H2) and pass-4 (H2). No code change in pass-5.
- **Fix path:** either restrict the config schema to the methods the binder actually implements, or add a real `did:key` / `did:web` resolver behind the existing dispatch.

**NEW-1 regression test (carried from pass-4).**
- The ordering fix is in place but unguarded. A future refactor that re-introduces "record PoP before signing" would silently regress without a test. Add a fixture that injects a deterministic signing failure (e.g., missing issuer key) and asserts the next `POST /credentials/issue` with the same holder proof succeeds.

### MEDIUM

**H3 — `cnf.jwk` not honored when binding mode is `jwk`.**
- `crates/evidence-core/src/sd_jwt.rs:141-142` still emits `cnf: { kid: ... }` unconditionally regardless of the holder binding mode declared by the claim definition. Spec requires `cnf: { jwk: <holder JWK> }` when mode is `jwk`.

**H6 — Disclosure profile reported as literal `"mixed"`.**
- `runtime.rs:1081-1093` still returns the string `"mixed"` when a claim's disclosures span multiple profiles. Spec calls for per-field profile reporting in the audit record. Operators reading audit logs cannot reconstruct which fields were value vs. predicate vs. redacted.

**M3 — JWK with private fields not rejected at PoP validation.**
- No explicit check in the PoP path that rejects holder JWKs containing `d`, `p`, `q`, `dp`, `dq`, `qi`. A misconfigured client could submit its full private key and the server would accept it (and log it in audit context).

**Cap. #34 / Test #34 — ID Mapper boundary is a no-op.**
- `src/evidence/registry_relay.rs`: `RegistryRelaySourceReader` does **not** override `map_subject`, and `lookup_value` at lines 275-286 only matches `subject_id | subject.id`; `subject.id_type` is never read.
- This is the same finding from pass-3 and pass-4. The spec calls for ID translation between caller-presented subject IDs and source-native IDs; today the implementation is identity.

### LOW / quality

**Q1 — Env-var read at signing time (architectural).**
- `crates/evidence-core/src/sd_jwt.rs:41` still calls `std::env::var(...)` inside the domain crate. The runtime race is mitigated by a `OnceLock`, but the architectural smell remains: domain crates shouldn't read process env. **New in pass-5:** the same pattern has been introduced in `src/evidence/registry_relay.rs:89` (`read_remote_registry_data_api_one` calls `std::env::var(&connection.token_env)` at request time). This is a regression in the direction of travel.

**Q3 — Vacuous test.**
- `crates/evidence-core/src/sd_jwt.rs:236-238`: `signing_algorithm_header_value_is_stable` still asserts `assert_eq!("EdDSA", "EdDSA")`. Either delete it or make it assert against the actual JWS header alg field.

**Q4 — `SubjectRequest.id_type` parsed but ignored.**
- `crates/evidence-core/src/model.rs:80` parses `id_type` and downstream code never consumes it. Either thread it through the lookup path (and into ID Mapper) or remove it from the request schema.

**Q5 — `results[0]` indexing in evaluation insert.**
- `crates/evidence-server/src/runtime.rs:115` indexes `evaluation.results[0]` without checking emptiness. An evaluation with zero results would panic. Today the call sites always produce at least one result, but this is a latent foot-gun.

### DoD items still PARTIAL or OPEN

| Item | Status | Where |
|---|---|---|
| Test #2 (claim definition error mapping) | PARTIAL | not all error variants exercised |
| Test #8 (per-item `evaluation_id` echoed in batch) | OPEN | no explicit assertion in `tests/evidence_api.rs` |
| Test #15 (issuer-missing format discovery) | OPEN | no test asserts behavior when issuer config absent |
| Test #18 (metadata conflict via route, not just validator) | OPEN | only tested at config-load time |
| Test #27 (disclosure downgrade to default / redacted) | OPEN | no fixture exercises downgrade path |
| Test #31 (purpose/requester mismatch, omitted purpose header) | PARTIAL | header omission not asserted |
| Test #34 (ID Mapper roundtrip) | OPEN | see Cap. #34 above |
| Test #37 / Cap. #31 (render audit on failure) | OPEN | `src/api/evidence.rs:329` returns directly without writing audit |

## DoD count

- Required Capabilities: 30 of 36 DONE
- Required Tests: 30 of 37 DONE
- Not Done If clauses: 12 of 17 cleared
- **Total: 72 of 90 (80%)**

## Shortest path to "ready"

Reduced from pass-4's 11 items to 7. In rough priority order:

1. **H2** — pick one: restrict `allowed_did_methods` to `["did:jwk"]` in config validation (and document it as the v0 scope), or implement `did:key` / `did:web` resolution behind the existing dispatch.
2. **NEW-1 regression test** — add a fixture that forces signing to fail and asserts the holder `jti` is still reusable.
3. **Cap. #34 / Test #34** — implement the ID Mapper boundary (`RegistryRelaySourceReader::map_subject` + use `subject.id_type` in lookups) and test the roundtrip.
4. **H3** — emit `cnf: { jwk }` when binding mode is `jwk`; keep `kid` only for `kid` mode.
5. **H6** — report per-field profiles in the disclosure audit record instead of the literal string `"mixed"`.
6. **M3** — reject holder JWKs carrying private-key fields at the PoP boundary.
7. **Remaining test gaps** — Test #8, #15, #18, #27, #31, #37. These are small, mostly assertion-only additions to existing fixtures.

After (1)–(7), the implementation would clear all HIGH findings, the architectural ID Mapper requirement, and the test gaps. Cap. #31 (render audit on failure) is bundled with Test #37 above. The env-var architectural smell (Q1, and its new instance in `registry_relay.rs:89`) is a v1 cleanup, not a v0 blocker.

## Honest read on "95%+ ready"

Pass-3 reported ~74%, pass-4 ~77%, pass-5 ~80%. The trajectory is correct but the rate is slower than the developer's framing implies. The hardest remaining items (H2, ID Mapper, render-audit-on-failure) have been carried unchanged across three review passes. Until those land, "95%+" is aspirational, not current.
