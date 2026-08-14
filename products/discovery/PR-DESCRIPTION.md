# feat(discovery): add a small immutable Registry Discovery index

## Summary

Replace the managed Federation V1 direction with Registry Discovery: Evidence
and Relay publish deterministic public descriptions, a catalog operator runs a
one-shot build from approved URLs, and a read-only service supports exact
search and evidence-type resolution from one immutable index.

Discovery is a curated index. The adopter remains responsible for native
Evidence or Relay trust and invokes the selected provider directly.

## Scope

- Closed `registry-discovery-v1alpha1` JSON-LD provider-publication profile.
- Offline RDFLib/pySHACL conformance oracle and Draft 2020-12 schema/Rust
  parity corpus.
- Deterministic Evidence and Relay public-description generation and serving.
- Bounded approved-origin build and immutable index.
- Health, readiness, OpenAPI, exact service search, and evidence-type
  resolution only.
- Rust, Node.js, and Python clients for product-specific bounded search,
  complete Evidence resolution context, correlated Relay selection, persisted
  selection validation, and explicit native-client handoff after local trust.
- Release-pipeline support from v0.23.0 for checksum-covered Node.js and Python
  artifacts, installed-package smoke tests, and exact npm/PyPI promotion from
  candidate bytes.
- Aggregate query, response-media, URL, method, shutdown, and blocking-work
  limits enforced consistently across the server, client, schemas, and
  generated OpenAPI.
- One Evidence and one Relay local acceptance journey, plus a clean-checkout
  adopter tutorial exercised in CI.

## Non-goals

- No scheduler, harvester, writable database, hot reload, catalog mutation,
  ranking, keyword search, pagination, aggregate catalog, or native proxy.
- No Discovery trust-store schema, credentials, authorization policy,
  provider routing, registration workflow, or Evidence procedure.
- No Discovery runtime installer or OCI image in this change.

## Refactor record

The file-level current-PR decision record is
[`products/discovery/SALVAGE-LEDGER.md`](SALVAGE-LEDGER.md). Deferred but
useful work is recorded in
[`products/discovery/FUTURE-WORK.md`](FUTURE-WORK.md), not left as dormant
production code.

## Architecture decisions

The approved boundary and standards decisions are recorded in
[`products/discovery/DECISIONS.md`](DECISIONS.md). Discovery remains a curated
index, provider descriptions remain owned by Evidence and Relay, exact
capability bindings remain distinct in RDF and the runtime index, and index
changes remain an explicit build-and-restart operation.

## Security notes

- Descriptions have one pinned local JSON-LD context and a closed strict
  parser. No remote context, RDF graph, schema, SHACL, link, or vocabulary is
  resolved at runtime.
- Evidence and Relay descriptions are closed public projections. Tests reject
  capability drift, prove private configuration cannot enter the publication,
  and preserve exact capability correlation through distinct binding IDs.
- Provider description routes serve only the packaged bytes without
  authentication, source access, signing, or audit work. Relay tests prove
  even a malformed bearer cannot turn that public route into authentication.
  The Relay exception is scoped to `discovery-description`; a regression test
  preserves supplied-bearer authentication for every other public artifact.
- The build owns exact approved HTTPS target, redirect, proxy, private-network,
  resource-bound, provenance, and atomic-write controls.
- Discovery output cannot create native trust or cause credentials or provider
  traffic before the adopter's existing local acceptance.
- Problems and diagnostics are value-free and bounded.

Security traceability: `products/discovery/contracts/security-invariant-matrix.yaml`.

## Remaining risks

- The profile is `v1alpha1` and pre-1.0. Adopters must pin it and coordinate
  profile or wire-contract upgrades.
- TLS and approved origins confine collection, but Discovery does not certify a
  provider, claim, or authorization decision. Consumers must keep their native
  Evidence or Relay trust configuration authoritative.
- Origin and mapping freshness is operationally managed through explicit
  rebuild and restart. There is intentionally no scheduler or hot reload.

## Verification

```text
[x] cargo fmt --all -- --check
[x] cargo check --locked --workspace --all-targets
[x] cargo clippy --locked --workspace --all-targets -- -D warnings
[x] cargo test --locked --workspace
[x] ~/.cargo/bin/cargo-deny check
[x] products/discovery/scripts/check-contracts.sh
[x] products/discovery/scripts/test-http.sh
[x] products/discovery/scripts/test-adopter-tutorial.sh
[x] products/evidence/scripts/check-contracts.sh
[x] products/evidence/scripts/check-source-neutrality.sh
[x] products/evidence/scripts/check-verifier-portability.sh
[x] products/relay-v2/scripts/check-contracts.sh
[x] products/relay-v2/scripts/check-authoring-schema.sh
[x] products/relay-v2/scripts/test-http.sh
[x] products/identifiers/scripts/check.sh
[x] Evidence and Relay Node clients: npm ci, build:debug, test, check:types
[x] Discovery Node and Python clients: build, tests, generated types, installed-package smokes
[x] Registry release plan, candidate inventory, and client-package promotion tests
[x] python3 .github/scripts/test_ci_changes.py
[x] cd docs/site && npm test
[x] cd docs/site && npm run check
```
