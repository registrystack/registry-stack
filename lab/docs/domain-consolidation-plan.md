# Identifier Domain Consolidation Plan

<!-- markdownlint-disable MD013 -->

**Status:** Deferred (planned, not executed)
**Created:** 2026-06-27
**Origin:** Surfaced during the `id.registrystack.org` static resolver review. The resolver already publishes every identifier under `id.registrystack.org`; the registry-stack source still emits non-resolvable placeholder hosts. This plan captures the source-side consolidation so it is not lost. **Executing it is out of scope for the resolver review.**

## Problem

Registry-stack runtime code and committed artifacts emit machine identifiers (problem `type` URIs, JSON Schema `$id`, JSON-LD namespace prefixes, SHACL shape IRIs) under six domains that do not exist and never resolve:

| Host | Occurrences | Used for |
| --- | --- | --- |
| `docs.registry-notary.dev` | 76 | Notary problem `type` URIs + doc links |
| `registry-relay.dev` | 46 | Relay problem `type` base, SHACL shape/namespace IRIs |
| `schemas.registry-relay.org` | 9 | Relay JSON Schema `$id`, provenance context `dg` prefix |
| `registry-notary.dev` | 9 | Notary identifiers / spec prose |
| `registry-manifest.dev` | 7 | Manifest identifiers |
| `registry-platform.dev` | 6 | Platform (httpsec) problem `type` URIs |

153 occurrences across **61 files**. A consumer that dereferences any of these gets nothing.

The resolver at `apps/registrystack-id` already re-homes all of these to `id.registrystack.org` in its generated output, so the *published* surface is correct. The gap is that the source of truth emits the placeholders, so the resolver is compensating by hand-copying and host-rewriting rather than mirroring what the services actually serve.

## Target state

A single canonical host for all machine identifiers: **`id.registrystack.org`**, using the path layout the resolver already defines.

| Kind | Today (example) | Target |
| --- | --- | --- |
| Relay problem type | `https://registry-relay.dev/problems/...` | `https://id.registrystack.org/problems/registry-relay/...` |
| Notary problem type | `https://docs.registry-notary.dev/problems/...` | `https://id.registrystack.org/problems/registry-notary/...` |
| Platform problem type | `https://registry-platform.dev/problems/...` | `https://id.registrystack.org/problems/registry-platform/...` |
| Relay schema `$id` | `https://schemas.registry-relay.org/<x>/v1.json` | `https://id.registrystack.org/schemas/registry-relay/<x>/v1.json` |
| Provenance context `dg` | `https://schemas.registry-relay.org/provenance/v1#` | `https://id.registrystack.org/ns/registry-relay/provenance/v1#` |
| Relay SHACL namespace | `https://registry-relay.dev/ns#` | `https://id.registrystack.org/ns/registry-relay/...#` |
| Manifest identifiers | `https://registry-manifest.dev/...` | `https://id.registrystack.org/.../registry-manifest/...` |

The target equals the resolver's current output, so consolidation makes the source mirror the resolver instead of diverging from it.

**Explicitly NOT in scope (leave as-is):**

- `registrystack.org`, `docs.registrystack.org`, `stats.registrystack.org`: real org/docs/stats hosts.
- `*.lab.registrystack.org` (17 hostnames): intentional lab/demo environment hosts under the real domain.
- Third-party hosts (`registry.npmjs.org`, `registry.scalar.com`, `spdci.org`, `iana.org`, `w3.org`, `json-schema.org`).

## Decisions to settle before execution

1. **URN problem types.** Federation problems use `urn:registry-notary:problem:federation:*` (and there are `urn:registry-notary:predicate:*` identifiers). URNs are non-resolvable by design, so they are not "fake hosts," but they are inconsistent with an HTTPS-resolvable scheme. Decide: harmonize federation/predicate URNs to `https://id.registrystack.org/...`, or keep URNs as a deliberate non-dereferenceable namespace. This is separable from the host consolidation and can ship later.
2. **Single source for the base.** Today the base host is scattered as literals (e.g. `registry-relay/src/error.rs:36 PROBLEM_TYPE_BASE`, `registry-relay/src/metadata/shacl.rs:1067`). Decide whether to introduce one shared constant/config per product so the host appears once. Recommended: yes, it makes this migration and any future move a one-line change.
3. **Relay schema/context: config vs artifact.** Relay provenance emission uses operator-configured base URLs (`config/provenance.rs`: `schema_base_url`, `context_base_url`), while the committed resource files (`resources/schemas/*`, `resources/jsonld/*`) hardcode `$id`/`dg`. Both must move to `id.registrystack.org`, and the lab configs that currently set placeholder bases must be updated too.
4. **Resolver follow-up.** Once the source emits `id.registrystack.org` natively, two resolver simplifications become possible: (a) `build.mjs` no longer needs to host-rewrite copied artifacts; (b) `scripts/check-upstream-artifacts.mjs` can tighten from "normalize `$id`/`dg`" to exact `$id` match. Track as a cleanup after this lands.

## Scope inventory (61 files)

**A. Runtime emitters (source of truth), edit directly (6):**

- `crates/registry-relay/src/error.rs` (`PROBLEM_TYPE_BASE`)
- `crates/registry-relay/src/metadata/shacl.rs` (shape namespace IRI)
- `crates/registry-notary-server/src/lib.rs`
- `crates/registry-notary-server/src/openapi.rs` (problem `type` URLs in the generated spec)
- `crates/registry-platform-httpsec/src/lib.rs`
- `crates/registry-manifest-core/src/lib.rs`

**B. Committed resource artifacts + hash pins (4):**

- `crates/registry-relay/resources/schemas/entity-record/v1.json` (`$id`)
- `crates/registry-relay/resources/schemas/aggregate-result/v1.json` (`$id`)
- `crates/registry-relay/resources/jsonld/provenance/v1/context.jsonld` (`dg` prefix)
- `crates/registry-relay/resources/MANIFEST.toml`: re-pin the three SHA-256 values; a test re-hashes and asserts equality. Hash space documented in `decisions/wave-3-data-provenance.md` §10 (update the note if it cites the old host).

**C. SHACL turtle (2):**

- `crates/registry-relay/scripts/shacl/dcat-ap-catalog-smoke.ttl`
- `crates/registry-relay/scripts/shacl/bregdcat-ap-catalog-smoke.ttl`

**D. Lab/operator config (9):** `lab/config/**` YAML setting placeholder base URLs.

**E. Generated/derived: regenerate, do not hand-edit (~25):**

- 14 insta snapshots: `crates/registry-relay/tests/snapshots/error_taxonomy__*.snap` (regenerate with `cargo insta accept`).
- Manifest golden JSON (3): `crates/registry-manifest-core/tests/fixtures/golden/example-civil-registration.*.json`.
- Relay VC fixtures (2): `crates/registry-relay/tests/fixtures/vc/{entity-record,aggregate-result}-v1/payload.json`.
- Generated OpenAPI: `products/notary/openapi/registry-notary.openapi.json` (regenerate from notary source).
- Binding tests with inline expectations: `products/notary/bindings/node/test/client.test.js`, `products/notary/bindings/python/tests/test_client.py`.
- Manifest CPSV-AP fixture: `products/manifest/fixtures/cpsv-ap/health-linked-child-support.cpsv-ap.jsonld`.

**F. Test assertions with inline URL expectations, update with the source (Rust):**

- `crates/registry-relay/tests/error_taxonomy.rs`, `vc_external_verifier.rs`
- `crates/registry-notary-client/tests/{client_contract,facade_contract}.rs`
- `crates/registry-notary-server/tests/standalone_http.rs`
- `crates/registry-platform-httpsec/tests/integration.rs`
- `crates/registry-platform-testing/tests/cross_crate_integration.rs`
- `crates/registry-manifest-core/tests/metadata_core.rs`

**G. Docs/specs (4):**

- `docs/site/src/content/docs/tutorials/verify-claim-registry-api.mdx`
- `products/notary/docs/release-notes.md`
- `products/notary/specs/federated-notary-manifest-spec.md`
- (plus the resolver-side docs already covered in the review)

## Execution sequence

1. **Settle the four decisions above** (URNs, shared constant, config vs artifact, resolver follow-up).
2. **Centralize the base** per product (optional but recommended) so the host is defined once.
3. **Edit the source of truth:** group A (runtime emitters), B (artifacts), C (ttl), D (config). Keep one host string per product.
4. **Re-pin hashes:** regenerate the three `MANIFEST.toml` SHA-256 values; update `decisions/wave-3-data-provenance.md` §10 if it names the old host.
5. **Regenerate derived artifacts** (group E): `cargo insta accept`, golden/fixture updates, OpenAPI regen. Never hand-edit these.
6. **Update inline test expectations** (group F) and docs/specs (group G).
7. **Verify:** full `cargo test` (workspace) green; docs site build green; then in the resolver run `npm run check:upstream` (should still pass), and afterward tighten it to exact `$id` match (decision 4).
8. **Land atomically** across `registry-relay`, `registry-notary-*`, `registry-manifest-*`, `registry-platform-*` so a single release never mixes old and new hosts.

## Risks

- **Hash re-pin is load-bearing.** Editing the three vendored artifacts breaks the `MANIFEST.toml` re-hash assertion until the pins are regenerated. Easy to miss; it is the first thing CI will fail on.
- **Snapshot/golden churn.** ~25 derived files change. Regenerate them with the proper tooling and review the diffs; do not hand-edit, or they will drift from source.
- **Atomicity.** A partial migration produces responses where, e.g., the problem `type` is `id.registrystack.org` but an embedded schema `$id` is still `schemas.registry-relay.org`. Land per-product changes together.
- **Already-issued references.** Any VC or problem document already emitted points at the old hosts. Because those hosts never resolved, external breakage is near-zero, but note it in release notes.
- **URN scope creep.** If decision 1 chooses to harmonize URNs, that expands the diff (predicate identifiers, federation problem types, their tests/snapshots). Keep it a separate, clearly-bounded follow-up.

## Related

- Resolver review: `apps/registrystack-id` (publishes `id.registrystack.org`).
- Drift guard added during the review: `apps/registrystack-id/scripts/check-upstream-artifacts.mjs` (`npm run check:upstream`).
- Problem-code accuracy corrections: `docs/site/src/content/docs/reference/errors.mdx`.
