# Evidence guidance

This guide covers `registry-evidence`, its verifier, authoring library,
`registry-evidencectl`, and Evidence product material. Read the root guidance
and the sources relevant to the changed boundary; maintenance does not restart
the original implementation phases.

## Ownership and boundaries

Evidence evaluates fixed requests against authoritative sources and returns
minimum-disclosure assertions. One `registry-evidence` crate and `evidence`
binary serve one operator-controlled trust domain. Evidence may consume a
Relay or BReg HTTP route through its ordinary fixed source contract. Their
authorization models remain separate.

- `registry-evidence-verifier` owns response formats, the payload contract,
  and relying-party verification. It carries no server or source access.
- `registry-evidence-client` uses that verifier for verification decisions.
  Client and binding work also follows [client guidance](../../crates/CLIENTS.md).
- `registry-evidencectl` delegates evaluation, signing, bundle validation,
  and fixture evaluation to `evidence`; its client operations reuse the client
  and verifier. It adds no Evidence semantics.
- `registry-evidence-authoring` owns the authoring model and its checks without
  file, network, process, or standard-stream I/O, so one compiler serves the
  CLI and unsaved editor buffers.
- `registry-language-server` consumes those shared checks and observes neither
  source values nor SQLite. Its entire source is covered by Evidence's
  neutrality checks because it ships inside `evidencectl`.
- The [OID4VCI adapter](../../crates/registry-evidence-oid4vci/AGENTS.md) is a
  supporting service. Evidence has no runtime dependency on it. Reuse platform
  primitives where their contracts fit directly.

The immutable governed bundle owns definitions, authority, scripts, source
plans, schemas, codelists, and signing identity. The separate closed runtime
file binds process-local resources and cannot override governed semantics.
Rust owns authentication, authorization, selector minimization, credentials,
fixed source execution, script limits, output validation, signing, and audit.
Rhai performs bounded preparation, extraction, and derivation through the
closed ABI, without I/O. Reviewed exact comparison against one uniquely
resolved record does not permit fuzzy matching or candidate selection.

Caller values never create authority. Principal extraction uses the configured
direct string claim without fallback. Invalid or unauthorized selectors fail
before credentials or source I/O. Durable access audit precedes acquisition;
the terminal disclosure audit gates the exact already-serialized response.
Signing and required audit failures release nothing. Signed flattened JWS is
the mandatory default; unsigned and SD-JWT forms require their explicit bundle
and complete matched-grant permissions and never act as failure fallbacks.
Request nonces bind audience-scoped requests and responses; they do not create
a replay store. Holder-bound assertions follow their separate closed profile.

Production behavior stays source-product and domain neutral. Adult status,
residence, licence, and legal-parent relationship are coequal acceptance cases,
not built-in types, routes, or operations. The local `evidencectl` source mock
may use its closed generic synthetic-data vocabulary and the authoring-only
`x-evidencectl-mock` extension. That exception grants no runtime capability and
permits no source-product-specific behavior. Do not add future-profile stubs.

## Sources and verification

All commands below run from the monorepo root. Select focused crate tests and
the gates for the surface changed; CI owns the broader regression matrix.

| Change | Read | Verify |
|---|---|---|
| Runtime, HTTP, authorization, response format | [CONCEPT.md](CONCEPT.md), relevant [contracts](contracts/README.md), security invariant and test traceability catalogs there | Focused `registry-evidence` tests; `products/evidence/scripts/check-contracts.sh` for contract changes |
| Source or Rhai behavior | [ADAPTER-API.md](reference/request-adapter/ADAPTER-API.md), relevant source/selector/ABI contracts, [SOURCE-TESTING.md](SOURCE-TESTING.md) | Relevant source and lifecycle tests; `products/evidence/scripts/check-source-neutrality.sh` |
| Deployment and configuration | [OPERATOR-CONTRACT.md](OPERATOR-CONTRACT.md), [deployment CONFIG.md](reference/request-adapter/deployment-projects/CONFIG.md), [FIXTURES.md](reference/request-adapter/deployment-projects/FIXTURES.md) | Focused config/fixture tests and `products/evidence/scripts/check-config-key-paths.sh` |
| Verifier or client | Verifier/client crate documentation and [client guidance](../../crates/CLIENTS.md) | Changed-crate tests; `products/evidence/scripts/check-verifier-portability.sh`; neutrality gate |
| Authoring or editor model | [authoring CONFIG.md](reference/authoring-projects/CONFIG.md) and authoring crate types | Relevant authoring/editor tests; `products/evidence/scripts/check-authoring-schema.sh`, `products/evidence/scripts/check-authoring-no-io.sh`, config-key-path and neutrality gates |

Use `cargo test --locked -p <changed-crate>` with a focused test filter while
iterating. Generated public contracts under `generated/` and authoring schemas
under `crates/registry-evidencectl/schemas/authoring/` have separate promises.
Use the generators named by their gates, never hand-edit the output. For
authoring:

```sh
cargo run --locked -p registry-evidence-authoring --features schema --example authoring-schema -- --output crates/registry-evidencectl/schemas/authoring
```

After a configuration grammar changes, run the config-key-path gate with
`--write` and explain each new key in the relevant reference prose. Keep the
changed normative contract and generated artifacts aligned; use the security
matrix's enforcement points and negative tests for affected trust boundaries.
The initial phase schedule is historical, not a maintenance gate.

For adopter-facing changes, exercise the actual authoring/check/build/fixture
path or client-to-source journey. Reuse the existing fixed HTTP adapter and
shared authoring diagnostics so a new institutional source does not require a
product fork, a new service, or repeated configuration.

Source compatibility uses sanitized local mocks. Live demo tests are optional,
ignored, read-only local checks under `SOURCE-TESTING.md`. Never retain secrets,
tokens, live responses, raw selectors, source values, low-entropy per-field
hashes, or private subject identifiers in tracked files, logs, errors, or
snapshots, and do not pass them on command lines.

The existing documentation-only exceptions remain: tutorials may state the
provider-published shared credentials for the DHIS2 demo at
`https://play.im.dhis2.org/stable-2-43-1/` and place them in ignored, owner-only
files; they may state the public OpenCRVS Farajaland human login and synthetic
Josh Hoeger identifiers and use those selectors in tutorial commands.
These exceptions exclude reader-created OAuth credentials, tokens, live
responses, real identifiers, and other demo-subject identifiers. The separately
maintained adopter lab is [Solmara Lab](https://github.com/registrystack/solmara-lab).
