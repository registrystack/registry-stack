# Evidence guidance

This guide covers `registry-evidence`, its verifier, authoring library,
`registry-evidencectl`, and Evidence product material. Read the root guidance
and the sources relevant to the changed boundary; maintenance does not restart
the original implementation phases.

## Ownership and boundaries

Evidence evaluates fixed requests against authoritative sources and returns
minimum-disclosure assertions. One `registry-evidence` crate and `evidence`
binary serve one operator-controlled trust domain. Evidence may consume a
protected registry HTTP route through its ordinary fixed source contract, or another
Evidence service through that contract's signed Evidence protocol. Their
authorization models remain separate. Signed sources reuse the Evidence
client's offline request preparation and verifier with governed trust pins.

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
- The standalone `registry-language-server` consumes those shared checks and
  observes neither source values nor SQLite. Its entire source remains covered
  by Evidence's neutrality checks because it is a public Evidence authoring
  surface, but it does not ship inside `evidencectl`.
- The [OID4VCI adapter](../../crates/registry-evidence-oid4vci/AGENTS.md) is a
  supporting service. Evidence has no runtime dependency on it. Reuse platform
  primitives where their contracts fit directly.
- The [OpenID4VP verifier](../../crates/registry-evidence-oid4vp/README.md) is
  a supporting service with the same dependency direction. It checks protocol
  facts only (decryption, `state`, response shape, single acceptance, expiry)
  and never persists a presentation. Every credential check runs in Evidence
  through the pure `registry-evidence-presentation` crate, so a compromised
  verifier service can withhold or misroute a presentation but cannot forge
  one.

The immutable governed bundle owns definition behavior, grant ceilings, scripts,
source plans, schemas, codelists and signing identity. Separately activated target
authority may narrow the package ceilings and has its own revision, digest and
durable history. The closed runtime file binds process-local resources and cannot
override governed semantics. One process retains its resolved authority snapshot;
live task-grant validity and release gates still apply.
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
a replay store. Intake idempotency keys of the status module are not request
nonces. Holder-bound assertions follow their separate closed profile.

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
| Runtime, HTTP, authorization, response format | Relevant [contracts](contracts/README.md), security invariant and test traceability catalogs there | Focused `registry-evidence` tests; `products/evidence/scripts/check-contracts.sh` for contract changes |
| Source or Rhai behavior | The [derivation script API](https://docs.registrystack.org/reference/evidence-request-adapter-api/) and the relevant source/selector/ABI contracts | Relevant source and lifecycle tests; `products/evidence/scripts/check-source-neutrality.sh` |
| Deployment and configuration | [OPERATOR-CONTRACT.md](OPERATOR-CONTRACT.md), [deployment CONFIG.md](reference/request-adapter/deployment-projects/CONFIG.md) and the [fixture contract](https://docs.registrystack.org/reference/evidence-fixtures/) | Focused config/fixture tests and `products/evidence/scripts/check-config-key-paths.sh` |
| Verifier or client | Verifier/client crate documentation and [client guidance](../../crates/CLIENTS.md) | Changed-crate tests; `products/evidence/scripts/check-verifier-portability.sh`; neutrality gate |
| Credential status ledger or OID4VCI store | `crates/registry-evidence/src/status/` and its `tests/status_*.rs` tests (the version 2 credential status profile is not yet published as a contract) | Changed-crate tests; with `--features postgres-test` and a disposable PostgreSQL server, `registry-evidence` `--test status_ledger --test status_transitions --test status_privacy` (`EVIDENCE_STATUS_TEST_DATABASE_URL`) and `registry-evidence-oid4vci` `--test store_contract` (`EVIDENCE_OID4VCI_TEST_DATABASE_URL`) |
| Holder-presented channel or OpenID4VP verifier | [contracts/oid4vp-profile.yaml](contracts/oid4vp-profile.yaml), and the [verifier README](../../crates/registry-evidence-oid4vp/README.md) | Changed-crate tests; with `EVIDENCE_BIN` and `EVIDENCECTL_BIN` built, `registry-evidence-oid4vp` `--test evidence_journey a_presented_credential_becomes_a_verified_assertion` and `--test device_run a_simulated_wallet_completes_the_device_run_harness`, each with `-- --ignored --exact`; `products/evidence/scripts/check-contracts.sh`, `check-verifier-portability.sh`, and the neutrality gate |
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

For adopter-facing changes, exercise the actual authoring/check/package/fixture
path or client-to-source journey. Reuse the existing fixed HTTP adapter and
shared authoring diagnostics so a new institutional source does not require a
product fork, a new service, or repeated configuration.

Source compatibility uses sanitized local mocks. Live demo tests are optional,
ignored, read-only, non-gating local checks run only after the deterministic
mocks pass and only with approved synthetic selectors and securely stored
credentials (see Live public-demo checks below). Never retain secrets,
tokens, live responses, raw selectors, source values, low-entropy per-field
hashes, or private subject identifiers in tracked files, logs, errors, or
snapshots, and do not pass them on command lines.

Evidence must not depend on `registry-notary*`, `registry-platform-oid4vci`,
`registry-platform-replay`, `registry-platform-sts`, or Registry Manifest.

## Live public-demo checks

Live checks live in the ignored `live_sources` test target of
`registry-evidence`. Run them in this order, and only after the package suite
passes:

```sh
cargo test --locked -p registry-evidence
cargo test --locked -p registry-evidence --test live_sources dhis2 -- --ignored
cargo test --locked -p registry-evidence --test live_sources opencrvs -- --ignored --exact
```

- A live test skips, rather than improvises, when required values or an
  approved synthetic selector are absent.
- Live tests are read-only. They may authenticate, request a token and perform
  a bounded record lookup. They must not create, update, register, certify,
  print, archive or delete records, and must not use a browser session, a human
  login or interactive two-factor credentials.
- OpenCRVS may record the system-client search in its remote audit log. That
  server-side effect and any request quota are part of the operator's decision
  to run the test.
- Selector values and any alternative tracking or national identifier stay
  local. They never appear in a fixture, test name, snapshot, log, audit
  record, error or command line.
- A pass shows only that the selected demo version still accepts the documented
  authentication and bounded lookup shape. A passing live check must not be
  described as certification of a complete deployment project; deterministic
  mocks and executable project fixtures own those contracts.

The existing documentation-only exceptions remain: tutorials may state the
provider-published shared credentials for the DHIS2 demo at
`https://play.im.dhis2.org/stable-2-43-1/` and place them in ignored, owner-only
files; they may state the public OpenCRVS Farajaland human login and synthetic
Josh Hoeger identifiers and use those selectors in tutorial commands.
These exceptions exclude reader-created OAuth credentials, tokens, live
responses, real identifiers, and other demo-subject identifiers. The separately
maintained adopter lab is [Solmara Lab](https://github.com/registrystack/solmara-lab).
