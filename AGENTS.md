# Registry Stack Agent Guidance

This is the Registry Stack monorepo: registry-facing services over data
institutions already hold. Pre-1.0; APIs and deployment contracts may change.

Three independent runtime patterns are relevant:

- **Registry Relay** exposes protected, scoped, read-only HTTP APIs over
  existing sources.
- **Registry Notary** certifies evidence: claim evaluation, credential
  issuance, disclosure policy, audit provenance.
- **Evidence** is a separate minimum-disclosure assertion service. It is not a
  Notary mode or rewrite and does not inherit the Notary product model.

Registry Manifest describes sources portably; Relay is its consumer in code
(Notary does not depend on the manifest crates). `registry-platform-*` crates
are shared primitives. `registryctl` is adopter tooling.

## Repository map

| Area | Owns |
|---|---|
| `crates/registry-relay` | Protected read APIs (Relay) |
| `crates/registry-notary*` | Evidence gateway: server, core, client, source adapters, worker harness (Notary) |
| `crates/registry-evidence` | Single-crate Evidence runtime and `evidence` binary |
| `crates/registry-manifest-*` | Manifest core types and CLI |
| `crates/registry-platform-*` | Shared primitives: audit, authcommon, cache, config, crypto, httpsec, httputil, oid4vci, oidc, ops, pdp, replay, sdjwt, sts, testing |
| `crates/registryctl` | Adopter tooling |
| `products/` | Product-owned specs, examples, fixtures, docs (not crates) |
| `docs/site/` | Public docs site (Astro). Has its own `AGENTS.md`; read it before touching this subtree |
| `release/` | Release manifests, schemas, notes, validation and conformance tooling, and the release source-model proof |
| `external/` | Notes on inputs that intentionally stay out of this tree (e.g. Crosswalk stays a pinned git dependency) |

## Evidence product boundary

Evidence work must remain independent from `registry-notary*`. Do not copy or
depend on Notary product abstractions merely because both products use the word
evidence. In particular, Evidence version one does not inherit credential
issuance, OID4VCI, SD-JWT, PDP, replay, federation, worker, or document
subsystems.

The implementation is one `registry-evidence` crate and one `evidence` binary.
It may reuse narrowly applicable `registry-platform-*`
primitives such as audit, crypto, OIDC, HTTP security, and testing. It must not
depend on `registry-notary*`.

Evidence configuration and scripts are trusted, startup-only deployment
artifacts. Rust owns authentication, authorization, fixed source execution,
bounded script execution, output validation, evidence construction, signing,
and audit. Rhai owns bounded request preparation, source extraction, and
requirement-specific derivation, using only deterministic, bounded,
domain-neutral primitives supplied by Rust.
Adult status, residence region, professional licence status, and legal-parent
relationship are coequal full-path Evidence acceptance definitions. None may
become a Rust domain type, built-in operation, special route, or implementation
phase.

Evidence implementation changes require its approved Version 1 contracts,
schedule, and Definition of Done to remain aligned in tracked product material.
Do not call the product implemented when only one assertion case or a subset of
that DoD passes. Stop before the approved concept's non-goals and future
profiles.

Evidence source compatibility is proven with sanitized local mocks in ordinary
tests. Public demo checks are opt-in, ignored, read-only local tests after the
mock suite passes. Credentials, tokens, live responses, demo-subject
identifiers, and human login or two-factor details must not be committed,
logged, placed in snapshots, or passed on command lines.

DHIS2 and OpenCRVS names and behavior are test-only. Evidence production code,
dependencies, Cargo features, public configuration schemas, routes, and CLI
options must remain source-product neutral.

The `changing-notary-endpoints` skill and Notary-specific OpenAPI commands do
not apply to Evidence. Use the Evidence-specific guidance and verification
commands rather than extending Notary guidance by analogy.

The adopter demo is maintained separately in
[`registrystack/solmara-lab`](https://github.com/registrystack/solmara-lab).

## Verify your change

Run the checks that match the files you changed; the full PR gate is
`.github/workflows/ci.yml`.

Rust workspace:

```bash
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo test --locked -p <changed-crate>   # then the workspace if platform crates changed
```

Root CI's `rust` job runs `cargo fmt --check`, `cargo check --locked
--workspace --all-targets`, `cargo clippy --workspace --all-targets --
-D warnings`, `cargo test --locked --workspace`, the full `cargo deny check`
(advisories included; unresolvable RUSTSEC advisories carry scoped ignores in
`deny.toml` with review triggers), and the Notary and Relay OpenAPI drift checks
(`just openapi-check` from `products/notary`, `just openapi-contract` from
`crates/registry-relay`). cargo-deny needs v0.19+ to parse this
`deny.toml`; CI pins 0.19.8.

Evidence-specific contracts and source neutrality:

```bash
products/evidence/scripts/check-contracts.sh
products/evidence/scripts/check-source-neutrality.sh
```

Release source checks:

```bash
python3 -m unittest release/scripts/test_registry_release.py
python3 -m unittest release/scripts/test_openid_conformance_runner.py
release/scripts/registry-release validate release/manifests/<current>.yaml
REGISTRY_RELEASE_SOURCE_MODE=monorepo release/scripts/check-release-source-model.sh
python3 -m unittest release/scripts/test_check_release_source_model.py
```

Docs site (from `docs/site/`): `npm test` and `npm run check`.

## Rules that bite

- Every commit needs a DCO sign-off: `git commit -s`.
- Commit subjects: imperative mood; `fix(notary):`, `feat(relay):`, and
  `feat(evidence):` style prefixes are the norm for product-scoped changes.
- History may be rewritten during review (session commits get squashed). In
  durable docs, cite only commits reachable from pushed `main`, and prefer
  stable facts plus dates over commit SHAs.
- Major functionality and bug fixes require automated tests with the change.
- Keep a change scoped to one owning area (`crates/`, `products/`,
  `docs/site/`, `release/`).
- Changes to authentication, authorization, credential issuance, signing,
  audit integrity, release provenance, deployment defaults, or data
  minimization are security-sensitive and need explicit review notes.
- Generated outputs (OpenAPI under `docs/site/openapi/`, `docs/site`
  generated data, release artifacts) must be reproduced by their documented
  generator commands, never hand-edited, and must be bit-for-bit repeatable.
  If you change an HTTP endpoint, regenerating and committing the OpenAPI
  documents is part of the change, not a follow-up.
- Suspected vulnerabilities (credential disclosure, auth bypass, audit
  redaction failure, connector data leakage, signing key handling) go through
  `SECURITY.md`, never public issues or PRs.

## Deeper guidance

`CONTRIBUTING.md` (policies in full), `README.md` (orientation),
`ROADMAP.md` (direction), `docs/site/AGENTS.md` (docs subtree),
`release/VERIFY.md` and `release/REPEATABLE-BUILDS.md` (release evidence).
