# Registry Stack Agent Guidance

This is the Registry Stack monorepo: registry-facing services over data
institutions already hold. Pre-1.0; APIs and deployment contracts may change.

Two runtime patterns anchor everything:

- **Registry Relay** exposes protected, scoped, read-only HTTP APIs over
  existing sources.
- **Registry Notary** certifies evidence: claim evaluation, credential
  issuance, disclosure policy, audit provenance.

Registry Manifest describes sources portably; Relay is its consumer in code
(Notary does not depend on the manifest crates). `registry-platform-*` crates
are shared primitives. `registryctl` is adopter tooling.

## Repository map

| Area | Owns |
|---|---|
| `crates/registry-relay` | Protected read APIs (Relay) |
| `crates/registry-notary*` | Evidence gateway: server, core, client, source adapters, worker harness (Notary) |
| `crates/registry-manifest-*` | Manifest core types and CLI |
| `crates/registry-platform-*` | Shared primitives: audit, authcommon, cache, config, crypto, httpsec, httputil, oid4vci, oidc, ops, pdp, replay, sdjwt, sts, testing |
| `crates/registryctl` | Adopter tooling |
| `products/` | Product-owned specs, examples, fixtures, docs (not crates) |
| `docs/site/` | Public docs site (Astro). Has its own `AGENTS.md`; read it before touching this subtree |
| `release/` | Release manifests, schemas, notes, validation tooling, and the release source-model proof |
| `external/` | Notes on inputs that intentionally stay out of this tree (e.g. Crosswalk stays a pinned git dependency) |

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
`deny.toml` with review triggers), and the OpenAPI drift checks for both
products (`just openapi-check` from `products/notary`, `just openapi-contract`
from `crates/registry-relay`). cargo-deny needs v0.19+ to parse this
`deny.toml`; CI pins 0.19.8.

Release source checks:

```bash
python3 -m unittest release/scripts/test_registry_release.py
release/scripts/registry-release validate release/manifests/<current>.yaml
REGISTRY_RELEASE_SOURCE_MODE=monorepo release/scripts/check-release-source-model.sh
python3 -m unittest release/scripts/test_check_release_source_model.py
```

Docs site (from `docs/site/`): `npm test` and `npm run check`.

## Rules that bite

- Every commit needs a DCO sign-off: `git commit -s`.
- Commit subjects: imperative mood; `fix(notary):` / `feat(relay):` style
  prefixes are the norm for product-scoped changes.
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
