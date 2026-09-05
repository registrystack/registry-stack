# Registry Stack Agent Guidance

This is the Registry Stack monorepo: registry-facing services over the data
institutions already hold and the registries they do not hold yet. Pre-1.0;
APIs and deployment contracts may change.

Three independent runtime products are relevant:

- **Base Registry Engine** compiles a declared registry project into a
  PostgreSQL-backed writable registry: schema, REST API, per-profile
  permissions, revision history, and audit journal.
- **Registry Relay** exposes protected, scoped, read-only HTTP APIs over
  existing sources.
- **Evidence** returns signed, minimum-disclosure assertions from fixed
  requests to authoritative sources.

The three compose without merging their product boundaries: Evidence may use a
Base Registry Engine route or a Relay-protected API as a fixed HTTP source, and
inherits neither one's authorization.

Registry Manifest describes sources portably; Relay is its consumer in code
and `registry-platform-*` crates are shared primitives. `relayctl` is Relay
adopter tooling; `registry-evidencectl` is Evidence adopter tooling.

Registry Mint is a supporting service, not a runtime product of its own: it
issues the access tokens a resource server such as Evidence or Base Registry
Engine verifies, for deployments with no identity provider. The dependency runs
one way only in production: no Evidence crate depends on Mint at runtime. Mint's
tests drive Evidence's authenticator, and Evidence test code may drive a real
Mint instance to prove a client against a real authorization server.

`registry-evidence-oid4vci` is a supporting service in the same sense, not a
runtime product of its own: it delivers Evidence credentials to a wallet over
OID4VCI 1.0 Final, the wallet-facing protocol Evidence deliberately refuses to
speak. It never signs a credential, Evidence signs; it never holds a holder
private key, it receives holder public keys inside wallet-signed proofs and
passes them to Evidence unchanged; and it adds no Evidence semantics of its own.
The dependency runs one way only in production: no Evidence crate depends on
`registry-evidence-oid4vci` at runtime.

## Repository map

| Area | Owns |
|---|---|
| `crates/registry-discovery` | Immutable Registry Discovery index runtime and the `discovery` binary |
| `crates/registry-discovery-profile` | Closed provider-publication profile shared by Evidence and Relay |
| `crates/registry-discovery-client` | Rust relying-party SDK for bounded search, resolution, and inert exact selections |
| `crates/registry-discovery-client-node` | Node.js binding for `registry-discovery-client`, via napi-rs |
| `crates/registry-discovery-client-py` | Python binding for `registry-discovery-client`, via PyO3 |
| `crates/registry-discoveryctl` | Offline origin and mapping checks plus immutable index builds |
| `crates/registry-breg` | Base Registry Engine runtime, the registry-project compiler, and the `breg` binary |
| `crates/registry-bregctl` | Base Registry Engine adopter tooling and the `bregctl` binary |
| `crates/registry-breg-client` | Base Registry Engine client and its opaque authorization handles |
| `crates/registry-breg-client-node` | Internal napi-rs binding used to assemble the unified Node.js client |
| `crates/registry-breg-client-py` | Internal PyO3 binding used to assemble the unified Python client |
| `crates/registry-stack-client` | Rust facade over the maintained Registry Stack product clients |
| `crates/registry-stack-client-node` | Public `@registrystack/client` facade and platform package definitions |
| `crates/registry-stack-client-py` | Public `registry-stack-client` Python facade assembled with all native bindings |
| `crates/registry-evidence` | Single-crate Evidence runtime and `evidence` binary |
| `crates/registry-evidence-verifier` | Portable Evidence response verification, shared by the runtime and client tooling |
| `crates/registry-evidence-client` | Evidence relying-party SDK: requests assertions and verifies them via `registry-evidence-verifier` |
| `crates/registry-evidence-client-node` | Node.js binding for `registry-evidence-client`, via napi-rs |
| `crates/registry-evidence-client-py` | Python binding for `registry-evidence-client`, via PyO3 |
| `crates/registry-evidencectl` | Evidence adopter tooling (`evidencectl`): key material, incomplete OpenAPI authoring workspaces, fixture runs for complete projects |
| `crates/registry-evidence-authoring` | The authoring form: the single implementation of the model an adopter writes and the checks it must satisfy, shared by adopter tooling |
| `crates/registry-mint` | Short-lived access tokens for registered clients, and the `mint` binary |
| `crates/registry-manifest-*` | Manifest core types and CLI |
| `crates/registry-platform-*` | Shared primitives used by the maintained runtimes and tooling |
| `crates/registry-platform-sqlite` | Shared bounded read-only SQLite security boundary used by Relay V2 and Evidence |
| `crates/registry-relay-v2` | Contract-compiled Relay V2 runtime and the `relay` binary |
| `crates/registry-relayctl` | Relay V2 adopter tooling and the `relayctl` binary |
| `crates/registry-evidence-oid4vci` | Wallet-facing OID4VCI delivery front end for Evidence credentials, and the `evidence-oid4vci` binary |
| `crates/registry-language-server` | Editor language server for Relay V2 and Evidence authoring documents, hosted for adopters by `evidencectl` and `relayctl` |
| `products/` | Product-owned specs, examples, fixtures, docs (not crates) |
| `docs/site/` | Public docs site (Astro). Has its own `AGENTS.md`; read it before touching this subtree |
| `release/` | Release manifests, schemas, notes, validation and conformance tooling, and the release source-model proof |
| `external/` | Historical external-input records and policy for reviewing any reintroduction |

Relay V2 is implemented by `registry-relay-v2` and `registry-relayctl`. Its
approved contracts, coequal acceptance projects, and gates live under
`products/relay-v2`.

Base Registry Engine is implemented by `registry-breg` and `registry-bregctl`.
Its approved contracts, acceptance journeys, quickstart, generated examples, and
gates live under `products/breg`. A registry project is configuration: the
runtime has no built-in business, facility, authority, permit, or asset model,
and none may become a Rust type, built-in operation, or special route.

Registry Discovery is a curated index over public provider descriptions, not
a trust broker, authorization service, protocol adapter, or data proxy.
`registry-discovery-profile` is the narrow shared publication contract that
Evidence and Relay depend on; it contains no runtime, source access, trust, or
native-client behavior. Discovery fetches only an operator-approved origin
list during an offline build, serves one immutable index, and leaves endpoint
trust plus native Evidence or Relay invocation to the relying application.
The Rust, Node.js, and Python Discovery clients must preserve that boundary:
they may search, resolve, validate, and persist inert exact selections, but
must never turn catalog metadata into trust or credentials.

Relay V2 editor support uses the shared in-memory authoring compiler in
`registry-relay-v2`; the language server must not observe SQLite or source
values. Regenerate the committed editor schemas from the strict Rust types,
never by hand:

```bash
cargo run -p registry-relay-v2 --features schema --example authoring-schema -- \
  --output crates/registry-relayctl/schemas/authoring
products/relay-v2/scripts/check-authoring-schema.sh
```

## Evidence product boundary

Evidence is its own minimum-disclosure assertion product, not a Relay mode.
Evidence may consume a Relay-protected API through its ordinary fixed HTTP
source contract, but it does not inherit Relay's authorization or policy
model. Evidence serializes the same stateless assertion as a signed flattened
JWS or, under its own frozen profile, as an SD-JWT VC response. The latter is a
second encoding of one response, never a credential lifecycle.

The runtime implementation is one `registry-evidence` crate and one `evidence`
binary. It may reuse narrowly applicable `registry-platform-*`
primitives such as audit, crypto, OIDC, HTTP security, SD-JWT serialization,
and testing.

`registry-evidence-verifier` is the portable response-verification library the
runtime depends on. It owns the response wire formats, the Evidence payload
contract, and relying-party verification, so client tooling can verify a signed
Evidence response without the runtime. It is a library, not a second runtime and
not a pattern of its own, and it carries no server, source access, or
service-runtime dependency; portable means free of the service runtime, not
target independent.

`registry-evidence-client` is the relying-party SDK beside the runtime. It
requests assertions over the public HTTP contract and links
`registry-evidence-verifier` for every verification decision, so it sits outside
the frozen Version 1 runtime contract and adds no Evidence semantics of its own.
`registry-evidence-client-node` (napi-rs) and `registry-evidence-client-py`
(PyO3) are thin bindings over that SDK and carry the same boundary. All three
are covered by the same source-product and domain neutrality checks as the
runtime.

`registry-evidencectl` (`evidencectl`) is adopter tooling beside the runtime,
like `relayctl` is for the rest of the stack. It sits outside the frozen
Version 1 runtime contract: it generates key material, starts incomplete
OpenAPI authoring workspaces, writes the project-local editor schema mappings
an adopter's YAML tooling reads, and drives fixture runs for complete
deployment projects. It delegates runtime evaluation, signing, bundle validation, and
fixture evaluation to the `evidence` binary, and reuses
`registry-evidence-client` and `registry-evidence-verifier` for relying-party
request preparation and offline response verification. It links
`registry-language-server`, so an adopter's editor reports the authoring
sentences the command line already reports. It adds no Evidence semantics of
its own. Its source is covered by the same source-product and domain neutrality
checks as the runtime, and so is the language server's in full: every line of
that crate ships inside `evidencectl`, and the modules its Relay half and its
Evidence half share are where a term would leak from one into the other.

`registry-evidence-authoring` is the library beside `evidencectl` holding the
single implementation of the authoring form: the model an adopter writes, the
checks that shape must satisfy, and the reading of an OpenAPI description that
turns a published operation into the leaves a question may select. It sits
outside the frozen Version 1
runtime contract, is not a second runtime, and adds no Evidence semantics of
its own; the sentences it reports are the ones adopter tooling already
reported. It performs no input or output, so a caller may run the same checks
against a file or an unsaved buffer, and its source is covered by the same
source-product and domain neutrality checks as the runtime.

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
The provider-published shared credentials for the public DHIS2 demo at
`https://play.im.dhis2.org/stable-2-43-1/` are a documentation-only exception:
public tutorials may state them and place them in ignored, owner-only local
files.
The provider-published human login credentials and synthetic Josh Hoeger record
identifiers for the public OpenCRVS Farajaland integration demo are a second
documentation-only exception. Public tutorials may state them so readers can
inspect the same synthetic record, use its stated selectors in tutorial
commands, and create their own Record Search client.
The exceptions do not cover OAuth client credentials created by a reader,
tokens, live responses, real identifiers, other demo-subject identifiers in
tracked files, logs, or snapshots.

DHIS2 and OpenCRVS names and behavior are test-only. Evidence production code,
dependencies, Cargo features, public configuration schemas, routes, and CLI
options must remain source-product neutral.

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
`deny.toml` with review triggers), and the Relay V2 product contract check
(`products/relay-v2/scripts/check-contracts.sh`). cargo-deny needs v0.19+
to parse this `deny.toml`; CI pins 0.19.8.

Evidence-specific contracts, source neutrality, and verifier portability:

```bash
products/evidence/scripts/check-contracts.sh
products/evidence/scripts/check-source-neutrality.sh
products/evidence/scripts/check-verifier-portability.sh
products/evidence/scripts/check-config-key-paths.sh
```

Registry Discovery contracts and end-to-end client handoff:

```bash
products/discovery/scripts/check-contracts.sh
products/discovery/scripts/test-http.sh
products/discovery/scripts/test-adopter-tutorial.sh
```

Registry Discovery language bindings, from their respective crate directories:

```bash
cd crates/registry-discovery-client-node
npm ci
npm run build:debug
npm test
npm run check:types

cd ../registry-discovery-client-py
cargo build --locked -p registry-discovery-client-py --lib \
  --features registry-discovery-client-py/extension-module
python3 -m unittest discover -s tests/python -v
```

The last check holds every Evidence configuration reference in exact parity
with the schema it explains: the frozen `bundle.schema.yaml` and
`runtime.schema.yaml` grammars against
`products/evidence/reference/request-adapter/deployment-projects/CONFIG.md`,
and the authoring-form schemas below against
`products/evidence/reference/authoring-projects/CONFIG.md`. Parity is the same
rule in both places and not the same promise: only the two grammars are frozen.
After changing any of them, run the check with `--write` to regenerate the
key-path blocks in the reference that carries them, then document each new key
in the prose above them.

The authoring-form JSON Schemas under
`crates/registry-evidencectl/schemas/authoring/` are adopter tooling, not part
of the frozen Version 1 contract set, so they carry their own gate:

```bash
products/evidence/scripts/check-authoring-schema.sh
```

Regenerate them with the generator the gate runs, never by hand:

```bash
cargo run -p registry-evidence-authoring --features schema --example authoring-schema -- --output crates/registry-evidencectl/schemas/authoring
```

`registry-evidence-authoring` is linked into the language server, so it reads no
file, opens no socket, starts no process, and touches neither standard stream.
`crates/registry-evidence-authoring/clippy.toml` is what holds that, by
disallowing the resolved types, methods, and macros that would break it; every
clippy run applies it, and this gate additionally fails the build when an entry
stops resolving and proves the lints still refuse the shapes they were written
for:

```bash
products/evidence/scripts/check-authoring-no-io.sh
```

Evidence client bindings, from `crates/registry-evidence-client-node`:

```bash
npm ci
npm run build:debug
npm test
npm run check:types
cmp ../../LICENSE LICENSE
```

and from `crates/registry-evidence-client-py`:

```bash
cargo build --locked -p registry-evidence-client-py --lib \
  --features registry-evidence-client-py/extension-module
python3 -m unittest discover -s tests/python -v
cmp ../../LICENSE LICENSE
```

The unified Node.js and Python packages are generated from all four product
bindings. After changing a binding or facade, run:

```bash
python3 release/scripts/sync-registry-client-node.py --check
cd crates/registry-stack-client-node
npm ci
npm test
npm run check:types
cd ../..
python3 -m unittest release/scripts/test_assemble_registry_client_wheel.py
```

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
- Commit subjects: imperative mood; `feat(relay):` and `feat(evidence):` style
  prefixes are the norm for product-scoped changes.
- History may be rewritten during review (session commits get squashed). In
  durable docs, cite only commits reachable from pushed `main`, and prefer
  stable facts plus dates over commit SHAs.
- Major functionality and bug fixes require automated tests with the change.
- Keep a change scoped to one owning area (`crates/`, `products/`,
  `docs/site/`, `release/`).
- Changes to authentication, authorization, assertion evaluation or signing,
  audit integrity, release provenance, deployment defaults, or data
  minimization are security-sensitive and need explicit review notes.
- Generated outputs (OpenAPI under `docs/site/openapi/`, `docs/site`
  generated data, release artifacts) must be reproduced by their documented
  generator commands, never hand-edited, and must be bit-for-bit repeatable.
  If you change an HTTP endpoint, regenerating and committing the OpenAPI
  documents is part of the change, not a follow-up.
- Suspected vulnerabilities (minimum-disclosure failure, auth bypass, audit
  redaction failure, connector data leakage, signing key handling) go through
  `SECURITY.md`, never public issues or PRs.

## Deeper guidance

`CONTRIBUTING.md` (policies in full), `README.md` (orientation),
`ROADMAP.md` (direction), `docs/site/AGENTS.md` (docs subtree),
`release/VERIFY.md` and `release/REPEATABLE-BUILDS.md` (release evidence).
