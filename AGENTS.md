# Registry Stack Agent Guidance

This is the Registry Stack monorepo: registry-facing services over the data
institutions already hold and the registries they do not hold yet. Pre-1.0;
APIs and deployment contracts may change.

This file routes. It names what each area owns, the boundary each product
keeps, and the rules that bite across the whole repository. The owning guide
for an area carries the product description, the verification commands, and
the workflow; read it before changing that area.

The maintained runtime products are **Base Registry Engine** (BReg, a
PostgreSQL-backed writable registry compiled from a declared registry
project), **Evidence** (signed, minimum-disclosure assertions from fixed
requests to authoritative sources), **Registry Casework** (policy-bound human
review tasks from trusted producers, with correlated results), **Registry
Scheduling** (bookable services over anchored supply, with holds and
appointments decided inside one capacity transaction under a task grant),
**Registry Messaging** (one message to one destination over one channel for
an authorized caller, from a reviewed template through an operator-configured
provider), **Registry Coordinator** (finite, reviewed workflows of product
API calls separated by durable waits), **Document Store** (document bytes held
in custody for an owning system, with an exact, verified version released to
the recipient a document grant names; held out of releases), and **Registry
Discovery** (a curated, immutable index over public provider descriptions).
Registry Manifest describes sources portably; `registry-platform-*` crates are
shared primitives; `registry-breg-mcp`, `registry-breg-review`, and
`registry-evidence-oid4vci` are supporting services beside a product, not
products of their own.

## Repository map

| Area | Owns |
|---|---|
| `crates/registry-coordinator` | Optional Coordinator runtime and operator CLI, durable workflow state and client adapters |
| `crates/registry-coordinator-client` | Bounded Rust Coordinator client over the runtime's HTTP contract |
| `crates/registry-coordinator-client-node` | Internal napi-rs binding assembled into the unified Node.js client from v0.44.0 |
| `crates/registry-coordinator-client-py` | Internal PyO3 binding assembled into the unified Python client from v0.44.0 |
| `products/coordinator` | Coordinator product contract, deployment runbook, example projects, generated schemas, OpenAPI and operation contracts, and contributor check and test scripts |
| `crates/registry-documents-core` | Source-neutral Document Store project model, problem codes, and wire constants |
| `crates/registry-documents` | PostgreSQL-backed Document Store runtime and the `documents` binary |
| `crates/registry-documentsctl` | Document Store operator tooling and the `documentsctl` binary |
| `crates/registry-documents-client` | Bounded Rust Document Store client over the runtime's HTTP contract |
| `products/documents` | Document Store product contracts, starter example, generated schemas and OpenAPI document, and contributor check scripts |
| `crates/registry-discovery` | Immutable Registry Discovery index runtime and the `discovery` binary |
| `crates/registry-discovery-profile` | Closed provider-publication profile implemented by Evidence; published v1alpha1 resources retain their historical broader vocabulary |
| `crates/registry-discovery-client` | Rust relying-party SDK for bounded search, resolution, and inert exact selections |
| `crates/registry-discovery-client-node` | Node.js binding for `registry-discovery-client`, via napi-rs |
| `crates/registry-discovery-client-py` | Python binding for `registry-discovery-client`, via PyO3 |
| `crates/registry-discoveryctl` | Offline origin and mapping checks plus immutable index builds |
| `crates/registry-breg` | Base Registry Engine runtime, the registry-project compiler, and the `breg` binary |
| `crates/registry-bregctl` | Base Registry Engine adopter tooling and the `bregctl` binary |
| `crates/registry-breg-client` | Base Registry Engine client and its opaque authorization handles |
| `crates/registry-breg-client-node` | Internal napi-rs binding used to assemble the unified Node.js client |
| `crates/registry-breg-client-py` | Internal PyO3 binding used to assemble the unified Python client |
| `crates/registry-breg-mcp` | Citizen-facing MCP gateway beside the Base Registry Engine and the `breg-mcp` binary |
| `crates/registry-breg-review` | Server-rendered citizen review page for BReg Proposal drafts and the `breg-review` binary |
| `crates/registry-linkml` | LinkML reader and embedded PublicSchema snapshot behind `bregctl init --from publicschema` |
| `crates/registry-casework-core` | Source-neutral Casework review model, HTTP DTOs, transitions, and read-only context contract |
| `crates/registry-casework-breg` | Read-only BReg Proposal context provider for exact human disclosure and service status |
| `crates/registry-casework` | PostgreSQL-backed Casework runtime and the `casework` binary |
| `crates/registry-caseworkctl` | Casework authoring and local operator tooling and the `caseworkctl` binary |
| `crates/registry-casework-client` | Rust Casework client and its bounded problem and recovery contract |
| `crates/registry-casework-client-node` | Internal napi-rs binding used to assemble the unified Node.js client |
| `crates/registry-casework-client-py` | Internal PyO3 binding used to assemble the unified Python client |
| `crates/registry-review-protocol` | Runtime-free wire contract between review producers and providers such as Casework and Coordinator |
| `crates/registry-review-client` | Product-neutral bounded client for the review handoff protocol, shared by the Casework client and BReg |
| `crates/registry-scheduling-core` | Source-neutral Scheduling policy model, wire DTOs, problem codes, and authoring checks |
| `crates/registry-scheduling` | PostgreSQL-backed Scheduling runtime and the `scheduling` binary |
| `crates/registry-schedulingctl` | Scheduling authoring and local operator tooling and the `schedulingctl` binary |
| `crates/registry-scheduling-client` | Bounded Rust Scheduling client over the runtime's HTTP contract |
| `crates/registry-scheduling-client-node` | Internal napi-rs binding used to assemble the unified Node.js client |
| `crates/registry-scheduling-client-py` | Internal PyO3 binding used to assemble the unified Python client |
| `crates/registry-messaging-core` | Source-neutral Messaging access decisions, package model, wire DTOs, and problem codes |
| `crates/registry-messaging` | PostgreSQL-backed Messaging runtime and the `messaging` binary |
| `crates/registry-messagingctl` | Messaging operator tooling and the `messagingctl` binary |
| `crates/registry-messaging-client` | Bounded Rust Messaging client over the runtime's HTTP contract |
| `crates/registry-messaging-client-node` | Internal napi-rs binding used to assemble the unified Node.js client |
| `crates/registry-messaging-client-py` | Internal PyO3 binding used to assemble the unified Python client |
| `crates/registry-record` | Product-neutral Registry Record v1 response DTOs used by the Base Registry Engine clients |
| `crates/registry-render` | Registry Render: governed, byte-stable PDF documents from registry data, rendered with Typst, and the `registry-render` binary |
| `crates/registry-render-client` | Bounded HTTP client for the optional Render serving adapter |
| `crates/registry-render-client-node`, `crates/registry-render-client-py` | Internal Render bindings for explicit local candidates; release readiness remains held |
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
| `crates/registry-manifest-*` | Manifest core types and CLI |
| `crates/registry-platform-*` | Shared primitives used by the maintained runtimes and tooling |
| `crates/registry-platform-sqlite` | Shared bounded read-only SQLite security boundary used by Evidence |
| `crates/registry-evidence-oid4vci` | Wallet-facing OID4VCI delivery front end for Evidence credentials, and the `evidence-oid4vci` binary |
| `crates/registry-language-server` | Editor language server for Evidence authoring documents, hosted for adopters by `evidencectl`; product navigation rules add no runtime dependencies |
| `crates/registry-thunderid-tooling` | Tooling-only support for adopter CLIs and integration tests against a pinned upstream ThunderID issuer; no runtime depends on it |
| `crates/registry-cli-docs` | Deterministic CLI reference data generated from Registry Stack Clap command trees, consumed by the docs site's CLI reference build |
| `crates/registry-cli-reference` | Deterministic reference data walked from one Clap command tree, shared by `registry-cli-docs` and each binary's `help --format json` |
| `products/` | Product-owned specs, examples, fixtures, docs (not crates) |
| `docs/site/` | Public docs site (Astro). Has its own `AGENTS.md`; read it before touching this subtree |
| `release/` | Release manifests, schemas, notes, validation and conformance tooling, and the release source-model proof |
| `external/` | Historical external-input records and policy for reviewing any reintroduction |

Before editing an area, read its owning guide:

- `registry-breg*`, `registry-bregctl`, `registry-breg-mcp`,
  `registry-breg-review`, `registry-linkml`: `products/breg/AGENTS.md`
- `registry-evidence*`, `registry-evidencectl`, `registry-language-server`:
  `products/evidence/AGENTS.md`
- `registry-casework*`, `registry-caseworkctl`, `registry-review-*`:
  `products/casework/AGENTS.md`
- `registry-scheduling*`, `registry-schedulingctl`:
  `products/scheduling/AGENTS.md`
- `registry-messaging*`, `registry-messagingctl`:
  `products/messaging/AGENTS.md`
- `registry-coordinator*`: `products/coordinator/AGENTS.md`
- `registry-documents*`, `registry-documentsctl`:
  `products/documents/AGENTS.md`
- `registry-discovery*`, `registry-discoveryctl`:
  `products/discovery/AGENTS.md`
- `registry-manifest-*`: `products/manifest/AGENTS.md`
- `registry-platform-*`: `products/platform/AGENTS.md`
- product clients, their language bindings, `registry-record`, and
  `registry-stack-client*`: `crates/CLIENTS.md` plus the owning product guide
- `docs/site/`: `docs/site/AGENTS.md`
- `release/`: `release/VERIFY.md` and `CONTRIBUTING.md`

Before adding or changing any configuration format a product reads or writes
(its keys, values, identifiers, parsing, schema, or diagnostics), read
`products/platform/CONFIG-CONVENTIONS.md`. It is normative for every product.

## Product boundaries

The products compose without merging their boundaries. A runtime composes
with another product only through that product's public HTTP contract and
maintained product client, under a dependency gate that names what it may
reach; outside its tests, a runtime never drives another product's CLI or
links another product's runtime or tooling crates. Adopter tooling may drive
the other product's public CLI (`evidencectl source add` drives the `bregctl`
of the same version on `PATH`), never a crate dependency. No product inherits
another product's authorization, and no product writes to another product's
database. Each product's own guide states the full boundary; the paragraphs
below are the cross-product invariants a change anywhere must respect.

**Base Registry Engine** (`registry-breg`, `registry-bregctl`,
`registry-breg-client`) is the writable system of record. A registry project
is configuration: the runtime has no built-in business, facility, authority,
permit, or asset model, and none may become a Rust type, built-in operation,
or special route. A governed action that declares `evidence` may consume an
Evidence assertion as an ordinary relying party through `evidence::resolve`,
backed by `registry-evidence-client` and `registry-evidence-verifier` only;
the trusted provider is operator configuration, BReg inherits no Evidence
authorization, and the retained assertion is a bounded relying-party record
erased after 24 hours by the supervised sweeper (`bregctl evidence-retention
erase-expired` for manual use), never a credential lifecycle. No Evidence
crate depends on `registry-breg`, and `registry-breg` never depends on the
`registry-evidence` runtime crate.

`registry-breg-mcp` (`breg-mcp`) and `registry-breg-review` (`breg-review`)
are supporting services beside the engine. The gateway serves MCP to a chat
host acting for one verified citizen and adds no registry semantics: it
verifies the chat host's token as a protected resource, exchanges it for a
delegated registry token on every call, never forwards the inbound token, and
writes an application's target record and owner from the citizen's own linked
record and the token subject, never from tool arguments. Every disclosure or
change decision is the registry's, under its agent access profile. The review
page is where a citizen submits a draft the gateway prepared. Both depend on
the engine only through `registry-breg-client`; no product crate depends on
either, and neither depends on the other or on `registry-breg` outside
dev-dependencies. `crates/registry-breg-mcp/clippy.toml` disallows the client
methods the gateway must never reach, and
`products/breg/scripts/check-mcp-gateway-boundary.sh` proves that list still
resolves and refuses. The gateway's ignored `native_citizen` test composes
independently built `breg`, `bregctl`, and `breg-review` executables over
public HTTP (`BREG_BIN`, `BREGCTL_BIN`, `BREG_REVIEW_NATIVE_BIN`,
`BREG_TEST_DATABASE_URL`) in the BReg `postgres` CI lane.

**Evidence** (`registry-evidence`, one crate and one `evidence` binary) is a
minimum-disclosure assertion product. It may consume a protected API through
its fixed HTTP source contract, or a BReg route as a fixed source, and
inherits none of that source's authorization or policy model. Rust owns
authentication, authorization, fixed source execution, bounded script
execution, output validation, evidence construction, signing, and audit; Rhai
owns bounded request preparation, source extraction, and requirement-specific
derivation over deterministic, domain-neutral primitives supplied by Rust.
Adult status, residence region, professional licence status, and legal-parent
relationship are coequal full-path acceptance definitions, and none may become
a Rust domain type, built-in operation, special route, or implementation
phase. `registry-evidence-verifier` (portable verification),
`registry-evidence-client` with its Node.js and Python bindings (relying-party
SDK), `registry-evidencectl` (adopter tooling), `registry-evidence-authoring`
(the single authoring-form implementation, no I/O), and
`registry-language-server` sit outside the frozen Version 1 runtime contract
and add no Evidence semantics; all are covered by the same source-product and
domain neutrality checks as the runtime. DHIS2 and OpenCRVS names and
behavior are test-only; production code, dependencies, Cargo features, public
schemas, routes, and CLI options stay source-product neutral. Evidence changes
keep the approved Version 1 contracts and Definition of Done aligned in
tracked product material; do not call the product implemented on a subset of
that DoD, and stop before the approved concept's non-goals and future
profiles. `registry-evidence-oid4vci` delivers Evidence credentials to a
wallet over OID4VCI 1.0 Final; it never signs, never holds a holder private
key, and no Evidence crate depends on it at runtime. The optional credential
status module inside `registry-evidence` (`products/evidence/CONCEPT.md`
section 15.9, approved; its ledger is library code the served runtime does not
call yet) follows these rules: it is the only
writer of its PostgreSQL ledger; allocation happens inside the signing
transaction; nothing outside Evidence reads the ledger; hook intake and the
operator endpoints are the only mutation surface; with status disabled there is
no PostgreSQL requirement; it never decides eligibility; it stores no raw
selector value or record identifier; and intake is source-neutral, verified
through `registry-platform-hooks`.

**Registry Casework** (`registry-casework`, `registry-casework-core`,
`registry-casework-breg`, `registry-caseworkctl`, its clients) coordinates
pinned review rounds, claims, private drafts, human decisions, and results.
Context providers preserve current source disclosure; Casework has no source
write or apply authority. The source-neutral core and generic clients must not
depend on BReg protocol types, and BReg must not depend on Casework.
`registry-review-protocol` and `registry-review-client` are the runtime-free
handoff contract between review producers and providers.

**Registry Scheduling** (`registry-scheduling`, `registry-scheduling-core`,
`registry-schedulingctl`, its clients) owns its capacity ledger absolutely.
Supply is operator-anchored runtime records the policy references by
identifier; a hold or appointment is created, moved, or released only inside
the runtime's own capacity transaction, under a task grant matched against the
offering's service, location, and action before the transaction opens and
re-checked inside it; no other product may write to that ledger, directly or
through a shared database. Reminders, observer-hook delivery, and retention
are outbox work. For the MVP, no scheduling crate reaches a BReg, Casework,
Document Store, Evidence, or Messaging crate in either direction; the
dependency-direction gate enforces that on the whole forward closure, and the
sentence is relaxed only by the change that adds an adapter crate, in the gate
and here together. Task-grant status checks over HTTP through
`registry-platform-oidc` are a protocol call, not such a reach.

**Registry Messaging** (`registry-messaging`, `registry-messaging-core`,
`registry-messagingctl`, its clients) owns rendering, its dispatch queue,
provider calls, receipts, attempt history, payload retention, and its audit
journal. Why and when to send, who the recipient is, and consent stay with the
caller's source of record. No Messaging crate reaches a BReg, Casework,
Scheduling, Coordinator, or Evidence crate, and no product crate reaches the
Messaging runtime or `messagingctl`: products call Messaging over its public
HTTP contract like any external caller. Messaging inherits no authorization
from a caller product; its own access profile decides.

**Registry Coordinator** (`registry-coordinator`, `registry-coordinator-client`
and its bindings) owns its reviewed workflow packages, durable run state,
prepared commands, waits, and audit journal, and never product authority,
data, eligibility, or capacity. A wait never renews an approval or creates
downstream authority. The runtime may depend on product clients, product
cores, `registry-record`, and `registry-platform-*`, never on a product
runtime, adopter tooling, a supporting service, or a binding; it reaches
Casework through `registry-casework-client` alone; its client reaches
`registry-platform-*` only. No product crate depends on a Coordinator crate
(only `registry-cli-docs` may), and the Casework, Scheduling, and Messaging
gates refuse the Coordinator from their side. A run may submit its own Review
request to Casework as a producer; Coordinator is not a Review provider.

**Document Store** (`registry-documents`, `registry-documents-core`,
`registry-documentsctl`, `registry-documents-client`) owns its custody records,
document grants, stored bytes, content verification state, and audit journal;
why a document exists, who it concerns, and whether a recipient is entitled to
it stay with the owning system. It is held out of releases while
`DOCUMENTS_FIRST_RELEASE` in `release/scripts/release_roster.py` is unset. No
Document Store crate reaches a BReg, Casework, Coordinator, Evidence,
Messaging, or Scheduling crate, and no product crate reaches the Document
Store runtime or `documentsctl`: products reach it over its public HTTP
contract like any external caller, and its dependency-direction gate enforces
that on the whole forward closure. The source-neutral core depends on no other
Document Store crate, and the client never reaches the runtime.

**Registry Discovery** is a curated index, not a trust broker, authorization
service, protocol adapter, or data proxy. `registry-discovery-profile` is the
narrow publication contract Evidence implements and carries no runtime,
source access, trust, or native-client behavior. The clients may search,
resolve, validate, and persist inert exact selections, but never turn catalog
metadata into trust or credentials.

The adopter demo is maintained separately in
[`registrystack/solmara-lab`](https://github.com/registrystack/solmara-lab).

## Verify your change

Run the checks that match the files you changed; the full PR gate is
`.github/workflows/ci.yml`. The root `rust` job runs:

```bash
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
```

cargo-deny needs v0.19+ to parse `deny.toml`; CI pins 0.19.8. Unresolvable
RUSTSEC advisories carry scoped ignores in `deny.toml` with review triggers.
On macOS, source `scripts/cargo-runtime-library-path.sh` before executing a
built binary or entering a binding crate; `CONTRIBUTING.md` and
`crates/CLIENTS.md` show the exact sequence.

Each owning guide lists its own gates. The entry points:

| Area | Start with | Full list |
|---|---|---|
| BReg | `products/breg/scripts/check-contracts.sh`, `products/breg/scripts/test-postgres.sh` | `products/breg/AGENTS.md` |
| Evidence | `products/evidence/scripts/check-contracts.sh`, `check-source-neutrality.sh`, `check-verifier-portability.sh`, `check-config-key-paths.sh`, `check-authoring-schema.sh`, `check-authoring-no-io.sh`, the status ledger and OID4VCI store PostgreSQL suites | `products/evidence/AGENTS.md` |
| Casework | `products/casework/scripts/check-checkpoint.sh`, then `products/casework/README.md` for PostgreSQL | `products/casework/AGENTS.md` |
| Scheduling | `products/scheduling/scripts/check-checkpoint.sh`, `check-contracts.sh`, the `postgres_commitments` suite | `products/scheduling/AGENTS.md`, `products/scheduling/README.md` |
| Messaging | `products/messaging/scripts/check-checkpoint.sh`, `check-contracts.sh`, the `postgres_migrate` suite | `products/messaging/AGENTS.md`, `CONTRIBUTING.md` |
| Coordinator | `products/coordinator/scripts/check_dependency_direction.py`, `check-schemas.sh`, `test-postgres.sh` | `products/coordinator/AGENTS.md` |
| Document Store | `products/documents/scripts/check-checkpoint.sh`, `check-contracts.sh`, the PostgreSQL suites (`postgres_journey` also needs `REGISTRY_RENDER_BIN`) | `products/documents/AGENTS.md`, `products/documents/README.md` |
| Discovery | `products/discovery/scripts/check-contracts.sh`, `test-http.sh` | `products/discovery/AGENTS.md` |
| Clients, bindings, unified packages | per-binding `npm test` and `unittest` runs, `release/scripts/sync-registry-client-node.py --check` | `crates/CLIENTS.md` |
| Release | `release/scripts/registry-release validate release/manifests/<current>.yaml`, `check-release-source-model.sh` | `CONTRIBUTING.md`, `release/VERIFY.md` |
| Docs site | `npm test` and `npm run check` in `docs/site/` | `docs/site/AGENTS.md` |

Identifier references shared across products are checked by
`python3 products/identifiers/scripts/generate.py --check-references`; run it
after a Scheduling or Messaging contract change.

A PostgreSQL suite needs a separate disposable database and the
`postgres-test` feature. A test binary that skips because its database URL is
absent is not database verification.

## Review guidelines

The "Check commit sign-offs" CI job is authoritative for DCO. A bot's own
`Signed-off-by` trailer (for example `Signed-off-by: dependabot[bot] <...>`)
satisfies it. Do not open a missing-sign-off finding; check the job's result
instead of re-deriving it from the diff. If a finding cites a commit, cite one
that still resolves in the pull request, not a rewritten or squashed SHA.

## Rules that bite

- Every commit needs a DCO sign-off: `git commit -s`.
- Commit subjects: imperative mood; `feat(breg):` and `feat(evidence):` style
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
- Generated outputs (site references, OpenAPI, release artifacts) must be
  reproduced by their documented generator commands, never hand-edited, and
  must be bit-for-bit repeatable. Site CLI pages and the site's generated data
  under `docs/site/src/data/generated/` are ignored build artifacts; commit
  their sources and generators, not rendered copies. Generated inputs whose
  diff is the review, such as the OpenAPI documents and the CLI command catalog
  `crates/registry-cli-docs/catalog.json`, are committed instead and held to
  their sources by drift gates. If you change an HTTP endpoint, regenerating
  and committing the OpenAPI documents is part of the change, not a follow-up.
  If you change a binary's clap definitions or other public command content,
  run `cargo run --locked -p registry-cli-docs -- --write` and commit the
  regenerated `crates/registry-cli-docs/catalog.json` as part of the change;
  its diff is the CLI reference review, and the `registry-cli-docs` snapshot
  test fails until it is current. A workspace-version-only change leaves that
  catalog and the publication record `docs/site/src/data/cli-reference.yaml`
  unchanged; `docs/site/AGENTS.md` describes both.
- Suspected vulnerabilities (minimum-disclosure failure, auth bypass, audit
  redaction failure, connector data leakage, signing key handling) go through
  `SECURITY.md`, never public issues or PRs.

## Deeper guidance

`CONTRIBUTING.md` (policies in full), `README.md` (orientation),
`ROADMAP.md` (direction), `docs/site/AGENTS.md` (docs subtree),
`release/VERIFY.md` and `release/REPEATABLE-BUILDS.md` (release evidence).

A checkout may carry git-ignored, locally installed workflow skills under
`.claude/skills/`. When that directory exists, load the skill matching the
change before editing; this file routes, the skill carries the workflow.
