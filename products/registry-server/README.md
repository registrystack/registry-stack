# Registry Server

Registry Server is a small PostgreSQL system of record whose data model and
REST surface are compiled from governed configuration. It is intended for
institutional registries that need reliable writes, history, access control,
and a safe way to evolve their schema without building a bespoke service.

The runtime has no built-in person, household, farmer, disability, business,
programme, or asset model. An entity, relationship, route, field, access
profile, and event exists only when an active Registry package declares it.
For example, a household membership is an ordinary configured relationship
entity, not a server feature.

The product starts with two executables:

- `registry-server` loads one verified package and serves its configured REST
  API against PostgreSQL.
- `registry-serverctl` is deterministic tooling for authoring, checking,
  packaging, applying, and verifying Registry configuration.

AI-assisted authoring remains outside the production authority boundary. It
may propose configuration and run deterministic checks, but it cannot bypass
package review, signature policy, or the separate migration database role.

## Pilot operator lifecycle

The pilot lifecycle uses the published `registry-serverctl` and
`registry-server` executables. It does not require a Rust change for a new
configured domain or a compatible additive schema change.

1. An author runs `registry-serverctl check <project> --production`, generates
   review artifacts as needed, and uses `diff` against the active runtime
   configuration for a successor.
2. `registry-serverctl test` executes the declared journeys against a separate
   schema-test database. Its result binds the candidate source, database
   identity, exact catalog fingerprint, signature policy, and test receipt.
3. `registry-serverctl package` reproduces that tested candidate and stops at
   `awaiting_signatures`. An external signer reviews and signs the exact
   `signing-input.json`; rerunning `package` with the detached signature
   document publishes the verified package. The CLI accepts no private signing
   key.
4. An operator with the migration database credential runs
   `registry-serverctl apply --runtime-config <file> --package <directory>` and
   then `registry-serverctl verify --runtime-config <file>`. Initial activation
   also requires `--initial`.
5. `registry-server --config <file>` serves the active package. Authorized
   bulk operations use `registry-serverctl data validate`, `data import`, and
   `data export`, which reuse the packaged plans and normal authenticated API
   paths.

For a compatible successor, repeat test, package, external signing, and apply
with the active runtime configuration as the baseline, then restart the same
server executable on the successor package. A migration failure after
maintenance begins leaves the database durably in maintenance and readiness
fails until an operator resolves the cause and applies the exact successor
again or completes the reviewed restore path.

Authoring, signing, and migration authority are deliberately separate. An
author or coding agent can edit configuration, inspect a diff, and run checks.
Those commands cannot mint a package signature or obtain the production
migration credential. A runtime configuration without that credential is
refused before initial production control-plane state or DDL is created.

OIDC key resolution is deployment configuration, not governed package content.
If `authentication.oidc.jwksSource` is omitted, discovery is used. An operator
can instead pin a static document through a protected secret reference:

```yaml
authentication:
  oidc:
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
```

The static document must be a bounded, duplicate-free set of public keys that
matches the configured algorithm, signature use, verification operation, key
identifier policy, and key shape. It is resolved once when the verifier is
constructed, so rotation requires a reviewed configuration change and process
restart.

## Scope

Registry Server owns typed configured storage, generated REST contracts,
authorization, record revisions, audit ordering, idempotency, outbox creation,
and governed migrations. It does not provide a UI, GraphQL, workflow,
eligibility, payment, identity matching, SQLite support, a multi-registry
control plane, or runtime code plugins.

The focused direction for hooks is documented in
[`EVENTS-AND-WEBHOOKS.md`](EVENTS-AND-WEBHOOKS.md). Version 1 uses explicit
transactional events and authenticated after-commit webhooks, with future Rhai
rules kept behind the same governed extension boundary.

PostgreSQL is the sole Version 1 database. The administrator installs
`btree_gist`; neither the runtime nor migration role installs extensions.

## Product contracts

The files in `contracts/` are the authoritative machine-readable delivery
catalog. They deliberately distinguish a `planned` invariant from an
`enforced` one. A planned row records a concrete threat and future refusal but
does not pretend that a test exists. The implementation change that enforces
it must add one resolving negative executable test in the same patch.

The five projects under `acceptance/` are authored configuration inputs for the
same compiler and binary. They cover asset/site placement, PublicSchema-shaped
household membership, disability, farmer, and business registries. They are not
generated output or implicit runtime models. The real-PostgreSQL pilot test
executes all five, while the public-binary adopter workflow proves signed
activation, authenticated data access, an additive upgrade, failure recovery,
and unchanged server bytes for the non-person project.

Run the current deterministic contract checks with:

```bash
products/registry-server/scripts/check-contracts.sh
```

For an interactive local household example backed by disposable PostgreSQL,
Registry Mint, a real local package, and deterministic relational data, run:

```bash
products/registry-server/demo/run.sh
```

The launcher retains every key and token in an ignored owner-only directory
and prints a separate query helper rather than printing bearer credentials.

## Portable metadata and composition

Domain-semantic entries in `manifestProjection` are optional overlays on the
configured data model. They can declare localized catalogue text, dataset and
API metadata, entity concept URIs, identifiers, field concepts, relationship
roles, and codelist schemes. The compiler refuses overlay entries outside the
selected access profile and classification ceiling. It does not infer or
hardcode a domain model.

The PublicSchema-shaped household fixture demonstrates Person, Household, and
GroupMembership alignment entirely in configuration:

```bash
registry-serverctl generate manifest \
  products/registry-server/acceptance/publicschema-household \
  --output ./household-metadata
```

This produces the canonical Registry Manifest source and a DCAT JSON-LD
catalogue. Registry Manifest owns the standards rendering, so Registry Server
does not carry a second DCAT implementation.

Evidence can consume an authenticated Registry Server REST route through its
existing bounded `http-json` source and an explicitly reviewed adapter. Relay
remains a separate publication boundary. A direct Relay source adapter should
be added only for a concrete publication journey, rather than coupling either
product to Registry Server internals.

## Relationship to Registry Stack

Registry Server is a writable source-of-truth product. Registry Relay remains
the separately deployed read-only publication product; Evidence remains the
minimum-disclosure assertion product; Manifest receives a safe one-way
metadata projection; Mint may issue configured OIDC tokens; and PublicSchema
is an authoring input rather than a runtime dependency.
