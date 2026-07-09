# registry-relay development guide

This guide is for contributors working on the gateway codebase. Operator docs live in [ops.md](ops.md), [configuration.md](configuration.md), [api.md](api.md), [metadata.md](metadata.md), [client-integration.md](client-integration.md), and [provenance.md](provenance.md).

## Local setup

Install the pinned toolchain and fetch dependencies:

```sh
just setup
```

Build the release binary:

```sh
just build
```

Run with the canonical example config:

```sh
mkdir -p data
cp fixtures/example_social_registry.xlsx data/social_registry.xlsx
export PROGRAM_SYSTEM_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export STATS_OFFICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export VERIFICATION_SERVICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export REGISTRY_RELAY_AUDIT_HASH_SECRET='<at least 32 random bytes>'
just run
```

For richer local flows, use the demo pack in [../demo/README.md](../demo/README.md).

## Running against a local IdP

The steps below are a worked example for contributors, using the project's own local development stack (a Zitadel instance provisioned by the sibling `publicschema.com` compose stack). For a real deployment, adapt them to your own IdP.

The publicschema.com dev compose stack provisions a Zitadel organisation, project, OIDC application, test user, machine service account, and the relay-facing project roles on first boot. See `apps/publicschema.com/compose/seed/zitadel-bootstrap.md` for the resources created, the env-file shape, and the claim that carries roles in minted access tokens.

**Prerequisites.** The bootstrap must have completed against a current Zitadel volume so the `publicschema-api` machine user has `accessTokenType: JWT` and a generated client secret (Section 7b of `compose/seed/zitadel-init.sh`). Token minting uses the SA's `client_credentials` grant rather than the `workbench-dev` OIDC app's, because Zitadel WEB-typed OIDC applications silently drop the `client_credentials` grant at write time. If the `publicschema-api` machine user lacks `accessTokenType: JWT`, re-run `docker compose -f compose/dev.compose.yaml up zitadel-init` against the publicschema.com stack to regenerate the SA credentials and refresh `compose/seed/zitadel.env`; otherwise the token mint will fail with `invalid_grant` or produce an opaque bearer that the relay cannot verify.

To exercise the relay end-to-end:

```sh
# 1. Bring up Zitadel from the sibling stack.
cd ../publicschema.com
docker compose -f compose/dev.compose.yaml up -d zitadel zitadel-init

# 2. Mint a test access token.
cd ../registry-relay
TOKEN="$(./scripts/mint-zitadel-token.sh)"

# 3. Run the relay against the OIDC example.
cargo run -- --config config/example.oidc.yaml

# 4. Hit a protected endpoint with the minted bearer.
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18080/metadata/catalog
```

The `tests/oidc_zitadel.rs` integration test exercises the same path and asserts the granular failure modes above. The test reads `OIDC_ISSUER`, `OIDC_SA_CLIENT_ID`, and `OIDC_SA_CLIENT_SECRET` from the environment, so source the bootstrap env file first:

```sh
source ../publicschema.com/compose/seed/zitadel.env
cargo test --test oidc_zitadel -- --ignored --nocapture
```

The integration test verifies the auth wiring (signature, issuer, audience, principal extraction, granular `auth.*` codes) using a token minted by the bootstrap. Asserting RBAC against specific resource scopes requires either roles in the token that match `oidc.scope_map`'s keys, or aligning `oidc.scope_claim` with the IdP's role-bearing claim; the example `config/example.oidc.yaml` ships with the values the bootstrap emits.

## Verification commands

Use the project recipes when possible:

```sh
just fmt-check
just lint
just test
just build
just deny
```

`just ci` runs the full local gate. For focused iteration, run the narrow Rust test first, then at least the closest broader check before finishing.

Useful focused examples:

```sh
cargo test --test auth_flow
cargo test --test catalog_entity
cargo test --features ogcapi-records --test ogc_records_api
cargo test --test api_docs
```

Portable metadata checks are separate from the Relay runtime:

```sh
just metadata-validate profiles/example-civil-registration/fixtures/metadata.yaml
just metadata-validate-profiles
cargo test --test demo_configs_load
```

`just metadata-*` recipes use `REGISTRY_MANIFEST_CLI` when set, an installed
`registry-manifest` binary when present, a sibling `../registry-manifest`
checkout during local development, or the published
`https://github.com/jeremi/registry-manifest` tag configured by
`scripts/run_registry_manifest_cli.sh`.

The demo runtime configs are split-backed: every `demo/config/*.yaml` points
at a sibling `*.metadata.yaml` manifest, and `demo_configs_load` validates the
runtime bindings against those manifests. Keep [metadata.md](metadata.md)
current when changing the manifest model, renderer outputs, publication layout,
or `/metadata/*` routes.

For rendering individual artifacts and publishing static bundles, see [metadata.md](metadata.md#cli-reference).

DCAT-AP catalog validation runs at two levels:

```sh
REGISTRY_RELAY_RUN_EXTERNAL_SHACL=1 \
  cargo test --test catalog_entity generated_catalog_can_run_external_shacl_validation_when_enabled
```

The CI workflow also exports a sample catalog and validates it with the
local SHACL smoke profile. For a manual external check against the
European Commission SEMIC validator, run:

```sh
just validate-catalog-semic catalog=target/dcat-ap/metadata.bregdcat-ap.jsonld
```

The default external profile is `dcatap.3_0_1_base`.

For offline diagnostics against the vendored SEMIC SHACL resources, run:

```sh
just validate-catalog-semic-local catalog=target/dcat-ap/metadata.bregdcat-ap.jsonld
```

The local recipe defaults to `bregdcatap.2_1_0` and is a compatibility/gap
check only. Keep the external SEMIC recipe as the release validation signal.

### Fixture corpus

Relay-local response credential fixtures were removed with Relay credential
issuance. Keep credential issuance fixtures in Registry Notary. Relay fixtures
should cover ordinary data responses, metadata responses, and rejection or
migration paths for removed credential-issuance configuration only.

## Coverage metrics

Use `cargo-llvm-cov` when you need quantitative coverage metrics to complement the qualitative test review:

```sh
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
cargo llvm-cov --all-features --json --summary-only --output-path target/llvm-cov-summary.json
```

The summary report is written under ignored `target/` artifacts. For a quick local refresh after an instrumented coverage build already exists, add `--no-clean` to reuse compiled coverage artifacts:

```sh
cargo llvm-cov --all-features --json --summary-only --output-path target/llvm-cov-summary.json --no-clean
```

If a Homebrew-managed Rust toolchain cannot find `llvm-cov` or `llvm-profdata`, install Homebrew LLVM and point `cargo-llvm-cov` at it explicitly:

```sh
brew install llvm
LLVM_COV="$(brew --prefix llvm)/bin/llvm-cov" \
LLVM_PROFDATA="$(brew --prefix llvm)/bin/llvm-profdata" \
cargo llvm-cov --all-features --json --summary-only --output-path target/llvm-cov-summary.json
```

External-service tests remain ignored unless their required environment is configured, such as `DATA_GATE_POSTGRES_TEST_URL` for PostgreSQL and the Zitadel OIDC variables documented in [configuration.md](configuration.md#oidc-oauth2).

## Project layout

```text
src/api/          HTTP handlers and route-local helpers
src/audit/        audit records, sinks, redaction, hash chaining
src/auth/         auth trait, API-key provider, scope checks
src/config/       YAML model, loader, validation
src/entity/       entity registry built from config
src/format/       CSV, XLSX, and Parquet decoders
src/ingest/       source ingest, cache layout, refresh, readiness
src/metadata/     Relay adapters for scoped metadata publication
src/api/ogc/      optional OGC API Features and Records adapters
src/query/        entity and aggregate query planning
src/server.rs     router composition and cross-cutting middleware
profiles/        ecosystem profile descriptors and fixture metadata manifests
```

Portable metadata crates live in the public
`https://github.com/jeremi/registry-manifest` repository. Relay consumes
`registry-manifest-core` as a tagged Git dependency and shells out to
`registry-manifest-cli` only for local validation, rendering, and static
publication helper recipes.

Storage tables are private. Public routes must go through entity config, scope checks, audit, and query planning.

## Change guidelines

- Keep the public URL space entity-shaped. Do not expose table ids in data-plane paths.
- Add config fields through `src/config/mod.rs` and validation in `src/config/validate.rs`.
- Keep portable metadata in the split `registry-manifest-core` crate; it must not depend on Relay runtime, Axum, DataFusion, auth, scopes, OpenAPI, or connector code.
- Keep auth scopes independent. Metadata, rows, evidence verification, aggregate, and admin must not imply one another.
- Treat audit as a product surface. New routes should populate endpoint kind, dataset/entity/table ids, purpose, row count, suppression count, and stable error code when applicable.
- Prefer structured parsers and DataFusion expressions over string-built query logic.
- Do not log raw keys, fingerprints, private JWKs, row values, or full environment dumps.
- For user-visible API behavior, update [api.md](api.md) and focused integration tests in the same change.
- For operator-visible config behavior, update [configuration.md](configuration.md), [ops.md](ops.md), and config-loader tests.
- For portable metadata behavior, update [metadata.md](metadata.md), metadata-core tests, and split config binding tests.

## Adding an endpoint

1. Add the route handler under `src/api/`.
2. Mount it in `src/api/mod.rs` and `src/server.rs` on the correct public, protected, or admin surface.
3. Enforce the exact scope needed for the operation.
4. Ensure audit fields are populated and sensitive inputs are redacted.
5. Add OpenAPI coverage in `src/api/openapi.rs` when the endpoint is public.
6. Add focused tests for success, missing auth, wrong scope, and malformed input.
7. Update [api.md](api.md) if clients need to know about the behavior.

## Adding config

1. Add the serde model to `src/config/mod.rs`.
2. Add validation in `src/config/validate.rs`.
3. Update `config/example.yaml` only when the field is part of the canonical example.
4. Add positive and negative loader tests under `tests/config_loader.rs` or a focused test file.
5. Update [configuration.md](configuration.md) and [ops.md](ops.md) when operators must set or rotate it.

## Pull requests

Keep pull requests focused. Include tests for any code change, or explain why the change is documentation, configuration, or tooling only. Do not commit secrets, production data, private operator notes, or internal planning documents.

## Documentation style

Docs should describe the current supported behavior first, then any reserved or deferred surfaces. Keep `README.md`, `docs/api.md`, `docs/configuration.md`, `docs/client-integration.md`, and `docs/ops.md` operationally current.

Inline Rust docs should explain invariants and boundaries that break readily while editing. Avoid comments that repeat obvious field names or preserve obsolete implementation scaffolding after the code has matured.

## OpenAPI release policy

Registry Relay has two OpenAPI surfaces:

- Runtime OpenAPI: auth-gated by default, generated from the running configuration, and filtered to the caller's metadata scopes. Demo and controlled tooling configs can expose the full OpenAPI surface without auth.
- Static OpenAPI: the checked-in abstract artifact under [`../openapi/`](../openapi/), used for release review and contract discussion.

The runtime document is the source of truth for a deployed instance. The static artifact is a release artifact, not a replacement for deployment discovery. Fetch runtime `/openapi.json` from a deployment for concrete dataset and entity operations.

### When to refresh the static artifact

Refresh the static OpenAPI artifact when any of these change:

- public route family;
- auth or scope requirement;
- query parameter or request body;
- response body or media type;
- Problem Details schema or stable error code;
- standards adapter surface;
- metadata visibility rule that changes generated operations.

Do not refresh it for implementation-only refactors that leave the public contract unchanged.

### Refresh procedure

1. Update [api.md](api.md) for any public contract change.
2. Start Relay with a representative release config.
3. Fetch the runtime OpenAPI document with a principal that can see the intended release surface, or with `server.openapi_requires_auth: false` in a controlled local release-artifact config.
4. Reduce instance-specific dataset/entity names to abstract placeholders if the release artifact is meant to stay deployment-neutral.
5. Validate JSON formatting.
6. Run the API documentation tests.
7. Diff the static artifact and check that every meaningful change is explained in release notes.

Suggested checks:

```sh
python -m json.tool openapi/registry-relay.openapi.json >/dev/null
cargo test --test api_docs
```

### Review rules

Review the static artifact for:

- no secret examples;
- no private source paths;
- no deployment-only hostnames except example domains;
- no accidental broadening of scopes;
- Problem Details responses on non-2xx operations;
- correct media types for JSON and CSV responses;
- no removed Relay response-credential media types or support routes;
- tags and summaries that match the docs;
- route families that match the API guide.

### Release note requirement

Every static OpenAPI refresh should mention one of:

- no public contract change, artifact refreshed for documentation parity;
- additive contract change;
- breaking contract change;
- route-design cleanup before the API is declared stable.

Release notes should call the artifact abstract when it uses placeholder dataset/entity names and should direct deployments to fetch the runtime `/openapi.json` document for concrete route and dataset shape.

## Monorepo preflight

Relay consumes `registry-platform` and `registry-manifest` from the
registry-stack workspace. Run the local preflight before merging
Platform-facing changes:

```sh
just ci-preflight
```

The command runs locked Cargo metadata and a Relay package check from the
monorepo root so Cargo resolves the same workspace graph used by root CI.

The mapper dependency uses the local Crosswalk crate at
`../crosswalk/crates/crosswalk-core` in `Cargo.toml`, matching the
workspace checkout used for release builds.
