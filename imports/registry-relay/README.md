# Registry Relay

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Registry Relay is a config-driven Rust service that turns sensitive government tabular files and selected database tables into protected, read-only, domain-oriented APIs.

V1 is built around two layers:

- Storage tables read local CSV, XLSX, Parquet, or PostgreSQL sources into Arrow/DataFusion. Table ids are private implementation detail.
- Entities expose domain resources such as `household` or `individual`, with field projection, relationships, scopes, configured aggregates, semantic metadata, and audit records.

This is not an open-data portal and not a spreadsheet wrapper. It publishes restricted consultation APIs for authorized systems.

## Background

Registry Relay is an experiment toward a redesigned [GovStack](https://govstack.global/) Digital Registries Building Block. The current BB spec defines a single uniform CRUD platform; this project explores the BB instead as a protected consultation gateway with optional capability families (evidence verification, aggregates, standards adapters) over a shared entity model. Provisioning and Write are intentionally out of scope for V1; conformance is by capability, not by a single mandatory interface.

Standards integrations such as DCAT-AP, OGC API Records, OGC API Features, PublicSchema, provenance VCs, and the optional [Social Protection Digital Convergence Initiative (SP DCI)](https://spdci.org/) sync adapter are layered on top of the core gateway. Use them when a deployment needs those interoperability contracts; the default product model remains protected read-only registry consultation.

## Current Status

0.1.0 targets the V1 protected consultation API surface over local CSV, XLSX, Parquet, and bounded PostgreSQL sources. Postgres snapshot sources are supported for structured tables and configured read-only queries; Postgres live sources are supported only for structured tables, with generated column projection pushdown and gateway-side filters/limits. The config model, startup ingest, entity-shaped routes, API-key and OIDC auth, readable operational logs with optional JSONL, stdout/file/syslog audit sinks with chained platform audit envelopes, admin reload on `server.admin_bind`, refresh loops, scoped OpenAPI, portable metadata publication, and DCAT-AP/SHACL validation workflow are present. Catalog JSON-LD can include dataset-scoped ODRL Offers, standards-shaped media type metadata, evidence offerings, and DCAT access-service metadata for downstream connector integration. Optional feature-gated adapters expose OGC API Features, OGC API Records, PublicSchema VC mapping, and SP DCI sync routes. Admin routes are intentionally not mounted on the public data-plane listener.

## Repository Map

- [config/example.yaml](config/example.yaml): canonical example config.
- [docs/README.md](docs/README.md): documentation map, status labels, and missing-doc backlog.
- [docs/client-integration.md](docs/client-integration.md): language-neutral caller integration guide.
- [docs/configuration.md](docs/configuration.md): operator-facing configuration reference.
- [docs/deployment-hardening.md](docs/deployment-hardening.md): production hardening checklist.
- [docs/xlsx-readiness-contract.md](docs/xlsx-readiness-contract.md): checklist for using XLSX workbooks as stable Registry Relay sources.
- [docs/api.md](docs/api.md): authentication, endpoint, filtering, pagination, and error contract.
- [docs/metadata.md](docs/metadata.md): portable metadata manifests, static publication, and `/metadata/*` routes.
- [STANDARDS_ASSUMPTIONS.md](STANDARDS_ASSUMPTIONS.md): standards evidence,
  Registry Relay publication choices, and downstream interpretation boundaries.
- [docs/evidence-verification.md](docs/evidence-verification.md): Registry Notary discovery notes.
- [registry-notary](https://github.com/jeremi/registry-notary): standalone Registry Notary
  workspace for registry-backed claim evaluation, rendering, and credential
  issuance.
- [docs/ops.md](docs/ops.md): deployment and operations runbook.
- [docs/openapi-release-policy.md](docs/openapi-release-policy.md): static and runtime OpenAPI release rules.
- [docs/provenance.md](docs/provenance.md): signed Verifiable Credentials guide.
- [docs/relay-scenario-catalog.md](docs/relay-scenario-catalog.md): personas, scenarios, and support status.
- [docs/standards-adapter-operator-guide.md](docs/standards-adapter-operator-guide.md): operator checklist for optional standards adapters.
- [docs/use-cases.md](docs/use-cases.md): core product journeys.
- [docs/development.md](docs/development.md): local development, verification, and contribution notes.
- [docs/release-notes.md](docs/release-notes.md): adopter-facing release notes and known limits.
- [registry-manifest-core](https://github.com/jeremi/registry-manifest/tree/main/crates/registry-manifest-core): portable metadata manifest model, validation, and renderers.
- [registry-manifest-cli](https://github.com/jeremi/registry-manifest/tree/main/crates/registry-manifest-cli): local metadata validation, rendering, and static publish CLI.
- [profiles/](profiles/): non-normative example profile descriptors and fixture metadata manifests.
- [docs/performance-load-testing-spec.md](docs/performance-load-testing-spec.md): performance and load testing plan.
- [perf/](perf/): k6 scenarios, synthetic fixture configs, and performance run helpers.
- [benches/](benches/): Criterion microbenchmarks for auth, ETags, query planning, JSON, registry lookup, and audit.
- [fixtures/](fixtures/): small local files for development and demos.
- [src/](src/): gateway implementation.
- [tests/](tests/): focused integration and unit tests.

## Build

Prerequisites:

- Rust stable toolchain
- `just` for task shortcuts

```sh
just setup
just build
```

The release binary is written to `target/release/registry-relay`.
Coverage metrics use `cargo-llvm-cov`; see [docs/development.md#coverage-metrics](docs/development.md#coverage-metrics) for the install and report commands.

## Metadata Manifests

Portable metadata lives in `metadata.yaml` manifests. Runtime config binds those logical datasets, entities, and fields to live sources. Metadata manifests must not contain tables, columns, source paths, scopes, or Relay runtime backend URLs. Evidence offerings may declare standards-facing service `endpoint_url` and `discovery_url` values when the offering is fulfilled by Registry Notary.

Use this split when you want standards-facing metadata that can outlive Registry Relay itself. A civil registration application, a social benefits application, or another registry system can validate and publish the same manifest through static files without adopting Relay's runtime API. The checked-in app profiles are hypothetical examples; real OpenCRVS, OpenSPP, PublicSchema, or SP DCI profiles should be added only after review with the relevant project artifacts or maintainers.

Use the metadata CLI through `just`:

```sh
just metadata-validate profiles/example-civil-registration/fixtures/metadata.yaml
just metadata-validate-profiles
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml dcat target/metadata/dcat.jsonld
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml json-schema target/metadata/person.schema.json "--dataset vital-events --entity person"
just metadata-publish profiles/example-civil-registration/fixtures/metadata.yaml target/metadata/public
```

These recipes use an installed `registry-manifest` binary when present, a
sibling `../registry-manifest` checkout during local development, or the
published `registry-manifest` Git tag when running from a clean Relay clone.

`metadata-publish` writes a static bundle with `index.json`, the original manifest, catalog JSON, evidence-offering JSON, policy JSON-LD, base DCAT, profile DCAT, SHACL, and entity JSON Schemas. The bundle can be served as static files without starting Registry Relay.

When Relay serves a split config, it validates runtime bindings against the compiled manifest at startup and exposes caller-scoped metadata under `/metadata/*`. See [docs/metadata.md](docs/metadata.md) for the manifest shape, publication layout, endpoint list, and error codes.

## Configure

The binary reads config from the first available source:

1. `--config <path>`
2. `REGISTRY_RELAY_CONFIG`
3. `./config/example.yaml`

API keys are never stored in the YAML file. Each configured key points at an environment variable containing a SHA-256 fingerprint of a high-entropy raw key:

```yaml
auth:
  mode: api_key
  api_keys:
    - id: program_system
      hash_env: PROGRAM_SYSTEM_API_KEY_HASH
      scopes:
        - social_registry:metadata
        - social_registry:aggregate
        - social_registry:rows
```

Clients authenticate with either:

```http
Authorization: Bearer <api-key>
```

or:

```http
X-Api-Key: <api-key>
```

Use dataset scopes narrowly. `metadata`, `aggregate`, `rows`, `evidence_verification`, and `admin` are independent. An evidence-verification-only key cannot list metadata, run aggregates, read rows, or reload data. Relay no longer hosts claim-verification execution endpoints; `evidence_verification` remains a distinct scope label for standards adapters and integrations that need evidence-oriented access.

Alternatively, set `auth.mode: oidc` to verify bearer JWTs against an external OpenID Connect / OAuth2 IdP. The relay is a resource server: it validates tokens against the IdP's JWKS but never mints, refreshes, or stores them.

```yaml
auth:
  mode: oidc
  oidc:
    issuer: https://idp.example.gov
    audience:
      - registry-relay
    discovery_url: https://idp.example.gov/.well-known/openid-configuration
    algorithms:
      - RS256
    # scope_map renames IdP roles/claims to the relay's
    # `<dataset_id>:<level>` scopes; required when IdP role names
    # differ from relay scope names. See config/example.oidc.yaml
    # and docs/configuration.md for the full set.
    scope_map:
      "role:social-registry-reader": "social_registry:rows"
```

See [config/example.oidc.yaml](config/example.oidc.yaml) for a complete drop-in alternative targeting a local Zitadel and [docs/configuration.md](docs/configuration.md#oidc-oauth2) for the full field reference plus the granular `auth.*` failure-code taxonomy. The publicschema.com dev compose stack provisions a Zitadel instance you can point at directly; `scripts/mint-zitadel-token.sh` and `tests/oidc_zitadel.rs` exercise the path end-to-end.

Relay validates the access-token JOSE `typ` header against `auth.oidc.token_types`, which defaults to `JWT` and `at+jwt`. The shared verifier currently rejects tokens that omit `typ`; configure the IdP to emit an access-token type header rather than bypassing that check in Relay.

## Run Locally

The example config references data under `./data/social_registry.xlsx`, so either adapt the path or copy a fixture into place:

```sh
mkdir -p data
cp fixtures/example_social_registry.xlsx data/social_registry.xlsx
export PROGRAM_SYSTEM_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export STATS_OFFICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export VERIFICATION_SERVICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export REGISTRY_RELAY_AUDIT_HASH_SECRET='<at least 32 random bytes>'
just run
```

Health endpoints are unauthenticated:

```sh
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/ready
```

Protected endpoints require a configured API key:

```sh
curl -H "Authorization: Bearer $PROGRAM_SYSTEM_API_KEY" \
  http://127.0.0.1:8080/v1/datasets
```

## Public API Shape

The public URL space is entity-shaped:

```text
GET /docs
GET /openapi.json
GET /metadata
GET /metadata/catalog
GET /metadata/dcat
GET /metadata/dcat/{profile}
GET /metadata/shacl
GET /metadata/policies
GET /metadata/profiles
GET /metadata/profiles/{profile}
GET /metadata/datasets
GET /metadata/datasets/{dataset_id}
GET /metadata/datasets/{dataset_id}/policy
GET /metadata/datasets/{dataset_id}/entities
GET /metadata/datasets/{dataset_id}/entities/{entity}
GET /metadata/datasets/{dataset_id}/entities/{entity}/schema
GET /metadata/datasets/{dataset_id}/entities/{entity}/shacl
GET /metadata/schema/{dataset_id}/{entity}/schema.json
GET /metadata/ogc/records
GET /metadata/ogc/records/{record_id}
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
GET /.well-known/api-catalog
GET /ogc/v1                                 (feature: ogcapi-features)
GET /ogc/v1/conformance                     (feature: ogcapi-features)
GET /ogc/v1/collections                     (feature: ogcapi-features)
GET /ogc/v1/datasets/{dataset_id}/collections  (feature: ogcapi-features)
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}  (feature: ogcapi-features)
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items  (feature: ogcapi-features)
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}  (feature: ogcapi-features)
GET /ogc/v1/records                         (feature: ogcapi-records)
GET /ogc/v1/records/conformance             (feature: ogcapi-records)
GET /ogc/v1/records/collections             (feature: ogcapi-records)
GET /ogc/v1/records/collections/{collection_id}  (feature: ogcapi-records)
GET /ogc/v1/records/collections/{collection_id}/items  (feature: ogcapi-records)
GET /ogc/v1/records/collections/{collection_id}/items/{record_id}  (feature: ogcapi-records)
GET /ogc/edr/v1                             (feature: ogcapi-edr)
GET /ogc/edr/v1/conformance                 (feature: ogcapi-edr)
GET /ogc/edr/v1/collections                 (feature: ogcapi-edr)
GET /ogc/edr/v1/collections/{collection_id} (feature: ogcapi-edr)
GET|POST /ogc/edr/v1/collections/{collection_id}/area  (feature: ogcapi-edr)
GET /v1/datasets
GET /v1/datasets/{dataset_id}
GET /v1/datasets/{dataset_id}/entities/{entity}/schema
GET /v1/datasets/{dataset_id}/entities/{entity}/records
GET /v1/datasets/{dataset_id}/entities/{entity}/records/{id}
GET /v1/datasets/{dataset_id}/entities/{entity}/records/{id}/relationships/{relationship}
GET /v1/datasets/{dataset_id}/aggregates
GET /v1/datasets/{dataset_id}/aggregates/{aggregate_id}
POST /v1/datasets/{dataset_id}/aggregates/{aggregate_id}/query
GET /v1/datasets/{dataset_id}/aggregates/{aggregate_id}/metadata
GET /v1/datasets/{dataset_id}/indicators
GET /v1/datasets/{dataset_id}/indicators/{indicator_id}
GET /v1/datasets/{dataset_id}/dimensions
GET /v1/datasets/{dataset_id}/dimensions/{dimension_id}
POST /dci/{registry}/registry/sync/search   (feature: spdci-api-standards)
POST /dci/{registry}/registry/sync/disabled (feature: spdci-api-standards)
POST /dci/{registry}/registry/sync/get-disability-details  (feature: spdci-api-standards)
POST /dci/{registry}/registry/sync/get-disability-support  (feature: spdci-api-standards)
```

For SP DCI, `sync/search` supports every named registry entry configured under
`standards.spdci.registries` such as `dr`, `sr`, `crvs`, or `fr`. The
`disabled`, `get-disability-details`, and `get-disability-support` routes are
Disability Registry-specific: `{registry}` must resolve to a registry entry
whose dataset/entity match `standards.spdci.disability_registry`.

Evidence offerings are discovery records only. Relay publishes offerings whose
metadata declares `access.kind: registry-notary`; clients call the advertised
Registry Notary endpoint directly for claim and evidence verification.

Storage table ids do not appear in these paths. Filters are allowed only when declared under the entity's `api.allowed_filters`. Arbitrary SQL is not exposed.

`GET /docs` serves a local Scalar API reference shell. The shell is public, but it contains no catalog data by itself. It asks for a bearer token and then fetches the auth-gated `GET /openapi.json` document with that token.

See [docs/api.md](docs/api.md) for scope requirements, query parameters, pagination, `Data-Purpose`, conditional requests, and Problem Details error shapes.

When provenance is configured and enabled, public unauthenticated support routes also expose `/.well-known/did.json` in gateway issuer mode and `/schemas/{claim_type}/{version}` plus `/contexts/{vocab}/{version}` for verifier resolution.

## DCAT-AP And SHACL Validation

The generated `/metadata/dcat/bregdcat-ap` document is JSON-LD with embedded entity SHACL node shapes. To validate a saved catalog or a running endpoint with a real SHACL engine:

```sh
just validate-catalog-shacl catalog=target/metadata.bregdcat-ap.jsonld
uv run --with 'pyshacl>=0.27,<0.31' --with 'rdflib-jsonld>=0.6' \
  python scripts/validate_dcat_shacl.py \
  --catalog http://127.0.0.1:8080/metadata/dcat/bregdcat-ap \
  --header "Authorization: Bearer $PROGRAM_SYSTEM_API_KEY"
```

The recipe uses `uv` to run `pyshacl` and the local smoke profile at `scripts/shacl/dcat-ap-catalog-smoke.ttl`. Pass stricter national or EU DCAT-AP shapes directly to the script when they are available:

```sh
uv run --with 'pyshacl>=0.27,<0.31' --with 'rdflib-jsonld>=0.6' \
  python scripts/validate_dcat_shacl.py \
  --catalog target/metadata.bregdcat-ap.jsonld \
  --shapes path/to/external-dcat-ap-shapes.ttl
```

For CI jobs that should exercise the external engine from Rust tests, set `REGISTRY_RELAY_RUN_EXTERNAL_SHACL=1` before running `cargo test --test catalog_entity generated_catalog_can_run_external_shacl_validation_when_enabled`.

For external DCAT-AP profile validation, export a catalog and submit it
to the European Commission SEMIC SHACL validator:

```sh
curl -H "Authorization: Bearer $PROGRAM_SYSTEM_API_KEY" \
  http://127.0.0.1:8080/metadata/dcat/bregdcat-ap \
  > target/metadata.bregdcat-ap.jsonld

just validate-catalog-semic catalog=target/metadata.bregdcat-ap.jsonld
```

The default SEMIC profile is `dcatap.3_0_1_base`. Use
`validation_type=dcatap.3_0_1_full` or another SEMIC validation type when
you need a stricter release check.

For repeatable offline diagnostics against the vendored SEMIC SHACL resources,
run the local compatibility check. This is useful for BRegDCAT-AP gap reports
and CI triage when the external validator is unavailable, but it is not a
replacement for the live SEMIC ITB validation service:

```sh
just validate-catalog-semic-local catalog=target/metadata.bregdcat-ap.jsonld
just validate-catalog-semic-local catalog=target/metadata.bregdcat-ap.jsonld profile=dcatap.2_0_0
```

## Container Image

The image build uses the shared `registry-platform` and `cel-mapping` crates
through the same path dependency layout as local Cargo builds. Keep those
checkouts next to this repository, or set `REGISTRY_PLATFORM_DIR` and
`CEL_MAPPING_DIR` when using the helper script.

Build the production image with Docker:

```sh
docker buildx build --load \
  --build-context registry-platform=../registry-platform \
  --build-context cel-mapping=../cel-mapping \
  -t registry-relay:local \
  .
```

or with the helper:

```sh
scripts/build-image.sh registry-relay:local
```

The image:

- builds the Rust release binary in a cargo builder stage;
- copies only the binary and license into a small Debian runtime stage;
- runs as the non-root `registry_relay` user;
- exposes port `8080`;
- uses `/etc/registry-relay/config.yaml` as the default config path;
- creates `/var/lib/registry-relay/cache`, `/var/lib/registry-relay/data`, and `/var/log/registry-relay`.

Example run:

```sh
docker run --rm -p 8080:8080 \
  -e PROGRAM_SYSTEM_API_KEY_HASH \
  -e STATS_OFFICE_API_KEY_HASH \
  -e VERIFICATION_SERVICE_API_KEY_HASH \
  -e REGISTRY_RELAY_AUDIT_HASH_SECRET \
  -v "$PWD/config/example.yaml:/etc/registry-relay/config.yaml:ro" \
  -v "$PWD/fixtures:/var/lib/registry-relay/data:ro" \
  registry-relay:local
```

For production, mount a deployment-specific config, mount source data read-only, provide API-key hashes through the platform secret store, and choose the audit sink that matches the platform logging model.

## Signed Verifiable Credentials (Opt-In)

The gateway can return W3C Verifiable Credentials (compact JWS) for supported aggregate and entity-record responses. The feature is off by default; enable it by adding a `provenance:` block to the config (see [config/example.yaml](config/example.yaml) for the template). Callers opt in per request with:

```http
Accept: application/vc+jwt
```

When either side opts out, responses stay plain JSON. Issued VCs carry a `provenance.vc.issued` audit event alongside the regular audit record.

See [docs/provenance.md](docs/provenance.md) for the full wire shape, issuer modes (`gateway`, `delegated`), supporting endpoints (`/.well-known/did.json`, `/schemas/*`, `/contexts/*`), key rotation procedure, and external verification recipe.

## Performance Testing

Performance testing uses generated synthetic fixtures, generated throwaway API keys, k6 HTTP scenarios, and Criterion microbenchmarks. Generated fixtures, secrets, and reports stay under ignored paths such as `perf/fixtures/generated/` and `target/perf/`.

Prepare local fixtures and perf keys:

```sh
just perf-gen profile=large
just perf-keys
```

Run the default overnight soak profile:

```sh
just perf-soak
```

That starts the release server with `perf/config/large.yaml`, runs `perf/k6/soak.js` for 60 minutes, samples process stats every 5 seconds, and writes reports under `target/perf/reports/`.

Useful shorter runs:

```sh
just perf-scenario cached_304
just perf-scenario large_304 large 10s
just perf-scenario mixed_read medium 2m
```

Build and syntax-check the perf harness without running k6:

```sh
just perf-smoke
```

Run Criterion microbenchmarks:

```sh
just perf-bench
```

Reported numbers should state the machine, profile, fixture size, VU count, duration, compression setting, and whether the run is loopback-only. See [perf/README.md](perf/README.md) for the full local workflow and [docs/performance-load-testing-spec.md](docs/performance-load-testing-spec.md) for the benchmark design and thresholds.

## Operations

See [docs/ops.md](docs/ops.md) for deploy, configuration, key rotation, audit handling, dataset reload, and troubleshooting guidance.

## Platform Compatibility

Relay consumes `registry-platform` from a sibling checkout during local commons
release work. Run the compatibility gate before merging Platform-facing
changes:

```sh
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform scripts/check-platform-compat.sh
```

The command checks the all-feature build plus the focused OIDC and audit tests
that exercise the shared Platform security APIs. When
`REGISTRY_PLATFORM_SOURCE_DIR` is not the sibling path encoded in Cargo, the
script builds in a temporary sibling-layout copy so Cargo resolves the same
Platform checkout the script validated. Set `CEL_MAPPING_SOURCE_DIR` as well
when the Crosswalk checkout is not available at `../cel-mapping`.
