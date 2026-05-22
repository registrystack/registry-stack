# Registry Relay

Registry Relay is a config-driven Rust service that turns sensitive government tabular files and selected database tables into protected, read-only, domain-oriented APIs.

V1 is built around two layers:

- Storage tables read local CSV, XLSX, Parquet, or PostgreSQL sources into Arrow/DataFusion. Table ids are private implementation detail.
- Entities expose domain resources such as `household` or `individual`, with field projection, relationships, scopes, configured aggregates, semantic metadata, and audit records.

This is not an open-data portal and not a spreadsheet wrapper. It publishes restricted consultation APIs for authorized systems.

## Background

Registry Relay is an experiment toward a redesigned [GovStack](https://govstack.global/) Digital Registries Building Block. The current BB spec defines a single uniform CRUD platform; this project explores the BB instead as a protected consultation gateway with optional capability families (evidence verification, aggregates, standards adapters) over a shared entity model. Provisioning and Write are intentionally out of scope for V1; conformance is by capability, not by a single mandatory interface.

Standards integrations such as DCAT-AP, OGC API Records, OGC API Features, PublicSchema, provenance VCs, and the optional [Social Protection Digital Convergence Initiative (SP DCI)](https://spdci.org/) sync adapter are layered on top of the core gateway. Use them when a deployment needs those interoperability contracts; the default product model remains protected read-only registry consultation.

## Current Status

0.1.0 targets the V1 protected consultation API surface over local CSV, XLSX, Parquet, and bounded PostgreSQL sources. Postgres snapshot sources are supported for structured tables and configured read-only queries; Postgres live sources are supported only for structured tables, with generated column projection pushdown and gateway-side filters/limits. The config model, startup ingest, entity-shaped routes, API-key auth, readable operational logs with optional JSONL, stdout/file/syslog audit sinks, optional audit chaining, admin reload on `server.admin_bind`, refresh loops, best-effort OpenAPI, and DCAT-AP/SHACL validation workflow are present. Catalog JSON-LD can include dataset-scoped ODRL Offers, standards-shaped media type metadata, evidence offerings, and DCAT access-service metadata for downstream connector integration. Admin routes are intentionally not mounted on the public data-plane listener.

## Repository Map

- [config/example.yaml](config/example.yaml): canonical example config.
- [docs/configuration.md](docs/configuration.md): operator-facing configuration reference.
- [docs/api.md](docs/api.md): authentication, endpoint, filtering, pagination, and error contract.
- [docs/metadata.md](docs/metadata.md): portable metadata manifests, static publication, and `/metadata/*` routes.
- [STANDARDS_ASSUMPTIONS.md](STANDARDS_ASSUMPTIONS.md): standards evidence,
  Registry Relay publication choices, and downstream interpretation boundaries.
- [docs/evidence-verification.md](docs/evidence-verification.md): evidence verification guide, examples, privacy model, and signed receipts.
- [docs/evidence-server-spec.md](docs/evidence-server-spec.md): draft target
  architecture for a standalone evidence server that computes registry-backed
  claims.
- [docs/ops.md](docs/ops.md): deployment and operations runbook.
- [docs/provenance.md](docs/provenance.md): signed Verifiable Credentials guide.
- [docs/development.md](docs/development.md): local development, verification, and contribution notes.
- [crates/registry-metadata-core](crates/registry-metadata-core): portable metadata manifest model, validation, and renderers.
- [crates/registry-metadata-cli](crates/registry-metadata-cli): local metadata validation, rendering, and static publish CLI.
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

Portable metadata lives in `metadata.yaml` manifests. Runtime config binds those logical datasets, entities, and fields to live sources. Metadata manifests must not contain tables, columns, source paths, scopes, or backend URLs.

Use this split when you want standards-facing metadata that can outlive Registry Relay itself. A civil registration application, a social benefits application, or another registry system can validate and publish the same manifest through static files without adopting Relay's runtime API. The checked-in app profiles are hypothetical examples; real OpenCRVS, OpenSPP, PublicSchema, or SP DCI profiles should be added only after review with the relevant project artifacts or maintainers.

Use the metadata CLI through `just`:

```sh
just metadata-validate profiles/example-civil-registration/fixtures/metadata.yaml
just metadata-validate-profiles
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml dcat target/metadata/dcat.jsonld
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml json-schema target/metadata/person.schema.json "--dataset vital-events --entity person"
just metadata-publish profiles/example-civil-registration/fixtures/metadata.yaml target/metadata/public
```

`metadata-publish` writes a static bundle with `index.json`, the original manifest, catalog JSON, base DCAT, BRegDCAT-AP, SHACL, and entity JSON Schemas. The bundle can be served as static files without starting Registry Relay.

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

Use dataset scopes narrowly. `metadata`, `aggregate`, `rows`, `evidence_verification`, and `admin` are independent. An evidence-verification-only key cannot list metadata, run aggregates, read rows, or reload data.

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

## Run Locally

The example config references data under `./data/social_registry.xlsx`, so either adapt the path or copy a fixture into place:

```sh
mkdir -p data
cp fixtures/example_social_registry.xlsx data/social_registry.xlsx
export PROGRAM_SYSTEM_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export STATS_OFFICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export VERIFICATION_SERVICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
just run
```

Health endpoints are unauthenticated:

```sh
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/ready
```

Protected endpoints require a configured API key:

```sh
curl -H "Authorization: Bearer $PROGRAM_SYSTEM_API_KEY" \
  http://127.0.0.1:8080/datasets
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
GET /metadata/datasets
GET /metadata/datasets/{dataset_id}
GET /metadata/datasets/{dataset_id}/policy
GET /metadata/datasets/{dataset_id}/entities/{entity}/schema
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
GET /ogc/v1/records                         (feature: ogcapi-records)
GET /ogc/v1/records/collections             (feature: ogcapi-records)
GET /ogc/v1/records/collections/datasets/items  (feature: ogcapi-records)
GET /datasets
GET /datasets/{dataset_id}
GET /datasets/{dataset_id}/{entity}/schema
GET /datasets/{dataset_id}/{entity}
GET /datasets/{dataset_id}/{entity}/{id}
GET /datasets/{dataset_id}/{entity}/{id}/{relationship}
POST /evidence-offerings/{offering_id}/verifications
GET /datasets/{dataset_id}/{entity}/aggregates
GET /datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}
```

Storage table ids do not appear in these paths. Filters are allowed only when declared under the entity's `api.allowed_filters`. Arbitrary SQL is not exposed.

`GET /docs` serves a local Scalar API reference shell. The shell is public, but it contains no catalog data by itself. It asks for a bearer token and then fetches the auth-gated `GET /openapi.json` document with that token.

See [docs/api.md](docs/api.md) for scope requirements, query parameters, pagination, `Data-Purpose`, conditional requests, and Problem Details error shapes.

## DCAT-AP And SHACL Validation

The generated `/metadata/dcat/bregdcat-ap` document is JSON-LD with embedded entity SHACL node shapes. To validate a saved catalog or a running endpoint with a real SHACL engine:

```sh
just validate-catalog-shacl catalog=target/metadata.bregdcat-ap.jsonld
uv run --with 'pyshacl>=0.27,<0.31' --with 'rdflib-jsonld>=0.6' \
  python scripts/validate_dcat_shacl.py \
  --catalog http://127.0.0.1:8080/metadata/dcat/bregdcat-ap \
  --header "Authorization: Bearer $PROGRAM_SYSTEM_API_KEY"
```

The recipe uses `uv` to run `pyshacl` and the local smoke profile at `tests/fixtures/shacl/dcat-ap-catalog-smoke.ttl`. Pass stricter national or EU DCAT-AP shapes directly to the script when they are available:

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

Build the production image with Docker:

```sh
docker build -t registry-relay:local .
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
  -v "$PWD/config/example.yaml:/etc/registry-relay/config.yaml:ro" \
  -v "$PWD/fixtures:/var/lib/registry-relay/data:ro" \
  registry-relay:local
```

For production, mount a deployment-specific config, mount source data read-only, provide API-key hashes through the platform secret store, and choose the audit sink that matches the platform logging model.

## Signed Verifiable Credentials (Opt-In)

The gateway can return W3C Verifiable Credentials (compact JWS) for supported evidence-verification, aggregate, and entity-record responses. The feature is off by default; enable it by adding a `provenance:` block to the config (see [config/example.yaml](config/example.yaml) for the template). Callers opt in per request with:

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
