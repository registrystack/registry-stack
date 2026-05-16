# Registry Relay

Registry Relay is a config-driven Rust service that turns sensitive government tabular files and selected database tables into protected, read-only, domain-oriented APIs.

V1 is built around two layers:

- Storage tables read local CSV, XLSX, Parquet, or PostgreSQL sources into Arrow/DataFusion. Table ids are private implementation detail.
- Entities expose domain resources such as `household` or `individual`, with field projection, relationships, scopes, configured aggregates, semantic metadata, and audit records.

This is not an open-data portal and not a spreadsheet wrapper. It publishes restricted consultation APIs for authorized systems.

## Current Status

0.1.0 targets the V1 protected consultation API surface over local CSV, XLSX, Parquet, and bounded PostgreSQL sources. Postgres snapshot sources are supported for structured tables and configured read-only queries; Postgres live sources are supported only for structured tables, with generated column projection pushdown and gateway-side filters/limits. The config model, startup ingest, entity-shaped routes, API-key auth, JSON operational logs, stdout/file/syslog audit sinks, optional audit chaining, admin table reload on `server.admin_bind`, refresh loops, best-effort OpenAPI, and DCAT-AP/SHACL validation workflow are present. Catalog JSON-LD includes DSP-facing participant id, ODRL offer, transfer format, and access-service metadata for downstream connector integration. Admin routes are intentionally not mounted on the public data-plane listener. A few surfaces remain intentionally deferred:

- `POST /admin/reload` is reserved for registry-wide reload and currently returns `501 admin.reload_unavailable` on the admin listener when `server.admin_bind` is configured.
- Bulk export endpoints are contract-locked for V1.x and are not implemented.

Keep deployment docs and examples aligned with the operator and API guides, and treat deferred surfaces as unavailable until their owning follow-up lands.

## Repository Map

- [config/example.yaml](config/example.yaml): canonical example config.
- [docs/configuration.md](docs/configuration.md): operator-facing configuration reference.
- [docs/api.md](docs/api.md): authentication, endpoint, filtering, pagination, and error contract.
- [docs/ops.md](docs/ops.md): deployment and operations runbook.
- [docs/provenance.md](docs/provenance.md): signed Verifiable Credentials guide.
- [docs/development.md](docs/development.md): local development, verification, and contribution notes.
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

Use dataset scopes narrowly. `metadata`, `aggregate`, `rows`, `verify`, `bulk_export`, and `admin` are independent. A verify-only key cannot list metadata, run aggregates, read rows, or reload data.

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
GET /catalog
GET /catalog/dcat-ap.jsonld
GET /datasets
GET /datasets/{dataset_id}
GET /datasets/{dataset_id}/{entity}/schema
GET /datasets/{dataset_id}/{entity}
GET /datasets/{dataset_id}/{entity}/{id}
GET /datasets/{dataset_id}/{entity}/{id}/{relationship}
GET /datasets/{dataset_id}/{entity}/verify
GET /datasets/{dataset_id}/{entity}/aggregates
GET /datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}
```

Storage table ids do not appear in these paths. Filters are allowed only when declared under the entity's `api.allowed_filters`. Arbitrary SQL is not exposed.

`GET /docs` serves a local Scalar API reference shell. The shell is public, but it contains no catalog data by itself. It asks for a bearer token and then fetches the auth-gated `GET /openapi.json` document with that token.

See [docs/api.md](docs/api.md) for scope requirements, query parameters, pagination, `Data-Purpose`, conditional requests, and Problem Details error shapes.

## DCAT-AP And SHACL Validation

The generated `/catalog/dcat-ap.jsonld` document is JSON-LD with embedded entity SHACL node shapes. To validate a saved catalog or a running endpoint with a real SHACL engine:

```sh
just validate-catalog-shacl catalog=target/catalog.dcat-ap.jsonld
uv run --with 'pyshacl>=0.27,<0.31' --with 'rdflib-jsonld>=0.6' \
  python scripts/validate_dcat_shacl.py \
  --catalog http://127.0.0.1:8080/catalog/dcat-ap.jsonld \
  --header "Authorization: Bearer $PROGRAM_SYSTEM_API_KEY"
```

The recipe uses `uv` to run `pyshacl` and the local smoke profile at `tests/fixtures/shacl/dcat-ap-catalog-smoke.ttl`. Pass stricter national or EU DCAT-AP shapes directly to the script when they are available:

```sh
uv run --with 'pyshacl>=0.27,<0.31' --with 'rdflib-jsonld>=0.6' \
  python scripts/validate_dcat_shacl.py \
  --catalog target/catalog.dcat-ap.jsonld \
  --shapes path/to/external-dcat-ap-shapes.ttl
```

For CI jobs that should exercise the external engine from Rust tests, set `REGISTRY_RELAY_RUN_EXTERNAL_SHACL=1` before running `cargo test --test catalog_entity generated_catalog_can_run_external_shacl_validation_when_enabled`.

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

The gateway can return W3C Verifiable Credentials (compact JWS) for verify, aggregate, and entity-record responses. The feature is off by default; enable it by adding a `provenance:` block to the config (see [config/example.yaml](config/example.yaml) for the template). Callers opt in per request with:

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
