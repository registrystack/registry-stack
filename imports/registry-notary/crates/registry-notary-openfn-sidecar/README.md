# Registry Notary Source Adapter Sidecar

This crate exposes a synchronous Registry Data API-shaped source endpoint. A
source can run through the pinned OpenFn worker pool or through the built-in
`http_json` adapter for straightforward HTTP JSON registries. In both cases the
Rust sidecar owns the HTTP contract, manifest validation, concurrency limits,
timeouts, normalization, health checks, and credential non-disclosure boundary.

Registry Notary should connect to this sidecar with the `openfn_sidecar`
source connector:

```text
GET /v1/datasets/{dataset}/entities/{entity}/records?{lookup_field}={lookup_value}&fields=a,b&limit=2
Authorization: Bearer <notary-to-sidecar-token>
Data-Purpose: <purpose>
```

Successful responses always use the Registry Data API shape:

```json
{ "data": [] }
```

or:

```json
{ "data": [{ "field": "value" }] }
```

The sidecar returns at most two records so Registry Notary can preserve its
existing exact, not found, and ambiguous-source behavior.

## Governed Configuration

Production deployments start the sidecar from a governed TUF target. The
default startup loader rejects YAML without `config_trust`; legacy unsigned
manifests require the explicit `--allow-unsigned-dev-config` local-development
escape hatch. In governed mode the local YAML contains only listener/auth
bootstrap plus `config_trust`; workflow runtime material lives in the signed
target.

```yaml
server:
  bind: "127.0.0.1:9191"
  request_timeout_ms: 30000
  request_body_timeout_ms: 10000
  http1_header_read_timeout_ms: 10000
  max_connections: 1024
auth:
  bearer_tokens:
    - id: notary
      hash_env: OPENFN_SIDECAR_TOKEN_HASH
config_trust:
  product: registry-notary-openfn-sidecar
  instance_id: demo
  environment: staging
  stream_id: openfn-sidecar-runtime
  root_path: /etc/registry-notary-openfn-sidecar/tuf/root.json
  metadata_dir: /etc/registry-notary-openfn-sidecar/tuf/metadata
  targets_dir: /etc/registry-notary-openfn-sidecar/tuf/targets
  datastore_dir: /var/lib/registry-notary-openfn-sidecar/tuf
  target_name: openfn-sidecar-runtime.json
  antirollback_state_path: /var/lib/registry-notary-openfn-sidecar/config-trust/antirollback.json
  accepted_roots: []
```

`accepted_roots: []` is intentionally incomplete. Real production bootstrap
must list the trusted TUF root, accepted signer keys, roles, thresholds, and
allowed change classes. Startup fails closed if the target is not verified,
authorized, bound to the configured product/instance/environment/stream, marked
`restart_required`, or accepted by anti-rollback after runtime checks pass.

The signed target uses schema `registry.notary.openfn_sidecar.runtime.v1` and
always contains `limits` and `sources`. It contains `openfn`, `worker`, and
`jobs_root` only when at least one source uses `engine: openfn`; `http_json`-only
targets omit the worker runtime fields. In governed mode every OpenFn workflow
expression path is relative to `jobs_root` and every OpenFn step must include
`expression_sha256`. Absolute paths, `..` traversal, symlink escapes, missing
files, malformed hashes, and hash mismatches fail startup before the HTTP
listener serves traffic.

The sidecar exposes `GET /v1/assurance` with the verified product identity,
TUF versions, signer kids, change classes, and `config_hash`. `GET /ready`
stays compact and includes only readiness status, `config_hash`, and the key
verification booleans. Neither endpoint includes target credentials, workflow
contents, raw smoke lookup payloads, or environment details.

Release helpers render, locally sign, and verify governed runtime material:

```bash
cargo run -p registry-notary-openfn-sidecar -- \
  config render-target \
  --manifest /path/to/openfn-sidecar.yaml \
  --jobs-root /opt/openfn/jobs \
  --output /tmp/openfn-sidecar-runtime.json

cargo run -p registry-notary-openfn-sidecar -- \
  config print-expression-hashes \
  --target /tmp/openfn-sidecar-runtime.json

cargo run -p registry-notary-openfn-sidecar -- \
  config verify-bundle \
  --target /tmp/openfn-sidecar-runtime.json
```

For local demos and release rehearsal, create a signed local TUF repository from
the rendered target. This helper uses the supplied root and signing key. It is
not a substitute for production key custody or approval workflow.

```bash
cargo run -p registry-notary-openfn-sidecar -- \
  config create-local-tuf-repo \
  --target /tmp/openfn-sidecar-runtime.json \
  --target-name openfn-sidecar-runtime.json \
  --root-path /path/to/tuf/root.json \
  --signing-key-path /path/to/tuf/targets-signing-key.pem \
  --metadata-dir /tmp/openfn-sidecar-tuf/metadata \
  --targets-dir /tmp/openfn-sidecar-tuf/targets \
  --product registry-notary-openfn-sidecar \
  --instance-id demo \
  --environment staging \
  --stream-id openfn-sidecar-runtime \
  --bundle-id opencrvs-sidecar-2026-06-09 \
  --sequence 1 \
  --previous-config-hash sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --change-class openfn_sidecar_workflow_bundle \
  --declared-signer-kid local-demo-signer
```

To verify an already signed local TUF repository, omit `--target` and provide
the local TUF coordinates plus the expected identity:

```bash
cargo run -p registry-notary-openfn-sidecar -- \
  config verify-bundle \
  --product registry-notary-openfn-sidecar \
  --instance-id demo \
  --environment staging \
  --stream-id openfn-sidecar-runtime \
  --root-path /etc/registry-notary-openfn-sidecar/tuf/root.json \
  --metadata-dir /etc/registry-notary-openfn-sidecar/tuf/metadata \
  --targets-dir /etc/registry-notary-openfn-sidecar/tuf/targets \
  --datastore-dir /var/lib/registry-notary-openfn-sidecar/tuf \
  --target-name openfn-sidecar-runtime.json
```

The verification report includes the target `config_hash`, expression hashes,
and, for local TUF verification, signer kids, change classes, and TUF metadata
versions.

Registry Notary pins the expected sidecar state in the source connection:

```yaml
source_connections:
  openfn_crvs:
    base_url: http://127.0.0.1:9191
    token_env: OPENFN_SIDECAR_TOKEN
    allow_insecure_localhost: true
    expected_sidecar:
      product: registry-notary-openfn-sidecar
      instance_id: demo
      environment: staging
      stream_id: openfn-sidecar-runtime
      config_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
      require_expression_hashes_verified: true
      require_runtime_verified: true
      require_smoke_verified: true
```

Notary refreshes expected sidecar assurance through readiness checks and caches
the observed assurance for a short TTL. Source reads reject mismatched
assurance and include the observed sidecar config hash in redacted audit
context. This assurance is self-attested by the trusted private sidecar; it
does not protect against a sidecar that can forge responses on the private
listener.

## Manifest

```yaml
server:
  bind: "127.0.0.1:9191"
  request_timeout_ms: 30000
  request_body_timeout_ms: 10000
  http1_header_read_timeout_ms: 10000
  max_connections: 1024
auth:
  bearer_tokens:
    - id: notary
      hash_env: DEV_SIDECAR_TOKEN_HASH
limits:
  max_workers: 4
  worker_timeout_ms: 10000
  max_worker_memory_mb: 512
  max_output_bytes: 1048576
  max_request_bytes: 16384
  max_query_parameter_bytes: 1024
  max_batch_items: 100
  batch_timeout_ms: 30000
  liveness_window_ms: 30000
  retry_after_seconds: 1
openfn:
  cli_build_tool: "1.2.5"
  runtime: "1.9.3"
worker:
  command: "node"
  args:
    - "--experimental-vm-modules"
    - "/opt/openfn/openfn_worker.mjs"
  version_args:
    - "--experimental-vm-modules"
    - "/opt/openfn/openfn_worker.mjs"
    - "--version"
    - "--require-adaptor"
    - "@openfn/language-common@3.2.3"
    - "--require-adaptor"
    - "@openfn/language-http@7.2.0"
sources:
  openfn_crvs:
    dataset: civil_registry
    entity: civil_person
    batch:
      mode: sequential_lookup
    limits:
      max_in_flight: 2
    workflow:
      start: prepare_request
      batch_mode: per_item
      steps:
        - id: prepare_request
          expression: /opt/openfn/jobs/prepare-person-request.js
          adaptors:
            - "@openfn/language-common@3.2.3"
          next:
            fetch_person: true
        - id: fetch_person
          expression: /opt/openfn/jobs/fetch-person.js
          adaptors:
            - "@openfn/language-http@7.2.0"
          next:
            normalize_response: true
        - id: normalize_response
          expression: /opt/openfn/jobs/normalize-person-response.js
          adaptors:
            - "@openfn/language-common@3.2.3"
    credential_env: OPENCRVS_READER_CREDENTIAL_JSON
    allowed_base_urls:
      - https://example.test
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields: ["national_id"]
      purpose: startup-readiness-smoke
```

At startup the sidecar checks that bearer-token fingerprints are loaded from
`hash_env`, credentials are present as JSON in `credential_env`, configured
credential `baseUrl` values match `allowed_base_urls` when present, and every
source has a smoke lookup that can execute. For OpenFn sources it also verifies
that expression files exist and that the worker version output contains the
exact configured OpenFn compiler/build tool, runtime, and adaptor pins.
`auth.bearer_tokens[].token` is rejected; keep the raw sidecar bearer in the
caller's secret store and expose only its `sha256:<hex>` fingerprint through the
configured `hash_env`. Runtime execution must not fetch packages from the
network.

The worker reports adaptor pins as
`@openfn/language-http@7.2.0:7.2.0=/path/to/package`. The sidecar verifies that
the configured adaptor specifier is present and that the installed package
version exactly matches the configured pin.

The production worker script is [workers/openfn_worker.mjs](workers/openfn_worker.mjs).
Install its pinned dependencies from [workers/package.json](workers/package.json)
inside the sidecar image and preinstall each configured adaptor in the same
Node package root. The image includes the local
`@registry/notary-openfn` adaptor package from
[workers/adaptors/registry-notary](workers/adaptors/registry-notary). Use it in
OpenFn jobs when authors should work with Registry Notary concepts instead of
the sidecar wire format. It exposes helpers such as `assertNotaryRequest`,
`lookup`, `requestedFields`, `returnRecords`, `assertBatchRequest`,
`batchItems`, `batchItemLookup`, and `returnBatchItems`, and re-exports
`fn` from `@openfn/language-common` for simple jobs.

Each source uses a `workflow.steps` plan for an OpenFn runtime workflow.
Workflow steps use the OpenFn runtime `next` edge map, including
boolean and conditional edges. Linear flows and mutually exclusive branches are
supported when each lookup produces exactly one final leaf state. Join/merge
aggregation is not automatic: Lightning-style merge runs the target once per
incoming path, so aggregation must be encoded in a normal OpenFn step. The
pinned runtime does not support merge nodes, and the sidecar still requires a
single final state that normalizes to one RDA `data` array. A runnable
local manifest is available at
[examples/openfn-sidecar.yaml](examples/openfn-sidecar.yaml), backed by a
three-step fixture workflow in [examples/jobs](examples/jobs). There is also a
three-step HTTP adaptor sample workflow using
[examples/jobs/http-prepare-person-request.js](examples/jobs/http-prepare-person-request.js),
[examples/jobs/http-fetch-person.js](examples/jobs/http-fetch-person.js), and
[examples/jobs/http-normalize-person-response.js](examples/jobs/http-normalize-person-response.js),
which can be run against the local mock registry in
[examples/mock-registry-server.mjs](examples/mock-registry-server.mjs).
The worker compiles the configured OpenFn workflow steps, injects
`state.configuration` from the Rust sidecar request, runs the plan with
`@openfn/runtime`, and returns only an RDA-shaped `{ "data": [...] }` envelope
to the Rust HTTP boundary.

### Built-In HTTP JSON Adapter

Use `engine: http_json` when a registry can be queried with a governed HTTP
request and a small CEL mapping. This avoids a worker process for simple
endpoints while keeping the same Notary-facing RDA route, bearer auth, source
concurrency limit, startup smoke lookup, metrics, and governed config path.

```yaml
sources:
  people_registry:
    engine: http_json
    dataset: civil_registry
    entity: civil_person
    credential_env: PEOPLE_REGISTRY_CREDENTIAL_JSON
    credential_public_fields:
      - baseUrl
      - clientId
    allowed_base_urls:
      - https://registry.example.test
    http_json:
      method: GET
      base_url:
        cel: credential_public.baseUrl
      path: /people
      query:
        id:
          cel: lookup.value
      headers:
        x-client-id:
          cel: credential_public.clientId
      auth:
        type: bearer
        token:
          secret: apiToken
      response:
        records:
          cel: body.results
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields: ["national_id"]
      purpose: startup-readiness-smoke
```

Only fields listed in `credential_public_fields` are available to CEL as
`credential_public`. Secret material remains available only to explicit adapter
secret references such as `http_json.auth.token.secret`,
`http_json.auth.username.secret`, and `http_json.auth.password.secret`. Supported
HTTP auth modes are `bearer` and `basic`; both read secret values from the
sidecar credential, not from CEL. The adapter rejects a base URL that is not in
`allowed_base_urls`, does not follow redirects, rejects plaintext HTTP to public
hosts or public IP literals, and blocks loopback, private, link-local, and cloud
metadata addresses unless the source opts into the matching development escape
hatch. The private-network escape hatch still blocks cloud metadata addresses.
When `base_url` includes a path prefix, such as a versioned DHIS2 play URL, the
configured `path` is appended under that prefix; protocol-relative paths and
`.`/`..` path segments are rejected before dispatch. The sidecar reuses a
bounded `reqwest` client per source/base URL after the URL policy and DNS/IP
checks pass, so steady-state reads can reuse TLS connections without relaxing
redirect, timeout, or DNS pinning behavior.

### Batch And Backpressure

The sidecar exposes the RDA batch shape at:

```text
POST /v1/datasets/{dataset}/entities/{entity}/records:batchMatch
```

Source batch behavior is explicit:

- `batch_mode: per_item` in the source workflow, or request-level
  `batch.mode: sequential_lookup`, is the default compatibility mode. The
  sidecar sends one batch worker request, but the worker runs the configured
  lookup workflow once per item. This reduces HTTP chatter between Notary and
  the sidecar, but it does not reduce calls to the upstream registry.
- `batch_mode: native` in the source workflow, or request-level
  `batch.mode: workflow_batch`, runs the configured OpenFn workflow once with
  the full batch in `state.data.items` and the query signature in
  `state.data.query_signature`. Use this only for source jobs that intentionally
  translate a batch into a backend-supported bulk API, for example a target
  search endpoint or bulk read endpoint. A workflow that still loops and calls
  the target once per item is not a real upstream batch optimization. Native
  workflows should usually return through `returnBatchItems` from
  `@registry/notary-openfn`.
- `batch.mode: parallel_lookup` is available for `engine: http_json` sources and
  runs per-item lookups concurrently up to `batch.max_parallel`. It is opt-in
  because it can increase upstream pressure.
- `batch.mode: native_batch` is available for `engine: http_json` sources that
  expose a real bulk endpoint. Configure `http_json.batch.response.record_key`
  and `item_key` CEL expressions to fan response records back to request items.
  Unknown response keys are ignored; multiple records for one requested key are
  returned for that item and then normalized by the existing cardinality rules.

Each source can also set `limits.max_in_flight`. When all permits for that source
are in use, the sidecar returns `503` with `Retry-After` before dispatching a
worker request. This is separate from the global worker pool size and is intended
to protect slower upstreams such as DHIS2, CRVS, or facility registries from one
Notary batch consuming all local worker capacity or exceeding the target system's
safe rate.

For target protection over time, a source can set
`limits.requests_per_second` and optional `limits.burst`. These are enforced at
the upstream dispatch boundary for `http_json`; cache hits do not spend rate
tokens. When a target returns `429`, the sidecar remembers the returned
`Retry-After` window per source and fails fast with `source.target_rate_limit`
until the window expires.

`limits.batch_timeout_ms` is an optional whole-batch deadline. If it is unset,
the sidecar computes the batch deadline as `worker_timeout_ms * item_count`; if
it is set, the lower of the configured value and the computed value is used.
Timeouts return `504` with code `source.timeout`.

Result caching is disabled by default. A source may explicitly configure
`cache.exact_match_ttl_ms` and/or `cache.not_found_ttl_ms`; only exact one-record
results and not-found empty arrays are cached. Cache keys include the source id,
source config hash, dataset, entity, lookup, requested fields, limit, and
purpose. Cache metrics expose only `source_id` and low-cardinality outcomes.

The `/metrics` endpoint reports worker capacity plus per-source outcomes,
duration totals, and item totals:

```text
registry_notary_openfn_sidecar_lookup_total{source_id="openfn_crvs",outcome="batch_success"} 1
registry_notary_openfn_sidecar_lookup_items_total{source_id="openfn_crvs",outcome="batch_success"} 3
registry_notary_openfn_sidecar_source_permits{source_id="openfn_crvs",state="in_flight"} 0
registry_notary_openfn_sidecar_http_json_clients{source_id="http_people"} 1
```

Metrics labels intentionally include only `source_id` and outcome. They must not
include credentials, lookup values, correlation IDs, or target URLs.

The smoke fixture
[examples/jobs/registry-notary-native-batch-person-lookup.js](examples/jobs/registry-notary-native-batch-person-lookup.js)
shows native batch authoring with `@registry/notary-openfn`.

## Worker Protocol

Requests are sent as one JSON value per line over private worker stdin, and each
worker must answer with one JSON value per line on stdout. `state.configuration`
is included in the request JSON and stays inside the sidecar process tree.

A request is executed by at most one worker: failures, invalid output, oversized
output, and timeouts are not retried for the same request. Worker stderr is
drained so a noisy worker cannot block on a full pipe, but only the configured
prefix is retained for diagnostics. Error formatting reports captured byte
counts and truncation state, not captured content.

## Local Run

Unsigned manifests are for local development only. Production startup requires
`config_trust`; use `--allow-unsigned-dev-config` only for these legacy examples
and smoke scripts.

```bash
export OPENCRVS_READER_CREDENTIAL_JSON='{"baseUrl":"https://example.test","apiToken":"dev"}'
export DEV_SIDECAR_TOKEN_HASH='sha256:<sha256-hex-of-your-sidecar-token>'
REGISTRY_NOTARY_OPENFN_SIDECAR_CONFIG=/path/to/sidecar.yaml \
  cargo run -p registry-notary-openfn-sidecar -- \
    --config /path/to/sidecar.yaml \
    --allow-unsigned-dev-config
```

Compute the hash from your sidecar bearer token. The demo uses
`dev-sidecar-token`:

```bash
python3 - <<'PY'
import hashlib
token = "replace-with-local-token"
print("sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest())
PY
```

To try the full HTTP adaptor path locally:

```bash
crates/registry-notary-openfn-sidecar/scripts/run-openfn-http-demo.sh start

curl -sS \
  -H "Authorization: Bearer dev-sidecar-token" \
  -H "Data-Purpose: demo" \
  "http://127.0.0.1:19191/v1/datasets/civil_registry/entities/civil_person/records?national_id=person-123&fields=national_id,birth_date&limit=2" | jq

crates/registry-notary-openfn-sidecar/scripts/run-openfn-http-demo.sh stop
```

The sidecar is intended for localhost or private pod-network traffic from
Registry Notary. Do not expose it publicly. Its outbound target access should
also be constrained by deployment networking, for example Kubernetes network
policy or an internal Docker network. `allowed_base_urls` validates configured
credential targets at startup, but it is not a general JavaScript egress
sandbox. The sidecar provides:

- `/v1/datasets/{dataset}/entities/{entity}/records` for synchronous RDA lookups.
- `/ready` for startup readiness after config, credential, version, worker, and
  smoke checks.
- `/healthz` for process liveness while requests are arriving.
- `/metrics` for Prometheus text metrics without lookup values or credentials.

## Container Image

The repository owns the sidecar image through
[`Dockerfile.openfn-sidecar`](../../Dockerfile.openfn-sidecar). The image
contains the Rust sidecar binary, [workers/openfn_worker.mjs](workers/openfn_worker.mjs),
and the locked Node dependencies from [workers/package-lock.json](workers/package-lock.json).
Deployment-specific job files remain configuration and should be mounted into
the container, for example under `/opt/openfn/jobs`.

```bash
docker build \
  --build-context registry-platform=../registry-platform \
  --build-context crosswalk=../crosswalk \
  -f Dockerfile.openfn-sidecar \
  -t registry-notary-openfn-sidecar .
```

The container healthcheck runs
[scripts/container-healthcheck.mjs](scripts/container-healthcheck.mjs) with
Node's built-in `fetch`, so the image does not need curl. It probes
`http://127.0.0.1:9191/healthz` by default; set
`REGISTRY_NOTARY_OPENFN_SIDECAR_HEALTHCHECK_URL` when the sidecar binds a
different listener.

## Verification

The focused sidecar checks are:

```bash
cargo test -p registry-notary-openfn-sidecar
cargo clippy -p registry-notary-openfn-sidecar --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build -p registry-notary-openfn-sidecar
crates/registry-notary-openfn-sidecar/scripts/smoke-openfn-worker.sh
crates/registry-notary-openfn-sidecar/scripts/smoke-openfn-sidecar.sh
crates/registry-notary-openfn-sidecar/scripts/smoke-openfn-http-sidecar.sh
crates/registry-notary-openfn-sidecar/scripts/smoke-http-json-dhis2-sidecar.sh
crates/registry-notary-openfn-sidecar/scripts/load-http-json-sidecar.sh
```

For repeatable local load checks against the built-in `http_json` engine, run:

```bash
LOAD_HTTP_JSON_REQUESTS=200 \
LOAD_HTTP_JSON_CONCURRENCY=16 \
  crates/registry-notary-openfn-sidecar/scripts/load-http-json-sidecar.sh

LOAD_HTTP_JSON_SCENARIO=batch \
LOAD_HTTP_JSON_BATCH_MODE=parallel_lookup \
LOAD_HTTP_JSON_REQUESTS=100 \
LOAD_HTTP_JSON_BATCH_SIZE=20 \
LOAD_HTTP_JSON_CONCURRENCY=8 \
LOAD_HTTP_JSON_MAX_PARALLEL=4 \
  crates/registry-notary-openfn-sidecar/scripts/load-http-json-sidecar.sh

LOAD_HTTP_JSON_SCENARIO=batch \
LOAD_HTTP_JSON_BATCH_MODE=native_batch \
LOAD_HTTP_JSON_REQUESTS=100 \
LOAD_HTTP_JSON_BATCH_SIZE=20 \
LOAD_HTTP_JSON_CONCURRENCY=8 \
  crates/registry-notary-openfn-sidecar/scripts/load-http-json-sidecar.sh

LOAD_HTTP_JSON_SCENARIO=cache \
LOAD_HTTP_JSON_REQUESTS=200 \
LOAD_HTTP_JSON_CONCURRENCY=16 \
  crates/registry-notary-openfn-sidecar/scripts/load-http-json-sidecar.sh
```

Set `LOAD_HTTP_JSON_RELEASE=1` for capacity baselines. Without it the harness
runs the sidecar through Cargo's debug profile, which is useful for fast local
iteration but not for performance numbers.

The load harness starts a synthetic upstream and sidecar, writes a JSON report
under `target/http-json-sidecar-load-*`, captures sidecar metrics and upstream
stats, and fails when status validation, leak checks, error-rate thresholds, or
`LOAD_HTTP_JSON_MAX_P95_MS` fail. It is a local regression harness, not a
substitute for environment-specific capacity tests with production network
limits and a source-owner-approved request rate.

For a live target canary against the DHIS2 play server, run:

```bash
HTTP_JSON_DHIS2_PASSWORD=... \
  crates/registry-notary-openfn-sidecar/scripts/smoke-http-json-dhis2-sidecar.sh

OPENFN_DHIS2_PASSWORD=... \
  crates/registry-notary-openfn-sidecar/scripts/smoke-openfn-dhis2-sidecar.sh
```

The http_json and OpenFn DHIS2 canaries default to the public play instance URL
and username. For local runs, provide the matching password environment variable
and override `HTTP_JSON_DHIS2_HOST_URL` / `HTTP_JSON_DHIS2_USERNAME` or
`OPENFN_DHIS2_HOST_URL` / `OPENFN_DHIS2_USERNAME` when needed. The OpenFn canary
is also available as the manual `OpenFn DHIS2 Canary` GitHub Actions workflow,
where the password is read from the `OPENFN_DHIS2_PASSWORD` repository secret
and the target host and username are fixed by the workflow.
