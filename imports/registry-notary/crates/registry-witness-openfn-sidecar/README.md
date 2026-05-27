# Registry Witness OpenFn Sidecar

This crate exposes a synchronous Registry Data API-shaped source endpoint backed
by a bounded pool of long-lived worker processes. The first intended worker
implementation is a pinned OpenFn adaptor runner, but the Rust sidecar owns the
HTTP contract, manifest validation, concurrency limits, timeouts, normalization,
health checks, and credential non-disclosure boundary.

Registry Witness should connect to this sidecar with its existing
`registry_data_api` connector:

```text
GET /datasets/{dataset}/{entity}?{lookup_field}={lookup_value}&fields=a,b&limit=2
Authorization: Bearer <witness-to-sidecar-token>
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

The sidecar returns at most two records so Registry Witness can preserve its
existing exact, not found, and ambiguous-source behavior.

## Manifest

```yaml
server:
  bind: "127.0.0.1:9191"
auth:
  bearer_tokens:
    - id: witness
      hash_env: DEV_SIDECAR_TOKEN_HASH
limits:
  max_workers: 4
  worker_timeout_ms: 10000
  max_worker_memory_mb: 512
  max_output_bytes: 1048576
  max_request_bytes: 16384
  max_query_parameter_bytes: 1024
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
    workflow:
      start: prepare_request
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
`hash_env`, expression files exist, credentials are present as JSON in
`credential_env`, configured credential `baseUrl` values match
`allowed_base_urls` when present, the worker version output contains the exact
configured OpenFn compiler/build tool, runtime, and adaptor pins, and every
source has a smoke lookup that can execute. `auth.bearer_tokens[].token` is
rejected; keep the raw sidecar bearer in the caller's secret store and expose
only its `sha256:<hex>` fingerprint through the configured `hash_env`. Runtime
execution must not fetch packages from the network.

The worker reports adaptor pins as
`@openfn/language-http@7.2.0:7.2.0=/path/to/package`. The sidecar verifies that
the configured adaptor specifier is present and that the installed package
version exactly matches the configured pin.

The production worker script is [workers/openfn_worker.mjs](workers/openfn_worker.mjs).
Install its pinned dependencies from [workers/package.json](workers/package.json)
inside the sidecar image and preinstall each configured adaptor in the same
Node package root. Each source uses a `workflow.steps` plan for an OpenFn runtime
workflow. Workflow steps use the OpenFn runtime `next` edge map, including
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

```bash
export OPENCRVS_READER_CREDENTIAL_JSON='{"baseUrl":"https://example.test","apiToken":"dev"}'
export DEV_SIDECAR_TOKEN_HASH='sha256:a61cb2a28977890d2e95d2eb9f5355b184d48dc2aec23252bdeb08eca7f42544'
REGISTRY_WITNESS_OPENFN_SIDECAR_CONFIG=/path/to/sidecar.yaml \
  cargo run -p registry-witness-openfn-sidecar -- --config /path/to/sidecar.yaml
```

The example hash above is the SHA-256 fingerprint for the demo bearer
`dev-sidecar-token`. For a new local token:

```bash
python3 - <<'PY'
import hashlib
token = "replace-with-local-token"
print("sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest())
PY
```

To try the full HTTP adaptor path locally:

```bash
crates/registry-witness-openfn-sidecar/scripts/run-openfn-http-demo.sh start

curl -sS \
  -H "Authorization: Bearer dev-sidecar-token" \
  -H "Data-Purpose: demo" \
  "http://127.0.0.1:19191/datasets/civil_registry/civil_person?national_id=person-123&fields=national_id,birth_date&limit=2" | jq

crates/registry-witness-openfn-sidecar/scripts/run-openfn-http-demo.sh stop
```

The sidecar is intended for localhost or private pod-network traffic from
Registry Witness. Do not expose it publicly. Its outbound target access should
also be constrained by deployment networking, for example Kubernetes network
policy or an internal Docker network. `allowed_base_urls` validates configured
credential targets at startup, but it is not a general JavaScript egress
sandbox. The sidecar provides:

- `/datasets/{dataset}/{entity}` for synchronous RDA lookups.
- `/ready` for startup readiness after manifest, credential, version, worker,
  and smoke checks.
- `/healthz` for process liveness while requests are arriving.
- `/metrics` for Prometheus text metrics without lookup values or credentials.

## Verification

The focused sidecar checks are:

```bash
cargo test -p registry-witness-openfn-sidecar
cargo clippy -p registry-witness-openfn-sidecar --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build -p registry-witness-openfn-sidecar
crates/registry-witness-openfn-sidecar/scripts/smoke-openfn-worker.sh
crates/registry-witness-openfn-sidecar/scripts/smoke-openfn-sidecar.sh
crates/registry-witness-openfn-sidecar/scripts/smoke-openfn-http-sidecar.sh
```
