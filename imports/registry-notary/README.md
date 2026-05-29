# Registry Notary

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Standalone Registry Notary workspace, claim evaluation, federated delegated
evaluation, credential issuance, and attestation service.

This repository owns claim configuration, claim evaluation, disclosure policy,
Registry Notary API routes, credential issuance primitives, static-peer
federation, HTTP source connectors, fail-closed API key and bearer-token auth,
and redacted audit event emission. Registry Relay or Registry Manifest may
publish metadata that points to a Registry Notary, but Registry Notary does
not import or link Registry Relay code.

## Layout

- [`crates/registry-notary-core`](crates/registry-notary-core/README.md):
  portable Registry Notary domain, config, auth, audit, request, response, and
  SD-JWT VC contracts.
- [`crates/registry-notary-server`](crates/registry-notary-server/README.md):
  Axum routes, runtime evaluation, renderers, credential issuance wiring, HTTP
  Registry Data API and DCI source connectors, auth middleware, audit emission,
  and standalone app assembly.
- [`crates/registry-notary-bin`](crates/registry-notary-bin/README.md):
  process startup, config loading, bind address, tracing, graceful shutdown, and
  OpenAPI generation.
- [`crates/registry-notary-openfn-sidecar`](crates/registry-notary-openfn-sidecar/README.md):
  synchronous Registry Data API-shaped sidecar for running pinned OpenFn adaptor
  jobs behind Registry Notary source lookups.
- `demo/config/registry-notary.yaml`: split demo config used by
  `registry-relay`'s narrated Registry Notary walkthrough.
- [`docs/openspp-disability-dci.md`](docs/openspp-disability-dci.md):
  OpenSPP Disability Registry DCI demo backend setup, known interop boundaries,
  and demo SD-JWT VC caveats.
- [`docs/opencrvs-dci.md`](docs/opencrvs-dci.md):
  OpenCRVS DCI demo setup notes and current interop boundaries.
- [`docs/opencrvs-dci-standalone-tutorial.md`](docs/opencrvs-dci-standalone-tutorial.md):
  standalone quickstart for `init dci`, the explicit OpenCRVS DCI config edits,
  `doctor`, `explain-config`, `--env-file`, source OAuth, and demo SD-JWT VC
  issuance.
- [`docs/opencrvs-dci-setup-simplification-spec.md`](docs/opencrvs-dci-setup-simplification-spec.md):
  implementation-aligned setup simplification spec for the generic env-file,
  source-auth, diagnostics, initializer, API-key hash, and demo issuer
  workflows.
- [`docs/federated-notary-manifest-spec.md`](docs/federated-notary-manifest-spec.md):
  Registry Manifest-backed federation, peer discovery, trust, delegated
  evaluation, credential issuance, and audit checkpoint design.
- [`docs/federated-evaluation-mvp-spec.md`](docs/federated-evaluation-mvp-spec.md):
  first practical federation slice for static-peer, signed delegated
  evaluation.
- [`docs/federated-evaluation-operator-guide.md`](docs/federated-evaluation-operator-guide.md):
  minimal static-peer setup, env vars, replay limitation, and verification
  checklist for the MVP.
- [`docs/notary-scenario-catalog.md`](docs/notary-scenario-catalog.md):
  scenario catalog for where Notary helps, who is involved, current support
  status, and the gaps surfaced by local evaluation, federation, proof, issuance,
  and audit workflows.

## Credential Conformance

Registry Notary currently issues SD-JWT VC credentials using
`application/dc+sd-jwt`, EdDSA over Ed25519 issuer keys, and `did:jwk` holder
binding. Credential profiles default to a short-lived 600-second validity when
`validity_seconds` is omitted, and explicit values remain bounded by the
self-attestation token policy ceiling. The supported wire contract and explicit
non-support list are defined in
[`docs/sd-jwt-vc-conformance-profile.md`](docs/sd-jwt-vc-conformance-profile.md).

## Federated Evaluation

Registry Notary includes a first federation slice for static-peer delegated
evaluation. When `federation.enabled` is true, the standalone router mounts:

```text
POST /federation/v1/evaluations
```

The endpoint accepts a compact JWS request with
`typ = registry-notary-request+jwt`, verifies the trusted peer and local
policy before any source read, evaluates one configured profile, emits audit,
and returns a compact JWS response with
`typ = registry-notary-response+jwt`.

The MVP is deliberately scoped to delegated evaluation. It does not implement
open federation, dynamic trust chains, audit checkpoint exchange, or federated
credential issuance. See
[`docs/federated-evaluation-mvp-spec.md`](docs/federated-evaluation-mvp-spec.md)
and
[`docs/federated-evaluation-operator-guide.md`](docs/federated-evaluation-operator-guide.md)
for the wire profile, config shape, replay limitation, and rollout checklist.

## Replay Store

Replay protection for federation request JWTs, OID4VCI nonces, and holder proof
JWTs is configured under the top-level `replay` block. The default store is
single-process memory:

```yaml
replay:
  storage: in_memory
```

`in_memory` is safe only for a single running Notary process because replayed
identifiers are not shared across processes. Active-active deployments should
use Redis:

```yaml
replay:
  storage: redis
  redis:
    url_env: REGISTRY_NOTARY_REPLAY_REDIS_URL
    key_prefix: registry-notary
    connect_timeout_ms: 1000
    operation_timeout_ms: 500
```

Replay storage is implemented through `registry-platform-replay`, which layers
replay and consumable nonce semantics over `registry-platform-cache`. Redis keys
hash replay scope and one-time identifiers before storage, keeping peer ids,
subjects, holders, nonces, and JWT `jti` values out of backend keys.

## Credential Lifecycle

Registry Notary issues holder-bound SD-JWT VC credentials with short lifetimes
from each credential profile's `validity_seconds`. Profiles default to 600
seconds when `validity_seconds` is omitted. The default posture is status-free:
issued credentials do not include credential status, revocation lists, or
lifecycle callbacks.

Operators can enable a storage-backed status endpoint with
`credential_status.enabled = true`. When enabled, issued SD-JWT VC payloads
include a `status` claim whose `statusUrl` points to
`/credentials/status/{credential_id}`. The backing store can be in-memory for
lab deployments or Redis for deployable multi-process instances:

```yaml
credential_status:
  enabled: true
  base_url: https://issuer.example
  storage: redis
  retention_seconds: 86400
  redis:
    url_env: REGISTRY_NOTARY_STATUS_REDIS_URL
    key_prefix: registry-notary
```

The public status endpoint returns `valid`, `suspended`, `revoked`, or derived
`expired`. Operators update mutable states through
`POST /admin/credentials/status/{credential_id}` with the
`registry_notary:admin` scope. Status records intentionally contain no subject
ids, holder keys, claim values, SD-JWT disclosures, or source rows.

## Metrics

The Prometheus metrics surface is `/metrics`. Metrics are intended to be safe to
scrape and must use low-cardinality labels only, such as route, method, outcome,
status class, profile, and source id. Labels must not contain subject ids,
principal ids, holder material, tokens, source rows, request ids, correlation
ids, SD-JWT disclosures, or raw error details. Keep the endpoint behind the
deployment's normal network and scrape controls even though the metric content
is designed to avoid secrets and personal data.

## Local Run

```bash
export REGISTRY_NOTARY_API_KEY_HASH=sha256:ca2b7917b5d2bdc05d445ce8d50c3adad19ac355d6d40ede18b1f341d7c6e546
export REGISTRY_NOTARY_BEARER_TOKEN_HASH=sha256:f2721a9dae064d1fdbc74cae1fb1baf26fac01b8aac160ae5acab97c35667d7f
export REGISTRY_NOTARY_AUDIT_HASH_SECRET=dev-registry-notary-audit-hash-secret
export EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN=dev-source-token
export REGISTRY_NOTARY_ISSUER_JWK='{"kty":"OKP","crv":"Ed25519","d":"...","x":"...","alg":"EdDSA"}'
cargo run -p registry-notary-bin -- --config demo/config/registry-notary.yaml
```

Config-aware commands and server startup also accept `--env-file` for
env-backed local runs:

```bash
cargo run -p registry-notary-bin -- \
  --config demo/config/registry-notary.yaml \
  --env-file .env.local
```

The demo config uses HTTP source connections, so claim evaluation requires a
source service at the configured `base_url`. The binary still starts fail-closed:
no Registry Notary route is served without a configured API key or bearer token.

## Audit Sink Configuration

Registry Notary emits redacted, tamper-evident audit envelopes. Configure the
audit destination under `audit` and provide a stable HMAC secret through
`hash_secret_env`:

```yaml
audit:
  sink: file
  path: /var/log/registry-notary/audit.jsonl
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
  max_size_bytes: 10485760
  max_files: 5
```

Supported sink values:

- `stdout`: writes one JSON audit envelope per line to process stdout. Use this
  when a container runtime or process supervisor owns log collection.
- `file` or `jsonl`: writes JSONL envelopes to `path`. `max_size_bytes` enables
  byte-based rotation and `max_files` controls retained files, including the
  active file. Set `max_size_bytes: 0` to disable in-process rotation.
- `syslog`: writes JSONL envelopes as RFC 5424 messages to the local syslog Unix
  datagram socket. Use `syslog_socket_path` when the deployment socket differs
  from the platform default.

`REGISTRY_NOTARY_AUDIT_HASH_SECRET` must contain a high-entropy deployment
secret. Registry Notary fails closed when the variable named by
`hash_secret_env` is missing, and uses it to HMAC identifiers before they enter
the audit envelope. Keep the secret stable for correlation across records; rotate
it only with an audit-retention plan.

Each envelope links to the previous envelope through `prev_hash` and exposes its
own `record_hash`. For file/jsonl sinks, startup resumes from the retained tail
hash. For stdout, syslog, or rotated-file retention windows, publish external
anchors for the retained head and tail hashes in storage the audit writer cannot
rewrite. Verification should check both the trusted starting `prev_hash` for a
retained suffix and the trusted final `record_hash` for the period under review.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p registry-notary-server --no-default-features
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo run -p registry-notary-bin -- openapi > target/registry-notary.openapi.json
```

Registry Notary depends on sibling `../registry-platform` path crates. CI checks
out `registry-platform` at `REGISTRY_PLATFORM_REF` beside this repository before
running Cargo jobs. Private platform checkouts require a repository secret named
`REGISTRY_PLATFORM_TOKEN`.

CEL is enabled by default through the `registry-notary-cel` feature and is
implemented through the local `crosswalk-core` crate at
`../cel-mapping/crates/crosswalk-core`.

## Docker

The Docker build also needs the sibling platform workspace. Build with Docker
BuildKit and pass `../registry-platform` as a named context:

```bash
docker build --build-context registry-platform=../registry-platform -t registry-notary .
```

## OpenAPI

Registry Notary owns its OpenAPI output. Generate the current document with:

```bash
cargo run -p registry-notary-bin -- openapi
```

## Distribution

The workspace crates are not published to crates.io. Consumers should use the
Docker image or a pinned git tag/revision.

## Security

Report vulnerabilities through GitHub Security Advisories. See
[`SECURITY.md`](SECURITY.md) for scope and acknowledgement expectations.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
