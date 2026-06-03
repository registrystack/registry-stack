# Registry Notary

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Release label: pre-1.0 technical release for evaluation and integration pilots.

Standalone Registry Notary workspace, claim evaluation, federated delegated
evaluation, credential issuance, and attestation service.

This repository owns claim configuration, claim evaluation, disclosure policy,
Registry Notary API routes, credential issuance primitives, static-peer
federation, HTTP source connectors, fail-closed API key and bearer-token auth,
and redacted audit event emission. Registry Relay or Registry Manifest may
publish metadata that points to a Registry Notary, but Registry Notary does
not import or link Registry Relay code.

Shared security and operations primitives come from sibling
`registry-platform-*` crates, including audit envelopes, auth common code,
cache/replay stores, HTTP security helpers, OIDC, OpenID4VCI, and SD-JWT
support.

## Layout

- [`crates/registry-notary-core`](crates/registry-notary-core/README.md):
  portable Registry Notary domain, config, auth, audit, request, response, and
  SD-JWT VC contracts.
- [`crates/registry-notary-server`](crates/registry-notary-server/README.md):
  Axum routes, runtime evaluation, renderers, credential issuance wiring, HTTP
  Registry Data API and DCI source connectors, auth middleware, audit emission,
  and standalone app assembly.
- [`crates/registry-notary-client`](crates/registry-notary-client/README.md):
  typed Rust HTTP client, JSON facade, route-aware retry, bounded response
  reads, JWKS refresh, and redacted errors.
- [`crates/registry-notary-bin`](crates/registry-notary-bin/README.md):
  process startup, config loading, bind address, tracing, graceful shutdown, and
  OpenAPI generation.
- [`crates/registry-notary-openfn-sidecar`](crates/registry-notary-openfn-sidecar/README.md):
  synchronous Registry Data API-shaped sidecar for running pinned OpenFn adaptor
  jobs behind Registry Notary source lookups.
- [`bindings/python`](bindings/python): `registry-notary` sync and async
  dictionary-friendly Python wrapper.
- [`bindings/node`](bindings/node): `@registry-notary/client` Promise client
  with TypeScript declarations.
- [`docs/`](docs/README.md): guides, tutorials, and references for integrators,
  operators, and maintainers, sorted by reader. Demo configs live in
  `demo/config/`.
- [`specs/`](specs/README.md): design specifications and implementation traces for
  self-attestation, static-peer federation, manifest-backed federation,
  the `/v1` REST route cleanup, OpenID4VCI wallet facade, OpenFn sidecar source
  integration, and scalability.

## Credential Conformance

Registry Notary currently issues SD-JWT VC credentials using
`application/dc+sd-jwt`, EdDSA over named Ed25519 signing keys, and `did:jwk`
holder binding. Credential profiles reference keys from `evidence.signing_keys`
instead of carrying key material themselves. Local JWK keys support development
and mounted-secret deployments; PKCS#11 keys are available behind the optional
server feature for HSM-backed signing. Credential profiles default to a
short-lived 600-second validity when `validity_seconds` is omitted, and explicit
values remain bounded by `evidence.max_credential_validity_seconds`.
Self-attestation credential profiles are additionally bounded by
`self_attestation.token_policy.max_credential_validity_seconds`.

The supported wire contract and explicit non-support list are defined in
[`docs/sd-jwt-vc-conformance-profile.md`](docs/sd-jwt-vc-conformance-profile.md).
Signing key configuration and rotation are covered in
[`docs/signing-key-provider.md`](docs/signing-key-provider.md).

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
[`specs/federated-evaluation-mvp-spec.md`](specs/federated-evaluation-mvp-spec.md)
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
`/v1/credentials/{credential_id}/status`. The backing store can be in-memory for
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
`POST /admin/v1/credentials/{credential_id}/status` with the
`registry_notary:admin` scope. Status records intentionally contain no subject
ids, holder keys, claim values, SD-JWT disclosures, or source rows.

## Metrics

The Prometheus metrics surface is `/metrics`. Metrics are intended to be safe to
scrape and must use low-cardinality labels only, such as route, method, outcome,
status class, profile, and source id. Labels must not contain subject ids,
principal ids, holder material, tokens, source rows, request ids, correlation
ids, SD-JWT disclosures, or raw error details. The endpoint requires an
authenticated principal with the `registry_notary:admin` scope; configure
Prometheus scrape jobs to send an admin credential. Static-auth deployments can
use an admin bearer token or an admin API key in `x-api-key`; OIDC deployments
can use a token whose mapped scopes include `registry_notary:admin`. An
internal-only listener/proxy is defense in depth only and must still forward or
inject a valid admin credential. Keep the endpoint behind the deployment's
normal network and scrape controls even though the metric content is designed
to avoid secrets and personal data.

Example Prometheus scrape shape:

```yaml
scrape_configs:
  - job_name: registry-notary
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /run/secrets/registry-notary-metrics-token
    static_configs:
      - targets: ["registry-notary:8081"]
```

## Local Run

```bash
export REGISTRY_NOTARY_API_KEY_HASH='sha256:<sha256-hex-of-your-api-key>'
export REGISTRY_NOTARY_BEARER_TOKEN_HASH='sha256:<sha256-hex-of-your-bearer-token>'
export REGISTRY_NOTARY_AUDIT_HASH_SECRET='<stable-random-audit-hash-secret>'
export EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN='<registry-relay-source-token>'
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
hash, which proves local chain consistency but does not by itself prevent a
writer with local file access from rewriting history. Beta deployments that rely
on audit tamper-evidence must ship stdout/syslog envelopes off-host or publish
external anchors for retained head and tail hashes in storage the audit writer
cannot rewrite. Verification should check both the trusted starting `prev_hash`
for a retained suffix and the trusted final `record_hash` for the period under
review.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p registry-notary-server --no-default-features
cargo test --workspace --all-features
# cargo-deny is pinned through this wrapper.
./scripts/cargo-deny-check.sh
cargo build --workspace --all-features
cargo run -p registry-notary-bin -- openapi > target/registry-notary.openapi.json
```

Use the wrapper for dependency policy checks. It installs and runs the pinned
`cargo-deny` version expected by `deny.toml`, so older global installs do not
break local or CI verification.

Registry Notary depends on sibling `../registry-platform` path crates. CI checks
out `registry-platform` at `REGISTRY_PLATFORM_REF` beside this repository before
running Cargo jobs. Private platform checkouts require a repository secret named
`REGISTRY_PLATFORM_TOKEN`.

Run the focused Platform compatibility gate before merging Platform-facing
changes:

```bash
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform scripts/check-platform-compat.sh
```

The command checks the all-feature server build plus the OID4VCI nonce replay
and keyed audit-chain tests that exercise shared Platform security APIs. When
`REGISTRY_PLATFORM_SOURCE_DIR` is not the sibling path encoded in Cargo, the
script builds in a temporary sibling-layout copy so Cargo resolves the same
Platform checkout the script validated. Set `CEL_MAPPING_SOURCE_DIR` as well
when the Crosswalk checkout is not available at `../cel-mapping`.

CEL is disabled in default beta builds. It remains available through the
explicit `registry-notary-cel` feature and is implemented through the local
`crosswalk-core` crate at `../cel-mapping/crates/crosswalk-core`. The current
CEL timeout bounds request latency but is not a hard CPU or step limit, so
CEL-enabled builds are experimental until hardened subprocess isolation lands.

## Docker

The Docker build also needs the sibling Platform and Crosswalk workspaces.
Build with Docker BuildKit and pass both named contexts:

```bash
docker build \
  --build-context registry-platform=../registry-platform \
  --build-context cel-mapping=../cel-mapping \
  -t registry-notary .
```

Default Docker builds match the default Cargo feature set. Lab or integration
builds that need CEL can opt in without changing the default image:

```bash
docker build \
  --build-context registry-platform=../registry-platform \
  --build-context cel-mapping=../cel-mapping \
  --build-arg REGISTRY_NOTARY_FEATURES=registry-notary-cel \
  -t registry-notary:cel .
```

The product container workflow publishes CI images as `main` / `sha-<commit>`
and the CEL-enabled lab image as `main-cel` / `sha-<commit>-cel` under
`ghcr.io/jeremi/registry-notary`. First serious release readiness is checked
through the coordinated pre-tag release plan. Lab deployments should consume the
selected CEL-enabled image by immutable digest for rollback.

Native runs default to `127.0.0.1:8081`. The Docker image sets
`REGISTRY_NOTARY_BIND=0.0.0.0:8080` and exposes port `8080`; override it with
`--bind` or `REGISTRY_NOTARY_BIND` when deploying behind a different listener.
The image healthcheck runs `registry-notary healthcheck`, which probes
`http://127.0.0.1:8080/healthz` by default and does not require a shell or curl
inside the distroless runtime. Override `REGISTRY_NOTARY_HEALTHCHECK_URL` when
the container listener differs.

Mounted config supports simple environment expansion before YAML parsing:
`${VAR}` requires a non-empty value, `${VAR:-default}` supplies a default, and
`${VAR:?message}` fails startup with the provided message when the value is
missing. This keeps distroless deployments from needing shell wrappers for
environment-specific URLs.

The OpenFn sidecar image is owned by this repository as well:

```bash
docker build \
  --build-context registry-platform=../registry-platform \
  --build-context cel-mapping=../cel-mapping \
  -f Dockerfile.openfn-sidecar \
  -t registry-notary-openfn-sidecar .
```

It packages the Rust sidecar binary, the pinned OpenFn worker, and its locked
Node dependencies. The sidecar healthcheck uses Node's built-in `fetch` against
`http://127.0.0.1:9191/healthz` by default; override
`REGISTRY_NOTARY_OPENFN_SIDECAR_HEALTHCHECK_URL` when the sidecar binds a
different port.

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
