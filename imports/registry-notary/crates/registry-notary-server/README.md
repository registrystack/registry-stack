# registry-notary-server

Standalone Registry Notary runtime, API routes, auth, audit, source connectors,
renderers, and credential issuance wiring.

## What It Provides

- Axum routers for the Registry Notary API.
- Runtime claim evaluation with dependency ordering and batch memoization.
- HTTP Registry Data API and DCI source connectors.
- API-key and bearer-token auth through `registry-platform` primitives.
- Redacted audit event emission.
- JSON, SD-JWT VC, and credential response renderers.
- Static-peer federated delegated evaluation at `/federation/v1/evaluations`
  when federation is enabled in config.
- Prometheus metrics contract for `/metrics` with safe, low-cardinality labels.
- OpenAPI document generation.

## Typical Use

```rust
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::{standalone_router, StandaloneServerError};

fn app(config: StandaloneRegistryNotaryConfig) -> Result<axum::Router, StandaloneServerError> {
    standalone_router(config)
}
```

## Features

- Default: no CEL runtime.
- `registry-notary-cel`: enables CEL-backed claim expression evaluation through
  `crosswalk-core` in a hardened worker process with bounded IO, environment
  scrubbing, resource limits where supported, timeout kill, and worker
  replacement.
- `pkcs11`: enables HSM-backed SD-JWT VC issuer signing through PKCS#11. The
  provider supports Ed25519 EdDSA keys and is configured through
  `evidence.signing_keys`. See
  [`../../docs/signing-key-provider.md`](../../docs/signing-key-provider.md).

Run server tests without default features when checking the beta binary shape:

```sh
cargo test -p registry-notary-server --no-default-features
```

Run the PKCS#11 feature path separately:

```sh
cargo test -p registry-notary-server --no-default-features --features pkcs11 --lib
```

When SoftHSM and OpenSSL are installed, that feature test includes a live
PKCS#11 signing smoke test.

## Replay Store Configuration

Replay protection for federation request JWTs, OID4VCI nonces, and holder proof
JWTs is configured under `StandaloneRegistryNotaryConfig.replay`:

```yaml
replay:
  storage: in_memory
```

`in_memory` retains one-time identifiers in the current process and is not safe
for active-active serving because another Notary process cannot see those
replay decisions.

Production multi-instance deployments should use Redis as the shared replay
store:

```yaml
replay:
  storage: redis
  redis:
    url_env: REGISTRY_NOTARY_REPLAY_REDIS_URL
    key_prefix: registry-notary
    connect_timeout_ms: 1000
    operation_timeout_ms: 500
```

`url_env` names the environment variable containing the Redis URL. The router
fails to build when that variable is missing, and `/ready` fails closed if Redis
cannot be reached. Replay storage is implemented through
`registry-platform-replay`, which layers replay and consumable nonce semantics
over `registry-platform-cache`. Redis keys hash replay scope and one-time
identifiers before storage, keeping peer ids, subjects, holders, nonces, and
JWT `jti` values out of backend keys.

## Credential Lifecycle

SD-JWT VC issuance is intentionally short-lived and status-free by default.
Each credential profile controls the credential lifetime with
`validity_seconds`, which defaults to 600 seconds when omitted.

Set `credential_status.enabled = true` to add a storage-backed credential
status endpoint. Issued SD-JWT VC payloads then include a `status.statusUrl`
claim pointing at `/v1/credentials/{credential_id}/status`. The store supports
`in_memory` for lab deployments and `redis` for deployable multi-process
instances. The public endpoint returns `valid`, `suspended`, `revoked`, or
derived `expired`; admins update mutable states through
`POST /admin/v1/credentials/{credential_id}/status` with the
`registry_notary:admin` scope. Status records contain only credential lifecycle
metadata, not subject ids, holder keys, claim values, disclosures, or source
rows.

## Metrics

`/metrics` is the Prometheus scrape surface for server metrics. Metric families
and labels must be safe for operational scraping: use bounded labels such as
endpoint kind, method, status code, status class, error code, outcome, profile,
and source id. Do not label or emit subject ids, principal ids, holder keys,
access tokens, source rows, request or correlation ids, SD-JWT disclosures, or
raw error details. The endpoint requires an authenticated principal with the
`registry_notary:metrics_read` scope, so Prometheus scrape jobs must send a
dedicated metrics credential. Static-auth deployments can use a metrics bearer
token or a metrics API key in `x-api-key`; OIDC deployments can use a token
whose mapped scopes include `registry_notary:metrics_read`. An internal-only
listener/proxy is defense in depth only and must still forward or inject a valid
metrics credential. It should still be exposed only through the deployment's
normal network and scrape controls.

Example Prometheus scrape shape:

```yaml
scrape_configs:
  - job_name: registry-notary
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /run/secrets/registry-notary-metrics-token
    static_configs:
      - targets: ["registry-notary:4325"]
```

## Operations Posture

`GET /admin/v1/posture` returns the redacted `registry.ops.posture.v1`
operations document for fleet polling. It requires an authenticated principal
with exactly the read-only `registry_notary:ops_read` scope; the write-capable
`registry_notary:admin` scope does not authorize posture unless the same
credential also carries `registry_notary:ops_read`.

Registry Notary supports a dedicated admin listener with
`server.admin_listener.mode: dedicated`. In that mode `/admin/v1/*` and
`/metrics` are not mounted on the public listener. Simple local deployments may
use `server.admin_listener.mode: shared_with_public`, but governed
configuration with `config_trust` requires dedicated admin mode at startup.
Every topology still enforces the application scope checks.

## Audit Configuration

`standalone_router` builds the audit pipeline from
`StandaloneRegistryNotaryConfig.audit`. The pipeline writes one redacted,
tamper-evident JSON envelope per security-relevant event and fails closed if the
configured hash secret is unavailable.

```yaml
audit:
  sink: file
  path: /var/log/registry-notary/audit.jsonl
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
  max_size_mb: 100
  max_files: 14
```

Sink options:

- `stdout` writes JSONL to process stdout and is appropriate when platform log
  collection provides durability.
- `file` and `jsonl` require `path`. Use `max_size_mb` for active-file rotation
  and `max_files` for retained file count. `max_files` includes the active
  file; `max_size_mb: 0` disables rotation.
- `syslog` writes JSONL envelopes to a local Unix datagram syslog socket. Set
  `syslog_socket_path` to override the platform default:

```yaml
audit:
  sink: syslog
  syslog_socket_path: /run/systemd/journal/syslog
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
```

`hash_secret_env` names an environment variable containing the deployment HMAC
secret used for audit identifier hashing. Use a generated, high-entropy value,
keep it out of config files, and keep it stable for the retention period where
auditors must correlate records.

Audit envelopes contain `prev_hash` and `record_hash`. File/jsonl sinks resume
from the retained tail hash on startup. Sinks that cannot be read back, such as
stdout and syslog, need an external anchoring process if auditors must prove
continuity across process restarts. Store the retained head hash, meaning the
first envelope's `prev_hash`, and the tail hash, meaning the last envelope's
`record_hash`, in append-only or independently controlled storage. Verification
should reject a retained suffix unless its head matches the trusted starting
hash and its tail matches the trusted final hash for the review window.

## Security Notes

- The server starts fail-closed when credentials are missing or invalid.
- SD-JWT VC credential profiles default to 600-second validity when
  `validity_seconds` is omitted; self-attestation keeps profiles within the
  configured credential validity ceiling.
- Federated evaluation routes are not mounted unless `federation.enabled` is
  true, and accepted requests must be signed compact JWS bodies from configured
  peers.
- The default replay store is `in_memory`; active-active deployments need the
  Redis replay backend before privileged federation traffic is enabled.
- Source connectors send explicit purpose headers and use configured source
  tokens.
- Redis durability for replay protection is provided by `registry-platform-replay`
  and selected through the Notary replay configuration.

## Testing

```sh
cargo test -p registry-notary-server --no-default-features
cargo test -p registry-notary-server --all-features
```

## License

Apache-2.0.
