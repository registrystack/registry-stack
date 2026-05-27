# registry-witness-server

Standalone Registry Witness runtime, API routes, auth, audit, source connectors,
renderers, and credential issuance wiring.

## What It Provides

- Axum routers for the Registry Witness API.
- Runtime claim evaluation with dependency ordering and batch memoization.
- HTTP Registry Data API and DCI source connectors.
- API-key and bearer-token auth through `registry-platform` primitives.
- Redacted audit event emission.
- JSON, SD-JWT VC, and credential response renderers.
- Static-peer federated delegated evaluation at `/federation/v1/evaluations`
  when federation is enabled in config.
- OpenAPI document generation.

## Typical Use

```rust
use registry_witness_core::StandaloneRegistryWitnessConfig;
use registry_witness_server::{standalone_router, StandaloneServerError};

fn app(config: StandaloneRegistryWitnessConfig) -> Result<axum::Router, StandaloneServerError> {
    standalone_router(config)
}
```

## Features

- Default: `registry-witness-cel`.
- `registry-witness-cel`: enables CEL-backed claim expression evaluation through
  `crosswalk-core`.

Run server tests without default features when checking the non-CEL binary
shape:

```sh
cargo test -p registry-witness-server --no-default-features
```

## Audit Configuration

`standalone_router` builds the audit pipeline from
`StandaloneRegistryWitnessConfig.audit`. The pipeline writes one redacted,
tamper-evident JSON envelope per security-relevant event and fails closed if the
configured hash secret is unavailable.

```yaml
audit:
  sink: file
  path: /var/log/registry-witness/audit.jsonl
  hash_secret_env: REGISTRY_WITNESS_AUDIT_HASH_SECRET
  max_size_bytes: 10485760
  max_files: 5
```

Sink options:

- `stdout` writes JSONL to process stdout and is appropriate when platform log
  collection provides durability.
- `file` and `jsonl` require `path`. Use `max_size_bytes` for active-file
  rotation and `max_files` for retained file count. `max_files` includes the
  active file; `max_size_bytes: 0` disables rotation.
- `syslog` writes JSONL envelopes to a local Unix datagram syslog socket. Set
  `syslog_socket_path` to override the platform default:

```yaml
audit:
  sink: syslog
  syslog_socket_path: /run/systemd/journal/syslog
  hash_secret_env: REGISTRY_WITNESS_AUDIT_HASH_SECRET
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
- Federated evaluation routes are not mounted unless `federation.enabled` is
  true, and accepted requests must be signed compact JWS bodies from configured
  peers.
- The MVP replay store is `in_process_single_instance_only`; active-active
  deployments need a shared replay store before privileged federation traffic is
  enabled.
- Source connectors send explicit purpose headers and use configured source
  tokens.
- Replay persistence and deployment-grade retention remain consumer and
  operator responsibilities.

## Testing

```sh
cargo test -p registry-witness-server --no-default-features
cargo test -p registry-witness-server --all-features
```

## License

Apache-2.0.
