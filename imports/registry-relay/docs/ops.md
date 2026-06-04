# registry-relay Operations Runbook

This runbook describes the V1 operating model for running Registry Relay in development, staging, and production-like deployments.

## Deployment Model

Recommended production topology:

- Run one `registry-relay` process or container per deployment unit.
- Bind the data plane on `server.bind`, usually `0.0.0.0:8080` in a container.
- Put TLS, WAF rules, and external auth policy at the ingress or service mesh layer.
- Keep source files mounted read-only.
- Keep `server.cache_dir` writable by the `registry_relay` user.
- Prefer stdout audit records in containers and let the platform log pipeline retain, rotate, and forward them.
- When `server.admin_bind` is enabled, expose it only on an internal address or private network policy.

Container defaults:

```text
/etc/registry-relay/config.yaml       default config path
/var/lib/registry-relay/data          recommended source-data mount
/var/lib/registry-relay/cache         default writable cache mount when configured
/var/log/registry-relay               audit file mount for VM-style deployments
```

The binary exits non-zero if config parsing or validation fails, if required API-key hash environment variables are missing, or if listeners cannot bind.

```mermaid
flowchart TB
  Client["API clients"] --> Ingress["Ingress or service mesh<br/>TLS, WAF, external auth"]
  Mon["Monitoring network"] -. "scrape /metrics" .-> Admin
  AdminNet["Private admin network"] --> Admin

  subgraph Proc["registry-relay process or container"]
    direction TB
    Data["Data-plane listener<br/>server.bind"]
    Admin["Admin listener<br/>server.admin_bind, /metrics, reload"]
  end

  Ingress --> Data
  Data --> Src[("Source files<br/>read-only mount")]
  Data --> Cache[("server.cache_dir<br/>writable")]
  Data -. "audit JSONL" .-> Sink["Audit sink<br/>stdout, file, or syslog"]
  Admin -. "audit JSONL" .-> Sink
```

*Recommended production topology. TLS, WAF, and external auth sit at the
ingress. The admin listener carries metrics and reload and is reachable only
from the private admin and monitoring networks. Source files are read-only; the
cache is writable; the public data-plane listener does not mount `/metrics`.*

## Build And Release

Build a local release binary:

```sh
just build
```

Build a container image:

```sh
docker buildx build --load \
  --build-context registry-platform=../registry-platform \
  --build-context registry-manifest=../registry-manifest \
  --build-context cel-mapping=../cel-mapping \
  -t registry-relay:<version> \
  .
```

or:

```sh
scripts/build-image.sh registry-relay:<version>
```

The base image is built with no optional Cargo features. Standards-enabled
release or lab images must opt in explicitly:

```sh
REGISTRY_RELAY_FEATURES=spdci-api-standards,standards-cel-mapping,ogcapi-edr \
  scripts/build-image.sh registry-relay:<version>-standards
```

If release notes claim SP DCI, standards CEL mapping, or OGC EDR support, record
the standards-enabled image tag or digest in the release evidence.

The build requires the pinned `registry-platform`, `registry-manifest`, and
`cel-mapping` source trees because Relay uses sibling path dependencies. For
local builds, keep those checkouts next to this repository or set
`REGISTRY_PLATFORM_DIR`, `REGISTRY_MANIFEST_DIR`, and `CEL_MAPPING_DIR` before
running `scripts/build-image.sh`.

Before promoting an image, inspect the effective config and verify that every referenced `hash_env` is supplied by the runtime environment. Do not bake API keys or API-key hashes into the image.

If the runtime config uses `metadata.manifest_path`, validate the manifest and
runtime bindings before promotion:

```sh
just metadata-validate path/to/metadata.yaml
cargo test --test demo_configs_load
```

For standalone metadata publication, use `just metadata-publish` and publish the
generated `index.json` as the discovery entry point. See [metadata.md](metadata.md)
for the bundle layout.

For releases that claim DCAT-AP interoperability, run the
`dcat-ap-external-validation` GitHub Actions workflow or validate an
exported `/metadata/dcat/bregdcat-ap` with the SEMIC validator:

```sh
just validate-catalog-semic catalog=target/metadata.bregdcat-ap.jsonld
```

The release workflow uploads both the generated catalog and the SEMIC
JSON report as artifacts. Treat `dcatap.3_0_1_base` as the minimum
external profile; use stricter SEMIC profiles such as
`dcatap.3_0_1_full` when the deployment is intended to satisfy the full
European profile.

## Configure

Set the config path with `--config <path>` or `REGISTRY_RELAY_CONFIG`. The container image defaults to:

```sh
registry-relay --config /etc/registry-relay/config.yaml
```

Important configuration blocks:

- `server.bind`: public data-plane listener.
- `server.admin_bind`: optional admin listener. Intended for reload and future admin operations on a restricted network.
- `server.cache_dir`: writable cache for normalized Parquet files and ingest state.
- `server.cors.allowed_origins`: default deny when empty.
- `server.trust_proxy`: only enable when the gateway is behind trusted proxies and those proxy CIDRs are configured.
- `auth.api_keys`: key ids, hash env var names, and scopes.
- `datasets[].source.path`: local file path inside the container or host.
- `datasets[].refresh`: `mtime`, `interval`, or `manual`.
- `audit`: audit sink and JSONL options.

Config reload is restart-only in V1. Dataset reload does not reload `config.yaml`.

## API-Key Provisioning And Rotation

API-key config stores only:

- a stable key id;
- an environment variable name holding the SHA-256 fingerprint of the raw key;
- the key's scopes.

Recommended rotation procedure:

1. Generate a new random API key outside the gateway.
2. Store `sha256:<sha256(raw key)>` in the deployment secret store.
3. Add a new `auth.api_keys[]` entry or update the existing entry's `hash_env` reference.
4. Restart or roll the gateway, because the current keyring is loaded at process startup.
5. Confirm the new key can call the intended lowest-privilege endpoint.
6. Update the consumer to use the new raw key.
7. Remove the old key entry or old secret and restart or roll again.

Live keyring reload is not wired in V1. Treat key rotation as a rolling restart operation.

Never log raw keys, fingerprints, or full environment dumps. In issue reports, include only key ids and scope names.

## Provenance Signer Rotation

The provenance feature (signed Verifiable Credentials, see [docs/provenance.md](provenance.md)) introduces a signing key. The runtime contract is identical in shape to API-key rotation, but the recovery model is different: existing VCs signed under a retired key must still verify until they expire, so the DID Document keeps publishing those keys for a controlled window.

The signing key never lives in YAML. It is injected through the env var named by `provenance.issuer.signer.jwk_env`, holding a JSON-encoded private JWK. The public half goes in the DID Document; the private half stays in the secret store.

Production smoke for local software Ed25519 deployments:

1. Boot or roll the gateway with `REGISTRY_RELAY_PROVENANCE_JWK`
   injected by the runtime secret store.
2. Fetch `/.well-known/did.json` and
   `/schemas/entity-record/v1.json` from the public data-plane URL.
3. Request an entity-record VC with `Accept: application/vc+jwt` and a key
   scoped only for row reads.
4. Run `node scripts/verify_vc_jwt.mjs` against the saved VC, DID
   Document, expected issuer, expected `EntityRecord` claim type, and
   saved schema.
5. During rotation, save a pre-rotation VC, roll the new private JWK
   and `verification_method_id`, confirm the DID Document publishes
   both old and new `kid` values, then verify both old and new VCs.
   Remove the retired public key only after the longest configured
   `claim_validity` window has elapsed and repeat the DID fetch.

See [Production Smoke Checklist](provenance.md#production-smoke-checklist) for exact commands.

Rotation procedure (gateway mode):

1. Mint a new Ed25519 keypair for `EdDSA`. Store the new private JWK in the deployment secret store.
2. Add the new public JWK to the DID Document under a new `verificationMethod` id (e.g. `did:web:data.example.gov#issuance-2026q3`).
3. Move the currently active verification method to `provenance.issuer.retired_keys[]`, recording the `retired_after` RFC 3339 timestamp and the public JWK in its own env var.
4. Update `verification_method_id` to the new id and point `signer.jwk_env` at the new env var.
5. Roll the gateway. The keyring loads at process start, so rotation is a rolling-restart operation.
6. Confirm the new VCs verify with the new public JWK and that previously issued VCs (still inside their validity window) verify against the retired entry.
7. Once the longest applicable `claim_validity` window has elapsed since `retired_after`, drop the retired entry from config and remove the public JWK from the DID Document on the next deploy.

Delegated mode follows the same steps, except the DID Document edits land on the ministry's side. Coordinate the cutover so the ministry publishes the new `verificationMethod` before the gateway starts signing with the corresponding private key.

Remote signing (`signer.kind: kms`) is reserved for a future backend and is rejected by V1 config validation. The supported production path is local software Ed25519 signing with the private JWK loaded from the configured secret environment variable.

Never log the JWK, the env var value, or any full environment dump. The provenance audit block intentionally records only `iss`, `kid`, `jti`, `claim_type`, `subject`, and the `iat`/`nbf`/`exp` triple, not the signed body or any signing material.

## Audit Sink And Rotation

Audit records are JSON Lines and are separate from operational logs. Operational logs go to stderr as readable text by default. Set `REGISTRY_RELAY_LOG_FORMAT=json` or `REGISTRY_RELAY_LOG_FORMAT=jsonl` when operational logs should be emitted as JSON Lines for collection or redirected files.

Current runtime behavior:

- The public and admin listeners cap accepted sockets with `server.max_connections`, close incomplete HTTP/1 headers after `server.http1_header_read_timeout`, and bound request-body reads with `server.request_body_timeout`. Direct HTTP/2 serving uses the same finite connection cap and keepalive timeout, but production deployments that terminate HTTP/2 at a reverse proxy must set bounded proxy header/body read timeouts and per-client connection limits before forwarding to the relay.
- `audit.sink: stdout` writes audit JSONL to stdout.
- `audit.sink: file` writes audit JSONL to the configured path and rotates in-process by `rotate.max_size_mb` and `rotate.max_files`.
- `audit.sink: syslog` ships audit JSONL to the local syslog Unix datagram socket.
- Audit output is always wrapped in `registry-platform-audit` envelopes with `prev_hash` and `record_hash` fields. These fields detect ordering gaps and accidental corruption in retained logs, but the beta file/stdout/syslog sinks do not protect against a writer that can rewrite the sink. Use an append-only external log store or independent tail-hash anchoring when stronger integrity is required. `audit.chain` is retained for config compatibility.
- HTTP request completion is logged at `info` with method, matched route template, request id, status, and latency. It does not log raw query strings, request bodies, auth headers, or row values.
- `REGISTRY_RELAY_LOG_FORMAT=json` switches stderr operational logs from text to JSONL.

File sink example:

```yaml
audit:
  sink: file
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_AUDIT_HASH_SECRET
  path: /var/log/registry-relay/audit.jsonl
  rotate:
    max_size_mb: 100
    max_files: 14
```

For container deployments, `stdout` is still the simplest default because the platform log pipeline owns retention, rotation, access control, and SIEM forwarding. For VM deployments, use `file` when the gateway should own audit rotation locally, or `syslog` when the host forwards records to a central collector.

`audit.hash_secret_env` is required for runtime startup and must point to at least 32 bytes of deployment-specific random secret material. The relay fails closed when the setting is missing, empty, unset, or weak, so sensitive audit lookup hashes never silently downgrade to unkeyed SHA-256.

Audit records must not contain raw secrets or raw API keys. Mark identifier fields as `sensitive: true` in table or entity field config when query values should be deterministically hashed in audit rather than omitted entirely. The flag is audit-only in beta; it does not remove fields from authorized API responses.

## Dataset Refresh And Reload

Refresh modes:

- `mtime`: poll source file modification time and reload when it changes. The default poll interval is 60 seconds.
- `interval`: reload unconditionally on the configured interval.
- `manual`: reload only through an admin request.

The original source file is never modified. On ingest failure, the intended behavior is to keep serving the previously loaded table and mark readiness degraded for the failed resource.

Manual table reload:

```sh
curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" \
  http://127.0.0.1:8081/admin/v1/datasets/social_registry/tables/individuals_table/reload
```

Manual registry reload:

```sh
curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" \
  http://127.0.0.1:8081/admin/v1/reload
```

The reload-all response includes `status` and aggregate `counts` for total, succeeded, and failed resources. A non-zero failure count returns HTTP 500 with `status: "failed"`; inspect the audit and operational logs for the resource-level failure context.

## Readiness And Probes

Use:

```text
GET /healthz
GET /ready
```

`/healthz` is liveness only and does not check datasets. `/ready` returns 200 only when configured resources have ingested successfully once the readiness watch is installed. On ingest failures it returns `503 application/problem+json` with failed or not-ready resources.

In orchestrators:

- Use `/healthz` for liveness.
- Use `/ready` for readiness and traffic gating.
- Give startup enough time for the largest XLSX/Parquet ingest.

## Metrics

When `server.admin_bind` is configured, the admin listener exposes:

```text
GET /metrics
```

The response is Prometheus-style `text/plain` suitable for scraping from the private admin network. The public data-plane listener does not mount `/metrics`.

Metrics are intentionally bounded. Request metrics use low-cardinality labels such as method, route or endpoint class, and status, plus request-duration buckets. Readiness metrics are gauges derived from the ingest readiness snapshot. Metrics must not include raw query values, raw bearer tokens, request ids, API-key ids, key fingerprints, `Data-Purpose` values, or dataset row content.

Recommended scrape posture:

- Scrape only the admin listener from a private monitoring network.
- Treat `/metrics` as operational telemetry, not an audit record or per-request trace.
- Use audit logs for security review and request-level accountability.
- Alert on readiness gauges and elevated 5xx/error counters before routing traffic away.

## Troubleshooting

Config fails at startup:

- Check YAML shape against [config/example.yaml](../config/example.yaml).
- Confirm every `hash_env` variable is set.
- Confirm each `hash_env` value is a `sha256:<64 lowercase hex chars>` fingerprint.
- Confirm ids are lower-snake and unique.
- Check vocabulary prefixes used by `concept_uri` and `conforms_to`.
- For `metadata.manifest.*` errors, validate the portable metadata manifest.
- For `runtime.binding.*` errors, compare runtime dataset, entity, field, filter, and relationship ids with the compiled metadata manifest.

Protected endpoint returns 401:

- Confirm the request has `Authorization: Bearer <key>` or `X-Api-Key`.
- Confirm the raw key hashes to one configured fingerprint.
- Confirm the process was restarted after key changes.

Protected endpoint returns 403:

- Confirm the key has the exact scope named by the entity access block.
- Remember that metadata, aggregate, rows, evidence verification, and admin scopes do not imply one another.
- For row or OGC feature endpoints on entities with `require_purpose_header: true`, include `Data-Purpose`.

Dataset or entity returns unknown-resource errors:

- Confirm the public path uses the entity `name`, not the backing table id.
- Confirm entity relationships target entities in the same dataset.
- Confirm field filters use exposed entity field names, not hidden storage columns.

Readiness is 503:

- Inspect stderr operational logs for ingest errors.
- Check the source file exists at the path visible to the container or process.
- For XLSX, ensure the configured sheet is a clean rectangular table. Use `header_row` and `data_range` when the file has surrounding notes.
- Confirm strict schema fields match the source columns and types.
- Confirm `server.cache_dir` is writable.

Audit records missing:

- In containers, check stdout, not stderr.
- Confirm `audit.include_health` if expecting health and ready records.
- For `audit.sink: file`, confirm the parent directory exists or can be created by the `registry_relay` user.
- For `audit.sink: syslog`, confirm the host exposes the expected Unix datagram socket (`/var/run/syslog` on macOS, `/dev/log` on other Unix platforms).

Caller expected a signed VC but received plain JSON:

- Confirm the request `Accept` header lists one of `provenance.accepted_media_types` (default `application/vc+jwt` or `application/jwt`).
- Confirm `provenance.enabled: true` in the loaded config and that the process was restarted after the config change.
- Confirm the env var named by `provenance.issuer.signer.jwk_env` is set and holds a valid JWK; a missing or malformed JWK fails the signer at startup, not at request time.
- For `mode: delegated`, confirm the ministry's DID Document publishes the gateway's `verification_method_id`.

Admin reload fails:

- Confirm `server.admin_bind` is configured and reachable only from the private admin network.
- Confirm the key has the independent `admin` scope.
- Check the per-resource `error_code` in the reload-all response. Use the table-specific endpoint to retry one failed source after correcting the underlying data or connectivity issue.

Metrics missing:

- Confirm you are scraping the admin listener, not `server.bind`.
- Confirm `server.admin_bind` is configured and reachable from the monitoring network.
- Expect `/metrics` on the public listener to be unavailable. Depending on the auth stack, the response may be `401` rather than `404`.
