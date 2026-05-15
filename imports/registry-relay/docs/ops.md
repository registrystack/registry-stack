# data_gate Operations Runbook

This runbook describes the intended V1 operating model and calls out current Wave 5 assumptions where runtime work is still landing.

## Deployment Model

Recommended production topology:

- Run one `data_gate` process or container per deployment unit.
- Bind the data plane on `server.bind`, usually `0.0.0.0:8080` in a container.
- Put TLS, WAF rules, and external auth policy at the ingress or service mesh layer.
- Keep source files mounted read-only.
- Keep `server.cache_dir` writable by the `data_gate` user.
- Prefer stdout audit records in containers and let the platform log pipeline retain, rotate, and forward them.
- When `server.admin_bind` is enabled, expose it only on an internal address or private network policy.

Container defaults:

```text
/etc/data_gate/config.yaml       default config path
/var/lib/data_gate/data          recommended source-data mount
/var/lib/data_gate/cache         default writable cache mount when configured
/var/log/data_gate               audit file mount for VM-style deployments
```

The binary exits non-zero if config parsing or validation fails, if required API-key hash environment variables are missing, or if listeners cannot bind.

## Build And Release

Build a local release binary:

```sh
just build
```

Build a container image:

```sh
docker build -t data_gate:<version> .
```

or:

```sh
scripts/build-image.sh data_gate:<version>
```

Before promoting an image, inspect the effective config and verify that every referenced `hash_env` is supplied by the runtime environment. Do not bake API keys or API-key hashes into the image.

## Configure

Set the config path with `--config <path>` or `DATAGATE_CONFIG`. The container image defaults to:

```sh
data_gate --config /etc/data_gate/config.yaml
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
- an environment variable name holding the Argon2id PHC hash;
- the key's scopes.

Recommended rotation procedure:

1. Generate a new random API key outside the gateway.
2. Hash it with Argon2id and store the PHC string in the deployment secret store.
3. Add a new `auth.api_keys[]` entry or update the existing entry's `hash_env` reference.
4. Restart or roll the gateway, because the current keyring is loaded at process startup.
5. Confirm the new key can call the intended lowest-privilege endpoint.
6. Update the consumer to use the new raw key.
7. Remove the old key entry or old secret and restart or roll again.

Live keyring reload is not wired in V1. Treat key rotation as a rolling restart operation.

Never log raw keys, PHC strings, or full environment dumps. In issue reports, include only key ids and scope names.

## Audit Sink And Rotation

Audit records are JSON Lines and are separate from operational logs. Operational logs go to stderr as structured JSON.

Current runtime behavior:

- `audit.sink: stdout` writes audit JSONL to stdout.
- `audit.sink: file` writes audit JSONL to the configured path and rotates in-process by `rotate.max_size_mb` and `rotate.max_files`.
- `audit.sink: syslog` ships audit JSONL to the local syslog Unix datagram socket.
- `audit.chain: true` wraps sink output with `prev_hash` and `record_hash` fields for tamper-evidence.

File sink example:

```yaml
audit:
  sink: file
  format: jsonl
  path: /var/log/data_gate/audit.jsonl
  rotate:
    max_size_mb: 100
    max_files: 14
```

For container deployments, `stdout` is still the simplest default because the platform log pipeline owns retention, rotation, access control, and SIEM forwarding. For VM deployments, use `file` when the gateway should own audit rotation locally, or `syslog` when the host forwards records to a central collector.

Audit records must not contain raw secrets or raw API keys. Mark identifier fields as `sensitive: true` in table or entity field config when query values should be deterministically hashed in audit rather than omitted entirely.

## Dataset Refresh And Reload

Refresh modes:

- `mtime`: poll source file modification time and reload when it changes. The default poll interval is 60 seconds.
- `interval`: reload unconditionally on the configured interval.
- `manual`: reload only through an admin request.

The original source file is never modified. On ingest failure, the intended behavior is to keep serving the previously loaded table and mark readiness degraded for the failed resource.

Manual table reload:

```sh
curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" \
  http://127.0.0.1:8081/admin/datasets/social_registry/tables/individuals_table/reload
```

`POST /admin/reload` is specified as reload-all, but the current handler reports `501 admin.reload_unavailable` until registry-wide reload is implemented.

## Readiness And Probes

Use:

```text
GET /health
GET /ready
```

`/health` is liveness only and does not check datasets. `/ready` returns 200 only when configured resources have ingested successfully once the readiness watch is installed. On ingest failures it returns `503 application/problem+json` with failed or not-ready resources.

In orchestrators:

- Use `/health` for liveness.
- Use `/ready` for readiness and traffic gating.
- Give startup enough time for the largest XLSX/Parquet ingest.

## Troubleshooting

Config fails at startup:

- Check YAML shape against [config/example.yaml](../config/example.yaml).
- Confirm every `hash_env` variable is set.
- Confirm each `hash_env` value is an Argon2id PHC string.
- Confirm ids are lower-snake and unique.
- Check vocabulary prefixes used by `concept_uri` and `conforms_to`.

Protected endpoint returns 401:

- Confirm the request has `Authorization: Bearer <key>` or `X-Api-Key`.
- Confirm the raw key matches one configured PHC hash.
- Confirm the process was restarted after key changes.

Protected endpoint returns 403:

- Confirm the key has the exact scope named by the entity access block.
- Remember that verify, metadata, aggregate, rows, bulk export, and admin scopes do not imply one another.
- For row or verify endpoints on entities with `require_purpose_header: true`, include `X-Data-Purpose`.

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
- For `audit.sink: file`, confirm the parent directory exists or can be created by the `data_gate` user.
- For `audit.sink: syslog`, confirm the host exposes the expected Unix datagram socket (`/var/run/syslog` on macOS, `/dev/log` on other Unix platforms).

Admin reload unavailable:

- Confirm `server.admin_bind` is configured and reachable only from the private admin network.
- Confirm the key has the independent `admin` scope.
- Use the single-table reload path for V1. If `POST /admin/reload` returns `501 admin.reload_unavailable`, use the table-specific endpoint, refresh mode, or restart as the operational workaround.
