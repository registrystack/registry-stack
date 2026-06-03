# registry-notary-bin

Process entrypoint for the standalone Registry Notary service.

The crate builds the `registry-notary` binary.

## What It Provides

- CLI parsing for `--config` and subcommands.
- YAML config loading and validation.
- Tracing initialization.
- Axum listener startup and graceful shutdown.
- OpenAPI document printing through `registry-notary openapi`.
- Container liveness probing through `registry-notary healthcheck`.
- Machine-readable build capability reporting through `registry-notary build-info`.

## Subcommands

| Subcommand | Purpose |
|---|---|
| `openapi` | Print the OpenAPI document as JSON. |
| `build-info` | Print package, version, compiled features, and runtime capabilities as JSON. |
| `doctor` | Validate config, env-backed secrets, source auth, and VC wiring. |
| `explain-config` | Print resolved config and required env vars. |
| `init dci` | Generate a generic DCI source starter skeleton. |
| `hash-api-key` | Generate or hash a Registry Notary API key. |
| `demo-issuer-key` | Generate a demo Ed25519 issuer JWK for local VC smoke tests. |
| `healthcheck` | Probe the local HTTP health endpoint and exit non-zero when unhealthy. |
| `schema` | Print a lightweight JSON schema for top-level config discovery. |

## Typical Use

Run the service:

```sh
cargo run -p registry-notary-bin -- --config demo/config/registry-notary.yaml
```

Print the OpenAPI document:

```sh
cargo run -p registry-notary-bin -- openapi > target/registry-notary.openapi.json
```

Probe the container health endpoint without requiring curl in the image:

```sh
cargo run -p registry-notary-bin -- healthcheck --url http://127.0.0.1:8080/healthz
```

## Features

- Default: no CEL runtime.
- `pkcs11`: enables the server crate's PKCS#11 signing provider.
- `registry-notary-cel`: enables the server crate's CEL runtime feature.

## Testing

```sh
cargo test -p registry-notary-bin
cargo run -p registry-notary-bin -- openapi > target/registry-notary.openapi.json
```

## License

Apache-2.0.
