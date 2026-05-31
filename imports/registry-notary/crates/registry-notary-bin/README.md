# registry-notary-bin

Process entrypoint for the standalone Registry Notary service.

The crate builds the `registry-notary` binary.

## What It Provides

- CLI parsing for `--config` and subcommands.
- YAML config loading and validation.
- Tracing initialization.
- Axum listener startup and graceful shutdown.
- OpenAPI document printing through `registry-notary openapi`.

## Subcommands

| Subcommand | Purpose |
|---|---|
| `openapi` | Print the OpenAPI document as JSON. |
| `doctor` | Validate config, env-backed secrets, source auth, and VC wiring. |
| `explain-config` | Print resolved config and required env vars. |
| `init dci` | Generate a generic DCI source starter skeleton. |
| `hash-api-key` | Generate or hash a Registry Notary API key. |
| `demo-issuer-key` | Generate a demo Ed25519 issuer JWK for local VC smoke tests. |
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

## Features

- Default: no CEL runtime.
- `registry-notary-cel`: enables the server crate's CEL runtime feature.

## Testing

```sh
cargo test -p registry-notary-bin
cargo run -p registry-notary-bin -- openapi > target/registry-notary.openapi.json
```

## License

Apache-2.0.
