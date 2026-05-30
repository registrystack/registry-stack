# registry-notary-bin

Process entrypoint for the standalone Registry Notary service.

The crate builds the `registry-notary` binary.

## What It Provides

- CLI parsing for `--config` and subcommands.
- YAML config loading and validation.
- Tracing initialization.
- Axum listener startup and graceful shutdown.
- OpenAPI document printing through `registry-notary openapi`.

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
