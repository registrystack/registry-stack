# registry-witness-bin

Process entrypoint for the standalone Registry Witness service.

The crate builds the `registry-witness` binary.

## What It Provides

- CLI parsing for `--config` and subcommands.
- YAML config loading and validation.
- Tracing initialization.
- Axum listener startup and graceful shutdown.
- OpenAPI document printing through `registry-witness openapi`.

## Typical Use

Run the service:

```sh
cargo run -p registry-witness-bin -- --config demo/config/registry-witness.yaml
```

Print the OpenAPI document:

```sh
cargo run -p registry-witness-bin -- openapi > target/registry-witness.openapi.json
```

## Features

- Default: `registry-witness-cel`.
- `registry-witness-cel`: enables the server crate's CEL runtime feature.

## Testing

```sh
cargo test -p registry-witness-bin
cargo run -p registry-witness-bin -- openapi > target/registry-witness.openapi.json
```

## License

Apache-2.0.
