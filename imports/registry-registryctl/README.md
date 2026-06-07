# registryctl

`registryctl` is the local adopter CLI for Registry Commons.

Current status: Relay-first MVP implementation in progress. The first supported
path is:

```sh
registryctl init spreadsheet-api my-first-api --sample benefits
cd my-first-api
```

The generated project contains a local Registry Relay configuration, sample
XLSX workbook, Compose file, project manifest, and local demo credentials.

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`registryctl` consumes `registry-platform-authcommon` from the `main` branch of
`registry-platform`, so a registryctl checkout does not need a sibling Registry
Platform source checkout. This intentionally tracks current main until the
shared crates have fresh release tags.

## End-to-end smoke

The generated project uses the public Relay image published from current main:
`ghcr.io/jeremi/registry-relay:snapshot`. With Docker Compose available, run:

```sh
tmpdir="$(mktemp -d)"
cargo run -- init spreadsheet-api "$tmpdir/my-first-api" --sample benefits
cd "$tmpdir/my-first-api"
registryctl start
registryctl status
registryctl smoke
registryctl stop
```
