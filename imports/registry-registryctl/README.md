# registryctl

`registryctl` is the local adopter CLI for Registry Commons.

Install the latest main snapshot without cloning this repo:

```sh
curl -fsSL https://raw.githubusercontent.com/jeremi/registry-registryctl/main/install.sh | sh
```

Then create and start your first secured spreadsheet API:

```sh
registryctl init relay my-first-api --sample benefits
cd my-first-api
registryctl start
registryctl smoke
```

The generated project contains a local Registry Relay configuration, sample
XLSX workbook, Compose file, project manifest, local demo credentials, and an
optional Bruno API collection.

For the full walkthroughs, use the Registry Docs tutorials:

- [Publish a spreadsheet as a secured registry API](https://docs.registrystack.org/tutorials/publish-spreadsheet-secured-registry-api/)
- [Verify a claim from your registry API](https://docs.registrystack.org/tutorials/verify-claim-registry-api/)
- [Verify a claim from your own API](https://docs.registrystack.org/tutorials/verify-claim-own-api/)

The installer downloads the `snapshot` release binary for your OS and CPU. To
install a tagged release instead:

```sh
REGISTRYCTL_VERSION=vX.Y.Z curl -fsSL https://raw.githubusercontent.com/jeremi/registry-registryctl/main/install.sh | sh
```

Snapshot binaries are currently published for Linux x86_64, Linux aarch64, and
macOS aarch64.

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
cargo run -- init relay "$tmpdir/my-first-api" --sample benefits
cd "$tmpdir/my-first-api"
registryctl start
registryctl status
registryctl smoke
registryctl stop
```
