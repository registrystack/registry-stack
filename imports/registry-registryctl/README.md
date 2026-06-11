# registryctl

`registryctl` is the local adopter CLI for Registry Commons.

Install a pinned release without cloning this repo:

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

The installer defaults to `v0.1.0`. To install a different pinned release, set
`REGISTRYCTL_VERSION`:

```sh
REGISTRYCTL_VERSION=vX.Y.Z curl -fsSL https://raw.githubusercontent.com/jeremi/registry-registryctl/main/install.sh | sh
```

Binaries are published for Linux x86_64, Linux aarch64, and macOS aarch64.

## OpenFn sidecar import

`registryctl openfn import` converts an OpenFn workflow URL or exported YAML
into Registry Notary OpenFn sidecar runtime files:

```sh
registryctl openfn import ./openfn.yaml \
  --workflow person-lookup \
  --source person_lookup \
  --dataset civil_registry \
  --entity civil_person \
  --credential-env REGISTRY_SOURCE_CREDENTIAL_JSON \
  --smoke national_id=smoke-person
```

The command writes a sidecar manifest, OpenFn job expression files, and a
starter Notary config snippet. It checks the workflow topology, adaptor pins,
credentials, smoke lookup inputs, and sidecar limits before writing output.

For OpenFn-authored native batch workflows, use the
`@registry/notary-openfn` adaptor in the workflow and import with:

```sh
registryctl openfn import ./openfn.yaml \
  --workflow native-batch-person-lookup \
  --source person_lookup \
  --dataset civil_registry \
  --entity civil_person \
  --credential-env REGISTRY_SOURCE_CREDENTIAL_JSON \
  --smoke national_id=smoke-person \
  --batch-mode native
```

`--batch-mode per-item` remains the default. It compiles the workflow once and
runs the lookup workflow for each batch item. `--batch-mode native` runs the
workflow once with `state.data.items` and requires the Registry Notary adaptor
so authors can return validated per-item results from OpenFn.

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
