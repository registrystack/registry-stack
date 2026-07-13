# registryctl

`registryctl` is the local adopter CLI for Registry Commons.

Install a pinned release without cloning this repo:

```sh
curl -fsSL https://raw.githubusercontent.com/registrystack/registry-stack/refs/tags/v0.9.0/crates/registryctl/install.sh | bash
```

The quick installer verifies downloaded release assets against `SHA256SUMS`
only. It installs the binary for releases before `v0.9.0`; beginning with
`v0.9.0`, it installs the binary and matching image lock beside each other. It
does not verify cosign signatures or SLSA provenance; use
[`release/VERIFY.md`](../../release/VERIFY.md) for release authenticity checks.

Then create and start your first secured spreadsheet API:

```sh
registryctl init relay my-first-api --sample benefits
cd my-first-api
registryctl doctor --profile local --format json
registryctl start
registryctl smoke
```

The generated project contains a local Registry Relay configuration, sample
XLSX workbook, Compose file, project manifest, local demo credentials, and an
optional Bruno API collection.

Run `registryctl doctor --format json` before starting a generated stack or
after editing config. It calls the product-owned validators, redacts local
secret values, and returns a machine-readable report for troubleshooting.

For the full walkthroughs, use the Registry Docs tutorials:

- [Publish a spreadsheet as a secured registry API](https://docs.registrystack.org/tutorials/publish-spreadsheet-secured-registry-api/)
- [Verify a claim from your registry API](https://docs.registrystack.org/tutorials/verify-claim-registry-api/)
- [Connect Notary to a Registry Data API source](https://docs.registrystack.org/tutorials/run-notary-standalone-for-api/)

## Country integration authoring

Start from the declarative bounded-HTTP workspace, run its closed offline
fixtures, inspect the redacted generated plan, and build deterministic Relay
and Notary inputs:

```sh
registryctl init --from bounded-http --country-dir country
registryctl test --project country
registryctl check --project country --environment local --explain
registryctl build --project country --environment local
```

The authoring contract accepts one to four exact subject inputs. Input names
match `[a-z][a-z0-9_]{0,63}`, values are bounded to 256 bytes, and patterns are
bounded to 1024 bytes. Credentials are fixed interfaces whose values remain
environment-only secret references. `check` and `build` compile the generated
closure with the product-owned Relay and Notary validators. `test` additionally
executes deterministic source fixtures without granting fixture YAML network,
credential, filesystem, or worker authority.

Sandboxed Rhai is an advanced, release-gated integration mode. Its offline
conformance fixtures use the isolated implementation-owned worker harness;
ordinary startup remains unavailable unless the release includes the reviewed
Sandboxed Rhai authoring and worker contract and the country environment has
explicit operator-security enablement. Source product and version remain review
and provenance metadata; they do not select the Rhai runtime or executor.
`test --live` requires an explicit non-production environment and uses only the
governed deployed Notary path. It never contacts a source registry directly.

To scaffold a standalone Notary project for an existing FHIR source-adapter
sidecar:

```sh
registryctl init notary my-fhir-notary --source-kind fhir-sidecar
```

This generates a starter `patient-record-exists` claim using the Notary
source-adapter contract and defaults the sidecar URL to
`http://host.docker.internal:4360`. It does not start a FHIR server or the
FHIR sidecar for you.

The installer defaults to `v0.9.0`. To install a different pinned release, set
`REGISTRYCTL_VERSION`:

```sh
curl -fsSL https://raw.githubusercontent.com/registrystack/registry-stack/refs/tags/vX.Y.Z/crates/registryctl/install.sh | REGISTRYCTL_VERSION=vX.Y.Z bash
```

Fetch the installer from the same pinned tag selected by
`REGISTRYCTL_VERSION`. An older installer does not know the asset contract of a
newer release.

Prebuilt binaries are published for the `v0.9.0` stack release on Linux x86_64,
Linux arm64, and macOS arm64. On other platforms, install from source with
`cargo install --git https://github.com/registrystack/registry-stack --tag v0.9.0 registryctl --locked`.
Intel macOS has no prebuilt binary for `v0.9.0`, so the installer stops after
printing that Cargo command. It does not run the source build automatically.

## Release image lock (`v0.9.0` and later)

`registryctl init` and `registryctl add` read
`registryctl-vX.Y.Z-image-lock.json` beside the running binary before writing
project files. The strict lock binds the CLI release, source commit, tag target,
`linux/amd64` platform, and exact Relay and Notary image digests. Registryctl
does not discover images from mutable tags or a live registry.

For `v0.9.0` and later, if you move or build the binary separately, place the
checksum-verified image lock from the same release beside it. An operator or
source test can set `REGISTRYCTL_IMAGE_LOCK` to an explicit verified lock path.
Registryctl never searches the current working directory for a lock, and
rejects a missing, mismatched, oversized, symlinked, or structurally invalid
file.

Existing projects do not need the lock for `start`, `stop`, `status`, or other
runtime commands. They keep using the immutable image references already stored
in `registryctl.yaml` and `compose.yaml`. A later `init` or `add` is a generation
operation and requires the lock for that registryctl version.

## Update checks

`registryctl` checks GitHub releases at most once per day for normal
human-facing commands and prints an upgrade notice to stderr when a newer
release is available. It skips the automatic check in CI and while running
`registryctl doctor` so JSON output stays quiet.

Run an explicit check at any time:

```sh
registryctl update-check
```

Disable automatic checks with `REGISTRYCTL_NO_UPDATE_CHECK=1` or
`REGISTRYCTL_UPDATE_CHECK=0`.

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

The generated project uses the digest-pinned Registry Relay image recorded in
the matching registryctl release image lock, not a floating image tag. The
source tutorial gate builds registryctl and the product images from the same
checkout, places a strict test lock beside the binary, rebinds the generated
project to those local images, and executes both reader tutorials. With Docker
and the docs dependencies available, run:

```sh
cd docs/site
npm ci
npm run check:tutorial:registryctl
```
