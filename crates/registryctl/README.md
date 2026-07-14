# registryctl

`registryctl` is the local adopter CLI for Registry Stack.

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

## Registry Stack project authoring

Start from a built-in Registry Stack project starter, run its closed offline
fixtures, inspect the redacted generated plan, and build deterministic Relay
and Notary inputs. Available starters are `http`, `dhis2-tracker`,
`opencrvs-dci`, `fhir-r4`, and `snapshot`:

```sh
registryctl init --from http --project-dir registry-project
registryctl test --project-dir registry-project
registryctl check --project-dir registry-project --environment local --explain
registryctl build --project-dir registry-project --environment local
```

The authoring contract accepts one to eight exact selector inputs and up to
sixteen typed inputs in total. Canonical selectors have a fixed 4096-byte
aggregate ceiling. Input names match `[a-z][a-z0-9_]{0,63}` and use a bounded
scalar JSON Schema subset. Credentials are fixed interfaces whose values
remain environment-only secret references. `check` and `build` compile the
generated closure with the validators for the selected Relay-only, Notary-only,
or combined deployment. `test` additionally executes deterministic,
request-aware source fixtures without granting fixture YAML network,
credential, filesystem, or worker authority.

`script` uses the release-gated Rhai v1 authoring ABI. Its offline conformance
fixtures use the isolated implementation-owned worker harness, and deployment
uses the same fixed source authority, budgets, and reviewed script closure.
Source product and version remain optional interoperability evidence; they do
not select the Rhai runtime, source operations, or executor.
`test --live` requires an explicit non-production environment and uses only the
governed deployed Notary path. It never contacts a source registry directly.

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
