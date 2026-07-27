# registryctl

`registryctl` is the local adopter CLI for Registry Stack.

The latest published Registry Stack release is
[v0.13.0](https://github.com/registrystack/registry-stack/releases/tag/v0.13.0).
Use its [versioned documentation](https://docs.registrystack.org/v/0.13.0/)
and exact release assets. The spreadsheet onboarding flow described in this
source tree is unreleased. No published Registryctl currently supports it, so
do not substitute a repository checkout or source build for a released
adopter path.

The next release is intended to support the complete local beginner runtime
on Linux x86_64. Its Linux arm64 and macOS arm64 assets are intended for CLI
authoring, validation, and build tasks only because the candidate image lock
does not advertise those hosts for the complete runtime. Intel macOS and
Windows remain unsupported.

Interactive report commands print concise human-readable results. Add `--format json` when
another program needs a versioned report. Artifact and protocol commands, including authoring
schemas, editor metadata, the language server, and logs, retain their native output formats.

The initialization report identifies the project root and supported generated
entry points. Automation must use the versioned JSON report rather than
hard-code the local tutorial's generated directory layout, which remains an
implementation detail.

`registryctl doctor` calls the product-owned Relay validator through the
digest-pinned Docker Compose v2 service, so no host Relay binary is required.
It validates the authored project, complete workbook, generated product input,
closed runtime, and required provider while redacting local secret values. Add
`--format json` when another program needs the versioned diagnostic report.

The final-form next-release walkthroughs are retained as an unreleased,
digest-bound CI preview. They are not production documentation and must not
be presented as published until matching CLI, installer, image-lock, and docs
artifacts exist.

## Registry Stack project authoring

Start from a built-in Registry Stack project starter, run its closed offline
fixtures, inspect the redacted generated plan, and build deterministic Relay
and Notary inputs. Available starters are `spreadsheet`, `http`,
`dhis2-tracker`, `opencrvs-dci`, `fhir-r4`, and `snapshot`:

```sh
registryctl init --from http --project-dir registry-project
registryctl authoring editor --project-dir registry-project
registryctl test --project-dir registry-project
registryctl check --project-dir registry-project --environment local --explain
registryctl build --project-dir registry-project --environment local
```

Initialization copies the five schemas embedded in `registryctl`, configures project-relative VS
Code and Zed schema mappings, and reports the generated editor manifest. The explicit
`authoring editor` command verifies the setup and safely refreshes an unchanged generated bundle
after an upgrade. Starter initialization validates the starter and editor setup in private staging
before publishing project files, so editor failure leaves the destination untouched. JSON init
requires a UTF-8 destination, validated before an initializer runs or writes project files.

The authoring contract accepts one to eight exact selector inputs and up to
sixteen typed inputs in total. Canonical selectors have a fixed 4096-byte
aggregate ceiling. Input names match `[a-z][a-z0-9_]{0,63}` and use a bounded
scalar JSON Schema subset. Credentials are fixed interfaces whose values
remain environment-only secret references. `check` and `build` compile the
generated closure with the validators for the selected Relay-only, Notary-only,
or combined deployment. `test` additionally executes deterministic,
request-aware source fixtures without granting fixture YAML network,
credential, filesystem, or worker authority.

When `check` finds invalid authoring, it reports independent problems together
with stable diagnostic codes and normalized project-relative files. JSON and
human output contain the same typed diagnostics. Syntax diagnostics include a
safe 1-based location and authoring-schema command when available. Script
diagnostics can include a static released-signature suggestion. Diagnostics do
not echo YAML values, source origins, secret references, fixture observations,
or Script arguments. Safe missing entity and integration references aggregate.
Unsafe paths, symlinks, oversized files, and files that cannot be safely
inspected stop later inspection. The same boundary check covers every
environment YAML file included in the project digest, even when that
environment is not selected. Any diagnostic prevents compilation, generated
product validation, fixture execution, and build output.

Treat generated Relay and Notary configuration as build output, not as another
authoring surface. `registryctl` diagnostics apply to the project sources that
produced that output. Hand-editing compiled configuration is unsupported and
has no project-level diagnostic path; change the project and regenerate it.

`script` uses the release-gated Rhai v1 authoring ABI. Its offline conformance
fixtures use the isolated implementation-owned worker harness, and deployment
uses the same fixed source authority, budgets, and reviewed script closure.
Source product and version remain optional interoperability evidence; they do
not select the Rhai runtime, source operations, or executor.
`test --live` requires an explicit non-production environment and uses only the
governed deployed Notary path. It never contacts a source registry directly.

An environment can set `notary_cel.worker_memory_bytes` when its dedicated CEL
workers need a platform-specific process limit. The Notary default remains
128 MiB. The maximum 1 GiB value supports emulated local runtimes and is a
per-worker data/address-space ceiling, not reserved memory.

Download the versioned installer from the same pinned release whose assets it
will install:

```sh
tag=vX.Y.Z
curl -fsSLO "https://github.com/registrystack/registry-stack/releases/download/${tag}/registryctl-${tag}-install.sh"
bash "./registryctl-${tag}-install.sh"
```

The versioned filename selects the same release by default. An explicit
`REGISTRYCTL_VERSION` must match that release unless a release operator is
performing a separately verified compatibility check.

The unreleased v0.14.0 candidate is designed to contain prebuilt Registryctl
binaries for Linux x86_64, Linux arm64, and macOS arm64. Do not treat those
assets as published until the release page contains the exact installer,
binaries, image lock, checksums, signatures, and provenance. The complete
local beginner runtime is release-gated on Linux x86_64 only because the
candidate image lock binds Linux amd64 images. Linux arm64 and macOS arm64 are
authoring, validation, and build platforms. Intel macOS and Windows have no
planned prebuilt v0.14.0 binary. Use Linux x86_64 for the beginner runtime
after the matching release is published instead of building the tool from
source.

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

Existing local tutorial projects do not need the lock for `start`, `stop`,
`status`, or other runtime commands. Those commands use the immutable image
references already written into the project. A later `init` or `add` is a
generation operation and requires the lock for that registryctl version.

## Update checks

`registryctl` checks GitHub releases at most once per day for normal human-facing commands and
prints an upgrade notice to stderr when a newer release is available. It skips the automatic check
in CI and while running `registryctl doctor`, so doctor diagnostics are not accompanied by an
update notice.

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
the matching Registryctl release image lock, not a floating image tag. The
source tutorial gate builds Registryctl from the checkout, places a strict
generation-only test lock beside it, and verifies the canonical spreadsheet
initializer, fixtures, preflight, explanation, and deterministic product
build. The release-candidate workflow separately executes the exact sealed
installer and runtime journey without rewriting image references. With the
docs dependencies available, run:

```sh
cd docs/site
npm ci
npm run check:tutorial:registryctl
```
