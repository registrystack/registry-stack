# registryctl

`registryctl` is the local adopter CLI for Registry Stack.

The complete local beginner runtime is supported on Linux x86_64. Linux arm64
and macOS arm64 release assets support CLI authoring, validation, and build
tasks, but the current image lock does not advertise those hosts for the
complete runtime. Intel macOS and Windows are unsupported.

Install a pinned release without cloning this repo:

```sh
tag=vX.Y.Z
curl -fsSLO "https://github.com/registrystack/registry-stack/releases/download/${tag}/registryctl-${tag}-install.sh"
bash "./registryctl-${tag}-install.sh"
```

Executing this quick installer trusts GitHub and TLS. The installer then
verifies the downloaded binary and image lock against the release's
`SHA256SUMS`. It does not authenticate the installer, checksums, signatures,
or provenance. Use [`release/VERIFY.md`](../../release/VERIFY.md) to verify
release authenticity before installation.

Then create and start your first secured spreadsheet API:

```sh
registryctl init --from spreadsheet --project-dir my-first-api
cd my-first-api
registryctl doctor --profile local
registryctl start
registryctl smoke
```

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

For the full walkthroughs, use the Registry Docs tutorials:

- [Run a protected registry API locally](https://docs.registrystack.org/tutorials/publish-spreadsheet-secured-registry-api/)
- [Use your own spreadsheet](https://docs.registrystack.org/tutorials/use-your-spreadsheet/)
- [Evaluate your first registry-backed claim](https://docs.registrystack.org/tutorials/verify-claim-registry-api/)

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
When a project includes consultation profiles, the build emits separate
`private/relay-public` and `private/relay-consultation` signing inputs. Each contains
one primary `config/relay.yaml` plus only that runtime instance's artifacts,
operations, and secret-consumer descriptor. The matching Notary input remains
under `private/notary`.

When continuing from approved signed inputs, supply each generated runtime
instance through its matching baseline pair:

```sh
registryctl build \
  --project-dir registry-project \
  --environment local \
  --relay-against public-relay-bundle \
  --relay-anchor public-relay-anchor.json \
  --relay-consultation-against consultation-relay-bundle \
  --relay-consultation-anchor consultation-relay-anchor.json \
  --notary-against notary-bundle \
  --notary-anchor notary-anchor.json
```

Omit a pair only when that product input is absent from the project topology.
The earlier v1-v3 combined Relay closure cannot prove independent lineage for
the split public and consultation inputs. Re-review that project and sign both
new Relay inputs before continuing its approved baseline.

OAuth client-credentials integrations select one exact token-response shape
with `source.auth.response_profile`:

| Profile | Accepted response | Freshness behavior |
|---|---|---|
| `oauth2_bearer` | Exactly `access_token`, case-sensitive `token_type: Bearer`, and bounded `expires_in` | Relay may cache only within the compiled expiry bound and safety skew. |
| `oauth2_bearer_no_expiry` | Exactly `access_token` and case-sensitive `token_type: Bearer` | Relay disables token caching. It acquires a token for the current bounded consultation and does not retain it for another consultation. |

Choose `oauth2_bearer_no_expiry` only when the token endpoint does not return
`expires_in`. It rejects an expiry member, extra members, and `refresh_skew`.
Registryctl does not infer expiry from unverified token contents. Both profiles
retain the same host-owned credential, destination, TLS, SSRF, response-size,
and fail-closed source-dispatch boundaries.

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

Prebuilt Registryctl binaries are published with each stack release for Linux
x86_64, Linux arm64, and macOS arm64 when that release is cut. The complete
local beginner runtime is supported and release-gated on Linux x86_64 only
because the release image lock currently binds Linux amd64 images. The Linux
arm64 and macOS arm64 binaries support CLI authoring, validation, and build
tasks, but are not advertised for the complete local runtime. Intel macOS and
Windows have no prebuilt binary. Use Linux x86_64 for the beginner runtime
instead of building the tool from source.

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
