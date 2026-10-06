# Operate and use the nightly release channel

The nightly channel publishes evaluation builds from protected `main` after the
exact source commit passes protected-main CI. A failed build leaves the channel
on its last successful build. Use a numbered release for a production deployment.

## Understand the nightly identity

Each successful nightly build has one immutable tag:

```text
v<base>-nightly.<YYYYMMDD>.<full-40-character-source-SHA>
```

`<base>` is the canonical numbered version in the source tree. `YYYYMMDD` is the
UTC build date, and the final component is the complete Git commit SHA built by
the workflow. The binaries report the same prerelease version without the tag's
leading `v`, so a log or `--version` result identifies both the build date and
source without consulting the channel pointer.

The nightly version marker is compiled into the binaries and container images.
A numbered release therefore rebuilds its artifacts with the numbered version
marker; release publication cannot promote or relabel nightly bytes.

The channel publishes:

- An immutable GitHub prerelease with the native binary shards, installers,
  `SHA256SUMS`, image scan and software bill of materials evidence, and that
  build's `nightly.json`.
- GitHub build provenance for every file in the prerelease.
- Immutable tags on the existing public Registry Stack container packages.
- A `nightly.json` pointer on the `nightly-channel` branch, advanced by a new
  commit only after the release assets and container images pass publication
  verification.

Current manifests use `registry-stack.nightly.v2` with the frozen
`registry-stack.nightly-roster.v2.0` profile. That profile names the complete
image, installer, and binary payload roster; a source change cannot redefine an
older manifest by recomputing its inventory. An incompatible inventory requires
a new schema and profile. The reader still accepts frozen
`registry-stack.nightly.v1` manifests, including historical v0.39.0 nightlies
that carried Relay, so an existing channel head can be reconciled and advanced
without rewriting published bytes.

The channel does not publish npm packages, PyPI packages, or a documentation
site. Use the source documentation at the nightly commit when behavior differs
from the latest numbered release. The `nightly-channel` branch contains
generated channel state; it is not a source or release branch.

Linux amd64 is the canonical build platform and contains every current release
binary group. Linux arm64 contains the binaries supported for that platform by
the current release inventory. macOS arm64 uses the current native release
shards, including each binary's adjacent libraries and notices where the shard
is an archive. Each installer installs the toolset its platform publishes in
that build. The Registry Scheduling runtime is published for Linux amd64 only,
so on Linux arm64 and macOS arm64 the Scheduling installer installs
`schedulingctl` alone. An installer exits without changing the install directory
when its operating system or architecture has no asset in that build.

## Install the latest successful nightly

Use an installer from source when selecting a channel. With no channel or build
argument, a source installer resolves the latest numbered release. The four
nightly-aware installers are:

| Toolset | Source installer | Install directory variable | Verified asset directory variable |
| --- | --- | --- | --- |
| Base Registry Engine | `crates/registry-breg/install.sh` | `BREG_INSTALL_DIR` | `BREG_ASSET_DIR` |
| Evidence authoring | `crates/registry-evidencectl/install.sh` | `EVIDENCECTL_INSTALL_DIR` | `EVIDENCECTL_ASSET_DIR` |
| Registry Casework | `crates/registry-casework/install.sh` | `CASEWORK_INSTALL_DIR` | `CASEWORK_ASSET_DIR` |
| Registry Scheduling | `crates/registry-scheduling/install.sh` | `SCHEDULING_INSTALL_DIR` | `SCHEDULING_ASSET_DIR` |

`--channel nightly` resolves
`https://raw.githubusercontent.com/registrystack/registry-stack/nightly-channel/nightly.json`.
`--build '<tag>'` resolves
`https://github.com/registrystack/registry-stack/releases/download/<tag>/nightly.json`
instead.

For example, install the latest successful Evidence nightly:

```sh
curl -fsSL https://raw.githubusercontent.com/registrystack/registry-stack/main/crates/registry-evidencectl/install.sh | bash -s -- --channel nightly
```

Replace the installer path with another row from the table to install that
toolset. Replace `| bash` with `| less` if you want to inspect the source
installer before running it.

The source installer resolves the `nightly-channel` pointer once and verifies
the immutable installer named by that build against its `nightly.json` entry.
The pinned installer then downloads the toolset its platform publishes,
verifies every asset against `SHA256SUMS`, and installs all of those binaries or
none of them. A scheduled or
manual build failure does not change what `--channel nightly` resolves.

An installer downloaded from a numbered GitHub release remains pinned to that
release. It refuses `--channel`, `--build`, or a conflicting version environment
variable, which prevents a frozen release installer from silently selecting
movable state.

## Install one immutable nightly build

Pass the full nightly tag to reproduce a known build without following the
channel pointer:

```sh
curl -fsSL https://raw.githubusercontent.com/registrystack/registry-stack/main/crates/registry-evidencectl/install.sh | bash -s -- --build '<tag>'
```

The installer downloads that prerelease's checksum-covered `nightly.json`
rather than consulting the channel branch. Keep the complete tag in deployment
records. A date alone does not identify a build because more than one source
commit can exist on the same UTC date.

Container deployments use the same immutable nightly tag on the product's
existing package:

```text
ghcr.io/registrystack/<product>:<tag>
```

Resolve and record the container digest before deployment. The tag is
immutable, while the digest is the registry identity that deployment tooling
can pin directly. The workflow does not publish a mutable `:nightly` container
tag. Select the immutable tag or digest recorded in `nightly.json`.

## Verify a nightly build

The installers verify downloaded bytes against `SHA256SUMS`. This detects a
corrupt or mismatched download, but a checksum obtained from the same release is
an integrity check, not proof that Registry Stack published the bytes.

For higher assurance, download the build into a fresh directory, authenticate
each file you intend to use, then verify those files against `SHA256SUMS`:

```sh
tag='<tag>'
mkdir "verify-${tag}"
cd "verify-${tag}"
gh release download "${tag}" --repo registrystack/registry-stack

artifact='<downloaded-file>'
gh attestation verify "${artifact}" \
  --repo registrystack/registry-stack \
  --signer-workflow registrystack/registry-stack/.github/workflows/nightly-release.yml \
  --signer-digest '<source-commit-SHA>' \
  --source-ref refs/heads/main \
  --source-digest '<source-commit-SHA>' \
  --deny-self-hosted-runners

sha256sum --check --strict --ignore-missing SHA256SUMS
```

Use the source SHA recorded for the immutable build for both digest flags. The
nightly workflow runs from the exact `main` commit that it builds, so the signer
workflow revision and source revision must be identical. Run the attestation
command for `nightly.json`, `SHA256SUMS`, the installer, and every binary or
archive you will use. Confirm that every asset your installation needs appears
among the files reported as checksum verified: `--ignore-missing` permits
assets for other platforms to remain absent.

Each successful attestation authenticates the file's digest, repository,
signer workflow, workflow revision, source branch, and source commit. The
checksum command separately checks the release inventory and detects missing or
mismatched bytes. The attested `nightly.json` also records every published
container digest, binding the image inventory to the same workflow and source.

Install from the verified directory so the installer does not download another
copy. For Evidence, run the downloaded immutable installer:

```sh
EVIDENCECTL_ASSET_DIR="$PWD" bash "./evidencectl-${tag}-install.sh"
```

Use the asset-directory variable from the installer table for another toolset.

## Run the nightly workflow

The `RegistryStack Nightly Release` workflow starts one scheduled attempt each
day. A manual dispatch has no source or version inputs and is accepted only from
`main`; it can run between scheduled attempts. Every attempt uses the exact
commit that contains the workflow definition. Before building, the workflow
requires the successful protected-main CI run for that same commit. It skips a
source commit already recorded as a successful nightly instead of publishing a
second identity for unchanged source.

Nightly image publication rejects an unknown vulnerability severity and a
vulnerability database more than three days old. It rejects a High or Critical
finding unless the reviewed release baseline for that image,
`release/security/<image>-advisory-baseline.json`, holds a current exception for
the same vulnerability, package, and installed version at the same severity, and
the scanner reports no fix. An exception is current from its review date through
its expiry date, both read as UTC dates. The check refuses a High or Critical
finding the scanner reports more than once, and one that does not name its
vulnerability, package, and installed version.

The release advisory checker loads the baseline. A baseline it cannot load
blocks that image, including when the scan has no High or Critical finding. An
image with no baseline file has no reviewed exceptions.

A nightly reuses the reviewed decision about a package version, not the proof a
numbered release requires. A release also proves that its candidate image has
the reviewed layers, process contract, and file digests. The nightly bytes
differ from the reviewed release bytes, so that proof cannot hold for a nightly
image and the nightly check does not claim it.

That gap is real exposure, not a formality. A reviewed exception often rests on
the image's executables not reaching the vulnerable code, and that was judged
against the release image. The nightly check does not judge it again. A nightly
can change an executable so that it reaches the vulnerable code, and the check
still admits the finding until the exception expires. Do not run a nightly
image where an excepted vulnerability would matter; use a numbered release.

A new finding, a changed package version, a changed severity, an available fix,
or an expired exception blocks publication until the finding is fixed or the
release baseline is reviewed again. The workflow has no bypass input, and a
first run is not guaranteed to publish.

For a normal run:

1. Confirm protected-main CI succeeded for the current `main` commit.
2. Run the `RegistryStack Nightly Release` workflow from `main`, or let the daily schedule run.
3. Confirm every required platform shard and container image completed.
4. Confirm the GitHub prerelease is public, remains marked as a prerelease, and
   can never become **Latest**.
5. Confirm the immutable assets against `SHA256SUMS` and verify the published
   provenance against the workflow and source commit.
6. Confirm every container tag resolves to the verified digest.
7. Confirm the new `nightly-channel` commit points to that exact tag, source,
   asset inventory, and image inventory.

The metadata commit is the final publication step. The workflow updates the
branch with a compare-and-swap check against the channel head it read; a stale
builder aborts instead of replacing a newer successful pointer. If any earlier
step fails, the workflow leaves the previous channel commit in place, so
adopters continue to resolve the last complete build.

## Recover an interrupted publication

If the `attest` or `publish` job fails after `prepare` succeeds, rerun the failed
jobs within the seven-day artifact retention window:

```sh
gh run rerun <run-id> --failed --repo registrystack/registry-stack
```

Those jobs use the recorded artifact names from their successful producers,
including the original run attempt. They retain the original tag, build date,
source commit, workflow commit, asset bytes, and image digests. Do not rerun all
jobs to recover a partial publication: rebuilding scan reports or binaries can
produce different bytes. For failures before `prepare` completes, start a fresh
manual dispatch after addressing the failure.

The workflow may accept
an existing asset or image tag only after proving that its digest exactly
matches the expected output. It may publish an absent image or an absent asset
while the GitHub Release remains a draft. A public prerelease with an incomplete
asset roster cannot be completed by retry; fix forward under a new identity.

Never delete or replace a published nightly asset to make a retry pass, never
overwrite a mismatched container tag, and never move the build tag. A mismatch
means the immutable identity is already occupied by different state. Leave the
channel pointer on its last successful build, diagnose the conflict, and fix
forward with a newer source or UTC date under a new nightly identity.

After a complete retry, perform the release, provenance, image, and channel
checks in [Run the nightly workflow](#run-the-nightly-workflow). Advancing
`nightly-channel` before those checks would expose a partial build to source
installers.
