# Repeatable build evidence

Registry Stack tests repeatability after publication. The scheduled proof is
an assurance control, not part of the ordinary release transaction.

## Current proof

`.github/workflows/release-repeatability.yml` runs weekly and supports manual
dispatch. The scheduled run selects the newest published semantic-version
release. A manual run can select an exact public tag:

```sh
gh workflow run release-repeatability.yml \
  --repo registrystack/registry-stack \
  --ref main \
  -f tag=v<version>
```

The workflow:

1. Resolves an immutable published tag reachable from protected `main`.
2. Downloads and authenticates `SHA256SUMS`, the Linux amd64 binaries, and the
   release manifest.
3. Rebuilds the canonical Linux payload with fresh Cargo and target
   directories.
4. Requires byte equality for every Linux amd64 binary declared by the selected
   release manifest.
5. Rebuilds each release image without cache.
6. Compares its image configuration and ordered root filesystem layers with
   the published digest-bound image.
7. Records a compact result and retains it for 30 days.

The proof excludes native macOS and Linux arm64 Relayctl binaries,
environment independence, generated SBOM or scan bytes, signatures,
provenance envelopes, and documentation archives. Starting with v0.33.0, that
macOS exclusion covers each complete native archive: the executable, relocated
AWS-LC-FIPS shared libraries, notices, ad hoc signatures, and archive bytes.
The candidate build verifies that packaged closure, but the scheduled Linux
AMD64 proof makes no macOS repeatability claim.

## Release build marker

`release/scripts/build-release-binaries.sh` sets `REGISTRY_RELEASE_TAG` to the
exact release tag. That marker is what makes an executable report the bare
released version, such as `relayctl 0.19.0`. A build without it reports a
development version, such as `relayctl 0.19.0-dev`, so an executable built from
the same source revision outside the release cannot be mistaken for the
published one.

A rebuild must therefore go through that script, as this workflow does.
`cargo build --release` over the same source produces a development version and
different bytes, which is a different build rather than a failed reproduction.

For releases that include BReg, the script installs the exact libclang and
protobuf compiler packages needed by BReg's pinned SQL parser, plus the exact
cmake and Go packages needed to build `aws-lc-fips-sys`, the FIPS cryptography
backend the runtimes link, from a dated Debian snapshot inside the pinned
builder container. The source commit therefore fixes both the builder image
and the additional build packages instead of consulting Debian's mutable
package indexes.

The native macOS builder uses the hosted runner's CMake and explicitly installs
Go 1.24.4 for `aws-lc-fips-sys`. From v0.33.0 it preserves the resulting shared module,
relocates each executable's loader commands to the adjacent packaged dylibs,
signs the changed Mach-O files, and creates one deterministic archive per
executable. Those steps define the supported macOS release payload, but they
remain outside the Linux-only repeatability proof above.

## The source tree, not the checkout

A release binary must be a function of the source tree. Four crates in the lock
run `git rev-parse HEAD` in their build script and bake the answer into what
they compile: `wasmtime-internal-cache` keys its module cache on the full
commit, `cranelift-codegen` writes `0.135.2-<first nine>` into its `VERSION`
constant, `typst-utils` records `TYPST_COMMIT_SHA`, and `wasm-bindgen-shared`
records the first nine characters as `WBG_VERSION`. Each is meant to read that
crate's own development checkout. The first two reach a released binary today,
through the WebAssembly action executor the Base Registry Engine enables from
v0.33.0; the other two are in the lock but not in any release asset.

The canonical builder mounts the repository at `/workspace` and puts
`CARGO_HOME` inside it, so those build scripts resolved this repository instead
and recorded the commit being released. The scheduled proof above cannot see
that: it rebuilds one published tag, where the commit is identical on both
sides. What it breaks is the image advisory baseline, whose reviewed layer
digests are recorded in one commit and compared against the candidate built
from the next one. Those can never match, so the fingerprint assertion stops
converging and no renewal of it can succeed.

`release/scripts/build-release-binaries.sh` therefore runs the container with
`GIT_CEILING_DIRECTORIES=/workspace`. Repository discovery stops at the mount
point, which reaches every build script because Cargo runs them below the
repository root and the ceiling does not apply only to Cargo's own working
directory. Each of the four crates then takes the fallback it already has for a
packaged build. The inner invocation refuses to build a payload without the
ceiling, so it is part of the canonical container contract rather than a
setting a caller may drop.

Before the payload is checksummed, the same script reads every staged binary
back and fails the build when one still contains the exact source commit. That
is a regression check for a path the ceiling does not cover, such as a build
script that names the repository directory itself. It matches the full commit
only, so a build script that embeds an abbreviation alone passes it and is
caught by the ceiling instead.

## The C compiler, the linker, and the GNU libc floor

The same container carries the Zig cross-compiler, installed from the Python
index against the file hashes recorded in
`release/requirements/ziglang-0.12.1.txt`. Every product binary is compiled and
linked through it, targeting the GNU libc stubs of the floor in
`release/glibc-floor.env`, so a binary imports only symbol versions that exist
at the floor. Without it the builder's own much newer GNU libc decides the
requirement by accident: the binaries start inside the container and refuse to
start on a supported distribution.

The floor is a build input, but it does not name the builder image the way the
packages above do. `release/scripts/build-release-binaries.sh` reads
`release/glibc-floor.env` fresh at the start of every build instead of baking
it into the image, so a floor change reuses the same builder image and takes
effect through the file it reads. The local builder tag is the hash of
`release/docker/Dockerfile.builder` and the pinned Zig requirements file only;
changing either of those names a different image, changing the floor does
not. The Cargo and target-directory caches in the release workflows hash the
floor file alongside those same recipe inputs, so a floor change still
invalidates a cached build instead of silently reusing binaries built to the
older contract.

Before the payload is checksummed, `release/scripts/check-glibc-floor.sh` reads
every staged binary and fails the build when one requires a newer GNU libc than
the floor, or imports a strong symbol with no version at all. The three
published installer scripts refuse the same two cases before they download
anything, and carry the floor as a generated block written by
`release/scripts/render-installer-libc-preflight.py`.

The arm64 path reaches the same floor differently. Instead of cross-compiling
through Zig, it builds natively on a runner already pinned to the floor's GNU
libc (`ubuntu-22.04-arm`, glibc 2.35), and a dedicated workflow step runs
`check-glibc-floor.sh` over the produced binaries before they reach the
payload.

### Local observation on Apple Silicon

Two complete payload builds of 0.26.1 ran on one Apple Silicon workstation
through the emulated `linux/amd64` builder, each with its own Cargo home and
its own target directory. All ten staged Linux amd64 binaries and all five
container binaries matched byte for byte between the two runs. The Zig cache
directory differs between runs because it sits inside the temporary wrapper
directory the build removes on exit, so the equality also shows that path does
not reach the output.

A third build of the same payload ran natively on aarch64. Its binaries are
aarch64 and are not comparable with the amd64 payload; what it shows is that
the floor selection and the gate work on the second published architecture.
Registry Manifest does not compile for aarch64, so that one slot was left out
of the aarch64 run.

The scheduled workflow above remains the proof of record. It builds
`linux/amd64` only, so nothing observed here extends repeatability to arm64.

## OpenSSF Silver claim boundary

The OpenSSF `build_repeatable` answer is supportable only while the latest
applicable repeatability workflow completed successfully within the preceding
30 days.

A failed run, or no successful applicable run in 30 days, makes the
repeatable-build justification stale. Update the public badge answer or
justification until a fresh clean proof passes. The stale or failed result
does not change an already published release and does not block an ordinary
release.

Check the public workflow history:

```sh
gh run list \
  --repo registrystack/registry-stack \
  --workflow release-repeatability.yml \
  --limit 30
```

For a claim review, record the successful run URL, tested tag, completion
time, result artifact SHA-256, and `silver_claim_valid_through` timestamp from
`release-repeatability-result.json`.

## Failures

| Failure | Action |
| --- | --- |
| Binary bytes differ | Treat as a build-integrity investigation; preserve both inventories |
| Image configuration or ordered layers differ | Compare builder, recipe, base image, and lock changes |
| Published checksum or release manifest fails authentication | Follow the security reporting process in `SECURITY.md` |
| Runner or registry outage | Rerun without changing the published release |
| Proof becomes older than 30 days | Mark the OpenSSF repeatability justification stale until a new proof passes |

Reactivating duplicate builds in the release-blocking path requires a named
consumer or build-integrity threat, an owner, a duration, and a removal
condition.

## Historical evidence

Older entries in Git history record manual or release-coupled proofs, including
the former preparation-commit and tag-target model. Those records remain
historical evidence for their named tags. They are not the active release
procedure and do not extend the current 30-day Silver claim boundary.
