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
4. Requires byte equality for the seven declared Linux amd64 binaries.
5. Rebuilds each release image without cache.
6. Compares its image configuration and ordered root filesystem layers with
   the published digest-bound image.
7. Records a compact result and retains it for 30 days.

The proof excludes native macOS and Linux arm64 Relayctl binaries,
environment independence, generated SBOM or scan bytes, signatures,
provenance envelopes, and documentation archives.

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
protobuf compiler packages needed by BReg's pinned SQL parser from a dated
Debian snapshot inside the pinned builder container. The source commit
therefore fixes both the builder image and the additional build packages
instead of consulting Debian's mutable package indexes.

## The C compiler, the linker, and the GNU libc floor

The same container carries the Zig cross-compiler, installed from the Python
index against the file hashes recorded in
`release/requirements/ziglang-0.12.1.txt`. Every product binary is compiled and
linked through it, targeting the GNU libc stubs of the floor in
`release/glibc-floor.env`, so a binary imports only symbol versions that exist
at the floor. Without it the builder's own much newer GNU libc decides the
requirement by accident: the binaries start inside the container and refuse to
start on a supported distribution.

The floor is a build input like the packages above. One source commit fixes the
builder image, the additional Debian packages, the C compiler and linker, and
the oldest GNU libc a published binary can start on. A change to the floor file
or to the pinned Zig file names a different builder image, because the local
builder tag is the hash of the recipe and of the files it installs from.

Before the payload is checksummed, `release/scripts/check-glibc-floor.sh` reads
every staged binary and fails the build when one requires a newer GNU libc than
the floor, or imports a strong symbol with no version at all. The three
published installer scripts refuse the same two cases before they download
anything, and carry the floor as a generated block written by
`release/scripts/render-installer-libc-preflight.py`.

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
