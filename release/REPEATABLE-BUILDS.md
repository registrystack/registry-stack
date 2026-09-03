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
