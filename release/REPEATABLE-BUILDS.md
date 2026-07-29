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
   release image lock.
3. Rebuilds the canonical Linux payload with fresh Cargo and target
   directories.
4. Requires byte equality for the six Linux amd64 payloads.
5. Rebuilds Registry Notary and Registry Relay images without cache.
6. Compares image configuration and ordered root filesystem layers with the
   published digest-bound images.
7. Records a compact result and retains it for 30 days.

The proof excludes native macOS and Linux arm64 Registryctl binaries,
environment independence, generated SBOM or scan bytes, signatures,
provenance envelopes, and documentation archives.

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
| Published checksum or image lock fails authentication | Follow the security reporting process in `SECURITY.md` |
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
