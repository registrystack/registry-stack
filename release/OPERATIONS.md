# Operate a Registry Stack release

The active release path uses one release PR, one private candidate, and one
annotated tag. It promotes candidate bytes and image manifests without
rebuilding them. The workflow never creates or pushes a Git ref.

## Prerequisites

Start release preparation only when:

- Protected-main CI is green.
- The intended release source and release-control changes are already on
  `main`.
- The exact workflow revision has a successful
  `.github/workflows/release-canary.yml` run from the preceding 24 hours.
- The release version, GitHub Release destination, and final image tags are
  unused.

The canary runs nightly and supports manual dispatch:

```sh
gh workflow run release-canary.yml \
  --repo registrystack/registry-stack \
  --ref main
```

A workflow, build recipe, packaging, scanner policy, signing, provenance, or
trust-anchor change invalidates the previous canary. Run the revised canary and
wait for it to pass before opening the release PR.

## Release clock

The release clock starts when the release PR opens from a branch whose
prerequisites are green. The hard service-level objective is 120 minutes
through successful production documentation smoke.

Do not change the release system after the clock starts. Stop the train if a
release-system defect appears. Fix and canary the release system outside the
release PR, then prepare a new release attempt.

## Prepare one release PR

Start from current protected `main`:

```sh
git fetch origin main
git switch -c release/v<version> origin/main

release/scripts/registry-release prepare \
  --version <version> \
  --release-id <release-id>
```

Review and commit the generated version, lockfile, changelog, release-note,
manifest, and docs metadata changes. The manifest and docs metadata use the
stable release identity, not a future merge commit.

The release PR contains no release-workflow or release-tool implementation
changes. Merge the release PR after its protected checks pass. Its squash
commit is the candidate source and future tag target. There is no finalization
or closeout PR.

## Request and verify one candidate

Resolve the release PR's merge commit and request the candidate:

```sh
git fetch origin main
source_sha="$(git rev-parse origin/main)"

release/scripts/registry-release request-candidate \
  --version <version> \
  --release-id <release-id> \
  --source-sha "${source_sha}"
```

The candidate workflow rejects malformed identity, failed source CI, missing
or stale canary evidence, invalid manifests or pins, and occupied destinations
before build work starts.

The successful candidate:

- Builds each Linux payload, additional Registryctl platform, OCI image, and
  docs archive once.
- Publishes candidate images only to the private
  `registry-notary-candidate` and `registry-relay-candidate` packages.
- Scans exact candidate digests and enforces the advisory decision.
- Runs the exact Linux candidate Registryctl binary through the offline HTTP,
  OAuth and Rhai, and synthetic OpenCRVS authoring journeys using the exact
  extracted candidate docs archive.
- Seals one 24-hour candidate bundle and one
  `registry-stack.release-candidate.v2` manifest.
- Attests both candidate files after an independent byte recheck.

The candidate does not install Registryctl, accept a signed
`RegistryReleaseLockV1`, or run Docker. Those release-identity and runtime
proofs require the immutable tag and run in the tag-triggered release workflow
before publication.

Use the successful candidate run ID for local verification:

```sh
release/scripts/registry-release verify-candidate \
  --version <version> \
  --release-id <release-id> \
  --candidate-run <run-id>
```

The command verifies source ancestry, workflow and canary identity,
attestations, bundle contents, payload hashes, image digests, docs, Software
Package Data Exchange (SPDX) software bill of materials (SBOM), scans, and the
advisory verdict. It also checks that public destinations remain absent.

On success, the command prints the exact annotated tag command. Run that
command without editing its message, inspect the tag, and push only that ref:

```sh
tag=v<version>
git show "${tag}"
git push origin "refs/tags/${tag}"
```

The annotation binds the candidate run, attempt, and manifest SHA-256. The tag
object is annotated but is not cryptographically signed.

## Public promotion

The tag-triggered workflow:

1. Revalidates the tag, candidate, source ancestry, attestation, expiry, and
   canary.
2. Creates a nonpublic draft GitHub Release and uploads exact candidate
   payloads.
3. Generates `SHA256SUMS`, one Sigstore checksum bundle, consolidated SPDX
   SBOM, security-evidence archive, image lock, and tag-bound SLSA provenance.
4. Downloads and reconciles the complete draft inventory before a public
   write.
5. Rechecks candidate expiry and final image destinations.
6. Promotes each private candidate image manifest to its final tag at the same
   digest.
7. Creates and verifies the tag-bound signed `RegistryReleaseLockV1`, runs the
   exact installer, and proves the full first-country Docker lifecycle against
   the promoted images.
8. Publishes the reconciled draft.
9. Dispatches `docs-pages.yml` with the exact release tag and docs SHA-256.

The docs workflow authenticates the published archive, promotes it to `/` and
`/v/<version>/`, builds `/dev/` from protected `main`, deploys one Pages
artifact, and runs production smoke.

Release completion requires the GitHub Release, exact final image digests, and
live smoke for `/`, a deep canonical route, `/dev/`, `/v/<version>/`, search,
`sitemap.xml`, `llms.txt`, and current machine-readable docs.

## Failure handling

| Failure state | Response |
| --- | --- |
| Pure validation failure | Fix source or metadata, then request a new candidate |
| Candidate infrastructure failure before sealing | Rerun the candidate workflow |
| Candidate byte, recipe, scan, or advisory change | Build a new candidate |
| Unchanged candidate, draft-stage failure, and candidate remains unexpired | Retry the tag workflow against the same nonpublic draft or recreate that exact draft |
| Release-system defect | Stop, fix outside the release PR, pass a new canary, and restart |
| Any failure after a final image tag or GitHub Release becomes public | Burn the version and patch forward |
| Pages failure with the same authenticated docs bundle | Retry Pages for the same released tag |
| Repeatability, Scorecard, telemetry, hosted, or announcement failure | Record follow-up work; do not change the public release result |

Never retag, replace a public asset, overwrite a final image tag, or delete a
published release to retry.

## Asynchronous controls

The following controls run outside ordinary publication:

- Weekly or manually dispatched clean repeatability proof.
- Scheduled OpenSSF Scorecard.
- CodeQL, dependency, and image monitoring.
- Extended provenance review.
- Historical docs sweeps.
- Solmara or hosted proof unless the release announcement advertises that
  environment.
- Storage telemetry, retrospective, and announcement work.

Reactivate an asynchronous control as a release blocker only for a named
threat or consumer. Record the invariant, owner, duration, and removal
condition before adding it to the release clock.

Candidate Actions artifacts are retained for seven days, but candidate
promotion validity is 24 hours. The daily cleanup workflow removes older
private candidate package versions. It cannot target public package names.
