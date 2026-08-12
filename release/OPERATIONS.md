# Operate a Registry Stack release

Registry Stack is pre-1.0 Beta software for self-hosted institutional pilots.
An ordinary Beta release protects the exact source, shipped bytes, image
digests, applicable vulnerability decision, and first-run path. It does not
repeat every 1.0-readiness exercise.

The active path uses one release PR, one private candidate built from protected
`main`, one annotated tag, and one publication dispatch from protected `main`.
Publication promotes the candidate bytes and image manifests without rebuilding
them. A normal release should need less than 15 minutes of operator time and
less than one hour elapsed, dominated by the candidate build.

## Prerequisites

Start release preparation when:

- Protected-main CI is green.
- The intended release source and release-control changes are already on
  `main`.
- The release version, GitHub Release destination, and final image tags are
  unused.
- Each final GHCR package is public and grants this repository's Actions
  workflow write access.

The scheduled release canary is useful maintenance telemetry, but it is not a
Beta release prerequisite.

For the first release under a new image package name, provision the package
once before requesting the candidate. GitHub creates a first-published
container package as private, so publish a clearly non-release bootstrap
artifact without putting a token on the command line:

```sh
bootstrap_dir="$(mktemp -d)"
printf 'Registry Stack Relay package bootstrap\n' \
  > "${bootstrap_dir}/bootstrap.txt"
printf '%s' "${GHCR_BOOTSTRAP_TOKEN:?set a classic PAT with write:packages}" \
  | oras login ghcr.io \
      --username "${GHCR_BOOTSTRAP_USER:?set the PAT owner}" \
      --password-stdin
oras push \
  --artifact-type application/vnd.registrystack.package-bootstrap.v1 \
  --annotation \
    org.opencontainers.image.source=https://github.com/registrystack/registry-stack \
  ghcr.io/registrystack/relay:bootstrap \
  "${bootstrap_dir}/bootstrap.txt:text/plain"
```

In the organization package settings, change only `relay` to public and grant
`registrystack/registry-stack` Actions access with Write. Verify the resulting
metadata before candidate dispatch:

```sh
gh api /orgs/registrystack/packages/container/relay \
  --jq '[.name,.package_type,.visibility]'
```

The result must be `["relay","container","public"]`. Keep the bootstrap
version until the first real version is public, then remove only that bootstrap
version. This is a package-identity setup step, not part of later releases.

## Prepare one release PR

Start from current protected `main`:

```sh
git fetch origin main
git switch -c release/v<version> origin/main

release/scripts/registry-release prepare \
  --version <version> \
  --release-id <release-id>
```

Review and commit the version, lockfile, changelog, release-note, manifest, and
generated contract changes reported by the planner. Do not mix release-workflow
or release-tool implementation changes into this PR. Merge after the protected
checks pass. The merge commit is the intended candidate source. The exact
protected-main revision accepted by `request-candidate` becomes the candidate
source and future tag target. There is no finalization or closeout PR.

Before opening the release PR, push the prepared branch and run the read-only
Ubuntu rehearsal from that branch:

```sh
rehearsal_branch="$(git branch --show-current)"
rehearsal_request_id="$(openssl rand -hex 16)"
gh workflow run release-rehearsal.yml \
  --repo registrystack/registry-stack \
  --ref "${rehearsal_branch}" \
  -f version=<version> \
  -f release_id=<release-id> \
  -f request_id="${rehearsal_request_id}"

rehearsal_run=""
for _ in $(seq 1 30); do
  rehearsal_run="$(
    gh run list \
      --repo registrystack/registry-stack \
      --workflow release-rehearsal.yml \
      --branch "${rehearsal_branch}" \
      --event workflow_dispatch \
      --limit 100 \
      --json databaseId,displayTitle \
      --jq ".[] | select(.displayTitle | endswith(\"(${rehearsal_request_id})\")) | .databaseId"
  )"
  test -z "${rehearsal_run}" || break
  sleep 2
done
test -n "${rehearsal_run}"
gh run watch "${rehearsal_run}" \
  --repo registrystack/registry-stack \
  --exit-status
```

The rehearsal requires the future tag to remain absent. It validates the
prepared plan, current manifest and source model, reproduces the exact archive
lock on Ubuntu, exercises unpublished-tag archive bootstrap, and checks the
production-shaped `/dev/` documentation links. It publishes nothing and stays
outside the release clock. Require the exact dispatched run to succeed before
opening the PR.

Starting with version `0.19.1`, the release manifest records the committed
identifier catalog path, SHA-256 digest, and active entry count. The planner
checks that binding against the source tree. Live resolver availability remains
an asynchronous publication smoke rather than a candidate-build gate.

Release documentation also resumes with `0.19.1`. Version `0.19.0` remains a
published historical exception and must not be modified after publication.

## Request and verify one candidate

Resolve current protected `main` and request the candidate:

```sh
git fetch origin main
source_sha="$(git rev-parse origin/main)"

release/scripts/registry-release request-candidate \
  --version <version> \
  --release-id <release-id> \
  --source-sha "${source_sha}" \
  --wait-for-ci \
  --wait
```

The command prints the exact candidate run ID and URL immediately after the
dispatch is correlated. `--wait-for-ci` waits only for protected-main `ci.yml`
at the exact source SHA, then refreshes protected `main` again immediately
before dispatch. `--wait` follows only that uniquely identified candidate run.
Omit either flag when another operator or monitor owns the corresponding wait.

The request is accepted only when `source_sha` is the exact protected-main
workflow revision and that revision has successful protected-main CI. Request
the candidate immediately after the release PR merges. If `main` advances
before dispatch, the CLI stops without creating a candidate. Inspect the
intervening commits, rerun `prepare` and the applicable validators and
rehearsal against the new tip, and use the new protected-main revision only
when the release identity and notes remain accurate. Otherwise update them in
another release PR. A later `main` advance does not invalidate a candidate that
the workflow already accepted and bound to its exact source. The candidate
workflow then:

- Validates the release identity, manifests, pins, recipes, and destinations.
- Builds the release payloads and OCI image once.
- Builds the exact locked release documentation archive once and includes it in
  the candidate payload closure.
- Publishes images only to private candidate packages.
- Scans the exact candidate image digests and enforces the advisory decision.
- Runs the release payload checks.
- Seals a candidate manifest and bundle that remain promotable for seven days.
- Attests the manifest and bundle after re-verifying their bytes.

Use the successful candidate run ID for local verification:

```sh
release/scripts/registry-release verify-candidate \
  --version <version> \
  --release-id <release-id> \
  --candidate-run <run-id>
```

The command verifies the exact source and workflow ancestry, candidate
attestations, bundle payload hashes, image digests, SPDX SBOMs, scans, and
advisory verdict. For an initial publication it also requires the release tag,
GitHub Release, and final image destinations to be unused.

## Tag and publish

On success, `verify-candidate` prints all three operator commands:

1. Create the exact annotated tag bound to the candidate run, attempt, and
   manifest SHA-256.
2. Push only that tag ref.
3. Dispatch publication from protected `main` with the exact tag.

The final command has this form:

```sh
gh workflow run release.yml \
  --repo registrystack/registry-stack \
  --ref main \
  -f tag=v<version>
```

Run the printed commands without editing the annotation. Inspect the tag before
pushing it. The tag is annotated but not cryptographically signed.

The publication workflow runs from protected `main`, while the candidate and
tag remain bound to the release source commit. This separation permits a
release-workflow repair and exact retry without moving the source tag.
Publication:

1. Verifies the tag binding, source ancestry, seven-day candidate validity, and
   candidate attestations.
2. Creates or reconciles the nonpublic draft GitHub Release with the exact
   candidate payloads.
3. Promotes each private image manifest to the final tag at the candidate
   digest. An absent tag is copied, an existing exact digest is accepted, and a
   mismatch stops publication.
4. Adds `SHA256SUMS` and one keyless Sigstore bundle for the checksum file.
5. Rechecks the full asset inventory, checksum signature, and image digests,
   then publishes a public, non-prerelease GitHub Release.
6. Dispatches the docs workflow with the exact released documentation digest.
   The same workflow rebuilds `/dev/` on every push to protected `main` while
   retaining the latest authenticated docs-bearing release at the canonical
   and versioned routes.

The candidate attestation and signed checksum chain are the Beta provenance
model. Ordinary Beta publication does not generate a second generic SLSA
provenance asset. Pre-v0.19 release finalizers remain only in their immutable
historical release tags.

After publication, run the minimum public verifier from a checkout whose
`origin` is the Registry Stack repository:

```sh
release/scripts/registry-release verify-public --tag v<version>
```

It verifies the annotated tag target, latest published non-prerelease state,
every downloadable asset against GitHub's digest metadata, the exact
`SHA256SUMS` closure and its protected-main Sigstore identity, the release-body
manifest binding, every final OCI digest, and one maintained binary version
smoke. It is read-only and can be rerun independently.

## Failure handling

| Failure state | Response |
| --- | --- |
| Validation failure before a candidate is sealed | Fix the source or metadata, then request a candidate from protected `main` |
| Candidate infrastructure failure before sealing | Rerun the candidate workflow |
| Candidate byte, recipe, scan, or advisory decision changes | Build and verify a new candidate |
| Candidate expires before the tag is pushed | Request and verify a new candidate |
| Bound draft or publication step fails while the candidate remains valid | Fix the workflow on protected `main` if needed, then dispatch `release.yml` again with the same tag |
| Documentation deployment fails after publication | Rerun `docs-pages.yml`; its optional exact tag and digest inputs fail closed if the request is stale |
| One final image tag already has the expected digest | Retry; publication accepts and re-verifies the exact digest |
| A final image tag has a different digest, or a published asset differs | Stop and patch forward with a new version |
| Repeatability, canary, Scorecard, telemetry, hosted, or announcement failure | Record follow-up work; do not change the public release result |

Never move a pushed tag, replace a published release asset, or overwrite a
mismatched final image tag. Exact partial state is retryable; incompatible
immutable state requires a new version.

## Asynchronous controls

The following controls stay outside ordinary Beta publication unless the
release changes or explicitly claims their surface:

- Scheduled release canary and clean repeatability proof.
- OpenSSF Scorecard, CodeQL, dependency, and image monitoring.
- Extended provenance or historical archive review.
- Hosted, external conformance, and 1.0-readiness exercises.
- Storage telemetry, retrospective, and announcement work.

Add one of these controls to the release clock only for a named threat or user
claim. Record the invariant, owner, duration, and removal condition.

Candidate promotion validity is seven days. The final candidate artifact and
private candidate images are retained for eight days, leaving one day of
cleanup margin without adding an operator step. Cleanup cannot target public
package names.
