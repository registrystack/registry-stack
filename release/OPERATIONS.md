# Operate A Registry Stack Release

The hosted release path builds a private pre-tag candidate, verifies that
candidate, and promotes the same bytes after an operator creates the tag.
The workflow never creates or pushes Git refs.

## Choose The Proof Level

Candidate requests accept `auto` or `extended`.
There is intentionally no operator-selected `standard` value.
`auto` selects the standard beta path only when the comparison with the
authoritative previous promoted receipt or tag is unambiguous and no
release-system or trust-anchor path changed.

The selector requires extended proof when any of these conditions applies:

- Release workflow, build recipe, packaging, signing, provenance, scan policy,
  builder, BuildKit, runtime base, lockfile, or other trust-anchor code changed
- Candidate evidence available to the selector is incomplete or records
  disagreement
- The release is a stable, audit, or `1.0` or later milestone
- The previous promoted receipt or tag is missing, conflicting, unreachable, or
  not an ancestor of the candidate source
- The operator requests `extended`

A candidate uses one canonical build and fails on incomplete binary inventory,
invalid immutable image topology, an unreviewed advisory, or any source and
artifact binding mismatch. Extended proof is additional evidence produced by
the separate repeatability workflow, not a second build in the blocking
candidate path.
Grype process status is not itself the advisory decision. The candidate first
requires a complete scan report, then the reviewed advisory policy decides
whether that report is acceptable. Database identity accepts both the legacy
flat Grype descriptor and the nested descriptor emitted by the pinned Grype
release.

The selector writes `registry-stack.release-proof-selection.v1` JSON into the
candidate evidence.
The previous release's promoted candidate receipt is the preferred comparison
base.
The exact previous promoted tag is the fallback and a cross-check when both are
available.

The candidate path does not claim build determinism from two builds in one
workflow. The clean rebuild in `.github/workflows/release-repeatability.yml`
carries that separate claim without delaying publication.

## Check The Storage Gate

Every expensive build runs the storage preflight first.
`release/storage-budget.json` currently has status `measurement_required`
because no real candidate run has recorded peak per-runner storage.
The required byte count is `null`.
Do not replace it with an estimate.

An ordinary candidate or repeatability run remains blocked in this bootstrap
state.
For the first instrumented real candidate only, set
`client_payload.measurement_bootstrap` to `true`.
The candidate records periodic filesystem and workspace samples from each
runner.
After that run, update the budget with:

- The candidate workflow run URL
- The measured timestamp
- The label, baseline filesystem-used bytes, peak filesystem-used bytes, and
  peak release-workspace bytes from the job with the largest
  `peak_additional_filesystem_used_bytes`
- That job's `peak_additional_filesystem_used_bytes`, which must equal its peak
  filesystem-used bytes minus its baseline filesystem-used bytes
- `required_available_bytes`, set to
  `ceil(peak_additional_filesystem_used_bytes * (1 + safety_margin_ratio))`

The budget loader checks both equations and rejects arbitrary thresholds,
including a one-byte placeholder. Absolute filesystem-used bytes are retained
as audit evidence; they are not compared with available bytes.

Splitting the canonical, platform, and verification work across separate
runners limits the budget to per-job peak pressure.
The gate is preventive; no prior hosted candidate disk exhaustion is recorded.

## Request A Candidate

The release-prep PR keeps the new docset in `draft` status because the
protected-main squash commit does not exist yet. In the source-ref
finalization PR, pin the docset and release manifest to the release-prep merge
commit, change the docset status to `archived`, build it, and append its bundle
and tree digests to the immutable lock:

```sh
cd docs/site
npm ci
DOCS_DOCSET=vX.Y.Z npm run build:archive
npm run archive:snapshot -- vX.Y.Z --write-lock
npm run generate
npm run check:archive-lock -- --base-ref origin/main
cd ../..
```

Commit the new lock entry in that source-ref finalization PR. Existing entries
cannot be changed or removed. Merge the finalization PR before requesting the
candidate. The candidate, tag workflow, and Pages deployment all verify the
same bytes.

Then start from a clean local checkout with current `origin/main`.
Resolve the exact protected-main commit and choose an unused release ID.

```sh
git fetch origin main
source_sha="$(git rev-parse origin/main)"

release/scripts/registry-release request-candidate \
  --version 0.15.1 \
  --release-id beta-21 \
  --source-sha "${source_sha}" \
  --proof-level auto
```

The command sends the `release_candidate` repository dispatch with exact
`version`, `release_id`, `source_sha`, and `proof_level` fields.
Use `--proof-level extended` for an explicit audit request.
The workflow rejects any source that is not the current protected-main commit.

While the storage budget is still in its documented bootstrap state, request
the one instrumented measurement run through the supported release command:

```sh
release/scripts/registry-release request-candidate \
  --version 0.15.1 \
  --release-id beta-21 \
  --source-sha "${source_sha}" \
  --proof-level extended \
  --milestone beta \
  --measurement-bootstrap
```

This flag bypasses the unavailable measured threshold exactly once so the
workflow can collect the real peak. Do not use it after a measured budget is
committed.

## Finalize And Tag A Candidate

Wait for the candidate run to finish and record its run ID.
The finalization command resolves the run attempt from the trusted GitHub API;
the operator does not supply an attempt number.
The candidate must be less than 72 hours old when promotion starts.

Run the local verifier before creating a tag:

```sh
candidate_run="${CANDIDATE_RUN_ID:?set CANDIDATE_RUN_ID to the exact run}"

release/scripts/registry-release finalize \
  --version 0.15.1 \
  --release-id beta-21 \
  --promotion-commit "$(git rev-parse origin/main)" \
  --candidate-run "${candidate_run}"
```

The verifier fetches the exact candidate artifact IDs, verifies the closed
receipt, run attempt, workflow identity, GitHub attestations, artifact bytes,
image digests, scans, whether same-run comparisons were performed, and release
identity.
On success, it prints one exact annotated `git tag -a` command whose message
binds the run ID, run attempt, and receipt SHA-256.
Run that printed command, inspect the tag, and push only that exact ref:

```sh
tag=v0.15.1
git show --show-signature "${tag}"
git push origin "refs/tags/${tag}"
```

Git tag objects are not cryptographically signed.
The annotated candidate binding, receipt attestation, asset signatures, and
tag-bound release provenance do not change that OpenSSF status.

## Handle Failures

A failure before any public image or GitHub Release write is retry-safe from
the same unexpired candidate.
A tag without a published release burns that version.
Any failure after the first public write also burns the version.
Fix forward with a new patch version.

Never delete or replace a public release asset, public image tag, or completed
promotion to retry.
The promotion state check rejects reuse of a promoted identity and candidate.

## Retain And Clean Candidate Evidence

Actions candidate artifacts use a seven-day retention period.
The private staging packages are exactly:

- `registry-notary-candidate`
- `registry-relay-candidate`

The daily cleanup workflow deletes versions older than seven days using GitHub
server timestamps.
Its script has a closed allowlist and refuses the public `registry-notary` and
`registry-relay` package names.
Manual cleanup uses `repository_dispatch`, keeping package-write workflow code
on the default branch.

Run a dry run:

```sh
gh api --method POST repos/registrystack/registry-stack/dispatches \
  -f event_type=release-candidate-cleanup \
  -F 'client_payload[apply]=false'
```

Apply the same exact retention policy:

```sh
gh api --method POST repos/registrystack/registry-stack/dispatches \
  -f event_type=release-candidate-cleanup \
  -F 'client_payload[apply]=true'
```

The hosted standard path does not require a multi-gigabyte local evidence
cache.
Download a candidate locally only for incident review or the pre-tag finalize
check, then remove that local copy under the operator's normal workstation
retention policy.

## Run The Later Clean Proof

The repeatability workflow runs weekly against the newest published release
that carries a candidate receipt.
Dispatch an exact published tag manually when extended proof or external audit
requires it:

```sh
gh api --method POST repos/registrystack/registry-stack/dispatches \
  -f event_type=release-repeatability \
  -f 'client_payload[tag]=v0.15.1'
```

The job compares the clean rebuild with published hashes and image digests,
attests its receipt, retains supporting artifacts for seven days, and refreshes
the durable evidence comment on
[GH#127](https://github.com/registrystack/registry-stack/issues/127).

The first real extended proof and the enforced numeric storage budget cannot be
completed before a candidate-based release runs.
Those are live operational blockers, not locally generated evidence.
