# Registry Stack Release Command Contract

This public manual defines the release commands that are safe to copy into a
maintainer runbook. It contains no hosted environment details, credentials,
private review evidence, or assertion that a held gate has passed.

Run the command-contract checker before a release window:

```bash
python3 release/scripts/check-release-manual.py --manual release/MANUAL.md
```

## Prepare A Candidate

The operator chooses the version and release ID. The command validates that
decision and emits a deterministic plan; it does not silently select or mutate
a release.

<!-- registry-release-check -->
```bash
release/scripts/registry-release prepare \
  --version "${version}" \
  --release-id "${release_id}" \
  --plan-output prepare-plan.json
```

Validate the selected manifest and every archived documentation set:

<!-- registry-release-check -->
```bash
release/scripts/registry-release validate \
  "release/manifests/registry-stack-${release_id}.yaml"
```

<!-- registry-release-check -->
```bash
release/scripts/registry-release validate-docsets
```

Audit the immutable external-source import map:

<!-- registry-release-check -->
```bash
release/scripts/registry-release audit \
  release/manifests/import-map-2026-06-24.yaml
```

## Finalize Promoted Source

After promotion, record the exact promotion commit. Finalization remains a
plan until the operator applies and reviews its explicit pointer changes.

<!-- registry-release-check -->
```bash
release/scripts/registry-release finalize \
  --version "${version}" \
  --release-id "${release_id}" \
  --promotion-commit "${promotion_commit}" \
  --default-branch origin/main \
  --plan-output finalize-plan.json
```

The finalized manifest must prove that the immutable tag and the default
branch contain the selected source:

<!-- registry-release-check -->
```bash
release/scripts/registry-release validate-source \
  "release/manifests/registry-stack-${release_id}.yaml" \
  --tag "v${version}" \
  --default-branch origin/main
```

## Verify Publication And Render Evidence

Run the complete consumer journey from a clean checkout at the immutable
release tag. The verifier downloads the exact public pre-evidence asset set
unless `--assets-dir` identifies an already downloaded exact set.

<!-- registry-release-check -->
```bash
release/scripts/registry-release verify-published \
  "release/manifests/registry-stack-${release_id}.yaml" \
  --output-json "registry-stack-v${version}-post-publication-verification.json"
```

Collect the bounded public evidence bundle only after the verifier passes.
The output must remain outside the pre-evidence asset directory so it cannot
attest to itself.

<!-- registry-release-check -->
```bash
release/scripts/registry-release collect-evidence-bundle \
  --manifest "release/manifests/registry-stack-${release_id}.yaml" \
  --capsule "release-assets/registry-stack-v${version}-release-capsule.json" \
  --verification-result "registry-stack-v${version}-post-publication-verification.json" \
  --asset-dir release-assets \
  --output-json "registry-stack-v${version}-release-evidence.json"
```

Render the public closeout from the validated bundle:

<!-- registry-release-check -->
```bash
release/scripts/registry-release render-release-closeout \
  --bundle "registry-stack-v${version}-release-evidence.json" \
  --output-markdown "registry-stack-v${version}-release-closeout.md"
```

The bundle and public closeout contain only the closed public schema. A
private closeout system may consume the same signed bundle and add restricted
evidence on its side of the privacy boundary; restricted evidence must never
be passed into these public commands or committed here.

## Held Gates

These commands validate only their public, machine-readable contracts. They do
not satisfy required review, protected-branch checks, DCO, CodeQL, secret
scanning, security-alert review, hosted publication, adopter repinning, or any
other recorded hold. Keep each unsatisfied gate explicit in the release
evidence bundle and close it only from independently verified evidence.
