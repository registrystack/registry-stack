# Verify A Registry Stack Release

The release workflow's `github-release` job signs a selected set of artifacts
using keyless cosign. For each artifact that job signs, it uploads the artifact
with a sibling `.sig` signature and `.pem` signing certificate. For
tag-triggered releases, a separate SLSA generator job uploads the release-level
provenance asset named
`registry-stack-${tag}-release-provenance.intoto.jsonl`. The provenance asset
does not have sibling cosign files; `slsa-verifier` authenticates it and checks
that the release artifact is one of its subjects.

Earlier releases, including `v0.8.2`, may include cosign signatures but no SLSA
provenance asset. `v0.8.0` is unsigned. The commands below verify a
tag-triggered release that includes provenance. Replace `v0.8.4` and the asset
name with the release you are checking.

Repeatable build evidence for the `v0.8.3` Linux amd64 binary assets is
documented in [`release/REPEATABLE-BUILDS.md`](REPEATABLE-BUILDS.md).

## Install Verification Tools

The commands below use the GitHub CLI, cosign, and `slsa-verifier`.
Install `slsa-verifier` from the upstream
[`slsa-framework/slsa-verifier` releases](https://github.com/slsa-framework/slsa-verifier/releases).
For repeatable evidence, pin and record the verifier version you used. As of
2026-07-09, the current upstream release is
[`v2.7.1`](https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.7.1).

## Download Assets

```bash
tag=v0.8.4
asset=registryctl-${tag}-linux-amd64
provenance=registry-stack-${tag}-release-provenance.intoto.jsonl

mkdir -p "verify-${tag}"
cd "verify-${tag}"

gh release download "${tag}" \
  --repo registrystack/registry-stack \
  --pattern "${asset}" \
  --pattern "${asset}.sig" \
  --pattern "${asset}.pem" \
  --pattern "SHA256SUMS" \
  --pattern "${provenance}"
```

## Check The Asset Hash

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

`sha256sum` should report `OK` for the downloaded asset.

## Verify The Keyless Signature

```bash
cosign verify-blob "${asset}" \
  --signature "${asset}.sig" \
  --certificate "${asset}.pem" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/tags/${tag}"
```

For release-capsule or image-evidence assets, use the same command with that
asset's filename and matching `.sig` and `.pem` files.

## Verify The SLSA Provenance

```bash
slsa-verifier verify-artifact "${asset}" \
  --provenance-path "${provenance}" \
  --source-uri github.com/registrystack/registry-stack \
  --source-tag "${tag}"
```

The provenance subject set covers release artifacts before their generated
`.sig` and `.pem` files are added.

If a release was rebuilt manually through `workflow_dispatch`, inspect the
certificate identity, the release capsule's workflow URL, and the SLSA
provenance source before accepting the asset. The release workflow only uploads
SLSA provenance when the run is associated with `refs/tags/${tag}`.

## Current Scope

The `github-release` job signs binaries, checksums, release binary SBOMs,
image-input binary SBOMs, image evidence files, image SBOMs, Grype reports, and
release capsules before uploading them. When the workflow runs from the release
tag ref, the separate SLSA generator job publishes provenance for those
non-signature artifacts. OCI image signatures are not yet published for the
root monorepo release.

The release capsule summarizes binary asset hashes, binary SBOM asset names,
image digests, image SBOMs, Grype reports, workflow lineage, and release
warnings. It does not carry per-artifact signature or provenance status fields;
verify cosign signatures for artifacts uploaded by the `github-release` job
from their sibling `.sig` and `.pem` files. Verify the separately uploaded
release-level provenance asset with `slsa-verifier`.
