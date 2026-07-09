# Verify A Registry Stack Release

Registry Stack GitHub Release assets are signed by the release workflow using
keyless cosign. Each uploaded release asset has a sibling `.sig` signature and
`.pem` signing certificate. Tag-triggered releases produced by the current
release workflow also include a release-level SLSA provenance asset named
`registry-stack-${tag}-release-provenance.intoto.jsonl`.

Earlier releases, including `v0.8.2`, may include cosign signatures but no SLSA
provenance asset. The commands below verify a tag-triggered release that
includes provenance. Replace `v0.8.4` and the asset name with the release you
are checking.

Repeatable build evidence for the `v0.8.3` Linux amd64 binary assets is
documented in [`release/REPEATABLE-BUILDS.md`](REPEATABLE-BUILDS.md).

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

The release workflow signs GitHub Release assets: binaries, checksums, release
binary SBOMs, image-input binary SBOMs, image evidence files, image SBOMs,
Grype reports, and release capsules. It publishes SLSA provenance for those
non-signature release assets when the workflow runs from the release tag ref.
OCI image signatures are not yet published for the root monorepo release.

The release capsule summarizes binary asset hashes, binary SBOM asset names,
image digests, image SBOMs, Grype reports, workflow lineage, and release
warnings. It does not carry per-artifact signature or provenance status fields;
verify those properties from each asset's sibling `.sig` and `.pem` files and
from the release-level SLSA provenance asset.
