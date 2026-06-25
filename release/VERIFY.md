# Verify A Registry Stack Release

Registry Stack GitHub Release assets are signed by the release workflow using
keyless cosign. Each uploaded release asset has a sibling `.sig` signature and
`.pem` signing certificate.

The commands below verify a tag-triggered release such as `v0.8.0`. Replace
`v0.8.0` and the asset name with the release you are checking.

## Download Assets

```bash
tag=v0.8.0
asset=registryctl-${tag}-linux-amd64

mkdir -p "verify-${tag}"
cd "verify-${tag}"

gh release download "${tag}" \
  --repo registrystack/registry-stack \
  --pattern "${asset}" \
  --pattern "${asset}.sig" \
  --pattern "${asset}.pem" \
  --pattern "SHA256SUMS"
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

If a release was rebuilt manually through `workflow_dispatch`, inspect the
certificate identity and the release capsule's workflow URL before accepting the
asset. Manual rebuilds can have a workflow identity tied to the branch that ran
the dispatch instead of `refs/tags/${tag}`.

## Current Scope

The release workflow signs GitHub Release assets: binaries, checksums, image
evidence files, SBOMs, Grype reports, and release capsules. OCI image signatures
and SLSA provenance attestations are not yet published for the root monorepo
release.
