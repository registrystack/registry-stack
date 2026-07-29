# Verify a Registry Stack release

Current releases use a signed checksum chain. One keyless Sigstore bundle
authenticates `SHA256SUMS`; the checksum file covers every public payload,
including the release manifest, image lock, consolidated SPDX SBOM, and
security-evidence archive. Tag-bound SLSA provenance covers the same payload
subject set.

## Install tools

The commands require GitHub CLI, Cosign, `slsa-verifier`, `jq`, `crane`, and
GNU `sha256sum`. Pin and record the tool versions used for an audit.

## Download one release

Set an exact published tag and use a fresh directory:

```sh
tag="${RELEASE_TAG:?set RELEASE_TAG to vMAJOR.MINOR.PATCH}"
case "${tag}" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "invalid release tag" >&2; exit 1 ;;
esac

mkdir "verify-${tag}"
cd "verify-${tag}"

gh release download "${tag}" \
  --repo registrystack/registry-stack
```

Confirm that GitHub reports a public, non-prerelease release:

```sh
gh release view "${tag}" \
  --repo registrystack/registry-stack \
  --json isDraft,isPrerelease,tagName \
  | jq -e --arg tag "${tag}" \
      '.tagName == $tag and .isDraft == false and .isPrerelease == false'
```

## Authenticate the checksum chain

Verify the one Sigstore bundle before trusting a checksum:

```sh
checksum_bundle="registry-stack-${tag}-SHA256SUMS.sigstore.json"

cosign verify-blob SHA256SUMS \
  --bundle "${checksum_bundle}" \
  --certificate-identity \
    "https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/tags/${tag}" \
  --certificate-oidc-issuer \
    https://token.actions.githubusercontent.com
```

Then verify every covered payload:

```sh
sha256sum --check --strict SHA256SUMS
```

`SHA256SUMS` intentionally excludes itself, its Sigstore bundle, and the
separately signed provenance envelope.

## Verify release identity and image bindings

Inspect the compact public release manifest:

```sh
manifest="registry-stack-${tag}-release-manifest.json"

jq -e --arg tag "${tag}" '
  .schema_version == "registry-stack.release-candidate.v2" and
  .repository == "registrystack/registry-stack" and
  .release.tag == $tag and
  (.release.source_sha | test("^[0-9a-f]{40}$")) and
  .workflow.path == ".github/workflows/release-candidate.yml" and
  (.workflow.revision | test("^[0-9a-f]{40}$")) and
  (.workflow.run_id | type == "number") and
  (.workflow.run_attempt | type == "number") and
  .advisory.verdict == "passed"
' "${manifest}"
```

The release image lock is covered by `SHA256SUMS`. Verify its closed release
identity and immutable digest references:

```sh
image_lock="registryctl-${tag}-image-lock.json"

jq -e --arg tag "${tag}" '
  .schema_version == "registryctl.release_image_lock.v1" and
  .release_tag == $tag and
  .platform == "linux/amd64" and
  (.images["registry-relay"] |
    test("^ghcr\\.io/registrystack/registry-relay@sha256:[0-9a-f]{64}$")) and
  (.images["registry-notary"] |
    test("^ghcr\\.io/registrystack/registry-notary@sha256:[0-9a-f]{64}$"))
' "${image_lock}"

for name in registry-notary registry-relay; do
  ref="$(jq -er --arg name "${name}" '.images[$name]' "${image_lock}")"
  expected="${ref##*@}"
  test "$(crane digest "${ref}")" = "${expected}"
done
```

The final release tags recorded in the manifest must resolve to the same
digests:

```sh
while IFS=$'\t' read -r digest final_ref; do
  test "$(crane digest "${final_ref}")" = "${digest}"
done < <(jq -r '.images[] | [.digest,.final_ref] | @tsv' "${manifest}")
```

## Verify SBOM and security evidence

The consolidated SBOM must identify SPDX 2.3 JSON:

```sh
sbom="registry-stack-${tag}.sbom.spdx.json"

jq -e '
  .spdxVersion == "SPDX-2.3" and
  (.SPDXID | type == "string") and
  (.name | type == "string") and
  (.packages | type == "array")
' "${sbom}"
```

List the security-evidence archive without extracting it over existing files:

```sh
evidence="registry-stack-${tag}-security-evidence.tar.gz"
tar -tzf "${evidence}"
```

The archive contains image-specific SPDX and Syft reports, Grype reports, and
the advisory verdict used for candidate acceptance. Their archive hash is
covered by the authenticated checksum chain.

## Verify provenance subject coverage

Verify each checksum-covered payload against the tag-bound provenance:

```sh
provenance="registry-stack-${tag}-release-provenance.intoto.jsonl"

while read -r expected name; do
  slsa-verifier verify-artifact "${name}" \
    --provenance-path "${provenance}" \
    --source-uri github.com/registrystack/registry-stack \
    --source-tag "${tag}"
done < SHA256SUMS
```

The provenance authenticates the tag-bound payload subjects. The signed
checksum chain authenticates their exact public inventory. The release
manifest records the private candidate workflow revision, run, attempt,
source, scans, advisory verdict, and image promotion binding.

## Legacy releases

Historical assets remain immutable. Releases created before the compact
checksum-chain cutover may use per-file `.sig` and `.pem` pairs, release
capsules, candidate receipts, separate digest files, multiple SPDX files, or
no provenance asset.

Use the verification document committed at the historical tag:

```sh
gh api \
  "repos/registrystack/registry-stack/contents/release/VERIFY.md?ref=${tag}" \
  --jq .content \
  | base64 --decode > "VERIFY-${tag}.md"
```

Do not infer current guarantees for a historical release when its asset
inventory does not provide the required evidence. `v0.8.0` remains an unsigned
historical release.
