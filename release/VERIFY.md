# Verify a Registry Stack release

Current Beta releases use two linked controls. The candidate workflow attests
the exact candidate manifest and bundle. The protected-main publication
workflow verifies those attestations before promotion, then keyless-signs one
`SHA256SUMS` file covering every public payload, including the release
manifest, consolidated SPDX SBOM, and security-evidence archive.

## Install tools

The commands require GitHub CLI, Cosign, `jq`, `crane`, and GNU `sha256sum`.
Pin and record the tool versions used for an audit.

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

Verify the one Sigstore bundle before trusting a checksum. Current publication
runs from protected `main`, so that branch is part of the signer identity:

```sh
checksum_bundle="registry-stack-${tag}-SHA256SUMS.sigstore.json"

cosign verify-blob SHA256SUMS \
  --bundle "${checksum_bundle}" \
  --certificate-identity \
    "https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer \
    https://token.actions.githubusercontent.com
```

Then verify every covered payload:

```sh
sha256sum --check --strict SHA256SUMS
```

`SHA256SUMS` intentionally excludes itself and its Sigstore bundle.

## Verify release identity and image bindings

Inspect the compact public release manifest:

```sh
manifest="registry-stack-${tag}-release-manifest.json"

jq -e --arg tag "${tag}" '
  (if ($tag | test("^v0\\.(19|20)\\."))
   then ["relay"] else ["evidence", "mint", "relay"] end) as $image_names |
  .schema_version == "registry-stack.release-candidate.v2" and
  .repository == "registrystack/registry-stack" and
  .release.tag == $tag and
  (.release.source_sha | test("^[0-9a-f]{40}$")) and
  .workflow.path == ".github/workflows/release-candidate.yml" and
  (.workflow.revision | test("^[0-9a-f]{40}$")) and
  (.workflow.run_id | type == "number") and
  (.workflow.run_attempt | type == "number") and
  (.images | map(.name) | sort == $image_names) and
  all(.images[];
    .final_ref == ("ghcr.io/registrystack/" + .name + ":" + $tag) and
    .candidate_ref ==
      ("ghcr.io/registrystack/" + .name + "-candidate@" + .digest)) and
  .advisory.verdict == "passed"
' "${manifest}"
```

Starting with `v0.21.0`, the exact image set is Evidence Gateway, Registry
Mint, and Registry Relay. The final release tags recorded in the manifest
must resolve to the same digests as their candidate bindings:

```sh
while IFS=$'\t' read -r name digest final_ref; do
  case "${name}" in
    evidence|mint|relay) ;;
    *) echo "unexpected release image: ${name}" >&2; exit 1 ;;
  esac
  test "$(crane digest "${final_ref}")" = "${digest}"
done < <(jq -r '.images[] | [.name,.digest,.final_ref] | @tsv' "${manifest}")
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

Starting with `v0.21.0`, the archive contains image-specific SPDX and Syft
reports and Grype reports for `evidence`, `mint`, and `relay`; `v0.19.x` and
`v0.20.x` archives contain those reports for `relay` only. The archive also
contains the advisory verdict used for candidate acceptance. Each report names
the exact candidate digest that was promoted. The archive hash is covered by
the authenticated checksum chain.

## Verify client registries

Registry Stack v0.21.1 and later publish the checksum-covered Evidence and Relay client
packages to npm and PyPI. With the release assets still in the current
directory, compare every registry version with its release tarball or wheel:

```sh
version="${tag#v}"
for client in evidence relay; do
  for tarball in \
    "registrystack-${client}-client-darwin-arm64-${version}.tgz" \
    "registrystack-${client}-client-linux-arm64-gnu-${version}.tgz" \
    "registrystack-${client}-client-linux-x64-gnu-${version}.tgz" \
    "registrystack-${client}-client-${version}.tgz"; do
    test "$(python3 release/scripts/client_registry.py npm-state \
      --tarball "${tarball}")" = present
  done
  test "$(python3 release/scripts/client_registry.py pypi-state \
    --directory . --version "${version}" --client "${client}")" = present
done
```

The npm comparison uses the registry's SHA-512 integrity. The PyPI comparison
uses each file's SHA-256 digest and rejects missing, additional, changed, or
repeated release files.

## Provenance boundary

The candidate manifest records the candidate workflow revision, run, attempt,
source, scans, advisory verdict, and image promotion binding. GitHub artifact
attestations authenticate the candidate manifest and bundle before promotion.
The signed checksum chain authenticates the exact public release inventory.

Ordinary Beta releases do not publish a second generic
`release-provenance.intoto.jsonl` asset. Do not treat its absence as missing
release evidence.

## Legacy releases

Historical assets remain immutable. Earlier releases may use per-file `.sig`
and `.pem` pairs, release capsules, candidate receipts, separate digest files,
multiple SPDX files, generic SLSA provenance, or no provenance asset.

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
