# Verify a Registry Stack release

Current Beta releases use two linked controls. The candidate workflow attests
the exact candidate manifest and bundle. The protected-main publication
workflow verifies those attestations before promotion, then keyless-signs one
`SHA256SUMS` file covering every public payload, including the release
manifest, consolidated SPDX SBOM, and security-evidence archive, and publishes
SLSA build provenance for that checksum file.

## Install tools

The commands require GitHub CLI, Cosign, `jq`, `crane`, GNU `sha256sum`,
`python3`, and `base64`. Pin and record the tool versions used for an audit.

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

`SHA256SUMS` intentionally excludes itself, its Sigstore bundle, and its
provenance bundle.

## Authenticate the checksum provenance

Releases from `v0.27.1` publish `registry-stack-${tag}-SHA256SUMS.intoto.jsonl`,
a Sigstore bundle carrying a SLSA build provenance statement whose subject is
`SHA256SUMS`. Verify that it was produced by the protected-main publication
workflow of this repository:

```sh
provenance_bundle="registry-stack-${tag}-SHA256SUMS.intoto.jsonl"

gh attestation verify SHA256SUMS \
  --bundle "${provenance_bundle}" \
  --repo registrystack/registry-stack \
  --signer-workflow \
    registrystack/registry-stack/.github/workflows/release.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```

Verify both this attestation and the checksums to authenticate the complete
payload inventory. The attestation records the protected-main publication
execution that assembled `SHA256SUMS`; its source revision is the publication
workflow revision, which can differ from the release tag's source. The
candidate attestations and release manifest retain the binding to the payload
build. This checksum attestation alone does not prove how each binary was
compiled.

The asset is required from `v0.27.1`. Published releases through `v0.27.0`
remain verifiable without it. If an earlier release carries the asset, the
public verifier authenticates it too.

## Verify release identity and image bindings

Inspect the compact public release manifest:

```sh
manifest="registry-stack-${tag}-release-manifest.json"

jq -e --arg tag "${tag}" '
  ($tag | capture("^v(?<major>[0-9]+)\\.(?<minor>[0-9]+)\\.") |
    {major: (.major | tonumber), minor: (.minor | tonumber)}) as $version |
  (if ($version.major > 0 or $version.minor >= 30)
   then ["breg", "casework", "discovery", "evidence", "relay"]
   elif $version.minor >= 26 then ["breg", "discovery", "evidence", "mint", "relay"]
   elif $version.minor >= 24 then ["discovery", "evidence", "mint", "relay"]
   elif $version.minor >= 21 then ["evidence", "mint", "relay"]
   else ["relay"] end) as $image_names |
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
Mint, and Registry Relay. Registry Discovery joins at `v0.24.0`, and Base
Registry Engine joins at `v0.26.0`, and Registry Casework joins at `v0.30.0`.
Mint is retired from `v0.30.0`; historical releases retain their original roster.
The final release tags recorded in the manifest must resolve to the same digests
as their candidate bindings:

```sh
while IFS=$'\t' read -r name digest final_ref; do
  case "${name}" in
    breg|casework|discovery|evidence|mint|relay) ;;
    *) echo "unexpected release image: ${name}" >&2; exit 1 ;;
  esac
  resolved_digest="$(crane digest "${final_ref}")"
  if [[ "${resolved_digest}" != "${digest}" ]]; then
    echo "digest mismatch for ${name}: manifest ${digest}, resolved ${resolved_digest}" >&2
    exit 1
  fi
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
reports and Grype reports for `evidence`, `mint`, and `relay`, joined by
`discovery` from `v0.24.0`, `breg` from `v0.26.0`, and `casework` from
`v0.30.0`. Mint reports are excluded from `v0.30.0` onward; `v0.19.x` and
`v0.20.x` archives contain those reports for `relay`
only. The archive also
contains the advisory verdict used for candidate acceptance. Each report names
the exact candidate digest that was promoted. The archive hash is covered by
the authenticated checksum chain. The candidate workflow also evaluates any
version-4 exception against a temporary export of that exact image rootfs and
requires each inspected file to match the native Syft SHA-256 evidence. The
workflow independently resolves the current candidate digest, cross-checks it
against both scan reports, and verifies the protected source revision in the OCI
labels. The checker also requires the full OCI config's authoritative ordered
`.rootfs.diff_ids` to equal both reports. The libc exceptions then require that
complete ordered DiffID list, the closed production runtime configuration
(`User`, `Entrypoint`, `Cmd`, `WorkingDir`, `Env`, `Healthcheck`, `ArgsEscaped`,
`ExposedPorts`, `StopSignal`, the three current OCI identity labels, and the
fixed runtime UID/GID labels), and each
reviewed file digest in both Syft and the exported rootfs. These are uncompressed
rootfs DiffIDs, not compressed manifest layer digests, and they cover the complete
filesystem, including libraries, interpreters, loader inputs, and symlinks. Each
baseline records the exact reviewed reference image, source revision and
provenance. A reference may be a local reproduction from the read-only rehearsal;
the candidate independently verifies its own image identity and protected source.
A changed DiffID, configuration, path, or digest requires a fresh review and
renewed definition digest. This DiffID-based contract avoids an in-tree manifest-digest self-reference
when the source revision label changes. The temporary rootfs is deleted after the
decision and is not a release asset. `release/OPERATIONS.md` gives the exact
private-candidate recovery and evidence-regeneration procedure for a failed gate.

## Verify client registries

Registry Stack v0.22.0 publishes the checksum-covered Evidence and Relay client
packages to npm and PyPI. Registry Stack v0.23.0 and later also publish the
Discovery clients. Starting with v0.26.1, Registry Stack publishes only the
unified `@registrystack/client` and `registry-stack-client` packages; releases
through v0.26.0 keep their immutable product-specific packages, and those are
not republished under the unified names. With the release assets still in the
current directory, compare every registry version with its release tarball or
wheel:

```sh
version="${tag#v}"
IFS=. read -r major minor patch <<<"${version}"
if (( major > 0 || minor > 26 || (minor == 26 && patch >= 1) )); then
  clients=(stack)
else
  clients=(evidence relay)
  if (( major > 0 || minor >= 23 )); then
    clients=(discovery "${clients[@]}")
  fi
fi

gh api \
  "repos/registrystack/registry-stack/contents/release/scripts/client_registry.py?ref=${tag}" \
  --jq .content \
  | base64 --decode > client_registry.py

for client in "${clients[@]}"; do
  if [[ "${client}" == stack ]]; then
    stem="registrystack-client"
  else
    stem="registrystack-${client}-client"
  fi
  for tarball in \
    "${stem}-darwin-arm64-${version}.tgz" \
    "${stem}-linux-arm64-gnu-${version}.tgz" \
    "${stem}-linux-x64-gnu-${version}.tgz" \
    "${stem}-${version}.tgz"; do
    npm_state="$(python3 client_registry.py npm-state --tarball "${tarball}")"
    if [[ "${npm_state}" != present ]]; then
      echo "missing npm package: ${tarball}" >&2
      exit 1
    fi
  done
  pypi_state="$(python3 client_registry.py pypi-state \
    --directory . --version "${version}" --client "${client}")"
  if [[ "${pypi_state}" != present ]]; then
    echo "missing pypi package: ${client} ${version}" >&2
    exit 1
  fi
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

Releases from `v0.27.1` add one SLSA build provenance bundle for `SHA256SUMS`.
Its absence from an earlier release is not missing release evidence.

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
