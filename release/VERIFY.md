# Verify A Registry Stack Release

The release workflow signs release artifacts using keyless cosign.
Each signed artifact has a sibling `.sig` signature and `.pem` signing
certificate.
A separate SLSA generator uploads the tag-bound release provenance asset named
`registry-stack-${tag}-release-provenance.intoto.jsonl`.
`slsa-verifier` authenticates that provenance and checks that a release
artifact is one of its subjects.

Releases produced by the candidate path also publish
`registry-stack-${tag}-candidate-receipt.json`.
The candidate receipt records the exact build workflow, run, attempt, source
commit, builder fingerprints, artifact hashes, image topology, scans, and
comparison results.
GitHub build attestation authenticates the receipt.
The receipt itself is then included in the signed and reconciled GitHub Release
asset set.

Release provenance binds the tagged source and published bytes.
The candidate receipt records the build run identity that compiled those bytes.
Together they provide the tag to promotion to candidate-build chain without
claiming that the promotion run recompiled the payload.

`v0.13.0` is the current public evidence example for image locks, signatures,
provenance, and repeatable Linux amd64 outputs.
It predates the candidate receipt chain.
Earlier releases, including `v0.8.2`, may include cosign signatures but no SLSA
provenance asset.
`v0.8.0` is unsigned.

The current lock-bearing release workflow refuses to build or push a release
below `v0.9.0`. A historical tag rerun uses the workflow committed at that tag.

Repeatable build evidence through `v0.13.0` is documented in
[`release/REPEATABLE-BUILDS.md`](REPEATABLE-BUILDS.md).

## Install Verification Tools

The commands below require the GitHub CLI, cosign, `slsa-verifier`, `jq`, and
GNU `sha256sum`. On macOS, install GNU coreutils and place its `gnubin`
directory on `PATH` so the command is available as `sha256sum`.

Install `slsa-verifier` from the upstream
[`slsa-framework/slsa-verifier` releases](https://github.com/slsa-framework/slsa-verifier/releases).
For repeatable evidence, pin and record the verifier version you used. As of
2026-07-09, the current upstream release is
[`v2.7.1`](https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.7.1).

## Verify A Candidate Receipt

Use this procedure only for a release that contains
`registry-stack-${tag}-candidate-receipt.json`.
Set `RELEASE_TAG` to the exact published tag before running the commands.

```bash
tag="${RELEASE_TAG:?set RELEASE_TAG to an exact published tag}"
receipt="registry-stack-${tag}-candidate-receipt.json"

mkdir -p "verify-${tag}"
cd "verify-${tag}"

gh release download "${tag}" \
  --repo registrystack/registry-stack \
  --pattern "${receipt}" \
  --pattern "${receipt}.sig" \
  --pattern "${receipt}.pem"
```

Check the receipt's closed identity fields against the selected tag:

```bash
jq -e \
  --arg tag "${tag}" \
  --arg repository registrystack/registry-stack '
  .schema_version == "registry-stack.release-candidate-receipt.v1" and
  .repository == $repository and
  .release.tag == $tag and
  (.release.source_sha | test("^[0-9a-f]{40}$")) and
  .workflow.path == ".github/workflows/release-candidate.yml" and
  .workflow.event == "repository_dispatch" and
  (.workflow.run_id | type == "number") and
  (.workflow.run_attempt | type == "number") and
  .comparisons.binary_bytes == true and
  .comparisons.image_config_and_layers == true and
  .promotion.state == "candidate"
' "${receipt}"
```

Verify the release signature created by the tag-bound promotion workflow:

```bash
cosign verify-blob "${receipt}" \
  --signature "${receipt}.sig" \
  --certificate "${receipt}.pem" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    "https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/tags/${tag}"
```

Then authenticate the candidate workflow and exact workflow revision recorded
by the receipt:

```bash
workflow_sha="$(jq -er '.workflow.sha' "${receipt}")"

gh attestation verify "${receipt}" \
  --repo registrystack/registry-stack \
  --signer-workflow \
    registrystack/registry-stack/.github/workflows/release-candidate.yml \
  --signer-digest "${workflow_sha}" \
  --source-ref refs/heads/main \
  --source-digest "${workflow_sha}" \
  --deny-self-hosted-runners
```

Do not derive the expected workflow path from the receipt.
The literal trusted path in this command is part of the verification policy.
The receipt's `release.source_sha`, release tag target, and release provenance
source must all agree.

## Verify A v0.8.4 Registryctl Binary

### Download The v0.8.4 Assets

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

### Check The v0.8.4 Binary Hash

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

`sha256sum` should report `OK` for the downloaded binary. Registryctl `v0.8.4`
does not have an image-lock asset.

### Verify The v0.8.4 Keyless Signature

```bash
cosign verify-blob "${asset}" \
  --signature "${asset}.sig" \
  --certificate "${asset}.pem" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/tags/${tag}"
```

### Verify The v0.8.4 SLSA Provenance

```bash
slsa-verifier verify-artifact "${asset}" \
  --provenance-path "${provenance}" \
  --source-uri github.com/registrystack/registry-stack \
  --source-tag "${tag}"
```

## Verify v0.9.0+ Registryctl Image-Lock Assets

Use the matching procedure for a `v0.9.0` or later tag. Start from a fresh
working directory rather than the `verify-v0.8.4` directory above.

### Download The v0.9.0+ Assets

```bash
tag=v0.13.0
asset=registryctl-${tag}-linux-amd64
image_lock=registryctl-${tag}-image-lock.json
image_lock_sbom=${image_lock}.spdx.json
capsule=registry-stack-${tag}-release-capsule.json
provenance=registry-stack-${tag}-release-provenance.intoto.jsonl

mkdir -p "verify-${tag}"
cd "verify-${tag}"

gh release download "${tag}" \
  --repo registrystack/registry-stack \
  --pattern "${asset}" \
  --pattern "${asset}.sig" \
  --pattern "${asset}.pem" \
  --pattern "${image_lock}" \
  --pattern "${image_lock}.sig" \
  --pattern "${image_lock}.pem" \
  --pattern "${image_lock_sbom}" \
  --pattern "${image_lock_sbom}.sig" \
  --pattern "${image_lock_sbom}.pem" \
  --pattern "${capsule}" \
  --pattern "${capsule}.sig" \
  --pattern "${capsule}.pem" \
  --pattern "registry-relay.digest" \
  --pattern "registry-relay.digest.sig" \
  --pattern "registry-relay.digest.pem" \
  --pattern "registry-notary.digest" \
  --pattern "registry-notary.digest.sig" \
  --pattern "registry-notary.digest.pem" \
  --pattern "SHA256SUMS" \
  --pattern "${provenance}"
```

### Check The Binary And Image-Lock Hashes

```bash
sha256sum --check --ignore-missing SHA256SUMS
chmod 0755 "${asset}"
test "$("./${asset}" --version)" = "registryctl ${tag#v}"
```

`sha256sum` should report `OK` for the binary and image lock. The version check
proves that the binary searches for the same versioned lock shipped beside it.

### Verify The Strict Image-Lock Bindings

The lock is a release file, not an executable. Confirm its strict shape, release
identity, source lineage, platform, and literal digest-bound repositories:

```bash
jq -e --arg tag "${tag}" '
  keys == ["images", "manifest_source_ref", "platform", "release_tag", "schema_version", "tag_target"] and
  .schema_version == "registryctl.release_image_lock.v1" and
  .release_tag == $tag and
  .platform == "linux/amd64" and
  (.manifest_source_ref | test("^[0-9a-f]{40}$")) and
  (.tag_target | test("^[0-9a-f]{40}$")) and
  (.images | keys == ["registry-notary", "registry-relay"]) and
  (.images["registry-relay"] | test("^ghcr\\.io/registrystack/registry-relay@sha256:[0-9a-f]{64}$")) and
  (.images["registry-notary"] | test("^ghcr\\.io/registrystack/registry-notary@sha256:[0-9a-f]{64}$"))
' "${image_lock}"

test "$(jq -r .manifest_source_ref "${image_lock}")" = \
  "$(jq -r .source.source_ref "${capsule}")"
test "$(jq -r .tag_target "${image_lock}")" = \
  "$(jq -r .source.source_commit "${capsule}")"
cmp <(jq -r '.images["registry-relay"]' "${image_lock}") registry-relay.digest
cmp <(jq -r '.images["registry-notary"]' "${image_lock}") registry-notary.digest
```

### Verify The File SBOM And Capsule Classification

Confirm the SPDX file subject describes this JSON file and its actual hash, then
confirm the capsule classifies it under `release_files`, not `binaries`:

```bash
image_lock_sha=$(sha256sum "${image_lock}" | awk '{print $1}')
image_lock_sbom_sha=$(sha256sum "${image_lock_sbom}" | awk '{print $1}')

jq -e --arg name "${image_lock}" --arg sha "${image_lock_sha}" '
  .documentDescribes as $described |
  any(.packages[];
    (.SPDXID as $id | ($described | index($id)) != null) and
    .name == $name and
    .packageFileName == $name and
    any(.checksums[]; .algorithm == "SHA256" and .checksumValue == $sha)
  )
' "${image_lock_sbom}"

jq -e \
  --arg name "${image_lock}" \
  --arg sha "${image_lock_sha}" \
  --arg sbom "${image_lock_sbom}" \
  --arg sbom_sha "${image_lock_sbom_sha}" '
  any(.release_files[];
    .name == $name and
    .kind == "registryctl-release-image-lock" and
    .sha256 == $sha and
    .sbom.asset_name == $sbom and
    .sbom.sha256 == $sbom_sha
  ) and
  (all(.binaries[]; .name != $name))
' "${capsule}"
```

### Verify Signatures And Provenance For Every Lock Subject

```bash
for signed_asset in \
  "${asset}" \
  "${image_lock}" \
  "${image_lock_sbom}" \
  "${capsule}" \
  registry-relay.digest \
  registry-notary.digest
do
  cosign verify-blob "${signed_asset}" \
    --signature "${signed_asset}.sig" \
    --certificate "${signed_asset}.pem" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/tags/${tag}"

  slsa-verifier verify-artifact "${signed_asset}" \
    --provenance-path "${provenance}" \
    --source-uri github.com/registrystack/registry-stack \
    --source-tag "${tag}"
done
```

The provenance subject set covers release artifacts before their generated
`.sig` and `.pem` files are added. The lock, file-subject SBOM, capsule, and
exact Relay and Notary digest evidence are all independent signed and
provenance-covered subjects.

## Verify An Immutable Documentation Archive

Releases created after the immutable archive contract publish
`registry-docs-${tag}.tar.gz`. The archive digest must match the append-only
`docs/site/src/data/archive-lock.yaml` entry committed at that tag.

```bash
docs_archive="registry-docs-${tag}.tar.gz"
docs_archive_sbom="${docs_archive}.spdx.json"

gh release download "${tag}" \
  --repo registrystack/registry-stack \
  --pattern "${docs_archive}" \
  --pattern "${docs_archive}.sig" \
  --pattern "${docs_archive}.pem" \
  --pattern "${docs_archive_sbom}" \
  --pattern "${provenance}"

expected="$(
  gh api "repos/registrystack/registry-stack/contents/docs/site/src/data/archive-lock.yaml?ref=${tag}" \
    --jq .content | base64 --decode |
    python3 -c 'import sys,yaml; tag=sys.argv[1]; print(yaml.safe_load(sys.stdin)["archives"][tag]["bundle_sha256"])' "${tag}"
)"
test "$(sha256sum "${docs_archive}" | awk '{print $1}')" = "${expected}"

cosign verify-blob "${docs_archive}" \
  --signature "${docs_archive}.sig" \
  --certificate "${docs_archive}.pem" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/tags/${tag}"

slsa-verifier verify-artifact "${docs_archive}" \
  --provenance-path "${provenance}" \
  --source-uri github.com/registrystack/registry-stack \
  --source-tag "${tag}"
```

The file-subject SBOM and release capsule classify this payload as
`registry-docs-archive`. Pages verifies the same locked bundle and extracted
tree digests before serving it.

## Install Or Move Registryctl

For `v0.9.0` and later, the matching release installer checksum-verifies and
installs the binary and versioned image lock beside each other. Fetch the
installer from the same pinned tag whose assets it installs:

```bash
curl -fsSL "https://raw.githubusercontent.com/registrystack/registry-stack/refs/tags/${tag}/crates/registryctl/install.sh" |
  REGISTRYCTL_VERSION="${tag}" bash
```

A standalone or Cargo-installed registryctl does not acquire the `v0.9.0+`
lock automatically. After verifying it as above, either copy
`registryctl-${tag}-image-lock.json` beside the running binary or set
`REGISTRYCTL_IMAGE_LOCK` to its exact path. Registryctl never searches the
current working directory. Existing generated projects can start from their
stored digest pins without the lock, but `registryctl init` and `registryctl add`
fail before mutation when the matching lock is absent or invalid.

Registryctl `v0.8.4` predates this lock contract and remains a binary-only
installation.

## Promotion And Current Scope

The candidate workflow compiles the release payload before the tag exists.
The tag-bound workflow verifies the exact candidate run, attempt, receipt, and
bytes, then promotes those bytes without rebuilding product binaries.
It signs binaries, the registryctl image lock, the immutable documentation
archive, checksums, release file SBOMs,
image-input binary SBOMs, image evidence files, image SBOMs, Grype reports,
release capsules, and the candidate receipt before upload.
The separate SLSA generator publishes tag-bound provenance for those
non-signature artifacts.
OCI image signatures are not yet published for the root monorepo release.

The workflow never replaces assets on an existing GitHub Release.
If a tag run has already created the Release, fix forward with a new version
instead of rerunning it with `--clobber`.
This keeps published payloads, signatures, candidate receipt, and SLSA
provenance immutable as one set.

For a historical release rebuilt through the earlier `workflow_dispatch` path,
inspect the certificate identity, release capsule workflow URL, and SLSA
provenance source before accepting the asset.

Registry-pushed Notary and Relay image indexes retain BuildKit provenance.
`RELEASE_IMAGE_OCI_LAYOUT` disables timestamped BuildKit provenance only for
retained local layouts used in exact same-ref reproducibility comparisons.
Do not publish that comparison layout as the release image.
For post-tag verification, require the pushed image's Linux amd64 image config
and ordered rootfs layers to match the retained candidate proof, then verify
the published index's BuildKit provenance separately.

The release capsule summarizes binary asset hashes, the image lock and
documentation archive under `release_files`, file SBOM asset names, image
digests, image SBOMs, Grype
reports, workflow lineage, and release warnings. It does not carry
per-artifact signature or provenance status fields. Verify cosign signatures
from sibling `.sig` and `.pem` files, and verify the separately uploaded
release-level provenance asset with `slsa-verifier`.
