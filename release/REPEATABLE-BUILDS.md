# Repeatable Build Evidence

Registry Stack release builds are intended to be repeatable from the release
tag, locked dependencies, and the pinned release builder image declared in
`.github/workflows/release.yml`.

## v0.12.2 Linux amd64 Binary and OCI Image Proof

On 2026-07-20 and 2026-07-21, `v0.12.2` was rebuilt and compared at both the
release preparation commit and the annotated tag target, then compared with
the successful published release workflow:

- Preparation commit (`P`):
  `0e76f5ea61f78bbc15d91fcb6e9dfcaa956c3df8`
- Annotated tag object:
  `3be92d5a0eee60c89c51a952f136611edf4f77e9`
- Tag target (`T`): `e25f081ce800ade13e892503cc19b96588e081ef`
- Published release: <https://github.com/registrystack/registry-stack/releases/tag/v0.12.2>
- Successful release workflow:
  <https://github.com/registrystack/registry-stack/actions/runs/29774136957>

### Canonical binary builds

Two independent builds at `P` and two independent builds at `T` used clean
source worktrees, initially empty independent Cargo and target directories,
and the canonical container paths implemented by
`release/scripts/build-release-binaries.sh`. All four builds produced
byte-identical Linux amd64 release binaries and image inputs. `P` and `T` also
matched each other exactly.

The release-binary SHA-256 inventory common to all four builds was:

```text
d5925c796401325da87d33c5947c6dd6cf401b0de229ab611646fe209de4b888  registry-manifest-v0.12.2-linux-amd64
1afc577165453ddb0b3c9e9cb0dff1b9429eb14439d367357e7313a860a64289  registry-notary-v0.12.2-linux-amd64
92eca85c6015429c2f55ca979a2b874483fb8932ee43c4fb19d5f46dadbd184d  registry-notary-cel-worker-v0.12.2-linux-amd64
2d85e540a9df62eb8ddd34c258184623934111ae7bb2389dba520424851f590a  registry-relay-v0.12.2-linux-amd64
93829df5f2f1c6c55051b079f2427d0f21c594fc5943a98126190751ed34c228  registry-relay-rhai-worker-v0.12.2-linux-amd64
1dc185b3aa56afaaacc805eedb5e8e301562b9bddc5a5d20a677bc242c48c966  registryctl-v0.12.2-linux-amd64
```

The image-input SHA-256 inventory common to all four builds was:

```text
f59ca2916e4f8868c7c857f3cfbb7e0799e1880ccb859831ac283e3ee4695389  RELEASE_BUILDER_IMAGE
b9d40cea2b7e044409aa92f9c2182c02f2ec656a9b2781cae26633c9abe4b07a  registry-notary
92eca85c6015429c2f55ca979a2b874483fb8932ee43c4fb19d5f46dadbd184d  registry-notary-cel-worker
2d85e540a9df62eb8ddd34c258184623934111ae7bb2389dba520424851f590a  registry-relay
93829df5f2f1c6c55051b079f2427d0f21c594fc5943a98126190751ed34c228  registry-relay-rhai-worker
```

The Linux binary and image-input artifacts downloaded from release workflow
run `29774136957` were byte-identical to the retained `T` inventories and
files.

### OCI image builds and publication

Two no-cache builds at `T` used the same image refs and deliberately different
input mtimes. For each product, the two builds had identical OCI layout bytes,
application manifest, and ordered rootfs layers. The exact Registry Notary
equality targets were:

- Application manifest:
  `sha256:3d5f1efa62ef4aff5a6a6141ea6646233360309562e66460030fe1a4114f73aa`
- Ordered rootfs-layers digest:
  `sha256:bbf1a58ea6bff27940a50d49cf8870851d6281f8675c11997a712b691fc0cdae`
- Reviewed rootfs aggregate:
  `sha256:2dd9f5f9d9eadcaa10644a977e3fad2b1e1b3b529c9b8fe647de34f5664dada3`

The exact Registry Relay equality targets were:

- Application manifest:
  `sha256:fd18796aba0f75840b2747a4c21e91e34d1e5befa5953a67fae532096d08afe5`
- Ordered rootfs-layers digest:
  `sha256:fb786a5e7f088821cec2fc6082d215d1c5f0662bf69b8360a15bc2cdbd28cd54`
- Reviewed rootfs aggregate:
  `sha256:47f838a9c902008b857ff83bd148f087941c2a04cdc732adf9ee1bda504e5b0f`

Both `P` image builds also had ordered rootfs bytes identical to their paired
`T` builds. The published Linux amd64 application manifests are exactly the
Notary and Relay application-manifest digests above, and all 23 ordered rootfs
layer descriptors for each published image match the retained `T` layout.

The published OCI index digests are
`sha256:fbb2bfc7db13a62ab79b85722569f01af510bd3a8278291c89a7cf2b7f9f262b`
for Notary and
`sha256:35d663e3b814207876fecc053eef1124e8c76f81c650da568483d356809536a4`
for Relay. They differ from the provenance-disabled local comparison layouts
as expected: each published index contains one Linux amd64 application
manifest and one associated BuildKit provenance attestation manifest.

### Scope and exclusions

The `registryctl` Linux arm64 and macOS arm64 binaries were not independently
rebuilt. This proof makes no bit-for-bit reproducibility claim for SBOM, Grype
report, release capsule, signature, certificate, or SLSA provenance bytes. A
provenance-bearing published OCI index digest is not expected to equal a
provenance-disabled local layout index. OCI image signatures were not
published; the release workflow's signatures cover GitHub Release evidence
files instead.

## v0.8.3 Linux amd64 Binary Proof

On 2026-06-26, the Linux amd64 binary release assets for `v0.8.3` were rebuilt
locally from the public release tag and compared against the published
`SHA256SUMS` file from the GitHub Release.

Release under test:

- Tag: `v0.8.3`
- Tag object: `0d55086a7db0ac4cb6c513b96e713ad22d8e145e`
- Tag target commit: `ecde458f08f9cf60fdc4f7a265902cf800822dac`
- Published release: <https://github.com/registrystack/registry-stack/releases/tag/v0.8.3>
- Published checksum file: `SHA256SUMS` from the `v0.8.3` GitHub Release

Builder environment:

- Release builder image:
  `rust@sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb`
- Docker client: `Docker version 29.4.0, build 9d7ad9f`
- Docker server: `29.4.0 aarch64 linux`
- Build container platform: `linux/amd64`

The rebuild used a detached worktree at `v0.8.3` and the same Linux amd64
binary build command from the `binaries` job in `.github/workflows/release.yml`.
The command rebuilt:

- `registryctl-v0.8.3-linux-amd64`
- `registry-manifest-v0.8.3-linux-amd64`
- `registry-relay-v0.8.3-linux-amd64`
- `registry-notary-v0.8.3-linux-amd64`

After the rebuild, the locally generated files were checked against the
published `SHA256SUMS` entries:

```text
registry-manifest-v0.8.3-linux-amd64: OK
registry-notary-v0.8.3-linux-amd64: OK
registry-relay-v0.8.3-linux-amd64: OK
registryctl-v0.8.3-linux-amd64: OK
```

The matching hashes were:

```text
9a5f1baa97969001a9968a467f2870bb749ab047a3bdb17bbda4a88d47438078  registry-manifest-v0.8.3-linux-amd64
bb04aaa219b7c46377d8b5e128a05e9651fc672fa18d77530c00f99d1fd5031b  registry-notary-v0.8.3-linux-amd64
62a687a58140b349ca20ec8e3fb800c858b4d4b01329bc55fc7979530675d39e  registry-relay-v0.8.3-linux-amd64
16ce960092c81841c1dbb43a34844adcc917fd9154f525e134339e018481cf62  registryctl-v0.8.3-linux-amd64
```

## Scope

This proof covers the Linux amd64 binary artifacts produced from source by the
release workflow's pinned Rust builder image. It does not claim bit-for-bit
reproduction of the macOS arm64 `registryctl` build, the Linux arm64
`registryctl` build, generated image evidence, release capsules, SBOMs, Grype
reports, signatures, certificates, or provenance files.

Signature, certificate, checksum, and SLSA provenance verification for the
published release assets is documented in `release/VERIFY.md`.
