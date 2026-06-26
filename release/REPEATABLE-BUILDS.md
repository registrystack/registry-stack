# Repeatable Build Evidence

Registry Stack release builds are intended to be repeatable from the release
tag, locked dependencies, and the pinned release builder image declared in
`.github/workflows/release.yml`.

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
