# Registry Platform Build Info

`registry-platform-buildinfo` is the single place Registry Stack decides what
version text an executable reports. Every executable with a `--version` surface
prints `DISPLAY_VERSION` from this crate.

A build reports the bare released version, such as `0.17.0`, only when the
build environment sets `REGISTRY_RELEASE_TAG` to that exact release tag,
`v0.17.0`. `release/scripts/build-release-binaries.sh` is the only supported
place that sets it, so the released binaries and the Relay image carry it and
nothing else does.

Every other build reports a development version, such as `0.17.0-dev`: a local
`cargo build`, a CI build, and a build of protected `main` between releases.
Those builds share a source revision with the release whose version they
carry, so without the suffix an operator could not tell them apart. The suffix
matches the prerelease segment of the `v<version>-dev.<run>.<attempt>`
development tags the Evidence development build publishes.

A `REGISTRY_RELEASE_TAG` that names a different version fails the build rather
than downgrading to a development version, because that combination is a
misconfigured release build and not an ordinary one.

The Cargo package version is untouched by all of this. It stays canonical
`MAJOR.MINOR.PATCH` text, which the release manifests, candidate schemas, and
the Evidence development build all require.
