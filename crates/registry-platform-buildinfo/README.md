# Registry Platform Build Info

`registry-platform-buildinfo` is the single place Registry Stack decides what
version text an executable reports. Legacy Stack executables print the crate's
`DISPLAY_VERSION`. Independently versioned products generate their own
`DISPLAY_VERSION` by calling `product::emit_product_build_info` from the
product package's build script.

A build reports the bare released version, such as `0.17.0`, only when the
build environment sets `REGISTRY_RELEASE_TAG` to that exact release tag,
`v0.17.0`. `release/scripts/build-release-binaries.sh` is the only supported
place that sets it, so released binaries and images carry it and nothing else
does.

Every other build reports a development version, such as `0.17.0-dev`: a local
`cargo build`, a CI build, and a build of protected `main` between releases.
Those builds share a source revision with the release whose version they
carry, so without the suffix an operator could not tell them apart. The suffix
matches the prerelease segment of the `v<version>-dev.<run>.<attempt>`
development tags the Evidence development build publishes.

A `REGISTRY_RELEASE_TAG` that names a different version fails the build rather
than downgrading to a development version, because that combination is a
misconfigured release build and not an ordinary one.

An independently versioned product release instead sets
`REGISTRY_PRODUCT_RELEASE_TAG` to `<product>/v<product-version>`, for example
`discovery/v0.44.0`. The product build script validates that marker against its
own Cargo package version and reports the bare product version. The marker is
scoped, so it cannot relabel another product executable and does not require
the internal build-info crate to share the product version. A product marker,
legacy Stack release marker, and nightly marker are mutually exclusive.

A legacy Stack release marker remains valid for a product while the product
and Stack package versions match. Once they diverge, the marker is still
validated against the Stack version, but the product reports its own
development version. This lets other Stack packages compile the product as a
dependency without claiming a product release. The Stack release must carry
the already published product artifact rather than ship that development
binary.

A nightly build sets `REGISTRY_NIGHTLY_TAG` instead. Its exact form is
`v<version>-nightly.<YYYYMMDD>.<40-character lowercase source SHA>`, and the
reported version is that full identity without the leading `v`. The base must
match the Cargo package version, the date must be valid, and the full source SHA
must be present. Setting both release markers fails the build, so a nightly can
never report itself as a numbered release.

For an independently versioned product, the common nightly tag remains
anchored to the Stack package version. The product reports its own version plus
the validated common nightly date and source suffix. For example, a Discovery
package at `1.7.2` built under
`v0.44.0-nightly.20261002.<source-sha>` reports
`1.7.2-nightly.20261002.<source-sha>`.

Cargo package versions are untouched by all of this. They stay canonical
`MAJOR.MINOR.PATCH` text, which release manifests, candidate schemas, and the
Evidence development build require.
