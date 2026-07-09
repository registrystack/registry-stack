# Security assurance

The root monorepo release workflow publishes Registry Relay images from semver
`vX.Y.Z` release tags to `ghcr.io/registrystack/registry-relay:<tag>`. The
workflow records the pushed image digest, SBOM, and Grype report as GitHub
Release assets. It does not currently publish moving aliases such as `latest`,
`vX`, or `vX.Y`, snapshot tags, `sha-<commit-sha>` image tags, or OCI image
signatures for the container image itself. Final deployments should pin the
selected image by digest.

A release is gated on zero unreviewed `zizmor` findings at severity `high` or
above, zero unreviewed Grype image findings at severity `critical` or above,
and no expired reviewed advisory-baseline entry. Route exposure waivers, when
present, live on the affected `security/exposure-manifest.json` entry so the
review context stays with the route. GitHub Actions use major-version pins for
well-known maintained actions, with `zizmor`, the reviewed advisory baseline,
and code review enforcing least-privilege permissions and safe event handling
instead of a blanket SHA-only pin policy.

## Repository controls you can audit

- Route exposure waivers: [`security/exposure-manifest.json`](../security/exposure-manifest.json).
  Each endpoint carries enforcement tests or a narrow per-route waiver. There is
  no separate `security/waivers.yml` in this repository; deployment-gate waivers
  are runtime configuration and surface through the admin posture document.
- Reviewed advisory ratchets: [`security/advisory-baseline.json`](../security/advisory-baseline.json).
  Each reviewed entry names a fingerprint, owner, reason, review date, and
  expiration date. Stale reviewed entries are reported so the baseline can
  shrink after the underlying issue is fixed.
- Unauthenticated endpoint allowlist: [`security/auth-none-allowlist.yml`](../security/auth-none-allowlist.yml).
  Additions require maintainer review through [CODEOWNERS](../CODEOWNERS).
- GitHub Actions pinning: most workflows pin well-known maintained actions to
  a major version; individual workflows document a stronger SHA pin where one
  is required.

## OpenAPI comparison strategy

Relay has two OpenAPI shapes:

- `openapi/registry-relay.openapi.json` is the curated release artifact for the
  default feature build.
- Runtime OpenAPI is config-expanded, scope-filtered, and may inline parameters.

Because generated-vs-curated comparison creates false positives, the Relay
OpenAPI drift check uses baseline-vs-baseline comparison of the committed
curated artifact across revisions and keeps the runtime generator covered by
existing Rust tests. A future normalizer may replace this with
generated-vs-normalized comparison once both shapes can be canonicalized without
losing security scheme or route semantics.

Default-feature manifest entries marked `openapi: true` are compared against the
curated OpenAPI artifact with path-parameter normalization. Feature-gated
manifest entries remain in the exposure inventory, but they are not required in
the default artifact unless the default feature set enables them.

## Image release evidence

The root monorepo release workflow publishes Registry Relay image digests, image
SBOMs, vulnerability scan reports, release capsules, and keyless cosign
signatures for GitHub Release assets. The workflow signs the release asset
files, including image evidence files, but does not yet publish OCI image
signatures for the container images themselves.

Older product-local workflows used keyless `cosign` for product images under
the previous GHCR namespace. Treat those records as legacy product-specific
history, not as evidence that current root monorepo OCI images are signed.

Verify an immutable image digest from the root release capsule:

```sh
docker buildx imagetools inspect ghcr.io/registrystack/registry-relay@sha256:<digest>
```

Verify the release capsule, binary assets, SBOMs, and image evidence files with
the root release verification procedure:

```sh
less release/VERIFY.md
```

Previous product-local releases used keyless `cosign` for image tags under the
old personal GHCR namespace and product-local workflow identities. Treat those
records as legacy evidence for those historical artifacts only; they do not
verify current `ghcr.io/registrystack` monorepo images.

## Local security command

Run the practical local subset:

```sh
just security
```

This validates exposure contracts, Dockerfile secret-copy guardrails, optional
GitHub Actions tooling when installed for workflow files in scope, the reviewed
`zizmor` high-severity ratchet, gitleaks current-tree scanning, and Semgrep
rules when installed.

Endpoint exposure is checked in three directions: route inventory to
manifest, manifest to route inventory, and Rust Axum route declarations to
route inventory. Protected public routes with non-optional features are also
covered by `tests/security_assurance_surface.rs`, which builds the production
public app and verifies the manifest routes are actually mounted behind auth.

Hadolint ignores `DL3022` because the Dockerfile intentionally copies from
named external build contexts. It also ignores `DL3008` for the apt package
installation style already used in the relay container.
