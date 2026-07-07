# Security assurance

Registry Relay's container workflow publishes release images from stable
`vX.Y.Z` tags and `registry-stack-technical-preview-<date-or-version>` tags to
`ghcr.io/registrystack/registry-relay`. Every release publishes
`sha-<commit-sha>` as the immutable image tag. Stable releases also update
`vX.Y.Z`, `vX.Y`, `vX`, and `latest`; `latest` means latest stable release.
Technical-preview releases publish the matching
`registry-stack-technical-preview-<date-or-version>` alias and do not move
`latest`. Pull requests and `main` pushes build a local validation image for
smoke, SBOM, and Grype evidence, but do not push a GHCR tag. Nightly or manual
development snapshots publish `snapshot`, `snapshot-YYYYMMDD`, and
`snapshot-<shortsha>` only when the existing `snapshot` image's
`org.opencontainers.image.revision` label does not already match the current
`main` revision. Final deployments should pin the selected image by digest.

A release is gated on zero unreviewed `zizmor` findings at severity `high` or
above, zero unreviewed Grype image findings at severity `critical` or above,
and no expired security waiver or advisory-baseline entry; GitHub Actions use
major-version pins for well-known maintained actions, with `zizmor`, the
reviewed advisory baseline, and code review enforcing least-privilege
permissions and safe event handling instead of a blanket SHA-only pin policy.

## Repository controls you can audit

- Security waivers: `security/waivers.yml`. Each waiver names an owner,
  rationale, review trigger, and expiration. The default owner is
  `@PublicSchema/maintainers`.
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

- `openapi/registry-relay.openapi.json` is the curated release artifact.
- Runtime OpenAPI is config-expanded, scope-filtered, and may inline parameters.

Because generated-vs-curated comparison creates false positives, the Relay
OpenAPI drift check uses baseline-vs-baseline comparison of the committed
curated artifact across revisions and keeps the runtime generator covered by
existing Rust tests. A future normalizer may replace this with
generated-vs-normalized comparison once both shapes can be canonicalized without
losing security scheme or route semantics.

Manifest entries marked `openapi: true` are compared against the curated
OpenAPI artifact with path-parameter normalization. `/.well-known/api-catalog`
is intentionally marked `openapi: false` because it is not in the curated
artifact.

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

Legacy product-local cosign verification for old `ghcr.io/jeremi` image tags
used the triggering Git release tag:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/jeremi/registry-relay/.github/workflows/container.yml@refs/tags/<git-tag>" \
  ghcr.io/jeremi/registry-relay:<tag>
```

For those legacy image tags, the certificate identity is the Git tag that
triggered the workflow, not
necessarily the GHCR tag being verified. When verifying moving aliases such as
`latest`, `vX`, `vX.Y`, or the immutable `sha-<commit-sha>` tag, set
`<git-tag>` to the stable `vX.Y.Z` tag or
`registry-stack-technical-preview-<date-or-version>` tag that produced the
alias. To verify a moving alias without preselecting one release tag, constrain
the signing workflow with a release-tag regexp:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/jeremi/registry-relay/\.github/workflows/container\.yml@refs/tags/(v[0-9]+\.[0-9]+\.[0-9]+|registry-stack-technical-preview-[0-9A-Za-z][0-9A-Za-z._-]*)$' \
  ghcr.io/jeremi/registry-relay:<moving-tag>
```

## Local security command

Run the practical local subset:

```sh
just security
```

This validates exposure contracts, Dockerfile secret-copy guardrails, workflow
syntax/security tooling when installed, the reviewed `zizmor` high-severity
ratchet, gitleaks current-tree scanning, and Semgrep rules when installed.

Endpoint exposure is checked in three directions: route inventory to
manifest, manifest to route inventory, and Rust Axum route declarations to
route inventory. Protected public routes with non-optional features are also
covered by `tests/security_assurance_surface.rs`, which builds the production
public app and verifies the manifest routes are actually mounted behind auth.

Hadolint ignores `DL3022` because the Dockerfile intentionally copies from
named external build contexts. It also ignores `DL3008` for the apt package
installation style already used in the relay container.
