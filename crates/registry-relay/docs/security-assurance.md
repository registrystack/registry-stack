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

Security waivers live in `security/waivers.yml` when needed. Each waiver must
name an owner, rationale, review trigger, and expiration. The default owner is
`@PublicSchema/maintainers`.

Reviewed advisory ratchets live in `security/advisory-baseline.json`. The
initial blocking gates are:

- `zizmor` findings with severity `high` or above.
- Grype image findings with severity `critical` or above.

Every reviewed entry must include a fingerprint, owner, reason, review date,
and expiration date. New unreviewed findings at or above the threshold fail CI.
Expired reviewed entries fail CI while the finding is still active. Stale
reviewed entries are reported so the baseline can shrink after the underlying
issue is fixed.

The unauthenticated endpoint allowlist lives in
`security/auth-none-allowlist.yml`. Additions require maintainer review through
CODEOWNERS.

GitHub Actions in this repo intentionally use major-version pins for
well-known maintained actions unless a workflow documents a stronger SHA pin.
`zizmor`, the reviewed advisory baseline, and code review enforce
least-privilege permissions and unsafe event handling, not a blanket SHA-only
policy.

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

## Implementation review log

- Endpoint exposure is checked in three directions: route inventory to
  manifest, manifest to route inventory, and Rust Axum route declarations to
  route inventory. This caught and corrected the aggregate query route method,
  which was `POST` in Rust but `GET` in the initial inventory.
- Protected public routes with non-optional features are also covered by
  `tests/security_assurance_surface.rs`, which builds the production public app
  and verifies the manifest routes are actually mounted behind auth.
- Manifest entries marked `openapi: true` are now compared against the curated
  OpenAPI artifact with path-parameter normalization. `/.well-known/api-catalog`
  is intentionally marked `openapi: false` because it is not in the curated
  artifact.
- Enforcement evidence must reference concrete test functions using
  `path::test_name`; file-only references are rejected.
- `zizmor` still runs with `--no-exit-codes` so the tool can emit a complete
  JSON report, but `scripts/check_advisory_baselines.py` blocks unreviewed
  high-severity findings and expired reviewed entries.
- Container image SBOM generation is enforced in CI. Grype image vulnerability
  reports are emitted as JSON and `scripts/check_advisory_baselines.py` blocks
  unreviewed critical image findings. High-severity image findings remain the
  next ratchet target once critical baselines are stable.
- Hadolint ignores `DL3022` because the Dockerfile intentionally copies from
  named external build contexts. It also ignores `DL3008` for the apt package
  installation style already used in the relay container.
- Relay keeps the release OpenAPI artifact curated, so endpoint exposure drift
  is guarded by the exposure manifest plus baseline-vs-baseline OpenAPI review
  rather than a raw generated-vs-curated diff.
