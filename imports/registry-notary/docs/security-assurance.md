# Security Assurance

Registry Notary's container workflow publishes stable images only from
`vX.Y.Z` tags to `ghcr.io/jeremi/registry-notary` and
`ghcr.io/jeremi/registry-notary-openfn-sidecar`. Release tags also update
`vX.Y`, `vX`, and `latest`; `latest` means latest stable release. Pull requests
and `main` pushes build local validation images for smoke, SBOM, and Grype
evidence, but do not push GHCR tags. Nightly or manual development snapshots
publish `snapshot`, `snapshot-YYYYMMDD`, and `snapshot-<shortsha>` unless both
existing `snapshot` images' `org.opencontainers.image.revision` labels already
match the current `main` revision. Final deployments should pin the selected
images by digest.

The Registry Notary image is built with CEL and PKCS#11 compiled in. Runtime
use remains config-gated, and the image is covered by the CEL worker-protocol
smoke, SBOM, and Grype critical-vulnerability gate.

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

GitHub Actions in this repo are SHA-pinned where practical. Any major-version
pin must include a workflow comment explaining why the tag movement is accepted.
`zizmor`, the reviewed advisory baseline, and code review enforce
least-privilege permissions and unsafe event handling.

## OpenAPI comparison strategy

Notary's OpenAPI generator is deterministic:

```sh
cargo run -p registry-notary-bin -- openapi
```

CI compares that generated output with
`openapi/registry-notary.openapi.json`. Any difference is treated as API drift
and must be committed intentionally with review.

## Image signing status

Registry Notary release images are not signed with `cosign` or another image
signature workflow yet. The current release evidence relies on immutable
`vX.Y.Z` tags, digest pinning, SBOM generation, and Grype image vulnerability
reports.
Operators should pin the selected image by digest and treat image-signature
verification as not available for this release.

## Local security command

Run the practical local subset:

```sh
just security
```

This validates exposure contracts, Dockerfile secret-copy guardrails, the
OpenAPI baseline, workflow syntax/security tooling when installed, the reviewed
`zizmor` high-severity ratchet, gitleaks current-tree scanning, and Semgrep
rules when installed.

