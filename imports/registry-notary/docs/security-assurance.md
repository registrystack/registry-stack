# Security Assurance

Registry Notary's container workflow publishes
`ghcr.io/jeremi/registry-notary:sha-${GITHUB_SHA}` and
`ghcr.io/jeremi/registry-notary-openfn-sidecar:sha-${GITHUB_SHA}`. Those
immutable SHA image tags are CI artifacts used for evidence gathering. First
serious release readiness is established through the coordinated pre-tag release
plan; final deployments should pin the selected images by digest.

The optional CEL-enabled image is published as
`ghcr.io/jeremi/registry-notary:sha-${GITHUB_SHA}-cel` and is covered by the
same worker-protocol smoke, SBOM, and Grype critical-vulnerability gate.

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
`sha-${GITHUB_SHA}` tags, digest pinning, SBOM generation, and Grype image
vulnerability reports. Operators should pin the selected image by digest and
treat image-signature verification as not available for this release.

## Local security command

Run the practical local subset:

```sh
just security
```

This validates exposure contracts, Dockerfile secret-copy guardrails, the
OpenAPI baseline, workflow syntax/security tooling when installed, the reviewed
`zizmor` high-severity ratchet, gitleaks current-tree scanning, and Semgrep
rules when installed.

## Implementation review log

- Endpoint exposure is checked in three directions: route inventory to
  manifest, manifest to route inventory, and Rust Axum route declarations to
  route inventory.
- Manifest entries marked `openapi: true` are compared against the committed
  generated OpenAPI baseline with path-parameter normalization, including Axum
  catch-all paths such as `/credentials/{*vct_path}`.
- Enforcement evidence must reference concrete test functions using
  `path::test_name`; file-only references are rejected.
- The standalone auth bypass uses exact matched route templates for public
  probe paths. Prefix-based bypass for `/v1/credentials/...` was removed so a
  future route under that prefix will not silently become public.
- Some Notary endpoints require an authenticated principal without a fixed
  route-level scope. The manifest records those as `scopes: []` rather than
  overstating an `evidence:metadata` scope requirement.
- `zizmor` still runs with `--no-exit-codes` so the tool can emit a complete
  JSON report, but `scripts/check_advisory_baselines.py` blocks unreviewed
  high-severity findings and expired reviewed entries.
- Container image SBOM generation is enforced in CI. Grype image vulnerability
  reports are emitted as JSON and `scripts/check_advisory_baselines.py` blocks
  unreviewed critical image findings. High-severity image findings remain the
  next ratchet target once critical baselines are stable.
- Local gitleaks enforcement scans the current tree with `--no-git`. A full
  history scan found pre-existing historical sample-token findings unrelated to
  this change, so history cleanup should be handled as a separate coordinated
  remediation.
- Hadolint ignores `DL3022` because the Dockerfiles intentionally copy from
  named external build contexts used by the sibling build workflow.
