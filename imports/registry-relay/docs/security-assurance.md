# Security Assurance

Registry Relay treats the current push to `main` as the release signal until a
tagged release workflow exists. The container workflow publishes
`ghcr.io/jeremi/registry-relay:sha-${GITHUB_SHA}` and `:main`; security evidence
is tied to the immutable `sha-${GITHUB_SHA}` image.

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
