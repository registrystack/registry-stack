# Security Assurance

Registry Notary treats the current push to `main` as the release signal until a
tagged release workflow exists. The container workflow publishes
`ghcr.io/jeremi/registry-notary:sha-${GITHUB_SHA}` and
`ghcr.io/jeremi/registry-notary-openfn-sidecar:sha-${GITHUB_SHA}`; security
evidence is tied to those immutable SHA image tags.

Security waivers live in `security/waivers.yml` when needed. Each waiver must
name an owner, rationale, review trigger, and expiration. The default owner is
`@PublicSchema/maintainers`.

The unauthenticated endpoint allowlist lives in
`security/auth-none-allowlist.yml`. Additions require maintainer review through
CODEOWNERS.

GitHub Actions in this repo are SHA-pinned where practical. Any major-version
pin must include a workflow comment explaining why the tag movement is accepted.
`zizmor` and code review enforce least-privilege permissions and unsafe event
handling.

## OpenAPI comparison strategy

Notary's OpenAPI generator is deterministic:

```sh
cargo run -p registry-notary-bin -- openapi
```

CI compares that generated output with
`openapi/registry-notary.openapi.json`. Any difference is treated as API drift
and must be committed intentionally with review.

## Local security command

Run the practical local subset:

```sh
just security
```

This validates exposure contracts, Dockerfile secret-copy guardrails, the
OpenAPI baseline, workflow syntax/security tooling when installed, gitleaks
current-tree scanning, and Semgrep rules when installed.

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
- `zizmor` currently runs as advisory evidence with `--no-exit-codes` because
  the existing workflow baseline reports findings such as artifact permission
  hardening and action pinning policy. New workflow syntax is still blocked by
  `actionlint`, and the advisory report gives reviewers a ratchet list for
  follow-up hardening.
- Container image SBOM generation is enforced in CI. Grype image vulnerability
  reports currently run as advisory evidence and are uploaded with the image
  security artifact; the blocking threshold should be ratcheted on after the
  first reviewed image vulnerability baseline and any required waivers are in
  place.
- Local gitleaks enforcement scans the current tree with `--no-git`. A full
  history scan found pre-existing historical sample-token findings unrelated to
  this change, so history cleanup should be handled as a separate coordinated
  remediation.
- Hadolint ignores `DL3022` because the Dockerfiles intentionally copy from
  named external build contexts used by the sibling build workflow.
