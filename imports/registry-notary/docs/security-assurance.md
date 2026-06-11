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

## Deliberate route posture exceptions

Some routes deviate from the `/v1/` versioning convention by design. These
exceptions are recorded in `security/exposure-manifest.json` (per-entry
`notes`) and `security/auth-none-allowlist.yml` (per-entry `reason`).

### Bare VCT type-metadata routes

`GET /credentials/{*vct_path}` and `GET /.well-known/vct/{*vct_path}` are
deliberately unversioned (no `/v1/` prefix):

- **`/credentials/{*vct_path}`**: per SD-JWT VC type-metadata dereference, a
  client resolves credential type metadata by dereferencing the `vct` claim
  directly (which is `https://{host}/credentials/{vct_path}`). The server path
  must match the VCT URL path component exactly. Adding `/v1/` would break
  dereference for any credential whose `vct` does not include that prefix.
- **`/.well-known/vct/{*vct_path}`**: per RFC 8615, well-known URI paths are
  determined by the protocol and cannot be prefixed or versioned.

Both routes serve type metadata only and are unrelated to `POST /v1/credentials`
(credential issuance). The namespace proximity (`GET /credentials/*` vs
`POST /v1/credentials`) is a known hazard; it is resolved by documentation and
the explicit `deliberate freeze exception` notes in the exposure manifest rather
than by route changes that would violate the protocol constraints above.

## Local security command

Run the practical local subset:

```sh
just security
```

This validates exposure contracts, Dockerfile secret-copy guardrails, the
OpenAPI baseline, workflow syntax/security tooling when installed, the reviewed
`zizmor` high-severity ratchet, gitleaks current-tree scanning, and Semgrep
rules when installed.
