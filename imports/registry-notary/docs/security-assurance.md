# Security Assurance

Registry Notary's container workflow publishes release images from stable
`vX.Y.Z` tags and `registry-stack-technical-preview-<date-or-version>` tags to
`ghcr.io/jeremi/registry-notary` and
`ghcr.io/jeremi/registry-notary-openfn-sidecar`. Every release publishes
`sha-<commit-sha>` as the immutable image tag for both images. Stable releases
also update `vX.Y.Z`, `vX.Y`, `vX`, and `latest`; `latest` means latest stable
release. Technical-preview releases publish the matching
`registry-stack-technical-preview-<date-or-version>` alias and do not move
`latest`. Pull requests and `main` pushes build local validation images for
smoke, SBOM, and Grype evidence, but do not push GHCR tags. Nightly or manual
development snapshots publish `snapshot`, `snapshot-YYYYMMDD`, and
`snapshot-<shortsha>` unless both existing `snapshot` images'
`org.opencontainers.image.revision` labels already match the current `main`
revision. Final deployments should pin the selected images by digest.

The Registry Notary image is built with CEL and PKCS#11 compiled in. Runtime
use remains config-gated, and the image is covered by the CEL worker-protocol
smoke, SBOM, and Grype critical-vulnerability gate.

## Container runtime policy

The main Registry Notary image is a distroless Rust service image. Its runtime
stage must remain `gcr.io/distroless/cc-debian12:nonroot` pinned by digest,
shell-free, package-manager-free, and compatible with a binary healthcheck and
JSON-array entrypoint. The container CI guard enforces the runtime base,
`registry-notary healthcheck`, and `ENTRYPOINT ["/usr/local/bin/registry-notary"]`.

`Dockerfile.openfn-sidecar` is an intentional Node slim exception because it
ships the OpenFn JavaScript worker runtime and npm dependencies. It still uses a
JSON-array entrypoint, runs as the image's `node` user, and keeps its healthcheck
runtime-native with `node /opt/openfn/container-healthcheck.mjs`.

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

Published Registry Notary and source adapter sidecar image tags are signed with
keyless `cosign` from the container workflow after they are pushed to GHCR. The
workflow verifies that each pushed alias resolves to the same digest as that
image's `sha-<commit-sha>` tag and verifies the signature for every pushed ref
before it completes.

Verify a release alias and its immutable SHA tag resolve to the same digest:

```sh
docker buildx imagetools inspect ghcr.io/jeremi/registry-notary:sha-<commit-sha>
docker buildx imagetools inspect ghcr.io/jeremi/registry-notary:<release-alias>
docker buildx imagetools inspect ghcr.io/jeremi/registry-notary-openfn-sidecar:sha-<commit-sha>
docker buildx imagetools inspect ghcr.io/jeremi/registry-notary-openfn-sidecar:<release-alias>
```

Verify the cosign signature for a tag using the triggering Git release tag:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/jeremi/registry-notary/.github/workflows/container.yml@refs/tags/<git-tag>" \
  ghcr.io/jeremi/registry-notary:<tag>

cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/jeremi/registry-notary/.github/workflows/container.yml@refs/tags/<git-tag>" \
  ghcr.io/jeremi/registry-notary-openfn-sidecar:<tag>
```

The certificate identity is the Git tag that triggered the workflow, not
necessarily the GHCR tag being verified. When verifying moving aliases such as
`latest`, `vX`, `vX.Y`, or either image's immutable `sha-<commit-sha>` tag, set
`<git-tag>` to the stable `vX.Y.Z` tag or
`registry-stack-technical-preview-<date-or-version>` tag that produced the
alias. To verify a moving alias without preselecting one release tag, constrain
the signing workflow with a release-tag regexp:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/jeremi/registry-notary/\.github/workflows/container\.yml@refs/tags/(v[0-9]+\.[0-9]+\.[0-9]+|registry-stack-technical-preview-[0-9A-Za-z][0-9A-Za-z._-]*)$' \
  ghcr.io/jeremi/registry-notary:<moving-tag>

cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/jeremi/registry-notary/\.github/workflows/container\.yml@refs/tags/(v[0-9]+\.[0-9]+\.[0-9]+|registry-stack-technical-preview-[0-9A-Za-z][0-9A-Za-z._-]*)$' \
  ghcr.io/jeremi/registry-notary-openfn-sidecar:<moving-tag>
```

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

## Audit assurance posture

The operations posture report (`GET /admin/v1/posture`) carries an `audit`
object that describes, in a fixed vocabulary, the assurance properties of the
running audit pipeline. The object is computed from the resolved audit
configuration, never inferred from traffic, and always reports the same eight
fields so operators and reviewers can compare two deployments by reading one
block.

| Field | Values | Meaning |
| --- | --- | --- |
| `write_policy` | `fail_closed_route_families`, `availability_first` | Whether protected route families refuse to serve when the audit write cannot be made durable. Becomes `fail_closed_route_families` once keyed integrity is configured. |
| `redaction_mode` | `redacted` | Audit records carry redacted payloads; raw disclosure values are never written to the sink. |
| `hash_chain` | `process_local`, `none` | Whether consecutive records are linked by a per-process hash chain. `process_local` once keyed integrity is configured; `none` otherwise. |
| `keyed_integrity` | `hmac`, `none` | `hmac` when an HMAC key is supplied through the audit `hash_secret_env` setting, so records carry a keyed integrity tag; `none` when no key is set. |
| `sink_class` | `file`, `external`, `stdout`, `none` | Where audit records are written. `file` covers file and JSONL sinks; `external` covers syslog; `stdout` is the process stream; `none` means no sink is configured. |
| `retention_owner` | `operator`, `unspecified` | `operator` when the sink is durable (`file` or `external`), signalling that retention is the operator's responsibility; `unspecified` for non-durable sinks. |
| `checkpoints` | `unsupported` | Periodic signed checkpoints over the audit chain are not produced by this build. |
| `anchoring` | `none` | Audit state is not anchored to an external transparency log or ledger. |

Note: a running notary always reports `keyed_integrity = hmac` and
`write_policy = fail_closed_route_families` because startup refuses any
configuration that omits the `hash_secret_env` HMAC key; the `hmac` and
`none` rows in the table reflect the vocabulary, not states a live process can
reach.

Keyed integrity is the pivot. Supplying an HMAC key through the audit
`hash_secret_env` setting moves `keyed_integrity` to `hmac`, `hash_chain` to
`process_local`, and `write_policy` to `fail_closed_route_families` together,
because a keyed, chained audit trail is only meaningful if protected routes stop
serving rather than silently lose records. Durability of the sink, reported
through `sink_class` and `retention_owner`, is an independent axis: a keyed
pipeline can still write to `stdout`, and a durable `file` sink can still run
without a key.

These properties also feed the deployment profile gates. The
`notary.audit.sink_missing` gate refuses startup under the `production` and
`evidence_grade` profiles when no durable sink is configured, and downgrades to
a waivable finding under `hosted_lab`. See
[Deployment Profile and Gates](operator-config-reference.md#deployment-profile-and-gates)
for the full gate catalog and severities.

## Local security command

Run the practical local subset:

```sh
just security
```

This validates exposure contracts, Dockerfile secret-copy guardrails, the
OpenAPI baseline, workflow syntax/security tooling when installed, the reviewed
`zizmor` high-severity ratchet, gitleaks current-tree scanning, and Semgrep
rules when installed.
