# Security Assurance

The root monorepo release workflow publishes Registry Notary images from semver
`vX.Y.Z` release tags to `ghcr.io/registrystack/registry-notary:<tag>`. The
workflow records the pushed image digests, SBOMs, and Grype reports as GitHub
Release assets. It does not currently publish moving aliases such as `latest`,
`vX`, or `vX.Y`, snapshot tags, `sha-<commit-sha>` image tags, or OCI image
signatures for the container images themselves. Final deployments should pin
the selected images by digest.

The Registry Notary image is built with CEL and PKCS#11 compiled in. Runtime
use remains config-gated, and the image is covered by the CEL worker-protocol
smoke, SBOM, and Grype gate for every fixable finding plus every unreviewed High
or Critical finding.

## Container runtime policy

The main Registry Notary image is a distroless Rust service image. Its runtime
stage must remain `gcr.io/distroless/cc-debian13:nonroot` pinned by digest,
shell-free, package-manager-free, and compatible with a binary healthcheck and
JSON-array entrypoint. The container CI guard enforces the runtime base,
`registry-notary healthcheck`, and `ENTRYPOINT ["/usr/local/bin/registry-notary"]`.

Debian 13 receives full Debian support through August 9, 2028 and LTS through
June 30, 2030. Registry Stack must select a successor base before the applicable
support window ends. The upstream lifecycle is recorded at
<https://www.debian.org/releases/trixie/>. The Rust builder, runtime-preparation,
and Distroless bases are pinned to multi-architecture image-index digests. An
immutable digest makes a build input repeatable, but it does not make that input
perpetually current. Release operators refresh all three pins together before
each release candidate and whenever an upstream security update or scan finding
requires it, then run:

```sh
python3 release/scripts/check-debian13-images.py
```

Changing the builder OS intentionally changes the release build input and may
change linked binary bytes even when Rust sources and the Rust toolchain version
do not change. Repeatability is established by two clean builds with the same
new builder digest and lockfiles, comparing `dist/image-bin/SHA256SUMS`; hashes
from the retired builder are not the expected comparison.

The Debian 13 migration check on July 19, 2026 scanned a structural Notary
image with the pinned final base and placeholder binaries. It found the
non-fixable Debian 13 `libc6` findings CVE-2026-5450 (Critical), CVE-2026-5928
(High), and CVE-2026-5435 (High). No risk dispositions are recorded for these
findings, so a candidate that still reports them remains blocked. This
structural scan only supports removal of the retired Debian 12 exception. The
scan of the exact pushed image, including the real Notary and CEL worker
binaries, supersedes it for release decisions.

PKCS#11 support remains compiled in but config-gated. A vendor module and any
vendor-owned shared-library dependencies remain deployment inputs, not image
layers. Mount them read-only at operator-owned absolute paths and set the
provider's `module_path` to the mounted module. Do not copy an HSM module, PIN,
token database, or vendor configuration into the image. Because Distroless has
no package manager, the exact candidate must prove that the intended external
module and its dependency closure load on this base.

For each candidate digest, run the Notary container as UID/GID `65532:65532`
with a read-only root filesystem and only explicitly documented state and audit
mounts writable. Verify CA-root TLS, binary and CEL-worker execution, PKCS#11
module loading and signing, filesystem permissions, `registry-notary
healthcheck`, and readiness. The release workflow must then produce digest-bound
SBOM, Grype, and capsule evidence. These candidate checks cannot be inferred
from source-only image-contract tests.

Route exposure waivers, when needed, live on the affected entry in
`security/exposure-manifest.json` so the review context stays with the route.
There is no separate `security/waivers.yml` in this repository;
deployment-gate waivers are runtime configuration and surface through the admin
posture document.

Reviewed advisory ratchets live in `security/advisory-baseline.json`. The
initial blocking gates are:

- `zizmor` findings with severity `high` or above.
- Grype image findings with a known fix, regardless of severity.
- Grype image findings with severity `high` or above when they do not have a
  current reviewed disposition.

Fixable findings cannot be dispositioned. Every reviewed non-fixable High or
Critical finding must include a fingerprint, matching rule and severity, owner,
reason, review date, and expiration date. Future-dated or expired entries fail
CI while the finding is still active. Stale reviewed entries are reported so
the baseline can shrink after the underlying issue is fixed.

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
cargo run -p registry-notary -- openapi
```

CI compares that generated output with
`openapi/registry-notary.openapi.json`. Any difference is treated as API drift
and must be committed intentionally with review.

## Image release evidence

The root monorepo release workflow publishes Registry Notary image digests,
image SBOMs, vulnerability scan reports, release capsules, and keyless cosign
signatures for GitHub Release assets. The workflow signs the release asset
files, including image evidence files, but does not yet publish OCI image
signatures for the container images themselves.

Older product-local workflows used keyless `cosign` for product images under
the previous GHCR namespace. Treat those records as legacy product-specific
history, not as evidence that current root monorepo OCI images are signed.

Verify an immutable image digest from the root release capsule:

```sh
docker buildx imagetools inspect ghcr.io/registrystack/registry-notary@sha256:<digest>
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

## Deliberate route posture exceptions

Some routes deviate from the `/v1/` versioning convention by design. These
exceptions are recorded in `security/exposure-manifest.json` (per-entry
`notes`) and `security/auth-none-allowlist.yml` (per-entry `reason`).

### Protected evidence-service discovery

`GET /.well-known/evidence-service` is intentionally unversioned because it is
a discovery route, but it is not on the unauthenticated allowlist. It exposes
configured Notary capability metadata and requires normal Notary caller
credentials. `server.openapi_requires_auth` only controls `/openapi.json`; it
does not make evidence-service discovery public.

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

The nested `posture.audit` diagnostic block also reports the audit shipping
target as two fields: `shipping_target_configured` and `shipping_target`, where
`shipping_target` is `stdout`, `syslog`, `declared_external`, `none`, or
`unknown`. Both are DECLARED state derived from configuration, the sink type
plus the operator's `deployment.evidence.audit_offhost_shipping` attestation,
not observed delivery health: a local file sink counts as having a shipping
target only when the operator attests that logs are shipped off-host.

When `deployment.evidence.audit_ack_cursor_path` points at the local state
file an off-host audit shipper writes on each successful hand-off (the
`registry.audit.ack_cursor.v1` contract: `acked_at`, `last_acked_hash`, an
optional `writer`), the block adds two more fields: `shipping_health` (`ok`,
`stale`, `missing`, `invalid`, `unverified`, or `null`) and
`shipping_observed_at` (the cursor's `acked_at`, or `null`). Both are `null`
whenever `shipping_target_configured` is `false`; `shipping_health` is
`unverified` when no cursor is configured or an offline diagnostic cannot bind
it to a live chain. Runtime `ok` requires both a fresh `acked_at` and a
`last_acked_hash` equal to the current keyed audit-chain tail, establishing a
zero local backlog for the trusted shipper's claim. The cursor is unsigned
local state, so this is not cryptographic proof of remote receipt. A mismatch,
missing or stale cursor, unsafe file type, cursor larger than 16 KiB, or cursor
read that exceeds 500 ms fails closed. The shipper must atomically replace the
cursor, keep it on local storage, and run independently of Notary readiness.
The signed-bundle acceptance audit advances the tail before Notary serves
requests, so an evidence-grade instance stays not ready until the shipper
acknowledges that boot record. Offline `registry-notary doctor` cannot bind to
the live tail and reports a fresh cursor as `unverified`. Evidence-grade
deployments require the cursor at startup and recheck it for every readiness
and posture request.

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

For contributors working in the repository, run the practical local subset:

```sh
just security
```

This validates exposure contracts, Dockerfile secret-copy guardrails, the
OpenAPI baseline, optional GitHub Actions tooling when installed for workflow
files in scope, the reviewed `zizmor` high-severity ratchet, gitleaks
current-tree scanning, and Semgrep rules when installed.
