# Security assurance

The root monorepo release workflow publishes Registry Relay images from semver
`vX.Y.Z` release tags to `ghcr.io/registrystack/registry-relay:<tag>`. The
workflow records the pushed image digest, SBOM, and Grype report as GitHub
Release assets. It does not currently publish moving aliases such as `latest`,
`vX`, or `vX.Y`, snapshot tags, `sha-<commit-sha>` image tags, or OCI image
signatures for the container image itself. Final deployments should pin the
selected image by digest.

A release is gated on zero unreviewed `zizmor` findings at severity `high` or
above, zero fixable Grype image findings at any severity, zero unreviewed Grype
image findings at severity `high` or above, and no expired reviewed
advisory-baseline entry. Route exposure waivers, when
present, live on the affected `security/exposure-manifest.json` entry so the
review context stays with the route. GitHub Actions use major-version pins for
well-known maintained actions, with `zizmor`, the reviewed advisory baseline,
and code review enforcing least-privilege permissions and safe event handling
instead of a blanket SHA-only pin policy.

## Container base lifecycle

Maintained Relay builders and final images use Debian 13. Final production and
demo images use the shell-free Distroless `cc-debian13:nonroot` base and run as
UID/GID `65532:65532`. Debian 13 receives full Debian support through August 9,
2028 and LTS through June 30, 2030. Registry Stack must select a successor base
before the applicable support window ends. The upstream lifecycle is recorded
at <https://www.debian.org/releases/trixie/>.

All upstream bases are pinned to multi-architecture image-index digests. An
immutable digest makes a build input repeatable, but it does not make that input
perpetually current. Release operators refresh the Rust builder, preparation,
and Distroless digests together before each release candidate and whenever an
upstream security update or scan finding requires it. Run the repository gate
after every refresh:

```sh
python3 release/scripts/check-debian13-images.py
```

Changing the builder OS intentionally changes the release build input and may
change linked binary bytes even when Rust sources and the Rust toolchain version
do not change. Repeatability is therefore established by two clean builds with
the same new builder digest and lockfiles, comparing the generated
`dist/image-bin/SHA256SUMS`; it is not established by matching hashes produced
with the retired builder. The exact pushed candidate still needs its normal
digest-bound SBOM, Grype, release-capsule, and standalone implementer evidence.

The failed `v0.12.0` release workflow run `29714784416` scanned exact Relay
image digest
`sha256:06dddb1cb88bb9f5dfae8eacfb71e25a49e4a9d370a539b7ff2ce90259c59672`.
It confirmed the non-fixable Debian 13 `libc6` findings CVE-2026-5450
(Critical), CVE-2026-5928 (High), and CVE-2026-5435 (High). Debian classifies
all three Trixie issues as minor and no-DSA. The exact service's two direct
AWS-LC `sscanf` call sites use fixed `%lu` and `%lx` numeric formats. Neither
the service nor its linked libcrypto contains the vulnerable `%mc` conversion.
Neither the service nor Rhai worker imports `ungetwc` or the affected deprecated
DNS-printing functions. The libstdc++ object that imports `ungetwc` is not in
either executable dependency closure.

The implementation reviewed for the pre-tag `v0.12.1` candidate is protected-
main revision `d6d2d167426ada77097c8d5606f100b1554aaadc`, which remains an ancestor
of the release lineage. The versioned candidate was built with the release's
pinned Linux/amd64 builder and scanned at exact Relay image digest
`sha256:b1d93ce38ae70f27f2fd0b04bdd5deb5ab5f7772bd205188a64cff9dd6253168`.
Grype 0.114.0 with valid database schema v6.1.9, built July 19, 2026, reported
the same three non-fixable blocking-severity findings and no fixable finding.
The reviewed root filesystem digest is
`sha256:c399a0f9eb66fe583597398356893e92268c954ce905db8ca434e158b94743a8`.
Direct inspection of the candidate service and Rhai worker confirmed that they
do not import `ungetwc` or the affected DNS-printing functions and contain no
`%mc` format string. The tagged release must reproduce this root filesystem
digest and pass the same policy against its exact pushed digest.

The matching accepted-risk entries expire on August 20, 2026. A Trixie fix,
changed fingerprint, new scanf format or call path, new C++ or wide-character
input path, or new DNS TSIG debugging or printing path requires earlier review.
The accepted-risk entries record the evidence image digest and the reachable
protected-main implementation revision inspected during review. The exact
candidate OCI revision label is verified separately when the image is built.
Enforcement binds the review to a digest of the ordered root filesystem layers,
so a changed package or binary layer requires a new review while a review-only
commit that changes the OCI revision label does not create a self-referential
image digest. The next candidate must still produce an exact digest-bound scan;
this review does not waive fixable findings or a changed package fingerprint.

For each candidate, execute the image with a read-only root filesystem and only
the documented cache, data, and audit mounts writable. Confirm that the Relay
binary and Rhai worker run as `65532:65532`, CA roots support an HTTPS discovery
or PostgreSQL TLS journey, and readiness succeeds. These runtime results belong
to the exact candidate digest; the source checks do not substitute for them.

## Repository controls you can audit

- Route exposure waivers: [`security/exposure-manifest.json`](../security/exposure-manifest.json).
  Each endpoint carries enforcement tests or a narrow per-route waiver. There is
  no separate `security/waivers.yml` in this repository; deployment-gate waivers
  are runtime configuration and surface through the admin posture document.
- Reviewed advisory ratchets: [`security/advisory-baseline.json`](../security/advisory-baseline.json).
  Fixable Grype findings block at every severity and cannot be dispositioned.
  Each reviewed High or Critical entry names a matching rule and severity,
  owner, reason, review date, expiration date, evidence image digest and
  revision, and the root filesystem layer digest enforced by the checker.
  Future-dated, expired, or rootfs-mismatched entries fail while the finding is
  active. Stale reviewed entries are reported so the baseline can shrink after
  the underlying issue is fixed.
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
