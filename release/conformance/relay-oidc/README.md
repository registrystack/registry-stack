# Registry Relay OIDC release smoke

This directory owns the candidate-neutral Relay and Zitadel topology required
by issue #205. It exercises a published Registry Relay image as an OAuth 2.0
resource server with `auth.mode: oidc`. It does not build Relay from the source
checkout and does not depend on a hosted environment or Solmara Lab.

The topology uses digest-pinned Zitadel, PostgreSQL, and Python images. The
runner resolves Relay from the exact release manifest and matching
`registryctl-<tag>-image-lock.json` release asset. It rejects a source-ref,
release-tag, product-version, or image-digest mismatch before starting Docker.
The image lock must remain in its downloaded release asset directory alongside
`SHA256SUMS`, the release capsule, the shared release provenance, and the
Cosign signature and certificate files for both the image lock and capsule.
The runner verifies those bindings with installed `cosign` and `slsa-verifier`
before using either product image digest.

## Evidence boundary

The checked-in assets and their offline tests prove that the harness is
reviewable and candidate-neutral. They are not live release evidence. A live
run writes a report classified as `unreviewed-live-candidate-output` with
`review_required: true`. A maintainer must review the embedded candidate
binding and results before the report can become release evidence.

The report contains identifiers, configuration and topology digests, bounded
diagnostics, and assertion results. It never contains the bootstrap PAT, client
secret, access token, database password, audit hash secret, or Zitadel master
key. Runtime secrets are not confined to files while the smoke is running. The
database password, audit hash secret, and secret canary exist ephemerally in
isolated container environment metadata, and the Zitadel master key exists in
its container command metadata. A Docker daemon administrator can inspect that
metadata during the run. The bootstrap PAT lives in a project-scoped named
volume. The generated client secret and access token are stored only in mode
`0600` files under the runner's mode `0700` private runtime directory, which is
bind-mounted into the helper; the helper necessarily also handles them in
process memory and request headers.

The HTTP clients bypass environment proxies and never follow redirects, so the
bootstrap PAT, client credentials, and Relay bearer remain on their exact local
origin. The runner removes the exact Compose project, its named volumes, and
the private runtime directory even after a failed assertion. A canary scan
rejects secret material in subprocess output and the report.

Do not commit a raw or unreviewed run directory. Do not describe a development
or earlier-release image run as evidence for a 1.0 release candidate.

## What the live smoke asserts

The runner provisions a fresh Zitadel project, native project role, and machine
service account. It requests the role using Zitadel's native project-role
scope, inspects the resulting role-object claim, and binds Relay to Zitadel's
project-specific native claim name. The legacy native claim name remains
accepted for Zitadel compatibility. Relay maps `registry-smoke-reader` to
`smoke_registry:metadata` and requires the service account's organization key
to carry an active value.

It then requires these exact results:

- the running Relay container references the requested digest;
- no credential returns `401 auth.missing_credential`;
- the valid Zitadel role token returns `200` and exposes the synthetic dataset;
- a structurally valid token with a changed signature returns
  `401 auth.token_signature_invalid`;
- an audience mismatch returns `401 auth.audience_mismatch`;
- an unaccepted JOSE token type returns `401 auth.malformed_credential`; and
- a role-object organization-key mismatch returns `403 auth.scope_denied`.

Zitadel, the helper, and Relay share Zitadel's network namespace. This keeps the
HTTP issuer and discovery URL on loopback, which is the only insecure fetch
form Relay permits for local development. The Relay API is published separately
on a randomly selected loopback port.

## Candidate review

Python 3.11 or later is required. Validate the checked-in topology and render a
candidate-bound plan without Docker. Candidate binding invokes `cosign` and
`slsa-verifier`, which may use their normal verification network paths:

```bash
release/scripts/relay-oidc-smoke.py validate

release/scripts/relay-oidc-smoke.py plan \
  --release-manifest 'release/manifests/registry-stack-<release-id>.yaml' \
  --image-lock '/private/path/registryctl-v<version>-image-lock.json'
```

The plan deliberately records `live_evidence: false`.

## Run a published candidate

Docker with Docker Compose is required. The Relay image must already be
published by digest:

```bash
release/scripts/relay-oidc-smoke.py run \
  --release-manifest 'release/manifests/registry-stack-<release-id>.yaml' \
  --image-lock '/private/path/registryctl-v<version>-image-lock.json'
```

The command prints only the path to the unreviewed report. Use `--output-dir`
to choose an empty report directory and `--host-port` only when a fixed free
loopback port is required. The default output is under
`target/relay-oidc-smoke/`, which Git ignores.

The release-owned topology is the default. An optional Solmara adopter
exercise must add
`--topology solmara --solmara-source-ref '<40-lowercase-hex-commit>'`;
an unpinned Solmara checkout is rejected.

If teardown fails, treat the run as an error. The diagnostic includes the exact
random Compose project name only in the local command output, so an operator
can inspect and remove that isolated project without risking unrelated Docker
resources.
