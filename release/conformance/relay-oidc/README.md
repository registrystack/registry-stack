# Registry Relay OIDC release smoke

This directory owns the candidate-neutral Relay and Zitadel topology required
by issue #205. It exercises a published Registry Relay image as an OAuth 2.0
resource server with `auth.mode: oidc`. It does not build Relay from the source
checkout and does not depend on a hosted environment or Solmara Lab.

The topology uses digest-pinned Zitadel, PostgreSQL, and Python images. The
runner accepts Relay only as the exact image reference
`ghcr.io/registrystack/registry-relay@sha256:<digest>`. The candidate source
commit and release identifier are also mandatory, so an output cannot be
mistaken for evidence about a different candidate.

## Evidence boundary

The checked-in assets and their offline tests prove that the harness is
reviewable and candidate-neutral. They are not live release evidence. A live
run writes a report classified as `unreviewed-live-candidate-output` with
`review_required: true`. A maintainer must bind that report to the published
candidate manifest and review it before it can become release evidence.

The report contains identifiers, configuration and topology digests, bounded
diagnostics, and assertion results. It never contains the bootstrap PAT, client
secret, access token, database password, audit hash secret, or Zitadel master
key. Runtime secrets live only in a mode `0700` temporary directory, secret
files use mode `0600`, and the runner removes the exact Compose project,
volumes, and temporary directory even after a failed assertion. A canary scan
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

## Offline review

Python 3.11 or later is required. Validate the checked-in topology and render a
candidate-bound plan without Docker or network access:

```bash
release/scripts/relay-oidc-smoke.py validate

release/scripts/relay-oidc-smoke.py plan \
  --relay-image 'ghcr.io/registrystack/registry-relay@sha256:<64-lowercase-hex>' \
  --candidate-source-ref '<40-lowercase-hex-commit>' \
  --release-id '1.0.0-rc.1'
```

The plan deliberately records `live_evidence: false`.

## Run a published candidate

Docker with Docker Compose is required. The Relay image must already be
published by digest:

```bash
release/scripts/relay-oidc-smoke.py run \
  --relay-image 'ghcr.io/registrystack/registry-relay@sha256:<64-lowercase-hex>' \
  --candidate-source-ref '<40-lowercase-hex-commit>' \
  --release-id '1.0.0-rc.1'
```

The command prints only the path to the unreviewed report. Use `--output-dir`
to choose an empty report directory and `--host-port` only when a fixed free
loopback port is required. The default output is under
`target/relay-oidc-smoke/`, which Git ignores.

If teardown fails, treat the run as an error. The diagnostic includes the exact
random Compose project name only in the local command output, so an operator
can inspect and remove that isolated project without risking unrelated Docker
resources.
