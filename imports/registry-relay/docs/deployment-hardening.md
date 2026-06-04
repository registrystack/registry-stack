# Deployment Hardening Guide

This checklist is for operators taking Registry Relay beyond a local demo. It
collects security and reliability decisions that are spread across the
configuration and operations docs.

## Network Boundaries

- Put the public data-plane listener behind TLS.
- Bind the admin listener only to a private interface or localhost behind an
  operator-only tunnel.
- Do not expose admin reload or metrics routes through the public ingress.
- Rate-limit at the edge for broad metadata discovery and expensive aggregate
  workflows.
- Preserve request ids and trace headers through the proxy when your logging
  policy allows them.

## Auth

- Prefer OIDC for multi-service production deployments.
- Use API keys only when the deployment has a rotation and storage workflow.
- Grant dataset scopes narrowly.
- Keep metadata, rows, aggregates, evidence-oriented access, and admin scopes
  separate.
- Review `scope_map` whenever IdP role names change.
- Test denied callers for every exposed dataset and adapter.

## Secrets

- Store API-key hashes, audit hash secrets, OIDC client material, database
  passwords, and provenance signing keys in the platform secret manager.
- Never put raw keys or private JWKs in YAML, image layers, shell history,
  crash reports, or issue trackers.
- Disable full environment dumps in diagnostics.
- Rotate provenance signing keys with a DID document overlap window long enough
  for existing credentials to expire.

## Source Data

- Mount file sources read-only.
- Use database credentials with read-only privileges.
- Keep live PostgreSQL sources bounded by configured projections, filters, and
  limits.
- Treat table ids, column names, source paths, and query text as operator
  internals unless explicitly published through metadata.
- Keep cache directories writable only by the Relay service account.

## Audit And Logs

- Configure an audit sink before production use.
- Use append-only storage where the platform supports it.
- Set `audit.hash_secret_env` to deployment-specific random secret material.
- Mark identifier fields `sensitive: true` when query values need audit
  redaction or deterministic hashing.
- Remember that `sensitive: true` is audit-only. It does not hide fields from
  authorized responses.
- Do not log bearer tokens, raw API keys, raw query values, row bodies, VC-JWTs,
  or unreviewed Problem Details `detail`.

## Metadata And Static Publication

- Validate portable metadata before deployment.
- Keep runtime backend URLs, source paths, scope names, and table ids out of
  portable metadata manifests.
- Publish static metadata only after reviewing its audience and cache policy.
- Treat scoped runtime metadata as principal-specific. Do not place it in shared
  public caches.

## Provenance

- Enable provenance only when verifiers can resolve the configured schemas,
  contexts, and DID documents.
- Keep the signer private key in the secret manager.
- Exercise key rotation in staging before production.
- Monitor provenance issuance failures separately from plain JSON response
  failures.
- Keep Registry Notary evidence verification separate from Relay response
  provenance.

## Operational Readiness

- Configure health and readiness probes.
- Alert on startup validation failures, source ingest failures, audit sink
  failures, auth provider failures, and provenance signer failures.
- Run reload workflows in staging with production-shaped data sizes.
- Test degraded-source behavior and readiness expectations.
- Record the exact config, binary version, feature flags, and metadata manifest
  used for each deployment.

## Container Runtime Policy

- Use the production `Dockerfile` for release images. Its runtime base is pinned
  distroless `cc-debian12:nonroot`.
- Treat the distroless non-root identity as UID/GID `65532:65532`. Writable
  mounts for `server.cache_dir` or `audit.sink: file` must be writable by that
  identity.
- Keep `/etc/registry-relay/config.yaml` as the default config path,
  `/var/lib/registry-relay` as the working directory,
  `/var/lib/registry-relay/cache` as the default writable cache path,
  `/var/lib/registry-relay/data` as the source-data mount convention, and
  `/var/log/registry-relay` as the VM-style audit-file directory.
- Do not add shell, package-manager, `curl`, or `wget` dependencies to the
  production runtime stage. Container liveness uses
  `registry-relay healthcheck`, which probes `/healthz` directly.
- Verify TLS client behavior after base-image changes by exercising an HTTPS
  OIDC JWKS/discovery path or a PostgreSQL TLS configuration.
- `Dockerfile.demo` is debug/demo-only and intentionally divergent. It may keep
  Debian slim for demo inspection and optional standards-adapter feature
  combinations, but it must not be used as production runtime evidence.

## Pre-Production Gate

Run the closest practical checks for the enabled feature set:

```sh
just fmt-check
just lint
just test-default
just test
just build
just metadata-validate-profiles
```

When optional adapters are enabled, include focused all-feature integration
tests for those adapters before exposing them to consumers.

## Runtime Image Policy Work

Definition of done for the Relay runtime image policy work:

- `README.md` or this deployment guide names the production Relay runtime base
  policy as distroless `cc-debian12:nonroot`, with `Dockerfile.demo` classified
  separately.
- `Dockerfile` matches the documented production policy. If it uses distroless,
  the runtime stage contains no `apt-get`, `groupadd`, `useradd`, `/bin/sh`,
  `curl`, or `wget` dependency.
- `Dockerfile` runs the service as a non-root identity that is documented by
  numeric UID/GID or by the base image's published non-root user contract.
- The production image preserves these runtime paths: default config at
  `/etc/registry-relay/config.yaml`, working directory
  `/var/lib/registry-relay`, writable cache path
  `/var/lib/registry-relay/cache`, optional writable audit-log path
  `/var/log/registry-relay`, and source-data mount path
  `/var/lib/registry-relay/data`.
- The production image has a shell-free healthcheck. The healthcheck command
  exits `0` for a healthy local `/healthz` response and non-zero for connection
  failure, timeout, or non-2xx response.
- The healthcheck has focused tests for default URL, URL override, timeout
  override, success, non-2xx failure, and connection failure.
- CA certificate behavior is verified by an image startup or smoke check that
  exercises at least one TLS client path used by Relay, such as OIDC JWKS fetch
  or PostgreSQL TLS connection setup.
- `Dockerfile.demo` is explicitly classified as debug/demo-only or
  intentionally divergent in docs. If it remains Debian slim, the docs state the
  operational reason.
- `registry-lab` Relay image usage is either updated to match the product policy
  or tracked in a linked follow-up with the exact Compose/Dockerfile surfaces
  listed.
- Focused Dockerfile contract checks fail when the documented runtime policy and
  Dockerfile runtime stage drift.
- Verification evidence includes the exact commands and image tags used to build
  and run the production image, inspect the effective user, hit `/healthz`, hit
  `/ready`, and confirm writable cache and log paths.

Implementation plan:

- Wave 1: Policy and contract baseline.
  - Worker A updates the product runtime policy docs and classifies
    `Dockerfile.demo`.
  - Worker B adds or updates Dockerfile contract checks for runtime base,
    forbidden shell/package tooling, non-root identity, and healthcheck presence.
  - Done when docs name the policy, contract tests fail against the current
    Debian-slim production Dockerfile, and `just docker-build-contract` runs.
  - Code-review checkpoint: review the policy wording and failing contract test
    expectations before changing runtime behavior.
- Wave 2: Shell-free healthcheck.
  - Worker A adds a first-party `registry-relay healthcheck` command with URL
    and timeout configuration.
  - Worker B adds focused CLI tests for defaults, overrides, healthy response,
    non-2xx response, timeout, and connection failure.
  - Done when the healthcheck tests pass and the command requires no external
    binary such as `curl`, `wget`, or `/bin/sh`.
  - Code-review checkpoint: review CLI behavior and tests before wiring Docker.
- Wave 3: Production image conversion.
  - Worker A updates `Dockerfile` to the documented runtime base and moves any
    directory preparation or ownership work out of the shell-dependent runtime
    stage.
  - Worker B updates docs for UID/GID, writable paths, CA certificates, and
    image healthcheck behavior.
  - Done when the production image builds, starts as non-root, reports healthy,
    reports ready with the example config, writes to configured cache/log paths,
    and the contract tests pass.
  - Code-review checkpoint: inspect the Dockerfile diff, image user, path
    permissions, and smoke output before touching demo or lab surfaces.
- Wave 4: Demo and lab alignment.
  - Worker A reviews `Dockerfile.demo` against its documented classification and
    updates it only if the classification requires a runtime change.
  - Worker B updates `registry-lab` Relay healthchecks and image assumptions
    where they are independent of product repo changes.
  - Done when demo/lab either run without `curl` inside the Relay image or have
    a linked follow-up that names every intentionally divergent surface.
  - Code-review checkpoint: review cross-repo changes separately from product
    Dockerfile changes and confirm no unrelated lab behavior changed.
- Wave 5: Final verification and release evidence.
  - Run focused unit tests, Dockerfile contract checks, container build, container
    smoke, and the closest available Relay startup integration test.
  - Done when every definition-of-done item above has command output or a
    documented blocker, and no item is marked complete without passing evidence.
  - Code-review checkpoint: final self-review of diffs, commands, image tag or
    digest, skipped checks, and residual risk before closing the issue.
