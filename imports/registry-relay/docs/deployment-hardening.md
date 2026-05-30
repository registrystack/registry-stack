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
