# Registry Messaging changelog

## Unreleased

- Add the Registry Messaging skeleton: the `messaging` runtime with `migrate`
  and `serve` over PostgreSQL, the runtime configuration with its generated
  schema, package access profiles, OIDC bearer authentication, the keyed
  audit journal, `/health` and `/ready`, the authenticated message status
  route, and `/metrics` on a separate private listener. The contract is
  pre-1.0 and may change in a later minor release.
- Refuse unknown configuration keys with their path, and refuse an
  environment expression in any member that names a secret.
- Refuse a pinned `package.expectedDigest` until the package ledger can
  verify it.
- Add `messagingctl check`, which loads a runtime configuration and its
  package offline exactly as `serve` would.
- Add `registry-messaging-client` with health and readiness.
- Publish the security invariant matrix, the recorded decisions, and the
  problem catalog under `https://id.registrystack.org/problems/registry-messaging/`.
