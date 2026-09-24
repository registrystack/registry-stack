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
- Add `messagingctl check`, which loads a runtime configuration and its
  package offline exactly as `serve` would.
- Add package providers, sender profiles, and versioned templates: bounded,
  loader-free Jinja with `date` and `number` filters, a JSON Schema per
  version, exact locales, HTML escaping that cannot be turned off, and SMS
  segment counting against a sender profile's `maximumSegments`.
- Add the package ledger: `messagingctl apply` records the package digest,
  `serve` refuses a package the ledger does not name active, a change applies
  on restart, and `package.expectedDigest` pins the digest.
- Add `POST /v1/templates/{template_id}/versions/{version}/preview`, which
  renders without persisting, audits metadata only, and answers the bytes
  `messagingctl preview` prints.
- Add `messagingctl init`, `preview`, and `apply`, and `check --package`.
- Add the problems `template.not-found`, `template.data-invalid`,
  `template.locale-unavailable`, `template.render-refused`,
  `content.invalid`, `content.too-large`, and `content.too-many-segments`.
- Add `registry-messaging-client` with health and readiness.
- Publish the security invariant matrix, the recorded decisions, and the
  problem catalog under `https://id.registrystack.org/problems/registry-messaging/`.
