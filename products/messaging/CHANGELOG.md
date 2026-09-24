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
- Add `POST /v1/messages`, which accepts one message under a caller-scoped
  `Idempotency-Key`, renders it from the active package at acceptance, and
  records the message, its dispatch job, and its acceptance audit in one
  transaction. The same key and request answer the stored receipt again
  after the caller is authorized and the message rendered again.
- Serve `GET /v1/messages/{message_id}` from the message store and add
  `POST /v1/messages/{message_id}/cancel`. Both answer only the submitting
  access profile and operators, mask the recipient, and answer a message the
  caller may not see exactly like one that does not exist.
- Add the dispatch worker on the platform PostgreSQL dispatch substrate, with
  lease-fenced outcome writes, retries bounded by the sender profile's
  dispatch policy, a per-attempt time budget, and quarantine of a message
  whose send may have happened unless its provider deduplicates or its sender
  profile accepts duplicates. A provider without a transport fails its
  messages with `provider-unconfigured`.
- Write every message audit record into an outbox inside the transaction
  that makes the change, published to the journal by the runtime.
- Add `messagingctl messages list`, `show`, `retry`, `settle`, and `cancel`.
  Actions preview unless `--apply` is given.
- Add the problems `message.dispatch-started` and `message.terminal`, and the
  provider `idempotentSubmit` flag.
- Add `registry-messaging-client` with health and readiness.
- Publish the security invariant matrix, the recorded decisions, and the
  problem catalog under `https://id.registrystack.org/problems/registry-messaging/`.
