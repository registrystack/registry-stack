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
- Answer a submission whose body is well-formed JSON of the wrong shape, an
  unknown member, a recipient of the wrong channel, or a malformed or
  out-of-window instant with `422 request.unprocessable`, as the preview
  route and Scheduling do. A body that is not strict JSON, or a missing or
  malformed `Idempotency-Key`, stays `400 request.invalid`.
- Record that status reads are not journaled (MESSAGING-DEC-15).
- Read every `http` provider's package half from `providers/<id>/`:
  `provider.yaml` and exactly the scripts it names, digested with the
  package, compiled at load, and refused with its path when an entry is
  unknown, hidden, a symbolic link, or missing. The starter ships the mock
  provider as `sms-gateway`.
- Declare idempotent submission once, as `idempotentSubmit` on the manifest's
  provider entry. An `smtp` provider may not declare it, and
  `capabilities.idempotentSubmit` in `provider.yaml` is refused.
- Activate every provider the runtime configuration connects at startup:
  `providers.<id>` gives an `smtp` or `http` provider its connection and
  credentials, `tlsTrustProfiles` names PEM trust bundles an `http` provider
  may select, and every credential, bundle, and callback secret is a
  `secret:` reference resolved before either listener binds. A declared
  provider with no connection logs a warning and fails its messages with
  `provider-unconfigured`.
- Add provider delivery callbacks: `POST /v1/provider-callbacks/{provider_id}`
  and, for a `path-token` verifier, `POST
  /v1/provider-callbacks/{provider_id}/{token}`, authenticated by the
  provider's `callbackVerifier` (`hmac-sha1-url-form` with its external `url`,
  `hmac-sha256-body`, or `path-token`) rather than a bearer token. The
  package's receipt script reads a verified callback, and its receipt moves
  the message's delivery report only forward, joins a bounded history of
  distinct receipts, and is audited as `messaging.receipt.recorded` in the
  same transaction. A receipt naming no message answers 204 and is counted
  in `messaging_provider_callbacks_total`.
- Add the problems `callback.unverified` (403) and `callback.unreadable`
  (422).
- Serve the message view's `dispatch` member (`queued`, `sending`,
  `submitted`, `failed`, `unknown`, `cancelled`, `expired`) beside the
  delivery `report` (`none`, `sent`, `delivered`, `undelivered`, or
  `unavailable` when the provider records no receipts) and `reportedAt`.
  `status` is derived from the two: a submitted message is `delivered` or
  `failed` once its report is final. `messagingctl messages list --status`
  filters on the derived status, list and show print the dispatch state, and
  `retry`, `settle`, and `cancel` decide eligibility from it.
- Enforce each access profile's `requestsPerMinute` and `burst` per caller
  (`429 rate-limit.exceeded`) and its `dailyLimit` over the profile's
  accepted messages of the last 24 hours (`429 quota.exceeded`), both with
  `Retry-After`. Pace each `http` provider's sends to its
  `capabilities.ratePerSecond`. Migration 0004 indexes a profile's
  acceptances.
- Add the problems `rate-limit.exceeded` (429) and `quota.exceeded` (429).
- Enforce retention: a payload is erased `retention.payloadDays` and a
  record deleted `retention.recordDays` after the message reached a terminal
  state, and a submission receipt is dropped after
  `retention.submissionReceiptDays`. A queued, sending, or unknown message
  is never erased. The runtime sweeps at start and hourly and journals
  `messaging.retention.erased`; `messagingctl retention erase-expired
  --before` runs the same sweep on demand, previewing unless `--apply` is
  given. A deleted record frees its idempotency key. Migration 0005 drops
  the per-payload erase deadline, which counted from acceptance.
- Add `registry-messaging-client` with health, readiness, and
  `MessagingClient::message`, which reads one message's view under a bearer
  token.
- Publish the security invariant matrix, the recorded decisions, and the
  problem catalog under `https://id.registrystack.org/problems/registry-messaging/`.
