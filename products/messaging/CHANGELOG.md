# Registry Messaging changelog

## Unreleased

- BREAKING: a spent idempotency key is scoped to the caller's issuer and
  subject, as in Scheduling and Casework, instead of the caller's keyed audit
  pseudonym, so rotating `audit.hashKeyRef` no longer frees spent keys: an
  exact retry across a rotation replays its receipt or is refused with
  `410 idempotency.expired`, and never sends again. A deleted record's
  idempotency tombstone now holds the caller's issuer and subject. Audit
  records keep the pseudonym. Upgrade by running `messagingctl apply` with
  this release before starting the runtime; it applies schema version 3,
  which moves every key whose message is still held to that message's
  submitter. A key whose message retention already deleted, a key naming no
  held message, and the older of two records one caller held under two
  pseudonyms after an earlier rotation are preserved unchanged in
  `legacy_messaging_idempotency`, which nothing reads, and those keys can be
  used again. Drop that table once nothing needs it; a row that named a
  message keeps its request hash and receipt until then (#1912).

## v0.38.0 - 2026-10-01

- An http provider whose `baseUrl` names `localhost` or a `*.localhost` host
  in a production profile is refused at activation, where it was previously
  activated and then refused on every send. Use a loopback IP literal over
  `http` for a local development provider.
- BREAKING: package activation (`messagingctl plan`, `apply`, and `status`) and
  `messaging serve` startup refuse a PostgreSQL server older than 17 with an
  upgrade instruction, before any migration or activation write. Source
  deployments on PostgreSQL 16 or older must upgrade the database server
  before updating Messaging.
- BREAKING: source deployments must set `identity.databaseId` and activate
  their package with `messagingctl apply` before starting the runtime. Use
  `messagingctl plan` to inspect changes and `messagingctl status` to inspect
  activation history. These commands replace `messaging migrate` and the old
  preview-or-write behavior of `messagingctl apply`; activation `apply` no
  longer takes `--apply`.
  Existing package history is retained as an inert legacy ledger. Activation
  atomically applies migrations, records the package and database identity,
  and establishes runtime grants. Startup and readiness refuse a missing or
  mismatched activation or insufficient runtime privileges (#1731).
- Add Linux amd64 runtime and operator binaries, a Docker image, and Messaging
  exports in the unified Node.js and Python clients from v0.38.0.
- BREAKING: every `messagingctl --format json` report opens with `ok`,
  `command`, and `status`, in that order, as `caseworkctl` and
  `schedulingctl` reports do. `ok` is true exactly when the exit code is 0,
  and `command` names the subcommand path, such as `messages retry` or
  `retention erase-expired`, on every report, failures included, and is
  `usage` for a command line that did not parse. `status` keeps a report's
  own status where it has one, `ready` or `stopped` for `dev`, and is
  otherwise `complete` for a success and `domain-refusal`, `usage-error`, or
  `operational-failure` by exit class for a failure. A successful `preview`
  still prints the exact bytes the runtime's preview route answers.
- BREAKING: each `messagingctl` diagnostic carries `severity`, `code`,
  `artifact`, `path`, `message`, and `suggestedAction`, and a human failure
  on standard error reads `error[CODE] PATH: MESSAGE` followed by
  `  next: ACTION`. A usage diagnostic's `path` is `arguments` instead of `/`.
- BREAKING: `messagingctl messages retry`, `settle`, and `cancel` report the
  message's own status as `messageStatus`; `status` is the report's.
- A command line `messagingctl` refuses is described by the kind of error and
  the argument name, such as `unexpected argument --reason`, or by the
  argument's own validation reason, such as `invalid value for --before:
  expected an RFC 3339 instant such as 2026-09-01T00:00:00Z`, and names
  `messagingctl --help` as the next step. The refused value is never repeated
  on standard output or standard error.

- Write the runtime's operational log to stderr, so a `stdout` audit
  destination carries audit entries alone.
- Never send a message after its `expiresAt`: a paced attempt's wait for its
  send slot stops at the expiry, and an attempt past it reaches no provider;
  the message expires unsent, or stops `unknown` when an earlier attempt
  may have been sent.
- Pace a provider's sends as they leave: a paced attempt holds one of the
  connection's `concurrencyLimit` sends in flight before it takes its turn,
  so attempts queued behind a slow send no longer leave back to back.
- Shut the runtime down gracefully on SIGTERM or SIGINT: the worker stops
  claiming and finishes its in-flight sends, a retention sweep finishes the
  batch it is erasing and leaves the rest for the next start, the listeners finish their requests, and the process exits 0.
- Erase retention in batches of at most 1,000 of each kind, each batch its
  own transaction and journal record.
- Report whether an unfinished `messagingctl` write changed anything:
  `message.changed`, `message.outcome-unknown`, `package.outcome-unknown`,
  `retention.outcome-unknown`, `audit.unavailable`, and `audit.unconfirmed`.
  `apply` reports the active digest it read under the ledger lock.
- Let each transport classify its own timeout: an attempt that ran out of
  time before its request left is transient; one cut off after it, or one
  that overruns its budget by more than a second, is maybe-sent.
- Classify an HTTP provider's `408`, `500`, `502`, `504`, and other `5xx`
  answers as maybe-sent by default; `429` and `503` stay transient.
- Never let a possibly-sent message end failed, expired, or cancelled on
  the dispatcher's own decision: under `onUncertain: retry` it stops
  `unknown` when its attempts or time run out, even when a later attempt
  failed transiently or was refused permanently, and so does a quarantined
  one. A queued message cancels only while every attempt ended definitely
  not sent, and otherwise answers `409 message.dispatch-started`;
  `messagingctl messages cancel` previews and applies the same rule and
  refuses such a message with `message.dispatch-started`.
- Answer a same-key submission racing for the last daily place with its
  receipt, cap `Retry-After` at 86400 seconds, and refuse a window
  narrower than the microsecond precision stored.
- Journal an oversized or unreadable submission or preview body as a
  refusal with its problem, name only a shipped template in a preview's
  request record, and authenticate before decoding a route's path.
- Publish `WWW-Authenticate` and `Retry-After` in the OpenAPI document, the
  byte bounds of `correlationId` and email recipients, and
  `content.too-large` for previews.
- Refuse a secret access key outside visible ASCII, normalize namespaced
  AWS error types, and classify AWS authentication errors as permanent.
  Refuse a provider package that names a response header scripts cannot
  read. Show a receipt script only the callback parts its verifier signs.
- Drop NUL and other C0 controls from rendered HTML parts.

- Add an AWS End User Messaging SMS provider package and bounded AWS SigV4
  JSON request signing with explicit secret references and optional session
  credentials. Preserve uncertain-send holds; AWS acceptance is submitted,
  with delivery-event ingestion outside this adapter.

- Adopt the shared runtime configuration blocks and explicit listener binds.
  Replace `jwksUri` with the closed `jwksSource` configuration.
- Separate editable projects from installed packages. Add `messagingctl
  package PROJECT --output DIRECTORY`, `--dry-run`, optional `--revision`,
  and project-mode checks/previews. The runtime verifies the shared checksum
  envelope and consumes only bounded buffers rechecked against that envelope.
  Keep the product activation ledger and explicit apply/restart behavior.

- Add the Registry Messaging skeleton: the `messaging` runtime with `migrate`
  and `serve` over PostgreSQL, the runtime configuration with its generated
  schema, package access profiles, OIDC bearer authentication, the per-process
  audit journal, `/health` and `/ready`, the authenticated message status
  route, and `/metrics` on a separate private listener. The contract is
  pre-1.0 and may change in a later minor release. The database schema is
  one migration, version 1.
- Refuse unknown configuration keys with their path. Expand `${VAR}`
  expressions inside parsed YAML string values with the shared Registry Stack
  loader; keys stay literal and expressions in secret references or provider
  declarations are refused.
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
  records the message and its dispatch job in one transaction, with an
  accepted audit request before the effect and a response after proven commit. The same key and request answer the stored receipt again
  after the caller is authorized and the message rendered again.
- Serve `GET /v1/messages/{message_id}` from the message store and add
  `POST /v1/messages/{message_id}/cancel`. Both answer only the submitting
  principal, the same issuer and subject, and operators, mask the recipient, and answer a message the
  caller may not see exactly like one that does not exist.
- Add the dispatch worker on the platform PostgreSQL dispatch substrate, with
  lease-fenced outcome writes, retries bounded by the sender profile's
  dispatch policy, a per-attempt time budget, and quarantine of a message
  whose send may have happened unless its provider deduplicates or its sender
  profile accepts duplicates. A provider without a transport fails its
  messages with `provider-unconfigured`.
- Use the shared direct audit writer with separate runtime/operator streams,
  sticky writer health in readiness, and explicit unfinished/unknown outcomes.
  Remove the unreleased audit outbox; preserve domain transactions and stable
  keyed pseudonyms. A failed post-commit response append reports unavailable
  while the committed state remains authoritative.
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
  distinct receipts, and is audited as `messaging.receipt.recorded` after
  the commit is established. A receipt naming no message answers 204 and is counted
  in `messaging_provider_callbacks_total`. Callbacks are charged to a fixed
  per-provider rate of 6000 a minute (burst 600) before they are verified,
  with one shared bucket for every other callback path; past it they answer
  `429 rate-limit.exceeded` with `Retry-After` and are counted in
  `messaging_limit_refusals_total{limit="callback"}`.
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
  `capabilities.ratePerSecond`.
- Add the problems `rate-limit.exceeded` (429) and `quota.exceeded` (429).
- Enforce retention: a payload is erased `retention.payloadDays` and a
  record deleted `retention.recordDays` after the message reached a terminal
  state, and a submission receipt is dropped after
  `retention.submissionReceiptDays`. A queued, sending, or unknown message
  is never erased. The runtime sweeps at start and hourly and journals
  `messaging.retention.erased`; `messagingctl retention erase-expired
  --before` runs the same sweep on demand, previewing unless `--apply` is
  given. A deleted record keeps its idempotency key spent: the key
  row stays under the caller's keyed pseudonym, and a repeat is
  `410 idempotency.expired`.
- Answer `/ready` with `503` once the package ledger names a package other
  than the one the runtime serves, until the runtime is restarted onto it.
- Add `registry-messaging-client` with health, readiness, and
  `MessagingClient::message`, which reads one message's view under a bearer
  token.
- Publish the security invariant matrix, the recorded decisions, and the
  problem catalog under `https://id.registrystack.org/problems/registry-messaging/`.
- Add the metrics `messaging_provider_attempts_total`,
  `messaging_limit_refusals_total`, `messaging_retention_runs_total`, and the
  `messaging_dispatch_jobs` gauge, sampled from the database on each scrape,
  each under closed labels only.
- Enforce MESSAGING-SEC-08: one journey through every audited operation
  checks that audit envelopes, operational logs, and metrics carry no raw
  recipient, body, template datum, principal, or credential.
- Accept an SMTP provider's `tls: development-loopback` in a release build
  when the runtime's own listener is `development-loopback`; behind an
  `operator-controlled-upstream` listener it is still refused.
- Add `messagingctl dev`, a foreground local session that runs a package
  against a pinned PostgreSQL and a pinned Mailpit in Docker and a mock HTTP
  gateway that reports delivery through signed callbacks, and removes its
  containers when it stops, and `messagingctl dev token CLIENT`, which writes
  a one-hour bearer header file for a client an access profile names.
- Add `products/messaging/scripts/measure-throughput.sh`, which measures SMS
  dispatch on one replica against a 200 ms mock provider; the README records
  the measured rates.
- Extend `registry-messaging-client` with `submit` under a caller-chosen
  idempotency key, `cancel`, and `preview`, each refusing a malformed key,
  message identifier, template identifier, or version before any request,
  and never retrying. Expose the client through the Rust facade crate
  `registry-stack-client` and through Node.js and Python bindings, which the
  published `@registrystack/client` package and `registry-stack-client` wheel
  leave out until Messaging joins a release, and hold those bindings to the
  dependency-direction and vendor-neutrality gates. A `rate-limit.exceeded` or
  `quota.exceeded` refusal carries the bounded `Retry-After` wait, at most one
  day, in all three languages.
