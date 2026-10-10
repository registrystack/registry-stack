# Messaging runtime configuration

Messaging reads one versioned operator document selected with
`messaging --runtime-config ABSOLUTE_FILE serve`. The selected file path and
every operated resource path are absolute. The document is at most one
mebibyte.

`messagingctl check --runtime-config FILE` checks the same document offline,
with no built package, database, network, or secret: against the authoring
project or package `--project` or `--package` names, or else against the
package `package.root` names, its pinned digest included. Each `${VAR}`
expression is checked by its syntax and position, and with `--environment`
filled from the environment and checked by its value. The check reports
every finding at once, each with its code, member, and line and column, and
exits 0 when the document is accepted, 1 when it is refused, 2 for a usage
error, and 3 when the file or the package it names cannot be read;
`--deny-warnings` refuses a document with a warning.

The closed envelope is:

```yaml
apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1
kind: MessagingRuntimeConfig
```

The former `registry.registrystack.org/messaging-runtime/v1alpha1` is
refused with this replacement named. A removed key is refused with the key
that replaced it.

Every mapping is closed: an unknown key is refused with its path, so a
misspelled setting never falls back to a default silently.
`generated/runtime/runtime.schema.json` states the same grammar for editors;
it is generated from the Rust types with

```bash
cargo run -p registry-messaging --features schema --example runtime-schema -- \
  --output products/messaging/generated/runtime
```

and never hand-edited. `examples/starter/runtime.example.yaml` is a complete,
commented document.

## Environment expressions

The shared `RuntimeConfigLoader` parses YAML before substituting `${VAR}`,
`${VAR:-default}`, or `${VAR:?message}` inside string values. Comments are
not expanded. Substitution cannot create keys, lists, or YAML documents, and
an expanded string remains a string. Missing required variables fail with a
field-addressed diagnostic that does not reveal their values.

Keys remain literal. Expressions are refused in or below members ending in
`Ref` or `Refs`, and in
secret-provider declarations. Credentials remain literal `secret:` references
to the explicitly declared provider. The loader never substitutes a secret
value into runtime configuration.

## Keys

`package.root` is an installed package produced by `messagingctl package`,
including `SHA256SUMS`, `messaging.yaml`, `providers/`, and `templates/`. `package.expectedDigest`, when
set, pins the package to a `sha256:` digest: the runtime, `messagingctl
check`, and `messagingctl apply` refuse a package whose digest differs, before
any database is reached. `messagingctl check` reports the digest to pin.

`listener` is required. `listener.bind` is one numeric socket address and
must be explicit, for example `127.0.0.1:8107`. `listener.tlsTermination` is required: use
`operator-controlled-upstream` behind an operator-managed TLS edge, or
`development-loopback` for direct local development, which is refused on any
non-loopback bind. `listener.networkExposure` defaults to `private-address`;
`container-private` permits an unspecified bind only for a listener kept on a
private container network. A public unicast address is refused under every
combination.

`metricsListener` is optional. When present, its `bind` is required and
`/metrics` is served on that socket only; when absent, no metrics are served. The address must
be a concrete loopback or private address on a non-zero port, and must not be
the public listener's socket or one a wildcard public listener already covers.

The metrics are Prometheus text, every label closed:

| Series | Type | Labels |
|---|---|---|
| `messaging_http_requests_total` | counter | `route` (template), `method`, `status` (class) |
| `messaging_authentication_refusals_total` | counter | `reason` |
| `messaging_provider_callbacks_total` | counter | `outcome` |
| `messaging_provider_attempts_total` | counter | `outcome`: `accepted`, `transient`, `permanent`, `maybe-sent` |
| `messaging_limit_refusals_total` | counter | `limit`: `rate`, `daily`, `pacing`, `callback` |
| `messaging_retention_runs_total` | counter | `outcome`: `erased`, `idle`, `failed` |
| `messaging_dispatch_jobs` | gauge | `state`: `pending`, `leased`, `unknown` |

Counters are per process and start at zero. `messaging_dispatch_jobs` is read
from the database on each scrape; the queue depth is `pending` plus `leased`,
and `unknown` is the number of messages waiting for an operator to settle.
When the database cannot answer, that scrape has no `messaging_dispatch_jobs`
samples, and the runtime logs a warning. A `messagingctl retention
erase-expired` run is a separate process and is recorded in the audit journal,
not in these counters.

`secretProviders` explicitly enables each accepted reference form. Declare
`file: {root: ABSOLUTE_DIRECTORY}` before using `secret:file/name`, and
`environment: {}` before using `secret:env/NAME`. At least one is required,
and the runtime does not fall back from one provider to another.

`database.runtimeUrlRef` supplies the service connection and
`database.migrationUrlRef` the operator-run migration connection, each a
PostgreSQL URL held in a secret. The runtime requires TLS on both;
`database.trustedRootCertificateRef` optionally selects the PEM bundle of a
private CA. `database.testOnlyPlaintext: true` is accepted only by a build
carrying the `postgres-test` feature.

`authentication.oidc` requires `issuer`, `audience`, and `allowedClients`.
`allowedClients` lists at least one distinct client, and every requester
client an access profile names must be listed; a profile no admitted client
could reach is refused at load. An omitted member, an empty list, and a
repeated client are refused when the file is read, and so is the
`unrestricted` keyword the sibling runtimes accept on development loopback. `scopeClaim` defaults to `registry_scopes`. `jwksSource`
defaults to issuer discovery and can instead select
`{type: static, documentRef: secret:...}` or `{type: uri, uri: HTTPS_URL}`.
The former `jwksUri` member is refused. `assertionIssuers` maps an allowed client to at least one and at most
16 assertion authorities it may exchange a subject token from; a deployment
that performs no token exchange leaves it empty, and an exchanged token is
then refused. Tokens must be `at+jwt` access tokens.

`audit.destination` selects `file` (the default) or `stdout`. File mode uses
`audit.path`, `audit.rotateBytes`, and `audit.retentionDays` for a
per-process JSON Lines stream. File acceptance includes fsync; stdout is
best-effort and requires the deployment's log pipeline for durable
retention. Each process uses its own destination: applied operator commands
write a sibling `messagingctl` file, or stderr when the runtime uses stdout,
keeping command stdout machine-readable.

`audit.hashKeyRef` supplies the key for minimized identifier references. It
does not sign or chain the journal. Rotating it changes the caller and
recipient pseudonyms later audit records carry, so records written before and
after the rotation no longer join on them; it frees no idempotency key, which
is scoped to the caller's issuer and subject. External tamper evidence and
complete off-host retention are deployment responsibilities.
`retentionDays` removes local sealed segments; ship required records before
that retention expires. A failed writer remains unhealthy until restart and
makes `/ready` fail.

`retention` bounds how long data is kept:

| Key | Default | Bounds |
|---|---|---|
| `payloadRetentionDays` | 7 | 1 to 30 |
| `recordRetentionDays` | 90 | `payloadRetentionDays` to 3650 |
| `submissionReceiptRetentionDays` | 7 | 1 to `recordRetentionDays` |

The start record carries the deployed values.
`submissionReceiptRetentionDays` is also the idempotency window: a
submission repeating the request of a key whose receipt is older is refused
with `idempotency.expired`, and one that changes the request under the key
is refused with `idempotency.key-reused` whatever the key's age. A
submission whose `expiresAt` is already past, or falls more than
`payloadRetentionDays` after acceptance, is refused with
`request.unprocessable`, so a message is never still waiting to send when
its payload's period could end.

Each period counts from the moment the message reached a terminal state
(delivered, failed, expired, or cancelled), not from acceptance, so a
message still waiting in a retry keeps its payload. `payloadRetentionDays`
after that moment the rendered parts and the recipient contact are erased
and the message record stays; `recordRetentionDays` after it the record is
deleted with its attempts and receipts. The idempotency key stays spent,
held only as a digest of the caller and the key with its times, and a repeat
of it, with the same request or another, is refused with
`idempotency.expired`. `submissionReceiptRetentionDays` after acceptance the
stored submission receipt is dropped together with the raw issuer, subject,
and key beside it, the request hash stays with the message record, and the
same caller's repeat of its request under the key is refused with
`idempotency.expired` and a changed request with `idempotency.key-reused`;
their SHA-256 digest keeps the key spent for that caller alone. A message
that is queued, sending, or in an unknown outcome is never erased, and an
operator retry committed while a sweep waits for the message keeps its
payload.

The runtime sweeps once at start and then hourly, under the runtime
credential. A sweep erases in batches of at most 1,000 of each kind, each
batch its own transaction, and journals `messaging.retention.erased` with the
counts for every batch that erased something. `messagingctl retention
erase-expired --before <RFC 3339 instant>` runs the same sweep on demand under
the migration credential: it previews by default, erases with `--apply`,
journals every applied batch through its process audit writer (the first one
even when it erased nothing), and refuses a cutoff later than the database's
clock. Batches committed before a failure stay erased and journaled. One
advisory lock, taken by each batch, serializes the runtime's sweep and the
command.

### Providers

`providers` gives each provider `messaging.yaml` declares its connection,
keyed by the provider id and tagged with the same `type`. A connection for a
provider the package does not declare, or with another type, is refused. A
declared provider with no connection is not activated: startup logs a
warning, and its messages fail with the attempt failure code
`provider-unconfigured` without a send. Every credential, trust bundle, and
callback secret is a `secret:` reference, resolved once at startup before
either listener binds; a provider that cannot be activated stops the runtime
with an error naming the provider and the member, never a value.

An `smtp` connection:

| Key | Required | Meaning |
|---|---|---|
| `host` | yes | The relay's DNS name or IP literal, at most 253 bytes; the name TLS verifies |
| `tls` | yes | `starttls`, `implicit`, or `development-loopback` (plaintext to a loopback relay, accepted only by a test build or behind a `development-loopback` listener) |
| `port` | no | Defaults to 587 for `starttls` and 465 for `implicit`; required for `development-loopback` |
| `authentication` | no | `usernameRef` and `passwordRef` |
| `attemptTimeoutMilliseconds` | no | One attempt's whole budget, 1000 to 60000, default 30000 |
| `trustedRootCertificateRef` | no | A PEM root trusted besides the public web roots |
| `allowedPrivateCidrs` | no | Exact private networks the relay may resolve into |

An `http` connection:

| Key | Required | Meaning |
|---|---|---|
| `baseUrl` | yes | Origin and path prefix ending in `/`; `https`, or `http` only to a loopback host |
| `attemptTimeoutMilliseconds` | yes | One send's whole budget, 1 to 10000 |
| `maximumResponseBytes` | yes | The largest response body read, at most 1 MiB |
| `maximumConcurrentRequests` | yes | Sends in flight, 1 to 64 and at most the package's `capabilities.maximumConcurrentRequests` |
| `redirects` | yes | `deny`, the only policy |
| `authentication` | yes | One of the types below |
| `callbackVerifier` | when the package declares `receipts: callback`, and only then | See Provider callbacks |
| `tlsTrustProfile` | no | A `tlsTrustProfiles` name whose bundle is trusted in addition to the system roots |
| `allowedPrivateCidrs` | no | Exact private networks an `https` provider may resolve into |
| `acknowledgeQueryStringContent` | when, and only when, the package sends with `get` | Acknowledges that content travels in the query string |

`authentication.type` is `none` (only for a loopback `http` `baseUrl`),
`basic` (`usernameRef`, `passwordRef`), `static-authorization` (`tokenRef`,
and `scheme`, which may only be `Bearer`), `static-api-key` (`headerName`,
`valueRef`), `static-api-key-query` (`parameterName`, `valueRef`),
`aws-sigv4` (`region`, `service`, `accessKeyIdRef`, `secretAccessKeyRef`, and
optional `sessionTokenRef`), or
`oauth2-client-credentials` (`tokenEndpoint` on the `baseUrl`'s scheme,
`clientIdRef`, `clientSecretRef`, `maximumCacheSeconds` from 10 to 86400, and
optionally `scope`, `audience`, `resource`, `assumedLifetimeSeconds`, and
`credentialPlacement: form-body`). A resolved credential value is at most
4096 bytes. AWS access key identifiers and secret access keys have a tighter
128-byte limit; AWS session tokens retain the 4096-byte credential limit.

For `aws-sigv4`, `baseUrl` must name the JSON API root, ending in `/` with
no other path. The provider must declare POST and exactly the `x-amz-target`
request header. Its prepare script uses an empty relative target, `bodyFormat:
json`, and the AWS action in `x-amz-target`. Rust supplies JSON 1.0 content type
and signs the actual destination host, action, timestamp, session token when
present, and exact serialized body. Signing credentials never enter scripts.
The current signing profile supports root JSON RPC requests, not AWS Query
APIs such as Amazon SNS Publish, S3, or arbitrary AWS REST paths.

The included `examples/providers/aws-sms` package uses AWS End User Messaging
SMS `SendTextMessage`, with `service: sms-voice` and an explicit region. Configure
the matching regional endpoint and restrict its AWS principal to the required
send action/resources. Access keys and optional temporary session credentials
are explicit `secret:` references resolved at activation. There is no ambient
AWS credential chain, metadata lookup, role assumption, or token refresh;
replace the secret values and restart before temporary credentials expire.
No real AWS account or carrier delivery is exercised by the local fixture tests.

This adapter records AWS acceptance as `submitted`. It does not ingest SNS or
EventBridge delivery events and declares no receipt capability. AWS does not
provide a submission idempotency token on this operation: retain `onUncertain:
hold`; a possibly accepted send cannot be automatically retried safely. Sender
registration, account sandbox/production access, spend limits, and destination
country requirements remain AWS account prerequisites. The provider example
contains the installation steps and links to AWS's maintained documentation.

`tlsTrustProfiles` names at most 64 PEM trust bundles, each
`{bundleRef: secret:...}`, that an `http` connection's `tlsTrustProfile`
selects.

### Provider callbacks

An `http` provider whose package declares `receipts: callback` reports
delivery to `POST /v1/provider-callbacks/{provider_id}` on the public
listener, or, for `path-token`, to
`POST /v1/provider-callbacks/{provider_id}/{token}`. These routes take no
bearer token: the connection's `callbackVerifier` authenticates each
callback, and is one of

| `type` | Keys | Verifies |
|---|---|---|
| `hmac-sha1-url-form` | `url`, `header`, `secretRef` | HMAC-SHA1 over `url` and the request's query, then the form parameters sorted by name, base64 in `header` |
| `hmac-sha256-body` | `header`, `encoding` (`hex` or `base64`), `secretRef` | HMAC-SHA256 over the raw body, encoded in `header` |
| `path-token` | `tokenRef` | The secret token as the last path segment; it must resolve to UTF-8 of at most 1024 bytes |

`url` is the external callback URL the provider was given and signs, exactly
as given, `http` or `https`, without a query or fragment, at most 2048 bytes;
it is what a reverse proxy in front of the runtime must not change for the
provider. `header` is an HTTP header name of at most 128 bytes. There is no
unauthenticated type.

The receipt script reads only what the verifier signed: under
`hmac-sha256-body` its `query` is empty, under `hmac-sha1-url-form` its
`json` is `()`, and under `path-token` it reads the whole request.

A verified callback answers 204 whether its receipt moved the report,
changed nothing, reported a state the runtime does not record, or named no
message. A callback that does not verify, names a provider without a
verifier, or arrives on the route its verifier does not use answers `403
callback.unverified`; one the receipt script cannot read answers `422
callback.unreadable`; a body over the request edge's limit answers `413
request.body-too-large`; and a store failure answers `503
service.unavailable`, so the provider retries. The metrics listener counts
callbacks in `messaging_provider_callbacks_total{outcome}`, with `outcome`
one of `unverified`, `unreadable`, `ignored`, `applied`, `unchanged`,
`unmatched`, `ambiguous`, or `unavailable`.

Callbacks are rate limited before they are verified, at a fixed 6000 a
minute with a burst of 600 for each provider with a verifier, and the same
again shared by every other callback path. The rate is not configurable. A
callback past it answers `429 rate-limit.exceeded` with `Retry-After`, which
a provider retries, and is counted in
`messaging_limit_refusals_total{limit="callback"}`, not in
`messaging_provider_callbacks_total`.

## The package

`package.root/messaging.yaml` carries:

```yaml
apiVersion: id.registrystack.org/formats/messaging/project/v1alpha1
kind: MessagingProject
project: {id: starter, version: "1"}
accessProfiles: [...]
```

The former kind `MessagingPackage` is refused as `config.wrong-kind`,
naming `MessagingProject`, and the former
`registry.registrystack.org/messaging-package/v1alpha1` as
`config.retired-api-version`, naming the envelope above. `project.id` is a
local identifier and `project.version` a text label; together they are the
identity a package built from the project carries.

Each access profile is `{id, principalClaim, requiredScopes, requesterClients,
actorKind, role, senderProfiles, templates, allowDirectContent,
requestsPerMinute, burst, maximumMessagesPerDay}`. `id` is a local
identifier: a lowercase letter, then at most 63 lowercase letters, digits,
underscores, or hyphens. `requiredScopes` is required: a list of at least one
scope a token must carry, or `unrestricted` to require none. `requesterClients`
lists at least one client. `actorKind` is `human`, `agent`, or
`service`, and omitted means any. `role` is `sender` or `operator`. A sender
lists at least one sender profile and one template; an operator lists none and
may not allow direct content. A requester client belongs to exactly one
profile. `requestsPerMinute` is 1 to 60000, `burst` 1 to 10000, and
`maximumMessagesPerDay`, when set, 1 to 10000000.

`requestsPerMinute` and `burst` bound how fast each caller of the profile
submits: every `POST /v1/messages` after the role check is charged to a
token bucket keyed by the caller's issuer and subject, and one past the
burst is refused `429 rate-limit.exceeded` with `Retry-After`. The bucket
lives in the runtime process, so each replica enforces it on its own and a
restart refills it. `maximumMessagesPerDay`, when set, bounds the messages the whole
profile has accepted in the last 24 hours. It is counted from the accepted
messages in the acceptance transaction, so it holds across replicas and
restarts; a submission past it is refused `429 quota.exceeded` with
`Retry-After` set to when the oldest counted message leaves the window. A
replayed submission is charged to the rate but not to the daily limit.

The rest of the manifest declares what callers send through:

```yaml
providers:
  - {id: mail-relay, type: smtp}
  - {id: sms-gateway, type: http, idempotentSubmit: true}
senderProfiles:
  - {id: transactional, channel: email, provider: mail-relay, sender: notices@example.org}
  - {id: reminders-sms, channel: sms, provider: sms-gateway, sender: Registry, maximumSegments: 2}
templates:
  - {id: appointment-reminder, version: "1"}
```

A provider declares its `type`, `smtp` or `http`, and `idempotentSubmit`
when it deduplicates submissions on the idempotency key the runtime sends.
`idempotentSubmit` is the one declaration of that capability: only an `http`
provider may set it, and only then does its prepare script see the key. Its
endpoint and credentials are runtime configuration. A sender profile names its `channel`
(`email` or `sms`), a declared provider that can carry it, and the `sender`
identity. An SMS sender profile sets `maximumSegments`, from 1 to 10; a
rendered SMS needing more segments is refused `422
content.too-many-segments`. Each entry of `templates` names a version the
package ships; a version is a label, so quote a numeric one.

A sender profile also sets how the worker sends its messages. Each message
keeps the policy its profile had when it was accepted:

| Key | Default | Bounds |
|---|---|---|
| `retry.maximumAttempts` | 5 | 1 to 20 |
| `retry.initialDelaySeconds` | 30 | at least 1 |
| `retry.maximumDelaySeconds` | 3600 | `initialDelaySeconds` to 86400 |
| `onUncertain` | `hold` | `hold` or `retry` |
| `acceptDuplicates` | `false` | |
| `defaultExpirySeconds` | 86400 | 60 to 2592000 |

A send that definitely failed is retried with exponential backoff doubling
from the initial delay up to the maximum, with jitter. A send that may have
reached the provider, including one cut off by its time budget, stops the
message as `unknown` under `hold` until an operator settles it with
`messagingctl messages settle`. `retry` sends it again under the same
provider idempotency key, and is accepted only when the profile's provider
declares `idempotentSubmit: true`, meaning it deduplicates on that key, or
the profile sets `acceptDuplicates: true`, the operator's choice that a
duplicate is better than a missed message. A message whose request names no
`expiresAt` expires `defaultExpirySeconds` after acceptance, or at
`retention.payloadRetentionDays` if that comes first, and is not sent after
it expires.

### HTTP providers

Every `http` provider has a directory `providers/<id>/` holding
`provider.yaml` and the scripts it names, at the paths it names relative to
that directory:

```yaml
apiVersion: id.registrystack.org/formats/messaging/provider/v1alpha1
kind: MessagingProvider
prepareScript: scripts/prepare.rhai
interpretScript: scripts/interpret.rhai   # optional; the status code decides without one
receiptScript: scripts/receipt.rhai       # exactly when receipts is callback
request:
  method: post                            # or get, which runtime settings must acknowledge
  headers: [idempotency-key, x-request-id]
responseHeaders: [x-request-id]
capabilities:
  receipts: callback                      # none, callback, or reconcile
  maximumConcurrentRequests: 8            # 1 to 64
  ratePerSecond: 20                       # optional, 1 to 1000
```

`ratePerSecond` paces the worker: an attempt waits for the provider's next
send slot after it is leased and before anything reaches the provider, so at
most one send starts every `1 / ratePerSecond` seconds per runtime process.
A paced attempt first waits for one of the connection's
`maximumConcurrentRequests` sends in flight and holds it through the send,
so the rate spaces requests as they leave, including ones queued behind a
slow send. Both waits share their own ten-second allowance on top of the
send's time budget, and stop at the message's `expiresAt`; an attempt whose
slot does not open in time is retried under its dispatch policy without a
send, and one past its expiry is not sent again: it expires, or stays
`unknown` when an earlier attempt may have reached the provider and its
policy retries.

`provider.yaml` is closed and at most 1 MiB; each script is at most 64 KiB
and must compile with exactly its entry point when the package loads. A
directory for an `smtp` provider or an undeclared id, a file the provider does
not name, a hidden entry, or a symbolic link under `providers/` is refused
with its path, and a declared `http` provider without its directory or a
named script is refused as missing. `providers/` is digested with the rest of
the package. `products/messaging/examples/providers/` holds two example
provider directories, and the starter ships the mock one as `sms-gateway`.

### Templates

Each template version lives under `templates/<id>/<version>/`:

- `template.yaml`, closed: the envelope `apiVersion:
  id.registrystack.org/formats/messaging/template/v1alpha1` and `kind:
  MessagingTemplate`, then `channel`, `locales` (at most 32 simple language
  tags such as `en` or `pt-BR`), and `parts`. An email version renders
  `subject`, `text`, and optionally `html`; an SMS version renders exactly
  `text`.
- `schema.json`, a JSON Schema (draft 2020-12) the data must satisfy before
  anything renders. It may not reference anything outside itself.
- `sample.json`, optional: data every locale must render at load, so
  `messagingctl check` shows each locale's SMS segment count.
- `<locale>/<part>.j2` for every declared locale and part, at most 64 KiB each.

Templates are Jinja without a loader: no `include`, `import`, `extends`, or
macros, no built-in filters or globals, and no file, network, or clock access.
A missing or null value refuses the render rather than printing empty. Two
filters format for the requested locale: `date` for an ISO calendar date and
`number(decimals)` for a number. Each part has a fuel budget and a byte
ceiling (512 bytes for a subject, 64 KiB for text, 256 KiB for HTML). HTML
parts escape every value and cannot opt out; text and SMS parts strip control
characters, and a subject strips newlines. A locale the version does not
declare is refused `422 template.locale-unavailable`, never answered in
another language.

Symbolic links and unknown product files are refused in installed packages.
`messagingctl package PROJECT --output DIRECTORY` selects `messaging.yaml`,
`templates/`, and `providers/` from the editable project and excludes runtime
configuration, secrets, and development state. The output is write-once; an
optional `--revision TEXT` records provenance. `--dry-run` reports the plan
without writing. Use `check --project PROJECT` and `preview --project PROJECT`
while authoring, and `--package DIRECTORY` for installed output.

### Package activation

The package identity is the shared SHA-256 digest of `SHA256SUMS`. The runtime
verifies the envelope and optional pin, then rechecks each bounded file buffer
against its verified digest before parsing or compiling it. Rendering and
scripts use those owned buffers; later filesystem changes cannot replace
the bytes accepted at startup. `messagingctl plan --runtime-config FILE`
reports the package, database identity, pending schema versions, and runtime
role boundary without writing. `messagingctl apply --runtime-config FILE`
applies that plan in one locked transaction. `messagingctl status
--runtime-config FILE` reads activation history with the runtime credential.
`messaging serve` refuses unless the package and `identity.databaseId` equal
the active row and the runtime role still has the recorded authority. A
package change takes effect on restart after `apply`, and an edited file never
changes what a running deployment sends.
