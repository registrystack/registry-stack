# Messaging runtime configuration

Messaging reads one versioned operator document selected with
`messaging --runtime-config ABSOLUTE_FILE serve` or `migrate`, and
`messagingctl check --runtime-config ABSOLUTE_FILE` checks the same document
offline. The selected file path and every operated resource path are
absolute. The document is at most one mebibyte.

The closed envelope is:

```yaml
apiVersion: registry.registrystack.org/messaging-runtime/v1alpha1
kind: MessagingRuntimeConfig
```

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

A string value may carry `${VAR}`, `${VAR:-default}`, or `${VAR:?message}`.
Substitution happens after the YAML is parsed, one string at a time, so a
substituted value is always text and can never add a key, a list entry, or a
document. An expression is refused in every member whose name ends in `Ref`:
those members name a secret, and a secret is named by a `secret:` reference
the resolver reads, never by text an environment variable spliced in. A
refusal names the member and never repeats the value or the default text.

## Keys

`package.root` is the directory holding the authored package:
`messaging.yaml` and its `templates/` tree. `package.expectedDigest`, when
set, pins the package to a `sha256:` digest: the runtime, `messagingctl
check`, and `messagingctl apply` refuse a package whose digest differs, before
any database is reached. `messagingctl check` reports the digest to pin.

`listener` is required. `listener.bind` is one numeric socket address and
defaults to `127.0.0.1:8107`. `listener.tlsTermination` is required: use
`operator-controlled-upstream` behind an operator-managed TLS edge, or
`development-loopback` for direct local development, which is refused on any
non-loopback bind. `listener.networkExposure` defaults to `private-address`;
`container-private` permits an unspecified bind only for a listener kept on a
private container network. A public unicast address is refused under every
combination.

`metricsListener.bind` is optional. When present, `/metrics` is served on that
socket and nowhere else; when absent, no metrics are served. The address must
be a concrete loopback or private address on a non-zero port, and must not be
the public listener's socket or one a wildcard public listener already covers.

The metrics are Prometheus text, every label closed:

| Series | Type | Labels |
|---|---|---|
| `messaging_http_requests_total` | counter | `route` (template), `method`, `status` (class) |
| `messaging_authentication_refusals_total` | counter | `reason` |
| `messaging_provider_callbacks_total` | counter | `outcome` |
| `messaging_provider_attempts_total` | counter | `outcome`: `accepted`, `transient`, `permanent`, `maybe-sent` |
| `messaging_limit_refusals_total` | counter | `limit`: `rate`, `daily`, `pacing` |
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
`allowedClients` is never empty, and every requester client an access
profile names must be listed; a profile no admitted client could reach is
refused at load. `scopeClaim` defaults to `registry_scopes`. `jwksSource`
defaults to issuer discovery and can instead select
`{kind: static, documentRef: secret:...}`; `jwksUri` overrides the discovery
document's JWKS address. `assertionIssuers` maps an allowed client to at most
16 assertion authorities it may exchange a subject token from; a deployment
that performs no token exchange leaves it empty, and an exchanged token is
then refused. Tokens must be `at+jwt` access tokens.

`audit.path` is the journal file and `audit.hashKeyRef` the secret keying its
hash chain. The journal records the runtime start with the runtime version and
the retention periods in force.

`retention` bounds how long data is kept:

| Key | Default | Bounds |
|---|---|---|
| `payloadDays` | 7 | 1 to 30 |
| `recordDays` | 90 | `payloadDays` to 3650 |
| `submissionReceiptDays` | 7 | 1 to `recordDays` |

The start record carries the deployed values. `submissionReceiptDays` is
also the idempotency window: a submission repeating a key whose receipt is
older is refused with `idempotency.expired`. A submission whose `expiresAt`
is already past, or falls more than `payloadDays` after acceptance, is
refused with `request.unprocessable`, so a message is never still waiting to
send when its payload's period could end.

Each period counts from the moment the message reached a terminal state
(delivered, failed, expired, or cancelled), not from acceptance, so a message
still waiting in a retry keeps its payload. `payloadDays` after that moment
the rendered parts and the recipient contact are erased and the message
record stays; `recordDays` after it the record is deleted with its attempts,
receipts, and idempotency key, and the key can be used again.
`submissionReceiptDays` after acceptance the stored submission receipt is
dropped and a repeat of its key is refused with `idempotency.expired`. A
message that is queued, sending, or in an unknown outcome is never erased,
and an operator retry committed while a sweep waits for the message keeps
its payload.

The runtime sweeps once at start and then hourly, under the runtime
credential, and journals `messaging.retention.erased` with the counts
whenever it erased something. `messagingctl retention erase-expired --before
<RFC 3339 instant>` runs the same sweep on demand under the migration
credential: it previews by default, erases with `--apply`, journals every
applied run through the outbox, and refuses a cutoff later than the
database's clock. One advisory lock serializes the runtime's sweep and the
command.

### Providers

`providers` gives each provider `messaging.yaml` declares its connection,
keyed by the provider id and tagged with the same `kind`. A connection for a
provider the package does not declare, or with another kind, is refused. A
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
| `tls` | yes | `starttls`, `implicit`, or `development-loopback` (plaintext to a loopback relay, accepted only by a test build) |
| `port` | no | Defaults to 587 for `starttls` and 465 for `implicit`; required for `development-loopback` |
| `authentication` | no | `usernameRef` and `passwordRef` |
| `attemptTimeoutSeconds` | no | One attempt's whole budget, 1 to 60, default 30 |
| `trustedRootCertificateRef` | no | A PEM root trusted besides the public web roots |
| `allowedPrivateCidrs` | no | Exact private networks the relay may resolve into |

An `http` connection:

| Key | Required | Meaning |
|---|---|---|
| `baseUrl` | yes | Origin and path prefix ending in `/`; `https`, or `http` only to a loopback host |
| `timeoutMilliseconds` | yes | One send's whole budget, at most 10000 |
| `maximumResponseBytes` | yes | The largest response body read, at most 1 MiB |
| `concurrencyLimit` | yes | Sends in flight, at most the package's `capabilities.concurrencyLimit` |
| `redirects` | yes | `deny`, the only policy |
| `authentication` | yes | One of the kinds below |
| `callbackVerifier` | when the package declares `receipts: callback`, and only then | See Provider callbacks |
| `tlsTrustProfile` | no | A `tlsTrustProfiles` name whose bundle replaces the public web roots |
| `allowedPrivateCidrs` | no | Exact private networks an `https` provider may resolve into |
| `acknowledgeQueryStringContent` | when, and only when, the package sends with `get` | Acknowledges that content travels in the query string |

`authentication.kind` is `none` (only for a loopback `http` `baseUrl`),
`basic` (`usernameRef`, `passwordRef`), `static-authorization` (`tokenRef`,
and `scheme`, which may only be `Bearer`), `static-api-key` (`headerName`,
`valueRef`), `static-api-key-query` (`parameterName`, `valueRef`), or
`oauth2-client-credentials` (`tokenEndpoint` on the `baseUrl`'s scheme,
`clientIdRef`, `clientSecretRef`, `maximumCacheSeconds` from 10 to 86400, and
optionally `scope`, `audience`, `resource`, `assumedLifetimeSeconds`, and
`credentialPlacement: form-body`). A resolved credential value is at most
4096 bytes.

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

| `kind` | Keys | Verifies |
|---|---|---|
| `hmac-sha1-url-form` | `url`, `header`, `secretRef` | HMAC-SHA1 over `url` and the request's query, then the form parameters sorted by name, base64 in `header` |
| `hmac-sha256-body` | `header`, `encoding` (`hex` or `base64`), `secretRef` | HMAC-SHA256 over the raw body, encoded in `header` |
| `path-token` | `tokenRef` | The secret token as the last path segment |

`url` is the external callback URL the provider was given and signs, exactly
as given, `http` or `https`, without a query or fragment, at most 2048 bytes;
it is what a reverse proxy in front of the runtime must not change for the
provider. `header` is an HTTP header name of at most 128 bytes. There is no
unauthenticated kind.

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

## The package

`package.root/messaging.yaml` carries:

```yaml
apiVersion: registry.registrystack.org/messaging-package/v1alpha1
kind: MessagingPackage
accessProfiles: [...]
```

Each access profile is `{id, principalClaim, requiredScopes, requesterClients,
actorKind, role, senderProfiles, templates, allowDirectContent,
requestsPerMinute, burst, dailyLimit}`. `actorKind` is `human`, `agent`, or
`service`, and omitted means any. `role` is `sender` or `operator`. A sender
lists at least one sender profile and one template; an operator lists none and
may not allow direct content. A requester client belongs to exactly one
profile. Rates, bursts, and daily limits must be positive.

`requestsPerMinute` and `burst` bound how fast each caller of the profile
submits: every `POST /v1/messages` after the role check is charged to a
token bucket keyed by the caller's issuer and subject, and one past the
burst is refused `429 rate-limit.exceeded` with `Retry-After`. The bucket
lives in the runtime process, so each replica enforces it on its own and a
restart refills it. `dailyLimit`, when set, bounds the messages the whole
profile has accepted in the last 24 hours. It is counted from the accepted
messages in the acceptance transaction, so it holds across replicas and
restarts; a submission past it is refused `429 quota.exceeded` with
`Retry-After` set to when the oldest counted message leaves the window. A
replayed submission is charged to the rate but not to the daily limit.

The rest of the manifest declares what callers send through:

```yaml
providers:
  - {id: mail-relay, kind: smtp}
  - {id: sms-gateway, kind: http, idempotentSubmit: true}
senderProfiles:
  - {id: transactional, channel: email, provider: mail-relay, sender: notices@example.org}
  - {id: reminders-sms, channel: sms, provider: sms-gateway, sender: Registry, maximumSegments: 2}
templates:
  - {id: appointment-reminder, version: "1"}
```

A provider declares its `kind`, `smtp` or `http`, and `idempotentSubmit`
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
`retention.payloadDays` if that comes first, and is not sent after it
expires.

### HTTP providers

Every `http` provider has a directory `providers/<id>/` holding
`provider.yaml` and the scripts it names, at the paths it names relative to
that directory:

```yaml
prepareScript: scripts/prepare.rhai
interpretScript: scripts/interpret.rhai   # optional; the status code decides without one
receiptScript: scripts/receipt.rhai       # exactly when receipts is callback
request:
  method: post                            # or get, which runtime settings must acknowledge
  headers: [idempotency-key, x-request-id]
responseHeaders: [x-request-id]
capabilities:
  receipts: callback                      # none, callback, or reconcile
  concurrencyLimit: 8                     # 1 to 64
  ratePerSecond: 20                       # optional, 1 to 1000
```

`ratePerSecond` paces the worker: an attempt waits for the provider's next
send slot after it is leased and before anything reaches the provider, so at
most one send starts every `1 / ratePerSecond` seconds per runtime process.
The wait has its own ten-second allowance on top of the send's time budget;
an attempt whose slot does not open in it is retried under its dispatch
policy without a send.

`provider.yaml` is closed and at most 64 KiB; each script is at most 64 KiB
and must compile with exactly its entry point when the package loads. A
directory for an `smtp` provider or an undeclared id, a file the provider does
not name, a hidden entry, or a symbolic link under `providers/` is refused
with its path, and a declared `http` provider without its directory or a
named script is refused as missing. `providers/` is digested with the rest of
the package. `products/messaging/examples/providers/` holds two example
provider directories, and the starter ships the mock one as `sms-gateway`.

### Templates

Each template version lives under `templates/<id>/<version>/`:

- `template.yaml`, closed: `channel`, `locales` (at most 32 simple language
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

Symbolic links are refused anywhere in the package, and files at the package
root other than `messaging.yaml`, `templates/`, and `providers/` are ignored
and not part of the digest.

### The package ledger

The package digest is the SHA-256 of a canonical JSON listing of every
package file with its own SHA-256 and size. `messagingctl apply
--runtime-config FILE` reports whether the package on disk differs from the
one the database's package ledger names active; with `--apply` it records the
package. `messaging serve` refuses to start unless the package on disk has the
digest the ledger names active, so a package change takes effect when the
runtime restarts after `apply --apply`, and an edited file never changes what
a running deployment sends.
