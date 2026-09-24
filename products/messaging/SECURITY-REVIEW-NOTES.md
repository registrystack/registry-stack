# Registry Messaging security review notes

Review notes for the security-sensitive Messaging changes, held in tracked
material because commit messages do not survive a squash. Each section names
the threat it answers, the defaults the product ships, and the tests that pin
it. The security-invariant matrix in `contracts/` is the row-per-invariant
baseline; this file is the narrative behind it. A section marked pending
records the obligation of a later slice, not behaviour that exists.

## Authentication

Threat: a caller without a valid credential for this deployment reaches a
`/v1` route, or a credential minted for another service, another client, or
another purpose is accepted here.

There is no unauthenticated mode. Every `/v1` route except the provider
callback routes resolves its caller before any other decision; a callback
carries no bearer token and is authenticated by its provider's configured
verifier instead (see Callbacks). A credential is accepted only when it is a compact
RFC 9068 access token (`at+jwt`) from the configured issuer, for the
configured audience, from a client `authentication.oidc.allowedClients`
admits, signed by a key the issuer published or the static JWKS document
names. A token that arrived through a token exchange is refused unless the
deployment declared the assertion authority for that client in
`assertionIssuers`; with none declared, every exchanged token is refused.

Every refusal answers `401 authentication.refused` with a `WWW-Authenticate`
challenge and no detail that distinguishes one cause from another. Refusals
are counted on the private metrics listener under a closed reason label and
are not written to the audit journal (recorded decision MESSAGING-DEC-02).

`allowedClients` is required and never empty, unlike the sibling products'
development default that admits every client the issuer verifies: an access
profile resolves from the matched client, so an open client list would have
no profile to resolve to.

Tests: `crates/registry-messaging/src/auth.rs` (expired token, wrong token
type, unadmitted client, undeclared exchange) and
`crates/registry-messaging/src/http.rs` (missing or malformed credential,
forged signature, another audience). They are cited under MESSAGING-SEC-04 in
`contracts/security-test-traceability.yaml`.

## Authorization

Threat: an authenticated caller sends through a sender identity or template
it was not given, an operator credential submits messages, or one caller
reads another caller's messages.

Authorization is decided in `registry-messaging-core` against the one access
profile the verified client resolves to, never against raw claims. A client
listed in two profiles is refused when the package loads
(MESSAGING-DEC-03). The profile's scopes, actor kind, and principal claim
must all be present on the token, or the caller is refused
`403 profile.not-authorized`. An operation the caller's role does not carry,
such as an operator submitting, is refused `403 operation.not-authorized`.

- Submission (MESSAGING-SEC-01, enforced): `authorize_submission` admits
  only a sender profile whose `senderProfiles` and `templates` list the
  request's choices, and direct content only where `allowDirectContent` is
  set. Operators never submit (MESSAGING-DEC-04). `POST /v1/messages` calls
  it before the store is reached, on every request including a replay
  (MESSAGING-DEC-07).
- Visibility (MESSAGING-SEC-04, enforced): `check_message_visibility` shows
  a message to the principal that submitted it, the same issuer and
  subject, and to operator profiles only; another caller of the same
  access profile does not see it. A missing message answers exactly like an
  invisible one, `404 message.not-visible` (MESSAGING-DEC-01). The status and cancel routes both
  apply it, and a malformed identifier answers the same way before the store
  is consulted. The `postgres_messages` suite has a second sender read and
  cancel a real message.

## Configuration and secrets

Threat: a credential reaches the runtime from a place review does not see,
or a misspelled key silently leaves a setting at its default.

Every mapping in the runtime document and the package is closed, and an
unknown key is refused with its path. Credentials are named only by
`secret:env/NAME` or `secret:file/name` references in members ending in
`Ref`, under a provider the document explicitly enables. `${VAR}`
substitution happens after parsing and is refused in any `Ref` member
(MESSAGING-DEC-05). Refusal messages name the member and never repeat the
refused value, the substituted text, or a default. `Debug` output of the
database and metrics settings is redacted.

Tests: the `config.rs` and `environment.rs` unit tests, and the checkpoint's
`messagingctl check` refusal cases.

## Package integrity and the ledger

Threat: a file edited under `package.root` changes what a running or
restarted deployment sends without anyone recording the change, or a
deployment runs a package other than the one reviewed.

The package digest covers `messaging.yaml` and every file under
`templates/` and `providers/`, each by its own SHA-256 and size, in a canonical JSON
listing. The loader refuses symbolic links anywhere in the package, bounds the
entry count, each file, and the total, and reads nothing outside
`package.root`. A pinned `package.expectedDigest` must equal the digest read,
or the runtime and `messagingctl` refuse before reaching a database.
`messaging serve` refuses to start unless the ledger's active digest equals
the package read; `messagingctl apply --apply` is the one writer of the
ledger, under an advisory lock, so a change is recorded before it can serve
and applies on restart (MESSAGING-DEC-06). The runtime reads the package
once at startup, so a later edit changes nothing until the next restart,
which then refuses the unrecorded digest. `/ready` asks the ledger on every
call: once an operator applies another package, a running runtime answers
`503` until it is restarted onto it, so a load balancer stops sending it
traffic for a package the deployment no longer names (MESSAGING-DEC-23).

`messagingctl apply` does not write the audit journal: the runtime is its
single writer, and the ledger row with its runtime version and time is the
record of the change. The runtime start record names the package digest.

Residual risks: the package is read twice at startup (once while the
configuration is checked, once for serving), and only the second read is
compared with the ledger, which is the one served. A ConfigMap-style mount
that publishes files through symbolic links is refused; operators copy the
package into place instead (MESSAGING-DEC-24).

Tests: `config.rs::a_pinned_package_digest_must_equal_the_digest_of_the_package_read`,
`runtime.rs::the_runtime_serves_only_the_package_the_ledger_names_active`,
the `package.rs` loader tests, and the `postgres_package` suite.

## Listeners and metrics

Threat: the counters, or the runtime itself, are exposed on a public
interface.

The public listener refuses a public unicast bind under every setting, and
`development-loopback` refuses any non-loopback bind. `/metrics` is served
only on `metricsListener`, which must be a concrete loopback or private
address and may not share the public socket. Metric labels are closed by
construction: route templates, a fixed method vocabulary, status classes, and
refusal reasons. No identifier, principal, client, contact, or problem
detail becomes a label. `messaging_provider_callbacks_total` counts callbacks
by a closed outcome label only (`unverified`, `unreadable`, `ignored`,
`applied`, `unchanged`, `unmatched`, `ambiguous`, `unavailable`); neither the
provider id nor a path token becomes a label, and the request counters label
the callback routes by their templates.

Tests: `http.rs::the_metrics_listener_serves_counters_and_nothing_else`,
`metrics.rs::labels_are_closed`, the `config.rs` listener tests, and the
PostgreSQL suite's served runtime, which checks `/metrics` is absent from the
public listener.

## Audit

The journal is the platform keyed hash-chained sink under `audit.path`, keyed
by `audit.hashKeyRef`. The runtime start carries the runtime version, the
package digest, and the retention periods in force. A template preview
carries the access profile, a keyed pseudonym of the verified issuer and
subject, the package digest, the template reference when the package ships
it, and the outcome with its problem code; never the data, the rendered
parts, or the raw subject. A preview the journal cannot record is answered
`503 service.unavailable`, not rendered. An unauthenticated or unprofiled
request is not journaled, as for every route (MESSAGING-DEC-02). Listeners
bind before the start record is written, so a taken address never leaves a
start record for a runtime that did not serve.

A message's audit records are written into `messaging_audit_outbox` inside
the transaction that makes the change, and the runtime's publisher appends
them to the journal in outbox order. So an accepted message, a transition,
an attempt, a quarantine, or a settlement is recorded if and only if it
committed, and `messagingctl`, which never opens the journal, records its
operator actions the same way (MESSAGING-DEC-13). The events are
`messaging.message.accepted`, `messaging.dispatch.transition` with its actor
(`caller`, `worker`, or `operator-tool`), `messaging.attempt.started`,
`messaging.attempt.finished`, `messaging.message.quarantined`, and
`messaging.message.settled`, and `messaging.receipt.recorded` for a
delivery receipt that moved a report or joined a message's history. A refused or replayed submission is journaled
directly, as `messaging.message.refused` with its problem code or
`messaging.message.replayed` with the message identifier. The records carry
identifiers, classes, the principal pseudonym, and a keyed recipient
reference; never a contact, a part, template data, or the provider's own
message reference (MESSAGING-DEC-14).

Reads are not journaled: the status route and `messagingctl messages list`
and `show` leave no record (MESSAGING-DEC-15). Scheduling's appointment read
and Casework's review request and task reads are not journaled either;
Casework journals only its accountability read, which releases a raw
reviewer identity. A message view releases no contact, part, or data, so it
is an ordinary read.

## Data minimization and log and audit absence (pending, slice S6)

MESSAGING-SEC-08. Once messages exist, audit records carry the operation,
caller pseudonym, sender profile, template reference, correlation, outcome
class, and a keyed recipient reference, never a body, template data, or a raw
contact. The full-journey absence test lands with slice S6. `MESSAGING_LOG`
accepts only `error`, `warn`, or `info`, so no dependency's debug logging can
be switched on by the environment.

## Submission and idempotency

Threat: a caller smuggles a field the package did not review, replays a key
to learn or alter another request, or has one request delivered twice.

MESSAGING-SEC-02, enforced. The body is strict JSON (duplicate members
refused) in a closed shape. A body that is not strict JSON, or a missing
or malformed `Idempotency-Key`, is `400 request.invalid`; well-formed JSON
with an unknown member, a missing required member, a recipient of the wrong
channel, or a malformed or out-of-window instant is
`422 request.unprocessable`, as in Scheduling and the preview route; nothing
is recorded either way. The `Idempotency-Key` header is required and bounded, and is scoped to the
caller's issuer and subject, so a caller cannot probe another caller's keys.
The request hash covers the canonical request body: the same key with
another body is `409 idempotency.key-reused`, and a key older than
`retention.submissionReceiptDays` is `410 idempotency.expired`. A replay is
authorized and rendered again against the active package before the stored
receipt is answered, so a key cannot outlive the caller's authority
(MESSAGING-DEC-07). One transaction records the key, the message, its
payload, its dispatch job, and the acceptance audit; concurrent submissions
under one key produce exactly one message, which the `postgres_messages`
suite proves.

Tests: MESSAGING-SEC-01 and -02 in `contracts/security-test-traceability.yaml`.

## Limits

Threat: one integration exhausts the runtime, the provider account, or the
recipients' patience by submitting faster or more than its profile allows;
a limit that forgets on restart or splits across replicas lets a caller
reset it; the limiter itself becomes a label or journal channel for caller
identities.

Each access profile's `requestsPerMinute` and `burst` are a
`registry-platform-ratelimit` token bucket per caller, keyed by the caller's
keyed principal pseudonym, never by the raw subject. A submission is charged
after authentication and the role check and before its body is read, so a
caller cannot spend the runtime's rendering on requests it has no budget
for; past the burst it is `429 rate-limit.exceeded` with `Retry-After`, and
a limiter that cannot decide answers `503 service.unavailable`
(MESSAGING-DEC-20). The bucket is in-process: each replica enforces its own,
and a restart refills it. `dailyLimit` is counted over the profile's
accepted messages of the last 24 hours inside the acceptance transaction,
under a transaction advisory lock of the profile, so concurrent submissions
cannot both take the last place and the count survives a restart and holds
across replicas; past it the answer is `429 quota.exceeded` with
`Retry-After` (MESSAGING-DEC-21). A replay is charged to the rate, not to
the daily count. A refusal is journaled like every refused submission, as
`messaging.message.refused` with its problem code.

A provider's `capabilities.ratePerSecond` paces the worker in-process: a
leased attempt waits for the provider's next send slot, with a ten-second
allowance added to its time budget, and an attempt whose slot does not open
in it is transient and nothing is sent (MESSAGING-DEC-22).

Residual risk: a caller that keeps sending past its rate still makes the
runtime authenticate each request and write one journal record for it. The
request edge's body limit bounds each request, but no limit bounds the
journal growth of a refused flood; an operator relies on the deployment's
edge proxy for that.

Tests: `limits.rs` (`a_caller_is_refused_past_its_profile_burst_with_the_wait_needed`,
`callers_and_profiles_have_separate_budgets`,
`an_unknown_profile_or_an_unusable_key_is_refused_as_unavailable`,
`a_provider_starts_one_send_per_interval`), `http.rs`
`a_caller_past_its_profile_rate_is_refused_with_the_wait_needed`, and the
PostgreSQL suites' `a_profile_past_its_daily_limit_is_refused_across_a_restart`,
`concurrent_submissions_never_take_more_than_the_daily_limit`, and
`a_paced_provider_starts_one_send_per_interval`.

## Dispatch

Threat: a worker that lost its lease overwrites the outcome another worker
recorded, a send that may have reached the provider is sent again and the
recipient gets it twice, or a cancel races a send.

MESSAGING-SEC-05, enforced. The worker runs on
`registry-platform-dispatch`: a claim takes a lease, and every outcome write
names the lease and the generation, so a stale worker's write is refused
and changes nothing. An operator requeue starts a new generation.

MESSAGING-SEC-06, enforced. A transport must finish within the attempt's
budget; the worker stops waiting when it is spent and records the attempt as
maybe sent (MESSAGING-DEC-10). A maybe-sent attempt, or a lease that lapsed
mid-attempt, stops the message as `unknown` unless the sender profile set
`onUncertain: retry`, which the package accepts only over a provider that
declares `idempotentSubmit` or a profile that sets `acceptDuplicates`. A
retry then carries the same provider idempotency key, derived from the
message, its generation, and a digest of its content (MESSAGING-DEC-11).
Each provider kind decides whether a failure happened after the message
left: an `smtp` drop, timeout, or unreadable reply once the end-of-data
marker was written, and an `http` failure after the request was written,
is maybe-sent; a failure before either is not sent and transient.

A cancel takes the job row's lock, so it and a claim serialize: a message is
either cancelled before any attempt or refused `409 message.dispatch-started`
(MESSAGING-DEC-09), which the `postgres_messages` race test proves across
forty rounds. A message whose provider has no transport, or whose payload
was erased, fails permanently without a send (MESSAGING-DEC-12).

Tests: MESSAGING-SEC-05 and -06 in `contracts/security-test-traceability.yaml`
and the `postgres_dispatch` suite.

## Operator actions

Threat: an operator tool changes a message without a record, or an operator
changes one by mistake.

`messagingctl messages retry`, `settle`, and `cancel` report the action and
the status it would reach, and change nothing without `--apply`. Each checks
the message's status in the same transaction that changes it, refuses with
`message.not-eligible` or `message.changed` otherwise, and writes its
`operator-tool` audit record into the outbox (MESSAGING-DEC-13). `list` and
`show` mask the recipient and never print a part, template data, or the
submitter's subject. `messagingctl` reaches the database only through the
runtime configuration's credential references.

## HTTP provider egress (MESSAGING-SEC-03)

Threat: a provider package or its connection sends a message, or a
credential, to an address other than the provider the operator configured:
an internal service, a metadata endpoint, a path outside the provider's API,
or a header the runtime owns.

The HTTP provider kind sends only through the platform fixed-destination
substrate. The connection's `baseUrl` fixes the origin and a base path ending
in `/`; it may not carry userinfo, a query, a fragment, an escape, or a dot
segment, and plain `http` is accepted only to a loopback host. A production
(`https`) provider's name is resolved by the substrate, which refuses a
loopback, private, shared, link-local, or metadata address before connecting,
unless
the address falls in an exact `allowedPrivateCidrs` entry; the attempt is
then not sent and transient. Redirects are never followed; a 3xx is
classified like any other status. The OAuth token endpoint is a second fixed
origin under the same address rules and the same scheme.

The prepare script chooses only a relative target under the base path, the
values of headers the package declares, and a JSON or form body that Rust
serializes. A target that is absolute, rooted, protocol-relative, escaped,
carries a fragment, or climbs out of the base path, and a header the package
did not declare, is refused before anything is sent (`provider.request-refused`,
permanent). A package may not declare a runtime-owned header such as
`authorization`, `host`, `content-type`, or `cookie`, and an API key header
may not also be script-writable.

Credentials are `secret:` references resolved at activation. No script sees
a credential, a reference, the base URL, or a runtime-owned header: prepare
receives the rendered message and the sender profile, interpret the status,
the package's allowlisted response headers, and the JSON body read within
`maximumResponseBytes`, and receipt the callback's method, form, query, and
JSON body. Every script runs with a fresh scope, an operation budget, the
send deadline, and no `import`, `eval`, `print`, or `debug`; interpret and
receipt output is refused above 64 KiB. A 2xx the interpret script cannot
classify is `maybe-sent`, never accepted. Tracing records the stage, the HTTP
status, the failure kind, and the outcome class only.

`onUncertain: retry` is refused when the package loads unless the provider
declares `idempotentSubmit` or the sender profile accepts duplicates. The
manifest's provider entry is the one place that capability is declared: an
`smtp` provider may not declare it, `provider.yaml` has no such member, and
the prepare script sees the idempotency key only when it is declared, so a
script cannot rely on deduplication the manifest does not state.

Residual risks: the test suite cannot inject a resolver, so it proves the
refusal with a name that resolves to loopback and with literal private and
metadata addresses; the substrate's own tests cover an answer that changes
between resolutions. Scripts run on the async runtime thread within the send
deadline. The OAuth token decoder is closed: it accepts `access_token`,
`token_type` compared case-insensitively to `Bearer`, `expires_in` unless the
connection sets `assumedLifetimeSeconds`, and an optional string `scope`, and
refuses any other member, so the send is transient. A plain `http` base URL
to a loopback host is accepted by every build, unlike SMTP's
`development-loopback`, which only a test build accepts.

Tests: MESSAGING-SEC-03 in `contracts/security-test-traceability.yaml`, and
the `http_provider/tests.rs` suite, including
`secrets_are_absent_from_script_scope`,
`a_script_header_outside_the_declared_allowlist_is_refused`, and
`a_script_referring_to_anything_outside_its_arguments_fails`.

## SMTP provider egress (MESSAGING-SEC-03)

Threat: a message, or the relay credential, reaches a host other than the
relay the operator configured, travels in plaintext, or is accepted by a
relay presenting a certificate for another name; or a header line is
injected from template data.

The `smtp` provider kind connects to one configured `host`. Each attempt
resolves it once, refuses the whole answer set when any address is loopback,
private, shared, unique-local, link-local, or metadata, unless it falls in an
exact `allowedPrivateCidrs` entry (RFC 1918, CGNAT, or unique-local only),
and connects only to a checked address. The attempt is then not sent and
transient. TLS modes:

- `starttls` (default port 587) requires the relay to offer `STARTTLS`
  and upgrades before authentication or any envelope command; a relay that
  does not offer it gets no credential and no message.
- `implicit` (default port 465) is TLS from the first byte.
- `development-loopback` is plaintext to a loopback literal or `localhost`
  on an explicit port that is neither 587 nor 465, refuses every resolved
  answer that is not loopback, and admits no trusted root or private
  network. Like `database.testOnlyPlaintext`, only a build carrying a test
  feature accepts it (`postgres-test` or `smtp-test`); a release build
  refuses it at `messagingctl check` and at startup.

Both TLS modes verify the relay's certificate against the configured host
name, not the connected address, over the public web roots plus an optional
`trustedRootCertificateRef` PEM bundle. The session uses lettre's low-level
connection (`lettre` 0.11, `rustls`, no default features), driven step by
step so each stage is classified: authentication only over `PLAIN` or
`LOGIN`, and in a TLS mode only after TLS (`development-loopback` may
authenticate in plaintext to its loopback relay), `SMTPUTF8` and `8BITMIME` only when the relay
advertises them, and a permanent refusal otherwise. Addresses are parsed by
lettre before any connection; a subject strips newlines and lettre encodes
headers, so no value can open a header line. The `Message-ID` is
`<message id@sender domain>`, so a duplicate after an unknown outcome is
recognisable downstream. The EHLO name is lettre's default address literal;
an `ehloName` setting is not offered.

Credentials are `secret:` references resolved at activation into lettre
`Credentials`. No log line, attempt detail, or error carries an address, a
subject, a body, a credential, or a relay reply's text: the detail is a
stage, a reply code, and a failure class, and `Debug` output of the settings
and the provider redacts every reference and credential.

Residual risks: lettre's `Credentials` holds the username and password as
plain `String` values that are not zeroized when dropped, unlike the
runtime's own `ProtectedSecret`; they live for the life of the process. The
EHLO name `[127.0.0.1]` may be refused by a relay that checks it.

Tests: the `smtp/tests.rs` suite, including
`starttls_refuses_a_certificate_for_another_name`,
`a_relay_without_starttls_gets_no_credential_and_no_message`,
`a_subject_cannot_inject_a_header`, and
`no_log_line_carries_an_address_content_or_credential`; the
`smtp/settings.rs` tests, including
`plaintext_is_refused_by_a_build_without_a_test_feature`; and MESSAGING-SEC-03
and -06 in `contracts/security-test-traceability.yaml`.

## Provider activation

Threat: a provider starts half-configured, a startup failure prints a
credential, or a message is sent through a connection the package did not
declare.

`providers` in the runtime document gives each provider `messaging.yaml`
declares its connection, keyed by the same id and with the same `kind`; a
connection the package does not declare, or declares with another kind, is
refused by `messagingctl check` and at startup. Every credential, trust
bundle (`tlsTrustProfiles.<name>.bundleRef`), and callback verifier secret is
a `secret:` reference, checked offline for its grammar and enabled provider,
and resolved once at startup before either listener binds. A provider that
cannot be activated stops the runtime with an error naming the provider and
the member or reference, never a value. A declared provider given no
connection is not activated: startup logs a warning, and its messages fail
`provider-unconfigured` without a send (MESSAGING-DEC-12).

The HTTP transport passes the idempotency key to the prepare script only
when the package declares `idempotentSubmit` for the provider. Channel,
sender, and provider come from the persisted message, so a later package
cannot redirect a retry; the SMS segment bound comes from the active
package's sender profile.

Tests: `providers/tests.rs`, including
`a_provider_that_cannot_be_activated_names_itself_and_never_a_secret`, and the
`config.rs` provider connection tests.

## Callbacks

Threat: a forged, replayed, or reordered provider callback changes a
delivery report or regresses it; a callback route becomes an oracle for
which providers receive callbacks or which messages exist; a callback's
body, a path token, or a provider reference reaches a log, a label, or the
journal; a provider repeating itself grows the store without bound
(MESSAGING-SEC-07, enforced).

`POST /v1/provider-callbacks/{provider_id}` and
`POST /v1/provider-callbacks/{provider_id}/{token}` are served on the public
listener, carry no bearer token, and take the request edge's default body
limit (`413 request.body-too-large` above it). The path names the provider;
the verifier its runtime configuration names decides whether the request is
that provider's. `callbackVerifier` is required exactly when the package
declares `receipts: callback`, and is one of a closed set named by
algorithm: `hmac-sha1-url-form` (HMAC-SHA1 over the configured external
`url`, the request's query, and the form parameters sorted by name, base64 in
a configured header), `hmac-sha256-body` (HMAC-SHA256 over the raw body, hex
or base64 in a configured header), or `path-token` (a secret token as the
last path segment). `none` is not a kind. Tags are compared in constant time
by `aws-lc-rs`. The secret or token is a `secret:` reference resolved once at
startup.

An unknown provider, a provider without a verifier, a missing or wrong
signature or token, a token segment on a provider whose verifier is not
`path-token`, and a missing segment on one whose verifier is all answer
`403 callback.unverified` alike, so the route reveals neither which
providers receive callbacks nor why a request was refused. It is 403 rather
than 401 because there is no challenge scheme a provider could answer. The
refusal is logged with the provider id only when the provider is configured,
and with a value-free reason; nothing about the request is read before it
verifies.

A verified callback is read by the package's `receiptScript` on the blocking
pool, under the same bounded Rhai engine and budget as `interpret`. A script
that throws or returns the wrong shape answers `422 callback.unreadable`; one
that returns nothing (an intermediate state the runtime does not record)
answers 204. The receipt names its message by the reference the provider
answered when it accepted an attempt, scoped to that provider, so another
provider's reference names nothing. Everything the receipt changes is decided
in one transaction under the message row's lock: the report moves only
forward (none, `sent`, then `delivered` or `undelivered`, final once
terminal); the receipt joins the message's history of at most sixteen
distinct receipts unless the same report and code are already there; and a
receipt that moved the report or joined the history writes
`messaging.receipt.recorded` to the outbox in the same transaction, carrying
the message id, provider, report, the provider's code, whether it applied,
and the report before and after. The record, the history row, and the logs
never carry the reference, the recipient, a part, or the callback's body,
form, or headers.

`GET /v1/messages/{message_id}` serves the stored report, when it last moved
(`reportedAt`), the dispatch state, and the status derived from the two: a
submitted message is `delivered` once its report is `delivered` and `failed`
once it is `undelivered`; every other status is the dispatch state. The view
never carries the provider, the reference, the provider's code, or the
receipt history. A message whose provider the active package does not declare
`receipts: callback` for, and that holds no report, reads `unavailable`; the
flag is computed at read time, so a package change that adds or removes the
declaration changes what a report-less message reads as, never the stored
report. `messagingctl messages retry`, `settle`, and `cancel` decide
eligibility from the dispatch state, not the derived status, so a submitted
message the provider reported undelivered is never sent again by a retry.

There is no replay window: none of the three verifier kinds signs a
timestamp, so a window could not be enforced for them. A replayed genuine
callback repeats a report the message already holds or has passed, so it
changes nothing and, as an exact duplicate, is not stored or audited again.

A verified receipt whose reference names no message of the provider, or
names more than one, answers 204 so the provider does not retry it, changes
nothing, journals nothing, and is counted as `unmatched` or `ambiguous`. A
store or journal failure, or a provider without a receipt script, answers
`503 service.unavailable`, so the provider retries it.

Residual risks. A callback that arrives before the accepting attempt commits
finds no reference, is counted `unmatched`, and is lost unless the provider
repeats it. A receipt cannot settle a message held as `unknown` after a
maybe-sent attempt, since such an attempt stores no reference; spec 6.4's
"a receipt can also settle unknown" is not implemented. A reference two
messages share is not applied to either. A reference longer than 128 bytes
is never stored, so never matches. `hmac-sha1-url-form` verifies over the
operator-configured external `url`, not the URL the request arrived on, so a
reverse proxy that rewrites the path does not break it, but a wrong `url`
refuses every callback. HMAC-SHA1 is kept only because a widely deployed
provider signs with it; it is used as a MAC, where SHA-1's collision
weakness does not apply.

Tests: MESSAGING-SEC-07 in `contracts/security-test-traceability.yaml`: the
PostgreSQL suite `tests/postgres_callbacks.rs` (each verifier kind valid and
forged, duplicate and out-of-order receipts, a final report kept, the
history bound, unknown, foreign, and ambiguous references, unreadable and
ignored callbacks, and the absence of the reference, secrets, and token from
logs and the journal), the route tests in `http.rs`, and the verifier and
report-order tests in `registry-messaging-core`.

## Templates

Threat: a template reaches the network or a file, renders without bound and
exhausts the runtime, injects markup into an email or a header line, or
renders a message in a language the recipient was not addressed in
(MESSAGING-SEC-09, enforced).

Every part renders in its own `minijinja` environment built empty: no
loader, so no `include`, `import`, or `extends`; no macros; no built-in
filters, tests, or globals; and no file, network, or clock access. Templates
come only from the package loaded and digested at startup. A render is
bounded by a fuel budget, a recursion limit, and a byte ceiling per part
enforced as the output grows. Strict undefined refuses a missing or null
value rather than rendering it empty. The data is validated against the
version's JSON Schema first; the schema may not reference anything outside
itself, and refusals report at most eight JSON Pointers and schema keywords,
never a value. HTML parts escape every value, and the formatter ignores a
template's own `autoescape` block, so no author or data can turn escaping
off. Text and SMS parts strip control characters, and a subject strips
newlines, so no value can open a header line. A locale the version does not
declare is refused, never answered in a fallback language. An SMS whose
segment count exceeds the sender profile's `maximumSegments` is refused
before acceptance.

The preview route authenticates, requires the sender role
(`operation.not-authorized` otherwise), and requires the caller's profile to
list the template (`profile.not-authorized`, before any lookup, so a caller
cannot probe which templates exist). It persists nothing.

Residual risks: the fuel budget counts instructions, not bytes, so an
expression such as string repetition can allocate up to the data's size
multiplied by one factor before the output ceiling refuses it; the request
body limit bounds the data. `{% autoescape false %}` is accepted by the parser
and has no effect. The loader reads each file after listing the directory, so
a file swapped between the two reads is caught only by the digest the ledger
compares.

Direct content (`contentSource: direct`) needs the profile's
`allowDirectContent` and passes the same channel, size, control-character,
and segment rules; it has no route until submission lands in slice S3.

Tests: MESSAGING-SEC-09 in `contracts/security-test-traceability.yaml`, the
`content.rs` and `template.rs` core tests, and the preview route tests in
`http.rs`, including the unauthenticated, operator, unlisted-template, and
journal-failure negatives.

## Retention

Threat: payloads, contacts, or the records that describe them outlive the
periods the deployment declared; erasure removes the payload of a message
that may still be sent, requeued, or settled; a retention run erases what
has not expired, races an operator, or leaves no trace
(MESSAGING-SEC-10, enforced).

`retention.payloadDays` (1 to 30), `recordDays` (up to ten years), and
`submissionReceiptDays` (up to the record period) are validated and recorded
at start. The payload and record periods count from the instant the
message's dispatch job reached a terminal state, `delivered`,
`dead_lettered`, `expired`, or `cancelled`, which the job row already holds
(MESSAGING-DEC-16). A `pending`, `leased`, or `unknown` message is never
erased, whatever its age. A submission's `expiresAt` stays capped at
acceptance plus `payloadDays`. Past `payloadDays` the recipient and the
rendered parts are nulled and the content-free record stays; past
`recordDays` the record is deleted with its payload, job, attempts, delivery
receipts, and idempotency row, so its key can be used again
(MESSAGING-DEC-17). Past `submissionReceiptDays` the stored receipt is
dropped and a repeat of its key is `410 idempotency.expired`.

One run is one transaction under a transaction advisory lock, with a
five-second lock timeout and a sixty-second statement timeout; a run that
exceeds either is rolled back whole. Each due terminal job is locked
`FOR UPDATE` before its payload is erased, and the predicate is read again
under the lock, so an operator requeue that commits first keeps the payload,
and one that comes after fails as `payload-erased` without a send
(MESSAGING-DEC-12). The runtime runs retention at start and hourly under its
own credential with the database's clock as the cutoff
(MESSAGING-DEC-18). `messagingctl retention erase-expired --before` runs it
under the migration credential, previews unless `--apply` is given, and
refuses a cutoff later than the local clock before any input or output and
later than the database's clock inside the run (MESSAGING-DEC-19). A run
writes `messaging.retention.erased` into the outbox in its own transaction,
carrying the cutoff, the three counts, the periods in force, and its actor
(`runtime` or `operator-tool`), never an identifier of what it erased. The
runtime's sweep writes it only when it erased something; an applied operator
run always writes it; a preview writes nothing.

Residual risk: a run does not batch. A backlog large enough to exceed the
statement timeout erases nothing until an operator runs the command against
a cutoff that bounds the backlog. Published outbox rows, whose records carry
no payload value, are not pruned by retention.

Tests: MESSAGING-SEC-10 in `contracts/security-test-traceability.yaml`.
