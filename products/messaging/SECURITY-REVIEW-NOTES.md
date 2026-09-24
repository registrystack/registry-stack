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

There is no unauthenticated mode. Every `/v1` route resolves its caller
before any other decision. A credential is accepted only when it is a compact
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
  a message to its submitting profile and to operator profiles only, and a
  missing message answers exactly like an invisible one, `404
  message.not-visible` (MESSAGING-DEC-01). The status and cancel routes both
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

The package digest covers every file under `templates/` and
`messaging.yaml`, each by its own SHA-256 and size, in a canonical JSON
listing. The loader refuses symbolic links anywhere in the package, bounds the
entry count, each file, and the total, and reads nothing outside
`package.root`. A pinned `package.expectedDigest` must equal the digest read,
or the runtime and `messagingctl` refuse before reaching a database.
`messaging serve` refuses to start unless the ledger's active digest equals
the package read; `messagingctl apply --apply` is the one writer of the
ledger, under an advisory lock, so a change is recorded before it can serve
and applies on restart (MESSAGING-DEC-06). The runtime reads the package
once at startup, so a later edit changes nothing until the next restart,
which then refuses the unrecorded digest.

`messagingctl apply` does not write the audit journal: the runtime is its
single writer, and the ledger row with its runtime version and time is the
record of the change. The runtime start record names the package digest.

Residual risks: the package is read twice at startup (once while the
configuration is checked, once for serving), and only the second read is
compared with the ledger, which is the one served. A ConfigMap-style mount
that publishes files through symbolic links is refused; operators copy the
package into place instead.

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
detail becomes a label.

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
`messaging.message.settled`. A refused or replayed submission is journaled
directly, as `messaging.message.refused` with its problem code or
`messaging.message.replayed` with the message identifier. The records carry
identifiers, classes, the principal pseudonym, and a keyed recipient
reference; never a contact, a part, template data, or the provider's own
message reference (MESSAGING-DEC-14).

Reads are not journaled: the status route and `messagingctl messages list`
and `show` leave no record. See the open questions below.

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
refused) in a closed shape; an unknown member, a missing required member, or
a malformed instant is `400 request.invalid`, and nothing is recorded. The
`Idempotency-Key` header is required and bounded, and is scoped to the
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

## Dispatch

Threat: a worker that lost its lease overwrites the outcome another worker
recorded, a send that may have reached the provider is sent again and the
recipient gets it twice, or a cancel races a send.

MESSAGING-SEC-05, enforced. The worker runs on
`registry-platform-dispatch`: a claim takes a lease, and every outcome write
names the lease and the generation, so a stale worker's write is refused
and changes nothing. An operator requeue starts a new generation.

MESSAGING-SEC-06, partial. A transport must finish within the attempt's
budget; the worker stops waiting when it is spent and records the attempt as
maybe sent (MESSAGING-DEC-10). A maybe-sent attempt, or a lease that lapsed
mid-attempt, stops the message as `unknown` unless the sender profile set
`onUncertain: retry`, which the package accepts only over a provider that
declares `idempotentSubmit` or a profile that sets `acceptDuplicates`. A
retry then carries the same provider idempotency key, derived from the
message, its generation, and a digest of its content (MESSAGING-DEC-11). The
row stays partial because the provider kinds, not the worker, decide
whether a failure happened after the request was written.

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

## HTTP provider egress (MESSAGING-SEC-03 partial)

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

`onUncertain: retry` is refused at startup unless the provider declares
`idempotentSubmit` or the sender profile accepts duplicates
(`check_uncertain_retry`); the check is exposed for the configuration loader
to call.

Residual risks: the test suite cannot inject a resolver, so it proves the
refusal with a name that resolves to loopback and with literal private and
metadata addresses; the substrate's own tests cover an answer that changes
between resolutions. Scripts run on the async runtime thread within the send
deadline. The OAuth token decoder is closed: it accepts `access_token`,
`token_type` compared case-insensitively to `Bearer`, `expires_in` unless the
connection sets `assumedLifetimeSeconds`, and an optional string `scope`, and
refuses any other member, so the send is transient. The configuration loader that activates providers,
and the adapter that registers them as the worker's transport, are not wired
yet.

Tests: MESSAGING-SEC-03 in `contracts/security-test-traceability.yaml`, and
the `http_provider/tests.rs` suite, including
`secrets_are_absent_from_script_scope`,
`a_script_header_outside_the_declared_allowlist_is_refused`, and
`a_script_referring_to_anything_outside_its_arguments_fails`.

## Open questions

- Reads are not audited. The status route and `messagingctl messages list`
  and `show` are unjournaled, and no test pins that choice. Either record it
  as a decision with evidence or journal reads.
- The specification's `dispatch` member of the message view is not served.
- A malformed submission answers `400 request.invalid`, while the preview
  route answers a malformed body `422 request.unprocessable`.
- A payload may be erased `retention.payloadDays` after acceptance even when
  the message still waits in a retry; MESSAGING-SEC-10 and the sweep must
  decide how the two interact.
- The `messaging` binary registers no transport, so every claimed message
  fails `provider-unconfigured` until the SMTP and HTTP provider kinds are
  wired in.

## Callbacks (pending, slice S5)

MESSAGING-SEC-07: configured verifier kinds, a replay window, and delivery
reports that only move forward.

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

## Retention (pending, slice S6)

MESSAGING-SEC-10. The `retention` bounds are validated and recorded at start
today: payloads 1 to 30 days, records up to ten years, receipts up to the
record period. The sweep that enforces them, and refuses to erase a message
still sending or in an unknown outcome, lands with slice S6.
