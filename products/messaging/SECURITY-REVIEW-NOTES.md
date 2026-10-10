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

`allowedClients` is required and lists at least one distinct client. The
shared reader also accepts the keyword `unrestricted`, which admits every
client the issuer verifies, and each runtime decides whether to take it:
Base Registry Engine and Evidence accept it, Casework accepts it on
development loopback only, and Scheduling refuses it in every mode. Messaging
refuses it in every mode too: an access profile resolves from the matched
client, so an open client list would have no profile to resolve to.

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
`403 profile.not-authorized`. A profile states its scopes or writes
`unrestricted`: an omitted or empty `requiredScopes` is refused when the
project is read, so no profile is left open by a missing line
(MESSAGING-DEC-29). An operation the caller's role does not carry,
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

## Node request normalization

The Node facade snapshots plain JSON before handing a request or token to
native code. Its aggregate UTF-8 text budget counts enumerable property
names as well as string values, so one oversized key cannot bypass the
one-MiB bound. `__test__/sanitizer.test.js` verifies refusal before any
native submission call; the unified client copies the same facade through
the maintained synchronization script.

## Configuration and secrets

Threat: a credential reaches the runtime from a place review does not see,
or a misspelled key silently leaves a setting at its default.

Every mapping in the runtime document and the package is closed, and an
unknown key is refused with its path. Credentials are named only by
`secret:env/NAME` or `secret:file/name` references in members ending in
`Ref`, under a provider the document explicitly enables. `${VAR}`
expansion uses the shared `RuntimeConfigLoader` after YAML parsing. It only
substitutes string values; keys and comments stay literal, and substituted
text cannot alter the document's structure. Expressions in or below `Ref`
or `Refs` members and in secret-provider declarations are refused, including
through aliases (MESSAGING-DEC-05). Diagnostics identify the field without
revealing substituted or default values. Secret-bearing configuration blocks
redact their `Debug` output.

The runtime file is read under the configuration conventions. Every integer
member carries its bound in its type, every union names its variant under
`type`, and a mapping that merges shared blocks (the OIDC issuer and
clients, the audit key, a provider connection) is read without serde
flattening, so each unknown key inside it is refused at that key. A removed
key or the retired apiVersion is refused by name with its replacement, never
ignored, so an old file cannot fall back to a default. Each refusal carries
its code, its JSON Pointer, and its line and column, and no refusal repeats
a value read from the file or the environment: a digest pin that does not
match names the digest computed from the package, never the pin as written.
`messagingctl check` reads no database, network, or secret; without
`--environment` a `${VAR}` expression is checked for its syntax and position
only, so no variable's value is resolved into a finding. A callback
verifier's header, URL, and secret reference, and an `http` connection's
integer bounds, are refused when the file is read; activation keeps its own
checks, so a document built in code is held to the same rules.

Tests: the `config.rs` unit tests, the `registry-platform-config`
expansion and protected-member tests, and the checkpoint's `messagingctl
check` refusal cases.

## Package integrity and the ledger

Threat: a file edited under `package.root` changes what a running or
restarted deployment sends without anyone recording the change, or a
deployment runs a package other than the one reviewed.

Installed packages use the shared checksum envelope. `SHA256SUMS` determines
the package digest and covers each admitted product file, with optional
`REVISION` provenance. The loader verifies the envelope and pin before any
database work. It then rebinds the sum file and revision to the verified
identity, reads bounded files into owned buffers, checks each digest, and
parses/compiles only those buffers. Later file replacements cannot change
rendered or executed bytes. Symbolic links, unknown files, excessive sizes,
and excessive file counts are refused.

`messaging serve` reads the shared activation ledger and refuses unless its
active database identity and digest equal the configured deployment and
installed package. It also verifies the exact schema and effective runtime
role. In split-role mode the runtime can read both ledgers and use product
tables, but cannot write either ledger, own Messaging objects, create schema
objects, or reach a migration-owned write path. `messagingctl apply` runs all
pending migrations, grants that bounded runtime access, and appends the
activation in one locked transaction after request audit. A failed commit is
read back by its generated activation id and is never reported as a guessed
failure. Apply observes the runtime role's grants before it grants them, so a
reapply of the active package that restores stale split-role grants records a
new activation and is audited as `applied`, never as `unchanged`. An
`unchanged` response carries the activation id its request announced and names
the active ledger row separately as `activeActivationId`. Operator
references are stored and audited only as activation-scoped keyed hashes;
backup references are bounded. A new digest becomes served only
after restart (MESSAGING-DEC-06). `/ready` rechecks the active database
identity, package digest, schema, effective role grants, and writer health; a
running process stops being ready when any of those boundaries changes.

Editable projects remain separate from installed packages. Repackage and
explicitly apply a new digest before restarting. Accepted messages keep their
rendered payload, provider idempotency capability, and dispatch state. This
unreleased transition changes package identity and audit schema; it does not
authorize erasing an existing database or journal. A retained deployment needs
an explicit migration before adopting this schema. ConfigMap-style symlink
mounts remain refused; copy the installed package into place instead
(MESSAGING-DEC-24).

Tests: `config.rs::runtime_package_digest_pin_names_the_found_digest`,
the `package.rs` loader tests, and the PostgreSQL activation and package suites.

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
the callback routes by their templates. The rest of the set is closed the
same way: `messaging_provider_attempts_total` by attempt outcome (`accepted`,
`transient`, `permanent`, `maybe-sent`), `messaging_limit_refusals_total` by
limit (`rate`, `daily`, `pacing`, `callback`), `messaging_retention_runs_total` by sweep
outcome (`erased`, `idle`, `failed`), and the `messaging_dispatch_jobs` gauge
by state (`pending`, `leased`, `unknown`). No provider, sender profile,
access profile, or template becomes a label, so a series never tells which
caller or which recipient population is active.

The gauge is read from the store on each scrape, one read-only transaction
of three counts over partial indexes, bounded by a two-second statement
timeout (MESSAGING-DEC-25). A reader of the metrics listener can therefore
cause at most one such read per scrape; the listener is private, and a store
that cannot answer leaves the gauge without samples rather than reporting an
empty queue.

Tests: `http.rs::the_metrics_listener_serves_counters_and_nothing_else`,
`metrics.rs::labels_are_closed`,
`metrics.rs::every_attempt_limit_and_retention_outcome_is_exposed_from_zero`,
`metrics.rs::the_dispatch_queue_is_exposed_only_when_it_was_sampled`,
`postgres_dispatch.rs::the_metrics_sample_the_queue_and_count_attempts_by_outcome`,
the `config.rs` listener tests, and the PostgreSQL suite's served runtime,
which checks `/metrics` is absent from the public listener.

## Audit

The shared `AuditWriter` emits minimized request and response envelopes to a
per-process JSON Lines stream. File acceptance includes fsync; stdout is
best-effort. The hash key still derives the same caller and recipient
references. It no longer chains or signs log entries, and it scopes no
idempotency key: rotating it changes pseudonyms only (MESSAGING-DEC-17).
Tamper evidence, aggregation, and complete retention outside local
`retentionDays` are deployment responsibilities.

A fresh invocation correlation joins request and response. A caller's reusable
Idempotency-Key is not that correlation. The writer must accept the request
before a protected mutation, provider effect, or template render. Response
records that announce committed state follow proof of that commit, and required
response acceptance precedes returning success or rendered bytes. A failure
after commit cannot undo the effect: the caller receives unavailable and must
recover authoritative state through the operation's existing retry contract.
Same-key submission replay returns the original stored receipt after recovery.

Audit and PostgreSQL are separate systems. An accepted request can remain
unmatched after process or destination loss. Dropping a live `AuditRequest`
records an unfinished outcome while its process and writer survive. A COMMIT
error must not be reported as rollback without proof; bounded readback
separates committed, rolled-back, and unknown fate. Claim COMMIT errors do not
immediately send, including when readback finds a lease. Owned dispatch work
survives caller cancellation and captures caller/operator context before
spawning. Attempts, provider-reference locks, job transitions, and receipts
remain transactional domain state.

The runtime opens its writer before serving, and `/ready` includes the
writer's sticky health. Failure requires restart. Applied operator commands
use a separate `messagingctl` stream, or stderr when runtime audit uses stdout,
so machine-readable command stdout remains valid. There is no total order
across process streams and no audit outbox publisher or replay repair.

Records carry identifiers, bounded classes, caller pseudonyms, and keyed
recipient references. They never carry contacts, rendered parts, template
data, credentials, or provider message references (MESSAGING-DEC-14).
Authentication or access-profile refusals remain unaudited. Duplicate or
no-op callbacks remain unaudited, and retention's existing empty-runtime and
operator-preview policy remains unchanged.

Reads are not journaled: the status route and `messagingctl messages list`
and `show` leave no record (MESSAGING-DEC-15). Scheduling's appointment read
and Casework's review request and task reads are not journaled either;
Casework journals only its accountability read, which releases a raw
reviewer identity. A message view releases no contact, part, or data, so it
is an ordinary read.

## Data minimization and log and audit absence

MESSAGING-SEC-08. Audit records carry the operation, caller pseudonym, sender
profile, template reference, correlation, outcome class, and a keyed recipient
reference, never a body, template data, or a raw contact. Log fields never
carry a payload value, and every metric label is a closed set fixed in code.
`MESSAGING_LOG` accepts only `error`, `warn`, or `info`, so no dependency's
debug logging can be switched on by the environment.

The absence is the control, so it is proven by looking. Each suite checks the
records and log lines its own operations write, and one journey
(`postgres_callbacks.rs`,
`a_full_journey_leaves_no_payload_value_in_the_journal_log_or_metrics`) runs
every audited operation in turn: a preview, an acceptance, a replay, a
refusal, a delivered send, a dead-lettered send, a forged and a signed
callback, a status read, an interrupted send an operator settles, an
operator's retry, a caller's cancellation, and a retention sweep. It then
searches the journal, the captured operational log, and the metrics scrape for the recipient, the rendered and template values, the
principal, and the credentials, finds none, finds no provider reference in audit, and checks the emitted
request/response envelopes. The journey does not repeat the runtime start and quarantine records:
`postgres_migrate.rs` proves the start record carries no database URL or audit
secret, and the dispatch absence test in `postgres_dispatch.rs` covers
quarantines.

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
caller's verified issuer and subject, as in Scheduling and Casework, so a
caller cannot probe another caller's keys, and the same subject under
another issuer is another caller (MESSAGING-DEC-17). The scope does not
depend on the audit hash key: rotating `audit.hashKeyRef` changes the
pseudonyms the journal writes and frees no spent key, so an exact retry
across a rotation replays its receipt or is refused as expired and never
sends again.
The request hash covers the canonical request body: the same key with
another body is `409 idempotency.key-reused` whatever the key's age, as in
Base Registry Engine, Scheduling, and Casework, and the same body under a
key older than `retention.submissionReceiptRetentionDays` is
`410 idempotency.expired`. A replay is
authorized and rendered again against the active package before the stored
receipt is answered, so a key cannot outlive the caller's authority
(MESSAGING-DEC-07). The consequence for a caller is that an exact retry
refused with 403 or 422 after a package or profile change proves nothing
about the first attempt, which may have been accepted and may be sending; an
operator drains senders before activating a package that narrows what they
may send. One transaction records the key, the message, its
payload, its dispatch job, and the acceptance audit; concurrent submissions
under one key produce exactly one message, which the `postgres_messages`
suite proves.

Review note, data minimization (security-sensitive, accepted 2026-10-06,
revised 2026-10-07). A spent key is recorded and found under
`key_reference`, an unkeyed SHA-256 digest over the fixed domain
`registry-messaging-idempotency-key-v1` and the length-prefixed issuer,
subject, operation, and key. The row also holds the caller's raw issuer and
subject and the raw key, and only while its submission receipt does: when
retention erases the receipt after `submissionReceiptRetentionDays`, whether
the runtime sweep or `messagingctl retention erase-expired` runs it, the
same statement clears all three, and the record deletion after
`recordRetentionDays` clears them too if they remain (MESSAGING-SEC-11). A
schema constraint holds the pair: a row whose receipt is erased holds none
of the three, and a row whose receipt stands holds all three. The digest row
then stays indefinitely with the operation and its times, and the message
and request hash until `recordRetentionDays`, so the key stays spent for
that caller alone: the same caller's exact retry is
`410 idempotency.expired`, a changed one is `409 idempotency.key-reused`
while the request hash stays and `410` once the record deletion clears it,
and neither sends anything; another caller's identical key is fresh, and an
audit key rotation frees nothing, since the digest takes no key. The issuer
and subject name the authenticated caller, not a recipient, and that caller
is not always a service: an access profile may admit a human or agent actor,
or read the principal from a claim other than `sub`, so under such a profile
the raw subject may identify a person, such as a staff member's email
address. The raw values are accepted for at most
`submissionReceiptRetentionDays`, a period no longer than the one the
message row already holds the issuer and subject for
(`recordRetentionDays`). The residual is the digest itself: it is not keyed,
because a keyed digest would let a key rotation free every spent key, the
duplicate-send failure the pseudonym scope had before schema version 3.
Anyone who reads the table and can guess a caller's issuer, subject, and key
can therefore confirm that the caller spent that key. A random key makes the
guess impractical, and the API reference tells callers to choose one; a
short or predictable key does not. The audit journal and the rate limiter
keep the pseudonym. Schema version 3 discarded every idempotency record
written under the pseudonym scope, request hashes and receipts included, so
no pseudonym-keyed row survives the upgrade and every key spent before it is
free again (`postgres_migrate.rs`,
`version_3_discards_pseudonym_scoped_records_and_the_runtime_scopes_keys_to_the_caller`).

Tests: MESSAGING-SEC-01, -02, and -11 in
`contracts/security-test-traceability.yaml`.

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
and a restart refills it. `maximumMessagesPerDay` is counted over the profile's
accepted messages of the last 24 hours inside the acceptance transaction,
under a transaction advisory lock of the profile, so concurrent submissions
cannot both take the last place and the count survives a restart and holds
across replicas; past it the answer is `429 quota.exceeded` with
`Retry-After` (MESSAGING-DEC-21). A replay is charged to the rate, not to
the daily count. A refusal is journaled like every refused submission, as
`messaging.message.refused` with its problem code.

A provider's `capabilities.ratePerSecond` paces the worker in-process: a
leased attempt waits for one of the connection's `maximumConcurrentRequests`
sends in flight, holds it through the send, and then waits for the
provider's next send slot, so the rate holds for requests as they leave. The
wait has a ten-second allowance added to its time budget and never outlasts
the message's `expiresAt`; an attempt whose slot does not open in it is
transient and nothing is sent, and no attempt reaches the provider once the
message has expired (MESSAGING-DEC-22).

Residual risk: a caller that keeps sending past its rate still makes the
runtime authenticate each request and write one journal record for it. The
request edge's body limit bounds each request, but no limit bounds the
journal growth of a refused flood; an operator relies on the deployment's
edge proxy for that.

Tests: `limits.rs` (`a_caller_is_refused_past_its_profile_burst_with_the_wait_needed`,
`callers_and_profiles_have_separate_budgets`,
`an_unknown_profile_or_an_unusable_key_is_refused_as_unavailable`,
`a_provider_starts_one_send_per_interval`,
`an_attempt_takes_its_turn_only_once_it_holds_an_in_flight_slot`), `http.rs`
`a_caller_past_its_profile_rate_is_refused_with_the_wait_needed`, and the
PostgreSQL suites' `a_profile_past_its_daily_limit_is_refused_across_a_restart`,
`concurrent_submissions_never_take_more_than_the_daily_limit`,
`a_paced_provider_starts_one_send_per_interval`,
`a_paced_provider_below_the_worker_concurrency_still_sends_one_per_interval`,
and `a_message_that_expires_before_its_pacing_slot_expires_unsent`.

## Dispatch

Threat: a worker that lost its lease overwrites the outcome another worker
recorded, a send that may have reached the provider is sent again and the
recipient gets it twice, or a cancel races a send.

MESSAGING-SEC-05, enforced. The worker runs on
`registry-platform-dispatch`: a claim takes a lease, and every outcome write
names the lease and the generation, so a stale worker's write is refused
and changes nothing. An operator requeue starts a new generation.

MESSAGING-SEC-06, enforced. A transport must finish within the attempt's
budget and classifies its own deadline, since only it knows whether the
request was written. The worker stops waiting one second after the budget is
spent and records a transport that overran it as maybe sent
(MESSAGING-DEC-10). A maybe-sent attempt, or a lease that lapsed
mid-attempt, stops the message as `unknown` unless the sender profile set
`onUncertain: retry`, which the package accepts only over a provider that
declares `idempotentSubmit` or a profile that sets `acceptDuplicates`. A
retry then carries the same provider idempotency key, derived from the
message, its generation, and a digest of its content (MESSAGING-DEC-11).
Because an operator requeue starts a new generation and so a new key, a
retrying message whose attempts are spent, whose next retry would land past
its expiry, or whose expiry passes while that retry waits, after an attempt
that may have reached the provider stops `unknown`, never failed or expired;
this holds whether the last attempt answered maybe-sent, failed transiently,
or was refused permanently, since a later failure does not prove the earlier
attempt did not land. So does such a row the worker quarantines, and a leased
row it quarantines.
The expiry sweep and the claim decide this under the row lock they already
hold. A message never attempted, or one whose attempts all ended transient,
still expires unsent.
The provider capability is persisted with the accepted message, so removing
`idempotentSubmit` from a later package does not withdraw that key from a
previously accepted retry.
Each provider kind decides whether a failure happened after the message
left: an `smtp` drop, timeout, or unreadable reply once the end-of-data
marker was written, and an `http` failure after the request was written,
is maybe-sent; a failure before either, a stalled resolution, connection,
TLS handshake, token fetch, or wait for a send slot included, is not sent
and transient. An `smtp` goodbye that fails after the relay accepted the
message leaves it accepted. Without an interpret script an `http` status
decides: `429` and `503` are transient, and `408` and every other `5xx`
answer a request that was written and are maybe-sent.

A cancel takes the job row's lock, so it and a claim serialize: a message is
cancelled only while no attempt of its current generation may have reached
the provider, and otherwise refused `409 message.dispatch-started`
(MESSAGING-DEC-09), which the `postgres_messages` race test proves across
forty rounds. A message waiting to retry after attempts that all ended
transient still cancels; one waiting after an attempt that ended maybe-sent
or was interrupted by a lapsed lease is refused, and its retry keeps the
generation's idempotency key. A message whose provider has no transport, or whose payload
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
`operator-tool` request and established outcome to its separate stream
(MESSAGING-DEC-13). A change whose commit cannot be confirmed is reported
`message.outcome-unknown`, and one committed whose outcome record fails
`audit.unconfirmed`; neither is reported as a refusal that changed nothing.
`cancel` previews and applies the dispatcher's own rule (MESSAGING-DEC-09): a
queued message an attempt of whose current generation may have reached its
provider is refused with `message.dispatch-started`, as the HTTP API refuses
it, in the preview and on `--apply` alike. `list` and
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
`maximumResponseBytes`, and receipt the callback's method and those of its
form, query, and JSON body the callback verifier authenticates. Every script runs with a fresh scope, an operation budget, the
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
`development-loopback`, which only a test build or a runtime behind a
`development-loopback` listener accepts.

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
  network. A build carrying a test feature (`postgres-test` or
  `smtp-test`) accepts it; any other build accepts it only when the
  runtime's own `listener.tlsTermination` is `development-loopback`, which
  already binds only to loopback, and refuses it behind an
  `operator-controlled-upstream` listener at `messagingctl check` and at
  startup (MESSAGING-DEC-26). A production runtime therefore cannot be
  pointed at a plaintext relay without also giving up its production
  listener posture, and `messagingctl dev` can run a release build of the
  runtime against a local Mailpit.

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
when the acceptance-time package declared `idempotentSubmit` for the
provider. That declaration is stored with the message. Channel,
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
journal; a provider repeating itself grows the store without bound; a flood
of unauthenticated callbacks spends verification, receipt-script, and store
work without bound (MESSAGING-SEC-07, enforced).

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
last path segment). `none` is not a kind. Tags and tokens are compared in
constant time by the `registry-platform-crypto` MAC helpers. The secret or
token is a `secret:` reference resolved once at startup. A path token must
resolve to UTF-8 of at most 1024 bytes, matching the route verifier's bound;
an unusable token refuses activation without revealing its value.

An unknown provider, a provider without a verifier, a missing or wrong
signature or token, a token segment on a provider whose verifier is not
`path-token`, and a missing segment on one whose verifier is all answer
`403 callback.unverified` alike, so the route reveals neither which
providers receive callbacks nor why a request was refused. It is 403 rather
than 401 because there is no challenge scheme a provider could answer. The
refusal is logged with the provider id only when the provider is configured,
and with a value-free reason. Rate admission precedes body buffering;
verification may read the bounded raw bytes for HMAC, but the receipt script
and store are reached only after verification.

Before its body is buffered or it is verified, a callback is charged to a token bucket of 6000 a
minute with a burst of 600, held in the runtime process (MESSAGING-DEC-28).
Each provider with a verifier has its own bucket, keyed by its configured
id; every other path shares one bucket of the same size, so a refusal, like
`403 callback.unverified`, does not tell which providers receive callbacks.
Past the burst the callback answers `429 rate-limit.exceeded` with
`Retry-After`, is counted in
`messaging_limit_refusals_total{limit="callback"}` rather than by outcome, and
is not logged, so a flood cannot flood the log either; a limiter that cannot
decide answers `503 service.unavailable`. The rate is fixed, not configured.

A verified callback is read by the package's `receiptScript` on the blocking
pool, under the same bounded Rhai engine and budget as `interpret`. The
script reads only what the verifier authenticated: under `hmac-sha256-body`
the form fields and JSON read from the body and an empty query; under
`hmac-sha1-url-form` the query and form fields and no JSON; under
`path-token` all three, since the secret path authenticates the request. A script
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
a request before the mutation and `messaging.receipt.recorded` after its
commit is established, carrying
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
nothing, journals nothing, and is counted as `unmatched` or `ambiguous`.
Reference assignment and receipt lookup take the same transaction advisory
lock, keyed by provider and reference, before either can commit a decision;
a concurrently assigned duplicate reference is therefore checked as
ambiguous. Hash collisions only serialize unrelated references. A
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
weakness does not apply. The callback rate is charged before verification,
so anyone who knows a provider's id can spend that provider's budget and
delay its genuine callbacks, which the provider then retries; the separate
buckets keep such a flood from delaying another provider, and the budget is
per process, so it does not add up across replicas. A provider reporting
faster than 100 callbacks a second is refused in bursts until the rate is
made configurable.

Tests: MESSAGING-SEC-07 in `contracts/security-test-traceability.yaml`: the
PostgreSQL suite `tests/postgres_callbacks.rs` (each verifier kind valid and
forged, duplicate and out-of-order receipts, a final report kept, the
history bound, unknown, foreign, and ambiguous references, unreadable and
ignored callbacks, and the absence of the reference, secrets, and token from
logs and the journal), the route tests in `http.rs` (the callback rate
refusing before verification among them), the callback budget test in
`limits.rs`, and the verifier and report-order tests in
`registry-messaging-core`.

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

`retention.payloadRetentionDays` (1 to 30), `recordRetentionDays` (up to ten
years), and `submissionReceiptRetentionDays` (up to the record period) are
validated and recorded at start. The payload and record periods count from
the instant the message's dispatch job reached a terminal state,
`delivered`, `dead-lettered`, `expired`, or `cancelled`, which the job row
already holds (MESSAGING-DEC-16). A `pending`, `leased`, or `unknown`
message is never erased, whatever its age. A submission's `expiresAt` stays
capped at acceptance plus `payloadRetentionDays`. Past
`payloadRetentionDays` the recipient and the rendered parts are nulled and
the content-free record stays; past `recordRetentionDays` the record is
deleted with its payload, job, attempts, and delivery receipts; its
idempotency row stays with the message, the request hash, any stored
receipt, and the raw issuer, subject, and key nulled, holding only their
digest and its times, so a repeat, exact or changed, is still
`410 idempotency.expired` (MESSAGING-DEC-17), whatever audit hash key the
runtime holds then. Past `submissionReceiptRetentionDays` the stored receipt
is dropped together with the raw issuer, subject, and key, the request hash
stays, and the same caller's exact repeat of its key is
`410 idempotency.expired` and a changed one `409 idempotency.key-reused`
(MESSAGING-SEC-11).

An applied run erases in batches of at most 1,000 of each kind, oldest
first, and ends at the first batch shorter than that. Each batch is one
transaction under a transaction advisory lock, with a five-second lock
timeout and a sixty-second statement timeout; a batch that exceeds either is
rolled back whole, and the batches committed before it stay erased and
journaled. A preview is one transaction that counts everything due. Each due terminal job is locked
`FOR UPDATE` before its payload is erased, and the predicate is read again
under the lock, so an operator requeue that commits first keeps the payload,
and one that comes after fails as `payload-erased` without a send
(MESSAGING-DEC-12). The runtime runs retention at start and hourly under its
own credential with the database's clock as the cutoff
(MESSAGING-DEC-18); on shutdown its sweep ends after the batch in progress
commits, and the next start erases what is left. `messagingctl retention erase-expired --before` runs it
under the migration credential, previews unless `--apply` is given, and
refuses a cutoff later than the local clock before any input or output and
later than the database's clock inside the run (MESSAGING-DEC-19). Each batch
accepts request audit before erasure and records `messaging.retention.erased`
after its commit is established,
carrying the cutoff, the batch's three counts, the periods in force, and its actor
(`runtime` or `operator-tool`), never an identifier of what it erased. The
runtime's sweep writes it only for a batch that erased something; an applied
operator run always writes it for its first batch; a preview writes nothing.
A batch whose commit cannot be confirmed is reported as an unknown outcome,
and one whose outcome record fails after the commit as `audit.unconfirmed`,
never as a failure that erased nothing.

Residual risk: a batch whose single statement exceeds the statement timeout
erases nothing, so a backlog stalls only when one batch of 1,000 cannot
complete in sixty seconds. Audit segment retention is independent of
payload and record erasure; off-host shipping must precede local expiry.

Tests: MESSAGING-SEC-10 and -11 in `contracts/security-test-traceability.yaml`.

## Development session (MESSAGING-DEC-27)

Threat: a local development session leaves a credential, a rendered payload,
or a recipient behind, exposes a service beyond the machine, or teaches a
posture that reaches production.

`messagingctl dev` publishes PostgreSQL and Mailpit on 127.0.0.1 only and
runs the runtime on a `development-loopback` listener, which is refused on
any non-loopback bind. Every secret the session generates, the database
passwords, the audit key, the gateway token and callback key, and the token
signing key, is written owner-only (files 0600 under 0700 directories,
single link, never through a symbolic link) in the project's
`.messaging/dev`, which `.messaging/.gitignore` keeps out of version
control. No secret is placed on a command line: PostgreSQL's superuser
password reaches Docker through an owner-only `--env-file`, role passwords
reach `psql` on standard input, and a failed Docker command's error output is
repeated with the password removed. The database serves TLS with a
certificate signed by a session-generated authority, refuses every
non-TLS host connection, and checks passwords with SCRAM; the runtime
connects with the least-privilege runtime role and migrates with the
migration role, as in production.

A session token is signed with the session's own ES256 key, carries the
scopes and actor kind of the one access profile that names its client, and
expires in an hour; the runtime verifies it against the session's static key
set, so the key never leaves the session directory and no issuer runs. The
mock gateway compares the static bearer token in constant time, signs each
delivery report with the session's HMAC key, reads no field of a send, and
logs nothing a send carries. Stopping the session removes both containers
with their volumes; the next start in the project removes any container the
previous record names before it replaces the session directory, and a second
start is refused while one runs.

Residual risk: the audit journal and log of the last session stay in
`.messaging/dev` until the next start. Neither carries a payload value
(MESSAGING-SEC-08). A session killed with SIGKILL leaves its containers
running until the next start in the same project removes them.

Tests: the `dev` unit tests in `crates/registry-messagingctl/src/dev/`, and
`products/messaging/scripts/test-dev.sh`.

## AWS SMS request signing

The AWS End User Messaging provider uses the shared HTTP destination's typed
AWS JSON signing template. Operator configuration binds the endpoint, region,
service, and explicit secret references; the reviewed provider package shapes
the action and JSON body. The transport retains destination confinement,
DNS/address admission, no redirects, and one deadline. Signing occurs on the
final root POST bytes, with JSON 1.0 content type, action, host, timestamp,
payload digest, and optional session token covered by SigV4. Scripts cannot
supply authorization or signing headers, and never receive signing keys.
Secret owners and signature derivation buffers are zeroizing; diagnostic
objects redact credentials. No environment/default SDK credential chain or
metadata-service lookup is introduced.

The SMS adapter does not declare provider submission idempotency or delivery
receipts. Ambiguous send failures and malformed successful replies remain
maybe-sent and follow the existing hold policy. Local fixture tests establish
request/response compatibility, not a live AWS or carrier delivery claim.
The required AWS IAM authority, origination registration, regional availability,
and external secret rotation remain operator responsibilities. Temporary
credentials are loaded at activation and require replacement plus restart
before expiry. This does not relax the caller's Messaging access profile.

### PostgreSQL support floor

Activation and startup require PostgreSQL 17 or newer. The shared activation
boundary checks the server version before observing migration or activation
relations, including an empty database. Older servers refuse with an upgrade
instruction before migrations or activation writes. The shared
`postgres_version_floor_precedes_missing_ledger_observation` database test
covers that entry point; unit tests pin the 16/17 version boundary.
