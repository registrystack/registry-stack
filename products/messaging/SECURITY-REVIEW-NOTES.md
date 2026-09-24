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

- Submission (MESSAGING-SEC-01, partial): `authorize_submission` admits only
  a sender profile whose `senderProfiles` and `templates` list the request's
  choices, and direct content only where `allowDirectContent` is set.
  Operators never submit (MESSAGING-DEC-04). The decision is tested in the
  core; the submission route that calls it is pending until slice S3.
- Visibility (MESSAGING-SEC-04, partial): `check_message_visibility` shows a
  message to its submitting profile and to operator profiles only, and a
  missing message answers exactly like an invisible one, `404
  message.not-visible` (MESSAGING-DEC-01). The status route applies it today;
  since no message store exists yet, every authenticated read answers
  not-visible. The route-level test with a second sender reading and
  cancelling a real message is pending until slice S3.

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
by `audit.hashKeyRef`. In this version it records two events. The runtime
start carries the runtime version, the package digest, and the retention
periods in force. A template preview carries the access profile, a keyed
pseudonym of the verified issuer and subject, the package digest, the
template reference when the package ships it, and the outcome with its
problem code; never the data, the rendered parts, or the raw subject. A
preview the journal cannot record is answered `503 service.unavailable`, not
rendered. An unauthenticated or unprofiled request is not journaled, as for
every route (MESSAGING-DEC-02). Listeners bind before the start
record is written, so a taken address never leaves a start record for a
runtime that did not serve.

## Data minimization and log and audit absence (pending, slice S6)

MESSAGING-SEC-08. Once messages exist, audit records carry the operation,
caller pseudonym, sender profile, template reference, correlation, outcome
class, and a keyed recipient reference, never a body, template data, or a raw
contact. The full-journey absence test lands with slice S6. `MESSAGING_LOG`
accepts only `error`, `warn`, or `info`, so no dependency's debug logging can
be switched on by the environment.

## Egress (pending, slice S3)

MESSAGING-SEC-02, -03, -05, and -06: a closed submission schema, provider
egress through the platform fixed-destination substrate pinned after DNS, the
lease fence on outcome writes, and no retry of a maybe-sent attempt unless the
sender profile opts in. None of this exists yet; the matrix names each test
the slice owes.

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
