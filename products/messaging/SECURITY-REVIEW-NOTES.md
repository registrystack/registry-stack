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
database and metrics settings is redacted. A pinned `package.expectedDigest`
is refused until the package ledger can verify it (MESSAGING-DEC-06).

Tests: the `config.rs` and `environment.rs` unit tests, and the checkpoint's
`messagingctl check` refusal cases.

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
by `audit.hashKeyRef`. In this version it records one event, the runtime
start, carrying the runtime version and the retention periods in force; it
names no principal, contact, or secret. Listeners bind before the start
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

## Templates (pending, slice S2)

MESSAGING-SEC-09: a template engine with no loader beyond the package, no
file or network functions, fuel, and an output ceiling.

## Retention (pending, slice S6)

MESSAGING-SEC-10. The `retention` bounds are validated and recorded at start
today: payloads 1 to 30 days, records up to ten years, receipts up to the
record period. The sweep that enforces them, and refuses to erase a message
still sending or in an unknown outcome, lands with slice S6.
