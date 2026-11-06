# Scheduling security model

This page says what Scheduling's security controls guarantee, what they do
not, and what an operator must do for the guarantees to hold. The invariants
themselves (threat, enforcement point, refusal and test) are in
[`contracts/security-invariant-matrix.yaml`](contracts/security-invariant-matrix.yaml)
and are checked by `scripts/validate_contracts.py`. This page does not copy
them. Configuration members are described in [`RUNTIME-CONFIG.md`](RUNTIME-CONFIG.md)
and task-grant handling in [`TASK_GRANTS.md`](TASK_GRANTS.md).

## 1. Scope and trust boundaries

Scheduling commits capacity (holds, appointments, windows) inside PostgreSQL
transactions, for callers holding bearer tokens from a configured issuer.

- **Callers** are untrusted until the token verifies against the configured key
  source and carries a complete scheduling task grant (service, location, actions).
  A partial grant is refused, never honoured partially
  (SCHEDULING-SEC-04, SCHEDULING-SEC-05).
- **The issuer and task-grant authorities** are trusted to say who a caller is
  and whether a grant is still live. A declared issuer or key address is
  trusted on the operator's word, and with `allowInsecureHttp: true` an
  attacker on the network path to the issuer can substitute keys
  (SCHEDULING-RES-10). Scheduling checks a grant's status with
  its authority before every capacity commitment and every receipt replay when
  `taskGrantStatus` lists authorities (SCHEDULING-SEC-03).
- **The migration credential holder** is trusted to activate a package. The
  activation ledger records that an apply happened, which package, and under
  which role mode. It is not a signed approval (SCHEDULING-SEC-29 to
  SCHEDULING-SEC-32).
- **The runtime database credential** is trusted to serve, not to change
  activation state. In split role mode `apply` revokes ledger writes from it;
  in single role mode that separation does not hold, and `plan`, `apply` and
  `status` say so (SCHEDULING-SEC-30).
- **The database superuser and anyone who can read Scheduling tables** are
  outside the model. A table reader sees what the tables hold (see
  SCHEDULING-RES-04 and SCHEDULING-RES-05).
- **Host users who can write the audit destination** can alter audit history.
  Entries are not chained; tamper evidence belongs to the destination and the
  collection pipeline (SCHEDULING-SEC-14).
- **The clock.** The edge, the store and the workers read one store clock. The
  OIDC verifier and the grant expiry check at the door read the system clock.
  Hook delivery uses PostgreSQL `transaction_timestamp()`. The clock pin used in
  tests exists only in `postgres-test` builds (SCHEDULING-SEC-23).

Accountability: a commitment writes its audit `request` entry before its
transaction opens and its `response` entry after the transaction ends. If
either entry is refused, the caller gets `service.unavailable` instead of an
unaudited answer. A refused `request` entry opens no transaction; a refused
`response` entry after the commit answers `service.unavailable` with the
commitment in place. `/readyz` follows the audit writer.

## 2. Operator obligations

1. Run PostgreSQL 17 or newer. Activation and startup refuse older servers.
2. Reach PostgreSQL over TLS. The runtime requires it; `database.testOnlyPlaintext`
   is honoured only in `postgres-test` builds, and the shipped runtime refuses it
   with `scheduling.runtime.plaintext-database`.
3. Bind the listener to a loopback or private address, or declare
   `networkExposure: container-private`. Anything else refuses to start.
4. Terminate TLS in front of the runtime. Scheduling sets `Cache-Control:
   no-store`, security headers (without HSTS) and a 1 MiB body ceiling, and
   leaves TLS and HSTS to the deployer.
5. Use two database roles in production (migration and runtime) so the runtime
   cannot rewrite the activation ledger. Revoke any `TRIGGER` privilege the
   runtime role holds; `apply` refuses it and names the statement to run.
6. Put any second approver for a package in front of `schedulingctl apply`, in
   the pipeline that holds the migration credential. Nothing in Scheduling
   signs an activation.
7. Write `taskGrantStatus` explicitly. Omitting it is refused at startup. If you
   accept deferred grants, list at least one status authority (SCHEDULING-RES-02).
8. Grant `appointment.read` only to services whose workflow already selects the
   appointment (SCHEDULING-RES-01), and configure
   `authentication.oidc.appointmentReadProfiles` only for the cross-owner work
   lists you intend to expose (SCHEDULING-RES-03).
9. Send audit to storage that is append-only or otherwise tamper evident, and
   monitor it. Scheduling does not chain entries. Collect the `schedulingctl`
   sibling stream of `audit.path` too: `apply` and `records apply` write there,
   not into the runtime file. When a response entry is refused after an
   activation commits, `schedulingctl` exits 3 with
   `schedulingctl.activation.applied-unaudited`; the package is active, so
   restore the destination and confirm with `schedulingctl status`.
10. Set retention deliberately. The defaults (`retention.claimOwnerRetentionDays`
    of 7, `audit.retentionDays` of 90, `retention.receiptRetentionDays`) are placeholders,
    not a jurisdictional recommendation. See SCHEDULING-DEF-06.
11. Bound request rates at your ingress. Scheduling keeps no request budget of
    its own (SCHEDULING-RES-06).
12. Make your hook receivers tolerate duplicate events; delivery is
    at-least-once (SCHEDULING-RES-07).
13. Apply a new package to a new database when a refusal reports a pre-1.0
    schema. No release upgrades that state in place.
14. Use an HTTPS issuer and leave `authentication.oidc.allowInsecureHttp`
    unset. Declare only issuer and JWKS addresses you intend Scheduling to
    reach (SCHEDULING-RES-10).

## 3. Accepted residuals

### SCHEDULING-RES-01: a self-booked appointment is readable by id within the granted service and location

- **Condition.** The caller holds a current online `appointment.read` task
  grant for the appointment's service and location, and the appointment is
  self-booked (not source-managed).
- **Consequence.** The caller can read any appointment it names by id at that
  service and location. The grant does not bind an appointment id. For
  source-managed appointments the exact retained manager and source issuer are
  also required. The grant opens no list, history, catalogue or operational
  route.
- **Operator mitigation.** Issue the action only to services whose workflow
  already selects the appointment.
- **Related.** SCHEDULING-SEC-05, SCHEDULING-SEC-08, SCHEDULING-SEC-36.

### SCHEDULING-RES-02: the final fifteen minutes of a deferred grant are not revocation-checked

- **Condition.** The deployment writes `taskGrantStatus:
  unchecked-final-fifteen-minutes`. The signed token does not say whether the
  grant was issued in immediate or deferred mode.
- **Consequence.** A grant with 900 seconds or less remaining qualifies for the
  bounded offline path with no revocation check. Even with status checks, a
  withdrawal that follows a positive status answer can race the in-flight local
  commit; the interval is bounded by the short execution credential and by
  deadline re-checks after every lock wait and before commit.
- **Operator mitigation.** List at least one status authority. That disables
  the offline path for every grant, including sources not listed.
- **Related.** SCHEDULING-SEC-03.

### SCHEDULING-RES-03: operational profiles disclose cross-owner bookings by design

- **Condition.** The operator configures an `appointmentReadProfiles` entry.
- **Consequence.** Holders of that profile see other owners' bookings within the
  profile's service, location, resource set and time bounds. An explicit
  `unrestricted` resource scope covers every resource at that one service and
  location. Detail readers also receive the current attendance observation;
  operational readers receive it only if the profile selects attendance.
- **Operator mitigation.** Keep profiles narrow, and do not select attendance
  unless needed.
- **Related.** SCHEDULING-SEC-37, SCHEDULING-SEC-42.

### SCHEDULING-RES-04: the spent-key reference is an unkeyed digest kept indefinitely

- **Condition.** An idempotency attempt exists. Its reference is a digest of the
  caller scope and key.
- **Consequence.** Anyone who can read the table and already knows a caller's
  issuer, subject and exact key can confirm the attempt was made; guessable
  keys make that cheap. The row also keeps the command scope, request hash,
  outcome status and timestamps. The digest is not keyed with the audit key
  because rotating that key would free every spent key and allow double booking.
- **Operator mitigation.** Restrict database read access; have callers use
  unguessable keys. Receipt expiry clears the raw caller and key.
- **Related.** SCHEDULING-SEC-09, SCHEDULING-SEC-33.

### SCHEDULING-RES-05: the erased claim owner digest is pseudonymous, not anonymous

- **Condition.** The retention worker has cleared a claim's raw issuer and
  subject after `claimOwnerRetentionDays` (1 to 365, default 7).
- **Consequence.** A holder of candidate issuer and subject values and the claim
  UUID can test guesses against the stored digest. The keyed actor pseudonym
  remains in claim history and audit, whose retention is separate. Erasure
  needs a running runtime; the pass is idempotent. Once erased, the owner can no
  longer read, list or replay that claim's receipts, and receipt lookups answer
  `receipt.unresolved`, which does not prove no effect occurred.
- **Operator mitigation.** Choose the window with your records policy; keep
  the runtime running; treat history and audit retention as a separate decision.
- **Related.** SCHEDULING-SEC-34, SCHEDULING-DEF-06.

### SCHEDULING-RES-06: no request throttling

- **Condition.** An authenticated caller repeats a route, including receipt
  observation.
- **Consequence.** Each request costs one bounded indexed lookup and its audit
  records. Scheduling applies no read budget.
- **Operator mitigation.** Bound authenticated floods at the deployment ingress.
- **Related.** SCHEDULING-SEC-14.

### SCHEDULING-RES-07: hook delivery is at-least-once

- **Condition.** A send's response is lost, or a reminder's appointment is
  cancelled or moved while a dispatcher holds the reminder.
- **Consequence.** A destination that ignores the envelope `id` may see an event
  twice. A cancel or reschedule committed between the liveness check and the
  send can still send a stale reminder, and receivers get no ordering across
  processes. One worker serves each runtime process.
- **Operator mitigation.** Deduplicate on the envelope `id` and treat reminders
  as advisory.
- **Related.** SCHEDULING-SEC-24, SCHEDULING-SEC-38.

### SCHEDULING-RES-08: an open activation race fails closed with an availability cost

- **Condition.** An earlier runtime appends a delivery between the retained
  binding check and the activation locks, bound to a destination the new package
  rebinds. The check runs on its own connection before the locks, not inside the
  activation transaction.
- **Consequence.** `apply` does not see that delivery. No payload reaches the
  rebound destination: delivery re-checks each binding, and startup verifies
  retained bindings again and refuses to serve until the delivery drains or its
  binding is kept.
- **Operator mitigation.** Drain hook deliveries before applying a package that
  rebinds a destination; if startup refuses, wait for the delivery to drain or
  keep the binding.
- **Related.** SCHEDULING-SEC-29, SCHEDULING-SEC-32.

### SCHEDULING-RES-09: older input meets a less specific refusal

- **Condition.** Configuration or state from before the current baseline.
- **Consequence.** The usage error does not name `schedulingctl plan` and
  `apply`, and a corrupt-database refusal does not say to start from a new
  database. Schema versions below the version 200 baseline are refused as
  pre-1.0 and are not upgraded in place.
- **Operator mitigation.** Apply to a new database, as the release notes for
  the releases that made each break instruct.
- **Related.** SCHEDULING-SEC-29.

### SCHEDULING-RES-10: declared issuer and key endpoints are trusted

- **Condition.** The runtime file names an issuer or JWKS URI, or sets
  `authentication.oidc.allowInsecureHttp: true`.
- **Consequence.** A declared issuer or JWKS URI may name any private address
  that is not cloud metadata or link-local; the operator who writes the file is
  trusted to name it. A discovered key endpoint on another origin stays under
  the strict public-network policy and must use HTTPS, and redirects are
  disabled. Under `allowInsecureHttp: true`, an attacker on the network path to
  the issuer can substitute keys and so mint tokens Scheduling accepts. Startup
  logs a fixed warning when the setting is on.
- **Operator mitigation.** Use an HTTPS issuer; leave `allowInsecureHttp`
  unset; or pin keys with a static `jwksSource`.
- **Related.** SCHEDULING-SEC-04, SCHEDULING-SEC-16.

## 4. Deferrals

These are the matrix `deferred` rows. A change that closes one promotes the
matrix row and rewrites its section here.

### SCHEDULING-DEF-04: the channel is not bound to the verified caller

The channel that selects a window subquota is asserted by the caller and
persisted verbatim. It is not derived from the verified client or the grant, so
a caller entitled to book may choose which subquota it draws from. The policy
declares a closed channel set, an undeclared channel is refused with a typed
code, and every subquota is a ceiling inside the one published total, so a
mis-chosen channel cannot oversell the window. Binding the channel to the
verified client is a product decision not yet taken.

### SCHEDULING-DEF-05: no database backstop under the duplicate-key guard

The duplicate guard reads active bookings across the offering inside the same
capacity transaction as the claim it protects. The supporting index is partial
and not unique, so the guard rests on the transaction and not on a database
constraint. The offering's supply lock serializes the guard and the claim, so a
concurrent pair cannot straddle it, even when their intervals lie under
different published opening revisions.

### SCHEDULING-DEF-06: retention of committed scheduling data

Retention windows for committed claims, history and actionable or uncertain
outbox rows are a product question not yet answered. Idempotency receipts expire
and tombstone, clearing the raw caller and key (SCHEDULING-SEC-33). The claim
owner's raw issuer and subject expire under `claimOwnerRetentionDays`
(SCHEDULING-SEC-34). Delivered outbox intents of every purpose, reminders
cancelled before any attempt or set aside as superseded, and terminal hook
metadata are removed on `receiptRetentionDays` in bounded transactions
(256 rows per table family), preserving replay through payload expiry. Pending,
leased, retryable and uncertain work remains. Rotated audit files are removed
after `audit.retentionDays`. [`RUNTIME-CONFIG.md`](RUNTIME-CONFIG.md) states what
each sweep covers.

## 5. Development tooling

`schedulingctl api` and saved connections are diagnostics, not Scheduling
authority. Scheduling keeps no local caller session, so the command does not
resolve `--client`. A saved connection authenticates anonymously, with a
referenced bearer, or with a renewable `private_key_jwt` client under the
[`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary),
which owns endpoint confinement, credential precedence, redirects, proxies and
bounds. The runtime authenticates and authorizes every protected request
regardless of the connection label.

## 6. Reporting

Report vulnerabilities as described in [`SECURITY.md`](../../SECURITY.md).
