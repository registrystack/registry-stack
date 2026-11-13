# BReg security model

This page states what BReg's security invariants assume, what an operator must
do for them to hold, and which limits are accepted. The invariants themselves
(threat, enforcement point, refusal, and negative test) are in the
machine-checked [security invariant matrix](contracts/security-invariant-matrix.yaml)
and its [test traceability](contracts/security-test-traceability.yaml). This
page does not repeat those rows; it links them by ID (`BREG-SEC-NN`).

## 1. Scope and trust boundaries

BReg is trusted to keep a registry's records inside the row boundary of the
caller's access profile, to refuse rather than guess, and to leave an audit
trace of what it released. It is not trusted to defend against the parties
below, who hold more authority than the product can take back.

| Party | Trusted for | Not defended against |
|---|---|---|
| Holder of the migration credential | Applying a reviewed package and running operator commands (`bregctl apply`, `adopt`, `hook discard`, erasure). | Applying any valid successor of the active package. Packages are unsigned (BREG-SEC-02). |
| Holder of the runtime credential | Serving reads and writes through the generated row-level security policies. | In split-role mode, nothing beyond what the grants allow (BREG-SEC-04, BREG-SEC-118, BREG-SEC-119). In single-role mode, rewriting the activation ledger. |
| Database superuser | Nothing is withheld from a superuser. | Editing the ledger, the instance claim, or any row. The activation audit stream is the independent trace. |
| Operator who writes the runtime file | Naming the issuer, JWKS source, listeners, secret references, and destinations. | Naming a private-network issuer or an HTTP issuer when `allowInsecureHttp` is set. |
| Token issuer | Authenticating callers and signing the claims the access profiles map to authority. | An issuer that signs wrong claims. BReg verifies signature, issuer, audience, and lifetime; it does not second-guess the claims. |
| Review, evidence, and function providers | Their own decisions, within the exact bindings BReg freezes. | A provider that decides wrongly. BReg binds the result to the frozen request but does not judge it (BREG-SEC-34). |
| Host users who can write audit files | Nothing. | Rewriting or removing lines of a local audit file. Ship the stream to append-only storage (section 2). |
| Package authors | Authoring the project under review. | A reviewed package that is wrong. Deployment-only values (environment, instance, database) are refused in a package, so the same bytes are promoted unchanged (BREG-SEC-01). |

Supply chain posture: packages are verified by the SHA-256 of `SHA256SUMS`,
with every listed file re-hashed before the digest is trusted. No signature or
trust anchor is consulted. The Wasmtime build that runs WASM hook handlers is
pinned and built without its default features. No automated check pins that
feature set, so a change that unifies a default feature back on is not caught
by CI.

**Applicant review progress.** A current caller-owned status grant can opt in
to a provider-authored code (BREG-SEC-208). BReg authorizes and audits the read
before using the configured Review producer credential for a single bounded
lookup. It compares the whole accepted review binding, then rechecks Proposal
visibility and the live review round before the response audit and release.
Failure to observe the exact round yields the authorized local status with
progress omitted. A code is display data. It grants no approval or application
authority.

Read-boundary rationale. Row-level security on the entity tables is the single
read boundary, and `FORCE ROW LEVEL SECURITY` is on for every one. Entity
source views are created `security_invoker=true` and deliberately without
`security_barrier`, so a list page can be served from an index. That does not
let a row the caller cannot read reach a predicate: PostgreSQL applies a
table's policies as security conditions before any predicate that is not
leakproof, whether or not a view above the table is a barrier, and every read
policy carries `record_lifecycle = 'active'` itself. The runtime also sends
only SQL the engine generates (BREG-SEC-143). An executed proof reads the view
through a non-leakproof predicate that raises on a hidden record and shows it
is never shown one. The view options are part of the managed schema
fingerprint, so a database that regains `security_barrier` or loses
`security_invoker` is drift and startup refuses it. Derived views and the
spatial candidate view keep their barrier. See BREG-RES-16 for what remains.

## 2. Operator obligations

For the invariants to hold, a deployment must do the following.

1. **Run split database roles in production.** `bregctl init` writes a split
   runtime file. Startup refuses a runtime role that is a superuser, has
   `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, or database `CREATE`, owns any
   registry object, is a member of the migration role, or holds a write
   privilege on a registry schema. A write privilege, ownership, superuser, or
   migration-role membership is answered with a pointer to
   `bregctl apply --package DIR`, which names the object and the fix. The other
   refusals (`BYPASSRLS`, `CREATEDB`, `CREATEROLE`, database or schema
   `CREATE`) answer only that the database is not ready for this package, so
   check those role attributes first when startup refuses. Single-role mode
   (used by `bregctl dev` and the quickstarts) catches mistakes, not a holder
   of the credential (BREG-RES-02).
2. **Ship audit to append-only storage.** The audit stream is not
   tamper-evident on the host. Ship the `file` or `stdout` stream, including
   the activation audit stream, to storage the host users cannot rewrite.
   BReg's retention is the platform audit writer's rotation and
   `retentionDays`; BReg adds no prune or export of its own.
3. **Treat a restore as a security event.** A restore rewinds every row,
   including erasures, deliveries, and closed import authorities. After a
   physical restore, run `bregctl instance-claim adopt` before the copy
   serves, and fence the original first. After any restore, re-run the
   erasures and discards done since the backup, reopen only the import
   authorities you still need, and resume held timers with an audited
   timer-operator resume. A logical restore is refused at startup until
   adopted. `adopt --acknowledge-original-retired` raises the claim epoch,
   supersedes every open import authority, and moves native Record timers into
   adoption hold in one transaction.
4. **Pin the digest you reviewed.** Pass `--expected-digest` to `bregctl apply`
   and `plan`, and set `package.expectedDigest` in the runtime file. Without
   the flag, apply activates whichever verified package `--package` names. The
   digest binds bytes, not authorship; check provenance of cross-organization
   packages (for example a cosign signature) in the deploy step.
5. **Rehearse on a restored copy.** The migration rehearsal runs over empty
   tables and does not compare the PostgreSQL major version. A timeout that only
   real rows reach is found by your own rehearsal and by `apply`. A destructive
   reviewed migration needs backup evidence at most 31 days old.
6. **Choose the production identity.** Set `canonicalBaseIri` to a hostname you
   control before packaging. Only the reserved `.invalid` namespace is refused.
7. **Use TLS to PostgreSQL and an HTTPS issuer.** `database.testOnlyPlaintext`
   is refused in release builds. Loopback HTTP is accepted for an issuer;
   anything else needs `authentication.oidc.allowInsecureHttp: true`, which is
   logged at startup and reported by `bregctl doctor` (BREG-RES-17).
8. **Keep the metrics listener private.** `metricsListener.bind` must be a
   loopback or private address; it carries no authentication.
9. **Run the idempotency sweep.** `bregctl idempotency-retention erase-expired`
   is the only thing that clears raw caller and key values from spent rows;
   the engine schedules nothing. Resolve uncertain writes and finish or cancel
   open ingestion runs before changing `authentication.oidc.issuer` or the
   principal claim (BREG-RES-05).
10. **Provision the identities your profiles name.** The activation guard
    checks the compiled permission shape. It does not prove that a real
    identity satisfies a profile's claims and row bounds. A Proposal grant
    without `writableInputs` leaves every declared Action input writable; name
    the inputs on every grant that should not set all of them. A Proposal
    grant's `ownership: caller` restricts which Proposal documents the caller
    may touch, not the target Records, which stay bounded by the grant's
    `rowBoundaries`.
    Enable `readableReviewProgress` only on the applicant grants intended to
    receive it. Choose public stage codes at the review provider with the
    applicant audience in mind. A change in code presence can reveal a
    transition, so assign the same coarse code across stages whose distinction
    should stay private.
11. **Keep delegated agent review context disabled** until the institution has
    approved the reviewer population and source ceiling for the standing-agent
    profile that holds `get-review-context`.
12. **Review statistical releases as a disclosure decision.** Review the
    population, dimensions, cadence, and release policy of every dataset
    (BREG-RES-07).
13. **Plan backups for retention.** Expiry sweeps for Evidence and terminal
    webhook metadata are bounded work, not immediate erasure. Backup retention
    is yours.
14. **Handle destructive recovery deliberately.** `bregctl hook discard`
    permanently closes one delivery and is not audited when refused before the
    request is recorded. `bregctl hook drain` runs reviewed handlers in the
    `bregctl` process and needs the destination and audit secrets, handler
    assets, and any field-encryption keys. Retained local hook work (pending,
    leased, or operator-replayable dead-lettered Rhai and Wasm deliveries with
    unexpired payloads) blocks both `bregctl plan` and `bregctl apply` until a
    drain settles it. If catalog verification refuses a
    policy whose expression was altered but whose comment matches, a database
    administrator clears that policy's comment and applies the exact target
    package again.
15. **Upgrade one release at a time,** finishing each release's upgrade steps
    before the next.
16. **Resume a blocked application deliberately.** `bregctl review-recovery
    retry-application` requeues only an application job that is blocked with
    attempts left and a last error of `dependency-outage`, `source-unavailable`,
    or `lease-expired`, for the current submitted Proposal. Run it after the
    cause is fixed; it refuses a withdrawn, unsubmitted, or detail-erased
    Proposal and one blocked as `package-changed` or `application-refused`.
17. **Grant write access to a link's `fromField` only to identities trusted
    to assert that link.** Whoever can set that field on a root chooses the
    outside subject BReg asks the source for, under the deployment's source
    grant, and which subject's values readers of that root then see. Review a
    change to it as you would review a disclosure. See
    [External projection storage](external-projection-storage.md).
18. **Keep the external projection cache out of logical backups.** Dump with
    the seven `--exclude-table-data` options for the
    `registry_external_projection_*` and `registry_external_refresh_*` tables,
    so a restore starts with no source values, old bindings, queued selectors,
    or refresh receipts. Physical backups and
    storage snapshots cannot exclude them and need a separately approved
    erasure and restore procedure
    ([logical backups](external-projection-storage.md#logical-backups)).
19. **Withdraw a source grant in deployment configuration.** Remove the
    binding and restart; that is the only cutoff for acquisition.
    `bregctl external-projection withdraw` purges retained values and refresh
    receipts but does not stop acquisition, and a binding that stays
    configured acquires again at the next start. Record the withdrawal in
    deployment configuration or at the source authority so it also holds after
    a restore
    ([stop acquisition](external-projection-storage.md#stop-acquisition-withdraw-and-renew)).
20. **Give each refresh plan a scoped service identity.** Match the
    configured requester client, principal, profile and relevant row
    claims against the verified token before acquiring external values.
    Give a change notifier a separate service client and scope. It may
    submit an approved selector for a configured projection. A queued
    hint grants no right to read a root or disclose a source value.
    Verify signed webhook deliveries before forwarding their selectors.
    See [managed refresh](external-projection-storage.md#schedule-refresh-and-inspect-coverage).
21. **Issue task-grant tokens for at most 900 seconds.** BReg refuses a
    token that carries a task grant without `iat`, with `exp - iat` over
    900 seconds, or with `iat` later than its clock plus
    `leewayMilliseconds`, whatever `maximumTokenLifetimeSeconds` allows other
    tokens (BREG-SEC-209). Keep the exchange issuer's task-token lifetime at
    or under that bound and its clock within the leeway; Casework's exchange
    step documents 300 seconds ([task grants](TASK_GRANTS.md)).

The refresh path extends BREG-SEC-204 through 207. The
`managed_refresh_resumes_sweeps_and_rereads_only_the_notified_subject`
PostgreSQL journey exercises worker and notifier separation, identical
admission for an eligible and protected selector, and current-scope
reconciliation. `selector_lookup_skips_a_large_excluded_prefix_and_exhausts_no_witness`
verifies row policy before a targeted lookup can settle no match.
`durable_queue_fences_newer_enqueues_and_authority_changes` checks
queue generations and leases in addition to the existing per-key
publication tests. The excluded backup restore test verifies the new
operational tables also restore empty.

## 3. Accepted residuals

Ordered by operator impact. Each lists the condition, the consequence, the
mitigation, and related matrix IDs.

### BREG-RES-01 Physical copies are not detected (Instance claim)

- **Condition:** the database is restored by point-in-time recovery, a storage
  snapshot, a base backup, or a promoted replica.
- **Consequence:** these keep the system identifier and database oid, so the
  copy matches the claim and serves without adoption. A physical restore
  serves without the adopt that supersedes reopened authorities, so an import
  authority closed after the backup point is open again. Nothing enforces the
  adopt. Where the system identifier is unreadable (a managed service), the
  claim compares the database oid alone, which is weaker.
- **Mitigation:** fence the original, run `bregctl instance-claim adopt` on the
  copy before it serves (section 2, item 3).
- **Related:** BREG-SEC-114, BREG-SEC-115, BREG-SEC-116, BREG-SEC-117.

### BREG-RES-02 Single-role mode does not separate the credentials

- **Condition:** `database.roles.migration` equals `database.roles.runtime`.
- **Consequence:** a holder of the runtime credential can write the ledger and
  change which package the runtime serves. `bregctl doctor` and the startup log
  (`startup.role_mode.single`) say so.
- **Mitigation:** run split roles in production.
- **Related:** BREG-SEC-04, BREG-SEC-118, BREG-SEC-119.

### BREG-RES-03 The migration credential authorizes any valid successor

- **Condition:** a holder of the migration credential applies a package whose
  `migrationPlan.fromPackageDigest` names the active digest.
- **Consequence:** review is a process step before apply, not a cryptographic
  gate. A database restored to an earlier activation names that activation's
  package as active, so the successor applied after it applies again; it is the
  same transition.
- **Mitigation:** guard the migration credential, pin `--expected-digest`, and
  check release provenance in the deploy step.
- **Related:** BREG-SEC-02, BREG-SEC-120, BREG-SEC-121.

### BREG-RES-04 A database superuser can edit the ledger

- **Condition:** anyone with superuser on the database.
- **Consequence:** the ledger, the instance claim, and any row can be changed.
  This is not prevented.
- **Mitigation:** the activation audit stream, shipped to append-only storage,
  is the independent trace.
- **Related:** BREG-SEC-04, BREG-SEC-120.

### BREG-RES-05 Idempotency keys and run ownership are scoped to issuer and principal

- **Condition:** `authentication.oidc.issuer` or the principal claim changes;
  an operator never runs the sweep; a first response is lost and the retry
  arrives past the receipt horizon (seven days by default).
- **Consequence:** after a mapping change, a retry is another caller's fresh
  request and an open ingestion run belongs to no current caller. Spent rows
  are never deleted: the digest row is kept for provenance, and its raw issuer,
  principal, and key stay until the sweep clears them. A late retry cannot
  recover a lost body and must read the record or its history. Ingestion run
  creator values stay as long as the run row; there is no run retention.
- **Mitigation:** resolve uncertain writes and finish or cancel runs before a
  mapping change; run `erase-expired` on a schedule.
- **Related:** BREG-SEC-12, BREG-SEC-162 to BREG-SEC-167.

### BREG-RES-06 Import authorities bound volume, not content

- **Condition:** a holder of an import grant runs an import.
- **Consequence:** the input digest is computed and announced by the client; the
  server never receives the file and does not recompute it, so a pinned digest
  names what the operator expects, not what was sent. Admission reserves no
  volume and import is create only, so re-running committed lines creates their
  records again. The runtime role can lower `committed_items` (its column grant
  checks volume bounds, not monotonic growth), which is treated as equivalent to
  its existing `INSERT` power over records. `--operator-reference` and
  `--reason` are argv values visible on the local host while the command runs.
- **Mitigation:** grant import narrowly; follow the import guide for duplicates;
  treat the runtime credential as able to write records.
- **Related:** BREG-SEC-116.

### BREG-RES-07 Statistical datasets give no confidentiality guarantee

- **Condition:** a dataset is published with threshold suppression and rounding.
- **Consequence:** independent suppression and rounding do not prevent
  reconstruction. With `minimumCount` 5 and `roundingBase` 5, two suppressed
  positive cells and a rounded total of 10 force both cells to 4; seven
  suppressed cells and a rounded total of 5 force all seven to 1. Zero cells
  disclose group attributes. Deterministic rounding supports differencing across
  releases, overlapping datasets and external knowledge amplify disclosure, and
  no privacy budget limits repeated observation. Withdrawal erases the engine's
  stored content, not copies a reader already obtained; release headers and
  withdrawal reasons remain.
- **Mitigation:** institutions review population, dimensions, cadence, and
  release policy. Cell key perturbation is not implemented.
- **Related:** BREG-SEC-150 to BREG-SEC-160.

### BREG-RES-08 The instance id is not durably bound

- **Condition:** `identity.instanceId` is changed.
- **Consequence:** the id derives the webhook event source. Startup refuses the
  change while any pending or leased delivery with an unexpired payload names
  another source, but the registry state holds no binding of the id once
  deliveries drain.
- **Mitigation:** keep the previous id until deliveries drain, then change it.
- **Related:** none; startup refuses the change while deliveries are pending.

### BREG-RES-09 Review close and resubmission rely on the authority

- **Condition:** an operator closes or resubmits a review.
- **Consequence:** `close` sends nothing to the authority, so a reviewer there
  may still decide, and that late result is refused; `operator-closed` is
  resubmittable. Resubmission relies on the authority's idempotency: if it no
  longer honours the original key, resubmitting opens a second review.
- **Mitigation:** confirm the authority lost the review before resubmitting.
- **Related:** BREG-SEC-34, BREG-SEC-67.

### BREG-RES-10 ID-only review policy selection trusts the provider until first acceptance

- **Condition:** a Proposal selects a review policy by id alone.
- **Consequence:** the trusted provider may change its policy, including between
  human review and automatic assessment, while first acceptance is pending. After
  acceptance the exact binding is preserved and a replacement is refused. Each
  submission starts with no accepted binding, so a new submission after changes
  are requested selects the provider's current policy again unless it is
  pinned.
- **Mitigation:** pin both `version` and `digest` when the version chosen at
  submission must be the one that decides. A partial pin is invalid. The
  window for resolving a pending first acceptance is the review authority's
  `recoveryDays`, which has no default (1 to 3650 days).
- **Related:** BREG-SEC-34.

### BREG-RES-11 A source can revoke between status observation and commit

- **Condition:** a Proposal is applied under retained task authority.
- **Consequence:** BReg observes the source's status outside the mutation
  transaction and shares no distributed transaction with it, so a revocation
  after the observation and before local commit is not seen. Local expiry and
  submission-binding checks stay enforced.
- **Mitigation:** none beyond the source's own revocation latency.
- **Related:** BREG-SEC-169.

### BREG-RES-12 Disclosed Proposal text and actor pseudonyms

- **Condition:** a reviewer writes a public reason; a holder reads
  `appliedBy`.
- **Consequence:** BReg bounds the public reason's length but cannot judge its
  content, so personal data written there reaches every Get holder. `appliedBy`
  is a keyed pseudonym, not anonymous: a holder can link Proposals applied by
  the same actor within that database and issuer, and a holder of the audit hash
  key can recompute it for a known issuer and subject.
- **Mitigation:** instruct reviewers; grant `get-application-actor` narrowly;
  protect the audit hash key.
- **Related:** BREG-SEC-58, BREG-SEC-174, BREG-SEC-179.

### BREG-RES-13 Advisory answers are not authority

- **Condition:** an application, reviewer, or operator relies on a preview.
- **Consequence:** an Action availability result can be stale as soon as it is
  returned and covers only the target's declared field guards. Access
  explanations are review aids; runtime admission is authoritative. The
  same-engine fingerprint comparison when rehearsing over a predecessor does not
  stop `test`; the strict final check still catches any effect on the
  candidate. The deployment identity check guards against accident, not against
  an operator who means to bypass it: a database initialized for `local`
  accepts the reserved identity.
- **Mitigation:** treat availability as a form hint and handle Invoke refusal.
- **Related:** BREG-SEC-186.

### BREG-RES-14 A global unique constraint reveals that a value is taken

- **Condition:** an in-boundary create collides with a hidden row's unique value.
- **Consequence:** the value-free `409 mutation.conflict` tells the caller the
  value is taken somewhere. Nothing is written outside the boundary.
- **Mitigation:** avoid unique constraints on values whose existence is itself
  sensitive, or scope them in the model.
- **Related:** BREG-SEC-09, BREG-SEC-180.

### BREG-RES-15 Generated identifier reservations are never erased

- **Condition:** a Record with a generated business identifier is tombstoned or
  erased.
- **Consequence:** the append-only ledger `registry_generated_identifier_reservations`
  keeps each issued value and its scope values, so a code is never reissued. The
  compiler limits generated and scope fields to public or internal values, so the
  ledger holds a category code beside an institution-issued number, not
  restricted data.
- **Mitigation:** do not scope generated codes by sensitive data.
- **Related:** BREG-SEC-189.

### BREG-RES-16 Source views rely on PostgreSQL policy ordering

- **Condition:** a tombstoned, detail-erased change request is still readable by
  the caller its get policy admits.
- **Consequence:** that row may reach an outside predicate before the view's
  lifecycle condition drops it, for a caller already allowed to get it, and it is
  absent from every result. The ordering of policy conditions before other
  predicates is PostgreSQL behaviour the engine relies on and does not enforce
  itself; the executed proof would fail on a server that broke it. A read policy
  written to admit more than `record_lifecycle = 'active'` widens what can reach
  a predicate.
- **Mitigation:** run supported PostgreSQL majors; revisit this residual before
  adding a read policy that admits non-active rows.
- **Related:** BREG-SEC-04, BREG-SEC-143.

### BREG-RES-17 Declared issuer and key endpoints are trusted

- **Condition:** the runtime file names an issuer or JWKS URI.
- **Consequence:** a declared issuer or JWKS URI may name any private address
  that is not cloud metadata or link-local; the operator who writes the file is
  trusted to name it. A discovered cross-origin endpoint stays under the strict
  policy and must use HTTPS, and redirects are disabled. Under
  `allowInsecureHttp: true`, an on-path attacker can substitute keys. `breg-review`
  never takes the HTTP opt-in, because it sends client credentials to the token
  endpoint.
- **Mitigation:** use an HTTPS issuer; leave `allowInsecureHttp` off.
- **Related:** BREG-SEC-19.

### BREG-RES-18 The metrics listener is unauthenticated

- **Condition:** a reader reaches `metricsListener.bind`.
- **Consequence:** they can read the active package digest, which identifies the
  deployed bytes and not their content. A scrape holds one runtime pool
  connection for up to the 5-second statement timeout and takes no row locks.
- **Mitigation:** the bind is refused unless loopback or private; firewall it.
- **Related:** BREG-SEC-146.

### BREG-RES-19 A failing worker stops the process, and readiness does not show it

- **Condition:** a background worker faults, or faults on every start.
- **Consequence:** the process stops with a code that names the worker. A fault
  that recurs on every start makes the process restart repeatedly and takes reads
  and writes down between attempts. `/ready` does not reflect worker state, so a
  load balancer keeps routing until the process exits. The attachment queue is
  not sampled by `breg_queue_oldest_pending_age_seconds`; alert on
  `breg_worker_last_success_age_seconds` instead. A failed subject access log
  retention pass writes a raw error record without a closed `code`.
- **Mitigation:** alert on the worker metrics and on restarts.
- **Related:** BREG-SEC-146.

### BREG-RES-20 The attachment job table has no row-level security

- **Condition:** a holder of the runtime credential changes a job row.
- **Consequence:** the table holds job keys, states, attempts, and timestamps. A
  changed row can cause an extra verifier request or stall a verification. It
  cannot release bytes, because a verdict is written only into the admitted
  verdict row under a live lease, and a pending row stays quarantined. One
  attempt can be answered `unfinished` twice (by the worker that wrote it and by
  the worker recovering its lapsed lease), and a recovering verifier may wait up
  to an hour, jitter included, before a quarantined file is retried.
- **Mitigation:** none needed for integrity; monitor the worker age metric.
- **Related:** BREG-SEC-10.

### BREG-RES-21 Some requests leave no per-subject trace

- **Condition:** a caller reads a statistical aggregate, or sends a HEAD
  request.
- **Consequence:** an aggregate read emits no per-subject access-log hit. A HEAD
  request is refused as a concealed 404; outside `/v1/statistics/` that refusal
  writes no statistics refusal journal entry, and under it only an
  authenticated caller's HEAD is journaled.
- **Mitigation:** treat statistical output as released content (BREG-RES-07);
  do not rely on the subject access log to show who saw an aggregate.
- **Related:** none.

### BREG-RES-22 The standing-agent publish ceiling needs a declared actor kind

- **Condition:** a profile that holds `publish` on a statistical dataset
  declares no `actorKind`.
- **Consequence:** the ceiling refuses publish and withdraw only for a profile
  that declares `actorKind: agent` and no `taskGrant`. A profile without an
  `actorKind` accepts every actor kind by its own declaration, as it does for
  every other operation, so an agent token can publish through it.
- **Mitigation:** declare `actorKind: human` or `actorKind: service` on every
  profile that holds `publish`.
- **Related:** BREG-SEC-168.

### BREG-RES-23 A revoked task grant keeps reading until its token expires

- **Condition:** Casework revokes a task grant, or the task ends, while the
  agent still holds a token carrying it.
- **Consequence:** reads under the grant (Records, read paths, revisions,
  history and statistics) check no live Casework status, so they continue
  until the token or the grant deadline passes, whichever comes first. A token
  carrying a grant is issued for at most 900 seconds (BREG-SEC-209). Governed
  mutations check live status on every attempt and stop at once.
- **Mitigation:** keep task-grant tokens short at the exchange issuer;
  Casework refuses new assertions for a revoked grant, so no new token follows.
- **Related:** BREG-SEC-209, BREG-SEC-169.

## 4. Development tooling

`bregctl dev` runs a local session and is not a deployment.

- It runs single-role and accepts the reserved `.invalid` identity; release
  deployments refuse both outside local environments (section 2, items 1 and 6).
- On Linux, the dev purpose-JWKS listener binds every interface while
  alternate-purpose tokens are acquired, so anything on the host's networks can
  read that window's JWKS. It serves one public key and no other route, and stops
  once the tokens are acquired. The private key stays in the owner-only dev state
  directory. On macOS it binds loopback.
- Development tokens are not deployment credentials. The token endpoint is the
  session's loopback issuer. `bregctl dev token` requests one resource per client,
  so a mapped client gets no token for the BReg audience.
- A retained clients file edited by the session owner after start can map a client
  to a resource that validation would have refused. The owner already holds every
  client key in that tree, the issuer still decides what it issues, and the
  receiving runtime still checks the audience.
- `bregctl api PATH --client CLIENT` needs a ready local session, selects only a
  client admitted to the BReg resource, keeps the bearer in memory, and writes no
  reusable header file. It adds no grant: the runtime still verifies the
  credential and authorizes the route, record, fields, and operation.
- The local issuer renders only for development. A production issuer is operated
  separately, and each runtime enforces its own issuer, audience, scope, and
  boundary checks on every token.
- `database.testOnlyPlaintext` exists only in test builds; a release binary
  refuses it with `breg.runtime.plaintext-database`.

`rstack dev` can instead activate BReg as part of an isolated project run.
It uses the normal package and database activation checks, distinct TLS
PostgreSQL credentials, and a loopback listener. The runtime trusts the
run's static signing key under the declared issuer name. See
[Run isolation](../platform/PROJECT-DEV.md#run-isolation).

## 5. Reporting

Report vulnerabilities privately as described in [SECURITY.md](../../SECURITY.md).
