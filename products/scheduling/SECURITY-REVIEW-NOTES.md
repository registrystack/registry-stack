# Registry Scheduling security review notes

Review notes for the security-sensitive Scheduling changes, held in tracked
material because commit messages do not survive a squash. Each section names
the change by its subject, the threat it answers, the defaults it ships, and
the tests that pin it. The security-invariant matrix in `contracts/` is the
row-per-invariant baseline; this file is the narrative behind the decisions
and the deferrals the matrix records.

## The task-grant bounds in the platform

The change `feat(auth): add scheduling bounds to task grants` carries its
review record in the `registry-platform-oidc` crate README (threat, wire
format, issuer and verifier compatibility, test evidence). It is not
restated here. In short: `GrantBounds::Scheduling` is a closed tagged union
with `deny_unknown_fields`, cardinality and length bounds (64 permissions,
32 actions each, 512-byte service and location values, unique
service-and-location pairs), and a `Debug` implementation that redacts
every value. A scheduling grant parsed by the BReg binding is refused, and
a test in `registry-breg` pins that refusal.

## The runtime edge: authentication, audit, listeners, and defaults

The change `feat(scheduling): serve the runtime edge with auth, workers,
and schema` introduced the HTTP edge, the authenticator, the audit
pipeline, the worker supervision, the listener policy, and the retention
defaults. AGENTS.md requires review notes for changes of this class; these
are they.

### Threat

A Scheduling deployment answers over HTTP to callers holding bearer
tokens, commits capacity inside PostgreSQL transactions, and writes
audit entries. The threats this surface answers:

1. **A caller without a complete task grant books capacity.** The edge
   authenticates the bearer token against a pinned JWKS, requires the
   profile scope for every read and a separately configured explain scope
   for explanations, and requires a complete scheduling grant (service,
   location, actions) for every commitment. A partially formed grant set
   is refused as a credentials problem, never honoured partially.
2. **A token that was valid at the door commits after its grant lapsed.**
   The grant's expiry is re-checked inside the capacity transaction,
   immediately before the claim commits, against a fresh observation of
   the store's clock taken after every lock wait, not against the
   request's own entry time: a transaction delayed by contention cannot
   carry a lapsed grant to a commit. The full bounds are matched once
   at the service before the transaction opens; re-reading them inside
   would only defend against a grant revoked or narrowed at the issuer,
   and the runtime does not ask the issuer for a grant's status (matrix
   deferral SCHEDULING-DEF-01, recorded in the published reference and
   reasoned in "Grant status stays out of the capacity transaction"
   below).
3. **A deployment is reached over a public interface by accident.** The
   listener must bind a private address or an explicitly declared
   container network; anything else refuses to start.
4. **A commitment leaves no accountable trace.** Every ledger-decided
   commitment and refusal writes a request entry before its transaction
   and a response entry with a pseudonymized principal after it, and a
   commitment is never answered without both. A permission mismatch
   refused at the service, before the transaction opens, writes a response
   entry too, so probing grant scope against the edge is visible in the
   audit; the answer itself stays the same closed refusal, naming neither
   the failing bound nor whether a grant was carried. The changes that made
   that true are recorded below under "The audit journal" and "The audit
   writer".
5. **A refusal discloses supply or another caller's booking.** Admission
   refusals project through a public code; the member-level cause stays
   behind the separately authorized explain path.

### Defaults

- The database connection requires TLS (`SslMode::Require`); the plaintext
  escape exists only behind the `postgres-test` feature for disposable
  test databases.
- The listener refuses public addresses absent an explicit container
  network declaration.
- Every answer carries `Cache-Control: no-store`, the security headers
  without HSTS (TLS termination is the deployer's), a 1 MiB body ceiling,
  and the caller's trace identifier when a trace is presented.
- Retention defaults (attempt receipt days, cursor minutes) are
  placeholders: a jurisdiction must approve real retention periods before
  production use. Retention sweeps idempotency attempt receipts and
  cursors only, and clears an attempt's raw caller and key with its receipt
  (SCHEDULING-SEC-33); appointments, history, and outbox rows are never
  swept in this milestone (SCHEDULING-DEF-06, recorded in
  `RUNTIME-CONFIG.md`), so a hold or appointment keeps its owner's raw
  issuer and subject (SCHEDULING-SEC-34).
  Rotated audit files are removed after `audit.retentionDays`, 90 days by
  default, which is equally a placeholder.
- Reminder intents with no configured destination stay local and readable
  in place; nothing is delivered by default.

### Test evidence

`crates/registry-scheduling/src/auth.rs` pins the partial-grant refusal,
the foreign-resource profile refusal, the unknown-key credential refusal,
and the explain scope separation. `crates/registry-scheduling/src/config.rs`
pins the listener policy, the static JWKS shape (unique named asymmetric
keys), the verified-package requirement in production, and that typed parse
paths never echo a rejected value. `crates/registry-scheduling/src/http.rs`
pins the problem rendering of the closed vocabulary, framework rejection
normalization, no-store and trace stamping, and the idempotency key bounds.
The PostgreSQL suite in `crates/registry-scheduling/tests/` pins the edge
refusing unauthenticated callers and unauthorized mutations end to end.

## The reschedule exclusion

The change `fix(scheduling): keep the reschedule exclusion inside the
runtime's transaction` removed the caller-settable `rescheduleOf` from the
wire admission request and made the exclusion an evaluator argument that
only the reschedule transaction supplies, from the appointment row it
locks. Before it, naming any live claim's identifier on a create path
excluded that claim from every capacity check; the review classed it a
merge blocker. The threat, the wire change, and the test evidence are
recorded in that change's own notes; the standing invariant is matrix row
SCHEDULING-SEC-17.

## The audit journal: what it records, and in what order

Two changes to `crates/registry-scheduling/src/service.rs` and
`crates/registry-scheduling/src/store.rs` moved the journal from partly
accountable to accountable. Both are security-sensitive in the sense
AGENTS.md names, so the record belongs here rather than only in a commit
message.

**A permission refused before the transaction is audited.** *Threat:* the
permission check answered `operation.not-authorized` and returned without
writing anything, so a caller probing which services, locations, and
actions a grant carries could enumerate the edge and leave no trail. Every
refusal the ledger decided was recorded; every refusal decided above it
was not. *Default:* both refusal paths, the grantless case and the
scope-mismatch case, write an authorization record before they answer. The
answer is unchanged, so what changes is the record and not the disclosure.
*Test:* `a_permission_refused_before_the_transaction_writes_its_audit_row`,
`crates/registry-scheduling/tests/postgres_commitments.rs`. This retires
deferral SCHEDULING-DEF-02 and promotes matrix row SCHEDULING-SEC-14 to
`enforced`.

**The journal is published in the order it became visible.** *Threat:* the
audit outbox carried no ordering column, and the query feeding the
publisher ordered by a random version 4 event identifier while its own
documentation said oldest first. The publisher appends what that query
returns to a hash chain, so the chain was internally consistent and
attested to a sequence the deployment never had. A chain that certifies
the wrong order is worse than no chain, because it is believed.
*Default:* the outbox carries its own recorded sequence, the pending query
reads in it, and the chain continues across a restart from its verified
tail rather than from whatever the first query after startup returns. The
sequence is allocated when a row is written, not when its transaction
commits, so two concurrent transactions can publish in the opposite order
from their sequence numbers; the chain attests to publication order, and
no claim is made about insertion-sequence order between transactions that
committed in the other order.
The outbox, the publisher, and the chain were later removed by the change
recorded under "The audit writer", which retired this threat with them:
the runtime now appends each entry itself, in the order the writer accepts
it, and no query reorders the audit afterwards.

## The audit writer

The change `feat(scheduling)!: write audit through the platform audit
writer` replaced the PostgreSQL audit outbox, its background publisher, and
the keyed hash chain with the shared `registry-platform-audit` writer. It
changes audit integrity and the order of audit against protected writes,
so it is security-sensitive in the sense AGENTS.md names.

**Threat:** a commitment commits and is answered while its accountability
record exists only as a database row a publisher has not reached, or never
reaches, so the answer outlives its audit. A chain over that journal
attested only to publication order, and a deployment could not tell a
stalled publisher from a quiet one.

**Default:** audit is one single-writer destination, a rotated file or
standard output, that fails closed at the request boundary.

- A commitment's `request` entry is accepted before the capacity
  transaction opens. A refused request entry opens no transaction and
  answers `service.unavailable`.
- Its `response` entry, carrying the decision under the request's
  correlation, is written after the transaction commits or rolls back. A
  refused response entry for a committed commitment answers
  `service.unavailable` with the commitment in place, rather than hand the
  caller an unaudited answer.
- A replayed receipt, including one a concurrent identical request won, is
  answered only after its own `response` entry is accepted. The entry
  records the decision the receipt carries, so a replayed refusal is
  recorded as denied. A refused entry answers `service.unavailable` and the
  receipt is not released.
- A permission refused before the transaction is one `response` entry.
- Hook delivery accepts each attempt's request entry before egress, inside
  the delivery claim's transaction, so a refused entry rolls the claim back
  and nothing is sent.
- `/readyz` follows the writer, so a stopped destination drains traffic.
- `schedulingctl records apply` writes to a sibling file for its role,
  never into the runtime's file, and refuses to replace records when that
  file cannot be opened.
- Schema version 8 drops the outbox and refuses while it holds a record
  its publisher had not reached, so an upgrade cannot silently lose one.

Entries are no longer chained. Tamper evidence for the audit file is the
destination's and the operator's collection pipeline's, not the runtime's.

**Tests:**
`an_allowed_commitment_writes_its_request_before_and_its_response_after`,
`a_refused_request_entry_opens_no_capacity_transaction`,
`a_refused_response_entry_answers_unavailable_with_the_commitment_committed`,
`refusals_decided_inside_the_capacity_transaction_write_their_audit_rows`,
`a_permission_refused_before_the_transaction_writes_its_audit_row`,
`hook_delivery_audit_failure_prevents_egress`, and
`migration_refuses_to_drop_unpublished_audit_and_drops_a_drained_outbox`
(`crates/registry-scheduling/tests/postgres_commitments.rs`);
`records_apply_replaces_facts_wholesale_and_audits_each_write` and
`records_apply_rejects_a_different_deployment_identity_without_writing`
(`crates/registry-schedulingctl/tests/records_apply_postgres.rs`).

## The runtime edge hardening

Nine changes to the authenticator, the configuration reader, and the HTTP
edge, in the file's threat / default / test shape.

**A. Only the RFC 9068 access-token type is admitted.** *Threat:* the
accepted `typ` set included plain `JWT`, so an identity token, or any
other JWT the same issuer signs for another audience, satisfied the
access-token profile. *Default:* `at+jwt` and its case variants only;
there is no configuration key to widen it. *Test:*
`the_access_token_profile_admits_only_the_rfc_9068_pair`,
`crates/registry-scheduling/src/config.rs`.

**B. Every deployment names the clients it admits.** *Threat:* an
absent or empty `allowedClients` admitted every client the issuer
verifies, so any application in the issuer's realm could reach a
Scheduling deployment, and a development file copied toward production
kept doing so. *Enforcement point:* `RuntimeConfig::check` in
`crates/registry-scheduling/src/config.rs`. *Refusal:*
`scheduling.runtime.allowed-clients-required` at
`/authentication/oidc/allowedClients`, in every mode, development loopback
included. *Test:* `every_deployment_must_name_the_clients_it_admits`,
`crates/registry-scheduling/src/config.rs`.

**C. Exchanged credentials are bound to declared assertion authorities.**
*Threat:* a token exchanged from a third-party assertion was accepted on
the strength of the issuer the token itself named, so any authority the
identity provider would exchange from could reach the deployment.
*Default:* an `assertionIssuers` map declares each accepted authority and
the client that may exchange from it; an undeclared authority is refused,
and the map is bounded in the runtime JSON Schema. *Tests:*
`an_exchanged_token_is_refused_until_its_authority_is_declared`
(`auth.rs`), `a_declared_assertion_authority_binds_the_client_that_may_exchange_from_it`
and `an_assertion_issuer_map_outside_its_bounds_is_refused`
(`config.rs`).

**D. An unreadable clock refuses to judge an expiry.** *Threat:* the epoch
conversion was unwrapped, so a clock behind the epoch produced a timestamp
against which every grant compared as unexpired. *Default:* fail closed; a
clock the runtime cannot read is an authentication refusal, not a pass.
*Test:*
`an_unreadable_clock_refuses_to_judge_an_expiry_rather_than_passing_it`,
`crates/registry-scheduling/src/auth.rs`.

**E. A verifier that reached no verdict answers unavailable, not a
challenge.** *Threat:* a JWKS or issuer outage was rendered as 401, which
tells a caller their credential is bad when the deployment could not check
it, and invites a credential rotation that fixes nothing. *Default:*
infrastructure failure answers 503 with `Retry-After`; only a verdict of
refused answers a challenge. *Tests:*
`a_key_endpoint_outage_is_unavailable_not_a_refusal`,
`only_a_verifier_that_reached_no_verdict_is_unavailable` (`auth.rs`),
`a_verifier_that_cannot_answer_is_unavailable_not_a_challenge` with its
negative `a_refused_credential_still_answers_a_challenge` (`http.rs`).

**F. Caller strings are bounded at the edge, at the authoring grammar's
own bounds.** *Threat:* every caller string an admission or cancellation
carries is stored verbatim in the ledger entry, the idempotency receipt,
and the audit journal. Under the 1 MiB body allowance a credentialed
caller could write a megabyte into each, and an unbounded duplicate key
could be varied at will to slip the duplicate guard. *Default:* the bounds
are the policy grammar's, not new numbers, because a value outside them
could never have matched anything the deployment published; the
cancellation reason is bounded to the column that stores it, so an
over-long reason is `request.invalid` rather than a database refusal
surfacing as `service.unavailable`. *Tests:*
`an_admission_request_is_bounded_before_it_reaches_the_store`,
`a_cancellation_reason_is_bounded_below_the_column_that_stores_it`,
`a_listing_offering_is_bounded_the_same_way_a_body_is`, all
`crates/registry-scheduling/src/http.rs`. The standing invariant is matrix
row SCHEDULING-SEC-19, which replaced deferral SCHEDULING-DEF-03.

**G. A startup refusal says where and why without repeating the value.**
*Threat:* an operator could not find the member that failed, and the
obvious fix, putting serde's reason in the message, would echo
operator-authored text into the startup log, where a runtime configuration
names secret references, database URLs, and destinations. *Default:* the
runtime file and the packaged policy are read by the shared configuration
reader, whose diagnostics carry a stable code, the member's JSON Pointer
(a document refused whole is reported at the root), the file with its line
and column, and a fix, and are built from the expected shape and bound
rather than from the refused value. *Tests:*
`a_runtime_document_refused_whole_is_reported_at_the_root`,
`a_runtime_document_the_reader_stops_on_names_the_line_and_column`,
`a_rejected_runtime_member_names_the_cause_without_the_value`,
`a_refused_packaged_policy_names_the_member_and_its_position` (all
`config.rs`), plus the standing
`typed_parse_path_does_not_echo_the_rejected_value`
(SCHEDULING-SEC-13).

**H. The runtime serves only a verified shared package.** *Threat:* a
runtime that reads an authored project directly, or a package whose files
were edited after review, serves a policy nobody packaged. *Default:* at
every start, in every listener mode and with or without a pin, the runtime
verifies `package.root` against its `SHA256SUMS`: a changed, missing, or
extra file, an absent `SHA256SUMS`, or the retired `scheduling.package.json`
is refused by name before the policy is parsed, and the package digest is
the SHA-256 digest of `SHA256SUMS`. The semantic policy digest the store and
hooks record is unchanged and no longer doubles as the package identity.
*Tests:* `every_listener_mode_verifies_the_package_without_a_pin`,
`crates/registry-scheduling/src/config.rs`, and
`package_writes_a_package_the_runtime_verifies_and_refuses_replacement`,
`crates/registry-schedulingctl/src/lib.rs`.

**I. Client tolerance is response-only.** *Threat:* relaxing client-side
parsing so a client outlives a deployment that adds a member would, if
applied to the wrong half, let a caller smuggle a field the server does
not declare. *Default:* response shapes tolerate unknown members and
problems are matched on the code alone, never on title or detail text;
request shapes stay strict. *Tests:*
`answer_documents_tolerate_a_member_a_later_deployment_added` and
`request_documents_refuse_a_member_they_do_not_declare`
(`crates/registry-scheduling-core/src/wire.rs`),
`a_reworded_title_or_detail_is_still_the_problem_the_code_names`
(`crates/registry-scheduling-client/src/error.rs`).

## The combined policy and records invariants at the database

**Threat:** a deployment can come to hold a policy and window records
that contradict each other. The consequential case is a pool that staffs
a published window and also backs an exact-time offering: an exact-time
claim locks the pool anchor, an arrival claim locks the window anchor,
so the two capacity transactions never serialize and the ledger has no
row on which to observe that it sold the same staffing twice.
`SchedulingPolicy::check_window_records` is the canonical validation of
the pair and refuses that combination with `shared-supply-unpartitioned`.
Until this change it ran only in `schedulingctl`, against the files on an
operator's disk, so an operator who edited the policy and restarted the
runtime deployed the combination their own tooling refuses.

**Enforcement:** both database writes re-run that same check under the
locks they already hold. `apply_policy` loads the deployed window records
before it writes a revision, and `replace_facts` loads the retained
document of the deployed policy revision before it swaps the records.
Neither reimplements the rules: they call the authoring implementation
and narrow its findings to the contradictions. Two reasons name an
absence rather than a contradiction and are excluded, because ordinary
operator sequencing depends on both: `unknown-window`, a policy published
before the records that serve it, which every admission on that offering
already refuses loudly (SCHEDULING-SEC-02), and `unknown-offering`, a
deployed window whose offering this publication retires, without which an
arrival offering could never be withdrawn. Either write is refused whole,
naming each contradicting field in the operator's own vocabulary, and
leaves the policy revision, the window records, and the facts revision
unchanged.

**Tests:**
`records_replacement_refuses_a_window_staffed_by_an_exact_time_pool` and
`policy_publication_refuses_an_exact_time_offering_on_a_deployed_windows_staffing`
(`crates/registry-scheduling/tests/postgres_commitments.rs`) take the
refusal from each direction, and
`an_unpartitioned_shared_staffing_block_is_rejected`
(`crates/registry-scheduling-core/src/policy.rs`) holds the rule they
share. The per-admission refusal remains as defense in depth:
`a_window_record_must_belong_to_the_authorized_offering_and_location`
plants its contradicting record directly in the tables, underneath the
writes that now refuse to produce one.

## One supply identifier, one kind of supply

**Threat:** `scheduling_supply` is one flat table keyed by `supply_id`,
and both kinds of supply anchor their capacity transactions on a row in
it. Pool identifiers come from the policy package and window identifiers
come from the environment records, authored separately, so nothing made
the two namespaces disjoint. A collision was not symmetric and neither
half was safe. Publishing a window over a live pool identifier hit the
primary key and aborted the facts replacement with a database error
instead of a refusal. Publishing a pool over a live window identifier was
worse: the insert skipped the conflicting row, so the pool quietly
anchored on a row still marked `window`, and the next records replacement
deleted it along with the rest of that kind. From there `lock_supply`
found fewer rows than it asked for and every commitment against that pool
was refused, on a deployment whose policy looked published and whose
records looked current.

**Enforcement:** the collision is refused before it can be written, by
name, on both sides. `SchedulingPolicy::check` refuses an arrival
offering whose window identifier an exact-time offering already sells,
which is the check `schedulingctl package` runs with no records in hand,
and `check_window` refuses a published window that takes such an
identifier, which reaches both database writes through the combined check
above. Beneath them the two anchor writes are now one `anchor_supply`
insert that returns the kind the row settled on and refuses when that is
not the kind it asked for, so a standing anchor of the other kind is
named rather than aborting one path and being skipped on the other, and
the standing row keeps its kind. `lock_supply` names the identifiers it
could not find instead of reporting a corrupt ledger, which is what
SCHEDULING-SEC-02 already promised the operator's diagnostics would say.

**Tests:** `a_supply_identifier_may_not_anchor_both_a_pool_and_a_window`
(`crates/registry-scheduling/tests/postgres_commitments.rs`) publishes a
colliding identifier in both directions and asserts the named refusal and
that the standing anchor keeps its kind, and
`a_pool_and_a_window_may_not_share_one_supply_identifier`
(`crates/registry-scheduling-core/src/policy.rs`) holds the authoring
refusal that reports it offline.

## Package activation and the activation ledger

Package activation moved from `scheduling migrate` and a startup that
adopted the database and published the policy to `schedulingctl plan`,
`schedulingctl apply`, and `schedulingctl status` over a database
activation ledger, `scheduling_activations` (schema version 9). It changes
what authorizes the runtime to serve a package, the split between the two
database credentials, deployment defaults, and audit, so it is
security-sensitive in the sense AGENTS.md names. Matrix rows
SCHEDULING-SEC-29 to SCHEDULING-SEC-32 and recorded decisions
SCHEDULING-DEC-09 and SCHEDULING-DEC-10 carry it.

`registry-platform-activation` now owns the product-neutral ledger reads and
appends, `databaseId` and active-package comparisons, role observation,
runtime grants, indirect-authority and default-privilege checks, and lost
acknowledgement read-back. Scheduling retains its migrations, lock order,
unpublished-audit guard, policy-publication hooks, audit wording, and refusal
mapping inside the same activation transaction. This moves implementation
ownership; the Scheduling invariants and executable tests below remain the
product contract.

**What authorizes an activation.** Holding the migration credential
(`database.migrationUrlRef`) and running `schedulingctl apply` with a
package that verifies against its `SHA256SUMS` and passes the authoring
checks. Nothing is signed: the ledger records that an apply happened, which
package it applied, and under which role mode, not a cryptographic approval.
An operator who needs a second approver puts it in front of the command, in
the pipeline that holds the migration credential.

**Migration versus runtime authority.** `apply` is the only writer of the
ledger and connects with the migration credential. `plan` and `status`
connect with the runtime credential inside a read-only transaction and write
nothing, on an empty database too. `scheduling serve` reads the ledger with
the runtime credential and writes no activation state: it no longer adopts
the scheduling id or publishes the policy, which the apply does in its
transaction. `plan` refuses, as `schedulingctl.activation.ledger-unreadable`
(exit 1), a runtime role that cannot read the ledger it compares: one without
USAGE on the schema, which would hide the ledger and read the database as
empty, or without SELECT on `scheduling_activations` or
`scheduling_schema_migrations`, as a rotated runtime role before apply grants
it. The refusal names `schedulingctl apply --runtime-config FILE`, then `plan`
again. A database with no ledger is not refused. When schema migration 8 is
pending, `plan` counts the unpublished audit outbox rows it would drop without
a lock, passing over an outbox the runtime role cannot read, and reports
`schedulingctl.activation.unpublished-audit`; apply counts them again under an
exclusive lock inside its transaction before the drop. Plan also resolves the
candidate's hook destinations and signing material as apply does before it
writes anything, and reports `schedulingctl.activation.hook-destinations` when
one cannot run. It resolves a key only to learn that it exists at a usable
size and drops it; the report and the refusal text name neither the key nor
its source.

**Role separation and the grants apply issues.** Apply compares
`current_user` on the two connections. When they differ (split role mode)
it grants the runtime role USAGE on the schema, SELECT, INSERT, UPDATE, and
DELETE on its tables, use of its sequences, and EXECUTE on its functions,
then revokes INSERT, UPDATE, DELETE, and TRUNCATE on the ledger and on
`scheduling_schema_migrations`, and revokes all ledger privileges from
PUBLIC, all inside the activation transaction. The grants name each
`scheduling_*` object and each platform hook delivery object Scheduling
installs, never every object in the schema, so an object another
application keeps in a shared schema such as `public` stays out of the
runtime role's reach, and a split runtime role missing a grant on such an
object is not drift. It never grants or revokes TRIGGER. A TRIGGER privilege the runtime role holds is refused with the
`REVOKE TRIGGER` to run, and a default privilege of the migration role that
would grant it TRIGGER on the tables a migration creates is refused before
any migration, naming `ALTER DEFAULT PRIVILEGES ... REVOKE TRIGGER ON TABLES
FROM <grantee>`, since a table a refused first apply created is rolled back
before the operator could revoke anything on it. When they are one role
(single role mode) the separation does not hold, and `plan`, `apply`, and
`status` say so rather than refuse it, since a single-role local deployment
is an ordinary layout. The mode the ledger records is not the comparison of
user names: after the grants, apply reads what the runtime role can actually
do to the ledger (a write privilege on the ledger or on
`scheduling_schema_migrations`, a column-level INSERT or UPDATE included,
ownership of the ledger or the schema,
membership in the migration role, or a superuser or BYPASSRLS attribute) and
records `single` if any holds, with the runtime role's name. Startup refuses
a ledger that recorded `split` for a credential that can now write it, a
grant or membership added after the apply, naming `schedulingctl apply` to
reissue the grants, and a split runtime credential that no longer holds
every grant apply issues it, naming the same command. Re-applying the active
package is accepted when the runtime role or its mode differs from the
recorded row, or when a split runtime role no longer holds every grant apply
issues, so rotating the runtime role, moving to split mode, or restoring
grants an ownership change took away is one more apply. The runtime keeps
broad DML on the product tables it serves from, which SCHEDULING-DEC-10
records with its reasoning: the ledger decides what a restart may serve, so
it is the table the runtime must not rewrite.

**A weakened split.** A runtime role that differs from the migration role
can still write the ledger indirectly when it owns, or is a member of a role
that owns, the Scheduling schema or any other `scheduling_*` table,
sequence, view, or function, when it holds TRIGGER on a `scheduling_*`
table or view, or when it holds CREATE on the Scheduling schema: a deferred
constraint trigger on a table apply updates, for example, fires as the
migration role at commit and can insert an activation row. A trigger
already attached to a `scheduling_*` table weakens the split the same way,
since no Scheduling migration creates one and revoking the power that
attached it leaves it in place. The grants apply issues cannot take any of
these away, so they are not drift. In configured split mode `plan` reports
the effective mode as `single` with the refusal
`schedulingctl.activation.split-role-weakened`, `apply` refuses it before
any schema, publication, or ledger statement (and again after the grants on
a first apply), and startup refuses it in place of the drift refusal. Single
role mode does not refuse them, since that runtime role holds the migration
role's authority already. Each refusal names the statement that separates
the roles, run as a database administrator. After `REASSIGN OWNED BY
<owner> TO <migrator>` it names `schedulingctl apply --runtime-config FILE`,
because moving ownership takes the runtime role's grants on those objects
with it and apply reissues them. After `REVOKE TRIGGER ON <table> FROM
<grantee>`, `REVOKE CREATE ON SCHEMA <schema> FROM <grantee>`, or `DROP
TRIGGER <name> ON <schema>.<table>` for each attached trigger, which leave
the grants in place, it names rerunning the command that refused, or
`schedulingctl plan --runtime-config FILE` to confirm. The grantee is the
one the runtime role holds the privilege through: itself, PUBLIC, or a role
it is a member of. Every membership these checks read counts whether it
inherits the role's privileges or only permits `SET ROLE` to it, since
either lets the runtime credential act as that role.

**Serialization and identity.** The whole activation (schema versions,
scheduling-id adoption, policy publication, the ledger row, and the grants)
is one transaction under `pg_advisory_xact_lock` on the migration key, so a
concurrent apply waits and then sees what the first committed. When the
supply and meta tables exist, apply locks every supply anchor and then the
meta row before it runs any migration, the order a capacity transaction
takes them, so a migration's table locks are never held while the apply
waits on a booking; the retained-binding check runs before those locks on
its own connection. A delivery an earlier runtime appends between that
check and the locks, bound to a destination the candidate rebinds, is not
seen by the apply. That fails closed with an availability cost: delivery
re-checks each binding, so no payload reaches a rebound destination, and
startup verifies retained bindings again and refuses to serve until the
delivery drains or its binding is kept. Moving the check inside the
activation transaction is tracked in #1720.
`identity.databaseId` is recorded by the first apply, and a later apply,
`records apply`, or startup under another id is refused before any statement
changes the database. The refusal names only the key: both values are
operator identifiers, not a diagnosis. `records apply` reads the ledger again
inside its swap, once it holds every supply anchor and the meta row that an
apply takes before recording its row, so an apply of another package that
commits between the command's first check and the swap refuses the swap
rather than leaving records written under a package no longer active.

**Audit integrity of the activation record.** Apply writes a
`scheduling-activation-audit/v1` request entry to the `schedulingctl`
sibling of `audit.path` before it opens the activation transaction, and a
response entry after it commits or refuses, under the same correlation. The
response names the outcome (`allowed`, `refused` with its closed
`schedulingctl.activation.*` reason, `failed`, or `unfinished`), the
predecessor, and the effects. A commit whose acknowledgment is lost is read
back on another connection like a records swap: one that took effect is
answered as applied, and one whose outcome cannot be read is `unfinished`
with `schedulingctl.activation.unacknowledged`, never `failed`, since it may
have taken effect; the error names `schedulingctl status`. An audit destination that cannot be opened, or a request entry it
refuses, applies nothing. A response entry refused after the commit leaves
the activation in place and is reported as
`schedulingctl.activation.applied-unaudited` (exit 3), naming
`schedulingctl status` to confirm it; the ledger row is the durable record of
that activation. An audit destination that cannot be opened or written is an
operational failure (`schedulingctl.audit-unavailable`, exit 3), not a
refusal.

**Operator-reference hashing.** `--operator-reference` (at most 256 bytes,
printable) is stored in the ledger and written to the audit stream only as a
keyed hash under `audit.hashKeyRef`, with the activation id as its scope, so
one change ticket used for two activations does not correlate across them.
The raw value is never stored or logged. `--backup REF` values (at most 16)
are recorded as given, and the audit stream carries only their count.

**What startup refuses, and what it no longer does.** Startup refuses when
the ledger holds no row, when the ledger belongs to another
`identity.databaseId`, when the verified package is not the active one, and
when `package.expectedDigest` names another package than `package.root`
holds. Each ledger refusal names `schedulingctl plan --runtime-config FILE`
then `schedulingctl apply --runtime-config FILE`. Startup no longer migrates,
adopts, or publishes, and `scheduling migrate` exits 2 naming the same two
commands.

**Tests, one per invariant:**
`startup_refuses_a_database_the_ledger_does_not_name_for_this_package`
(SCHEDULING-SEC-29),
`split_roles_deny_the_runtime_a_ledger_write_and_the_service_still_serves`,
`a_runtime_role_that_can_write_the_ledger_is_refused_at_startup_until_apply_reissues_its_grants`,
`a_runtime_role_owning_a_scheduling_table_is_refused_in_split_mode_naming_reassign_owned`
(which also shows a trigger the owning runtime role attached still refused
after the reassignment, and startup refusing the grants the reassignment
took until apply reissues them),
`a_runtime_role_with_create_on_the_schema_is_refused_in_split_mode_naming_revoke_create`,
`a_runtime_role_holding_trigger_on_a_scheduling_table_is_refused_in_split_mode_naming_revoke_trigger`
(which also shows apply refusing a TRIGGER default privilege before any
migration, naming its `ALTER DEFAULT PRIVILEGES` revoke, and a TRIGGER held
through PUBLIC revoked from PUBLIC; the CREATE
test shows the same for CREATE),
`a_runtime_role_holding_the_migration_role_is_recorded_as_single`,
`rotating_the_runtime_role_reapplies_the_active_package`, and
`plan_as_a_rotated_runtime_role_that_cannot_read_the_ledger_names_apply`
(SCHEDULING-SEC-30; the drift test also grants UPDATE on
`scheduling_schema_migrations`),
`apply_refuses_the_active_package_and_a_foreign_database_without_writing`,
`apply_waits_for_the_migration_lock_another_apply_holds`, and
`apply_takes_the_publication_locks_before_it_migrates`
(SCHEDULING-SEC-31), and
`apply_refuses_to_activate_without_its_audit_destination`,
`apply_writes_nothing_when_its_request_audit_entry_is_refused`, and
`an_apply_whose_response_audit_entry_is_refused_reports_it_applied_unaudited`
(SCHEDULING-SEC-32), all in
`crates/registry-schedulingctl/tests/activation_postgres.rs`;
`plan_on_an_empty_database_reports_the_initial_activation_and_writes_nothing`,
`plan_before_the_first_split_apply_reports_the_initial_activation`, and
`apply_records_one_row_per_activation_and_a_previous_package_is_a_new_row`
(which also shows one operator reference hashing differently in two
activations) in the same suite; `the_removed_migrate_command_refuses_as_usage_naming_plan_then_apply`
(`crates/registry-scheduling/src/runtime.rs`); and
`records_apply_refuses_a_database_where_this_package_is_not_active`
(`crates/registry-schedulingctl/tests/records_apply_postgres.rs`).

## A hold's expiry is decided after its locks

The change `fix(scheduling): start a hold's TTL after its capacity locks`
moved the instant a new hold's expiry is computed from. It changes when a
capacity claim's lifetime is decided and which instant the grant re-check
uses, so the record belongs here.

**Threat.** `create_hold` computed `expiresAt` from the request's entry
instant, then waited on the supply anchor and the per-caller advisory lock.
Under contention the answered hold carried less than the configured TTL, or
had already expired when the caller received it, and the caller retried into
the same contention. Capacity was never at risk: an expired hold consumes
nothing and cannot be confirmed (SCHEDULING-SEC-11).

**Change.** After both locks, immediately before the hold is written, the
transaction takes one observation of the store's clock. The task grant is
re-checked against that instant, and the hold's expiry is that instant plus
the TTL; the receipt, the stored `hold_expires_at`, and the `held` history
event's `expiresAt` all carry it. Everything else in the transaction keeps the
request's single `now`, and the confirm, direct create, reschedule, release,
and cancel paths are unchanged.

**Why a hold still cannot oversell or outlive its grant's authority.** The
capacity decision is unchanged: the snapshot, the admission, and the revision
guards run under the same locks as before, and the later expiry only makes
the new hold consume longer from the instant it was decided, which is
conservative against every other transaction's snapshot. The observation is
taken before the commit, so a hold is visible for at most the authored TTL.
The grant is re-checked at exactly the instant the hold's lifetime starts,
after every wait, so a grant that lapsed while the create queued writes
nothing. A hold's lifetime was never bounded by its grant's expiry, before or
after this change; turning a hold into an appointment needs a confirmation,
which re-checks the grant inside its own transaction.

**Tests.** `a_hold_that_waited_for_the_supply_lock_keeps_its_whole_ttl`
(SCHEDULING-SEC-11) holds the pool anchor from a second transaction, waits
until the create is blocked on it, pins the store's clock five minutes later,
and asserts the receipt, the ledger, and the history carry the pinned instant
plus the TTL. `a_grant_that_lapses_before_the_commit_never_books` and
`every_mutation_rechecks_expiry_after_its_writes` (SCHEDULING-SEC-03) still
pin that a lapsed grant commits nothing on every path, the hold included, all
in `crates/registry-scheduling/tests/postgres_commitments.rs`.

## One clock for the edge, the store, and the workers

The change `test(scheduling): pin the commitment suite to one clock` moved
the HTTP edge's request instant, and the reminder dispatch, hold-expiry, and
retention passes, from reading the system clock directly to reading the
store's clock, the one the in-transaction re-checks already read. Production
still observes the system clock through it, so no deployment changes
behaviour. It is recorded here because the request instant is what the
capacity transaction first judges a task grant's expiry against, before the
post-lock re-check, so the change touches how grant expiry is decided at the
door.

**Threat.** A clock the edge and the store read separately lets a test pin
one without the other, and lets a later change feed the two different times
by accident; a grant judged current at the edge against one clock and
re-checked against another is harder to reason about than one judged twice
against the same clock. The commitment suite also derived its slots,
windows, ranges, and expiries from the wall clock against a test opening
that closes at 23:30 UTC, a latent time-of-day failure of the kind that took
out the merge queue in the arrival-window tests.

**What still reads the system clock.** The OIDC verifier judges the access
token's `iat` and `exp` against the system clock, and `auth.rs` judges the
grant's `registry_grant_exp` against it before the service runs, as before;
the pin cannot reach either. Hook delivery runs on PostgreSQL's
`transaction_timestamp()`, and the records-swap occupancy checks read
PostgreSQL `now()`; neither changed. The pin is a `postgres-test` setter
(`PostgresStore::pin_clock`), absent from every production build.

**Why a grant still cannot book past its expiry.** The edge's system-clock
check, the capacity transaction's entry check against the request instant,
and the post-lock re-check against a fresh observation all still run, in
that order, on every commitment. In production the second and third read the
same system clock they read before; only the path by which they reach it
changed.

**Tests.** `a_grant_that_lapses_before_the_commit_never_books` now pins the
edge's observation inside the grant and every later observation past it, so
it proves the post-lock re-check refuses rather than the entry check.
`every_mutation_rechecks_expiry_after_its_writes` (SCHEDULING-SEC-03) keeps
the edge's observation and the post-lock re-check before the writes inside
the grant, plus a confirmation's hold-liveness read between them, and moves
only the next observation past it: the re-check after the writes,
immediately before `COMMIT`. On all six paths it asserts that observation is
the last one and the one that refuses, and that every business write rolls
back, so removing that re-check fails the test.
`the_suite_reads_the_wall_clock_only_to_pin_it_and_to_sign_tokens` fails
the suite if a test derives an instant from the wall clock again. All are in
`crates/registry-scheduling/tests/postgres_commitments.rs`.

## State older than the immediate predecessor

Before 1.0 a release reads only the state its immediate predecessor wrote.
For Scheduling the change is confined to the release image: the optional
`schedulingctl` install, which served releases that published no
`schedulingctl`, is now unconditional. It touches deployment defaults and
release provenance. The runtime, its migrations, its activation ledger, and
its audit guards are unchanged.

**Threat.** A release image ships without `schedulingctl`, so the documented
plan, apply, and status steps cannot run from the image the release evidence
describes.

**Enforcement.** `release/docker/Dockerfile.scheduling` installs
`schedulingctl` unconditionally, so the build fails when the tool is not
staged beside the runtime, and `release/scripts/check-debian13-images.py`
refuses a Dockerfile that makes any operator tool conditional. v0.38.0
published `schedulingctl` for `linux-amd64`, the one platform the image is
built for.

**Tests.** `release/scripts/test_check_debian13_images.py`:
`test_operator_tools_cannot_be_optional`.

**Accepted residual.** The runtime still guards state older than v0.38.0:
the audit-outbox drop guard in `crates/registry-scheduling/src/store/activation.rs`
(SCHEDULING-SEC-14) and the removed-key refusals stay as they are. Removing
the guard needs a decision on a schema floor, because without one an
unsupported upgrade from before the audit writer would drop unpublished
audit rows silently.

## Grant status stays out of the capacity transaction

Casework answers a resource server's question about a task grant's
current status at `GET /v1/task-grants/{grantId}/status`, and the Base
Registry Engine (BReg) asks it before each task-granted write. Scheduling
does not ask, and SCHEDULING-DEF-01 stays deferred with its reason
restated. This is an authorization decision, so it is recorded here; the
runtime and its tests are unchanged.

**Threat.** A grant revoked at Casework, or invalidated there because its
holder lost eligibility or its template retired, still commits capacity at
Scheduling until its deadline passes: the token the agent already holds
carries the bounds, and Scheduling never asks whether the grant is still
active.

**Decision.** Keep the deferral. A grant Casework mints lives at most 900
seconds from its approval (`TASK_GRANT_LIFETIME_SECONDS` in
`crates/registry-casework-core/src/task_grant.rs`, which every task
template is held to), and Scheduling re-checks the grant's expiry inside
the capacity transaction, after every lock wait and immediately before
the claim commits (SCHEDULING-SEC-03). The exposure is therefore the rest
of one short deadline. A status call would put Casework's availability
inside every capacity transaction: each commitment would hold its
capacity locks while it waits on another product, and would have to
refuse while that product is unreachable, because answering without the
status would make the check decorative. BReg accepts that cost for most
of its writes: it asks inside the write's transaction, waits at most five
seconds, and refuses the write when no answer arrives in that time. For a
change-request apply and an Evidence-guarded action it asks before the
transaction opens and re-checks only the grant's expiry inside it, which
keeps the locks free but leaves the window between the answer and the
commit, so that shape narrows the exposure without closing it.

**Revisit trigger.** An adopter needs a revocation to take effect faster
than a grant expires. Closing the deferral then adds a Scheduling adapter
over `registry-casework-client`, which relaxes the MVP dependency sentence
in `AGENTS.md` and `products/scheduling/scripts/check_dependency_direction.py`
in the same change, and promotes SCHEDULING-DEF-01 to an enforced row with
the negative test that earns it.

**Tests.** None change. `a_grant_that_lapses_before_the_commit_never_books`
and `every_mutation_rechecks_expiry_after_its_writes` (SCHEDULING-SEC-03,
`crates/registry-scheduling/tests/postgres_commitments.rs`) remain the
proof that the compensating expiry re-check holds.

**Accepted residual.** The 900-second ceiling is Casework's, not
Scheduling's. Scheduling verifies a grant's deadline but does not cap how
far ahead it lies, and its token verifier sets no maximum token lifetime,
so a deployment that accepts grants minted by another authority takes
that authority's grant lifetime as its revocation window. Holding that
authority to deadlines no longer than Casework's is the deployment's
responsibility; Scheduling does not enforce it.

## A spent key forgets its caller

An idempotency attempt kept its verified token issuer, subject, and raw
key for as long as the row existed, and the row is never deleted: a key
whose receipt is erased stays spent, so a retry after the horizon is
refused rather than executed again. This touches data minimization, so it
is recorded here (SCHEDULING-SEC-33).

**Threat.** The identifiers a caller presented outlive the receipt they
were retained for, so the database holds every caller's raw issuer and
subject and every key it ever chose, indefinitely. Clearing them naively
would free the key, so the same caller's retry after the horizon would
book a second time.

**Enforcement.** An attempt is identified and kept unique by a key
reference: SHA-256 over the domain `scheduling-idempotency-key-v1` and the
issuer, subject, command scope, and key, each prefixed by its UTF-8 byte
length as a big-endian 64-bit integer (`attempt_key_reference` in
`crates/registry-scheduling/src/store/attempt_key.rs`, the same
construction as BReg's request references without a dependency on BReg).
The replay lookup and the unique constraint use only that reference.
`erase_expired_attempts` in `crates/registry-scheduling/src/store.rs`
drops the receipt and clears the raw issuer, subject, and key in one
statement, and `scheduling_attempts_raw_caller_check` holds all three
non-empty while the receipt is retained and all three NULL once it is
erased. Migration 11 computes the same digest in SQL for every existing
row, so a key spent before the upgrade stays spent, and clears the raw
values from rows already erased.

**Tests.** `crates/registry-scheduling/tests/postgres_commitments.rs`:
`a_spent_key_forgets_its_raw_caller_after_the_receipt_horizon_and_stays_spent`
(the same caller's exact retry answers `idempotency.expired`, a changed
retry `idempotency.key-reused`, another caller's identical key is fresh,
and a row inside its horizon is untouched).
`crates/registry-scheduling/src/store/attempt_key.rs`:
`the_attempt_key_reference_is_a_length_prefixed_domain_digest`.
`crates/registry-schedulingctl/tests/activation_postgres.rs`:
`attempt_key_reference_migration_rekeys_spent_keys_and_clears_erased_callers`
(the SQL digest equals the Rust one, including for a non-ASCII subject,
and the constraint refuses a raw caller on an erased row or a cleared one
on a live row).

**Accepted residual.** The reference is an unkeyed digest, kept forever.
Anyone who can read the table and already knows a caller's issuer,
subject, and the exact key can confirm that the attempt was made, and a
caller that chooses guessable keys makes that confirmation cheap. The
row also keeps the command scope, request hash, outcome status, and
timestamps. Keying the digest with the audit hash key would make a key
rotation free every spent key, which is the double booking this row
exists to refuse.

## A claim is owned by its verified caller

A hold or appointment was owned by the audit-keyed pseudonym of the issuer
and subject that booked it, so rotating `audit.hashKeyRef` detached every
existing claim from its booker. This touches ownership and data
minimization, so it is recorded here (SCHEDULING-SEC-34).

**Threat.** After a key rotation the booker gets an empty listing and is
refused on read, confirm, reschedule, cancel, and release, while its claims
keep their capacity. An orchestrator recovering an unknown outcome reads an
empty page as no booking and books again, and the per-caller hold ceiling
stops counting the holds the caller already has.

**Enforcement.** Migration 12 adds `owner_issuer` and `owner_subject` to
`scheduling_claims`, and `scheduling_claims_owner_check` holds both present
and non-empty or both absent. Every claim the runtime writes stores the
verified pair from the commitment. `ClaimRow::is_owned_by` in
`crates/registry-scheduling/src/store.rs` decides hold confirm and release
and appointment reschedule and cancel; `owned_booking` in `service.rs`
decides the read and history; `list_appointments_by_external_reference`
filters on the stored pair; `lock_caller_and_count_active_holds` locks and
counts on it; and the listing cursor context binds a digest of it. The
pseudonym stays on the claim and in history and audit, where it decides
nothing. The owner is `#[serde(skip)]`, so receipts, outbox payloads, and
observer projections never carry it.

**Tests.** `crates/registry-scheduling/tests/postgres_commitments.rs`:
`rotating_the_audit_key_keeps_existing_claims_with_their_owner` (after a
rotation the booker lists, pages with a cursor issued before it, reads,
reschedules, cancels, releases, and is still held to its hold ceiling;
another principal gets an empty page, `cursor.invalid`, and
`operation.not-authorized`, and the claims stay active).
`crates/registry-scheduling/src/service.rs`:
`a_success_replay_receipt_projects_through_the_same_document` (an owned
claim serializes exactly as an unowned one).
`crates/registry-scheduling/src/hooks.rs`:
`projections_disclose_only_the_requested_closed_fields` (owner canaries
never reach a projection).
`crates/registry-schedulingctl/tests/activation_postgres.rs`:
`claim_owner_migration_keeps_existing_claims_and_refuses_a_partial_owner`.

**Accepted residual.** The raw issuer and subject stay on the claim for as
long as it exists, and claims have no retention sweep (SCHEDULING-DEF-06);
a future claim retention must clear both columns, which the constraint
allows. A claim written before migration 12 recorded only the pseudonym,
from which the owner cannot be recovered: it keeps its capacity and
history and is owned by no caller, so no API caller can read, confirm,
reschedule, cancel, or release it. Before 1.0 there are no adopters whose
claims this strands.

## Known deferrals

The matrix records four deferrals with their compensating controls.
SCHEDULING-DEF-01 is stated in threat 2 above and reasoned in "Grant
status stays out of the capacity transaction"; the other three are
restated here as the index the matrix's `recordedIn` points at:

- **SCHEDULING-DEF-04, the channel is not bound to the verified caller.**
  A caller entitled to book may choose which subquota it draws from. The
  policy declares a closed channel set and every subquota is a ceiling
  inside the published total, so a mis-chosen channel cannot oversell the
  window. Binding the channel to the verified client is a product
  decision for a later phase.
- **SCHEDULING-DEF-05, no database backstop under the duplicate-key
  guard.** The guard runs inside the same capacity transaction as the
  claim it protects, so a concurrent pair cannot straddle it; the
  supporting index is partial rather than unique.
- **SCHEDULING-DEF-06, retention scope.** Recorded in
  `RUNTIME-CONFIG.md`, which states plainly what the sweeps cover.

A change that closes one of these promotes the matrix entry in the same
commit and rewrites this section with it.

### PostgreSQL support floor

Activation and startup require PostgreSQL 17 or newer. The shared activation
boundary checks the server version before observing migration or activation
relations, including an empty database. Older servers refuse with an upgrade
instruction before migrations or activation writes. The shared
`postgres_version_floor_precedes_missing_ledger_observation` database test
covers that entry point; unit tests pin the 16/17 version boundary.
