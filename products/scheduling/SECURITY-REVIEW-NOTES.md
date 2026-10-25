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
2. **A grant already invalid at the fresh status observation, or an expired
   credential, commits capacity.** A runtime configured with task-grant
   authorities obtains a fresh exact status before every capacity transaction
   and receipt replay. The outbound call completes before database locks are
   taken. Inside the transaction, the earlier of the verified access-token and
   grant deadlines is re-checked after every lock wait and immediately before
   commit. Every runtime file states `taskGrantStatus`, and a file that omits
   it is refused at startup; a runtime that writes
   `unchecked-final-fifteen-minutes` admits only the bounded offline path for
   a grant with at most 900 seconds left.
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
- Retention defaults are placeholders: a jurisdiction must approve real
  retention periods before production use. Retention clears an attempt's raw
  caller and key with its receipt (SCHEDULING-SEC-33), expires cursors, and
  clears a claim's raw owner after its terminal window (SCHEDULING-SEC-34).
  Claim, history, and actionable or uncertain outbox rows remain (SCHEDULING-DEF-06, recorded in
  `RUNTIME-CONFIG.md`).
  Rotated audit files are removed after `audit.retentionDays`, 90 days by
  default, which is equally a placeholder.
- Reminder intents with no configured destination are set aside as local
  and stay readable in place; nothing is delivered by default.

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
Entries are no longer chained. Tamper evidence for the audit file is the
destination's and the operator's collection pipeline's, not the runtime's.

**Tests:**
`an_allowed_commitment_writes_its_request_before_and_its_response_after`,
`a_refused_request_entry_opens_no_capacity_transaction`,
`a_refused_response_entry_answers_unavailable_with_the_commitment_committed`,
`refusals_decided_inside_the_capacity_transaction_write_their_audit_rows`,
`a_permission_refused_before_the_transaction_writes_its_audit_row`,
and `hook_delivery_audit_failure_prevents_egress`
(`crates/registry-scheduling/tests/postgres_commitments.rs`);
`records_apply_replaces_facts_wholesale_and_audits_each_write` and
`records_apply_rejects_a_different_deployment_identity_without_writing`
(`crates/registry-schedulingctl/tests/records_apply_postgres.rs`).

## The runtime edge hardening

Nine changes to the authenticator, the configuration reader, and the HTTP
edge, in the file's threat / default / test shape.

The configured issuer and explicit JWKS URI use the shared checked `Url`
before authentication is constructed, refusing backslashes and host text the
URL parser rewrites with value-free `config.invalid-value` at the member.
ASCII DNS case differences, punycode and IPv6 literals remain accepted; issuer
comparison stays textual. The declared issuer may resolve to a private
address, and so may an explicit JWKS URI, which is declared configuration and
inherits the declared-issuer allowance on any origin. A discovered JWKS URI
inherits that allowance only on the same origin; a discovered cross-origin
private address is refused, and cloud metadata and link-local addresses remain
refused for declared and discovered endpoints alike. Plain HTTP remains
limited to loopback unless the runtime explicitly sets
`allowInsecureHttp: true`, in which case startup emits a fixed warning; that
setting never extends plain HTTP to a discovered cross-origin endpoint, which
must use HTTPS. Redirects remain disabled. The shared
`issuer_and_jwks_uri_are_checked_urls_when_read` test pins the new refusals and
ordinary inputs. Scheduling's `the_oidc_issuer_and_clients_are_the_shared_blocks`
in `crates/registry-scheduling/src/config.rs` pins the remote HTTP refusal at
`/authentication/oidc/issuer`, and `runtime_reads_the_explicit_http_issuer_opt_in`
there covers the explicit HTTP exception and its startup diagnostic.

**A. Only the RFC 9068 access-token type is admitted.** *Threat:* the
accepted `typ` set included plain `JWT`, so an identity token, or any
other JWT the same issuer signs for another audience, satisfied the
access-token profile. *Default:* `at+jwt` and its case variants only;
there is no configuration key to widen it. *Test:*
`the_access_token_profile_admits_only_the_rfc_9068_pair`,
`crates/registry-scheduling/src/config.rs`.

**B. Every deployment names the clients it admits.** *Threat:* an
`allowedClients` that admits every client the issuer verifies lets any
application in the issuer's realm reach a Scheduling deployment, and a
development file copied toward production keeps doing so. *Enforcement
point:* the shared `OidcClientsConfig` reader in
`registry-platform-config`, when the file is decoded, then
`RuntimeConfig::check` in `crates/registry-scheduling/src/config.rs`.
*Refusal:* an omitted member is `config.missing-key` at
`/authentication/oidc`, an empty list `config.invalid-value` at
`/authentication/oidc/allowedClients`, a repeated client
`config.duplicate-item` at the repeated item, and `unrestricted`
`scheduling.runtime.allowed-clients-required` at
`/authentication/oidc/allowedClients`, each in every mode, development
loopback included. *Test:* `every_deployment_must_name_the_clients_it_admits`,
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
extra file or an absent `SHA256SUMS` is refused by name before the policy is
parsed, and the package digest is the SHA-256 digest of `SHA256SUMS`. The
semantic policy digest the store and hooks record is unchanged and no longer
doubles as the package identity.
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
activation ledger, `scheduling_activations`, part of the schema version 200
baseline. It changes
what authorizes the runtime to serve a package, the split between the two
database credentials, deployment defaults, and audit, so it is
security-sensitive in the sense AGENTS.md names. Matrix rows
SCHEDULING-SEC-29 to SCHEDULING-SEC-32 and recorded decisions
SCHEDULING-DEC-09 and SCHEDULING-DEC-10 carry it.

`registry-platform-activation` now owns the product-neutral ledger reads and
appends, `databaseId` and active-package comparisons, role observation,
runtime grants, indirect-authority and default-privilege checks, and lost
acknowledgement read-back. Scheduling retains its schema baseline, lock
order, policy-publication hooks, audit wording, and refusal mapping inside
the same activation transaction. This moves implementation
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
again. A database with no ledger is not refused. Plan also resolves the
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
role's authority already. Each refusal names the statements that separate
the roles, run as a database administrator. For ownership, it names an exact
`ALTER ... OWNER TO <migrator>` for each affected Scheduling schema object,
then `schedulingctl apply --runtime-config FILE`, because moving ownership
takes the runtime role's grants on those objects with it and apply reissues
them. After `REVOKE TRIGGER ON <table> FROM
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
adopts, or publishes, and `serve` is the runtime's only command.

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
`successor_apply_waits_for_publication_locks_before_it_publishes`
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
activations) in the same suite; `serve_is_the_only_command_and_any_other_name_is_a_usage_error`
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

**Accepted residual.** The removed-key refusals remain. Installation neither
creates nor drops an audit outbox. A database an earlier release migrated is
refused as a pre-1.0 schema, because its ledger holds a version below the
version 200 baseline, with an instruction to apply to a new database; no
release upgrades that state in place.

## Fresh task-grant status stays outside the capacity transaction

Casework answers a resource server's question about a task grant's current
status at `GET /v1/task-grants/{grantId}/status`. Scheduling now uses the
shared platform status transport before each capacity commitment and each
idempotent receipt replay when `taskGrantStatus` lists authorities. This keeps
Scheduling independent of Casework's implementation crate while sharing the
same exact wire contract with BReg.

**Threat.** A grant revoked at Casework, invalidated by a holder reassignment,
or changed at the authority could otherwise keep committing capacity through
an already issued access token. A request could also receive an active status
answer and then wait on a capacity lock until its short execution credential
expired.

**Decision.** The authority must answer with `active: true` and reproduce the
exact grant id, source issuer, principal, client, resource, purpose, bounds,
signed subject values, and deadline. A mismatch, inactive response, incomplete
signed binding, or unlisted source is an authorization refusal. An authority
or service credential outage, including a malformed authority response, is a
service outage. Positive answers are never cached, and the complete attempt,
including acquisition of the service credential, has a ten-second limit.

The status call completes before the capacity transaction opens, so it holds no
capacity lock while waiting on another product. The transaction then checks
the earlier of the verified access-token and grant deadlines after every lock
wait and immediately before commit. This bounds the interval between status
and commit by the short execution credential, even when the grant remains live
for days. It does not create a distributed transaction: a withdrawal after a
positive status answer can still race the in-flight local commit.

`taskGrantStatus` is required, so no runtime reaches the offline path by
omission: a file without it is refused at startup with
`scheduling.runtime.missing-task-grant-status`, and an empty list is refused
naming both choices. The keyword `unchecked-final-fifteen-minutes` selects the
bounded offline path, which accepts a grant only when it has no more than 900
seconds remaining at request entry and performs no revocation check. A list of
authorities disables that path for all grants, including sources that are not
listed. Deployments that accept deferred grants must list their authorities.

**Tests.** `configured_task_status_is_fresh_for_a_capacity_commit_and_its_replay`
proves that an initial capacity claim and its duplicate operation each obtain
a fresh status while the ledger records one effect.
`inactive_mismatched_and_unavailable_task_status_commit_no_capacity` covers
closed refusals and authority outage, and
`inactive_and_unavailable_task_status_refuse_every_mutation_without_changing_capacity`
extends them to hold create, hold release, confirmation from a hold,
reschedule, and cancel.
`an_unlisted_source_is_refused_and_never_reaches_the_offline_path` refuses a
grant from an unlisted source with less than 15 minutes left.
`the_offline_path_accepts_at_most_fifteen_minutes_of_remaining_lifetime`
pins the 900-second offline path at both sides of its bound, and
`a_commitment_blocked_past_its_access_token_deadline_never_books` holds a real
PostgreSQL capacity lock until the execution credential has expired. All are in
`crates/registry-scheduling/tests/postgres_commitments.rs` and carry
SCHEDULING-SEC-03. The database-free unit tests in
`crates/registry-scheduling/src/service.rs`
(`the_offline_path_accepts_only_an_unexpired_grant_with_at_most_fifteen_minutes_left`,
`listed_authorities_refuse_an_unlisted_source_and_an_unbound_grant_without_the_offline_path`,
and `a_listed_authority_answer_decides_the_grant`) pin the same decision
without a database. In `crates/registry-scheduling/src/config.rs`,
`a_missing_task_grant_status_is_refused_naming_both_choices` and
`an_empty_or_unknown_task_grant_status_is_refused_naming_both_choices` refuse
an absent member, an empty list, and an unknown keyword, and
`the_unchecked_keyword_selects_the_offline_path` reads the keyword.

**Accepted residual.** The signed token does not identify whether Casework
issued the grant in immediate or deferred mode. On a deployment that writes
`taskGrantStatus: unchecked-final-fifteen-minutes`, the final 15 minutes of an
originally deferred grant therefore qualify for the bounded offline path, with
no revocation check. Omission does not reach that path: it is refused at
startup. Operators who accept deferred grants close the residual by listing at
least one status authority, which makes status mandatory for every source.

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
erased. Fresh installation establishes the digest and raw-caller constraints
before attempts can be stored. It does not convert older attempt rows.

**Tests.** `crates/registry-scheduling/tests/postgres_commitments.rs`:
`a_spent_key_forgets_its_raw_caller_after_the_receipt_horizon_and_stays_spent`
(the same caller's exact retry answers `idempotency.expired`, a changed
retry `idempotency.key-reused`, another caller's identical key is fresh,
and a row inside its horizon is untouched).
`crates/registry-scheduling/src/store/attempt_key.rs`:
`the_attempt_key_reference_is_a_length_prefixed_domain_digest`.
`crates/registry-schedulingctl/tests/activation_postgres.rs`:
`fresh_attempt_storage_preserves_digests_and_refuses_partial_erasure`
(fresh storage retains caller-scoped runtime digests, including for a
non-ASCII subject; refuses missing, malformed, or duplicate digests; and
refuses a raw caller on an erased row or a cleared one on a live row).

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

**Enforcement.** The schema baseline gives `scheduling_claims`
`owner_issuer` and `owner_subject`, and `scheduling_claims_owner_check` holds both present
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
`fresh_claim_storage_refuses_a_partial_owner`.

**Retention.** The raw pair now has its own bounded terminal window, described
below. A claim with no raw owner is owned by no caller, so no API caller can
read, confirm, reschedule, cancel, or release it. Earlier claims are not
assigned an owner: v0.40.0 does not upgrade v0.39.0 state in place; apply to a
new database.

## Bounded claim owner retention (#2045)

**Decision and threat.** Keep live ownership independent of the audit key,
while ending indefinite retention of the raw verified issuer and subject.
`retention.claimOwnerRetentionDays` accepts 1 through 365 days and defaults to
seven days. This is a placeholder, not a jurisdictional recommendation.
The window starts at an appointment's end or cancellation, or a hold's expiry,
release, or consumption, whichever applicable instant comes first. Claim,
history, reminder outbox, and audit records are not deleted by this pass.

**Enforcement.** The schema baseline gives each claim an inert owner
reference and an erasure time.
`PostgresStore::erase_expired_claim_owners` atomically clears both raw columns
and writes a SHA-256 digest of a domain marker, claim UUID, and length-prefixed
issuer and subject. Its single UPDATE rechecks the eligible row after any
concurrent update. The retention worker invokes it using the configured window.
A constraint forbids restoring a raw owner on a tombstoned row. Mutation reads
lock the claim before checking ownership, so a mutation waiting behind erasure
cannot use a stale owner. The digest is never an authorization input.

Owner reads, history, reference listings, and hold counts continue to use only
the raw pair. Receipt observation joins the current claim owner; idempotent replay locks and checks the claim named by the receipt or the internal hold-release scope. An erased owner therefore cannot
recover claim data through a separately retained receipt. Receipt observation
answers `receipt.unresolved`; claim receipt replay answers `operation.not-authorized`. An empty hold-release
receipt follows the same owner check. These retain the existing recovery rules: use an
active claim owned by the current principal, and do not interpret unresolved
receipt evidence as proof that no effect occurred.

**Residual.** The digest is a pseudonymous reference, not anonymization: a
holder of candidate issuer/subject values and the claim UUID can test guesses.
Including the UUID avoids a stable cross-claim owner reference. The existing
keyed actor pseudonym remains in claim history and audit, whose retention is
separate. Erasure changes no revision, history entry, capacity, or audit event.
A running runtime is required for scheduled erasure; the pass is idempotent.

**Regression evidence.** The PostgreSQL tests
`claim_owner_retention_clears_only_elapsed_claims_and_preserves_the_ledger`,
`a_cleared_claim_owner_cannot_read_list_or_observe_a_retained_receipt`,
`an_erased_hold_owner_cannot_replay_a_retained_release_receipt`,
`a_mutation_waiting_on_owner_erasure_rechecks_ownership_before_writing`, and
`erased_hold_owners_do_not_hide_the_callers_remaining_hold_ceiling` cover the
cutoff, terminal variants, live claims, exact digest, unchanged ledger, receipt
paths, mutation race, and remaining hold limit. The configuration test
`claim_owner_retention_accepts_its_own_bounded_window` covers the independent
window and both bounds. The existing audit-key rotation test covers live claims.
The PR records which of these and the product gates actually ran.


## Client refusal vocabulary

Threat: a caller branching on a retired error word misclassifies a refused
request or a capacity mutation whose outcome remains unknown.

The Node and Python mappings in
`crates/registry-scheduling-client-node/src/lib.rs` and
`crates/registry-scheduling-client-py/src/lib.rs` expose kebab-case failure
words, including `invalid-request`, `header-bounds`, `trace-context`, and
`media-type`, from the same closed Rust failure variants. Shared transport
words come from `TransportKind::kind`. Response validation, retryability,
unknown-outcome reporting and the fixed value-free error message are
unchanged. Task-grant checks and capacity transaction decisions are unchanged.

Tests: `protocol_failures_use_the_public_snake_case_vocabulary` in the Node
binding's `src/lib.rs` asserts the current kebab-case protocol words.
`an_answer_the_binding_cannot_convert_is_a_protocol_failure_with_an_unknown_outcome`
in the Python binding's `src/lib.rs` asserts the protocol category, unknown
outcome and fixed message. The shared
`every_transport_failure_reports_its_own_kebab_case_kind` test in
`crates/registry-platform-httputil/src/client/mod.rs` pins transport words.
The Python test does not enumerate every protocol word; its closed source
mapping defines those words. These are proof references, not execution claims.

Callers must use the current vocabulary; no spelling alias or conversion is
provided.

## Known deferrals

The matrix records three deferrals with their compensating controls. They are
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

## Fresh attempt keys and claim ownership

Threat and enforcement: Installation must not rewrite the identity of a spent attempt or invent a claim owner. The baseline carries the live attempt-reference and owner constraints and no attempt digest backfill or erased-receipt caller rewrite. Fresh creation omits the obsolete audit outbox, and installation never drops an existing one; a database holding an earlier release's schema is refused as a pre-1.0 schema, because its ledger holds a version below the version 200 baseline, and nothing is committed. The stored-policy reader does not discard obsolete windows, same-policy publication does not reconstruct a missing document, and window-head creation does not copy earlier window rows. Capacity transactions, whole owner-pair checks, audit rotation, caller replay, and retention behavior are unchanged.

Verification: `registry-scheduling/tests/postgres_commitments.rs::rotating_the_audit_key_keeps_existing_claims_with_their_owner` and `registry-schedulingctl/tests/activation_postgres.rs::fresh_claim_storage_refuses_a_partial_owner`. Schema-only dumps of separate fresh
installations are compared before and after, with no ledger data.

Evidence also includes `a_retained_policy_with_obsolete_windows_is_not_reinterpreted` and `reapplying_a_policy_does_not_reconstruct_a_missing_retained_document` in `postgres_commitments.rs`. The pre-1.0 refusal is covered by `a_pre_1_0_schema_is_refused_by_migrate_and_readiness` in `postgres_commitments.rs`, `a_pre_1_0_schema_is_refused_by_name_at_plan_apply_and_startup` in `registry-schedulingctl/tests/activation_postgres.rs`, and `every_ledger_below_the_baseline_is_a_named_pre_1_0_refusal` in `crates/registry-scheduling/src/store/activation.rs`.

Residual: v0.40.0 does not upgrade v0.39.0 state in place; apply to a new
database. No compatibility reader or migration of earlier state is provided.

## Shipped database transport refusal

Threat: an operator copies `database.testOnlyPlaintext: true` from a disposable
test fixture into a shipped runtime configuration and silently loses database
TLS. The existing configuration guard refuses that member's true value in
builds without `postgres-test`, before opening a database connection. The
release binary build uses its default features; it does not enable
`postgres-test`.

`the_default_feature_runtime_refuses_test_only_plaintext` in `crates/registry-scheduling/tests/plaintext_config.rs`
executes the actual native runtime process and requires the product's
`scheduling.runtime.plaintext-database` refusal and `testOnlyPlaintext` recovery
field. This regression is excluded from `postgres-test` builds so a permissive
test binary cannot satisfy the shipped-feature proof. The runtime guard and
release build feature selection are unchanged; the existing default-feature
test suite owns this check.

## State no predecessor wrote is refused without a name of its own

Recorded 2026-10-12. Three refusals that named a shape only releases before
v0.40.0 wrote or accepted are removed, together with one `plan` condition
only a schema older than the activation ledger could meet. Before 1.0 a
release reads only what its immediate predecessor wrote or accepted. v0.40.0
neither wrote nor accepted any of these shapes: it carried the same three
refusals, and every v0.40.0 database is a new database at schema version 12.
The change touches deployment defaults: which refusal out-of-promise input
meets, and under which code. Authentication, authorization, the capacity
transaction, the activation ledger, and audit are unchanged.

**What was removed.**

- `scheduling.package.retired-manifest`
  (`RuntimeConfigError::RetiredPackageManifest`): the startup refusal that
  named a `package.root` holding `scheduling.package.json`.
- The hidden `scheduling migrate` command, which parsed only so it could
  exit 2 naming `schedulingctl plan` then `schedulingctl apply`.
- `schedulingctl.activation.earlier-release`
  (`StoreError::EarlierRelease`): the refusal that named a retained policy
  document whose identity sits under `scheduling` with no `project` block.
- In `plan_activation`, the allowance that ran the read-only publication
  check while the activation ledger's schema version was the only one
  pending. `plan` runs that check exactly when no schema version is
  pending.

**Threat.** Dropping a refusal by name turns the input it named into accepted
input: a stale manifest served as package content, a command that migrates
from the runtime, or an earlier policy document reinterpreted as the current
one.

**Enforcement.** Each input still meets a refusal that does not depend on
recognizing it.

- `verify_scheduling_package` verifies `package.root` against its
  `SHA256SUMS` before the policy is parsed. A file `SHA256SUMS` does not
  list is refused as an extra file whatever its name
  (`scheduling.package.invalid`), and one it does list is refused because
  the package must hold exactly `scheduling.yaml`
  (`scheduling.package.unexpected-contents`). Both name
  `schedulingctl package` (SCHEDULING-SEC-15). The `package.expectedDigest`
  pin is compared before the contents, so a listed file under a pin that
  names another digest is refused as `scheduling.package.digest-mismatch`.
- `serve` is the runtime's only command. Any other name is the argument
  parser's usage error, exit 2, raised before the runtime file is read, so
  no command line makes the runtime migrate, adopt, or publish
  (SCHEDULING-SEC-29).
- `SchedulingPolicy` requires `project` and denies unknown members, so
  `retained_policy` fails to read the document and answers
  `StoreError::Corrupt`. That is not an activation refusal: `schedulingctl`
  reports `schedulingctl.store-unavailable` with its operational-failure
  exit, publishes nothing, and repeats nothing the document holds.
- An activated database has no pending schema version. With the baseline
  pending, `plan` leaves the publication absent and `apply` runs the check
  inside its transaction after migrating.

**Tests.** `every_listener_mode_verifies_the_package_without_a_pin`
(`crates/registry-scheduling/src/config.rs`) refuses an unlisted
`scheduling.package.json` as an extra file.
`serve_is_the_only_command_and_any_other_name_is_a_usage_error`
(`crates/registry-scheduling/src/runtime.rs`) and
`a_command_other_than_serve_is_a_usage_error_that_reads_no_configuration`
(`crates/registry-scheduling/tests/usage_errors.rs`) hold the command line,
the second against the built binary.
`a_retained_policy_without_a_project_identity_is_refused_as_corrupt`
(`crates/registry-scheduling/tests/postgres_commitments.rs`) holds
publication and the records swap against PostgreSQL, and
`an_activation_refusal_is_a_domain_refusal_and_a_store_failure_is_operational`
(`crates/registry-schedulingctl/src/lib.rs`) holds how `schedulingctl`
reports it.

**Accepted residual.** Input older than v0.40.0 now meets a less specific
refusal. The usage error does not name `schedulingctl plan` and `apply`, and
the corrupt-database refusal does not say to start from a new database; its
suggested action is the one for a damaged database. The release notes of
the release that made each break, v0.36.0 and v0.40.0, carry the
instruction. The removed-key refusals remain.

## Original receipt observation

Threat: recovery submits a second effect after cancellation, expiry, or restore,
or accepts a different caller's receipt as evidence of its original command.
The receipt lookup uses current ordinary read authority, the original verified
issuer and subject, the exact operation key, and the existing canonical request
hash. It reads only retained successful receipts and never renders, writes business state,
replays, or creates an attempt. Task lineage already stored with the original
operation is preserved. A different standing identity gains no ownership.

Missing, changed, erased, expired, and non-success receipts all answer the
value-free `409 receipt.unresolved`. That response establishes no absence of
effect. A durable audit request precedes the database lookup and its response
precedes disclosure of the receipt. Payloads, keys, and raw identities never
enter these audit records. The focused PostgreSQL receipt tests exercise
ownership, exact-request refusal, retention, and unchanged product state.

Residual risk: receipt observation is not throttled, like every other
Scheduling route; Scheduling keeps no request budget of its own. An
authenticated caller that repeats it costs one bounded indexed lookup and its
audit records per request. This is accepted rather than given a read budget:
an operator bounds an authenticated flood at the deployment's ingress, as for
every other route.

## Scope defaults follow the maintained examples

Threat: an operator who omits `authentication.oidc.scopeClaim` or `readsScope`
gets a deployment that refuses every read its issuer's tokens were meant to
authorize, and nothing says why, so the fix that gets reached for is the
widest one at hand.

`scopeClaim` defaults to `scope` and `readsScope` to `scheduling:read`, the
values every maintained example, template, and native exchange already set
explicitly. `explainScope` defaults to `scheduling:explain`, the same colon
form, and the rule that the explain scope differs from the read scope is
unchanged. A deployment that relied on the earlier defaults
(`registry_scopes`, `scheduling-read`, `scheduling-explain`) now fails closed:
its readers receive `403 profile.not-authorized` until the file names the
claim and scope its issuer emits. The change still selects one claim and
one scope and never widens the match, but it can allow a token the earlier
defaults refused: one whose `scope` claim carries `scheduling:read` or
`scheduling:explain` while its `registry_scopes` claim did not carry the
earlier spelling. Such a token must still pass the issuer, audience, and
lifetime checks for this runtime, so only tokens minted for it qualify; an
issuer that puts different scopes in the two claims should name
`scopeClaim` explicitly.

A read or explain refusal for a missing scope logs one `info` line naming the
claim read, the scope expected, and the keys that select them. The line
carries configuration values only, never the caller's scopes, subject, or
token; the HTTP answer is unchanged and value-free. Tests:
`a_development_configuration_loads_and_exposes_its_defaults` pins the
defaults, `a_scope_refusal_names_the_expected_claim_scope_and_keys` pins the
sentence, and the existing profile-refusal tests in `auth.rs` still hold.

## Reminder events use the shared hook envelope

A reminder intent is delivered as the shared hook envelope observers receive,
with `content-type: application/json`. The envelope adds the appointment
record reference and revision as `subject` and a per-purpose `dataschema`; the
appointment identifier was already in `data`, so nothing new is disclosed.
`data` is the payload the runtime committed, unchanged. The optional bearer
credential `destinations.reminders.bearerTokenRef` and optional shared delivery
signature from `hmacSha256KeyRef` are independent. A receiver that requires
signed events verifies the exact request target, event metadata and body,
including the delivery timestamp and attempt. The intent identity and
idempotency key stay fixed across retries; a fresh attempt does not mint a
new notification. Event acceptance grants no appointment-read or message-send
authority.

`destinations.reminders.purposeUrls` may select separate endpoints for the
closed notification purposes. Every override must retain the fallback URL's
origin and satisfy the same URL restrictions. The shared bearer and signing
key therefore stay within one configured receiver origin. The runtime freezes
the request templates at activation, selects one by purpose, and uses its
exact target for both delivery and signing. Unknown purposes are refused.
Omitting the overrides preserves the existing destination; routing changes
neither dispatch identity nor retry and reminder-suppression rules. Different
receiver origins need separately authorized delivery arrangements.

`a_due_intent_renders_as_the_shared_hook_envelope` and the PostgreSQL dispatch
test pin the wire shape. The SEC-38 traceability row also names the URL refusal,
selected-target signature and stable-idempotency tests, plus native
confirmation and authored due-reminder journeys through Coordinator and
Messaging. Those journeys preserve the signed target without a re-signing
adapter. Messaging acceptance remains distinct from provider delivery.

## The task-grant status resource is named for what it binds

A `taskGrantStatus` entry names the audience its status credential is
requested for `statusResource` (was `caseworkResource`), because Coordinator
or an external task authority can answer grant status as well as Casework.
This is authorization configuration: the key selects the resource the
runtime's own status credential is issued for. The rename changes no
behavior. The value is read, validated as an absolute resource URI, and sent
exactly as before, and the old key is refused with `config.removed-key`
naming `statusResource` rather than read as an alias, so a file cannot carry
both spellings with different values. Tests:
`a_task_status_casework_resource_is_refused_naming_status_resource`, plus the
existing structural refusal tests that now use `statusResource`.

## One name and bound for the idempotency receipt window

`retention.attemptReceiptRetentionDays` is renamed
`retention.receiptRetentionDays`, the name BReg and Messaging use for the same
window, and its maximum narrows from 65535 to 365 days, BReg's bound. The old
key is refused naming the new one. The sweep, the default of 7 days, and what
a receipt holds are unchanged; a deployment that had set more than 365 days is
refused at startup and keeps raw caller identifiers for less time once it
lowers the value. `a_removed_runtime_key_names_the_key_that_replaced_it` and
the out-of-range cases in `config.rs` pin the name and the bound.


## Terminal dispatch metadata retention

The retention tick uses the existing receipt period for every delivered
outbox intent (confirmation, change, cancellation, reminder) and terminal hook
metadata. `PostgresStore::erase_terminal_dispatch`
bounds each table family to 256 rows and commits dependent deletions together.
Shared Dispatch rechecks terminal state and cutoff; Hooks requires completed
payload expiry for dead letters, locks state and shared events with SKIP LOCKED,
and deletes state, delivery metadata, then unreferenced events. Pending, leased,
retryable and uncertain work remains. Outbox local, failed and superseded
intents stay readable, whatever the intent's purpose. No migration credential or grant change is introduced.

The tests in the `terminal_retention` module in `tests/postgres_commitments.rs` cover cutoff boundaries,
protected row snapshots, shared siblings, receipt tombstones and repeated
cleanup. The batch test also injects a real dependent foreign key to require
rollback of all earlier deletions. Audit entries retain their independent
retention. Committed claims/history and actionable outbox retention remain
outside this change; terminal cleanup does not replace payload expiry auditing.

## Hook delivery identity from the activation record

**Decision and threat.** A hook worker must not deliver under a package that
is no longer active. The worker used to compare its scheduling id, policy
revision, and policy digest with the `scheduling_meta` row under `FOR SHARE`.
It now calls the shared `registry-platform-hooks` identity seam, which reads
the active row of `scheduling_activations` through
`registry-platform-activation` inside the same delivery transaction and
requires it to name the database id and package digest the worker was started
with. The policy is part of the package and changes only through an
activation, so a superseded policy is still caught, and a database id swap is
now caught too (see the tests below). Any mismatch, missing activation, or read failure is
`DeliveryError::Unavailable`, which sends nothing and audits nothing; the
reason is not carried.

**Locking.** The read is a plain snapshot read under a 5 second transaction
`lock_timeout`, and takes no advisory or row lock. An activation holds its own
exclusive lock and verifies retained deliveries on a second connection, so a
shared lock taken here could wait on it while it waits on the worker; a
migration lock held by an activation makes the attempt fail and retry instead.
Without the former `FOR SHARE`, an activation may commit between a claim's
check and its egress, which sends at most the batch already claimed under the
earlier package. That window existed before as well, because egress always
ran after the claim transaction committed; the finalize transaction checks
again and refuses.

**Capability set.** The runtime re-checks the compiled declarations against
`HookCapabilities::URL_ONLY` (url handlers, no `when`, no `principal`); the
policy shape already refuses those members, so this is defense in depth. A
refusal is `HookActivationError::UnsupportedCapability`, whose message leads
with the shared `hook.capability.unsupported` code.

**Tests.** `crates/registry-scheduling/tests/postgres_commitments.rs`:
`hook_delivery_stops_once_the_activation_record_names_another_package` (a
later activation for another package leaves the pending delivery unclaimed,
unsent, and unaudited),
`hook_delivery_is_refused_when_the_activation_record_names_another_database`
(the database id swap), and
`hook_delivery_is_refused_without_an_activation_record` (no activation row);
each of the last two also proves the delivery has no lease.
`crates/registry-scheduling/src/hooks.rs`:
`compile_refuses_a_when_condition_as_an_unsupported_capability`,
`compile_refuses_a_principal_as_an_unsupported_capability`, and
`compile_refuses_a_local_rhai_handler_as_an_unsupported_capability`.
`crates/registry-platform-hooks/src/capability.rs`:
`the_url_only_set_refuses_each_other_part_with_the_one_shared_diagnostic`.

## Delivery intents on the shared dispatch core

Threat: The outbox carries confirmation, change, cancellation, and reminder
intents to the operator's reminder destination after a commitment. A
hand-rolled claim, lease, and retry loop can send twice under a stale lease,
finish an intent another worker has since re-leased, or send a reminder for
an appointment that was cancelled or moved.

Enforcement: `scheduling_outbox` in
`crates/registry-scheduling/migrations/0200_scheduling.sql` is the
`registry-platform-dispatch` job table shape keyed by `outbox_id` and
`purpose`, with Scheduling's own columns and constraints added after it; a
row set aside must name its `last_failure_class`, and a delivered row names
none. `IntentStore` and `intent_policy()` in
`crates/registry-scheduling/src/runtime/intents.rs` give the dispatch core its
claim, lapsed-lease, and finish SQL and one frozen policy for every intent;
the runtime runs one `DispatchWorker` beside the serve loop. Scheduling keeps
the table name, the payload rows, the envelope rendering, the send, and the
retention erase. Observer hooks already ride the core through
`registry-platform-hooks` and are unchanged.

| Aspect | Hand-rolled loop | Dispatch core |
|---|---|---|
| Claim and lease | Up to 100 pending rows due by `due_at` and `next_attempt_at`, `ORDER BY due_at`, `FOR UPDATE SKIP LOCKED`; the claim adds one attempt and pushes `next_attempt_at` 600 seconds out as the lease | One row per claim, `pending` and due on the database clock, `ORDER BY next_attempt_at, outbox_id, purpose`; the lease lasts the attempt timeout plus 5 seconds and a finish is fenced by `lease_token`, `generation`, and `attempt` |
| Attempt timeout | 5 seconds | `attempt_timeout` 5 seconds, bound 5 to 5 seconds |
| Retry schedule | 30 seconds doubling, capped at 3600 seconds, a cap the eighth attempt never reached; `Retry-After` ignored | `RetrySchedule::Frozen` of 30, 60, 120, 240, 480, 960, and 1920 seconds; pause hints ignored |
| Maximum attempts and expiry | 8; no expiry | `maximum_attempts` 8; `expires_at` none |
| Terminal states | `delivered`, `local`, `failed`, `suppressed` | `delivered`; `cancelled` for a reminder superseded before any attempt; `dead-lettered` with `destination_unconfigured`, `destination_refused`, `delivery_failed`, `event_unrenderable`, `superseded`, or a quarantine class; `expired` for a quarantined row never attempted |
| Uncertain outcome | A send error is retried; a crash leaves the row to be reclaimed after the 600-second lease | `UncertainOutcome::Retry`: a lapsed lease counts as a failed attempt and waits the next back-off; a lapsed eighth attempt is dead-lettered |
| Receiver dedup | The envelope `id` is the `outbox_id` | Unchanged; `generation` stays 1 and `UNIQUE (outbox_id)` keeps one intent per identifier |
| Audit lifecycle | No audit event for intent delivery | Unchanged; dispatch operational events go to tracing only |

Behaviour that differs from the hand-rolled loop:

- A cancellation or reschedule moves the obsolete reminder from `pending`
  at attempt 0 to `cancelled` in its own transaction, through
  `registry_platform_dispatch::postgres::cancel_unattempted`, so no
  dispatcher claims it. A reminder already attempted or leased is left
  alone: `cancelled` keeps the core's meaning of never sent in that
  generation. For those, the transport reads the reminder's liveness under
  its lease with `Dispatcher::read_leased` immediately before the send and
  sets a reminder that no longer describes an active appointment at its
  current revision aside as `dead-lettered` with `superseded`, without a
  send. A lease that lapsed before that read starts no send.
- The lease lasts 10 seconds instead of 600 seconds per batch, and a lapsed
  lease waits the next back-off instead of being reclaimed as soon as it
  passes.
- Due time is judged on the database clock rather than the runtime's.
- A finish under a lease another worker has replaced returns an error the
  worker logs instead of updating zero rows silently.
- Column and state names follow the dispatch core. `undelivered_intents`
  maps `destination_unconfigured` to `local` and every other set-aside class
  but `superseded` to `failed`, so `schedulingctl intents` reports what it
  did. Scheduling applies only to a fresh database, so no migration carries
  old rows.

Verification: In `crates/registry-scheduling/tests/postgres_commitments.rs`,
`a_failing_reminder_intent_waits_out_its_back_off` pins the first two
back-offs, `a_claimed_intent_is_leased_and_its_outcome_is_fenced_by_the_lease`
holds one lease at a time, recovers a lapsed lease as a failed attempt, and
refuses a stale owner's finish,
`a_lapsed_final_attempt_is_set_aside_for_an_operator` dead-letters a lapsed
eighth attempt, `the_intents_nobody_will_deliver_are_readable_by_an_operator`
covers the unconfigured and exhausted branches,
`a_cancelled_appointments_reminder_is_cancelled_without_a_send` and
`a_reschedule_supersedes_the_obsolete_reminder_and_mints_its_replacement`
prove the transaction cancels an unattempted reminder and it is never sent,
`a_reminder_claimed_before_its_cancellation_is_set_aside_at_its_send` covers
the order claimed, cancelled, then sent,
`a_lapsed_dispatch_lease_starts_no_send` proves a lapsed lease sends nothing,
`an_unrenderable_intent_is_held_on_its_first_attempt_without_a_send` and
`an_unreadable_intent_is_quarantined_without_stalling_the_rows_behind_it`
cover the unrenderable and quarantine branches,
`due_intents_are_claimed_by_instant_then_identifier` pins the claim order, and
`a_dispatch_pass_delivers_retries_and_holds_by_what_the_destination_answers`
pins the refused, retried, and delivered outcomes. In
`crates/registry-scheduling/src/runtime/intents.rs`, unit tests hold the
migration to the dispatch core's DDL, the policy to its bounds and delays,
and every set-aside reason to its class.
`cancel_unattempted_withdraws_only_a_pending_job_never_attempted` in
`crates/registry-platform-dispatch/tests/postgres_dispatch.rs` proves the
cancel touches only a pending job at attempt 0.
`crates/registry-schedulingctl/tests/intents_postgres.rs` holds the operator
listing to the same states, and
`outbox_retention_uses_receipt_cutoff_for_every_purpose_and_preserves_actionable_work_and_tombstones`
ages out delivered, cancelled, and superseded rows on the receipt cutoff
while every other set-aside row stays.

Residual: Delivery stays at-least-once. A send whose response is lost is
retried under the same envelope `id`, so a destination that ignores it may
see an event twice. A reminder a dispatcher already holds when its
appointment is cancelled or moved waits for that send to be set aside. A
cancel or reschedule that commits between the liveness check and the send
still sends the stale reminder, and the receiver gets no ordering promise
across processes: that is inherent to at-least-once delivery. One worker
serves each runtime process.

## Cross-owner appointment detail and operational projections

### Threat

- A service or source manager uses detail authority for another service,
  location or retained manager, or turns that narrow grant into catalogue,
  list, history or operational access.
- A staff work list combines roles or expands beyond one configured service,
  location, resource set or time window. A continuation is reused by another
  caller, profile or query, or a current offering relabels an older booking.
- A detail, operational or attendance projection discloses contact, manager or
  staff identity, infers people from capacity units, or includes attendance
  without the operator selecting it.

### Enforcement and defaults

The ordinary appointment detail route admits retained owners or a verified
task grant carrying `appointment.read` for the stored appointment's service
and location. Source-managed appointments additionally require the exact
retained `identity.schedulingManager` value, the source issuer and fresh grant
status. This detail action opens no list, history, catalogue or operational
route. Its service and location authority is intentional and does not claim an
appointment-id binding.

Cross-owner work lists are off until the operator configures
`authentication.oidc.appointmentReadProfiles`. `authorize_operational_read` in
`crates/registry-scheduling/src/operational.rs` selects exactly one verified
profile scope and binds the caller identity, profile digest, normalized query,
service, location, effective resource set, time bounds and projection into the
read context and continuation. The store applies those predicates to every
page. Retained service and location labels come from the policy revision that
recorded the booking, and the claim ledger refuses a booking without them.

The closed operational projection vocabulary omits identity, contact, manager
and actor fields. Party counts remain booking facts and are never inferred
from allocation units. Attendance is absent unless the selected profile names
it, and then exposes the current visit's current observation without staff
identity. The separately configured attendance after-event uses the closed
`appointment.attendance-observed` trigger and its fixed minimized projection.

### Tests

`appointment_detail_accepts_its_explicit_grant_without_opening_other_reads` in
`crates/registry-scheduling/src/auth.rs` pins the dedicated detail profile.
`an_assisted_manager_is_selected_only_from_fresh_exact_source_authority` and
`assisted_manager_authority_is_bound_into_idempotency_and_retention` in
`crates/registry-scheduling/tests/postgres_commitments/booking_party.rs` pin
the source-managed boundary. The operational PostgreSQL tests
`operational_pages_require_one_profile_and_bind_every_authority_dimension`
and `a_later_offering_move_does_not_relabel_a_closed_appointment` pin profile,
continuation and retained-label behavior. The attendance tests
`attendance_is_off_by_default_and_explicit_in_operational_projection` and
`attendance_commit_captures_one_minimized_signed_after_event` pin opt-in
projection and the closed event payload. The traceability catalog records the
remaining focused proofs and does not assert that they ran.

### Accepted residuals

- A current `appointment.read` grant can read any appointment the caller names
  at its authorized service and location, subject to the retained manager rule
  for source-managed bookings. Institutions must grant it only to services
  whose workflow already selects the appointment.
- An operational profile intentionally discloses cross-owner bookings within
  its configured dimensions. An explicit `unrestricted` resource scope covers
  every resource at that one service and location; bounded time and projection
  rules still apply.
- Detail readers receive the current attendance observation with the ordinary
  appointment document. Operational readers receive it only when their profile
  explicitly selects attendance.

## Raw API connection authentication

Threat: a generic diagnostic command is mistaken for Scheduling authority, or
a credential selected for one connection is silently replaced on the request.

Scheduling retains no local caller session, so `schedulingctl api` does not
resolve `--client`. The operator selects a saved connection or an explicit
one-off URL. A saved connection may be anonymous, a referenced bearer, or a
renewable `private_key_jwt` client under the shared
[`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary).
That boundary owns endpoint confinement, automatic authorization, credential
resolution, redirects, proxies, bounds, and redaction; it carries no task
grant, catalogue scope, appointment ownership, or capacity authority.

The runtime continues to authenticate and authorize every protected request.
An anonymous connection reaches only routes the runtime already makes public.
`api_and_saved_connections_are_available_without_a_runtime_config` and
`raw_api_refuses_report_format_before_network_access` in
`crates/registry-schedulingctl/tests/api_cli.rs` pin the product surface. The
shared README names the saved bearer, `private_key_jwt`, and transport proofs.
These references do not assert an execution run here.
