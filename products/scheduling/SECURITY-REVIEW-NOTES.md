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
tokens, commits capacity inside PostgreSQL transactions, and writes an
audit journal. The threats this surface answers:

1. **A caller without a complete task grant books capacity.** The edge
   authenticates the bearer token against a pinned JWKS, requires the
   profile scope for every read and a separately configured explain scope
   for explanations, and requires a complete scheduling grant (service,
   location, actions) for every commitment. A partially formed grant set
   is refused as a credentials problem, never honoured partially.
2. **A token that was valid at the door commits after its grant lapsed.**
   The grant's expiry is re-checked inside the capacity transaction,
   immediately before the claim commits, against the same observed now the
   rest of the transaction decided under. The full bounds are matched once
   at the service before the transaction opens; re-reading them inside
   would only defend against narrowing at the issuer, which needs a
   revocation path this milestone does not have (matrix deferral
   SCHEDULING-DEF-01, recorded in the published reference).
3. **A deployment is reached over a public interface by accident.** The
   listener must bind a private address or an explicitly declared
   container network; anything else refuses to start.
4. **A commitment leaves no accountable trace.** Every ledger-decided
   commitment and refusal writes an audit row with a pseudonymized
   principal, and the audit rows chain by hash. A permission mismatch
   refused at the service, before the transaction opens, writes one too,
   so probing grant scope against the edge is visible in the journal; the
   answer itself stays the same closed refusal, naming neither the failing
   bound nor whether a grant was carried. The two changes that made that
   true are recorded below under "The audit journal".
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
  cursors only; appointments, history, outbox rows, and audit rows are
  never swept in this milestone (SCHEDULING-DEF-06, recorded in
  `RUNTIME-CONFIG.md`).
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

**The journal is published in the order it was written.** *Threat:* the
audit outbox carried no ordering column, and the query feeding the
publisher ordered by a random version 4 event identifier while its own
documentation said oldest first. The publisher appends what that query
returns to a hash chain, so the chain was internally consistent and
attested to a sequence the deployment never had. A chain that certifies
the wrong order is worse than no chain, because it is believed.
*Default:* the outbox carries its own recorded sequence, the pending query
reads in it, and the chain continues across a restart from its verified
tail rather than from whatever the first query after startup returns.
*Tests:* `the_audit_journal_is_read_in_the_order_it_was_written` and
`the_audit_chain_continues_across_a_restart`,
`crates/registry-scheduling/tests/postgres_commitments.rs`.

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

**B. A production deployment names the clients it admits.** *Threat:* an
absent `allowedClients` admitted every client the issuer verifies, so any
application in the issuer's realm could reach a Scheduling deployment.
*Default:* a non-loopback deployment refuses to start without a named
client list; development loopback stays permissive because it is not a
deployment an unrelated client can reach. *Test:*
`a_production_deployment_must_name_the_clients_it_admits`,
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
message names the member path (a document refused whole is reported at
`/`), carries serde's reason with its line and column, and strips the
offending value out of any `invalid type:` or `invalid value:` clause,
keeping only the shape word. *Tests:*
`a_runtime_document_refused_whole_is_reported_at_the_root`,
`a_refused_value_never_survives_the_clause_that_names_it`,
`a_runtime_document_the_reader_stops_on_names_the_line_and_column`,
`a_rejected_runtime_member_names_the_cause_without_the_value`,
`a_refused_authored_policy_names_the_member_and_the_cause` (all
`config.rs`), plus the standing
`typed_parse_path_does_not_echo_the_rejected_value`
(SCHEDULING-SEC-13).

**H. The package manifest is a different document from the policy it
identifies.** *Threat:* one `apiVersion` and `kind` pair named both
documents, so neither reader could refuse the other's document on its
declared names, and the package identity digest folded in a pair that did
not describe it. *Default:* the manifest declares its own pair, which the
identity digest binds; a document carrying the authored policy's names
never verifies as a package identity. *Tests:*
`a_manifest_wearing_the_authored_policy_names_is_refused` with
`a_package_manifest_is_a_different_document_from_the_policy_it_identifies`,
`crates/registry-scheduling/src/config.rs`.

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

## Known deferrals

The matrix records four deferrals with their compensating controls.
SCHEDULING-DEF-01 is stated in threat 2 above; the other three are
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
