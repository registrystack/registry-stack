# Native persisted field patterns

A persisted `string` or `text` field can declare `pattern` using PostgreSQL's
native advanced regular-expression syntax. PostgreSQL 15 or newer remains the
minimum version. There is no second regular-expression engine in BREG.

```yaml
fields:
  - id: identifier
    type: string
    maxLength: 13
    required: true
    classification: restricted
    pattern: '^[0-9]{13}$'
```

This example accepts exactly 13 ASCII digits, preserves a leading zero, and
rejects whitespace, Unicode digits, and embedded or trailing newlines. A string
is a suitable representation when leading zeros belong to the value. The rule
does not implement a checksum or identify a national identifier system.

The native `~` operator uses the authored expression unchanged. There is no
implicit anchoring, case conversion, or flag rewriting. An unanchored expression
matches a substring. Native options embedded in the expression retain their
PostgreSQL meanings. Requiredness remains separate: SQL null passes the pattern
check wherever the field or governed request-detail retention permits null.
An empty string is matched normally, and an empty pattern is valid PostgreSQL
syntax. Derived fields, action inputs, and other field types cannot declare
`pattern`; use a persisted target field for storage integrity.

An expression is limited to 4096 UTF-8 bytes and cannot contain NUL. Values keep
the existing field bounds: `string.maxLength` is at most 1,000,000 characters;
`text.maxLength` is at most 10,000,000 characters. The HTTP request, transaction,
and database statement deadlines continue to bound execution, including native
regex evaluation. A pathological expression can exhaust those limits. Review
and schema-test expressions against representative values before activation.
Runtime callers supply values, never expressions.

## Authoring and verification

`bregctl check <project>` performs offline structural checks and generates safely
quoted PostgreSQL SQL. It cannot establish PostgreSQL expression syntax or
existing-data conformance. It reports `field.pattern.unverified_offline` for each
pattern at its authored field path. These are advisory findings unless
`--deny-findings` is selected. Use the normal PostgreSQL-backed `bregctl test <project> --runtime-config <config>
--credentials <credentials> --database-id <database-id> --output <receipt.json>`
and package workflow before signing. The compiled installer explicitly evaluates
each native expression even when all fixture tables are empty. An invalid
expression refuses schema-test and installation. Schema-test and activation report
`field.pattern.syntax_invalid` at `entities[<id>].fields[<id>].pattern`, using
authored identifiers and a repair hint without including the expression or raw
database diagnostic. A failed activation keeps its exact target pinned in
maintenance. Invalid syntax cannot be repaired by changing that target's bytes:
restore the operator's pre-activation backup, correct the expression, and repeat
schema-test, packaging, signing, and activation. No command clears failed
maintenance to bypass this recovery.

The compiled effective model preserves the expression. Caller-filtered operation
metadata exposes it under `storageValidation` with `kind: postgresql-are` as
specified in [metadata.md](metadata.md). Generated JSON Schema and OpenAPI value
schemas do not publish a standard `pattern`, because their regex semantics are
different.

A named database CHECK enforces the rule for every current-row writer, including
direct CRUD, atomic batches, actions, reviewed application, and authorized SQL.
Ordinary CRUD does not invoke an action handler. A rejected SQL mutation rolls
back with its transaction. Direct writes and immediate actions return HTTP 409
with `code: mutation.conflict` and the authored entity and field admitted by
their write contract. Repair the submitted value before trying again; retrying
the unchanged request cannot make the value conform. HTTP 409 does not promise
that a conflict is transient. Change-request application returns the existing
generic conflict because application authority does not grant target-field
disclosure. No response includes stored values, physical table names, constraint
names, or raw PostgreSQL diagnostics.

## Package evolution

Every pattern check has a stable identity derived from its entity and field,
independent of the expression. Its physical-name inventory member is
`pattern:<field-id>`. The generated schema fingerprint covers the native CHECK.

Adding a rule emits `field_pattern_added`, classified `compatible_additive` like
existing added CHECK constraints. This classification permits the compiler-owned
DDL path; it does not promise that existing rows or future writes satisfy the
new rule. PostgreSQL validates every existing row before the addition commits.
A failure leaves the old package active and the target pinned in maintenance.
Activation reports `field.pattern.existing_rows_invalid` at the authored field.
Correct the violating data using the documented operator recovery procedure,
then retry the exact target. A successful future write alone does not validate
the preexisting rows.

Adding or replacing the validated CHECK takes an `ACCESS EXCLUSIVE` table lock
and scans existing rows. Plan a maintenance window around the table size and
expression cost, including readers and writers that may already hold locks.
The lock is held until the migration transaction ends. Rehearse with
representative data, and size
`operationalTimeouts.migrationStatementMilliseconds` for lock acquisition and
the full validation scan. `migrationLockMilliseconds` bounds each lock wait;
keep it shorter than the statement timeout when a separate lock-wait limit is
useful. Reviewed steps use their packaged `lockTimeoutMs` and
`statementTimeoutMs` bounds. A timeout leaves the same maintenance and recovery
interlock. See PostgreSQL's [ALTER TABLE locking and validation](https://www.postgresql.org/docs/18/sql-altertable.html)
and [statement and lock timeouts](https://www.postgresql.org/docs/18/runtime-config-client.html).

Changing or removing a rule emits `field_pattern_changed` or
`field_pattern_removed`, classified `destructive_or_irreversible` under the
existing reviewed migration contract. This includes loosening: the compiler does
not attempt to prove containment between two regex languages. A reviewed change
covers the authored field and its implicit `pattern:<field-id>` constraint;
reviewed SQL drops the existing check and installs the candidate check when one
remains. Use one transactional `ALTER TABLE` statement with `DROP CONSTRAINT`
and `ADD CONSTRAINT` clauses and a validated CHECK, not `NOT VALID`. The existing rehearsal, backup binding, exact catalog
fingerprint, and recovery requirements still apply. No orphan constraint should
remain after removal.

Entity patterns also bind immediate-action and change-request fingerprints.
Unchanged patterns preserve their existing contracts. A relevant changed pattern
makes a pending frozen proposal incompatible. Use the existing authorized rebase,
resubmission, and configured review process; activation does not silently rewrite
proposal values or rerun their computation.

Governed request-detail clearing can null eligible retained intake fields even
when their normal create contract requires a value and declares a pattern.
This remains separate from retained-history erasure, which does not rewrite the
current row.
