# Choose a profile for each task

This small registry demonstrates one policy in several tasks: a clerk reads
records in assigned districts and edits labels on records they own; a supervisor
can edit labels across the registry; an auditor reads assigned history. An
action-only registrar creates records. A separate reviewed-record entity
requires independent review stages before a label can be patched.

The example uses synthetic identities. It is an offline configuration example,
not a login application or evidence of live identity-provider interoperability.
The identity provider authenticates callers and issues permissions and
assignments. BReg uses those claims to enforce the profile selected by the
application for each request. Naming a profile never adds permissions.

## Inspect the policy

Run from the repository root after building `bregctl`:

```sh
target/debug/bregctl check products/breg/examples/access-review/task-profiles
target/debug/bregctl explain access products/breg/examples/access-review/task-profiles
target/debug/bregctl explain change-requests products/breg/examples/access-review/task-profiles
```

The supervisor deliberately has `rowBoundaries: []`, and the auditor has history
access. Review these findings rather than using `--deny-findings` for this
project. The submitter can write its district boundary when drafting a request;
that field and every applied target must still satisfy the caller's district
assignment. No direct patch may change an existing record's district or owner.

| Task | Profile and permission | Limits |
| --- | --- | --- |
| Read assigned records | `clerk-reader`, `record:read` | District is in `assigned_districts`. |
| Edit owned records | `clerk-editor`, `record:edit-own` | District is assigned, owner equals the principal, only label is writable. |
| Supervise the registry | `supervisor`, `record:supervise` | All districts; edit record labels, create and read reviewed records. |
| Inspect history | `auditor`, `record:audit` | Assigned districts, selected fields, no writes. |
| Register a record | `registrar`, `record:register` | Invoke `register-record`; assigned district and owner equals principal; no direct entity operations. |
| Review a correction | Four `correction-*` profiles with separate permissions | Submitter owns the request; assigned request and target districts; reviewer and final approver differ from submitter and each other. |

The example deliberately uses two entities with different write policies.
`record` permits direct label edits. `reviewed-record` declares
`changeControl.requiredFor: [patch]`, so patches must arrive through an applied
correction. The supervisor can create and read reviewed records, but no profile
can patch them directly. A change-request effect requires its target operation
to be controlled; the same entity cannot offer both direct and reviewed patch
paths.

Every boundary in a grant must hold. Profiles are not merged. The clerk therefore
uses `clerk-reader` to read colleagues' records and `clerk-editor` to edit their
own. `clerk-reader` is the default on record get/list routes, while `correction-submitter`
is the default on shared request reads. Direct record patches have several possible profiles with no default, so the
application must name its intended profile. Each stage-specific review route
has one eligible profile here and selects it automatically. Neither default is a fallback after refusal.

## Preview admission

```sh
target/debug/bregctl explain access products/breg/examples/access-review/task-profiles \
  --scenario products/breg/examples/access-review/task-profiles/clerk-read.json
target/debug/bregctl explain access products/breg/examples/access-review/task-profiles \
  --scenario products/breg/examples/access-review/task-profiles/clerk-cannot-select-supervisor.json
```

The first scenario satisfies profile admission. The second lacks
`record:supervise`, so it is refused despite selecting the supervisor profile.
Both commands exit successfully because an explanation was produced; for
automation inspect `explanation.admitted` in `--format json` output.

Other scenario files cover owned editing, a supervisor, history, an auditor's
refused edit, and reviewer admission. No scenario contains a real token or
record. An admitted preview has not checked a row, verified a credential,
applied a mutation, or checked a workflow's current stage or actor exclusions.
The action-only grant appears under `actions` in `explain access --format json`
output, not in the plain-text report; the entity admission preview does not
simulate invoking it.

## Bind real identities and verify records

Configure `authorityClaims.principal: registry_principal` in the runtime and
issue a stable string identity with that name. For an ownership check, BReg
reuses that same value; a second identity-valued claim is unnecessary.
Issue `assigned_districts` as a JSON string array. Issue the permissions for the
selected task through the runtime's one configured permission claim, and use
`record-administration` as purpose, or `record-audit` for the auditor.

A real journey should prove that the clerk can read a colleague's record in
an assigned district but cannot patch it; that out-of-district records remain
inaccessible; that the supervisor can edit a label in either district; and that
the auditor can read history without editing. For the action, prove both a valid
registration and refusal for another owner or an unassigned district.

For a correction against a reviewed record, prove that a direct patch is
refused, that the submitter cannot approve, that the first
reviewer cannot approve the final stage even with its permission, and that a
different final approver can complete review. Changing profile names must not
change those decisions. Manual application requires its own permission and
checks the target's district again; it does not require a fourth independent
actor.
