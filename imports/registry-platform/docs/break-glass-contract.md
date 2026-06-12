# Break-Glass Approval And Emergency Posture Contract

This note defines the shared break-glass and local-approval contract for Registry
runtimes that accept governed configuration, and the posture fields that report
emergency semantics. It is the design baseline for cutting follow-up
implementation issues in Registry Relay and Registry Notary without re-litigating
shared semantics.

The deliverable is a contract, not new infrastructure. It builds on primitives
that already exist in `registry-platform-ops`: `BreakGlassApproval`,
`LocalOperatorApproval`, `FileAntiRollbackStore`, `FileLocalApprovalStore`, and
the verifier-owned `BreakGlassRateLimit` policy. It does not propose a central
approval service or a shared network store. Per-product local files remain the
only durable approval state.

## Scope And Non-Goals

In scope:

- The semantic difference between ordinary admin authentication, local operator
  approval, and emergency break-glass approval.
- Whether approvals may be stored separately from the apply request body, and
  the rules a durable approval record must satisfy.
- Approval expiry and closure semantics.
- Emergency change-class binding.
- Where rate-limit policy is owned.
- Posture fields that report emergency semantics without leaking reason text.
- Product audit requirements for emergency applies.

Out of scope:

- A central approval service, a shared approval database, or any cross-node
  approval transport. Coordination across nodes stays a product concern, as the
  governed-configuration note already states for anti-rollback state.
- A two-person workflow engine. This note decides whether two-person approval is
  in the contract and how it is expressed, not a UI or ticketing integration.
- New cryptographic primitives. Signing, canonicalization, and hashing stay as
  they are.

## Relationship To The Current Model

This contract **confirms and extends** the current model. It does not replace it.

It confirms the inline `LocalOperatorApproval` data type and its validation
rules, the reference-based `FileLocalApprovalStore` lookup, the verifier-owned
`BreakGlassRateLimit`, and the anti-rollback acceptance order. These already work
and are not re-opened.

It extends the model in two narrow ways:

1. It makes the durable, reference-based approval store the contract path for
   break-glass approval too, not only for local operator approval. Today
   break-glass is supplied inline as a full `BreakGlassApproval` in the request
   body, while local approval is supplied as a reference and loaded out of band.
   This note closes that asymmetry at the contract level so a follow-up can move
   break-glass to the same durable pattern.
2. It adds posture fields that report emergency-apply semantics and an open
   exception window, which the current posture summary does not express.

One naming clarification carries through the rest of this note. The struct named
`LocalOperatorApproval` is the **durable approval record type** used by both the
local-approval path and (after the follow-up) the break-glass path. The struct
named `BreakGlassApproval` is the **current inline emergency-approval request
type**. The contract keeps both type names; it changes how break-glass approval
records are sourced, not the meaning of either type.

## Three Distinct Gates

A governed apply passes through three independent gates. They are not
substitutes for each other, and an emergency apply still passes all three.

1. **Ordinary admin authentication.** The transport-level check that the caller
   may reach the admin apply route at all. In Relay this is the admin auth
   layer; in Notary it is the `ADMIN_SCOPE` evidence principal check. It answers
   "may this caller call apply", nothing more. It never waives a chain check,
   never grants emergency semantics, and is required for every apply including
   verify and dry-run.

2. **Local operator approval.** A site-local acknowledgement that a specific
   change class for a specific config transition is allowed to proceed on this
   node. It is bound to `approval_reference`, `change_class`, `config_hash`, and
   `previous_config_hash`. It is the normal path for changes that need an
   explicit local sign-off (for example a Notary root transition or client-auth
   change). It does **not** waive the `previous_config_hash` chain check; the
   approval must match the proposal's previous hash.

3. **Emergency break-glass approval.** An emergency path that waives **only** the
   `previous_config_hash` chain check, and nothing else. It is bound to an
   `emergency_change_class` that must appear in the bundle's declared change
   classes. It is the only gate that grants emergency semantics, and it is the
   only gate surfaced as emergency in posture.

The practical distinction: a missing or stale chain link is a normal rejection,
unless an explicit emergency break-glass approval authorizes proceeding past it.
Local operator approval authorizes a sensitive change class on a healthy chain;
break-glass approval authorizes proceeding when the chain itself is broken.

## Direction Decisions

Each Direction bullet from the ticket is answered with a decision and the code
behavior it rests on.

### Separate Local Break-Glass Approval Records

**Decision: yes, and this becomes the contract path.** Break-glass approval
records may and should be stored in a durable local approval store, separate from
the apply request body, the same way local operator approval already is.

Today `FileLocalApprovalStore::load_for_apply` resolves a `LocalOperatorApproval`
from a verifier-owned JSON file at `local_approval_state_path`, keyed by
reference, change class, config hash, and previous config hash. The apply request
carries only `local_approval_reference`. Break-glass, by contrast, accepts the
full `BreakGlassApproval` inline in the request body. The contract treats the
reference-and-store pattern as the durable form for both. The inline
`BreakGlassApproval` stays valid for the local admin-only emergency path, but a
durable break-glass record loaded by reference is the form a two-person or
delegated workflow targets.

### Two-Person Or Delegated Approval Workflows

**Decision: expressed as durable approval records with two named approvers, not
as a workflow engine.** The contract requires the durable approval record to be
able to carry more than one approver identity and to require, by verifier-owned
policy, that an emergency change class needs at least two distinct approvers.

This mirrors how trust roots already forbid single-signer production roles for
high-risk change classes. The `RegistryTrustRoot` model requires at least two
signers for a high-risk change class in production. The approval record applies
the same shape at the local approval layer: an emergency or high-risk change
class may be configured to require two distinct approver identities in the
durable record before the verifier accepts it. The verifier checks the count;
the people, tickets, and routing are out of scope. The current single-operator
`approved_by` field is the one-person case of this rule.

### Approval Expiry And Closure Semantics

**Decision: keep absolute expiry, add explicit closure tied to acceptance and to
the chain.** Every approval already carries `expires_at_unix_seconds` and is
rejected once `expires_at_unix_seconds <= now`. The contract keeps that.

Closure is defined as follows:

- An approval is **consumed** when it is accepted for a specific sequence and
  config hash. The anti-rollback store already records each acceptance in
  `BreakGlassState` or `LocalApprovalState` with its sequence, config hash, and
  expiry. A durable approval record is single-use against the transition it
  authorizes: once the matching transition is accepted, the same record must not
  authorize a different `config_hash` or `previous_config_hash`.
- An approval is **expired** when wall-clock time passes `expires_at_unix_seconds`.
  Expired records are inert and must be rejected before acceptance.
- An emergency **exception window** is open while any accepted break-glass
  acceptance still has `expires_at_unix_seconds > now`. The window closes when the
  last such acceptance expires. This is the value posture reports (see Posture
  Fields). Closure is purely time-based; there is no separate "close" mutation a
  caller can replay.

The store already prunes acceptances outside the rate-limit window during
enforcement. The contract adds no new persisted closure state; the window state
is derived from existing acceptance records.

### Emergency Change-Class Binding

**Decision: confirm the current binding and require it for the durable path too.**
A break-glass approval must name an `emergency_change_class`, and the bundle's
declared `change_classes` must contain it. Relay and Notary already enforce this
in `require_break_glass_emergency_change_class`: if the approval's
`emergency_change_class` is not in the resolved bundle's change classes, the
apply is rejected as `rejected_break_glass`.

The contract carries this binding into the durable record unchanged. A durable
break-glass record names exactly one emergency change class, and the verifier
binds it to the bundle the same way the inline form is bound today. An emergency
approval for one change class must never authorize a different change class.

### Rate-Limit Behavior Owned By Local Verifier Policy

**Decision: verifier-owned policy is the contract; request-supplied policy is a
compatibility artifact and stays disallowed in the admin path.** Rate-limit
policy lives in operator config (`ConfigTrustConfig.break_glass_rate_limit`,
default one acceptance per 3600 seconds) and is passed to
`FileAntiRollbackStore::with_break_glass_rate_limit`. Both Relay and Notary
already reject any apply request that carries `break_glass_rate_limit` inline,
returning `rejected_break_glass`, so a request cannot loosen the limit.

The store's `AntiRollbackProposal.break_glass_rate_limit` compatibility field
remains only for older non-admin callers and must stay empty on the admin path.
When a store has a configured policy, a mismatching proposal policy is rejected
rather than honored. The contract states this as a rule: the rate-limit identity
and window are verifier-owned, never request-owned, for both break-glass and
local approval. The follow-ups should treat the proposal-side field as slated for
removal at the next breaking revision.

### Posture Fields That Indicate Emergency Semantics Without Leaking Reason Text

**Decision: add a redaction-safe `configuration.emergency` block.** See the
Posture Fields section for the schema. The block reports whether the last
accepted apply used emergency semantics and whether an exception window is open.
It carries the emergency change-class name, which is already public posture
vocabulary, and time fields. It never carries `reason`, `approved_by`, or
`approval_reference`, so no operator-supplied free text reaches posture.

### Product Audit Requirements

**Decision: emergency applies must emit a redacted audit event through the shared
audit primitive, and the posture exception window must be reconstructable from
audit.** Both products already attach break-glass and local-approval context to
the config audit record and report the detailed `ApplyReportResult`
(`rejected_break_glass`, `rejected_local_approval`, and so on). The contract makes
the following explicit:

- Every emergency break-glass apply, accepted or rejected, emits an audit event
  through `registry-platform-audit` (Security Principle 9), with reason and
  approver identities redacted or hashed per the audit redaction rules. Raw
  reason text must never reach the audit sink unredacted.
- The audit event records the non-secret facts needed to reconstruct the posture
  exception window: emergency change class, sequence, config hash, acceptance
  time, and expiry. These are the same fields already held in
  `BreakGlassAcceptance`.
- Rejected emergency attempts are audited with the rejection result code so a
  reviewer can see denied break-glass attempts, not only successful ones.

## Storing Approvals Outside The Request Body

**Decision: yes for both approval kinds; required for break-glass under any
multi-approver or delegated policy.**

The durable approval record is a verifier-owned local file, loaded by reference,
matching the existing `FileLocalApprovalStore` contract:

- The apply request carries a reference, not the approval body. For local
  approval this is `local_approval_reference` today. For durable break-glass the
  follow-up adds the same shape: a reference that resolves a stored
  break-glass record.
- The store resolves the record by reference, change class, config hash, and
  previous config hash, and validates it (non-empty operator, reason, reference,
  and rate-limit identity fields; correct hashes; not expired) before the
  proposal is built. A request cannot inject approver identity, reason, expiry,
  or rate-limit policy that was not written to the verifier-owned store.
- Inline `BreakGlassApproval` in the request body remains supported for the
  single-operator local emergency path, because it is already shipped and is the
  simplest path for a lone on-call operator. It cannot satisfy a two-approver
  policy, because a request body is caller-controlled and cannot prove two
  distinct approvers acknowledged out of band. Two-approver and delegated
  policies therefore require the durable store form.

The store path is what makes two-person approval meaningful: the second approver
writes to the verifier-owned record out of band, and the apply caller only names
it. The request can never assert approvals the store did not record.

## Posture Fields

The posture additions are specified at schema level against
`registry.ops.posture.v1`, consistent with the deployment-profile posture work.
They follow the existing conventions: `snake_case`, `additionalProperties:
false`, enums where the value space is closed, and no free-text reason fields.

### Emergency Apply Indicator And Exception Window

A new optional `emergency` object is added under the existing `configuration`
object. It is omitted when the runtime has never accepted an emergency apply.

```json
{
  "$defs": {
    "configuration_emergency": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "last_apply_emergency",
        "exception_window_open"
      ],
      "properties": {
        "last_apply_emergency": {
          "type": "boolean"
        },
        "last_emergency_change_class": {
          "type": ["string", "null"],
          "minLength": 1
        },
        "last_emergency_at": {
          "anyOf": [
            { "$ref": "#/$defs/rfc3339" },
            { "type": "null" }
          ]
        },
        "exception_window_open": {
          "type": "boolean"
        },
        "exception_window_expires_at": {
          "anyOf": [
            { "$ref": "#/$defs/rfc3339" },
            { "type": "null" }
          ]
        },
        "open_exception_count": {
          "type": "integer",
          "minimum": 0
        }
      }
    }
  }
}
```

The `configuration` object gains one optional property:

```json
{
  "configuration": {
    "properties": {
      "emergency": { "$ref": "#/$defs/configuration_emergency" }
    }
  }
}
```

Field meaning and source:

- `last_apply_emergency`: true when the most recent accepted apply used a
  break-glass acceptance. False when the last accepted apply was an ordinary or
  local-approval apply. Derived from whether the last accepted sequence is
  present in `BreakGlassState`.
- `last_emergency_change_class`: the `emergency_change_class` of the last
  emergency apply, or null. This is product-defined change-class vocabulary, the
  same vocabulary already exposed in bundle metadata, so it is posture-safe.
- `last_emergency_at`: RFC3339 timestamp of the last emergency acceptance, or
  null. Derived from `BreakGlassAcceptance.accepted_at_unix_seconds`.
- `exception_window_open`: true while any recorded break-glass acceptance still
  has `expires_at_unix_seconds > now`. This is the open-exception-window signal
  the ticket asks for.
- `exception_window_expires_at`: the latest `expires_at_unix_seconds` among open
  acceptances, as RFC3339, or null when no window is open. Tells an operator when
  the emergency posture clears on its own.
- `open_exception_count`: the number of currently open break-glass acceptances.
  Lets a dashboard show more than one open window without enumerating reasons.

None of these fields carry `reason`, `approved_by`, or `approval_reference`. The
emit-only sensitivity-tier filter keeps this block in both the default and
restricted posture tiers, because every field is already non-secret; the
allowlist for the default tier must include the `configuration/emergency`
pointers so the block survives default-tier filtering.

### Optional Emergency Deployment Finding

An open exception window may also be surfaced as a deployment finding so it shows
up in the same place as other posture findings. This is optional and additive; a
runtime may report the `configuration.emergency` block alone. When a finding is
emitted, it uses the existing `deployment_finding` shape and a finding id that
matches the `finding_id` pattern `^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_-]*)*$`, for
example:

```json
{
  "id": "config.emergency.exception_window_open",
  "severity": "finding_warn",
  "status": "active"
}
```

The finding carries no reason text. It is a flag that an operator should review
the durable approval store and audit log, where the redacted reason lives.

## Preserved Fail-Closed Rules

The contract preserves the existing fail-closed rules. None of them are waived by
either approval path, except the one explicit waiver break-glass already grants.

- **Signed input.** TUF verification, trust-root authorization, and product
  config validation run before any approval is consulted. Break-glass waives
  none of these.
- **Authorized emergency change class.** A break-glass approval is rejected
  unless its `emergency_change_class` is among the bundle's declared change
  classes.
- **Monotonic sequence.** Bundle sequence must strictly increase, and TUF root
  version must be non-decreasing. Break-glass waives neither.
- **Local rate limiting.** Verifier-owned `BreakGlassRateLimit` is enforced per
  rate-limit identity for both break-glass and local approval. Request-supplied
  rate-limit policy is rejected on the admin path.
- **Expiry.** Every approval is rejected once `expires_at_unix_seconds <= now`.
- **Redacted audit.** Emergency applies emit redacted audit events; raw reason
  text never reaches the sink, and PII-bearing identifiers are hashed or redacted
  before envelope construction.

The single, explicit, and bounded waiver remains: a valid break-glass approval
waives **only** the `previous_config_hash` chain check, for **only** the bound
emergency change class, within the verifier's rate limit and the approval's
expiry. Everything else fails closed.

## Open Questions

These are flagged for review and do not block cutting the follow-up issues. The
follow-ups can pick a default and note it.

1. **Two-approver field shape.** The contract requires the durable record to
   carry more than one approver and a verifier-owned minimum count, but it does
   not fix the field name or whether the count lives on the record or in
   `ConfigTrustConfig`. Proposed default: a `required_approver_count` in
   verifier config per emergency change class, plus an `approvers` array on the
   durable record, with the existing `approved_by` retained as the first
   approver for the one-person case. To be confirmed when the durable break-glass
   record type is added to `registry-platform-ops`.
2. **Whether to keep inline `BreakGlassApproval` long term.** This note keeps it
   for the single-operator path. If every deployment that uses break-glass is
   expected to adopt the durable store, the inline form could be deprecated at
   the next breaking revision alongside the proposal-side rate-limit field. Left
   open because removing it is a breaking change with no current forcing
   function.
3. **Default-tier posture allowlist entries.** The `configuration/emergency`
   pointers must be added to the default posture allowlist fixture so the block
   is not filtered out at the default tier. The exact pointer list is mechanical
   and belongs with the schema change, but it is called out here so it is not
   missed.

## Appendix: Draft Follow-Up Implementation Issues

These are drafts to be reviewed alongside this note. They are written so they can
be cut as-is once the contract is accepted. Do not treat them as filed issues.

### Draft Issue: Relay durable break-glass approval store and emergency posture

**Title:** Relay: durable break-glass approval records and emergency posture
fields

**Summary**

Adopt the durable, reference-based approval store path for break-glass in the
Relay governed-config admin API, matching the existing `local_approval_reference`
pattern, and emit the emergency posture fields defined in the break-glass
contract. This closes the inline-versus-stored asymmetry for break-glass without
adding any central service.

**Scope**

- Accept a stored break-glass approval by reference on the apply request, loaded
  from a verifier-owned store keyed by reference, emergency change class, config
  hash, and previous config hash, validated before the proposal is built. Keep
  the existing inline `break_glass_approval` for the single-operator path.
- Keep rejecting any request-supplied `break_glass_rate_limit` on the admin path.
  Keep verifier-owned `ConfigTrustConfig.break_glass_rate_limit` as the only
  source of rate-limit policy.
- Enforce a verifier-owned minimum approver count for emergency change classes
  when the durable record form is used. A single inline approval cannot satisfy a
  two-approver policy.
- Populate the new `configuration.emergency` posture block:
  `last_apply_emergency`, `last_emergency_change_class`, `last_emergency_at`,
  `exception_window_open`, `exception_window_expires_at`, and
  `open_exception_count`, derived from `BreakGlassState` and the last accepted
  sequence. Add the matching pointers to the default-tier posture allowlist.
- Emit a redacted audit event for every emergency apply, accepted or rejected,
  through `registry-platform-audit`, with reason and approver identities redacted
  or hashed.

**Out of scope**

- Any central or networked approval store. Per-node local file only.
- A two-person workflow engine, ticketing, or UI. The verifier checks the
  approver count; routing is external.

**Acceptance criteria**

- A break-glass apply can be driven entirely by a stored record named by
  reference, with no approval body in the request.
- A request that supplies `break_glass_rate_limit` is rejected as
  `rejected_break_glass`.
- An emergency change class configured to require two approvers rejects a
  single-approver durable record and rejects an inline approval.
- Posture reports `configuration.emergency` with an open exception window after a
  break-glass apply and clears it once all acceptances expire, with no reason
  text present in any tier.
- The emergency change class in the approval must match the bundle's declared
  change classes, unchanged from current behavior.

**Fail-closed checks preserved**

Signed input, authorized emergency change class, monotonic sequence, local rate
limiting, expiry, and redacted audit, per the break-glass contract. Break-glass
still waives only the `previous_config_hash` chain check for the bound change
class.

### Draft Issue: Notary durable break-glass approval store and emergency posture

**Title:** Notary: durable break-glass approval records and emergency posture
fields

**Summary**

Adopt the durable, reference-based approval store path for break-glass in the
Notary governed-config apply route, matching the existing per-change-class
`load_local_approval` pattern, and emit the emergency posture fields defined in
the break-glass contract.

**Scope**

- Resolve a stored break-glass approval by reference using the same
  `FileLocalApprovalStore` contract Notary already uses for local approvals at
  `local_approval_state_path`, keyed by reference, emergency change class, config
  hash, and previous config hash, validated before the proposal is built. Keep
  the existing inline `break_glass_approval` for the single-operator path.
- Keep the `ADMIN_SCOPE` evidence-principal check as ordinary admin
  authentication, distinct from approval. Authentication must remain required for
  every apply, including emergency apply.
- Keep rejecting request-supplied `break_glass_rate_limit`; keep verifier-owned
  `ConfigTrustConfig.break_glass_rate_limit` as the only rate-limit source.
- Enforce a verifier-owned minimum approver count for emergency change classes
  for the durable record form. Notary already gates root transitions and
  client-auth changes on local approval; emergency break-glass over a broken
  chain uses the same durable record shape with the emergency change-class
  binding.
- Populate the `configuration.emergency` posture block from `BreakGlassState` and
  the last accepted sequence, with the same fields as Relay, and add the matching
  default-tier posture allowlist pointers.
- Emit a redacted audit event for every emergency apply, accepted or rejected.

**Out of scope**

- Any central or networked approval store. Per-node local file only.
- Federation-wide emergency coordination. Each node owns its own approval store
  and posture, as anti-rollback state already is per node.

**Acceptance criteria**

- A break-glass apply can be driven entirely by a stored record named by
  reference, with no approval body in the request, for the bound emergency change
  class.
- `ADMIN_SCOPE` is still required for emergency apply; an unauthenticated or
  unscoped caller is rejected before any approval is consulted.
- A request that supplies `break_glass_rate_limit` is rejected as
  `rejected_break_glass`.
- An emergency change class configured to require two approvers rejects a
  single-approver durable record and rejects an inline approval.
- Posture reports `configuration.emergency` with an open exception window after a
  break-glass apply and clears it once all acceptances expire, with no reason
  text present in any tier.

**Fail-closed checks preserved**

Signed input, authorized emergency change class, monotonic sequence, local rate
limiting, expiry, and redacted audit, per the break-glass contract. Break-glass
still waives only the `previous_config_hash` chain check for the bound change
class.
