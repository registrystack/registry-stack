# Current membership access

A read profile can require a current active membership in the organization,
program, or team responsible for a record. Memberships are ordinary governed
records. An authorized steward creates or deactivates them through the normal
mutation API; the reader keeps the same identity token.

For example, a facility stores `organization`, a reference to an `organization`
entity. A separate `membership` entity stores an `organization` reference,
a string `principal`, and a Boolean `active`. Its optional descriptive fields
can remain private. Add the boundary to the facility's read grant:

```yaml
accessProfiles:
  - id: member
    principalClaim: principal
    requiredScopes: [records:read, membership:use]
    permissions:
      - entity: facility
        rowBoundaries: []
        operations: [get, list, lookup, snapshot, revisions]
        readableFields: [label]
        filterableFields: [label]
        sortableFields: [label]
        allowCount: true
        revisionAccess: true
        lookups:
          - selector: label
            valueOrigin: request
        membershipBoundaries:
          - field: organization
            membershipEntity: membership
            membershipKeyField: organization
            principalField: principal
            activeField: active
```

The `label` lookup selector must already be declared on the facility entity.
The two organization fields must be stored references to the same entity.
`principalField` must be a stored string or text field and `activeField` a
stored Boolean. Only active-lifecycle membership rows with `active: true` and
an exact match to the profile's verified principal grant access. A missing
membership, null value, inactive membership, or other principal does not.
Configure a stable identity claim from a trusted issuer; do not accept caller
submitted principal values as authority.

Every listed membership boundary and ordinary `rowBoundaries` predicate must
hold. Declare `rowBoundaries` explicitly even when membership is the only row
restriction; `rowBoundaries: []` adds no direct claim predicate and leaves the
membership checks in force. Up to eight membership boundaries are supported.
The declared fields
are authorization inputs, not an additional readable-field grant. Anonymous
profiles cannot use membership boundaries. The root profile must satisfy the
membership entity's mandatory scopes and purposes. The current boundary does
not carry additional direct row requirements from that source, so a membership
entity with mandatory `rowBoundaries` is rejected at compilation.

The complete authored model is in
[`organization-membership-access/registry.yaml`](fixtures/organization-membership-access/registry.yaml).
Run `bregctl check products/breg/fixtures/organization-membership-access`
from the repository root.
It also shows separate steward grants and an index on principal, organization,
and active status. The same boundary compiles for facility and document
registries without new server code.

## Revocation and history

Authorization queries read current membership records in PostgreSQL. A new
request issued after a membership deactivation commits is denied or returns an
empty authorized collection, including counts, lookups, and cursor continuations.
An already running read may finish from the statement snapshot that preceded
revocation. There is no token membership cache, external authorization service,
or registry-wide authorization lock.

Snapshots and revisions compare the retained record's organization with
**current** memberships. The historical membership state cannot restore access.
Deactivation removes access to those historical records as well. Moving a
facility to another organization does not by itself remove access to its older
revisions from members of the previous organization. This preserves the ordinary
historical row-boundary contract; current-owner-only history is a different
policy and is not implied by this feature. Erased history remains unavailable.

## Processing and supported operations

PostgreSQL enforces the predicate through generated `SECURITY INVOKER`
functions and forced row-level security. Each generated PL/pgSQL function saves
the prior authorization context, enables only its matching membership probe,
and restores the context before returning. Its exception block rolls back the
local context on errors. It does not grant direct membership endpoints or derived views
access to private membership records. The existing logical source views retain
`security_invoker` and `security_barrier` settings. No additional database role
or RLS bypass is required. PostgreSQL 15 remains the minimum for this surface;
other enabled features can require a newer supported version.

Membership profiles support get, list, count, lookup, snapshot, and revisions.
They can protect the root of a relationship read path; a related entity's
membership rules cannot silently be bypassed by targeting it through a separate
root grant. Such target permissions are rejected. Membership sources must remain
leaf entities without their own membership boundaries, change-request lifecycle,
or incoming relationship read paths, preventing recursive row-security policies.

Spatial bbox permissions use a separate authority role and cannot currently be
combined with membership boundaries. Ordinary reads of facilities remain
available under the membership profile.

Writes, actions, reviewed changes, and request lifecycle grants cannot use
membership-bounded profiles. The compiler rejects these combinations rather
than silently ignoring the boundary. Use a separate explicitly authorized
steward profile for membership administration and record mutations. This
version therefore has no mutation idempotency replay authorized through a
membership profile; read cursor replay always reevaluates live membership.

Use `bregctl explain access` to inspect the expanded membership boundary alongside
its scopes, purposes, and ordinary row boundaries. Compiler diagnostics identify
the unsupported field or grant and describe the supported alternative.

Focused verification lives in
[`membership_access.rs`](../../crates/registry-breg/tests/membership_access.rs)
and
[`postgres_membership_access.rs`](../../crates/registry-breg/tests/postgres_membership_access.rs).
