# Review access configuration

This offline example checks a district-scoped reader without PostgreSQL, Mint,
tokens, or real records. Run from the repository root after building
`registry-serverctl`.

```sh
target/debug/registry-serverctl check products/registry-server/examples/access-review --deny-findings
target/debug/registry-serverctl explain access products/registry-server/examples/access-review
```

The check accepts the project without findings. The explanation shows each
operation, field permission, and row restriction. All required scopes must be
present; one listed purpose must match; every row predicate must hold. Selecting
a profile never grants authority, and permissions from different profiles are
not merged.

## Try allowed and refused claims

```sh
target/debug/registry-serverctl explain access products/registry-server/examples/access-review \
  --scenario products/registry-server/examples/access-review/allowed.json
target/debug/registry-serverctl explain access products/registry-server/examples/access-review \
  --scenario products/registry-server/examples/access-review/missing-scope.json
```

The first scenario satisfies profile admission. The second reports
`required_scope_missing`. Both commands exit successfully because explanation
completed. Add `--format json` and inspect `explanation.admitted` in automation.
A malformed scenario exits unsuccessfully.

These are synthetic claims, not a token or a representation of a logged-in user.
The preview uses the same profile-admission function as HTTP, but does not check
OIDC signatures, expiry, actual record rows, request bodies, lookup values,
query validity, database availability, or audit availability. Direct claim names,
scalar/array shapes, and values are checked with the token authority mapper.
An allowed preview is not evidence that a real request will succeed. Claim values
are never printed.

## Catch an omitted restriction

Copy the project to your own directory. In the copy, remove the grant's
`rowBoundaries`, leaving the entity's `accessRequirements` intact. Run `check`
against the copy. Compilation refuses the profile with
`access.requirements.row_boundary_missing` and identifies the entity, profile,
and field. Restore the exact binding to make the check pass.

Then, in the copy, remove both the entity requirements and the grant's row
boundaries. Ordinary `check` accepts the model but reports
`access.profile.unrestricted_collection`; `check --deny-findings` exits
unsuccessfully. This distinguishes a declared invariant from an intentionally
reviewable design choice. The flag covers all compiler findings, including
incomplete package identity, not only access warnings.

## Requirements and limits

`accessRequirements` is optional and requires authenticated access when present.
It grants nothing. Every direct profile, including module contributions, must
explicitly include its mandatory scopes and exact row bindings. When
`allowedPurposes` is nonempty, profiles must restrict purpose to a nonempty subset
of it. An empty or omitted list imposes no purpose requirement. Profiles may be stricter.
Empty requirements are refused. An extension may add requirements to an entity
that has none, but cannot replace existing requirements.

Relationship routes are authorized by the root profile. Target and join entity
scope/purpose requirements apply to that profile too. Target or join row
requirements cannot be enforced by the current root-only relationship plan, so
such grants fail compilation. Use a direct route on the protected entity.
Root row requirements continue to work for relationship routes.

Requirements govern request access, not independently configured event
subscriptions or trusted internal derivations. Webhook projections, conditions,
destination ceilings, and retention remain separately reviewed disclosure.
Requirements also do not stop an authorized operator from replacing the complete
configuration. Review, package signatures, and deployment authority still matter.

`diff` reports field-by-field access changes, including scopes, purposes, row
bindings, fields, related-record grants, and export/history permissions. Mixed
changes are marked for review rather than assigned a guessed overall direction.
Changing mandatory requirements is included in package migration/change review.

The executable CLI regression is
`access_review_example_explains_simulates_and_refuses_footguns_without_live_data`.
The facility acceptance project also declares a mandatory purpose and row boundary;
its PostgreSQL journeys exercise real record isolation.
