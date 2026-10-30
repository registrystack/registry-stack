# Record lookup project

Use this synthetic example when a run knows a person's identifier, such as a
national ID, but not the Base Registry Engine (BReg) record identifier. The run
looks the record up with `breg.lookup-record/v1`, reads it again with
`breg.read-record/v2`, and finishes with the record identifier, its revision
and `observedAt`: when the Coordinator looked. The workflow, deterministic
scenarios and runtime template form one complete project. The project has no
`functions.rhai`, because every mapping is a reference in `workflow.yaml`.

From the repository root, run the offline authoring commands:

```sh
coordinatorctl check --project products/coordinator/examples/record-lookup --explain
coordinatorctl test --project products/coordinator/examples/record-lookup
```

The `lookup` step takes the BReg record-type route in `entity`, the compiled
lookup selector in `selector`, and the identifier fields in a nested `fields`
mapping called `values`. Values are text, whole numbers or flags; the mapping
holds between one and sixteen of them. A filter string is never accepted.
BReg answers one value-free `lookup.unresolved` for no match, two matches, a
row the profile cannot see and a missing claim alike, so the Coordinator
cannot tell them apart and the workflow must not either. The adapter passes
that on as the declared refusal `unresolved`, and `onDeclaredRefusal` routes it
to the `not-registered` finish.

Route `unresolved` to a finish or to another read, never straight to a step
that creates or changes a record. `coordinatorctl check` refuses the direct route
with `definition.unresolved-route`, because "not found, so create" makes a
duplicate when two records match or one is hidden. A mutation can still follow
once a person or another read has decided; that costs one extra step before a
create.

The `read` step takes the identifier the lookup returned and calls
`breg.read-record/v2`. Its input is the same as `breg.read-record/v1`, and its
output is the same record envelope plus a `provenance` member: the record
identifier, the revision identifier, the `etag` BReg sent, and `observedAt`.
`observedAt` is the Coordinator's clock when the read returned. It says when the
workflow looked, not when the fact became true.

The scenarios cover a record found and read with provenance, `unresolved`
finishing without a change, and a forbidden lookup, which fails the run
rather than reading as "not registered". They use synthetic replies only, so
they do not prove BReg lookup selectors, profile grants or access policy.

For a deployment, the institution must supply these prerequisites:

- BReg exposes the `registrants` record type with a compiled lookup selector
  named `by-national-id` over the field `nationalId`.
- The `registrant-reader` profile grants the operations `lookup` (for
  `breg.lookup-record/v1`) and `get` (for `breg.read-record/v2`) on that record
  type. `coordinatorctl check` does not read BReg profiles, so a missing grant
  shows at run time as the failure `product-forbidden`, never as `unresolved`.
- A lookup selector that needs a verified claim and no field values cannot be
  used here: the request is refused as `invalid-command` before BReg is
  contacted, because a service identity carries no such claim.
- Callers hold a Coordinator access token for the `record-lookup` workflow,
  and an explicit operator policy grants inspection and recovery separately.

The runtime template uses loopback endpoints and secret references only. Copy
it outside the package and adapt its endpoints, PostgreSQL identity and roles,
client and package pin. Follow [the deployment runbook](../../DEPLOYMENT.md) for
installation and apply.
