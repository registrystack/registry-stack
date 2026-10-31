# Adapter authorization spike: Cedar and closed YAML

Status: synthetic, offline experiment. This is not a deployment design, a
runtime authorization implementation, or a change to the Adapter's current
trusted-machine caller boundary. Record-level authorization remains planned,
not built.

## Question

Can the Adapter express two source-neutral record decisions with either the
official Cedar evaluator or a deliberately small closed YAML policy, while
failing closed on bad policy or trusted facts?

The two decisions are:

1. A verified person acting for the required service may read a record in the
   same organisation unit or a descendant unit.
2. A verified person acting for the required service may read a record whose
   source-owned owner relationship names that person.

The spike uses synthetic identifiers and entity data only. It reads no source,
credential, token, or real record.

## Implemented comparison

The executable experiment is under
`products/adapter/experiments/authorization-spike/`.

- Cedar uses the official `@cedar-policy/cedar-wasm` package pinned to 4.14.0
  in the lock file. The wrapper passes a schema, validates each policy in
  strict mode, enables request validation, executes `isAuthorized`, captures
  diagnostics, and returns deny for parse, validation, or evaluation errors.
- The YAML candidate accepts one fixed document shape and two relationship
  values. It rejects parser errors and warnings, including unknown tags, plus
  unknown, missing, and mistyped members. It has no role field, expressions,
  extension keys, or implicit grants.
- Both candidates receive the same validated trusted input. The Cedar
  principal comes from `trustedContext.authenticatedPrincipalId`, and the
  acting service comes from `trustedContext.actingService`. A caller-supplied
  principal selector must match the authenticated principal. Other caller-owned
  claims are retained only as adversarial test input and never become policy
  attributes.
- The Cedar schema and both Cedar policies parse and validate with zero errors
  and zero warnings.

Run the proof offline after installing the locked dependencies:

```bash
npm --prefix products/adapter/experiments/authorization-spike ci --ignore-scripts
npm --prefix products/adapter/experiments/authorization-spike test
npm --prefix products/adapter/experiments/authorization-spike run spike
```

The official package and language documentation used for this experiment are
the [Cedar Wasm package](https://github.com/cedar-policy/cedar/tree/main/cedar-wasm)
and the [Cedar documentation](https://docs.cedarpolicy.com/).

## Results

| Case | Cedar | Closed YAML |
|---|---:|---:|
| descendant organisation unit | permit | permit |
| same organisation unit | permit | permit |
| two-level descendant organisation unit | permit | permit |
| other organisation unit | deny | deny |
| source-owned record owner | permit | permit |
| non-owner | deny | deny |
| no matching permit, default decision | deny | deny |
| explicit deny despite an otherwise matching permit | deny | deny |
| wrong operation | deny | deny |
| person is not verified | deny | deny |
| wrong trusted acting service | deny | deny |
| caller selects another known person | deny | deny |
| missing trusted attribute | deny | deny |
| invalid trusted attribute type | deny | deny |
| unknown principal | deny | deny |
| unknown record | deny | deny |
| cyclic organisation-unit hierarchy | deny | deny |
| unknown organisation-unit parent | deny | deny |
| null or mistyped trusted-fact list entry | deny | deny |
| caller claims `admin`, matching unit, owner, service, and verification | ignored, deny | ignored, deny |
| malformed or schema-invalid policy | deny with diagnostics | deny with diagnostics |

The test suite has 45 tests. It also asserts exact decision parity, confirms
that the loaded Cedar version is 4.14.0, proves that Cedar's `forbid` overrides
an otherwise matching `permit`, and proves that the YAML policy rejects a role
member rather than treating a role string as authority.

The lead reran all 45 tests and asserted the executable comparison's decision
parity and zero Cedar diagnostics. An independent read-only review passed
after corrections to authenticated-person binding, acting-service separation,
forbid-overrides proof, malformed-fact handling and YAML warning refusal.
That reviewer did not rerun the tests. No runtime authorization was installed.

## What the policy engine does not solve

Both candidates depend on the same authoritative entity acquisition. Before a
runtime design, the owning institution would need to decide and operate:

- how verified-person status is bound to the authenticated principal, and how
  the acting service is established independently of caller claims;
- which source owns the record-owner relationship;
- which authority owns organisation-unit membership and the unit hierarchy;
- freshness, revocation, and failure behavior for each fact;
- whether a source can enforce the same restriction atomically for searches
  and writes, rather than returning a broad result for the Adapter to trim.

Missing, invalid, stale, or unknown facts must deny. A caller token, request
body, filter, route output, or source response cannot manufacture authority.
The evaluator needs only opaque entity identifiers and the relevant relations,
not the record body. That limits policy input disclosure, but relationship
facts can still be sensitive and need bounded retention, value-free diagnostics,
and an explicit audit contract.

## Maintainability assessment

Closed YAML is the smaller mechanism for exactly these two relationships. Its
review surface is obvious, and its parser and evaluator fit in a few small
functions. The cost appears when a third relationship or compound condition is
added: each addition changes application code and grows a bespoke policy
language whose precedence, diagnostics, and deny behavior we must maintain.

Cedar has more integration surface: a pinned Wasm dependency, schema and entity
mapping, Cedar diagnostics, and a policy review workflow. In return, the spike
uses the real evaluator for hierarchy membership, default deny, forbid-overrides,
typed request validation, and strict policy validation. New combinations can
remain policy changes instead of evaluator-code changes, within a deliberately
closed Adapter schema.

## Bounded recommendation

Use Cedar if the intended Adapter contract is a general, institution-authored
record-level authorization model. The strongest objection is valid: for only
these two frozen relationships, Cedar is more machinery than closed YAML. If
the product decision is to expose exactly this fixed catalog and no policy
composition, choose the closed YAML shape instead.

Do not integrate either candidate yet. First define the authoritative source,
freshness, revocation, disclosure, search, pagination, and write-enforcement
contract for the entity facts. Cedar can evaluate a decision, but it cannot
make caller-supplied facts trustworthy or make an upstream source enforce the
decision atomically. This spike changes no runtime, access profile, MCP gate,
or trusted-machine admission rule.
