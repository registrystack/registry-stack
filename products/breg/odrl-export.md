# Inspect access profiles as ODRL

Use `bregctl generate odrl` to inspect a conservative description of your
configured record-read permissions. The exporter derives ODRL 2.2 JSON-LD from
the compiled project and writes a coverage report explaining omitted grants.
It does not contact a running registry or read records.

```sh
bregctl generate odrl ./my-registry --output ./access-policy-review
```

To inspect one access profile, add `--access-profile PROFILE`. Without that
option, the exporter considers every compiled record access profile. An unknown
profile is refused before any output is written. The output directory must be
new, as for other `generate` commands.

The command writes:

| File under the output directory | Purpose |
|---|---|
| `generated/odrl/policies.jsonld` | Partial ODRL policies for supported grants |
| `generated/odrl/coverage.json` | Every considered record-operation grant and its outcome |
| `generated/odrl/profile.jsonld` | The vocabulary and interpretation rules consumers need |

These are **operator-review artifacts**. They can include non-public Record
types, field names, profile identifiers and token requirements. Review the
files before sharing them. This command does not apply the public
`manifestProjection` filter, publish an endpoint, or replace Manifest/DCAT
generation.

## What is translated

The supported subset is `get` and `list` on current records with unrestricted
row reach. Each permission targets a named projection containing exactly the
profile's readable fields. The native Registry Record envelope is outside that
field list. Every rule preserves the selected profile, exact operation,
authentication, principal-claim requirement, required scopes, permitted
purposes, requester-client restrictions and actor-kind restriction. It also
preserves native trusted-actor requirements and requires the caller context
to carry no task grant. These implicit admission rules apply even when the
source does not spell them out as separate restrictions.

Required scopes are conjunctive: every configured scope is required. Permitted
purposes and requester clients are alternatives: one listed value must match.
Conditions refer to BReg's verified caller context. A caller supplying a profile
name or purpose value does not establish authority.

The exporter uses `odrl:read` with the documented BReg profile at
`https://id.registrystack.org/profiles/breg-odrl/v1`. This is an experimental local
profile, not a claim of interoperability with every ODRL consumer. Consumers
must understand its terms, particularly the projected target and exact native
operation. The shipped `profile.jsonld` defines those terms without requiring a
network fetch.

## Eclipse EDC compatibility

This export is neither an Eclipse EDC Management API `PolicyDefinition` nor a
Dataspace Protocol Offer or Agreement. It has not been imported into or evaluated
by EDC. **Do not import it by wrapping a generated policy in `PolicyDefinition`.**
The reviewed EDC parser reads permission actions, constraints and duties but
drops rule-level targets. That loses the BReg projection identifier, Record type
and readable-field list, which define the permission's scope. A successful
parse would not establish equivalent behavior.

An EDC adapter would need to preserve every projection and its exact operation,
normalize JSON-LD list operands, bind `odrl:read` in each applicable evaluation
scope, and register functions for every BReg constraint. Those functions must
use BReg's verified caller context and refuse absent, unsupported or unverifiable
conditions. BReg would still authorize the actual request. The exporter includes
no such adapter or EDC extension.

These limits were checked against EDC's
[policy-definition schema](https://github.com/eclipse-edc/Connector/blob/cd7e556d365cd3e7195e5728cb9bf695c483599d/extensions/common/api/management-api-schema-validator/src/main/resources/schema/management/v4/policy-definition-schema.json),
[permission transformer](https://github.com/eclipse-edc/Connector/blob/cd7e556d365cd3e7195e5728cb9bf695c483599d/core/control-plane/control-plane-transform/src/main/java/org/eclipse/edc/connector/controlplane/transform/odrl/to/JsonObjectToPermissionTransformer.java)
and [policy-engine contract](https://github.com/eclipse-edc/Connector/blob/cd7e556d365cd3e7195e5728cb9bf695c483599d/spi/control-plane-spi/src/main/java/org/eclipse/edc/policy/engine/spi/PolicyEngine.java).

## What is omitted

A permission with row boundaries, current-membership requirements, subject
consent requirements or a task grant is omitted in full. The exporter never
removes an unsupported restriction to produce a broader permission. Operations
other than `get` and `list` are omitted as unsupported.

Actions, Proposals, statistical datasets, lookup grants, relationship paths,
historical reads, count requests and data export are outside the supported
surface. Their absence is not a prohibition and does not mean BReg lacks them.

`coverage.json` counts **record-operation grants**, after any profile selection.
A profile granting `get`, `list` and `patch` contributes three candidates.
The report identifies each exported or omitted candidate and gives reasons for
omissions. Its totals are not a percentage of the registry's entire
authorization model. Reasons can overlap when one grant has several unsupported
restrictions.

Zero supported grants is a successful, explicit empty export. It produces an
empty policy collection and a coverage report, never an unconditional default
permission. Invalid source, an unknown selected profile, or a failed write
remains an error.

## How to use the result

Treat the policies as a partial description of source configuration. The source
revision identifies what was inspected; it does not prove that the package is
active. BReg continues to authenticate and authorize every request using its
current package and state. The export does not describe downstream usage
obligations that were never present in the access profiles.

For application discovery, use the existing
[caller-filtered metadata](metadata.md) endpoint. For a publication intended for
anonymous readers, use the separate classified Manifest projection and review
any policy you attach to that offering.

The implementation is in `crates/registry-breg/src/odrl_export.rs`; the pure
ODRL serializer belongs to `registry-manifest-core`. The export tests cover
restriction preservation and omission, while the CLI tests run the native
command through output publication and refusal paths.

Standards references: [ODRL Information Model 2.2](https://www.w3.org/TR/odrl-model/),
[ODRL Vocabulary and Expression 2.2](https://www.w3.org/TR/odrl-vocab/), and
[ODRL Profile Best Practices](https://www.w3.org/community/reports/odrl/CG-FINAL-profile-bp-20240808.html#profile-vocab).
