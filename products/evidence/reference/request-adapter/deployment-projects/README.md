# Deployment-shaped Evidence projects

Status: Implemented Version 1 deployment references

These projects show the complete immutable bundle an operator would deploy,
not only a connector fragment. They include runtime security settings, source
authentication references, authority grants, selector profiles, requirement
definitions, scripts, schemas, and sanitized contract cases.

The projects use the Version 1 script contract:

```text
prepare(source_required_selectors, adapter_context) -> RequestParts
extract(source_response, adapter_context) -> LookupResult
derive(facts, authorized_requirement_selectors, evaluation_context)
    -> array<DerivedConceptValue>
```

They are conformance inputs for the implemented product contract and runtime,
not pseudoconfiguration that silently falls back to fixed selector placements.
The Evidence package tests load both runtime files and complete bundle
configurations, capture every referenced artifact, and compile every script
through the production ABI. Offline evaluation executes every fixture case
through production request materialization, lookup, derivation, output
validation, Evidence construction, ephemeral signing, JWS verification,
privacy, and failure contracts. It intentionally does not authenticate a JWT,
resolve deployment credentials, write audit, start HTTP, or contact the source;
package and HTTP-path tests cover those runtime boundaries. An adopter must run
the same fixtures with `evidence evaluate` before deployment.

## Projects

- [`dhis2-tracker-evidence/`](dhis2-tracker-evidence/) resolves one tracked
  entity by an exact reference and supports adult status from the configured
  date-of-birth attribute and professional licence status as an active-licence
  boolean plus a bounded expiry category.
- [`opencrvs-family-evidence/`](opencrvs-family-evidence/) resolves one
  registered birth event and supports adult status, exact registered-parent
  confirmation, and bounded registered-parent identification.
- [`relay-protected-read-evidence/`](relay-protected-read-evidence/) resolves
  one record through a protected, scoped, read-only registry API of the shape
  Registry Relay presents, and supports residence region as a coarse
  controlled code mapped from the register's own code.

Every hostname, issuer, identifier, and fixture value is synthetic. `.example`
hosts must be replaced during deployment. Secret files are referenced only by
logical names and must be independent, owner-only files beneath the configured
secret root. No credential value belongs in a bundle, command argument, test
fixture, snapshot, or diagnostic.

Follow the [authoring and production-build workflow](CONFIG.md#authoring-and-production-build-workflow)
when adapting a project. Use these complete bundles as reference material, not
as local state to copy or promote. An editable project gains its own reviewed
governance metadata and fixtures, then `evidencectl build` produces one closed
candidate. Keep that candidate bundle unchanged across environments and bind
each environment through its own runtime file and secret mounts.

## Security boundary

Rust still owns authentication, authorization, durable per-stage access audit,
the closed single or search-then-fetch acquisition, fixed transport authority,
credentials, call ceilings, limits, output validation, audience-scoped entity
references, signing, and disclosure audit.
Scripts are reviewed and trusted but remain deterministic and unable to
perform I/O.

Every project declares `responseFormats: [signed-jws]` at the bundle level and
on every grant, so they release only signed flattened JWS. That is the
production-shaped default: unsigned output is a development convenience that a
deployment must enable deliberately in both places.

Relationship derivation may compare one authorized candidate with a complete
relationship set from one uniquely resolved authoritative record. It may not
retrieve a broad candidate set, score candidates, choose a best match, or turn
an unresolved or partial result into `false`.

The family project's `reference_namespace` and
`relationship_set_contract` facts come from closed source adapter parameters.
Comparing them with closed requirement parameters proves startup agreement
between two reviewed bundle sections. It does not prove that the provider
returned either value. Governance must separately establish that returned
references belong to the declared namespace and that the configured fields are
complete for the declared relationship contract. If a provider's namespace or
contract varies by record, extraction must derive and validate that value from
projected provider data instead of copying a bundle constant.

Before copying a project, apply the
[provider prerequisites](CONFIG.md#provider-prerequisites). A source that cannot
distinguish zero, one, and multiple matches in one bounded request is not a
Version 1 integration even if its JSON can otherwise be mapped by Rhai.

[`CONFIG.md`](CONFIG.md) defines the Version 1 configuration vocabulary,
ownership split, enumerations, and optionality. [`FIXTURES.md`](FIXTURES.md)
defines the executable fixture vocabulary and exact comparison rules. Those
two references are normative for these projects; the project READMEs explain
only deployment-specific choices.
