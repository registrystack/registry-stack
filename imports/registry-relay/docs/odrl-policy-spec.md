# ODRL Policy Metadata Spec

Status: implemented for v0.1 metadata publication

This document specifies how Registry Relay should publish richer ODRL policy
metadata in DCAT/BRegDCAT-AP outputs without claiming to enforce, negotiate, or
evaluate those policies.
The broader standards and interpretation assumptions are tracked in
[`../STANDARDS_ASSUMPTIONS.md`](../STANDARDS_ASSUMPTIONS.md).

The intent is small and practical: make published metadata more useful to
Dataspace Atlas, catalog brokers, governance reviewers, and future DSP-aware
connectors while keeping Registry Relay a registry API and metadata publisher.

## Standards Anchor

The implementation should follow these W3C ODRL 2.2 concepts:

- A Policy groups one or more permissions, prohibitions, or obligations.
- An Offer proposes rules from an assigner, but does not grant privileges.
- An Agreement grants terms between assigner and assignee. Registry Relay does
  not publish Agreements in v0.1.
- A Permission allows an action over an asset when constraints and duties are
  satisfied.
- A Prohibition disallows an action over an asset.
- A Duty is an obligation to perform an action. A duty attached to a permission
  is a precondition for that permission.
- A Constraint refines when a rule applies, using left operand, operator, right
  operand, and optional unit.
- A top-level obligation is valid ODRL policy machinery, but it is not part of
  the first Registry Relay slice. v0.1 uses duties attached to permissions
  instead.

Reference documents:

- W3C ODRL Information Model 2.2:
  https://www.w3.org/TR/odrl-model/
- W3C ODRL Vocabulary and Expression 2.2:
  https://www.w3.org/TR/odrl-vocab/

## Brainstorm Summary

The current output publishes a minimal `odrl:Offer` with one `odrl:use`
permission. That is useful as a marker, but not enough for discovery workflows
such as:

- Can this dataset be used for social protection eligibility?
- Is resale or onward sharing prohibited?
- Does use require attribution, logging, deletion, or human review?
- Which agency is proposing the terms?
- Are policy terms machine-addressable through IRIs instead of free text?

The richer model should still be honest:

- Registry Relay publishes descriptive policy metadata.
- Registry Relay does not evaluate purpose, recipient, legal basis, or duties.
- Registry Relay does not create ODRL Agreements.
- Registry Relay does not negotiate DSP contracts.
- Registry Relay does not enforce ODRL at request time.

Downstream systems may use this metadata as evidence. They still need separate
authorization, governance, and contract processes before production data use.

## Goals

- Let dataset manifests describe common usage policy evidence in a compact,
  reviewable YAML shape.
- Render standards-shaped ODRL JSON-LD from that manifest.
- Keep policy values IRI-first so strict discovery can match them without AI or
  fuzzy text.
- Preserve the current simple default: if no policy block is configured,
  Registry Relay may still emit a minimal use offer.
- Make output useful for DCAT, BRegDCAT-AP, DSP-aware catalog discovery, and
  Dataspace Atlas capability review.

## Non-Goals

- No runtime policy enforcement.
- No ODRL evaluator.
- No policy conflict resolution.
- No ODRL inheritance processing.
- No ODRL Agreement generation.
- No top-level ODRL obligation generation in v0.1.
- No DSP contract negotiation or transfer process.
- No natural-language policy parser.
- No guessing policy terms from dataset title, field names, or owner.

## Core Decision

Registry Relay v0.1 should publish **ODRL Offers** attached to datasets using
`odrl:hasPolicy`.

`registry-manifest-core` owns ODRL policy publication. The core manifest,
compiled metadata view, validation, and DCAT/BRegDCAT-AP renderers must own
default and configured policy output. The legacy Relay renderer must either
delegate to the compiled metadata output or be updated to produce semantically
equivalent ODRL policy nodes verified by JSON assertions. Two divergent ODRL
renderers are not acceptable.

It should not publish `odrl:Agreement` because no party has accepted terms
through Registry Relay. An accepted data-sharing agreement can be linked later
as external governance evidence, but it is not produced by Registry Relay.

Each generated Offer must have:

- a stable IRI;
- an ODRL `uid` equal to that IRI;
- an assigner;
- at least one permission or prohibition.

Each rule should have:

- a target dataset IRI;
- an action IRI;
- optional constraints;
- optional duties for permissions.

## YAML Shape

Add an optional `policy` block to each dataset metadata manifest.

```yaml
datasets:
  - id: farmer_registry
    title: Farmer Registry
    policy:
      uid: https://data.example.gov/datasets/farmer_registry#offer
      assigner: did:web:agriculture.example.gov
      profile:
        - https://example.gov/odrl/profile/government-data-sharing
      permissions:
        - action: odrl:use
          constraints:
            - left_operand: odrl:purpose
              operator: odrl:isA
              right_operand:
                iri: https://example.gov/purpose/social-protection-eligibility
          duties:
            - action: odrl:attribute
            - action: odrl:delete
              constraints:
                - left_operand: odrl:elapsedTime
                  operator: odrl:lteq
                  right_operand:
                    value: P90D
                  datatype: xsd:duration
      prohibitions:
        - action: odrl:sell
        - action: https://example.gov/odrl/action/reidentify
```

### Defaults

If `policy` is absent, Registry Relay should preserve today's minimal behavior
by emitting a default ODRL-shaped use Offer. This default is enabled unless a
future manifest field explicitly disables policy publication. Do not add the
disable switch in v0.1 unless a real deployment needs it.

```json
{
  "@id": "https://data.example.gov/datasets/farmer_registry#offer",
  "@type": "odrl:Offer",
  "odrl:uid": "https://data.example.gov/datasets/farmer_registry#offer",
  "odrl:assigner": { "@id": "did:web:data.example.gov" },
  "odrl:permission": [{
    "odrl:target": { "@id": "https://data.example.gov/datasets/farmer_registry" },
    "odrl:assigner": { "@id": "did:web:data.example.gov" },
    "odrl:action": { "@id": "odrl:use" }
  }]
}
```

Default `assigner` resolution:

1. `dataset.policy.assigner`
2. `catalog.participant_id`
3. dataset publisher IRI, if configured
4. catalog base URL

The default policy must not invent purpose, recipient, legal basis, duties, or
prohibitions.

Default policy generation belongs in `registry-manifest-core`, because static
metadata publication should behave the same inside and outside Registry Relay.

## Manifest Types

The portable metadata manifest should add:

```rust
pub struct DatasetPolicyManifest {
    pub uid: Option<String>,
    pub assigner: Option<String>,
    pub profile: Vec<String>,
    pub permissions: Vec<PolicyRuleManifest>,
    pub prohibitions: Vec<PolicyRuleManifest>,
}

pub struct PolicyRuleManifest {
    pub action: String,
    pub target: Option<String>,
    pub assignee: Option<String>,
    pub constraints: Vec<PolicyConstraintManifest>,
    pub duties: Vec<PolicyDutyManifest>,
}

pub struct PolicyDutyManifest {
    pub action: String,
    pub target: Option<String>,
    pub assignee: Option<String>,
    pub constraints: Vec<PolicyConstraintManifest>,
}

pub struct PolicyConstraintManifest {
    pub left_operand: String,
    pub operator: String,
    pub right_operand: PolicyOperandValue,
    pub unit: Option<String>,
    pub datatype: Option<String>,
}

pub enum PolicyOperandValue {
    Iri { iri: String },
    Literal { value: String },
}
```

Exact Rust names may change to fit the codebase, but the serialized manifest
fields should stay stable.

`right_operand` must be serialized as an object with exactly one of:

- `iri`: for machine-addressable values used by strict discovery.
- `value`: for typed literals such as durations, counts, or dates.

The manifest must not support convenience shorthands such as `purposes:
[iri]` in v0.1. Purpose restrictions are normal constraints using
`left_operand: odrl:purpose`. This keeps the YAML shape small and prevents two
ways of saying the same thing.

## Vocabulary And IRI Rules

All policy identifiers should be explicit IRIs or compact IRIs expanded through
the manifest `vocabularies` block.

Registry Relay v0.1 must accept these absolute URI schemes for policy IRIs:

- `http`
- `https`
- `urn`
- `did`

Allowed built-in prefixes:

- `odrl`: `http://www.w3.org/ns/odrl/2/`
- `dcterms`: `http://purl.org/dc/terms/`
- `xsd`: `http://www.w3.org/2001/XMLSchema#`

The renderer must expand compact IRIs in validation and either:

- render the expanded IRI as `{"@id": "..."}`, or
- keep compact form only when the JSON-LD context defines the prefix.

Free-text policy values are allowed only for human-readable metadata and typed
literals such as duration or count values. They must not be used for strict
discovery fields such as action, purpose, recipient, assigner, assignee, unit,
or target.

### Operand Value Rules

Some ODRL left operands require IRI right operands because strict discovery
needs controlled terms rather than labels.

| Left operand | Right operand in v0.1 |
| --- | --- |
| `odrl:purpose` | IRI only |
| `odrl:recipient` | IRI only |
| `odrl:spatial` | IRI only |
| `odrl:industry` | IRI only |
| `odrl:systemDevice` | IRI only |
| `odrl:elapsedTime` | literal value, usually typed with `xsd:duration` |
| `odrl:dateTime` | literal value, usually typed with `xsd:dateTime` |
| `odrl:count` | literal value, usually typed with `xsd:integer` |

## Supported v0.1 Terms

Start with a small allowlist. Unknown ODRL-profile terms may be allowed only if
they are full IRIs or compact IRIs resolvable through `vocabularies`.

Recommended ODRL actions:

- `odrl:use`
- `odrl:read`
- `odrl:aggregate`
- `odrl:derive`
- `odrl:distribute`
- `odrl:extract`
- `odrl:attribute`
- `odrl:delete`
- `odrl:inform`
- `odrl:obtainConsent`
- `odrl:reviewPolicy`
- `odrl:sell`

Recommended ODRL left operands:

- `odrl:purpose`
- `odrl:recipient`
- `odrl:elapsedTime`
- `odrl:dateTime`
- `odrl:spatial`
- `odrl:count`
- `odrl:systemDevice`
- `odrl:industry`

Recommended ODRL operators:

- `odrl:eq`
- `odrl:neq`
- `odrl:isA`
- `odrl:isPartOf`
- `odrl:isAnyOf`
- `odrl:isAllOf`
- `odrl:isNoneOf`
- `odrl:lt`
- `odrl:lteq`
- `odrl:gt`
- `odrl:gteq`

Registry Relay should not define a new ODRL profile in v0.1. If a deployment
uses custom actions or operands, those terms must live in that deployment's
vocabulary and the policy must declare the corresponding `odrl:profile`.

## JSON-LD Rendering

Dataset node:

```json
{
  "@id": "https://data.example.gov/datasets/farmer_registry",
  "@type": "dcat:Dataset",
  "odrl:hasPolicy": {
    "@id": "https://data.example.gov/datasets/farmer_registry#offer",
    "@type": "odrl:Offer",
    "odrl:uid": "https://data.example.gov/datasets/farmer_registry#offer",
    "odrl:assigner": { "@id": "did:web:agriculture.example.gov" },
    "odrl:profile": [{
      "@id": "https://example.gov/odrl/profile/government-data-sharing"
    }],
    "odrl:permission": [{
      "odrl:target": {
        "@id": "https://data.example.gov/datasets/farmer_registry"
      },
      "odrl:assigner": { "@id": "did:web:agriculture.example.gov" },
      "odrl:action": { "@id": "odrl:use" },
      "odrl:constraint": [{
        "odrl:leftOperand": { "@id": "odrl:purpose" },
        "odrl:operator": { "@id": "odrl:isA" },
        "odrl:rightOperand": {
          "@id": "https://example.gov/purpose/social-protection-eligibility"
        }
      }],
      "odrl:duty": [{
        "odrl:action": { "@id": "odrl:attribute" }
      }]
    }],
    "odrl:prohibition": [{
      "odrl:target": {
        "@id": "https://data.example.gov/datasets/farmer_registry"
      },
      "odrl:assigner": { "@id": "did:web:agriculture.example.gov" },
      "odrl:action": { "@id": "odrl:sell" }
    }]
  }
}
```

Rendering rules:

- `@id` identifies the JSON-LD node.
- `odrl:uid` satisfies the ODRL policy identifier requirement.
- `odrl:target` defaults to the containing dataset IRI.
- `odrl:assigner` appears on the Offer and on each atomic rule.
- `odrl:assignee` is omitted unless explicitly configured.
- `odrl:profile` renders as an array when configured, even with one value.
- `odrl:permission` and `odrl:prohibition` are arrays.
- `odrl:duty` is nested under permission.
- Top-level `odrl:obligation` is not emitted in v0.1.
- Rule-level `odrl:constraint` is an array.
- IRI operands render as `{"@id": "..."}`.
- Literal operands render as `{"@value": "...", "@type": "..."}` when
  `datatype` is configured, otherwise as a JSON string.
- The renderer must not emit empty arrays.

The JSON-LD context must define `@type: @id` for all ODRL properties whose
values are IRIs:

- `odrl:uid`
- `odrl:assigner`
- `odrl:assignee`
- `odrl:profile`
- `odrl:target`
- `odrl:action`
- `odrl:leftOperand`
- `odrl:operator`
- `odrl:hasPolicy`

`odrl:rightOperand` must not be globally coerced to `@id` in the context,
because ODRL permits both IRI operands and literal operands. IRI operands are
rendered as explicit `{ "@id": "..." }` objects instead.

## Interaction With DCAT, BRegDCAT-AP, CPSV, And DSP

`dcatap:applicableLegislation` remains the place to link legal instruments that
apply to a dataset. ODRL constraints can point to purposes, recipients, or
conditions, but they must not replace legal-basis metadata.

`cpsv:PublicService` remains the place to describe public services that produce
or use a dataset. ODRL should describe usage terms, not source-of-truth status.

DSP alignment:

- A dataset-level ODRL Offer is useful catalog evidence for future DSP-aware
  connectors.
- Registry Relay must not claim to publish DSP Agreements or DSP Transfer
  Processes.
- Registry Relay's normal DCAT/BRegDCAT-AP metadata follows explicit W3C ODRL
  rule targets. It does not use DSP compact-offer conventions for ordinary
  Relay REST, OGC API, or SP DCI metadata.
- Registry Relay must not emit `dspace:dataServiceType` for normal Relay REST,
  OGC API, or SP DCI endpoints. DSP defines `dspace:dataServiceType` for
  Dataspace Protocol endpoints, with `dspace:connector` as the known connector
  type; Relay endpoints are instead described with `dcat:endpointURL`,
  `dcat:endpointDescription`, `dcterms:conformsTo`, and `dcterms:format`.

## Validation

Metadata validation must reject:

- malformed IRIs or unresolved compact IRIs;
- policy IRIs with unsupported absolute URI schemes;
- policy with no permission or prohibition;
- configured Offer with no assigner after defaulting;
- rule without an action;
- unknown short token values such as `use` when they cannot be expanded;
- literals used where strict IRI terms are required;
- duty without an action;
- constraint without left operand, operator, or right operand;
- constraint with both `right_operand.iri` and `right_operand.value`;
- constraint with literal right operand but an IRI-only left operand such as
  `odrl:purpose` or `odrl:recipient`;
- unsupported datatype aliases.

Use stable validation paths and messages. At minimum, tests must cover these
paths:

- `datasets[n].policy.uid`
- `datasets[n].policy.assigner`
- `datasets[n].policy.permissions[n].action`
- `datasets[n].policy.permissions[n].constraints[n].left_operand`
- `datasets[n].policy.permissions[n].constraints[n].operator`
- `datasets[n].policy.permissions[n].constraints[n].right_operand`
- `datasets[n].policy.permissions[n].duties[n].action`
- `datasets[n].policy.prohibitions[n].action`

The public Relay error code can remain `metadata.manifest.validation_failed`,
but the validation payload must preserve the failing path so callers can fix
metadata without reading logs.

Validation should warn, not reject:

- custom full-IRI actions;
- custom full-IRI operands;
- policy profile IRIs that Registry Relay does not dereference;
- assignee-specific offers, because they are metadata only and do not grant
  access.

## Discovery Semantics

Dataspace Atlas and `system-capability-discovery` may use emitted ODRL as
evidence for:

- allowed usage purposes;
- prohibited usage patterns;
- required governance duties;
- whether a route needs policy review before use;
- whether policy metadata is machine-readable.

They must not infer:

- access approval;
- final legal compliance;
- runtime authorization;
- that an ODRL duty has been fulfilled;
- that a recipient is eligible.

## Implementation Waves

### Wave 1: Manifest Model And Validation

- Add policy manifest structs to `registry-manifest-core`.
- Add policy to `CompiledDataset` or an equivalent compiled metadata structure.
- Add validation and compact IRI expansion for policy fields.
- Add focused tests for valid policy, unresolved prefix, empty policy,
  unsupported URI scheme, missing action, bad operand, purpose-as-literal, and
  unsupported top-level obligation.

Done when:

- `cargo test -p registry-manifest-core policy` passes.
- Existing metadata fixture tests still pass.
- Invalid policy manifests produce stable `metadata.manifest.*` error codes.

### Wave 2: Renderer

- Replace `dataset_offer(dataset)` with manifest-driven rendering.
- Keep default minimal offer when no policy block exists.
- Emit `odrl:uid`, `odrl:assigner`, rule `odrl:target`, rule `odrl:action`,
  constraints, duties, and prohibitions.
- Update JSON-LD contexts so ODRL IRI-valued properties are typed as `@id`.
- Preserve no-target compact behavior only if we deliberately choose compact
  policy rendering. The safer default is atomic rules with explicit targets.

Done when:

- Golden DCAT/BRegDCAT fixtures include the richer offer shape.
- Tests assert no `odrl:Agreement` appears.
- Tests assert no top-level `odrl:obligation` appears.
- Tests assert default policy does not invent purpose, recipient, or duties.
- Tests assert the default policy has exactly one `odrl:use` permission with
  explicit `odrl:target`, explicit `odrl:assigner`, no `odrl:assignee`, no
  `odrl:constraint`, no `odrl:duty`, and no `odrl:prohibition`.
- Tests assert `odrl:profile` renders as an array.
- Tests assert the JSON-LD context marks ODRL IRI-valued properties as `@id`.

### Wave 3: Runtime Adapter And Demo Metadata

- Map split metadata manifest policy blocks into the compiled metadata view.
- Add policy examples to the farmer, disability, and education demo metadata.
- Use realistic but hypothetical IRIs under example domains.
- Document that demo policy terms are illustrative, not official policy.

Done when:

- Demo config loads.
- Rendered demo DCAT output from Registry Relay contains policy evidence for all
  three social protection discovery examples.
- Existing Registry Relay API behavior is unchanged.

### Wave 4: Documentation And Validation

- Update `docs/metadata.md` and `docs/configuration.md`.
- Update `STANDARDS_ASSUMPTIONS.md`.
- Add a local JSON-LD smoke check that policy nodes are discoverable through
  `odrl:hasPolicy`.
- Re-run SEMIC validation to ensure ODRL enrichment does not regress DCAT-AP.

Done when:

- `cargo test -p registry-manifest-core --no-default-features` passes.
- `cargo test -p registry-relay --test catalog_entity` passes.
- A demo-render smoke test verifies `odrl:hasPolicy`, `odrl:uid`,
  `odrl:assigner`, `odrl:permission`, one `odrl:constraint`, one `odrl:duty`,
  and one `odrl:prohibition` in JSON-LD generated from the demo config.
- `cargo fmt --all --check` passes.
- Local SEMIC DCAT-AP validation passes or any failure is documented as
  unrelated to ODRL.

## v0.1 Definition Of Done

This work is done only when:

- Dataset manifests can declare policy metadata without runtime config leakage.
- Default policy output is deterministic: one `odrl:Offer` per dataset, one
  `odrl:use` permission, explicit dataset target, explicit assigner, no
  assignee, no constraints, no duties, and no prohibitions.
- Configured policy output uses standards-shaped ODRL terms.
- No policy output claims enforcement, agreement, negotiation, or access grant.
- All configured strict policy values are IRIs or resolvable compact IRIs.
- The demo supports purpose, prohibition, and duty examples.
- Golden fixtures and focused tests cover default and configured policies.
- The documentation clearly separates standard ODRL evidence from Registry Relay
  interpretation.
- The verification commands in Wave 4 pass.
- Normal Relay endpoints do not emit proprietary `dspace:dataServiceType`
  values. A future DSP connector profile would need to be explicitly named and
  disabled by default.
- The core renderer is the authoritative ODRL renderer, and no legacy Relay
  renderer can emit a divergent policy shape.
- The JSON-LD context types every ODRL IRI-valued property as `@id`.

The definition of done is intentionally testable. A release is not done if:

- configured policies can deserialize but are silently dropped from DCAT output;
- invalid policy manifests collapse into a generic config failure with no stable
  path;
- any configured policy value needed for strict discovery is plain text only;
- tests pass only with seeded fixtures and not with the demo config rendered
  through Registry Relay;
- generated JSON-LD contains `odrl:Agreement` or top-level `odrl:obligation` in
  v0.1;
- generated JSON-LD keeps `odrl:target` absent because of the old DSP compact
  offer assumption;
- policy examples use `did:` IRIs but validation rejects them.

## Parallel Implementation Plan

Implementation should run in a worktree with workers assigned to disjoint file
sets. Every worker must assume other workers are editing nearby behavior and
must not revert or reformat files outside their assignment.

### Wave A: Core Model And Validation

Owner: core metadata worker.

Files:

- `crates/registry-manifest-core/src/lib.rs`
- focused core tests and fixtures under `crates/registry-manifest-core/tests/`

Tasks:

- Add policy manifest and compiled policy types.
- Add `did:` support for policy IRIs.
- Add validation paths for every policy field named in this spec.
- Add invalid-manifest tests for unresolved prefixes, unsupported URI schemes,
  empty policy, missing action, bad right operand, purpose-as-literal, and
  top-level obligation rejection.

Done when:

- `cargo test -p registry-manifest-core policy` passes.
- Invalid policy tests assert stable field paths.
- The core model can round-trip a manifest containing permission, duty,
  prohibition, profile, IRI operand, and literal operand.

Review:

- One staff-style review checks that validation is deterministic, no runtime
  config leaked into core, and no shorthand policy fields were introduced.

### Wave B: Rendering And Legacy Alignment

Owner: renderer worker.

Files:

- `crates/registry-manifest-core/src/lib.rs`
- `src/metadata/shacl.rs`
- `tests/catalog_entity.rs`
- golden DCAT/BRegDCAT fixtures

Tasks:

- Render default and configured ODRL Offers from compiled metadata.
- Add explicit `odrl:target`, `odrl:uid`, `odrl:assigner`, arrays for
  `odrl:profile`, permission, prohibition, constraint, and duty.
- Type every ODRL IRI-valued JSON-LD context property as `@id`.
- Verify normal Relay REST, OGC API, and SP DCI metadata do not emit
  proprietary `dspace:dataServiceType` values.
- Ensure the legacy Relay renderer cannot diverge from core policy output.

Done when:

- Tests assert the exact default policy shape.
- Tests assert configured policy shape with purpose, duty, and prohibition.
- Tests assert no `odrl:Agreement` and no top-level `odrl:obligation`.
- Tests assert no normal Relay endpoint emits proprietary
  `dspace:dataServiceType`.

Review:

- One reviewer checks JSON-LD semantics, W3C ODRL shape, and DSP honesty.

### Wave C: Demo, Docs, And Consumer Evidence

Owner: demo/docs worker.

Files:

- `demo/config/*.metadata.yaml`
- `demo/config/*.yaml` only if the old mixed config still needs parity
- `docs/metadata.md`
- `docs/configuration.md`
- `STANDARDS_ASSUMPTIONS.md`
- optional demo-render smoke test

Tasks:

- Add illustrative policy metadata to farmer, disability, and education demo
  datasets.
- Keep demo policy IRIs hypothetical and clearly documented.
- Document the manifest fields, defaults, validation rules, and non-enforcement
  boundary.
- Add or update a demo-render smoke test that inspects generated JSON-LD from a
  realistic demo config.

Done when:

- Demo config loads without manual edits.
- Demo-render JSON-LD contains `odrl:hasPolicy`, `odrl:uid`,
  `odrl:assigner`, `odrl:permission`, one `odrl:constraint`, one `odrl:duty`,
  and one `odrl:prohibition`.
- Documentation says ODRL is descriptive metadata, not runtime enforcement or
  agreement.

Review:

- One reviewer checks that demo examples are not presented as official policy
  and that docs match the implemented manifest shape.

### Final Integration Gate

The feature is release-ready only after all of these pass in the worktree:

```sh
cargo test -p registry-manifest-core --no-default-features
cargo test -p registry-relay --test catalog_entity
cargo fmt --all --check
just validate-catalog-semic-local catalog=target/dcat-ap/metadata.bregdcat-ap.jsonld profile=dcatap.2_0_0
```

If SEMIC validation fails, the failure must be classified before release:

- release-blocking if caused by new ODRL/DCAT rendering;
- documented advisory failure if caused by an unrelated local profile or
  background-vocabulary gap.

Final review must verify:

- every item in the v0.1 definition of done is satisfied;
- all review findings from Waves A, B, and C are closed or explicitly deferred;
- the final diff contains no unrelated cleanup;
- demo output proves the behavior end to end rather than relying only on unit
  fixtures.
