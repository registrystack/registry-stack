# Standards Assumptions

Registry Relay publishes metadata that other systems can inspect. This document
keeps the line clear between standards evidence that Registry Relay emits and
interpretations that downstream consumers may derive from that evidence.

## Scope

Registry Relay may publish:

- DCAT and DCAT-AP catalogue, dataset, distribution, and data service metadata.
- BRegDCAT-AP profile metadata where configured.
- SHACL, JSON Schema, and OGC API Records metadata derived from configured
  entities.
- CPSV public service evidence when a dataset manifest declares a related
  service.

Registry Relay does not publish a proprietary source-of-truth flag.

## Facts, Publication Choices, And Downstream Hypotheses

Registry Relay publishes machine-readable metadata facts and descriptors. It
does not publish downstream conclusions.

- **Published fact**: a configured metadata manifest declares a dataset, entity,
  field, service, profile, ODRL Offer, or standard predicate, and Registry Relay
  renders it into `/metadata/*`.
- **Publication choice**: Registry Relay chooses a practical standards-shaped
  representation for a registry concept, such as describing entity routes as
  `dcat:Distribution` plus `dcat:DataService`.
- **Downstream hypothesis**: another tool, such as Dataspace Atlas, derives a
  candidate route, candidate source, confidence level, or governance gap from
  those published facts.

Downstream hypotheses must not be written back into Registry Relay metadata as
if they were original source facts.

## Standard Evidence We Emit

The following predicates are treated as standard-facing evidence:

- `dcterms:publisher`
- `dcterms:rightsHolder`
- `dcterms:accessRights`
- `dcterms:accrualPeriodicity`
- `dcterms:conformsTo`
- `dcterms:spatial`
- `adms:status`
- `dcatap:applicableLegislation`
- `dcat:distribution`
- `dcat:accessService`
- `dcat:servesDataset`
- `odrl:hasPolicy`
- `odrl:Offer`
- `odrl:permission`
- `odrl:prohibition`
- `odrl:duty`
- `odrl:constraint`
- `cpsv:PublicService`
- `cpsv:produces`

These signals are published so standards-aware clients can inspect the registry.
They are not, by themselves, proof that access is legally approved, operationally
ready, complete, or authoritative.

`dcterms:conformsTo` is profile or standard conformance evidence. Registry Relay
may render small typed standard nodes for consumer convenience, but it does not
mean the target IRI is a data resource to harvest as part of the registry.

`dcat:Distribution` and `dcat:DataService` identify declared access surfaces.
They do not mean a caller is authorized, that a specific identifier lookup is
supported, or that production integration has been reviewed.

## Our Interpretation Boundary

Registry Relay does not decide:

- whether a dataset is a system of record;
- whether a caller is legally allowed to use a dataset;
- whether a dataset is complete enough for a program decision;
- whether the dataset's owner is the final authority for every field;
- whether a discovered access route is fit for production integration.

Those decisions belong to downstream governance, review, and discovery layers.
For example, Dataspace Atlas may derive a `candidate_source` route from
`dcterms:publisher`, `dcatap:applicableLegislation`, and `cpsv:produces`, but
that role is an Atlas interpretation, not a Registry Relay predicate.

Registry Relay may publish enough evidence for a downstream tool to form that
hypothesis, but Registry Relay itself only claims what is in the metadata:
publisher, rights holder, applicable legislation, public service relation,
policy offer, access service, and schema evidence.

## ODRL Policy Assumptions

Registry Relay may publish ODRL policy metadata as discovery and governance
evidence. It does not evaluate or enforce ODRL policies, and it does not produce
accepted ODRL agreements. Dataset-level policy output should therefore use
`odrl:Offer`, not `odrl:Agreement`, unless a future feature explicitly models an
accepted agreement from an external governance process.

Configured policy values should be IRI-first. Purposes, recipients, actions,
operands, assigners, assignees, and units should be explicit IRIs or compact
IRIs expanded from the metadata manifest vocabularies. Human-readable policy
text can help reviewers, but it should not be the field that strict discovery
depends on.

The demo policy blocks use hypothetical `demo.example.gov` IRIs and illustrative
assigners such as `did:web:education.demo.example.gov`. They are examples for
metadata consumers and must not be read as official law, binding terms, legal
approval, or proof that a duty has been fulfilled.

Default policy output is intentionally minimal. A generated default `odrl:Offer`
means "this dataset has a discoverable policy node." It is not sufficient legal
basis, and it should not remove policy review gaps in downstream tools unless
more specific configured policy evidence is present.

See [ODRL Policy Metadata Spec](docs/odrl-policy-spec.md) for the proposed
implementation shape.

## DSP Alignment

Registry Relay is not a Dataspace Protocol connector. It may publish
DSP-relevant DCAT and ODRL evidence, such as `dspace:participantId`,
dataset-level `odrl:hasPolicy` Offers, and `dcat:DataService` access metadata,
but it does not implement DSP catalog request, contract negotiation, or transfer
process endpoints.

For that reason Registry Relay should not emit Relay-specific
`dspace:dataServiceType` values such as REST, OGC API, or SP DCI service names.
The current renderers use standard DCAT and Dublin Core fields for Relay access
services instead. DSP defines `dspace:dataServiceType` for Dataspace Protocol
endpoints, with `dspace:connector` as the known connector type. Relay access
services should be described through:
`dcat:endpointURL`, `dcat:endpointDescription`, `dcterms:conformsTo`, and
`dcterms:format`.

The current hypothesis is that these DCAT and ODRL signals make Registry Relay
metadata useful to DSP-aware catalogues without pretending to be a DSP control
plane. Implementing DSP catalog request, contract negotiation, and transfer
processes would be a separate product surface.

## Demo Assumptions

The demo metadata intentionally gives stronger standard evidence to:

- `farmer_registry`, via applicable legislation and a CPSV farmer registration
  service that produces the farmer registry dataset, plus illustrative ODRL
  terms for agricultural-subsidy eligibility discovery.
- `disability_registry`, via applicable legislation and a CPSV disability
  registration service that produces the disability registry dataset, plus
  illustrative ODRL terms for disability-benefit eligibility discovery.
- `education_registry`, via illustrative ODRL terms for student-support
  planning discovery. This policy evidence is not source-of-truth evidence for
  disability registration.

The demo does not give the same source evidence to every dataset that happens to
contain a related field. For example, `education_registry.student` may include a
`disability_status` field, but that does not make the education registry the
source for disability registration.

The demo datasets are hypothetical. They are not official OpenCRVS, OpenSPP,
SP DCI, SEMIC, or PublicSchema profiles. Real project-specific profiles should
be created only from reviewed artifacts and maintainer input.

## Endpoint Publication Assumptions

`/metadata` is the canonical discovery entry point for live Registry Relay
instances. It links to scoped metadata artifacts such as:

- `/metadata/catalog`;
- `/metadata/dcat`;
- `/metadata/dcat/{profile}`;
- `/metadata/shacl`;
- `/metadata/policies`;
- `/metadata/datasets/{dataset_id}/policy`;
- `/metadata/schema/{dataset_id}/{entity}/schema.json`.

The removed `/catalog` aliases are intentionally legacy. Documentation, Bruno
collections, and downstream fixtures should use `/metadata/*`.

`/metadata/policies` is a collection of dataset-scoped policy documents. It is
not one global policy for the whole deployment.

## Version Assumptions

The current metadata model is aligned with the DCAT-AP and BRegDCAT-AP profile
family, and it uses CPSV evidence where that profile family already models
public services.

Known caveat: the local `third_party/semic-shacl-validator` bundle includes
BRegDCAT-AP 2.x shapes, while some Registry Relay demo manifests currently claim
`bregdcat-ap` 3.0. Until the exact BRegDCAT-AP 3.0 SHACL shapes are pinned, SEMIC
validation should be treated as an advisory conformance check rather than the
only release gate.

## Validation Assumptions

Registry Relay tests verify that configured metadata is rendered consistently and
that the demo configs load. They do not replace external profile conformance
validation.

Recommended validation layers:

- local unit and integration tests for deterministic rendering;
- golden fixtures for profile outputs;
- optional SEMIC SHACL validation for DCAT-AP and BRegDCAT-AP conformance;
- human review for legal basis, source-of-truth, and access governance claims.
