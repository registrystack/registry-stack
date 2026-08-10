# Relay V2 standards alignment

Status: Maintained directional alignment note
Last reviewed: 2026-08-10

Relay V2 was reviewed against the written GovStack Digital Registries draft
`3.0.0-alpha.2`, its CFR target `govstack-cfr-2.1.0`, the GovStack API
Design Guide draft `0.1.0-draft`, and the SDMX REST specification `2.2.2`.
These are directional design inputs. This
note makes no conformance, compatibility, certification, or completeness
claim. The obsolete Digital Registries OpenAPI is not an input.

Primary SDMX inputs are the pinned
[SDMX REST 2.2.2](https://github.com/sdmx-twg/sdmx-rest/tree/v2.2.2),
[SDMX-JSON 2.1.0](https://github.com/sdmx-twg/sdmx-json/tree/v2.1.0),
and [SDMX-CSV 2.1.0](https://github.com/sdmx-twg/sdmx-csv/tree/v2.1.0)
specification sources, plus the published
[data JSON 2.1 schema](https://json.sdmx.org/2.1/sdmx-json-data-schema.json)
and
[Structure JSON 2.0 schema](https://json.sdmx.org/2.0.0/sdmx-json-structure-schema.json).

## Adopted direction

| Input concept | Relay V2 treatment |
|---|---|
| One Registry with named authority and authoritative scope | Authored once in `RegistryContract`, compiled into service metadata and package provenance. |
| Consultation Retrieve | Identifier read is compiled only when the resource declares `read`. |
| Consultation List | Deterministic list is compiled only when the resource declares `list`; pagination and filters are closed. |
| Consultation Search | A named exact lookup is the only accepted search-shaped operation. It returns one governed Record or the unresolved outcome. |
| Aggregate Data statistical dataflow | A format-neutral pre-aggregated statistical dataset can explicitly select a fixed SDMX data and structure binding. Relay derives or accepts reviewed stable SDMX identities, compiler-owns the advertised SDMX REST/JSON/CSV versions, and publishes SDMX-JSON/CSV 2.1 plus generated dataflow and DSD metadata without dynamic aggregation. The dataset model is not an SDMX DSD authoring format. |
| Registry semantics | Every resource and property has a stable local semantic identity; JSON-LD, JSON Schema, and SHACL artifacts are compiler outputs. |
| Governed representations | A compiled operation may expose only its finite reviewed representations, each with its own access, disclosure, semantic, schema, SHACL, JSON-LD, classification, and processing artifact. This is controlled publication, not content negotiation or dynamic ABAC. |
| Data governance review | Schema-only identification supplies deterministic review evidence. Classification remains Registry Authority review metadata and constrains compilation; it never grants an entitlement or becomes a remote runtime policy. |
| Capability discovery | The public and protected inventories are derived from compiled operations and their visibility. |
| API description | One full OpenAPI 3.1 document is package-only and one deterministic public subset is exposed at `/openapi.json`. |
| API error discipline | Relay uses RFC 9457 problems, stable Registry Stack codes, W3C Trace Context correlation, and value-free details. |

## Intentional gaps

- Exact lookup is not Record Match. Relay emits no candidates, confidence, or
  explanation.
- Version 1 does not negotiate response language. Authored semantic labels
  retain their language metadata.
- Registry Manifest, machine-readable GovStack alignment, DPV projection, and
  a GovStack linter remain future adopter-tooling projections.
- Dynamic masking, generic tags, external PDP, value sampling, and a general
  data-catalog integration remain outside this alignment. Only reviewed
  `partial-string` and `date-precision` output properties are in scope.
- A current SQLite source and its lifecycle policy do not prove that an
  institution has never reassigned an identifier.
- Relay responses are unsigned. Portable signed minimum disclosure belongs to
  Registry Evidence.
- The initial SDMX binding excludes validity-schema generation, availability
  queries, history/as-of, structure maintenance, arbitrary constraint operators,
  dynamic aggregation, and large-result streaming. The canonical schema and
  availability route shapes return a uniform value-free `501`; other recognized
  unsupported standard features also fail explicitly.
- SDMX artefact terminology is generated binding output, not the basic adopter
  authoring model. Dimensions, one time dimension, one measure, attributes, concepts,
  controlled vocabularies, classification, access, and query bounds remain
  binding-neutral so later statistical representations cannot redefine or
  widen governance.

## Rejected expansion

Relay V2 does not infer or advertise Provisioning, Write, Notification, other
Aggregate Data patterns, Access Transparency, Identity Federation, Evidence, credential
lifecycle, registry administration, or a generic compatibility mode. Offline
`relayctl` authoring is not a Provisioning API, audit is not an Access
Transparency API, and OAuth resource-server behavior is not Identity
Federation.

## Review trigger

Review this note when a pinned input changes, when a compiled capability
pattern changes, or when the public OpenAPI projection changes. The three
acceptance contracts carry the same pinned target versions; product validation
keeps those projects coequal and generated-baseline review makes output changes
visible.
