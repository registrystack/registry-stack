# Relay V2 standards alignment

Status: Maintained directional alignment note
Last reviewed: 2026-08-10

Relay V2 was reviewed against the written GovStack Digital Registries draft
`3.0.0-alpha.2`, its CFR target `govstack-cfr-2.1.0`, and the GovStack API
Design Guide draft `0.1.0-draft`. These are directional design inputs. This
note makes no conformance, compatibility, certification, or completeness
claim. The obsolete Digital Registries OpenAPI is not an input.

The statistical-dataflow binding is reviewed as a narrow aligned subset of
SDMX REST 2.2.2 with SDMX-JSON 2.1.0, SDMX-CSV 2.1.0, and Structure JSON 2.1.0.
The product profile lock pins the official specification revisions and the
digests of the official data and structure JSON schemas. Binding versions are
compiler-owned and are not adopter-authored Registry alignment targets. This
note does not claim complete SDMX conformance.

## Adopted direction

| Input concept | Relay V2 treatment |
|---|---|
| One Registry with named authority and authoritative scope | Authored once in `RegistryContract`, compiled into service metadata and package provenance. |
| Consultation Retrieve | Identifier read is compiled only when the resource declares `read`. |
| Consultation List | Deterministic list is compiled only when the resource declares `list`; pagination and filters are closed. |
| Consultation Search | Named exact lookup and named Point-bbox search are the only accepted search-shaped operations. Exact lookup returns one governed Record or the unresolved outcome; Point-bbox returns a bounded collection. |
| Bounded spatial consultation | A publisher-owned named Point-bbox operation is derived as `consultation.search`; its access profiles and scope are independent from list. This does not create an OGC API Features service. |
| Registry semantics | Every resource and property has a stable local semantic identity; JSON-LD, JSON Schema, and SHACL artifacts are compiler outputs. |
| Governed access profiles | A compiled operation may expose only its finite reviewed access profiles, each with its own access, disclosure, semantic, schema, SHACL, JSON-LD, classification, and processing artifact. `Accept` and optional `formatProfile` choose serialization after authorization; they never grant access. |
| GeoJSON and JSON-FG | A disclosed primary CRS84 Point may serialize as RFC 7946 GeoJSON. The `jsonfg` profile adds the fixed JSON-FG core and types/schemas metadata while retaining the same governed content. |
| Aggregate Data statistical dataflow | A format-neutral snapshot dataset with exactly one fixed access rule may select a required SDMX binding. Relay derives stable identities, generates exact dataflow and DSD package artifacts, and publishes only keyed data, the omitted-key alias, dataflow structure, and datastructure structure. It never aggregates source rows. |
| SDMX read formats | Data uses SDMX-JSON or SDMX-CSV 2.1.0 and structure uses Structure JSON 2.1.0. Official JSON schemas are fetched only by an explicit temporary validation path or read from an external cache, digest-verified, and never committed. |
| Data governance review | Schema-only identification supplies deterministic review evidence. Classification remains Registry Authority review metadata and constrains compilation; it never grants an entitlement or becomes a remote runtime policy. |
| Capability discovery | The public and protected inventories are derived from compiled operations and their visibility. |
| API description | One full OpenAPI 3.1 document is package-only and one deterministic public subset is exposed at `/openapi.json`. |
| API error discipline | Relay uses RFC 9457 problems, stable Registry Stack codes, W3C Trace Context correlation, and value-free details. |

## Intentional gaps

- Exact lookup is not Record Match. Relay emits no candidates, confidence, or
  explanation.
- The Point profile is not OGC API Features, CQL2, EDR, tiles, a coordinate
  transformation service, or a generic spatial database API. It supports only
  classified CRS84 Points assembled from reviewed longitude and latitude
  columns and exact inclusive, non-wrapping, bounded bbox containment.
- GeoPackage and SpatiaLite are future source-profile work. Relay neither
  loads SQLite extensions nor accepts geometry blobs.
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
- The aligned SDMX subset has no schema, availability, history, or
  structure-maintenance routes or placeholders, arbitrary operators, dynamic
  aggregation, or large-result streaming.

## Rejected expansion

Relay V2 does not infer or advertise Provisioning, Write, Notification, another
Aggregate Data pattern, Access Transparency, Identity Federation, Evidence, credential
lifecycle, registry administration, or a generic compatibility mode. Offline
`relayctl` authoring is not a Provisioning API, audit is not an Access
Transparency API, and OAuth resource-server behavior is not Identity
Federation.

## Review trigger

Review this note when a pinned input changes, when a compiled capability
pattern changes, or when the public OpenAPI projection changes. The three
Record acceptance contracts pin the same GovStack target versions. The
labour-statistics contract authors no SDMX targets because the binding owns
those versions. Product validation keeps all four projects coequal and
generated-baseline review makes output changes visible.
