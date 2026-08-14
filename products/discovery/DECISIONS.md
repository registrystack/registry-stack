# Registry Discovery decisions

## ADR-001: Discovery is an index, not a trust or invocation layer

Discovery records are advertisements with origin provenance. An adopting
application remains responsible for existing native Evidence or Relay trust
configuration and invokes the provider directly. Discovery has no trust-store
schema, credentials, provider proxy, or procedure model.

## ADR-002: One closed JSON-LD profile

`registry-discovery-v1alpha1` accepts a single `dcat:Catalog` JSON document
with `dcat:DataService` entries, one pinned context URL, and the media type
`application/ld+json;profile="https://registrystack.org/discovery/profile/v1alpha1"`.
The context is a local contract resource, not a runtime retrieval target.
Parsing rejects an alternative or remote context, unknown field, graph form,
remote import, link, schema, or shape. The runtime uses strict Rust types and
never performs RDF expansion, graph merging, SPARQL, or network I/O.

The profile uses DCAT 3, W3C Recommendation 22 August 2024:
<https://www.w3.org/TR/2024/REC-vocab-dcat-3-20240822/>. It uses only
`dcat:Catalog`, `dcat:DataService`, and `dcat:endpointURL`, plus
`dct:title`, `dct:description`, `dct:conformsTo`, and `dct:spatial`.
Each exact capability binding is a separate `dcat:DataService` node.
`bindingId` is the JSON-LD alias for `@id` and is derived from the native
`serviceId`, service kind, endpoint, protocol/profile identifiers, and exact
capability tuple. `serviceId` is a Registry extension IRI relation that keeps
the native service identity stable across those binding nodes. This prevents
JSON-LD or RDF processing from merging independently searchable capabilities
into a false cross-product.
It aligns selected registry concepts with
DCAT-AP 3.0.1, the Recommendation targeted here. BRegDCAT-AP 3.0.0 is a
Working Draft; BRegDCAT-AP 2.1.0 is the latest published release. Neither
version is implemented as a complete profile, and Registry Discovery makes no
DCAT-AP or BRegDCAT-AP conformance claim. The exact versions, links, and
selected terms are pinned in `contracts/standards-profile.yaml`.
Registry-specific capabilities and roles use the fixed
`https://registrystack.org/discovery/vocab/v1alpha1#` namespace.

RDF and SHACL are offline conformance tooling concerns. They are not accepted
as an alternative runtime input. `scripts/validate_profile_rdf.py` provides a
small deterministic drift check over the vendored context, expected N-Triples,
and selected local constraints. Independently, the pinned RDFLib and pySHACL
oracle in `scripts/test_standards_oracle.py` performs standards-based JSON-LD
expansion and SHACL validation, compares every exact graph, disables network
access, and proves distinct binding nodes preserve capability correlation.
Neither tool widens the closed runtime parser or resolves remote resources at
runtime.

## ADR-003: Canonical bytes and exact identifiers

The profile rejects duplicate JSON members before deserialization, uses strict
closed types, requires sorted unique identifier arrays, and renders RFC 8785
canonical JSON with one trailing newline. Identifiers compare as exact Unicode
code points after JSON unescaping. Labels, URLs, and role values never acquire
trust or routing authority through normalization.

`catalogRevision` covers the normalized semantic service projection. It
intentionally excludes `originContentDigest`, `originFetchedAt`, and `builtAt`.
Identical semantic inputs therefore preserve record identities, semantic
fields, and revisions across builds, while fetch and build provenance
timestamps may change. This is semantic stability, not a claim that complete
index records or index bytes are identical across builds.

## ADR-004: Publication roles remain descriptive

`publisherId`, `operatorId`, `registryAuthorityId`, `legalIssuerId`, and
`technicalProviderId` are optional public identifiers. They remain distinct
and describe neither trust nor authorization. Each product derives any role it
already owns; the catalog does not require an invented role.

## ADR-005: Profile boundary excludes index and mapping models

`registry-discovery-profile` owns provider-publication descriptions only. It
does not own origins, fetched-byte digests, index records, mappings, revisions,
HTTP routes, query filters, native clients, or provider routing.
