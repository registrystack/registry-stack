# Provider-publication profile

The published resource is a JSON-LD document whose `@context` is exactly
`https://registrystack.org/discovery/context/v1alpha1`. Implementations must
package and serve the bytes produced by `registry-discovery-profile`; they must
not assemble a live response or dereference the context.

The document is one `dcat:Catalog` JSON object holding `dcat:DataService`
entries, served as
`application/ld+json;profile="https://registrystack.org/discovery/profile/v1alpha1"`.
Parsing is closed: it refuses an alternative or remote context, an unknown
field, a graph form, an import, a link, a schema, or a shape. The runtime uses
strict Rust types and performs no RDF expansion, graph merging, SPARQL, or
network I/O. The selected DCAT and Registry extension terms are pinned in
`../contracts/standards-profile.yaml`.

Duplicate JSON members are rejected before deserialization, identifier arrays
must be sorted and unique, and identifiers compare as exact Unicode code points
after JSON unescaping. Labels, URLs, and role values never gain trust or
routing meaning through normalization. Canonical output is RFC 8785 JSON with
one trailing newline.

`publisherId`, `operatorId`, `registryAuthorityId`, `legalIssuerId`, and
`technicalProviderId` are optional public identifiers. They stay distinct,
describe neither trust nor authorization, and are derived by each product from
roles it already owns; the profile does not require a role a product lacks.
This profile describes provider publication only. It does not own origins,
fetched-byte digests, index records, mappings, revisions, HTTP routes, query
filters, native clients, or provider routing.

In an index service record, `semanticClassIds` and `operationFamilyIds` must be
empty arrays and `evidenceTypeIds` must be non-empty.

The published v1alpha1 context, schema, and SHACL bytes are unchanged. They
historically describe both Evidence and Relay advertisements. Relay fixtures
remain as profile-validation oracles only. The current Rust publication parser,
index, query API, and clients implement the Evidence-only subset and refuse a
Relay service. An operator with a mixed index must remove Relay origins and
rebuild the complete package before upgrading.

For the current Evidence subset, the schema describes the frozen historical
closed object shape. The Rust profile crate additionally applies the shared
`DisplayText` rule to `title` and `description`: it refuses bidirectional
embedding, override, and isolate controls, line and paragraph separators,
U+FEFF, and Unicode noncharacters while accepting the multilingual shaping and
direction characters U+00AD, U+061C, U+200B to U+200F, and U+2060. The
historical schema predates this runtime safety restriction, so schema acceptance
alone does not establish acceptance by the current parser.

The Rust profile crate also adds requirements this JSON Schema does not express
here: duplicate-key refusal, strict lexicographic collection ordering, URI
shape, local-test endpoint restriction, fixed upper bounds, product-kind
capability closure, and a centrally derived `bindingId` over the service
identity, kind, endpoint, conformance set, and exact capability tuple. Each
independently searchable capability binding is a separate Data Service node.
`serviceId` remains the native service identity shared by those nodes.

`../shapes/registry-discovery-v1alpha1.shacl.ttl` is the pinned offline SHACL
subset. `../../scripts/validate_profile_rdf.py --check` uses the local context
to expand the shipped fixtures to sorted N-Triples, then parses and evaluates
the selected local SHACL constraints as a deterministic drift check. The
product contract gate independently expands those same fixtures with pinned
RDFLib 7.1.4 and validates the resulting in-memory graph with pinned pySHACL
0.30.1. `uv sync --locked` may access the package index only to install that
test environment. Oracle execution is `--offline --no-sync`, injects only the
pinned local context and shapes, and denies socket connections. The independent
oracle also preserves the historical proof that two Relay binding nodes sharing
one `serviceId` retain their separate semantic-class and operation-family tuples.
