# Provider-publication profile

The published resource is a JSON-LD document whose `@context` is exactly
`https://registrystack.org/discovery/context/v1alpha1`. Implementations must
package and serve the bytes produced by `registry-discovery-profile`; they must
not assemble a live response or dereference the context.

The published v1alpha1 context, schema, and SHACL bytes are unchanged. They
historically describe both Evidence and Relay advertisements. Relay fixtures
remain as profile-validation oracles only. The current Rust publication parser,
index, query API, and clients implement the Evidence-only subset and refuse a
Relay service. An operator with a mixed index must remove Relay origins and
rebuild the complete package before upgrading.

For the current Evidence subset, the schema describes the closed object shape. The Rust profile crate adds
the requirements JSON Schema cannot express here: duplicate-key refusal,
strict lexicographic collection ordering, URI shape, local-test endpoint
restriction, fixed upper bounds, product-kind capability closure, and a
centrally derived `bindingId` over the service identity, kind, endpoint,
conformance set, and exact capability tuple. Each independently searchable
capability binding is a separate Data Service node. `serviceId` remains the
native service identity shared by those nodes.

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
