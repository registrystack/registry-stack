# Registry Record profile

This artifact-only product owns the Registry Record v1 base response profile
shared by Base Registry Engine and Registry Relay V2. It defines the stable profile,
schema, and JSON-LD context identifiers, but supplies no runtime code, resolver
client, authorization behavior, or source access.

The profile is intentionally open to product-owned extensions. Product OpenAPI
and response schemas remain responsible for closing the exact emitted shape and
for binding the response context to governed values. An exact JSON-LD product
schema must pin the complete ordered context URI array, and local product tests
must prove that locally pinned product contexts add terms without redefining a
shared-context-owned term. The open base schema is only a conformance aid: it
does not fetch context IRIs or turn them into trust or authority.

Run the local artifact and fixture contract check with:

```bash
products/registry-record/scripts/check.sh
```

The identifier catalog records exact SHA-256 digests for these published
artifacts. Resolver availability is a publication smoke check only, never a
runtime, compilation, validation, or startup dependency.
