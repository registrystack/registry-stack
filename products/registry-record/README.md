# Registry Record profile

This artifact-only product owns the Registry Record v1 base response profile
shared by Registry Server and Registry Relay V2. It defines the stable profile,
schema, and JSON-LD context identifiers, but supplies no runtime code, resolver
client, authorization behavior, or source access.

The profile is intentionally open to product-owned extensions. Product OpenAPI
and response schemas remain responsible for closing the exact emitted shape and
for binding the response context to governed values.

Run the local artifact and fixture contract check with:

```bash
products/registry-record/scripts/check.sh
```

The identifier catalog records exact SHA-256 digests for these published
artifacts. Resolver availability is a publication smoke check only, never a
runtime, compilation, validation, or startup dependency.
