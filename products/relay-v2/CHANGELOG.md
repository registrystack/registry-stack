# Relay V2 changelog

## Unreleased

## v0.26.0 - 2026-09-03

### BREAKING: adopt Registry Record profile v1

Relay JSON and JSON-LD consultation responses now conform to
`https://id.registrystack.org/profiles/registry-record/v1`. Every resource must
declare `datasetIdentifier` and `entityTypeIdentifier` beside `id`. These are
governed identifiers and are never inferred.

Before, every JSON or JSON-LD Record repeated `registryIdentifier`:

```json
{"data":{"registryIdentifier":"urn:example:registry:businesses","recordIdentifier":"B-1"}}
```

After, one homogeneous response context is carried by `meta`, and the Record
does not duplicate it:

```json
{"data":{"recordIdentifier":"B-1"},"meta":{"registryIdentifier":"urn:example:registry:businesses","datasetIdentifier":"legal-entities","entityTypeIdentifier":"company"}}
```

Migration:

1. Add stable `datasetIdentifier` and `entityTypeIdentifier` fields to every
   authored resource. Rename any domain property using a Registry Record
   envelope, identifier, context, or pagination member; those keys are
   reserved infrastructure and cannot appear in `domainData`.
2. Regenerate and reseal packages. Existing packages fail strict compilation
   because the new fields are required and participate in the package digest.
3. Read Registry, dataset, and entity-type identity from response `meta`, not
   from each `data` or `items` Record.
4. For JSON-LD, accept the two-entry `@context` array containing the shared
   Registry Record context followed by the generated operation context. The
   second context adds Relay and selected domain terms without redefining any
   shared term.
5. Treat pre-change cursors and ETags as invalid. Restart pagination and cache
   revalidation after deployment.
6. If you publish a Registry Discovery description for this deployment,
   declare `conformsTo` with both
   `https://id.registrystack.org/profiles/registry-record/v1` and the
   bumped `https://registrystack.org/relay/profile/v3`, replacing the prior
   `https://registrystack.org/relay/profile/v2`.

JSON and JSON-LD success responses advertise both the shared profile and Relay
profile v3 in `Link` headers. Generated OpenAPI operations identify the shared
response profile and close the three response-context values to the compiled
Registry and resource. GeoJSON keeps its separate OGC media profile and shape.
