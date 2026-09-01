# Registry Record v1 profile

Profile identifier: `https://id.registrystack.org/profiles/registry-record/v1`

Schema identifier: `https://id.registrystack.org/schemas/registry-record/v1`

JSON-LD context identifier:
`https://id.registrystack.org/contexts/registry-record/v1`

Registry Record v1 is a small, open base profile for one released Registry
record or a homogeneous collection of released Registry records. The three
identifiers above name reviewed local artifacts. Implementations must use
locally pinned bytes and digests; they must not fetch a resolver to authorize a
request, compile a package, validate a response, or start a service.

`/v1` is one compatibility line. Its required members and JSON-LD term
mappings cannot be added, removed, relocated, or redefined. A change requiring
consumers to change parsing or interpretation publishes a new profile version.

## Single record

```json
{
  "data": {
    "recordIdentifier": "company-123",
    "revisionIdentifier": "42",
    "domainData": {
      "legalName": "Example Ltd"
    }
  },
  "meta": {
    "registryIdentifier": "business-registry",
    "datasetIdentifier": "legal-entities",
    "entityTypeIdentifier": "company"
  }
}
```

## Collection

```json
{
  "items": [
    {
      "recordIdentifier": "company-123",
      "revisionIdentifier": "42",
      "domainData": {
        "legalName": "Example Ltd"
      }
    }
  ],
  "pageInfo": {
    "nextCursor": null
  },
  "meta": {
    "registryIdentifier": "business-registry",
    "datasetIdentifier": "legal-entities",
    "entityTypeIdentifier": "company"
  }
}
```

All five identifiers, `registryIdentifier`, `datasetIdentifier`,
`entityTypeIdentifier`, `recordIdentifier`, and `revisionIdentifier`, are
opaque non-empty strings. `nextCursor` is either `null` or an opaque non-empty
string. `domainData` is an object containing only fields released by the
selected product access context and projection. It must not contain profile
infrastructure members.

The collection response context appears once because every collection is
homogeneous for Registry, primary dataset, and entity type. A cross-dataset or
cross-entity operation must use another profile or explicit per-item context.

## JSON-LD

JSON uses no `@context`. JSON-LD uses `application/ld+json` and exactly the
governed context identifier below, and releases exactly the same values as
JSON. Inline, host-selected, and other context identifiers do not conform. The
shared context maps the five opaque identifiers to string-valued vocabulary
predicates, never to JSON-LD node identifiers. Canonical resource IRIs belong
in separate governed terms or links.

```json
{
  "@context": "https://id.registrystack.org/contexts/registry-record/v1",
  "data": {
    "recordIdentifier": "company-123",
    "revisionIdentifier": "42",
    "domainData": {
      "legalName": "Example Ltd"
    }
  },
  "meta": {
    "registryIdentifier": "business-registry",
    "datasetIdentifier": "legal-entities",
    "entityTypeIdentifier": "company"
  }
}
```

## Extension and representation rules

This is a base conformance profile. Product schemas may add members while
preserving the required members and meanings above. Consumers that validate
only this profile must tolerate those product extensions. A product profile may
close its actual response shape.

Successful single reads, single-result lookups, creates, patches, and
tombstones use the single shape. Homogeneous list and revision-history
operations use the collection shape. Batch mutations, GeoJSON, SDMX,
catalogue metadata, OpenAPI, JSON Schema, and other non-record representations
use separately named contracts. Successful responses advertise this profile
with an RFC 6906 `Link` header using `rel="profile"`.
