# OpenAPI Release Policy

Registry Relay has two OpenAPI surfaces:

- Runtime OpenAPI: auth-gated, generated from the running configuration, and
  filtered to the caller's metadata scopes.
- Static OpenAPI: the checked-in abstract artifact under
  [../openapi/](../openapi/), used for release review and contract discussion.

The runtime document is the source of truth for a deployed instance. The static
artifact is a release artifact, not a replacement for deployment discovery.

## Current Status

The REST route shape is under active design. Do not treat the static OpenAPI
file as final until the route design is stabilized and this policy has been run
for that release.

## When To Refresh The Static Artifact

Refresh the static OpenAPI artifact when any of these change:

- public route family;
- auth or scope requirement;
- query parameter or request body;
- response body or media type;
- Problem Details schema or stable error code;
- provenance media type or schema;
- standards adapter surface;
- metadata visibility rule that changes generated operations.

Do not refresh it for implementation-only refactors that leave the public
contract unchanged.

## Refresh Procedure

1. Stabilize the route design and update [api.md](api.md).
2. Start Relay with a representative release config.
3. Fetch the runtime OpenAPI document with a principal that can see the intended
   release surface.
4. Reduce instance-specific dataset/entity names to abstract placeholders if the
   release artifact is meant to stay deployment-neutral.
5. Validate JSON formatting.
6. Run the API documentation tests.
7. Diff the static artifact and check that every meaningful change is explained
   in release notes.

Suggested checks:

```sh
python -m json.tool openapi/registry-relay.openapi.json >/dev/null
cargo test --test api_docs
```

## Review Rules

Review the static artifact for:

- no secret examples;
- no private source paths;
- no deployment-only hostnames except example domains;
- no accidental broadening of scopes;
- Problem Details responses on non-2xx operations;
- correct media types for JSON, CSV, and VC-JWT responses;
- tags and summaries that match the docs;
- route families that match the stabilized API guide.

## Release Note Requirement

Every static OpenAPI refresh should mention one of:

- no public contract change, artifact refreshed for documentation parity;
- additive contract change;
- breaking contract change;
- route-design cleanup before the API is declared stable.

Until the REST design stabilizes, release notes should call the artifact
abstract and should direct deployments to fetch the runtime `/openapi.json`
document for concrete route and dataset shape.
