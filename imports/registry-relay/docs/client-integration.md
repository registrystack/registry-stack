# Registry Relay Client Integration Guide

This guide is for application teams calling Registry Relay. It describes client
behavior for the V1 dataset-scoped REST API.

For concrete deployment-specific paths and schemas, fetch the runtime OpenAPI
document from the deployment or use [api.md](api.md) as the general contract
reference. Runtime OpenAPI is auth-gated by default unless
`server.openapi_requires_auth` is disabled for demos or controlled tooling.

```mermaid
sequenceDiagram
  participant Client as Application client
  participant Relay as Registry Relay
  participant Notary as Registry Notary

  Client->>Relay: Authenticated discovery (OpenAPI, metadata, schemas)
  Relay-->>Client: Scoped views (ETag, 304 if unchanged)
  Client->>Relay: Read records (limit, cursor, Data-Purpose)
  alt transient failure, 429, or 503
    Relay-->>Client: Problem Details with Retry-After
    Client->>Relay: Retry idempotent GET with jittered backoff
  end
  Relay-->>Client: Entity records (opaque next_cursor)
  opt provenance enabled and requested
    Client->>Relay: Read with Accept application/vc+jwt
    Relay-->>Client: Signed VC-JWT, verified against issuer DID and schema
  end
  opt claim or evidence verification needed
    Client->>Relay: Discover evidence offering
    Relay-->>Client: access.kind registry-notary endpoint
    Client->>Notary: Follow Registry Notary client docs
  end
```

*The typical client lifecycle: authenticated discovery, scoped reads with
conservative retries, optional response provenance, and handoff to Registry
Notary for verification. Each step is detailed in the sections below.*

## Integration Checklist

Before a client is allowed to consume Relay data, confirm:

- The caller has a named service identity in the deployment's auth system.
- The caller has only the dataset scopes required for its workflow.
- Row reads that serve a human or program decision send `Data-Purpose`.
- Collection reads include required filters where entities declare them.
- The client handles RFC 9457 Problem Details instead of parsing text messages.
- The client treats cursors, ETags, and provenance credentials as opaque values.
- Logs redact bearer tokens, API keys, query values for sensitive fields, raw
  row bodies, VC-JWT bodies, and Problem Details `detail`.

## Authentication

Relay deployments use one auth mode at startup:

- API key: send the raw key as `Authorization: Bearer <key>`.
- OIDC: send the access token as `Authorization: Bearer <jwt>`.

Do not try both headers in the same client profile. Choose the mode advertised
by the deployment operator.

Scopes are dataset-local and independent:

| Scope Class | Use |
| --- | --- |
| `metadata` | Discover visible datasets, entities, schemas, policies, and scoped OpenAPI |
| `rows` | Read entity records and relationships |
| `aggregate` | Discover and execute configured aggregates |
| `evidence_verification` | Evidence-oriented standards adapter access, not Relay-local verification |
| `admin` | Reload sources on the private admin listener |

A `metadata` scope never implies row access. A row scope never implies
aggregate access. Evidence-verification scope does not expose a verification
execution endpoint in Relay.

## Purpose Header

Some entities require `Data-Purpose` for row or feature reads. Send a stable
purpose URI or controlled string that the operator can audit:

```http
Data-Purpose: https://data.example.gov/purposes/service-intake-check
```

The value is written into audit records. Do not put subject identifiers,
free-text case notes, bearer tokens, or other secrets in this header.

## Discovery

Use scoped discovery before hard-coding dataset assumptions:

1. Fetch the runtime OpenAPI document for the authenticated caller.
2. Fetch metadata catalog views for visible datasets and entity schemas.
3. Cache metadata only as a private, principal-specific artifact.
4. Refresh discovery after a deployment, config reload, or permission change.

Metadata responses may include `ETag`. If a client sends `If-None-Match`, an
unchanged scoped view can return `304 Not Modified`. Shared caches must not
reuse one caller's metadata for another caller.

## Reading Records

Treat entity names and field names as deployment contract, not table names.
Table ids and source column names are private operator configuration.

Recommended client behavior:

- Always set an explicit `limit`.
- Preserve opaque `next_cursor` values exactly as returned.
- Restart pagination from the first page when filters, projection, purpose, or
  auth context changes.
- Handle `pagination.cursor_invalidated` by restarting the read with the same
  query intent.
- Avoid broad unfiltered reads unless the entity contract explicitly allows
  them.

Fields marked `sensitive: true` are audit-redacted. That flag is not an
authorization control and does not hide fields from authorized API responses.

## Aggregates

Aggregates are predeclared by the operator. Clients may discover available
indicators, dimensions, defaults, disclosure controls, and metadata before
executing an aggregate.

For JSON responses, handle suppression and masking as normal result states.
Suppressed groups are not transport failures.

CSV output is intended for operational exports and interoperability. When a
deployment supports CSV aggregate output, clients should preserve:

- response headers describing disclosure and freshness;
- the `Link: rel="describedby"` aggregate metadata relation;
- CSV header names exactly as returned.

## Errors

Relay returns Problem Details for non-2xx responses. Log only safe fields:

- HTTP status
- `code`
- `title`
- request id, if present
- retry-related headers, if present

Avoid logging `detail` in production unless the operator has confirmed it is
redacted for that deployment.

Typical client handling:

| Code Family | Client Action |
| --- | --- |
| `auth.*` | Refresh credentials or fail closed |
| `entity.filter_required` | Add one of the required filters |
| `pagination.cursor_invalidated` | Restart pagination |
| `metadata.*` | Refresh discovery or report deployment mismatch |
| `aggregate.*` | Check aggregate metadata and caller scope |
| `provenance.*` | Fall back to plain JSON only if the workflow permits unsigned data |

## Retries

Use conservative retries:

- Retry idempotent GETs for transient transport failures, `429`, or `503`.
- Honor `Retry-After` when present.
- Use jittered exponential backoff.
- Do not retry requests that could create audit ambiguity unless the route
  contract explicitly says it is idempotent.

Relay is read-only for registry data, but retries still create extra audit
events and may repeat costly source reads.

## Provenance Opt-In

When provenance is enabled, clients can request signed response credentials with
an accepted VC media type. Treat the returned compact JWS as an opaque signed
artifact and verify it with the issuer DID document and published schemas.

Do not confuse Relay response provenance with Registry Notary evidence
verification. Relay can sign selected data responses. Registry Notary owns
claim evaluation, evidence verification, credential issuance workflows, and the
verification semantics behind evidence offerings.

## Registry Notary Handoff

Relay evidence-offering metadata may advertise `access.kind: registry-notary`.
When a client needs to verify claims or evidence:

1. Discover the offering through Relay metadata.
2. Read the advertised Registry Notary endpoint or discovery URL.
3. Follow Registry Notary's client documentation for request shape, claim
   semantics, presentation, result verification, and credential issuance.

Relay docs should not duplicate Registry Notary's verification contract.
