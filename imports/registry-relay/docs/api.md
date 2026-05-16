# registry-relay API Guide

This guide describes the V1 HTTP contract from a client and operator point of view. The product contract remains [Spec.md](../Spec.md); this file is the practical reference for calling a running gateway.

## Listeners And Surfaces

The data-plane listener is `server.bind`. It serves health probes, docs, catalog metadata, dataset metadata, entity reads, verify checks, aggregates, OpenAPI, and optional provenance resources.

The admin listener is optional and only exists when `server.admin_bind` is configured. Admin routes must stay on a private network. They are never mounted on the public data-plane listener.

Public unauthenticated routes:

```text
GET /health
GET /ready
GET /docs
GET /docs/scalar.js
```

Auth-gated data-plane routes:

```text
GET /openapi.json
GET /catalog
GET /catalog/dcat-ap.jsonld
GET /datasets
GET /datasets/{dataset_id}
GET /datasets/{dataset_id}/{entity}/schema
GET /datasets/{dataset_id}/{entity}
GET /datasets/{dataset_id}/{entity}/{id}
GET /datasets/{dataset_id}/{entity}/{id}/{relationship}
GET /datasets/{dataset_id}/{entity}/verify
GET /datasets/{dataset_id}/{entity}/aggregates
GET /datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}
```

Admin routes on `server.admin_bind`:

```text
GET /metrics
POST /admin/datasets/{dataset_id}/tables/{table_id}/reload
POST /admin/reload
```

`GET /metrics` returns Prometheus-style `text/plain` metrics for operators. It is intentionally admin-listener only and is not mounted on `server.bind`.

`POST /admin/reload` is reserved for registry-wide reload and currently returns `501 admin.reload_unavailable`.

## Authentication

Clients send either header:

```http
Authorization: Bearer <api-key>
```

or:

```http
X-Api-Key: <api-key>
```

When both are present, `Authorization` wins. The gateway hashes the presented raw key with SHA-256 and compares it to fingerprints loaded from the environment variables named by `auth.api_keys[].hash_env`.

Scopes are independent. Grant the narrowest scope that lets the caller do its job:

| Scope suffix | Allows |
| --- | --- |
| `metadata` | Catalog, dataset summaries, entity schema, and OpenAPI visibility for that dataset |
| `rows` | Entity collection, single-record, and relationship reads |
| `verify` | Existence checks through `/verify` only |
| `aggregate` | Aggregate discovery and configured aggregate execution |
| `bulk_export` | Reserved for the V1.x contract, not implemented in 1.0 |
| `admin` | Admin listener operations |

## Entity Reads

Entity routes use configured entity names, not storage table ids. For example:

```text
GET /datasets/social_registry/individual?municipality_code=riverbend&limit=50
GET /datasets/social_registry/individual/ind-123
GET /datasets/social_registry/household/hh-42/members
```

Only fields exposed through `entities[].fields` appear in responses. If `fields` is omitted, every table column is exposed under its declared name. Storage-only columns should therefore be hidden by explicitly listing the public fields.

## Filters

Filters are opt-in. A query parameter is accepted only when its field appears in `entities[].api.allowed_filters`.

Common forms:

```text
?id=ind-123
?id.eq=ind-123
?id.in=ind-123,ind-456
?payment_amount.gte=100
?payment_amount.lte=500
```

Operators are configured per field with `ops: [eq, in, gte, lte, between]`. Arbitrary SQL is never exposed.

Some entities declare `required_filters`. Collection reads for those entities must include at least one of those fields or the gateway returns `400 entity.filter_required`. This protects sensitive resources from accidental unfiltered enumeration.

## Pagination And Conditional Requests

Collection routes support `limit` up to the entity's configured `max_limit`. Responses may include an opaque cursor for the next page. Treat cursors as server-owned tokens and pass them back unchanged.

Entity collection and record responses include validators where supported. Clients can use `If-None-Match` to avoid re-downloading unchanged content. A matching validator returns `304 Not Modified`.

## Purpose Headers

Entities can require a purpose string for row and verify reads:

```http
Data-Purpose: eligibility-check
```

When `require_purpose_header: true`, missing purpose returns `400 auth.purpose_required`. Use stable, reviewable purpose names. Do not put secrets, bearer tokens, or personal data in this header because it is recorded in audit logs.

## Catalog And OpenAPI

`GET /catalog` and `GET /catalog/dcat-ap.jsonld` return only datasets visible to the authenticated principal's metadata scopes.

`GET /openapi.json` is also auth-gated and metadata-filtered. The generated document includes only the operations and dataset/entity tags visible to the caller. `GET /docs` serves the local Scalar viewer and asks for a bearer token before fetching `GET /openapi.json`.

## Verify And Aggregates

Verify routes answer existence checks without returning row content:

```text
GET /datasets/social_registry/individual/verify?id=ind-123
```

Aggregates are predeclared in config. Clients can list available aggregates and execute one by id:

```text
GET /datasets/social_registry/individual/aggregates
GET /datasets/social_registry/individual/aggregates/by_municipality
```

Disclosure control is configured per aggregate. Suppressed or masked groups are normal results, not errors.

## Problem Details

Errors use RFC 9457 Problem Details with a stable `code` field:

```json
{
  "type": "https://data.example.gov/problems/auth/forbidden",
  "title": "Forbidden",
  "status": 403,
  "code": "auth.forbidden",
  "detail": "scope is not sufficient for this operation"
}
```

The exact text in `detail` is operator-facing but intentionally scrubbed. Do not depend on it programmatically. Use the HTTP status and `code`.

## Provenance Opt-In

When `provenance.enabled: true`, callers can request signed Verifiable Credentials for supported response families:

```http
Accept: application/vc+jwt
```

Plain JSON remains the default when the caller does not opt in. See [provenance.md](provenance.md) for signer config, DID Web behavior, VC-JWT shape, and verification steps.
