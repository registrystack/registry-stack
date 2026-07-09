# Registry Relay client integration guide

This guide is for application teams calling Registry Relay. It describes client
behavior for the V1 dataset-scoped REST API.

For concrete deployment-specific paths and schemas, fetch the runtime OpenAPI
document from the deployment at `GET /openapi.json`, or read the
[Registry Relay API reference](https://docs.registrystack.org/api/registry-relay.html).
Runtime OpenAPI is auth-gated by default unless `server.openapi_requires_auth`
is disabled for demos or controlled tooling.

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
  opt claim or evidence verification needed
    Client->>Relay: Discover evidence offering
    Relay-->>Client: access.kind registry-notary endpoint
    Client->>Notary: Follow Registry Notary client docs
  end
```

*The typical client lifecycle: authenticated discovery, scoped reads with
conservative retries, and handoff to Registry Notary for verification or
credential issuance. Each step is detailed in the sections that follow.*

## Connect to an existing deployment

When another organization operates the Relay you are integrating with, request
three things from that operator before writing code:

- **A named service identity.** Every caller is a named principal in the
  deployment's auth config. For API-key deployments the operator runs
  `registry-relay generate-api-key --id <your_identity>` and hands you the raw
  key once; only the fingerprint is stored server-side, so a lost key means a
  new one. For OIDC deployments, ask for the client registration details and
  the scope grant instead.
- **Dataset scopes.** Scopes are dataset-local `<dataset_id>:<level>` labels.
  The levels are `metadata` (catalog, schema, and OpenAPI visibility), `rows`
  (entity record and relationship reads), `evidence_verification`
  (evidence-oriented standards-adapter access, separate from row reads),
  `aggregate` (aggregate discovery and execution), and `admin` (admin listener
  operations, never needed for data reads). Name the workflows you run and ask
  for the minimal scope list; see
  [Authentication in the API reference](api.md#authentication) for the full
  semantics.
- **Accepted purpose values.** If your reads serve a human or program
  decision, the deployment may require a `Data-Purpose` header. Ask which
  purpose URIs your data-sharing agreement authorizes; see
  [Purpose header](#purpose-header) below.

To confirm the grant works before integrating deeper, call `GET /v1/datasets`:
it lists every dataset visible to your principal. An empty list or a `403`
means the scope grant does not match what you asked for; resolve that with the
operator before debugging client code.

## Integration checklist

Before a client is allowed to consume Relay data, confirm:

- The caller has a named service identity in the deployment's auth system.
- The caller has only the dataset scopes required for its workflow.
- Row reads that serve a human or program decision send `Data-Purpose`.
- Collection reads include required filters where entities declare them.
- The client handles RFC 9457 Problem Details instead of parsing text messages.
- The client treats cursors and `ETags` as opaque values.
- Logs redact bearer tokens, API keys, query values for sensitive fields, raw
  row bodies, credential bodies from Notary workflows, and Problem Details `detail`.

## OpenFn workflows

OpenFn workflows can use the Registry Stack OpenFn Relay adaptor instead of a
generic HTTP step. The adaptor provides helpers for protected record reads,
relationship reads, aggregate queries, dataset discovery, entity schemas, and
evidence offering discovery:

```text
@openfn/language-registry-relay@local
```

Use the adaptor when the workflow is authorized to read Relay data directly.
Use Registry Notary when the workflow needs a governed trust decision or a
certified value claim. The [OpenFn Relay guide](openfn-relay-adaptor-guide.md)
shows the lab-backed workflow shape and guardrails.

## Authentication

Relay deployments use one auth mode at startup:

- API key: send the raw key as `Authorization: Bearer <key>`.
- OIDC: send the access token as `Authorization: Bearer <jwt>`.

Do not try both headers in the same client profile. Choose the mode advertised
by the deployment operator.

Scopes are dataset-local and written as `<dataset_id>:<level>` (for example
`social_registry:rows`). Request only the scopes your workflow needs: a
`metadata` scope never implies row access, a row scope never implies aggregate
access, and the `evidence_verification` scope grants standards-adapter access
only, not a Relay-local verification execution endpoint. For the full scope
semantics see the [Registry Relay API reference](api.md#authentication).

## Purpose header

Some entities require `Data-Purpose` for row or feature reads. Send a stable
purpose URI or controlled string that the operator can audit:

```http
Data-Purpose: https://data.example.gov/purposes/service-intake-check
```

The value is written verbatim into audit records. Purpose values are not
enforced or validated at the consultation layer; Registry Notary is the
purpose-certification layer. Do not put subject identifiers, free-text case
notes, bearer tokens, or other secrets in this header. For the full list of
entities that enforce this header and the resulting error code, see
the [Registry Relay API reference](api.md#purpose-headers).

The set of acceptable purpose values is defined by the operator and your
data-sharing agreement, not by Relay: there is no API route that enumerates
valid purposes. If your agreement does not name specific URIs, propose a small
set of stable URIs under a namespace your organization controls (one per
workflow, as in the example above) and have the operator confirm them. Keep
the values stable across releases so the operator's audit trail stays
queryable.

## Discovery

Use scoped discovery before hard-coding dataset assumptions:

1. Fetch the runtime OpenAPI document for the authenticated caller. Send your
   bearer credentials on this request too: `GET /openapi.json` is auth-gated by
   default, and an unauthenticated fetch fails unless the operator has disabled
   `server.openapi_requires_auth`.
2. Fetch metadata catalog views for visible datasets and entity schemas.
3. Cache metadata only as a private, principal-specific artifact.
4. Refresh discovery after a deployment, config reload, or permission change.

Metadata responses may include `ETag`. If a client sends `If-None-Match`, an
unchanged scoped view can return `304 Not Modified`. Shared caches must not
reuse one caller's metadata for another caller.

## Reading records

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
measures, dimensions, defaults, disclosure controls, and structure before
executing an aggregate.

For JSON responses, handle suppression and masking as normal result states.
Suppressed groups are not transport failures.

CSV output is intended for operational exports and interoperability. When a
deployment supports CSV aggregate output, clients must preserve:

- response headers describing disclosure and freshness;
- the `Link: rel="describedby"` aggregate structure relation;
- CSV header names exactly as returned.

SDMX JSON output is intended for statistical tooling. Request it with
`?f=sdmx-json`, request body `"format": "sdmx-json"`, or
`Accept: application/vnd.sdmx.data+json;version=2.1`. SDMX messages declare
`https://json.sdmx.org/2.1/sdmx-json-data-schema.json`; clients must also
check the `meta.x-completeness` object before treating a cube as complete.

### Relay SDMX conventions

Relay maps aggregate results onto SDMX JSON with a few relay-specific
conventions integrators must account for:

- Measure descriptors carry relay extension keys alongside the standard SDMX
  fields: `x-unitMeasure` reports the measure unit, `x-unitMultiplier` reports
  the unit multiplier (or `null` when unset), and `x-decimals` reports the
  configured decimal precision (or `null` when unset).
- `meta.sender` is fixed to `{ "id": "registry-relay", "name": "Registry
  Relay" }`. It identifies the relay as the message sender and does not vary by
  deployment or dataset.
- The measure `definition_uri` available in the native JSON and discovery
  responses is not mapped into the SDMX output. Clients that need a measure's
  definition URI must read it from the native structure or measure-discovery
  responses.

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
| `aggregate.*` | Check aggregate structure, measure discovery, and caller scope |

## Retries

Use conservative retries:

- Retry idempotent GETs for transient transport failures, `429`, or `503`.
- Honor `Retry-After` when present.
- Use jittered exponential backoff.
- Do not retry requests that could create audit ambiguity unless the route
  contract explicitly says it is idempotent.

Relay is read-only for registry data, but retries still create extra audit
events and may repeat costly source reads.

## Registry Notary handoff

Relay publishes evidence offering metadata for discovery and delegates all claim
and evidence verification to Registry Notary. Notary also owns credential
issuance. The only evidence offering routes
in Relay are:

```http
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
```

These routes require the caller's `metadata` scope for the owning dataset. They
return discovery records; they do not execute a check, compute claim hashes,
issue verification receipts, or disclose row data. There is no
`POST /evidence-offerings/{offering_id}/verifications` route in Relay.

```mermaid
sequenceDiagram
  participant Client as Service client
  participant Relay as Registry Relay
  participant Notary as Registry Notary

  Client->>Relay: GET /metadata/evidence-offerings
  Relay-->>Client: Offering metadata with access.kind registry-notary
  Client->>Notary: Submit claim or evidence to the advertised endpoint
  Notary-->>Client: Verification result or credential
```

*The discovery and verification boundary. Relay publishes evidence offering
metadata that points to a Notary; the client submits the claim or evidence to
that Notary, which performs verification. Relay makes no verification decision.*

When a client needs to verify claims or evidence:

1. Fetch `GET /metadata/evidence-offerings` (or the single-offering route by id)
   to discover available offerings.
2. Read the `access.kind: registry-notary` field and the advertised Notary
   endpoint or discovery URL.
3. Follow Registry Notary's client documentation for request shape, claim
   semantics, presentation, result verification, and credential issuance.

A discovery response looks like this (one offering shown; host names are
illustrative):

```json
{
  "evidence_offerings": [
    {
      "id": "benefits_person_evidence",
      "title": "Benefits person status evidence",
      "iri": "https://demo.example.gov/evidence-offerings/benefits-person",
      "description": "Registry Notary verification for submitted benefits person eligibility status and role facts.",
      "dataset_id": "benefits_casework",
      "entity": "person",
      "evidence_type": {
        "id": "benefits_person_record_evidence",
        "iri": "https://demo.example.gov/evidence-types/benefits-person-record",
        "name": "Benefits person record evidence"
      },
      "evidence_type_iri": "https://demo.example.gov/evidence-types/benefits-person-record",
      "issuing_authority": {
        "id": "ministry_of_social_affairs",
        "iri": "did:web:social-affairs.demo.example.gov",
        "name": "Ministry of Social Affairs",
        "country": "ZZ"
      },
      "jurisdiction": { "country": "ZZ", "region": null },
      "level_of_assurance": "substantial",
      "lookup_keys": ["id"],
      "policy": {
        "purpose": ["https://demo.example.gov/purpose/social-protection-eligibility"]
      },
      "procedure_contexts": [],
      "requirement_iris": ["https://demo.example.gov/requirements/benefits-person"],
      "information_concepts": [],
      "verification_request_schema_url": "https://relay.demo.example.gov/metadata/schema/benefits_casework/person/schema.json",
      "access": {
        "kind": "registry-notary",
        "ruleset": "benefits-person-v1",
        "endpoint_url": "https://notary.demo.example.gov/evidence-offerings/benefits-person/verifications",
        "discovery_url": "https://notary.demo.example.gov/.well-known/registry-notary",
        "conforms_to": "https://demo.example.gov/standards/registry-notary/evidence-v1"
      }
    }
  ]
}
```

The `access` object is what drives the handoff: `kind` is always
`registry-notary` in V1 (Relay is never the verifier), `ruleset` names the
Notary ruleset that governs verification for this offering, `endpoint_url` is
where claims or evidence are submitted, `discovery_url` is the Notary
well-known document for resolving endpoint details (either URL may be null
when the other is present), and `conforms_to` identifies the evidence contract
the offering follows.

The `evidence_verification` scope is available as a distinct label for
standards adapters and integrations that need evidence-oriented access separate
from row reads. It does not grant metadata, rows, aggregates, admin reload, or a
Relay-local verification endpoint.

Use Registry Notary's documentation as the source of truth for verification
semantics, claim request bodies, result interpretation, credential issuance,
client retries, and verifier behavior:

- [Registry Notary client SDK guide](https://docs.registrystack.org/products/registry-notary/client-sdk-guide/)
- [Registry Notary documentation](https://docs.registrystack.org/products/registry-notary/)
