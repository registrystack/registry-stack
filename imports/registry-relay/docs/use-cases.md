# Registry Relay Use Cases

## Purpose

These use cases describe the core Registry Relay product journeys. They focus on
Relay as a protected registry consultation gateway: turning sensitive registry
extracts into secure, read-only, domain-oriented APIs with scoped access,
metadata, aggregates, provenance, audit, and operational controls.

Evidence verification and credential issuance are intentionally not part of this
core set. Registry Relay may publish evidence offerings for discovery, but
Registry Notary is the home for claim evaluation, disclosure policy,
attestations, and credential issuance.

## 1. Registry Operator Turns A Spreadsheet Into A Protected Registry API

As a registry operator, I want to configure Registry Relay over an existing
Excel, CSV, Parquet, or PostgreSQL source, so that a sensitive registry extract
becomes a secure, read-only, domain-oriented API without exposing source files,
storage tables, or private columns directly.

Acceptance criteria:

- Source files or tables are mapped into configured datasets and entities, with
  storage table ids kept out of the public URL space.
- Only configured public fields appear in API responses.
- Authentication is required for protected routes through configured API-key or
  OIDC policy.
- Dataset scopes separate metadata, row reads, aggregates, and admin
  operations.
- Row APIs support configured limits, field projection, allowed filters,
  required filters, pagination, and purpose-header requirements.
- The gateway emits redacted, tamper-evident audit events and avoids logging raw
  secrets, auth headers, request bodies, or row values.
- Health, readiness, refresh, and admin reload behavior let operators serve new
  extracts without changing public API contracts.

## 2. Authorized System Consults Protected Registry Entities

As an authorized system, I want to query entity-shaped registry APIs, so that I
can consult the registry for a specific operational purpose without direct
database, spreadsheet, or filesystem access.

Acceptance criteria:

- The caller can list visible datasets and read only entities covered by its
  dataset scopes.
- Entity routes use domain names such as `individual`, `household`, or
  `birth_record`, not private storage table names.
- Collection reads accept only configured filters and enforce maximum limits.
- Sensitive entities can require at least one configured filter to prevent
  accidental enumeration.
- Record and relationship reads return only configured public fields.
- When a purpose header is required, missing or invalid purpose information is
  denied before the row read completes.
- Responses use consistent error shapes, cache controls, and pagination tokens
  that clients can treat as server-owned.

## 3. Integrating System Discovers Scoped Metadata And Policy

As an integrating system, I want to discover only the metadata, schemas, and
policy information visible to my principal, so that I can understand what the
registry exposes before building or calling an integration.

Acceptance criteria:

- Metadata routes are filtered by the caller's dataset metadata scopes.
- Relay can expose catalog, dataset, entity, field, relationship, JSON Schema,
  SHACL, DCAT, and OGC Records metadata without granting row access.
- OpenAPI output is auth-gated and includes only operations visible to the
  authenticated principal.
- Portable metadata manifests stay separate from runtime configuration, so
  source paths, table ids, scopes, backend URLs, and SQL are not published.
- Dataset ODRL Offers can describe intended purposes, duties, assigners, and
  prohibitions for governance and discovery.
- Published policy metadata is descriptive and does not itself grant access,
  enforce duties, create agreements, or negotiate contracts.

## 4. Authorized Analyst Runs Configured Aggregate Queries

As an authorized analyst, I want to run preconfigured aggregate queries, so that
I can get approved summary answers without receiving row-level registry data.

Acceptance criteria:

- Aggregate access is controlled by dataset aggregate scopes, independently from
  row-read scopes.
- Only configured aggregate ids can be executed; arbitrary SQL or ad hoc
  expressions are not exposed.
- Aggregate responses are computed over the configured entity model and respect
  the deployment's operational limits.
- Aggregates can be discoverable through scoped metadata when the caller has the
  required visibility.
- Aggregate calls are audited with bounded, redacted context.
- When provenance is enabled and requested, aggregate results can be returned as
  signed Verifiable Credentials.

## 5. Relying Party Receives Signed Provenance For Registry Responses

As a downstream relying party, I want signed provenance for selected registry
responses, so that I can prove a record or aggregate response came from the
registry gateway at a specific time under a configured issuer DID.

Acceptance criteria:

- Provenance issuance is opt-in by operator configuration and by caller `Accept`
  negotiation.
- Plain JSON remains the default response when signed output is not configured
  or not requested.
- Entity-record and aggregate-result credentials include issuer, subject,
  validity, schema, type, and signing-key information in the signed envelope.
- Signing keys are injected through secret environment variables and are never
  stored in runtime YAML, image layers, logs, or API responses.
- DID Documents, schemas, and contexts are published at stable URLs that
  downstream verifiers can resolve.
- Key rotation preserves verification for credentials issued under retired keys
  until their validity windows expire.
- Provenance issuance events are audited without recording private signing
  material or full signed credential bodies.
