# FHIR Source Adapter Guide

Registry Notary can read source data from FHIR R4 APIs to support configured
Notary claims. It does not become a FHIR server and it does not use the FHIR
`Evidence` resource as its claim model.

In the current implementation, FHIR access runs through the governed source
adapter runtime. Notary configs still use `connector: openfn_sidecar`; FHIR
request construction, Bundle parsing, graph traversal, and projection stay
inside that governed runtime bundle.

## Supported Prototype

The current prototype supports a bounded FHIR R4 GET graph:

- one anchor resource, such as `Patient`;
- explicit relation searches, such as `Coverage` by `beneficiary`;
- search parameter values from the primary lookup value, named query fields,
  literals, or a prior node reference;
- `token`, `reference`, `string`, `date`, and `code` search value encoding;
- JSON Pointer projection into Registry Data API-shaped rows;
- single reads and `records:batchMatch` batch reads;
- optional upstream bearer-token authorization from a sidecar-held environment
  variable;
- `Data-Purpose` forwarding to the upstream FHIR server;
- cardinality signaling through existing RDA row counts.

The adapter runtime never returns raw FHIR Bundles to Notary. It returns:

```json
{ "data": [{ "national_id": "person-123", "coverage_status": "active" }] }
```

Notary then evaluates ordinary claim rules over that projected row.

The current governed prototype covers these claim profiles with synthetic
fixtures:

- `patient-record-exists`
- `not-recorded-deceased`, including explicit `true`, explicit `false`, and
  missing `deceased[x]`
- `age-over-18`
- `coverage-active`
- `coverage-class-confirmed`
- `consent-valid-for-purpose`, with a configured FHIR purpose code
- `provider-affiliated-with-facility`
- `facility-offers-service`
- `requester-guardian-confirmed`

For batch evaluation, Notary sends the existing source adapter batch contract
with a `query_signature` and ordered item values. The adapter maps those values
back to named FHIR query inputs and returns per-item `data` arrays or sanitized
per-item errors.

## Coverage Active Shape

The first governed prototype is `coverage-active`:

```text
target.id
  -> Patient.identifier
  -> Coverage.beneficiary
  -> project Coverage.status
  -> Notary CEL: coverage_status == 'active'
```

Inactive coverage returns a projected row with `coverage_status: inactive`, so
the claim evaluates to `false`. Missing or ambiguous patient or coverage graph
matches continue to use existing Notary matching errors.

## Relationship Graph Shape

Profiles can use named query fields for requester or relationship-derived
inputs. Notary still owns the requester, relationship, and purpose policy; the
FHIR profile only receives the minimized field values it is configured to use.

Example:

```text
target.id + requester identifier
  -> Patient.identifier
  -> RelatedPerson.patient + RelatedPerson.identifier
  -> project relationship code
```

The sidecar profile uses `value_from_query` for named inputs:

```yaml
search:
  - param: identifier
    type: token
    system: https://example.gov/id/requester-id
    value_from_query: requester_id
```

## FHIR Source Profile

```yaml
sources:
  fhir_coverage:
    dataset: health_registry
    entity: coverage
    engine: fhir
    allow_insecure_localhost: true
    allowed_base_urls:
      - http://127.0.0.1:8080/fhir
    fhir:
      version: R4
      base_url: http://127.0.0.1:8080/fhir
      bearer_token_env: FHIR_UPSTREAM_TOKEN
      anchor:
        id: patient
        resource_type: Patient
        cardinality: one
        search:
          - param: identifier
            type: token
            system: https://example.gov/id/national-id
            value_from_lookup: true
      relations:
        - id: coverage
          resource_type: Coverage
          cardinality: one
          search:
            - param: beneficiary
              type: reference
              value_from_node: patient.reference
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        coverage_status:
          node: coverage
          pointer: /status
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields: [national_id]
      purpose: startup-smoke
```

FHIR projections can declare a scalar `default` for absent JSON Pointer values.
The `not-recorded-deceased` prototype uses this for missing
`Patient.deceased[x]`:

```yaml
deceased:
  node: patient
  pointer: /deceasedBoolean
  default: false
```

## Notary Binding

```yaml
source_connections:
  fhir_sidecar:
    base_url: http://127.0.0.1:9191
    allow_insecure_localhost: true
    retry_on_5xx: false
    bulk_mode: openfn_sidecar_batch
    token_env: FHIR_SIDECAR_TOKEN
    expected_sidecar:
      product: registry-notary-source-adapter-sidecar
      instance_id: demo
      environment: staging
      stream_id: openfn-sidecar-runtime
      config_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000
      require_expression_hashes_verified: true
      require_runtime_verified: true
      require_smoke_verified: true
claims:
  - id: coverage-active
    source_bindings:
      coverage:
        connector: openfn_sidecar
        connection: fhir_sidecar
        required_scope: health_registry:evidence_verification
        dataset: health_registry
        entity: coverage
        lookup:
          input: target.id
          field: national_id
          op: eq
          cardinality: one
        fields:
          coverage_status:
            field: coverage_status
            type: string
            required: true
    rule:
      type: cel
      expression: source.coverage.coverage_status == 'active'
```

The `config_hash` above is illustrative. Governed deployments must pin the
hash produced for the signed source adapter runtime bundle.

The repository also includes a parse-checked demo Notary config at
`demo/config/fhir-coverage-registry-notary.yaml`.

## Local Verification

Run the deterministic FHIR adapter fixture tests:

```bash
cargo test -p registry-notary-source-adapter-sidecar --test fhir_contract --locked
```

Run the governed Notary integration test:

```bash
cargo test -p registry-notary-server --features registry-notary-cel \
  governed_fhir_sidecar_e2e_evaluates_coverage_active_with_pinned_assurance \
  --locked
```

Both tests use synthetic in-process FHIR data. They do not call a public FHIR
server.

Validate the demo Notary config:

```bash
cargo test -p registry-notary-server --test demo_config \
  fhir_coverage_demo_config_loads_validates_and_builds_router \
  --locked
```

## Optional Live FHIR Exploration

Public FHIR test servers are useful for exploring real resource shapes before
turning them into local fixtures. They are not suitable for deterministic CI
because public data can change, be purged, or be temporarily unavailable.

Recommended no-auth R4 endpoints:

| Endpoint | Base URL | Best use |
| --- | --- | --- |
| SMART public R4 | `https://r4.smarthealthit.org` | First exploration target for linked synthetic patient data. |
| HAPI public R4 | `https://hapi.fhir.org/baseR4` | Broad resource-shape checks. Less deterministic because the server is regularly reloaded. |
| Firely public R4 | `https://server.fire.ly/R4` | Fallback open R4 server when SMART or HAPI do not expose a needed shape. |

Useful probes:

```bash
curl 'https://r4.smarthealthit.org/Patient?_summary=count'
curl 'https://r4.smarthealthit.org/Coverage?_count=5'
curl 'https://r4.smarthealthit.org/RelatedPerson?_count=5'
```

For review, record the endpoint, date, exact query path, observed resource
links, and whether the shape was captured as a synthetic local fixture. Do not
record real patient data, bearer tokens, or production identifiers.

Live smoke observed on 2026-06-16:

- HAPI public R4 exposed `Coverage/125144909 -> Patient/125144908`; direct
  patient read returned HTTP 200, and reverse
  `Coverage?beneficiary=Patient/125144908` returned one match.
- SMART public R4 count probes succeeded for the relevant resource families,
  but sampled `Coverage` and `RelatedPerson` references pointed to patients
  returning HTTP 410. Treat SMART as useful exploration data, not a guaranteed
  clean graph.

## Current Limits

- FHIR support currently runs through the source adapter runtime; there is no
  `connector: fhir`.
- FHIR searches use GET only.
- FHIR source profiles must declare `allowed_base_urls`; cleartext HTTP also
  requires `allow_insecure_localhost: true` and is accepted only for
  loopback/local test endpoints.
- Projection uses JSON Pointer only.
- Relation traversal is explicit and non-recursive.
- Batch matching is sequential per item inside the adapter runtime.
- The adapter trusts `entry.search.mode == "match"` and ignores `include` and
  `outcome` entries for cardinality.
