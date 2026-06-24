# Call Registry Relay From An OpenFn Workflow

> **Page type:** How-to · **Product:** Registry Relay · **Layer:** client integration · **Audience:** integrator

This guide shows the caller-side OpenFn pattern for Registry Relay: an OpenFn
workflow reads protected registry records, metadata, relationships, or
aggregate outputs through a scoped Relay credential.

Use this pattern only when the workflow is authorized to read registry data
directly. If the workflow needs a governed trust decision, such as whether a
farmer is eligible or a certified value such as farmed land size, call Registry
Notary instead.

## Adaptor

The current OpenFn language adaptors for Registry Stack live in:

```text
https://github.com/jeremi/openfn-language-registry-stack
```

When that repository is configured as an OpenFn local adaptor repository,
Lightning and the worker load the Relay package as:

```text
@openfn/language-registry-relay@local
```

Configure an OpenFn credential with:

- `relay_base_url`: Registry Relay service base URL.
- `token`: bearer token or API key for the Relay caller credential.

The adaptor sends credentials as `Authorization: Bearer <token>`. It does not
send `x-api-key`.

## Lab Credentials

The public Registry Stack lab publishes current demo service URLs, scopes, and
tokens at:

```text
https://lab.registrystack.org/api/lab.json
```

For the agriculture Relay examples below:

- use `agri-row-reader` for row reads;
- use `agri-aggregate-reader` for aggregate reads;
- use `agri-metadata` for dataset discovery;
- use `agri-evidence-only` for evidence offering discovery.

The lab UI at `https://lab.registrystack.org` shows the same public demo
credentials.

## Read One Record

```js
execute(
  getRecord({
    dataset: "agri_registry",
    entity: "farmer",
    id: dataValue("farmer_id"),
    purpose: "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
    fields: ["id", "district", "registration_status"],
    as: "farmer",
    redactDataPaths: ["farmer_id"],
  }),

  fn((state) => {
    const farmer = state.data.farmer.record;

    return {
      ...state,
      data: {
        ...state.data,
        decision_input: {
          farmer_id: farmer.id,
          district: farmer.district,
          relay_request_id: state.data.farmer.request_id,
        },
      },
    };
  }),
);
```

## List Records

Collection reads require an explicit `limit` and at least one filter unless
`allowUnfiltered: true` is set.

```js
execute(
  listRecords({
    dataset: "agri_registry",
    entity: "farmer",
    purpose: "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
    filters: {
      district: "north",
      "id.in": ["FARMER-1001", "FARMER-1002"],
    },
    fields: ["id", "district", "registration_status"],
    limit: 50,
    as: "farmers",
  }),
);
```

## Query An Aggregate

```js
execute(
  queryAggregate({
    dataset: "agri_registry",
    aggregate: "voucher_opportunities_by_district_crop_risk_input",
    purpose: "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
    dimensions: ["district_code"],
    measures: ["eligible_opportunity_count"],
    filters: { season: ["2026A"] },
    maxRows: 100,
    as: "district_summary",
  }),

  fn((state) => {
    const observations = state.data.district_summary.observations;

    return {
      ...state,
      data: {
        ...state.data,
        north_voucher_opportunities:
          observations.find((row) => row.district_code === "north")?.eligible_opportunity_count ?? 0,
      },
    };
  }),
);
```

## Discovery

```js
execute(
  discoverDatasets({ as: "catalog" }),
  getEntitySchema({
    dataset: "agri_registry",
    entity: "farmer",
    as: "farmer_schema",
  }),
  listEvidenceOfferings({ as: "evidence_offerings" }),
);
```

Relay evidence offering routes are discovery only. They tell the workflow which
Registry Notary endpoint to use; Relay does not evaluate a claim.

## Guardrails

The adaptor is intentionally stricter than a generic HTTP helper:

- row, relationship, and aggregate helpers require `purpose`;
- `listRecords` requires `limit` and filters unless `allowUnfiltered: true`;
- `X-Request-Id` uses `state.data.request_id` when present;
- `traceparent` is forwarded when `state.data.traceparent` is present;
- `ETag`, `Retry-After`, request id, and pagination cursors are preserved;
- credentials, raw request material, and `configuration` are removed from final
  state;
- Problem Details are reduced to `code`, `status`, `title`, and `retryable`;
  the adaptor does not expose Problem Details `detail`.

Common result branches are `succeeded`, `not_modified`, `not_found`,
`auth_failed`, `forbidden`, `filter_required`, `cursor_invalid`,
`retryable_infrastructure`, and `failed`.
