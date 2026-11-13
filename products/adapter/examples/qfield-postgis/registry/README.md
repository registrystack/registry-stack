# QField field-site registry

This synthetic BReg project is the destination for the sibling QField PostGIS
example. It declares one create-only `field-site` Record type and two fixed
request paths with equivalent fixed-effect Plans:

- `register-site` is immediate and requires Action `invoke` authority.
- `propose-site` is a service-owned Proposal with synthetic `review: none` and
  separately requires Proposal Start and Submit authority.

The `ingestion` profile accepts only the `adapter-field-ingestion` service
client with the `registry:write` scope. It grants no ordinary Record CRUD.
Each Plan fixes `owner` to that synthetic client identity, and target authority
requires the resulting owner to equal the verified `sub` claim. The two Plans
are deliberately duplicated because `registry.action-plan/v1` function inputs
accept scalar values, not the geometry and structured values used here.

## Inputs

Both Actions accept the same wire members:

| Wire member | BReg input | Contract |
|---|---|---|
| `sourceSubmissionId` | `source-submission-id` | Required UUID; unique on stored field sites |
| `siteName` | `site-name` | Required string, 1 to 160 characters |
| `position` | `position` | Required CRS84 GeoJSON Point, precision 7 |
| `boundary` | `boundary` | Required CRS84 GeoJSON Polygon, precision 7, at most 500 positions |
| `contacts` | `contacts` | Required array of 2 to 8 `{id, name}` objects with stable UUIDs and names of 1 to 80 characters |

Conditional display remains a source-form concern in this first example. No
`followUp` or `contactNote` input is stored or implied by BReg.

## Prepare the destination

Provision a separate BReg database for the project and follow the normal package activation steps.
The polygon requires the administrator to provision PostGIS in the BReg database.
[BReg package activation](../../../../../docs/site/src/content/docs/operate/breg-changes.mdx) and [spatial database requirements](../../../../breg/SPATIAL-QUERIES.md#database-and-upgrades).

## Offline checks

Run from the Registry Stack repository root with a `bregctl` built from this
checkout or the matching pinned release:

```sh
bregctl check products/adapter/examples/qfield-postgis/registry --deny-warnings
bregctl --format json explain actions products/adapter/examples/qfield-postgis/registry
bregctl --format json explain access products/adapter/examples/qfield-postgis/registry
```

`check` compiles both fixed Plans and validates their input, effect and access
contracts. `explain` exposes the compiled contract for review. The current
`project action-test` command runs named Rhai handlers only, so it cannot execute
these fixed Plans offline. Neither check proves runtime authorization, Proposal
application, uniqueness, spatial persistence or PostgreSQL transactions.

Run the declared immediate and Proposal journeys with a fixture-owned BReg
runtime, credential binding and receipt path:

```sh
bregctl test products/adapter/examples/qfield-postgis/registry \
  --runtime-config /absolute/path/to/runtime.yaml \
  --credentials /absolute/path/to/credentials.yaml \
  --output /absolute/path/to/receipt.json
```

The journey describes the distinct Invoke and Start/Submit routes.
The compiled access contract fixes the requester allowlist, scope, actor kind,
ownership and row boundary.

The maintained Adapter native acceptance executes both jobs against the real
PostGIS projection and BReg. It checks requester refusal on both mutation routes,
recovers the original Proposal after a lost response and reads both resulting
Records through BReg:

```sh
cargo test --locked -p registry-adapter-job \
  --features job-postgres,native-test-support,postgres-test,signed-coordinator-event \
  --test direct_breg_native \
  qfield_native::qfield_postgis_reaches_both_native_breg_action_modes_without_payload_storage \
  -- --ignored --exact --nocapture --test-threads=1
```

Use the Adapter `job-destinations` native runner to build and inject the exact
BReg binaries and the disposable PostgreSQL URL required by that ignored test.
