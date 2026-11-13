# Receive an offline QField site registration

Use an existing QGIS form and PostGIS collection database to start one BReg operation from each complete QField submission.
The example captures a site point, one related boundary polygon, and two to eight contact rows with stable IDs.
It uses QFieldSync to return the offline edits to PostGIS.
Adapter reads the eligible rows through a view and delivers them through BReg's configured API.

## Prepare the collection

1. Create a dedicated PostgreSQL 17 database with PostGIS 3.5 available and run [schema.sql](source/schema.sql) as a database administrator in one transaction.
   The script provisions PostGIS and the reader group as needed, then creates three editable layers and the eligibility and status views.
2. Give the QGIS synchronization account permission to write those layers.
   Provision a separate `qfield_adapter_reader` login with inherited membership in `field_collection_adapter_reader`.
   This group can select the eligible view. Provision its login and password through your normal database process.
3. Use the [QGIS project instructions](qgis/README.md) to configure and package the native form.
   Save the related boundary and contacts, then mark the site ready.
   Return the package using QFieldSync before running the job.
4. Check `field_collection.site_intake_status` as the source owner.
   A site becomes eligible when the ready marker, form version, geometry and exact child IDs agree in one source query.
   The ready marker records the intended membership.
   The source view reads the synchronized values together when it evaluates eligibility.

For a fresh synthetic collection, you can provision and verify the source from the repository root.
Bind the `qfield_source_admin` PostgreSQL service to the collection administrator.
The test script rolls back its fixtures.

```sh
psql --dbname "service=qfield_source_admin" -v ON_ERROR_STOP=1 --single-transaction -f products/adapter/examples/qfield-postgis/source/schema.sql
psql --dbname "service=qfield_source_admin" -v ON_ERROR_STOP=1 -f products/adapter/examples/qfield-postgis/source/test.sql
```

## Bind the job

[Deploy the example BReg project](registry/README.md) in a separate registry database and bind the ingestion service identity.
Choose one job per collection.
[job.yaml](job.yaml) invokes the immediate `register-site` Action.
[job.proposal.yaml](job.proposal.yaml) starts and submits `propose-site` using the example's service initiator and review policy.
Use separate synthetic collections if you want to try both modes.

Copy [job-runtime.example.yaml](job-runtime.example.yaml) to an operator file.
Bind your PostGIS login, BReg service credential and Adapter job database through the named secret references.
Set the destination `resource` to the audience configured by your BReg deployment and issuer.
Use verified TLS for the source and destination.
The native QGIS project names a PostgreSQL service for the sync writer.
Bind that writer separately from the Adapter reader and the BReg service client.

Run this check from the repository root:

```sh
example=products/adapter/examples/qfield-postgis
cargo run --locked -p registry-adapterctl -- job check "$example/pack.yaml" "$example/job.yaml" \
  --runtime "$example/job-runtime.example.yaml" \
  --profile "$example/profile.yaml" --project "$example/project.yaml"
```

Initialize the job store and run a pass with the PostgreSQL source and direct BReg features and your operator runtime file.

```sh
cargo run --locked -p registry-adapter-job --features job-postgres,direct-breg -- \
  init-store --runtime /path/to/job-runtime.yaml
cargo run --locked -p registry-adapter-job --features job-postgres,direct-breg -- \
  pass "$example/job.yaml" --pack "$example/pack.yaml" \
  --runtime /path/to/job-runtime.yaml \
  --profile "$example/profile.yaml" --project "$example/project.yaml"
```

Inspect the job result, then read the record or Proposal through the authorized BReg API.
For a continuous deployment, use the interval trigger with the same bindings.
[Job operation and recovery instructions](../kobotoolbox-job/OPERATIONS.md).

## Read and recover

The source view returns geometry and repeats as bounded JSONB columns.
The [mapping](mappings/register-site.rhai) supplies the same typed inputs to the Action or Proposal.
The job keeps the source namespace and a digest of the stable site ID with its delivery progress.
Keep the namespace, job ID and deployment binding stable through retries.
Use the source's reconciliation schedule to find records that become ready behind an earlier page.
An unchanged item reuses its effect.
An admitted item whose projected values change and whose row remains eligible is held with the prior result reference.
An edit that removes eligibility is visible in the source status.
Deleting the source row or clearing readiness has no BReg effect.

If a destination response is lost, keep the original source row readable while the job retries the same command.
When the source has changed or the receipt window has expired, reconcile against the authoritative BReg result before taking another action.
The source retains the collection data and BReg retains the accepted inputs and effects.
Transport completion, Adapter intake and Proposal application have separate status.

This profile uses a native QGIS project and attachment-free submissions.
Forms that require attachment delivery need a separate supported destination.
For changes to the view, pack or mapping, update the exact query, pack and mapping digests in the dependent documents and run both job checks.
