# PostgreSQL source example

This example reads a PostgreSQL view page by page and registers each row in BReg
through the `register-household` Action of
[`../kobotoolbox-breg/`](../kobotoolbox-breg/README.md). It is the smallest
complete job for a registry that already lives in a database. The data is
synthetic.

| File | What it is |
| --- | --- |
| [`households-view.sql`](households-view.sql) | Source-side setup: a table, the export view and a read-only login. Run it as the database owner. |
| [`queries/households.sql`](queries/households.sql) | The one query the pack runs. |
| [`pack.yaml`](pack.yaml) | The pack: one `postgres` endpoint, the pinned query and one `finite` route that rescans. |
| [`mappings/register-household.rhai`](mappings/register-household.rhai) | Turns one row into the Action inputs. |
| [`job.yaml`](job.yaml) | The job: pack pin, direct-BReg destination, projection and bounds. |
| [`profile.yaml`](profile.yaml), [`project.yaml`](project.yaml) | The Adapter profile and project the job compiles against. |
| [`job-runtime.example.yaml`](job-runtime.example.yaml) | The operator's runtime binding: database, TLS, secrets and the BReg client. |

## How the query is paged

The query is a plain `SELECT` with a root `ORDER BY` and no `LIMIT` or
`OFFSET`. The engine appends an `OFFSET` from the job cursor and reads at most
`maximumPageItems` rows per pass. Keep the `ORDER BY` on a unique column;
without it the pages are not stable.

`keyColumn: id` names the item identity. It must be unique, never `NULL` and
stable for the life of the row. The whole row is the source revision. The direct job skips an unchanged projection
and holds a changed projection for review after a possible or acknowledged effect. The
`registered_on` column is selected but not in the job projection, so it never
reaches BReg.

Column types map as the type table in
[`CAMEL-INGESTION-PORTS.md`](../../CAMEL-INGESTION-PORTS.md) says: text, the
integer and float types, `bool`, `numeric`, `date`, `timestamp`, `timestamptz`,
`uuid`, bounded `jsonb` and `NULL`. Cast anything else in the view. This example
exposes the key as text. Native `uuid` also works as a scalar key.

## Rescans

`scan: finite` reads the view to its end and stops. `edits: rescan` starts a new
pass from the first page after `rescanDelaySeconds` (3600 here). This is how
rows added or changed behind the read position are found. Lower the delay for a
fresher feed, and raise it for a large view.

## Use it for your registry

1. Create a view in your database with a stable text key `id` and only the
   columns the job needs. Create a read-only login with `SELECT` on that view
   only, as the SQL file shows.
2. Edit `queries/households.sql` for your view, then set the new sha256 of the
   file in `pack.yaml` under `queryFiles`.
3. Edit the mapping and the Action inputs in your BReg project to match your
   columns.
4. In `job-runtime.example.yaml`, set the host, database, user and
   `namespace`. Keep `passwordRef` as a reference into your secret provider.
   For a database whose certificate comes from a private CA, use
   `tls: {type: ca-bundle, caBundleFile: /path/to/ca.pem}`. TLS is required.
5. Repin: `shasum -a 256 pack.yaml` goes into `job.yaml` and `project.yaml`, and
   `shasum -a 256 mappings/register-household.rhai` goes into `job.yaml`.
6. Check the result, as below.

## Check it

From the repository root:

```sh
cargo run --locked -p registry-adapterctl -- job check products/adapter/examples/postgres-source/pack.yaml \
  products/adapter/examples/postgres-source/job.yaml \
  --runtime products/adapter/examples/postgres-source/job-runtime.example.yaml \
  --profile products/adapter/examples/postgres-source/profile.yaml \
  --project products/adapter/examples/postgres-source/project.yaml
```

The check compiles the job offline. It opens no database connection and
resolves no secret. It refuses a stale query, pack or mapping digest, and a
source the host build does not serve. `products/adapter/scripts/check-contracts.sh`
runs this command with the other job examples.

Check the BReg half with
`cargo run --locked -p registry-bregctl -- check products/adapter/examples/kobotoolbox-breg`.

## What is not covered here

No end-to-end run of this exact example is committed. The checked-in proofs run
the same host path against a disposable PostgreSQL with other fixtures:

- `crates/registry-adapter-job/tests/postgres_source_host.rs`, run by
  `products/adapter/scripts/test-job-postgres.sh`, pages a real PostgreSQL
  source through the host to the BReg and Coordinator destinations.
- `products/adapter/scripts/test-postgres-source-tls.sh` proves the verified-TLS
  path.

To run this example end to end, start a disposable PostgreSQL, run
`households-view.sql`, point `job-runtime.example.yaml` at it, and run the
`adapter-job` host built with `job-postgres` and `direct-breg`, against a BReg
that serves the `kobotoolbox-breg` project. The SQL and the paged query were run
by hand on PostgreSQL 17 to confirm the view returns the two registered rows.
