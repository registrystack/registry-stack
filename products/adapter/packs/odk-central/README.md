# odk-central pack

A reviewed job pack for governed ingestion. It acquires ODK Central submissions
over the Central OData endpoints, one page per route run, and returns the item
contract `{items: [{key, revision, value}], next}`. It carries no compiled
knowledge, no writes, and no delete or patch endpoint.

- `pack.yaml` declares the `odk-odata` endpoint and the `odk-submissions` and
  `odk-repeats` routes. `scripts/` holds the Rhai scripts that build the cursor
  and shape each page.
- `fixtures/` holds six synthetic suites (first run, continuation, tail pass,
  empty pages, a refused credential, and a repeat table). Every name and value
  in them is made up.
- The [`odk-central-job` example](../../examples/odk-central-job/)
  binds this pack to a job and a runtime configuration.

The pack has not been run against an ODK Central server. The read order,
cursor, authentication, item mapping, and the behavior to confirm on your
deployment are in
[Adapter job packs](https://docs.registrystack.org/configure/adapter-packs/).

## Test

`crates/registry-adapter/tests/job_pack_replay.rs` compiles the routes through
the job compiler and replays every fixture entry, checking the exact request
each route sends and the item page or problem class that comes back. It also
holds the refusal cases. `adapterctl job check` compiles the example job, and
`products/adapter/scripts/check-contracts.sh` runs it.
