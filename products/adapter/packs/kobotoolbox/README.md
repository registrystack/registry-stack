# kobotoolbox pack

A reviewed job pack for governed ingestion. It acquires KoboToolbox submissions
through the v2 data listing, one page per route run, and returns the item
contract `{items: [{key, revision, value}], next}`. It carries no compiled
knowledge, no writes, and no delete or patch endpoint.

- `pack.yaml` declares the `kobo-api` endpoint and the `kobo-submissions`
  route. `scripts/` holds the Rhai scripts that build the keyset query and
  shape each submission into an item.
- `fixtures/` holds five synthetic suites (first run, continuation, tail pass,
  empty pages, and a refused credential). Every name and value in them is made
  up.
- The [`kobotoolbox-job` example](../../examples/kobotoolbox-job/README.md)
  binds this pack to a job and a runtime configuration.

The read order, cursor, authentication, item mapping, limits, and the steps to
fork the pack for a wide form are in
[Adapter job packs](https://docs.registrystack.org/configure/adapter-packs/).

## Test

`crates/registry-adapter/tests/job_pack_replay.rs` compiles the route through
the job compiler and replays every fixture entry, checking the exact request
the route sends and the item page or problem class that comes back. It also
holds the refusal cases. `adapterctl job check` compiles the example job, and
`products/adapter/scripts/check-contracts.sh` runs it.
