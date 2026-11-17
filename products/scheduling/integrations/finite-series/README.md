# Finite reservation series

A maintained recipe that lets a source application reserve a bounded weekly series through
Registry Scheduling's public Python client. The source owns the recurrence rule, series revisions,
occurrence identities, and a SQLite recovery journal. Registry Scheduling remains the only capacity
authority.

Bounds, civil-time rules, partial results, recovery, correlation references, edits, and a usage
example are in
[Author a Scheduling policy](https://docs.registrystack.org/configure/scheduling/#book-a-finite-weekly-series).

## Files

- `finite_series.py`: `SeriesJournal` and `SeriesProcessor`.
- `test_finite_series.py`: unit tests against a contract-shaped client double.
- `native_journey.py`: the executable journey against a disposable Scheduling database.
- `pyproject.toml` and `uv.lock`: the recipe's own dependencies.

## Test

Run the source and recovery tests without building Rust crates:

```sh
uv run --locked --directory products/scheduling/integrations/finite-series \
  python -m unittest -v test_finite_series.py
```

These tests exercise the authored recurrence and journal behavior with a contract-shaped client
double. They do not establish native client packaging, HTTP behavior, PostgreSQL locking,
task-grant authorization, or runtime capacity enforcement. The native journey does.

## Run the native journey

`native_journey.py` imports `registry_client.scheduling`, reads its token only from
`REGISTRY_SCHEDULING_TOKEN`, and accepts the runtime URL, source state directory, future local
start, policy revision, offering, and resource as arguments. Its state directory must be empty and
disposable for each run.

The journey needs the unified `registry-stack-client` wheel built for the same deployment version,
Python interpreter, and platform. Set `REGISTRY_CLIENT_WHEEL` to the absolute path of the matching
wheel. `uv run --with` installs it in the runner environment without changing the lock file:

```sh
uv run --locked --directory products/scheduling/integrations/finite-series \
  --with "${REGISTRY_CLIENT_WHEEL:?set the absolute path to the matching unified wheel}" \
  python native_journey.py --help
```

Run against a disposable fixture with the `meeting-room` offering and `room-a` resource (or supply
their argument overrides), after setting a future `SERIES_LOCAL_START` in Europe/Zurich civil time
and an empty state directory:

```sh
uv run --locked --directory products/scheduling/integrations/finite-series \
  --with "${REGISTRY_CLIENT_WHEEL:?set the absolute path to the matching unified wheel}" \
  python native_journey.py \
  --base-url "${SCHEDULING_BASE_URL:?set the fixture runtime URL}" \
  --policy-revision "${SCHEDULING_POLICY_REVISION:?set the current fixture policy revision}" \
  --local-start "${SERIES_LOCAL_START:?set a future local timestamp without an offset}" \
  --state-directory "${SERIES_STATE_DIRECTORY:?set an empty disposable directory}"
```
