# Future activation with a Record timer

This complete, domain-neutral project schedules one `service` Record to move
from `scheduled` to `active`. The Record owns the intended activation time,
optional window end, rearm identity, and predicate facts. The root project
grants the exact `service/activate` timer; no caller can invoke its
`activate-service` Action.

From the repository root, check the authored project and inspect its effective
timer authority:

```sh
cargo run --locked -p registry-bregctl -- check \
  products/breg/examples/future-activation --production
cargo run --locked -p registry-bregctl -- --format json explain access \
  products/breg/examples/future-activation
```

Those commands prove parsing, compilation, and the reported authority. They do
not prove database scheduling, transaction atomicity, process recovery, or
replica contention.

## Run the native PostgreSQL journey

The native test requires a real PostgreSQL URL whose role may create and drop
disposable test databases and roles. It is opt-in through the
`postgres-test` feature and does not pass by skipping when the URL is absent.
Set the URL without committing credentials, then run the complete maintained
target serially:

```sh
export BREG_TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST:PORT/DATABASE'
cargo test --locked -p registry-breg --features postgres-test,tooling,schema \
  --test postgres_record_timer_native -- --test-threads=1
```

The target builds and starts independent native `breg` processes over one
fixture-owned database. Its maintained cases cover future activation,
contention and restart, global pause and resume, successor policy refresh,
ordinary writer ordering, and bounded recovery seams. The assertions use fresh
PostgreSQL time and check the relevant Record revision, durable timer
occurrence, Action receipt, history, and logical outbox effect. This focused
target does not establish every milestone 1 recovery or operator obligation;
see [Record timers](../../record-timers.md) for the explicit boundary.
