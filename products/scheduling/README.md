# Registry Scheduling product material

Registry Scheduling gives a registry a coordinated booking surface: published
openings, exact-time offerings over interchangeable resource pools, published
arrival windows with channel subquotas, holds, and accountable bookings, over
PostgreSQL. The runtime is `crates/registry-scheduling`; the source-neutral
model and evaluators live in `crates/registry-scheduling-core`; adopter
tooling is `crates/registry-schedulingctl` (`schedulingctl`).

This folder holds the product's own contracts, examples, fixtures, and gates.
The database-free checkpoint runs the dependency-direction gate and the whole
offline authoring journey:

```bash
cargo build --locked -p registry-schedulingctl
products/scheduling/scripts/check-checkpoint.sh
```

For PostgreSQL execution, destructive test suites require a separate disposable
database and the `postgres-test` feature; a test binary that skips because its
database URL is absent is not database verification.

`examples/standalone-exact-time/` is exactly what
`schedulingctl init --template standalone-exact-time` writes, and the
checkpoint fails if the two drift apart.

No scheduling crate, directly or through any shared dependency, may reach a
Base Registry Engine, Casework, or Evidence crate, and none of those products
may reach a scheduling crate. The source-neutral core sits at the bottom of
the product depending on no other scheduling crate, and the client shares the
core without ever linking the runtime or adopter tooling.
