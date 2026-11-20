# Registry Scheduling

Registry Scheduling gives a registry a coordinated booking surface: published openings, exact-time
offerings over interchangeable resource pools, published arrival windows with channel subquotas,
holds, and accountable bookings, over PostgreSQL 17 or newer.

The runtime is `crates/registry-scheduling`. The source-neutral model and evaluators live in
`crates/registry-scheduling-core`. Adopter tooling is `crates/registry-schedulingctl`
(`schedulingctl`), and the bounded Rust client is `crates/registry-scheduling-client`.

Concepts, configuration, operation, and the security model are on the documentation site:

- [Registry Scheduling overview](https://docs.registrystack.org/start/scheduling/)
- [Author a Scheduling policy](https://docs.registrystack.org/configure/scheduling/)
- [Deploy and operate Registry Scheduling](https://docs.registrystack.org/operate/scheduling/)
- [Registry Scheduling configuration reference](https://docs.registrystack.org/reference/scheduling-configuration/)
- [Registry Scheduling task grants](https://docs.registrystack.org/reference/scheduling-task-grants/)
- [Registry Scheduling API](https://docs.registrystack.org/reference/apis/registry-scheduling/)

## Start from an authored project

Create a starter, inspect its effective configuration, and replay its fixtures:

```sh
schedulingctl init ./scheduling --template standalone-exact-time
schedulingctl check ./scheduling
schedulingctl test ./scheduling
schedulingctl explain ./scheduling
```

`schedulingctl init` writes `runtime.example.yaml` and `records.yaml` beside the policy. Copy the
runtime example to `runtime.yaml`, set its absolute paths and secret references, then activate the
package, apply the live environment records, and start:

```sh
schedulingctl plan --runtime-config "$PWD/runtime.yaml"
schedulingctl apply --runtime-config "$PWD/runtime.yaml" --operator-reference CHG-1234
schedulingctl records apply --runtime-config "$PWD/runtime.yaml" "$PWD/records.yaml"
scheduling --runtime-config "$PWD/runtime.yaml" serve
```

[Deploy and operate Registry Scheduling](https://docs.registrystack.org/operate/scheduling/)
describes each command, the activation ledger, and the refusals `serve` reports.

## Local development

`products/scheduling/demo/run.sh` provisions a disposable TLS-enabled PostgreSQL database, a
throwaway signing key and JWKS, activates the package, applies example environment records, and
serves the runtime on loopback. See `products/scheduling/demo/README.md`.

## Directory

- `contracts/`: the security invariant matrix, its test traceability, and recorded decisions.
- `examples/`: `standalone-exact-time`, `standalone-arrival-window`, and `resource-reservations`
  are what `schedulingctl init --template <name>` writes, and `formats/` holds a sample
  `schedulingctl` report. The `resource-reservations` example also keeps a README.
- `generated/`: the OpenAPI description and the JSON Schemas derived from the Rust types. Do not
  edit them by hand.
- `demo/`: the acceptance demo.
- `integrations/`: maintained adopter recipes, each with its own README.
- `scripts/`: the product's checkpoint and contract checks.

## Integrations

- `integrations/finite-series`: a Python recipe that reserves a bounded weekly series through the
  public client and keeps a durable per-occurrence journal.
- `integrations/calendar-export`: an on-demand iCalendar export over the Rust client.
- `integrations/calendar-busy`: a calendar snapshot importer for source-owned busy intervals.
- `integrations/operational-reporting`: operational reporting over the bounded appointment reads.

## Build and test

The database-free checkpoint runs the contract checks, the dependency-direction gate, and the whole
offline authoring journey:

```bash
cargo build --locked -p registry-schedulingctl
products/scheduling/scripts/check-checkpoint.sh
```

`examples/standalone-exact-time/` is exactly what
`schedulingctl init --template standalone-exact-time` writes, and the checkpoint fails if the two
drift apart.

For PostgreSQL execution, the destructive test suites require a separate disposable database and
the `postgres-test` feature:

```bash
SCHEDULING_TEST_DATABASE_URL=postgres://user:password@host/database \
  cargo test --locked -p registry-scheduling --features postgres-test \
  --test postgres_commitments
```

`SCHEDULING_TEST_DATABASE_URL` names that disposable database for both PostgreSQL suites,
`registry-scheduling`'s commitment suite and `registry-schedulingctl`'s records-apply suite. Both
reset the `public` schema, so never point either at retained operator data, and never point both at
one database. A test binary that skips because its database URL is absent is not database
verification.

## Dependency boundary

No scheduling crate, directly or through any shared dependency, may reach a Base Registry Engine,
Casework, Document Store, Evidence, or Messaging crate, and none of those products may reach a
scheduling crate. Registry Coordinator is the one product that composes Scheduling: its
`scheduling.*` operations use `registry-scheduling-client` and `registry-scheduling-core` over the
public HTTP contract, never the runtime or `schedulingctl`, and no scheduling crate reaches a
Coordinator crate. The source-neutral core sits at the bottom of the product depending on no other
scheduling crate, and the client shares the core without ever linking the runtime or adopter
tooling.
