# Registry Scheduling product material

Registry Scheduling gives a registry a coordinated booking surface: published
openings, exact-time offerings over interchangeable resource pools, published
arrival windows with channel subquotas, holds, and accountable bookings, over
PostgreSQL. The runtime is `crates/registry-scheduling`; the source-neutral
model and evaluators live in `crates/registry-scheduling-core`; adopter
tooling is `crates/registry-schedulingctl` (`schedulingctl`).

This folder holds the product's own contracts, examples, fixtures, and gates.
It currently carries the dependency-direction gate that holds the product
boundary from the first commit:

```bash
python3 products/scheduling/scripts/check_dependency_direction.py
python3 -m unittest products/scheduling/scripts/test_dependency_direction.py
```

No scheduling crate, directly or through any shared dependency, may reach a
Base Registry Engine, Casework, or Evidence crate, and none of those products
may reach a scheduling crate. The source-neutral core sits at the bottom of
the product depending on no other scheduling crate, and the client shares the
core without ever linking the runtime or adopter tooling.
