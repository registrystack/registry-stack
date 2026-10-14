# Facility registry

This project combines ordinary record routes, an immediate Action that creates
a facility and assignment atomically, and durable Proposals for later changes.
Every permission and domain rule is authored in `registry.yaml`.

With matching `breg` and `bregctl` binaries on `PATH` and Docker running:

```sh
bregctl check .
bregctl explain actions .
bregctl explain proposals .
bregctl dev start .
bregctl examples run register-facility .
bregctl dev stop .
```

`bregctl check` reports an intentional related-disclosure advisory. The
`operators` related read uses the selected facility root profile, so review that
grant alongside direct operator access. This fixture gives both reads the same
jurisdiction boundary and readable field set.

The local journey creates an operator, invokes the registration Action, reads
both resulting records, and checks jurisdiction concealment. The example can
resume using its retained idempotency keys. Restarting the local session retains
its data; `bregctl dev stop --remove .` removes the session and its records.

The `deactivate-facility` Action uses a no-review Proposal with explicit manual
application. `correct-address` uses a frozen Rhai plan, independent review, and
automatic application after approval. Use the generated clients and promoted
Proposal operations to start, inspect, submit, observe, and recover that work.
The local `author` and `applier` are explicit synthetic human fixtures.

Independent review is optional at startup. To exercise address correction,
configure the `casework` authority in the local client file or the deployment
target and replace the synthetic policy digest with your compiled review policy.
An unavailable authority cannot approve or apply the correction. Registration,
reads, and the no-review Action retain their own authority.

The Registry Stack repository's `postgres_facility_proposal` test exercises the
complete correction with a small conforming review authority and real PostgreSQL.
`postgres_proposal` covers no-review manual and automatic paths. The sibling
standalone examples README gives the runnable commands. The optional `console/`
application consumes the generated project contracts and is maintained separately
from this authoring template.

Set the institution's registry identity and immutable source revision before
preparing a production package. Replace local callers with the institution's
OAuth claims and independently configured grants.
