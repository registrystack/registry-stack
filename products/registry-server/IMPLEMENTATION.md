# Implementation schedule

The product is delivered through small vertical slices. The canonical schedule
is `contracts/implementation-schedule.yaml`.

1. **W0:** publish validated contracts, a non-person authored fixture, the two
   crate boundaries, and one CI ownership path.
2. **W1:** compile a strict, deterministic effective model and all Slice 0
   inventories from one source of truth.
3. **W2:** prove the PostgreSQL role, RLS, advisory-lock, and connection-pool
   design against a real PostgreSQL instance.
4. **W3:** add the real REST router, request authorization, revisions,
   idempotency, audit ordering, and transactional outbox as one path.
5. **W4:** add verified packages, migrations, activation, and recovery.
6. **W5:** complete the pilot tooling, bounded data operations, webhooks, and
   five coequal adopter journeys.

No wave creates a generic storage framework, package framework, plugin runtime,
workflow engine, or second database client abstraction merely in anticipation
of future needs.
