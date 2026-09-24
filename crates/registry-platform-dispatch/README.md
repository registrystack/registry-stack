# Registry Platform Dispatch

`registry-platform-dispatch` is the shared Registry Stack implementation of
at-least-once dispatch: handing a job to something outside the product's own
transaction (a webhook destination, a message provider) under a fenced
PostgreSQL lease. It carries no product vocabulary. The product owns the job
table's schema and name, the policy and payload rows the claim reads, the
audit every transition writes, and the send itself.

The pure half is always compiled:

- `idempotency_key(domain, parts)` is the idempotency-key recipe: `sha256:`
  and the lowercase hex SHA-256 of the product's domain bytes followed by
  every part as an unsigned 64-bit big-endian length and its bytes. The
  product supplies its own domain, so two products never share a key space.
- `JobPolicy` is the policy frozen with each job: an attempt timeout, a
  maximum attempt count, a `RetrySchedule` (`Frozen` delays used exactly, or
  an exponential `Backoff` with optional equal `Jitter` that honours a
  receiver's `Retry-After` up to its maximum), an `UncertainOutcome` (`Retry`
  or `Hold`), and an optional expiry instant. A claim that finds the job past
  its expiry expires it instead of leasing it, and a retry that would fall at
  or after the expiry expires the job instead.
- `AttemptTimeoutBound` is the range of attempt timeouts one consumer accepts,
  at most `MAX_ATTEMPT_TIMEOUT` (60 seconds). A claimed job whose captured
  timeout falls outside it is refused before it is leased.
- `SendOutcome` is what a transport reports: `Accepted` with an optional
  provider reference of at most 128 bytes, `Transient` with an optional pause
  hint, `Permanent` with a failure code of at most 64 bytes, or `MaybeSent`
  when the attempt's fate is unknown.

The opt-in `postgres` feature adds the lease machine in `postgres`:

- `JobTable` names the product's table and key columns. Every name is checked
  once as a plain lowercase SQL identifier, so no name ever comes from request
  input, and `create_statements` returns the DDL for a product that does not
  already own an equivalent table. `enqueue` inserts one pending job inside the
  product's own transaction, due at the later of the transaction timestamp and
  an optional not-before instant.
- `DispatchStore` is the product's seam: it lends a connection, verifies the
  transaction's identity, decodes the product columns its `DispatchSql` joins
  into each read, writes the attempt and transition audits inside the
  transaction that makes them, and adds its own columns to terminal writes.
  `DispatchTransport` is the send: `send(&LeasedJob) -> Sent`.
- `Dispatcher` runs every transition. A claim recovers one lapsed lease,
  expires one job past its expiry, then leases the next due job with
  `FOR UPDATE SKIP LOCKED`, and commits the lease with its attempt audit before
  the transport runs. A lease lasts the captured attempt timeout plus
  `LEASE_FINALIZATION_ALLOWANCE` (5 seconds). Every later write carries the
  lease's `Fence` (key, generation, attempt, and lease token), so a worker that
  lost its lease matches no row. A lapsed lease is decided by the job's
  `UncertainOutcome`: retried as a transient failure, or held in `unknown`.
  `replay` restarts a terminal job the consumer marks replayable at a new
  generation and attempt zero, so a product that puts the generation in its
  idempotency key sends the replay under a new key. `cancel` withdraws a job
  no worker has claimed; a claim and a cancel of the same job never both win.
- `DispatchWorker` runs `dispatch_once` on a bounded number of lanes until no
  job is due, then polls, until shutdown is signalled.

The core writes no audit of its own. Each transition calls the store's audit
hook inside the same transaction, so an audit that fails rolls the transition
back, and no attempt is sent before its audit has committed.

Registry Platform Hooks is the first consumer: its notification delivery
worker runs on this core over the product's
`registry_webhook_delivery_state` table, with frozen retry delays, `Retry` on
an uncertain outcome, and attempt timeouts from 100 milliseconds to 10 seconds.
See `crates/registry-platform-hooks/src/delivery/store.rs`.

The `postgres-test` feature enables the PostgreSQL test consumer in
`tests/postgres_dispatch.rs`. Its tests require `DISPATCH_TEST_DATABASE_URL`,
naming a disposable database, and fail when it is absent.
