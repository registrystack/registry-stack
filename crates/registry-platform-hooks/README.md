# Registry Platform Hooks

`registry-platform-hooks` is the shared hook contract for Registry Stack. Every
product declares hooks the same way and runs them through the same mechanism. A
hook binds a product-owned trigger to a handler (Rhai, WASM, or a remote URL),
and every kind has the same shape: envelope in, message out. The product decides
what the message means and applies it through its own authorization and audit
path.

The crate is mechanism, not policy. It never defines a trigger, never validates
a trigger's vocabulary or a `when` condition, and never applies a proposal.
Trigger vocabularies, condition languages, projections, and proposal meanings
stay with the owning product.

## What the crate holds

- Declaration types: an ordered hooks document where every hook has an explicit
  `id`, a `phase` (`before` or `after`), a product trigger, opaque `when` and
  `projection` fields, and exactly one handler source kind (`rhai` requires
  `script`, `wasm` requires `module`, `url` requires `destinationId`, and
  nothing else). Nothing registers implicitly; declaration order is the
  execution order among hooks on one trigger.
- Compile-time (load-time) rules in the "refuse what cannot run" style:
  `phase: before` with a `url` handler is refused, kind and source pairing is
  enforced in both directions, the handler `abi` is a closed set
  (`registry.hook-handler/v1` in version one, required on `rhai` and `wasm`,
  forbidden on `url`), and duplicate hook ids are refused. Every refusal
  carries a pinned, machine-readable code.
- The envelope: one canonical JSON document (RFC 8785 through
  `registry-platform-canonical-json`) with `id`, `type`, `source`, `time`,
  `subject`, `dataschema`, `data`, and `causation` (`root`, `parent`, `hop`).
  Delivery attributes (`attempt`, `generation`, `delivery_time`,
  `idempotency_key`, `signature`) are explicitly not envelope fields; they stay
  on the transport, exactly as `EventDeliveryHeaders` carries them today. The
  envelope is what the handler reasons over; the attributes are what the worker
  reasons over.
- Causation and the hop guard: `hop` is 0 for a root event and parent hop + 1
  otherwise, the library ceiling is 8, and producing a child beyond the ceiling
  is refused with an error that names the ceiling so the worker can record a
  dead-letter reason instead of dropping the chain silently.
- The handler message: exactly one of `proposal` (a product-typed document the
  library checks only for size and canonical-JSON well-formedness), `none`, or
  `refusal` (a bounded code and summary). The named bounds are enforced, not
  decorative.
- The error taxonomy: the five run-time failure categories (Deadline, Resource,
  Execution, Source, Unavailable) with the per-kind mapping documentation.

## Budgets

- The envelope carries the same 2 MiB outbox payload bound the `registry_outbox`
  table enforces today (2,097,152 bytes).
- A handler's returned message carries the executor output ceiling; the library
  default mirrors `registry-platform-script`'s 1 MiB `max_output_bytes` default
  and stays operator-configurable per run.
- Every configurable budget carries a flip test at a non-default value. A
  budget without one is treated as not enforced.

## Out of scope in version one

- In-request decision hooks (a synchronous remote call inside a request).
- Phase `before` on plain writes (`created`, `patched`).
- Orchestration: fan-in, compensation, whole-flow visibility.
- Folding BReg's notification path into the handler path.

The delivery tables' DDL lives here behind the `postgres` feature
(`delivery_schema`): the product's kernel install includes those statements into
its own migration. No delivery worker and no executor live in this crate.
