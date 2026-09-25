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
  on the transport headers. The envelope is what the handler reasons over; the
  attributes are what the worker reasons over. `id`, `causation.root`, and
  `causation.parent` are UUIDs and `subject.recordRevision` is greater than
  zero, refused on both encode and decode; `time` is normalized to UTC at whole
  milliseconds on encode, so equal instants produce identical bytes, and decode
  refuses any other spelling of it; decode requires the bytes to equal their own
  canonicalization, so a decoded envelope re-encodes to the bytes it arrived as.
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

- The envelope carries the same 2 MiB payload bound the delivery store enforces
  (2,097,152 bytes). A per-delivery bound can only tighten it:
  `EnvelopeLimits::tightened_to` clamps a wider request back to
  `MAX_ENVELOPE_BYTES`.
- A handler's returned message carries the executor output ceiling,
  `MAX_OUTPUT_BYTES`, mirroring `registry-platform-script`'s 1 MiB
  `max_output_bytes` default. The operator configures the per-run ceiling, and a
  per-run ceiling can only tighten it: `HandlerOutputLimits::tightened_to`
  clamps a wider request back to `MAX_OUTPUT_BYTES`.
- Every configurable budget carries a flip test at a non-default value. A
  budget without one is treated as not enforced.
- Every diagnostic renders untrusted text bounded and escaped: 128 bytes per
  quoted token and 512 bytes per deserializer message, with unexpected values
  dropped and control characters escaped, so no value can put a newline, a
  terminal escape sequence, or a NUL into a log line.

## Out of scope in version one

- In-request decision hooks (a synchronous remote call inside a request).
- Phase `before` on plain writes (`created`, `patched`).
- Orchestration: fan-in, compensation, whole-flow visibility.
- Folding a product's existing notification path into the handler path.

## The PostgreSQL delivery half

The delivery tables' DDL lives here behind the opt-in `postgres` feature
(`delivery_schema`): the product's kernel install includes those statements into
its own migration, and `object_names` names the objects it creates for a product
that inventories its database. Installing them installs no ACL; the product owns
the `GRANT` and `REVOKE` on those objects. The notification delivery worker lives
here too, behind the same feature (`delivery`): it runs on the product's seams,
so the audit journal, operational vocabulary, identity preflight, and destination
signing stay with the product. The lease state machine under it (claim, fencing,
lease-expiry recovery, retry, dead letter, payload expiry, and replay) is
`registry-platform-dispatch`, run over the delivery state table: the worker keeps
the frozen retry delays the delivery was captured with, retries every failed or
interrupted attempt until its attempts are spent, and accepts attempt timeouts
from 100 milliseconds to 10 seconds. Nothing above this section is behind the feature:
the contract half has no database dependency, so a product that only declares and
validates hooks takes the crate with default features and links no PostgreSQL
client. No executor lives in this crate: running a Rhai or WASM handler is a
later step.
