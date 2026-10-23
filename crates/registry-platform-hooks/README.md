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

- Declaration types: ordered hook declarations where every hook has an explicit
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

- The envelope carries the 1 MiB Version 1 signable bound (1,048,576 bytes,
  the delivery signature's `MAX_BODY_BYTES`), so every envelope can be signed
  and verified. The delivery store's 2 MiB payload column is a looser outer
  bound. A per-delivery bound can only tighten it:
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
so the audit journal, operational vocabulary, and identity preflight stay the
product's decision. The pieces every product's seams are built from live here
as well: the signing URL destination (`UrlDestination`, `SharedUrlDestination`),
the audit entry builder
parameterised by the product's audit schema and event name
(`hook_audit_entry`, where the event is `<product>.hook-delivery`), the retry
schedule (`exponential_retry_delays_ms`), and the identity preflight
(`verify_active_package`), which reads the `registry-platform-activation`
record inside the delivery transaction and refuses unless it names the
database and package the worker was started with. The lease state machine under it (claim, fencing,
lease-expiry recovery, retry, dead letter, payload expiry, and replay) is
`registry-platform-dispatch`, run over the delivery state table: the worker keeps
the frozen retry delays the delivery was captured with, retries every failed or
interrupted attempt until its attempts are spent, and accepts attempt timeouts
from 100 milliseconds to 10 seconds. A product may override the default identity
check only for recording a settled URL proposal: an accepted send with an applied
or refused proposal, or a permanent failure with a dead-lettered proposal.
`DeliverySeams::verify_proposal_completion` defaults to the ordinary preflight.
Local, transient, uncertain, and non-proposal outcomes keep that preflight, as do
claims, material reads, recovery, and operator transitions. Dispatch still fences
the completion by its exact lease. Dead letters retain a closed, value-free
failure reason. The operator surface can
list work captured under a superseded binding and explicitly discard pending
work, a dead letter, or an expired lease under its exact generation. Discard
never rebinds or sends the work, refuses a live lease or recovered proposal
receipt, and preserves the shared envelope while another delivery needs it.

The simple URL hook destination block, `UrlHookDestinationConfig` (a `url`, an
`hmacSha256KeyRef`, and a delivery budget), is defined in
`registry-platform-config` and re-exported from `delivery`.
`activate_url_hook_destinations` turns a map of them into signing destinations
under a fixed outbound policy (https, or http on a loopback host, no private
address range, no client certificate) and records the binding digest. Scheduling
and Document Store share that block. The Base Registry Engine configures the
full outbound policy instead, because its destinations may reach private address
ranges and present a client certificate for mTLS.

Nothing above this section is behind the feature:
the contract half has no database dependency, so a product that only declares and
validates hooks takes the crate with default features and links no PostgreSQL
client.

## Capability sets

A product states the parts of the declaration it executes as a
`HookCapabilities` set: handler kinds, `when` conditions, and `principal`.
`HookCapabilities::URL_ONLY` admits a bare `url` hook. A declaration outside the set is refused at load
time with the one shared diagnostic `hook.capability.unsupported`, naming the
part, so products carry no refusal code of their own.

## The local handler executor

The `rhai` and `wasm` features hold the executor for local handlers. A product
hands each reviewed program over as a `LocalHookProgram`, admitted only when
its recorded digest covers its bytes and it speaks `registry.hook-handler/v1`,
and registers the admitted programs in a `LocalHookHandlers` set under the
package revision it runs. A delivery runs a program only when its compiled
delivery id, package revision, handler kind, and handler digest all match. The
program receives the envelope JSON as its one argument and returns the
handler message. The Rhai engine is the bare `registry-platform-script` engine
with no product helpers; the WASM engine is a hook-owned module runtime with
its own fuel, epoch ticker, and prepared-module cache, separate from any
product's action handler cache.


### Terminal delivery metadata

Products call `delivery::prune_terminal_deliveries` inside their retention
transaction with their metadata cutoff. Each call prunes at most 256 deliveries,
locking state and shared events with `SKIP LOCKED`. Pending and leased rows
remain. Dead letters require completed payload expiry and erasure before their
metadata ages out. State rows are deleted before delivery metadata, and an event
is deleted only after its last delivery is gone. A failure returns the shared
`RetentionError`, whose cause is the refused bound or the server's SQLSTATE. Audit retention remains the
product's responsibility; metadata cleanup never substitutes for expiry audits.

Dead-letter metadata ages from the dead-letter transition and becomes eligible
only after payload expiry and erasure complete. Later expiry does not restart
the metadata horizon. Explicit discard likewise uses its completed terminal
transition, without waiting for the original scheduled payload deadline.

## Security review notes

- The identity preflight takes no advisory or row lock: an activation holds
  its own exclusive lock and verifies retained deliveries on a second
  connection, so a shared lock here could deadlock against it. A transaction
  `lock_timeout` bounds the read, and any mismatch, missing activation, or
  read failure is `DeliveryError::Unavailable` with no reason carried.
- The executor adds no authority: a program's message is a proposal the
  product applies through its own seam, and `apply_proposal` stays with the
  product.
- Capability refusals are tested once, in `capability.rs`.
