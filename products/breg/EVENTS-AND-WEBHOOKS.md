# Events and webhooks

**Status:** Version 1 implemented

## Goal

Give a project one safe, reliable extension point: after a committed record
change, send a small authenticated event to a configured service. This should
cover the common integration need without turning Base Registry Engine into a
workflow engine or plugin host.

The mechanism is domain-neutral. A project may declare events for a business registration,
an establishment, a facility inspection, a permit, an asset, or any other
configured entity. Base Registry Engine has no built-in knowledge of those
models.

The existing transactional outbox and delivery worker are the starting point,
not a conformance claim for this spec. The immediate deltas are simpler
authoring, field conditions, CloudEvents, operator commands, a webhook demo,
payload erasure and retention, and upgrade-safe queued delivery.

The core threat is a hook leaking registry data, widening authority at
deployment, or causing an unaccounted side effect. The invariant is that only
the compiled projection may reach the exact activated logical destination,
only after an authorized mutation commits, with durable audit before egress.

## Version 1 contract

### Authoring

An event belongs to an entity and declares only what changes product meaning:

```yaml
hooks:
  - id: case-approved-v1
    phase: after
    trigger: patched
    projection: [status, programme]
    when:
      type: fields
      changed: [status]
      beforeEquals: {status: pending}
      afterEquals: {status: approved}
    handler:
      type: url
      destinationId: eligibility-service
```

- `id` is the stable external event contract. A breaking payload change uses a
  new versioned id.
- `phase` is `after`: an entity hook runs after the triggering transaction
  commits. The compiler refuses `before`, which the runtime cannot run here.
- `trigger` is one of `created`, `patched`, `tombstoned`, or `request-lifecycle`.
  Only a change-request entity can declare `request-lifecycle`.
- `projection` is the complete set of record values that may leave the
  registry. System event metadata does not need to be listed.
- `when` is optional. For record mutations, use `type: fields`. `changed`,
  `beforeEquals`, and `afterEquals` are optional, combine with AND, and accept
  declared fields with scalar or null comparison values. At least one test is
  required when `when` is present. `created` may use `afterEquals`, `patched`
  may use all three tests, and `tombstoned` may use `beforeEquals`; invalid
  combinations fail compilation.
- Lifecycle events use `type: request-lifecycle` with at least one nonempty
  `transitions` or `toStates` list. Each nonempty list must match;
  field predicates are not available for this trigger.
- `handler` declares either `type: url` with the logical `destinationId`, or
  one of the local kinds: `type: rhai` with a reviewed `script` path, or
  `type: wasm` with a reviewed `module` path. A url handler delivers to a bound
  destination; a local handler runs its program in the post-commit worker. The
  delivery row records the settled answer's digest, and never the answer
  bytes. One event has at most one handler. A project that needs fanout uses
  an external event gateway until native fanout is justified.
- Production compilation rejects an event without a handler because Version 1
  has no supported outbox consumer API.

Modules may add hooks to an existing entity using the normal deterministic
entity-extension mechanism. They may not silently replace an event owned by
another module.

Destination URLs, TLS policy, network policy, and HMAC keys remain deployment
configuration. The governed project refers only to a logical destination id.
Runtime configuration must bind the exact compiled destination set and may
tighten operational ceilings, never widen delivery authority.

The compiler derives the event classification from the highest-classified
field used by either the projection or a condition. The project does not
restate it. A condition can disclose information through whether an event
fires even when that field is not in the payload. Activation therefore
requires the runtime destination to permit the full derived classification,
but the destination can never add to the compiled projection.
Lifecycle events are at least as classified as their request entity. Events
whose transition and destination-state filters permit application also have
an `internal` classification floor, because the system request envelope may
contain an application reason. An omitted filter permits this outcome.
Filters that exclude it, such as `transitions: [cancel]` or
`toStates: [cancelled]`, keep the ordinary derived classification.

Compilation and mutation planning use the same classification rule. If the
runtime detects a delivery inventory that differs from the governed source,
it refuses the record change with `503 service.unavailable`.
This is a package or server fault, not invalid caller input.

### Event evaluation and capture

Conditions are evaluated against the validated before and after snapshots.
Evaluation and outbox insertion happen inside the record mutation transaction,
after authorization and validation. A failure creates neither the record
change nor the event. No user script, network call, or webhook runs inside that
transaction.

Lifecycle conditions are evaluated against the request transition. Their
projection contains request fields, not canonical target values, and capture
commits with the transition. A webhook notification grants no approval or
application authority.

The captured event is immutable and binds its event id, entity, record id,
revision, trigger, projected values, package revision, schema fingerprint,
destination, and delivery policy. A later package activation must not
reinterpret it. Activation refuses a destination change that would strand a
retained non-terminal delivery.

The stored outbox payload is that envelope, byte for byte, and the delivery
worker sends it unchanged. A row captured under the earlier bare-data body is
not an envelope; the worker refuses it rather than reshaping it. That refusal
is a failed attempt, not a terminal one, so the row retries on the captured
schedule and dead-letters only once its attempt budget is exhausted. A
deployment upgrading across this change should drain the outbox, or let it
settle, before the upgrade: every delivery captured under the earlier body
spends its whole retry budget on attempts that cannot succeed.

This contract does not reinterpret delivery history created by the earlier
experimental webhook shape. The delivery tables are read only as the previous
release wrote them; Base Registry Engine does not upgrade an older delivery
schema in place and does not invent CloudEvents metadata for its rows.

### Wire format

Webhooks use CloudEvents 1.0 HTTP binary mode with canonical JSON data:

- `ce-specversion: 1.0`
- `ce-id`: the stable event UUID
- `ce-source`: a stable URN for the Registry instance
- `ce-type`: the authored event id
- `ce-time`: the immutable mutation capture time recorded in the committing
  transaction
- `ce-dataschema`: a URN containing the Registry id, event id, and generated
  event-schema fingerprint

The body is one shared hook envelope, the envelope every Registry Stack product
delivers: `id`, `type`, `source`, `time`, `subject`, `dataschema`, `data`, and
`causation`, and nothing else. `id`, `type`, `source`, `time`, and `dataschema`
repeat the CloudEvents attributes above, so a receiver reading only the body
still knows which event it holds. `subject` carries the hashed record reference
and the revision the change produced, never the raw record id. `causation`
carries `root` and `hop`, plus `parent` once an event is caused by another; a
captured registry mutation is a root event, so `root` equals `id` and `hop` is
0. Delivery attributes stay on the transport and never enter the envelope.

`data` contains `entity`, `recordId`, `revision`, `trigger`,
`packageRevision`, and `values`. `values` contains exactly the declared
projection. Record identifiers are deliberately kept out of CloudEvents
headers because infrastructure commonly logs headers.

Lifecycle event data also requires a `request` object containing `proposalVersion`,
`workflowRevision`, `transition`, `fromState`, `toState`, `effectDigest`,
`deduplicationKey`, and `reasonPresent`. `effectDigest` may be null.
For apply transitions, an explanation supplied by the applier appears unchanged
as the optional `request.reason` string, bounded to 4096 Unicode characters. An absent
explanation omits `reason` and sets `reasonPresent` to false. The event's
compiled classification and destination authority govern delivery independently
of a reader's `readableRequestFields`.
The deduplication key stays stable across automatic retries and operator replay.
Request-detail erasure removes retained explanation text from request events
and webhook payloads while preserving the reason-presence flag.

Registry delivery headers add `Idempotency-Key`,
`X-Registry-Event-Generation`, `X-Registry-Delivery-Attempt`, and
`X-Registry-Delivery-Time`, plus `X-Registry-Signature`. The versioned
HMAC-SHA-256 signature uses an unambiguous length-prefixed encoding and covers
the exact CloudEvents attributes, delivery metadata, HTTP method, request
target, content type, and canonical body. Receivers verify the signature,
bounded delivery-time skew, and idempotency key before applying effects. The
shared secret is resolved only from runtime secret configuration and is never
project-authored, logged, or included in generated examples.

### Delivery behavior

Delivery is asynchronous, after commit, and at least once:

- Any `2xx` response acknowledges delivery. Redirects, transport failures,
  timeouts, and other statuses retry within a bounded product-owned profile.
- HMAC-SHA-256, dead-lettering, operator replay, a five-second attempt timeout,
  and five total attempts with 1, 2, 4, then 8 second delays are secure
  Version 1 defaults, not per-event authoring choices. `bregctl
  explain events` shows the effective values.
- The event id and idempotency key remain stable across automatic retries.
  Consumers must deduplicate by `Idempotency-Key`.
- A dead-letter replay keeps the event id, increments the generation, and gets
  a new idempotency key. Replay is audited and allowed only for a terminal
  dead-lettered delivery with retained payload.
- No global or per-record delivery order is promised. The record revision lets
  consumers detect stale or missing transitions.

A value-free attempt audit entry is accepted by the audit writer before
network egress. The terminal audit entry is written inside the delivery-state
transition's transaction, before that transaction commits. Audit failure
prevents the send or rolls the terminal transition back rather than creating
an unaccounted delivery. A commit that fails after an accepted entry leaves an
entry for a transition that did not happen, and the delivery keeps its earlier
state.

The payload is erased after every sibling delivery no longer needs it. Raw
handler answer bytes are erased immediately after successful delivery. The
delivered row retains the answer's digest, its
proposal disposition, and the bounded value-free summary, never the answer
itself. Pending and dead-letter payloads have a deployment-selectable
retention period capped at 30 days. After expiry, replay is impossible.
Digests and value-free operational metadata follow the normal audit
retention policy. Audit and operational logs contain no projected values,
raw record ids, destination URLs, or secrets. Payload erasure commits only
after its terminal audit entry is accepted.

The public record API exposes no outbox, payload, delivery, or replay route.

### Platform reuse

Reuse `registry-platform-httputil` for bounded destination and SSRF policy,
`registry-platform-canonical-json` for exact bytes, and the existing platform
audit, secret, configuration, and cryptographic primitives. Improve those
crates when a missing primitive is genuinely cross-product. The generic hook
contract, the shared envelope, and the delivery worker's claim, retry,
dead-letter, expiry, and replay mechanics live in `registry-platform-hooks`,
and the versioned delivery signature lives in `registry-platform-crypto` as a
product-neutral module. Base Registry Engine owns event meaning, capture, and
retention policy, and supplies the product constants, destination bindings,
and audit records those shared primitives run with.

## Developer and operator experience

The first complete journey must be possible without reading Rust code:

- `bregctl check` reports field-addressed event errors.
- `bregctl explain events` shows triggers, conditions, projections,
  classifications, destinations, payload bounds, and fixed delivery behavior,
  but no deployed URLs or secrets.
- `bregctl webhook sample` writes an exact example request with
  synthetic values and a placeholder signature.
- `bregctl dev start` binds declared destinations to an owned loopback receiver.
  `bregctl dev events` shows received delivery metadata; `--include-payload`
  explicitly reveals projected development values. See the
  [native development lifecycle](DEV.md#observe-local-events) for retention
  and runtime queue inspection.
- `bregctl webhook list` shows value-free pending and dead-letter
  status, including whether the captured binding is still active, whether an
  explicit discard is eligible, and a closed dead-letter reason.
- `bregctl webhook replay` replays one eligible dead letter using
  its event id, delivery id, and expected generation.
- `bregctl webhook discard` closes one retained pending delivery, dead letter,
  or expired lease using the same optimistic identity. Discard prevents future
  attempts and never reinterprets the work under a replacement binding. It
  does not undo a request the receiver may already have accepted.
- `products/breg/demo/run.sh --webhook` starts ThunderID, PostgreSQL,
  Base Registry Engine, and a local HMAC-verifying receiver. Its smoke journey
  demonstrates automatic retry, dead-letter inspection, operator replay, and
  eventual authenticated success without printing the token or key.

## Definition of done

Version 1 is done when one configured project can create or patch a record and
the demo proves the resulting CloudEvent is transactionally captured,
minimized, authenticated, retried, dead-lettered, inspected, and replayed.
Focused negative tests must prove rollback creates no event, conditions do not
overmatch, projections cannot cross their classification ceiling, runtime
bindings cannot widen or redirect authority, signatures bind the exact request,
payload retention is enforced, and a compatible package upgrade cannot strand
a pending delivery.

## Future direction

These are intentionally deferred, but the Version 1 shapes must leave room for
them:

1. **Rhai rules.** Add `when.kind: rhai` only after field conditions prove
   insufficient. Scripts are reviewed, hash-covered package artifacts with a
   small versioned ABI, deterministic fresh state, fixed resource limits, and
   minimized before/after inputs. They return only a Boolean or closed
   validation result. They receive no I/O, secrets, credentials, database
   handle, destination authority, clock, randomness, or audit ownership.
2. **Validation and computed fields.** Reuse the same bounded Rhai kernel for
   record validation first, then deterministic computed fields if a concrete
   project needs them. Script failure fails the mutation atomically. Do not
   extract a shared platform Rhai crate until Base Registry Engine is a real second
   consumer and the common kernel is clear.
3. **Richer event selection.** Add multiple field predicates, relationship
   changes, and safe transforms through a versioned tagged condition ABI. Do
   not grow an ad hoc expression language alongside Rhai.
4. **More delivery adapters.** Consider native fanout, CloudEvents structured
   mode, queues, or message brokers only for proven deployments. Keep the
   transactional event contract independent of transport.
5. **Inbound integration and scheduling.** Treat inbound webhooks, scheduled
   jobs, multi-step actions, approvals, and workflows as explicit adapters or
   separate products unless a recurring Base Registry Engine responsibility is
   demonstrated.
6. **Explicit business commands.** If projects need atomic multi-record
   behavior, prefer reviewed command endpoints with a bounded mutation plan,
   validation, authorization, audit, and events over implicit global model
   callbacks.
7. **UI and AI authoring.** A future UI and the separate control tool may build
   on generated schemas, sample events, checks, explanations, and demos. AI may
   propose configuration and tests but never bypass package review,
   runtime destination policy, or operator replay authority.

Arbitrary synchronous callbacks, Django-style global signals, dynamic Rust
plugins, and scripts with ambient I/O are not on the roadmap. We retain Odoo's
useful ability for modules to extend an existing model, while keeping extension
behavior explicit, inspectable, transaction-safe, and independently operable.
