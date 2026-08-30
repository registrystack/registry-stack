# Events and webhooks

**Status:** Proposed direction for the next implementation slice

## Goal

Give a project one safe, reliable extension point: after a committed record
change, send a small authenticated event to a configured service. This should
cover the common integration need without turning Registry Server into a
workflow engine or plugin host.

The mechanism is domain-neutral. A project may declare events for a person,
household membership, farm, disability assessment, company, asset, or any
other configured entity. Registry Server has no built-in knowledge of those
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
events:
  - id: case-approved-v1
    trigger: patched
    projection: [status, programme]
    when:
      kind: fields
      changed: [status]
      beforeEquals: {status: pending}
      afterEquals: {status: approved}
    webhook:
      destinationId: eligibility-service
```

- `id` is the stable external event contract. A breaking payload change uses a
  new versioned id.
- `trigger` is one of `created`, `patched`, or `tombstoned`.
- `projection` is the complete set of record values that may leave the
  registry. System event metadata does not need to be listed.
- `when` is optional. Version 1 supports only `kind: fields`. `changed`,
  `beforeEquals`, and `afterEquals` are optional, combine with AND, and accept
  declared fields with scalar or null comparison values. At least one test is
  required when `when` is present. `created` may use `afterEquals`, `patched`
  may use all three tests, and `tombstoned` may use `beforeEquals`; invalid
  combinations fail compilation.
- One event has at most one webhook destination. A project that needs fanout
  uses an external event gateway until native fanout is justified.
- Production compilation rejects an event without a delivery because Version
  1 has no supported outbox consumer API.

Modules may add events to an existing entity using the normal deterministic
entity-extension mechanism. They may not silently replace an event owned by
another module.

Destination URLs, TLS policy, network policy, and HMAC keys remain deployment
configuration. The governed project refers only to a logical destination id.
Runtime configuration must bind the exact compiled destination set and may
tighten operational ceilings, never widen delivery authority.

The compiler derives the event classification from the highest-classified
projected field. The project does not restate it. Activation requires the
runtime destination to permit that classification, but the destination can
never add to the compiled projection.

### Event evaluation and capture

Conditions are evaluated against the validated before and after snapshots.
Evaluation and outbox insertion happen inside the record mutation transaction,
after authorization and validation. A failure creates neither the record
change nor the event. No user script, network call, or webhook runs inside that
transaction.

The captured event is immutable and binds its event id, entity, record id,
revision, trigger, projected values, package revision, schema fingerprint,
destination, and delivery policy. A later package activation must not
reinterpret it. Activation refuses a destination change that would strand a
retained non-terminal delivery.

### Wire format

Webhooks use CloudEvents 1.0 HTTP binary mode with canonical JSON data:

- `ce-specversion: 1.0`
- `ce-id`: the stable event UUID
- `ce-source`: a stable URN for the Registry instance
- `ce-type`: the authored event id
- `ce-time`: the mutation commit time
- `ce-dataschema`: a URN containing the Registry id, event id, and generated
  event-schema fingerprint

The body contains `entity`, `recordId`, `revision`, `trigger`,
`packageRevision`, and `values`. `values` contains exactly the declared
projection. Record identifiers are deliberately kept out of CloudEvents
headers because infrastructure commonly logs headers.

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
  and the bounded retry profile are secure defaults, not per-event authoring
  choices. `registry-serverctl explain events` shows the effective values.
- The event id and idempotency key remain stable across automatic retries.
  Consumers must deduplicate by `Idempotency-Key`.
- A dead-letter replay keeps the event id, increments the generation, and gets
  a new idempotency key. Replay is audited and allowed only for a terminal
  dead-lettered delivery with retained payload.
- No global or per-record delivery order is promised. The record revision lets
  consumers detect stale or missing transitions.

A durable, value-free attempt audit commits before network egress. A terminal
audit and delivery-state transition commit together after the outcome. Audit
failure prevents the send or terminal transition rather than creating an
unaccounted delivery.

The payload is erased immediately after successful delivery. Pending and
dead-letter payloads have a deployment-selectable retention period capped at
30 days. After expiry, replay is impossible. Digests and value-free operational
metadata follow the normal audit retention policy. Audit and operational logs
contain no projected values, raw record ids, destination URLs, or secrets.
Payload erasure and its terminal audit record commit atomically.

The public record API exposes no outbox, payload, delivery, or replay route.

### Platform reuse

Reuse `registry-platform-httputil` for bounded destination and SSRF policy,
`registry-platform-canonical-json` for exact bytes, and the existing platform
audit, secret, configuration, and cryptographic primitives. Improve those
crates when a missing primitive is genuinely cross-product. Registry Server
continues to own event meaning, capture, retry state, replay, retention, and
the versioned signature contract. Do not add a new generic hook, CloudEvents,
or Rhai platform crate for this slice.

## Developer and operator experience

The first complete journey must be possible without reading Rust code:

- `registry-serverctl check` reports field-addressed event errors.
- `registry-serverctl explain events` shows triggers, conditions, projections,
  classifications, destinations, payload bounds, and fixed delivery behavior,
  but no deployed URLs or secrets.
- `registry-serverctl webhook sample` writes an exact example request with
  synthetic values and a placeholder signature.
- `registry-serverctl webhook list` shows value-free pending and dead-letter
  status.
- `registry-serverctl webhook replay` replays one eligible dead letter using
  its event id, delivery id, and expected generation.
- `products/registry-server/demo/run.sh --webhook` starts Mint, PostgreSQL,
  Registry Server, and a local HMAC-verifying receiver. It demonstrates one
  successful event and one automatic retry without printing the token or key.

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
   extract a shared platform Rhai crate until Registry Server is a real second
   consumer and the common kernel is clear.
3. **Richer event selection.** Add multiple field predicates, relationship
   changes, and safe transforms through a versioned tagged condition ABI. Do
   not grow an ad hoc expression language alongside Rhai.
4. **More delivery adapters.** Consider native fanout, CloudEvents structured
   mode, queues, or message brokers only for proven deployments. Keep the
   transactional event contract independent of transport.
5. **Inbound integration and scheduling.** Treat inbound webhooks, scheduled
   jobs, multi-step actions, approvals, and workflows as explicit adapters or
   separate products unless a recurring Registry Server responsibility is
   demonstrated.
6. **Explicit business commands.** If projects need atomic multi-record
   behavior, prefer reviewed command endpoints with a bounded mutation plan,
   validation, authorization, audit, and events over implicit global model
   callbacks.
7. **UI and AI authoring.** A future UI and the separate control tool may build
   on generated schemas, sample events, checks, explanations, and demos. AI may
   propose configuration and tests but never bypass review, package signing,
   runtime destination policy, or operator replay authority.

Arbitrary synchronous callbacks, Django-style global signals, dynamic Rust
plugins, and scripts with ambient I/O are not on the roadmap. We retain Odoo's
useful ability for modules to extend an existing model, while keeping extension
behavior explicit, inspectable, transaction-safe, and independently operable.
