# Registry Coordinator changelog

## Unreleased

First release of Registry Coordinator.

- Coordinator executes finite, acyclic Workflows across durable waits, outages, and restarts.
  Projects separate generated contracts, reusable types, named pure Functions, local exact
  Operation aliases, and one Workflow graph. Functions take one typed object of named inputs.
- Runtime bindings use one tagged `connections` map. Caller policies are keyed by exact verified
  client identity and scope run actions through `workflows`.
- Starts require an expected computed `workflowRevision`. Workflow discovery and generated
  TypeScript/Python wrappers provide revision-pinned typed `start`, `get`, and `cancel` through
  the source-built Coordinator client bindings. Unknown admission preserves its original revision and key.
- Named completions share `completion: {step, name}` across Casework results and bounded external
  job observation. Persistent read floors, retry ceilings, and
  observation budgets survive restarts and wake-ups. Blocked or uncertain evidence remains held.
- Base Registry Engine (BReg) Action aliases import owner-generated exact contracts for immediate
  Actions, which can route declared no-effect refusals explicitly. The applicant drives a Proposal
  in BReg; a Workflow follows it by product event or record read.
- Workflows can request independently authorized Casework review. Signed product events can start
  typed workflows through explicit source bindings.
  Receiving products retain effect authority and recheck their conditions before committing.
- Inspection reports accepted or unknown effects and bounded wait state without protected inputs,
  raw product responses, prepared requests, or correlation values. Encrypted PostgreSQL custody,
  durable audit, retention tombstones, and explicit fenced restore recovery protect work.
- Protected state schema version 4 directly replaces earlier pilot layouts. Incompatible state is
  refused; there is no in-place conversion or legacy authoring syntax.
- Maintained examples cover standalone Casework review, product events, and external job
  completion. Native service checks compose BReg, Casework, Scheduling, and Messaging; the
  deferred-appointment journey retains a real 961-second wait and original receipt recovery. Offline scenarios and message acceptance do not establish provider delivery.
- Signed event intake accepts deliveries up to the 1 MiB Version 1 signable bound, verifies them
  through the shared hooks receiver, and answers a larger one with `request.body-too-large`.
  Delivery counters are canonical positive decimals up to the signed 64-bit range. The admitted
  event value still fits the 128 KiB structured value profile; an event over that profile is
  refused with `event.too-large` (413), which names the bounds and asks the producer to project
  fewer or smaller fields into the event.
