# Registry Coordinator changelog

## Unreleased

First release of Registry Coordinator.

- `coordinatorctl check --project` reads an optional
  `check-acceptances.yaml`, keeps exactly matched warnings visible with their
  reasons, and excludes only those accepted warnings from `--deny-warnings`.
- Coordinator executes finite, acyclic Workflows across durable waits, outages, and restarts.
  Projects separate generated contracts, reusable types, named pure Functions, local exact
  Operation aliases, and one Workflow graph. Functions take one typed object of named inputs.
- Runtime bindings use one tagged `connections` map. Caller policies are keyed by exact verified
  client identity and scope run actions through `workflows`.
- Scheduling operations can read appointments, create and release holds, confirm holds, and
  reschedule or cancel appointments under task-bound authority. Each operation declares whether
  exact-command replay, original-result lookup, or a non-repeatable uncertainty hold is available.
- Starts require an expected computed `workflowRevision`. Workflow discovery and generated
  TypeScript/Python wrappers provide revision-pinned typed `start`, `get`, and `cancel` through
  the source-built Coordinator client bindings. Unknown admission preserves its original revision and key.
- Named completions share `completion: {step, name}` across Casework results and bounded external
  job observation. Persistent read floors, retry ceilings, and
  observation budgets survive restarts and wake-ups. Blocked or uncertain evidence remains held.
- `external.command/v1` sends one bounded POST to the exact `commandPath` an operator configures
  on an `external-http` connection. The command and its request id are persisted before the first
  send and the id travels as `Idempotency-Key`; a required pure `interpret` Function maps the
  validated response to an accepted result, a declared refusal, or an uncertain hold. Lost
  acknowledgements, timeouts, redirects, server errors, and unusable responses hold the run, and
  `retry-same` resends the same command with the same id. Scenarios reply to it with
  `type: response`. Providers must deduplicate on the request id.
- Base Registry Engine (BReg) Action aliases import owner-generated exact contracts for immediate
  Actions, which can route declared no-effect refusals explicitly. The applicant drives a Proposal
  in BReg; a Workflow follows it by product event or record read.
- Workflows can request independently authorized Casework review. Signed product events can start
  typed workflows through explicit source bindings.
  Receiving products retain effect authority and recheck their conditions before committing.
- Inspection reports accepted or unknown effects and bounded wait state without protected inputs,
  raw product responses, prepared requests, or correlation values. Encrypted PostgreSQL custody,
  durable audit, retention tombstones, and explicit fenced restore recovery protect work.
- Protected state schema version 4 directly replaces earlier pilot layouts. Earlier schema
  versions are refused; there is no in-place conversion or legacy authoring syntax.
  Recreate an unreleased development database made before the leased-job CHECK required
  `lease_expires_at IS NOT NULL` to obtain that constraint. Such a database still reports
  version 4: startup does not detect or migrate its older CHECK.
- Maintained examples cover standalone Casework review, product events, and external job
  completion. Native service checks compose BReg, Casework, Scheduling, and Messaging; the
  deferred-appointment journey retains a real 961-second wait and original receipt recovery. Offline scenarios and message acceptance do not establish provider delivery.
- Signed event intake accepts deliveries up to the 1 MiB Version 1 signable bound, verifies them
  through the shared hooks receiver, and answers a larger one with `request.body-too-large`.
  Delivery counters are canonical positive decimals up to the signed 64-bit range. The admitted
  event value still fits the 128 KiB structured value profile; an event over that profile is
  refused with `event.too-large` (413), which names the bounds and asks the producer to project
  fewer or smaller fields into the event.

- BREAKING: a discovery `jwks_uri` on another origin than the
  `deployment.authentication` issuer must use HTTPS and is refused when it
  resolves to a private or loopback address, under `development-loopback` too.
  The issuer and a declared `jwksSource.uri` may resolve to a private or
  loopback address, and `deployment.authentication.allowInsecureHttp: true`
  permits plain HTTP beyond loopback to them. Migration: declare the key
  endpoint as `jwksSource: {type: uri, uri: ...}` or serve it from the
  issuer's origin.
