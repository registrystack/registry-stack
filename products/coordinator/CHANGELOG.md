# Registry Coordinator changelog

## Unreleased

- BREAKING: protected state schema version 5 adds the latest Proposal
  observation to each wait that follows a BReg Proposal. Version 4 namespaces
  from 0.44.0 are refused. Settle their runs with the 0.44.0 binaries, then
  apply to a fresh namespace and database identity.
- BREAKING: the pure Function interpreter ABI is now `v2` because the
  profile gained helpers. Every definition frozen by 0.44.0 records `v1` and
  is refused with `definition.abi`, whether or not it has a Function, so no
  0.44.0 run continues on this version. Settle runs with the 0.44.0
  binaries, then check and promote the project again. A 1.0 install starts
  on `v2`.
- BREAKING: upgrade the Coordinator clients with the server. The 0.44.0
  Rust, Python and Node clients refuse unknown fields, so they refuse an
  inspection that carries `holdDetail`, `lastObservation` or `requestLink`.
  Rust callers that build `RunListQuery`, `WaitStatus`, `StepStatus` or
  `BRegProposalSubmission` as struct literals must set the new fields.
- Add the BReg Proposal operations `breg.read-proposal/v1`,
  `breg.start-proposal/v1`, `breg.submit-proposal/v1` and
  `breg.cancel-proposal/v1`. Each names a Proposal of one pinned Proposal
  Action, and the host-owned Proposal completion follows it by Proposal Get
  until it is applied, rejected or cancelled, or returned to the party after
  this run submitted it. Start and submit replay as frozen commands under
  stable keys; check refuses a cancel that does not name a Proposal the run
  opened. No operation decides a Proposal.
- A `breg` connection takes `resultCheckSeconds` (60 to 86,400, default 900)
  for how often a Proposal wait reads, and an `https` `requestLink` template.
  Neither enters the binding digest, so both can change while runs wait.
- `coordinatorctl check` warns `coordinator.follow.long` for a Proposal wait
  longer than 90 days and `coordinator.follow.timeout-unrouted` for one with
  no `onTimeout` route.
- Add `breg.read-in-force/v1`: one `:as-of` read for the record of a
  date-interval Record type in force for a structured `subject` on a `date`.
  It sends the date as a calendar date. No record is the declared refusal
  `none-in-force`, which needs an `onDeclaredRefusal` route; two records hold
  the run with `in-force-ambiguous`, and inspection names both record
  identifiers and the date. Check refuses a Record type without a date
  interval (`definition.read-in-force-entity`) and warns
  `coordinator.read-in-force.may-be-ambiguous` when no `temporal-non-overlap`
  constraint is scoped only by fields the subject names. It needs a BReg
  record schema that carries the `x-registry-temporal` marker.
- Add Check now: `POST /v1/runs/{run}/check` and `coordinatorctl check-now`
  bring forward the next read of a step's open wait. It keeps the read floor,
  counts against the wait's read budget, needs only the inspect grant, is
  audited as `check-now`, and answers `409 check.not-waiting` when the step
  has no pending wait, including a wait held for recovery.
- A `fields` mapping member can be a nested `fields` mapping, up to 4 levels
  and 64 members across levels, so a Workflow builds a structured input
  without a Function. Check reports `mapping.fields-depth` and
  `mapping.fields-count`, and checks each nested member against the input
  schema at its path.
- A `choose` step can route on `type: compare`, with `all` or `any` over one
  to sixteen conditions (`equals`, `oneOf`, `less`, `greater`, `present`),
  to the cases `matched` and `unmatched`. Dates order as calendar dates. A
  missing or wrongly typed value fails the run with `choice-invalid` rather
  than routing to `unmatched`.
- Inspection shows each Proposal wait's `lastObservation` (state, turn,
  submission version, any hand-off refusal code, `observedAt` and
  `stateSince`) and, when the BReg connection sets `requestLink`, its
  `requestLink`.
- `GET /v1/runs` and `coordinatorctl list` take `proposal=<id>` (`--proposal`)
  for the runs waiting on one BReg Proposal and `turn=party|official|nobody`
  (`--turn`) for runs whose Proposal wait last read that turn. List cursors
  carry these filters; a cursor issued by 0.44.0 is refused, so start the
  list again.
- Doctor reports `state.proposalWaitsByTurn`, the Proposal waits counted by
  their last observed turn plus those not yet observed, from stored rows
  without calling BReg.
- The Rust, Python and Node Coordinator clients decode a wait's
  `lastObservation` and `requestLink` on inspection, a held step's
  `holdDetail`, and their run lists take the `proposal` and `turn` filters.
- Functions can call Rhai's string helpers (`trim`, `split`, `starts_with`, `index_of`,
  `sub_string`, `pad`, `replace`, and the rest of its string package) and these number helpers:
  `parse_int`, `parse_float`, `to_int`, `to_float`, `sqrt`, `floor`, `ceiling`, `round`, `int`,
  `fraction`, `is_nan`, `is_finite`, `is_infinite`, `to_degrees`, `to_radians`, `PI` and `E`, next to
  the arithmetic package's `abs`, `sign`, `min` and `max`. The trigonometric, hyperbolic,
  exponential and logarithmic functions (`sin`, `exp`, `ln`, `log`, `hypot` and the like) are not
  available, because their last digits depend on the host's math library and Function results are
  recomputed. `replace` and `pad` refuse a result over the string limit before building it, and
  `pad` refuses an empty padding string. A Function result that holds NaN or an infinite number is
  refused with `function.execution` instead of becoming JSON `null`.
- `coordinatorctl check` reports a call to a name the pure profile lacks as
  `coordinator.function.unknown-call`, with its line and column, before any Function runs. It also reads a string literal given to `Fn`, `is_def_fn` or an array
  method such as `map` as a function name. It is an authoring aid; the engine still refuses an
  unknown name when the Function runs.
- `coordinatorctl explain functions` lists the helpers a Function may call, the interpreter ABI
  and the limits.

## 0.44.0 - 2026-10-27

First release of Registry Coordinator.

- v0.44.0 ships the `coordinator` and `coordinatorctl` binaries, their
  installer, and the Coordinator namespace in the unified Node.js and Python
  clients. The Coordinator image remains held.
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
  the Coordinator client bindings. Unknown admission preserves its original revision and key.
- Named completions share `completion: {step, name}` across Casework results and bounded external
  job observation. Persistent read floors, retry ceilings, and
  observation budgets survive restarts and wake-ups. Blocked or uncertain evidence remains held.
- `external.command/v1` sends one bounded POST to the exact `commandPath` an operator configures
  on an `external-http` connection. The command and its request id are persisted before the first
  send and the id travels as `Idempotency-Key`; a required pure `interpret` Function maps the
  validated response to an accepted result, a declared refusal, or an uncertain hold. Before
  any uncertain attempt, a 429 is treated as not processed and retried only when another
  attempt fits the remaining attempt and deadline budgets; otherwise the run ends without
  `retry-same`. Once an attempt has an unknown effect, a later 429 or declared refusal holds
  the run. A 503 is retried with the effect held as unknown only when another attempt fits both
  budgets; otherwise it holds the run at once. Lost acknowledgements, timeouts, redirects,
  other server errors, and unusable responses hold the run, and `retry-same` resends the same
  command with the same id. Scenarios reply to it with `type: response`, never with a
  synthetic `success` or `declared-refusal`, and only with a status that reaches the
  interpretation Function; a
  redirect, 429 or 5xx takes an `uncertain` or `retryable` reply instead. Providers must
  deduplicate on the request id.
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
