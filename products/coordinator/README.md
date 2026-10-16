# Registry Coordinator

Use Registry Coordinator when your institution needs a reviewed sequence of calls to continue
across durable waits, outages, and worker restarts. One optional Rust service executes finite,
acyclic workflows. PostgreSQL stores encrypted progress and prepared commands. Receiving products
retain authority and ownership of every effect.

The [product contract](PRODUCT-CONTRACT.md) defines the boundary; the
[deployment runbook](DEPLOYMENT.md) covers installation, custody, activation, and recovery.
Coordinator is pre-1.0. Use one source version's binaries, packages, configuration, and state
layout together. The current protected state schema is version 4, with no in-place migration
from earlier pilot layouts.

Build the Coordinator service, operator CLI, client, and client bindings from source using
the deployment runbook and the client crate instructions. The release binaries and container
image are not yet distributed, and the Coordinator client is not part of the unified Rust,
Node.js, or Python packages.

## Create and check a project

From the maintained Registry Stack checkout:

```sh
cargo run --locked -p registry-coordinator --bin coordinatorctl -- init --directory ./my-follow-up
cargo run --locked -p registry-coordinator --bin coordinatorctl -- check --project ./my-follow-up --explain
```

For subsequent commands, install the executable as described in the deployment runbook, or use
that `cargo run` prefix followed by `--`. Init accepts a new or empty directory. The starter
contains `workflow.yaml`, `functions.rhai`, `runtime.yaml`, `scenarios.yaml`, and a `.gitignore`
for local `.coordinator/` state. A project can omit functions when no mapping needs one.

A `CoordinatorProject` separates reusable assets from the one workflow that uses them:

- `project` supplies an ID and human version label.
- `contracts` optionally imports generated local product contracts.
- `types` optionally names reusable JSON Schemas.
- `functions` optionally names typed pure computations, their source assets, and entrypoints.
- `operations` names local aliases for exact versioned host operations and logical connections.
- `workflow` contains input, deadline, start step, steps, and declared outcomes.

```yaml
operations:
  read-application:
    uses: breg.read-record/v1
    connection: applications
workflow:
  input:
    type: object
    additionalProperties: false
    required: [applicationId]
    properties:
      applicationId:
        type: string
        format: uuid
  deadlineSeconds: 300
  start: read
  steps:
    read:
      type: call
      operation: read-application
      input:
        type: fields
        fields:
          collection:
            type: literal
            value: applications
          recordId:
            type: input
            path: /applicationId
      next: report
    report:
      type: finish
      outcome: observed
      output:
        type: step
        step: read
  outcomes:
    observed:
      operationOutput: read-application
```

Mappings select the workflow input, an available earlier step output, or a literal. `path` is an
RFC 6901 JSON Pointer. `type: fields` builds an object. `type: function` invokes a named Function
with an `inputs` object whose keys exactly match its declared inputs. Each Rhai entrypoint takes
one object of those named inputs and returns one typed value. The host validates inputs and
outputs and enforces the bounded pure profile. Functions have no clock, network, database,
credential, or filesystem capability. `add_seconds` and `seconds_between` compute over supplied
RFC 3339 instants. Optional function limits can narrow the host ceilings.

Schema positions accept a JSON Schema or `typeRef`, `operationInput`, `operationOutput`,
`operationRefusal`, or `completionOutput`. A completion output names its operation and completion.
Check resolves those references locally, verifies dominance on every incoming route, and fits
mappings to input and result contracts before execution. Dynamic values are validated again at
runtime before preparation or dispatch. An invalid command reports `failurePath`, never its value.

```sh
coordinatorctl check --project ./my-follow-up --explain
coordinatorctl test --project ./my-follow-up
coordinatorctl --runtime-config ./my-follow-up/runtime.yaml check --deny-warnings
```

Check, explain, test, package, and types export work offline. Scenario tests use a virtual clock
and fake replies. They prove workflow logic, not downstream acceptance. Diagnostics name source
positions and repairs without echoing protected values. `--environment` explicitly substitutes
runtime environment expressions; secrets are never resolved by an offline check. Commands print
text by default or a `CoordinatorCtlReport` with `--format json`. Exit codes are 0 for acceptance,
1 for refusal, 2 for usage, and 3 for unavailable resources.

## Start from a maintained project

- [Delayed follow-up](examples/delayed-follow-up/README.md) waits, reads current permission, and
  submits a separate Messaging notice.
- [Deferred appointment](examples/deferred-appointment/README.md) retains explicit deferred
  Casework task authority across a wait before a Scheduling commitment.
- [Approved record check](examples/approved-record-check/README.md) reads Base Registry Engine (BReg) under task authority.
- [Governed action follow-up](examples/governed-action-follow-up/README.md) uses an exact imported
  immediate BReg Action contract, then submits a separate notice.
- [Decision follow-up](examples/decision-follow-up/README.md) interprets a typed evaluation before
  a separately authorized BReg Action.
- [Standalone review](examples/standalone-review/README.md) submits a source-neutral Casework
  request using an explicit policy pin and waits for its result. An ID-only selector is the
  ordinary default; these examples also demonstrate the optional exact-pin form.
- [Reviewed notice](examples/reviewed-notice/README.md) combines standalone review with a fresh
  record and permission check before Messaging.
- [Product events](examples/product-events/README.md) admits committed BReg events and a
  conforming alternate-source fixture through the same signed event contract.
- [External directory](examples/external-directory/README.md) performs a configured HTTP GET.
- [External job](examples/external-job/README.md) uses a bounded completion poll and pure
  interpreter for one previously selected external job.

## Waits and polling

To react to product events, declare `workflow.eventTriggers` and bind each logical source in
runtime `eventSources`. The receiver at `POST /v1/events/{workflow}/{trigger}` accepts the shared
platform signed HookEnvelope. Its ordinary mapping selects typed Workflow input; product event
names and payload meanings remain in the authored project. The same event recovers one durable
Run after a lost response or restart. Downstream calls require their own product credentials.
Select state transitions and guard writes back to the source to avoid fresh-event loops.

`wait-until` persists an instant and continues immediately when that instant has passed.
`wait-for` observes a named completion exposed by an earlier accepted call:

```yaml
await-review:
  type: wait-for
  completion:
    step: submit-review
    name: result
  timeoutSeconds: 1209600
  next: report
  onTimeout: withdraw
  onCancel: withdraw
```

Casework submission exposes `result`.
An external GET operation can declare a named `bounded-poll` completion with a typed pure
`interpret` Function and `intervalSeconds`. The Function interprets the saved command and latest
validated response as pending, complete, or a declared business refusal. The host owns transport,
credentials, scheduling, correlation, and the observation budget. The workflow graph stays acyclic.

Completion observation is read-only. Every read has a persistent minimum spacing of at least 30
seconds. `minimumObservationIntervalSeconds` can raise that deployment-wide minimum. Casework
pending reads default to 900 seconds; Casework's `resultCheckSeconds` is configurable.
The operation interval and deployment minimum constrain external polls. Retry hints are honored
within the host ceiling of 86,400 seconds; an unusable hint holds the wait. Restart, a completion
wake-up, timeout, or recovery cannot bypass the durable read floor. Inspection reports the next
observation, floor, count, and limit. An authenticated Casework completion event only advances an
eligible result read. It carries no decision authority and starts no run.

A settled completion takes `next`. An expired wait takes `onTimeout`, or reports `wait-timed-out`.
An optional `onCancel` takes an authored cleanup path; repeated cancellation preserves that path.
Unavailable, mismatched, blocked, or uncertain evidence cannot become a business outcome. Inspect
and recover held work under the original deadline and identity. Timing out a Coordinator wait
does not cancel work in the owning product.

## Governed actions

A `breg.invoke-action/v1` alias names `action.contract` and `action.id`. Import the owning BReg
project's generated Action contract instead of reproducing its schema. The compiler pins its
revision, mode, inputs, output, and declared refusals. Metadata
checks at preparation, dispatch, and observation prevent a changed owner contract from silently
reinterpreting work. A standing BReg profile and identity authorize each call independently.

The operation invokes immediate Actions and returns their exact application result. The
compiler refuses a Proposal Action with `coordinator.operation.proposal-action`, and the runtime
refuses one at preparation with `action-unavailable`. The applicant drives a Proposal in BReg;
a Workflow follows it through a committed BReg product event or a later `breg.read-record/v1`
read.

`onDeclaredRefusal` routes only a validated owner-declared no-effect
refusal. Its output is `{refusalCode}`. Operational failures stay failures, and a later refusal cannot resolve an earlier
uncertain effect. The success and refusal outputs are available only along their respective
routes. A join reached through both has no single output shape. Omit `onDeclaredRefusal` and a
declared refusal fails the run with `product-refused`, like any other refusal.

Standalone Casework review is independent of BReg. Its submission includes an expected
`PolicyBinding`; the accepted request and eventual result must agree with that exact policy,
subject, and submission digest. Casework owns reviewer authority and outcomes. Review completion
creates no registry effect. A later BReg or Messaging call requires its own authority.

## Package and deploy

```sh
coordinatorctl package --project ./my-follow-up --output ./my-follow-up-package
coordinatorctl types --project ./my-follow-up --language typescript --output ./follow-up.ts
coordinatorctl types --project ./my-follow-up --language python --output ./follow_up.py
```

Package refuses existing output and failing scenarios. The package digest covers `SHA256SUMS`.
The computed `workflowRevision` identifies execution semantics; package checksums cover the
exact snapshot bytes. Titles, descriptions, and the human version label do not change that revision.
Existing runs retain their original snapshot and revision when a new package is activated.
Retain the keys needed to read them. New starts must pin the active revision; recovery of an unknown
admission uses the exact original key, input, and revision.

Generated TypeScript and Python wrappers provide typed `start`, `get`, and `cancel` through the
maintained public generic clients. They pin the workflow revision and validate returned workflow
identity and declared outcome names. Runtime schema validation remains with Coordinator.

The operator binds every alias's connection in one `connections` map. Each entry declares `type`:
`breg`, `casework-review-producer`, `messaging`, `scheduling`, `external-http`, or `evaluation`.
Caller policies are keyed by exact verified client identity and list allowed `workflows` and
actions. One deployment serves up to sixteen workflows in one trust domain, one package each.
Separate deployments where workflows must not share connection custody.

Discover a permitted active contract before starting new work:

```sh
coordinatorctl workflow --workflow delayed-follow-up --url https://coordinator.example.org --token-file ./producer-token
coordinatorctl start --workflow delayed-follow-up --workflow-revision <workflow-revision> --input ./input.json --key-file ./start-key --url https://coordinator.example.org --token-file ./producer-token
```

Start sends `workflow`, `workflowRevision`, and `input`. A fresh start must match the active
revision. An unknown admission is recovered with its exact original identity, key, revision, and
input, including after activation changes. A reused key with different work is refused.

## Observe and recover

Status and list expose bounded progress and authored outcome projections. Inspect adds step
state, accepted or unknown effects, durable waits, and recovery eligibility, without protected
inputs, raw responses, prepared requests, or correlation values. Run visibility checks both
ownership and current workflow policy. Operator status reaches other owners only in permitted
workflows. Deployment-wide actions need explicit operator authority.

Same-command recovery preserves the saved body, key, conditions, binding, and original approval
deadline while obtaining fresh credentials. Messaging and Scheduling offer original-key receipt
reads. BReg Action and Casework mutations cannot be settled by an ordinary record read or operator
assertion. A possibly dispatched evaluation stays held and cannot be replayed. Cancellation stops
future dispatch where possible and never rolls back accepted effects. Messaging acceptance is
separate from delivery.

Protected API actions and results require durable audit. Refusals use the generated RFC 9457
problem vocabulary and never echo submitted values. Retention erases eligible terminal payloads
while preserving spent-key tombstones. Live, uncertain, and restore-review work stays protected.
Backup recovery requires external fencing, held execution and admissions, and separate history
attestations. Follow the [deployment runbook](DEPLOYMENT.md#backup-and-restore) before releasing holds.

## Verify a change

The owning Cargo tests cover authoring, deterministic scenarios, runtime config,
package integrity, OIDC policy, product adapter boundaries, Scheduling command
recovery and the authoring of review waits. The PostgreSQL feature gates protect database-dependent suites from
ordinary workspace test runs, so this command runs every suite that needs no database:

```sh
cargo test --locked -p registry-coordinator --features schema
products/coordinator/scripts/check-schemas.sh
```

The schema check generates temporary outputs and compares them with the committed schemas and
OpenAPI document. It does not rewrite tracked artifacts; regenerate changed artifacts explicitly
with their owning generators.

With dedicated disposable PostgreSQL 17+ databases configured, use
`scripts/test-postgres.sh` for the maintained durable-state, encrypted-custody,
restart, deployment/router, review waits, standalone review, bounded external waits, and
Messaging integration checks. That script first
builds the independent Messaging service and operator executable, then supplies
`COORDINATOR_MESSAGING_BIN` and `COORDINATOR_MESSAGINGCTL_BIN` to the tests.
The integration fixtures compose through Messaging's public HTTP contract and
refuse missing executables; Coordinator does not link its runtime as a test
dependency. The native-service
fixture script runs the controlled BReg, Casework, Scheduling and Messaging
journey. It requires Python 3, OpenSSL, PostgreSQL client tools matching the test server,
Docker, and distinct disposable PostgreSQL databases. Use the explicit preparation command below
to build all ten service/operator binaries and the `reviewed-notice-input` helper with the required
features. Those contributor checks do not replace the deployment runbook or imply
production credentials are needed to author a project.

Run the generated TypeScript and Python client proofs with one owned disposable PostgreSQL 17+
database. The identity must create and drop the fixtures' unique schemas and roles. The helper
prepares the current Coordinator bindings and their FIPS/module paths; it needs the Cargo native
build toolchain, Python 3, Node/npm matching the binding packages, and Pyright on `PATH`.
Use `--pyright /absolute/path/pyright` to select another local installation. Missing Node development
dependencies are installed locally with the binding's pinned `npm ci`.

```sh
COORDINATOR_TEST_DATABASE_URL=<owned-loopback-database-url> \
  python3 products/coordinator/scripts/test-generated-clients.py
```

This check runs the strict TypeScript intersection regression and the four projects' generated
TypeScript/Python admission, status, cancellation, and revision-refusal journeys. The external-job
project additionally consumes a successful typed terminal outcome in both languages. It needs no
Messaging database, product service binaries, Docker, or global package installation.

The governed-action and external-directory examples have deterministic scenarios;
adapter checks use mock HTTP services and durable-state checks use PostgreSQL.
For native BReg action and notice acceptance, run this explicit helper from the checkout:

```sh
python3 products/coordinator/scripts/test-breg-action.py --env /absolute/path/coordinator-test.env
```

Provide Python 3, the current checkout's Cargo build prerequisites, and
distinct `COORDINATOR_TEST_DATABASE_URL` and
`COORDINATOR_MESSAGING_TEST_DATABASE_URL` values in the environment or named file.
Each URL must name an owned disposable PostgreSQL 17+ database on loopback.
The Coordinator database identity needs authority to create and drop unique
fixture databases and roles; both database identities must create and drop
fixture schemas. The helper builds current `breg`, `bregctl`, `messaging` and
`messagingctl` binaries and provisions synthetic credentials and data. Successful
runs clean up UUID-owned fixture resources without resetting the named databases.
Assertion failures can retain diagnostic Coordinator and Messaging schemas.
No live service credentials are required.

Native checks distinguish adapter reconstruction, worker reconstruction, and OS-process restart.
The separate native service journey composes BReg, Casework, Scheduling, and Messaging over their
public HTTP contracts with Casework review tasks, exact policy bindings, and durable Coordinator waits.

Prepare native executables once from the checkout, using a new private output directory outside
its source roots. Preparation needs the Rust/native build toolchain but starts no service and
requires no database URLs. It honors `CARGO_TARGET_DIR`, captures source identities before and
after the build, and refuses a source change during compilation. It freezes all ten executables,
`reviewed-notice-input`, and the exact macOS FIPS library with their hashes in `build-manifest.json`.
Existing output is never overwritten.

```sh
python3 products/coordinator/scripts/test-real-services.py --prepare /absolute/private/native-build
```

Then configure the two disposable database URLs described earlier and run the composition:

```sh
python3 products/coordinator/scripts/test-real-services.py \
  --bin-dir /absolute/private/native-build/bin \
  --build-manifest /absolute/private/native-build/build-manifest.json --wait-seconds 961
```

A supplied `--bin-dir` uses existing executables without rebuilding. Without it, the helper uses
Cargo metadata's `target_directory/debug`; that directory must already contain every required
executable. Retain the preparation directory until the journey has finished.

The real 961-second deferred-appointment wait crosses the immediate approval limit; a wait below
901 seconds is a smoke check only. Exact original-receipt recovery, expiry and revocation checks,
and message acceptance are distinct from recipient delivery. Offline scenarios do not establish
these native product effects.
