# Registry Coordinator

Use Registry Coordinator when your institution needs a reviewed sequence of
Registry Stack calls to continue across durable waits, service outages and
worker restarts. One optional Rust service executes finite, acyclic YAML plans
with bounded pure Rhai mappings. PostgreSQL stores encrypted progress and
prepared commands. Receiving products retain authorization and ownership of
every external effect.

This milestone supports controlled institutional pilots. Its
[pilot contract](PILOT-CONTRACT.md) describes the supported product boundary; the
[deployment runbook](DEPLOYMENT.md) covers installation, authenticated access,
package activation, operation and recovery. It does not claim distributed
rollback or production availability.

## Create and check a project

Run these commands from the maintained Registry Stack checkout. The two binaries
separate local authoring and deployment operations from the running service.

```sh
cargo run --locked -p registry-coordinator --bin coordinatorctl -- init --directory ./my-follow-up
cargo run --locked -p registry-coordinator --bin coordinatorctl -- check --project ./my-follow-up --explain
```

For the later `coordinatorctl` commands, use the installed executable from the
[deployment runbook](DEPLOYMENT.md#install-and-package), or the same `cargo run`
prefix followed by `--`. The starter
contains `workflow.yaml`, `functions.rhai` and `runtime.yaml`. Init creates a new
directory and refuses to overwrite an existing one. Check validates the graph,
function exports, argument references, input/outcome schemas and execution bounds
without credentials, network access or database writes. Add `--runtime-config
/absolute/path/runtime.yaml` to check the logical bindings as well.

`workflow.yaml` is a `CoordinatorProject` document. Its `project` block names the
workflow and version, `deadlineSeconds` states a bounded integer duration, and
`functionsFile` names `functions.rhai`. Each step declares its `type`: `wait-until`,
`call`, `choose`, or `finish`. Mapping arguments explicitly name their source:
`{type: input}` supplies the whole workflow input and
`{type: step, step: read-application}` supplies that earlier call's whole output.
The checker proves the referenced call completed on every incoming route. Select
individual fields inside the pure function.

All three configuration formats use the shared strict configuration reader and carry
editor schema modelines. JSON Schema fragments and scenario payloads retain their
own JSON value semantics, including nested null values; optional configuration
members are omitted. Check reports all independent structural errors with file,
line, column and a repair action, without echoing configured values.

Runtime files can also be checked alone:

```sh
coordinatorctl --runtime-config /absolute/path/runtime.yaml check --deny-warnings
```

The default check does not read environment values or secret material. It warns
where an environment expression defers a value check. Add `--environment` to
substitute those expressions explicitly; `--deny-warnings` makes deferred checks
fail. JSON reports use `CoordinatorCtlReport` on standard output, with `ok`,
`command`, `status` and a `diagnostics` array for refusals. Exit codes distinguish
accepted input (0), refused input (1), command usage (2) and unavailable resources
(3).

`explain --project DIR` describes each call's product, effect and recovery
contract. `test --project DIR` runs the project's `scenarios.yaml` with a virtual
clock and fake product replies. It uses the same graph, mapping and function
semantics as the service. Scenario tests never acquire real credentials or send
requests. `--format json` supplies structured reports for these commands.

## Start from a maintained project

- [Delayed follow-up](examples/delayed-follow-up/workflow.yaml) waits durably,
  reads a current Base Registry Engine (BReg) record, chooses a reviewed notice
  policy and submits one message. Its deterministic scenarios cover permission changes, waits,
  uncertain responses, frozen command retries and refusals.
- [Deferred appointment](examples/deferred-appointment/workflow.yaml) reads a
  current BReg record, waits, reads Scheduling availability, books with an
  explicitly approved Casework deferred grant, then submits a separate Messaging
  notice. The original grant reference and deadline stay fixed while credentials
  are acquired freshly. Standing catalogue read authority, booking task authority
  and Messaging identity are separately configured.
- [Approved record check](examples/approved-record-check/workflow.yaml) exercises
  a BReg read through explicit Casework task authority.
- [Governed action follow-up](examples/governed-action-follow-up/workflow.yaml)
  reads an application, invokes a governed BReg action through a permitted service
  profile, and submits a separate notice through Messaging.
- [External directory](examples/external-directory/workflow.yaml) reads a configured
  directory over HTTP GET and chooses an outcome from the validated response.

```sh
coordinatorctl check --project products/coordinator/examples/deferred-appointment --explain
coordinatorctl test --project products/coordinator/examples/deferred-appointment
coordinatorctl test --project products/coordinator/examples/delayed-follow-up
```

Adapt the reviewed functions and owning product policy to your institution. YAML
declares the finite graph, waits and fixed logical connections. Choose pure Rhai
for field mapping and branch selection within that graph. Rhai cannot acquire
credentials, contact products or construct additional steps. There are no SQL
steps, arbitrary HTTP methods, dynamic fan-out or automatic compensation.

The supported operation inventory is fixed:

| Operation | Receiver | Effect | Recovery |
| --- | --- | --- | --- |
| `read-record` | Base Registry Engine (BReg) | Read | Read again |
| `submit-message` | Messaging | Mutation | Same command and read-only receipt |
| `read-scheduling` | Scheduling | Read | Read again |
| `read-availability` | Scheduling | Read | Read again |
| `create-appointment` | Scheduling | Mutation | Same command and read-only receipt |
| `invoke-breg-action` | BReg | Mutation | Same prepared command; no read-only receipt |
| `external-get` | Configured external HTTP service | Read | Read again |
| `evaluate-decision` | Configured typed decision service | Evaluation | Hold after uncertain dispatch |

`invoke-breg-action` takes an action identifier and an object of action inputs.
It requires a standing BReg service identity and a profile that permits that
immediate action. It does not accept a Casework grant or inherit task authority.
The maintained BReg client owns metadata validation, condition ETags and prepared
command recovery. Preparation is nonmutating; its exact request and idempotency
key are saved before dispatch. Later attempts check current metadata and acquire
fresh credentials without refreshing the saved conditions or key. A changed
contract, denied authority or stale condition stops the action safely.

`external-get` binds through `runtime.externalHttpConnections`, separately from
product connections. Operators configure the base URL, exact permitted paths,
query parameter names, optional service authorization and response schema. The
workflow supplies only a permitted path and query values. The adapter performs
GET, rejects redirects, and returns the validated `{status, body}` JSON value.
An omitted authorization block means a public read, with no borrowed caller
credential. See the [configuration reference](../../docs/site/src/content/docs/reference/coordinator-configuration.mdx)
for limits and defaults.

`evaluate-decision` accepts typed predicate, choice and rubric-score questions.
Bind its logical `decision` connection under `runtime.decisionConnections` using
the System One or OpenAI Decisions protocol. The exact request is frozen before
sending; the validated result is saved before the next step. Rhai can apply
thresholds to the saved answers, then a separate product call acquires its own
authority. A refused or uncertain model result grants no authority.

An evaluation may be billable and cannot be treated as a repeatable read. An
ambiguous dispatch stops without automatic retry, `retry-same` or receipt
reconciliation. Cancel and make a separately authorized new start if another
potentially billable evaluation is appropriate. The
[decision example](examples/decision-follow-up/README.md) demonstrates offline
branching and distinguishes model refusal from transport uncertainty. General
structured generation, model tools and asynchronous jobs are not supported.

## Add a maintained operation

For an operation on an existing product boundary, add a versioned descriptor in
`src/operations.rs` under `crates/registry-coordinator`. Declare its product,
effect, key requirement, preparation requirement, recovery semantics and read-only
receipt capability. Add the owning client adapter and routing, with focused
contract and recovery tests. Use the `AdapterSet` preparation seam when the client
requires a saved prepared command. Product metadata, authorization and wire
validation remain the maintained client's responsibility.

The operation schema derives from the catalog; regenerate the project schema.
The worker, store and offline scenario state machine consume those declared
capabilities. They do not need operation-specific execution branches. Snapshots
pin exact semantics, so changing a descriptor or its version cannot silently
reinterpret retained runs. Preserve the original descriptors for compatible
restore, including the fixed legacy catalog. Add offline scenarios using typed
replies and only the declared recovery capabilities; passing them does not prove
a live product effect. Coordinator exports are not generated into a language SDK.

## Package and deploy

```sh
coordinatorctl package --project ./my-follow-up --output ./follow-up-package
```

The immutable package contains a Definition snapshot and shared `SHA256SUMS`
closure. It holds reviewed workflow/functions and executable ABI identities.
Endpoints, credentials, private access policies, database identity, encryption
keys and audit custody remain in runtime configuration. Compatible new packages
serve new admissions while previously admitted runs keep their original snapshots
and command identities. A new version cannot reinterpret a repeated start key.

The authored configuration conventions do not rewrite stored execution snapshots.
Existing immutable packages and admitted runs retain their original definition
bytes and ABI. New project files use the documented `CoordinatorProject` format;
an older `Workflow` authoring envelope is refused with migration guidance.

Version 4 snapshots pin each used operation's capabilities. Existing version 3
snapshots retain their original bytes and remain restorable with their original
five-operation contract. Packaging commands are unchanged; a newly packaged
definition with a changed digest needs a new workflow version if that ID and
version already exists in retained history.

Use [DEPLOYMENT.md](DEPLOYMENT.md) to provision OIDC clients, downstream bindings,
state-key custody, PostgreSQL split roles and a private listener. Apply explicitly
migrates and activates the pinned package. The service verifies activation and
never migrates during startup. Its authenticated admission API derives ownership
and idempotency scope from exact verified issuer and subject. Input identifiers
and grant references do not manufacture caller authority.

## Observe and recover

Authenticated status and list expose caller-owned progress and the reviewed
terminal projection. Inspection shows bounded step metadata, uncertainty and the
available recovery action. Operator policy explicitly grants recovery and private
diagnostics. Inputs, product responses and prepared commands remain encrypted and
are absent from these responses.

For a compatible current call, inspection includes `recovery.operation`: its
pinned ID, version, product, effect, key and preparation requirements, recovery
semantics and `readReceipt` capability. When inspection can otherwise proceed,
it omits the field if no compatible current call is available, including pure
steps, erased payloads or incompatible snapshots. An unresolved original binding
can still refuse inspection. For example, `invoke-breg-action` declares
`same-command` recovery with `readReceipt: false`. `retryAllowed` and `reason`
describe the run's eligibility to be scheduled. The operation descriptor does
not prove current product authority or the existence of an original-key receipt.

One deployment admits one active flow definition. Previously admitted versions
remain available for their existing runs. The list API returns the latest
caller-owned runs, with a default limit of 20 and a maximum of 100; it has no
pagination cursor. Coordinator does not yet have an `@registrystack/client` export.
Institutional applications compose through its authenticated HTTP API and the
owning Casework, BReg and optional Messaging APIs.

After a lost Messaging or Scheduling response, reconcile against the receiving
product's original-key receipt before retrying. BReg action reconciliation remains
unresolved because no read-only action receipt is available; an ordinary record
read does not prove that the original action succeeded. Same-command recovery
preserves the body, key, destination, caller and original task authority.
An unavailable product or expired receipt never proves that an effect did not
occur. Messaging acceptance records a
provider submission contract; provider delivery is a distinct observation.
Cancellation prevents later dispatch where possible and does not roll back an
appointment, governed action or notice already accepted by its owning product.

Retention erases eligible terminal payloads while preserving spent-key tombstones.
A retained run can still be inspected; it cannot be retried or reconciled without
its erased payload. Restore starts with dispatch and admission disabled. Recovery
hold marks every unfinished restored run for review, including commands not yet
prepared at the backup point. Execution history and admission history have separate
release requirements. The deployment runbook explains the explicit fencing and
complete-history attestations and the limits of older backups.

## Verify a change

The owning Cargo tests cover authoring, deterministic scenarios, runtime config,
package integrity, OIDC policy, product adapter boundaries and Scheduling command
recovery. The PostgreSQL feature gates protect database-dependent suites from
ordinary workspace test runs.

```sh
cargo test --locked -p registry-coordinator --features schema \
  --test authoring --test authored_project --test authored_scenarios \
  --test cli_authoring --test runtime_config \
  --test deployment_surface --test http_boundary --test scheduling_adapter \
  --test breg_action_adapter --test external_http --test external_runtime \
  --test decision_protocol --test decision_runtime \
  --test catalog_scenarios --test operation_compatibility
products/coordinator/scripts/check-schemas.sh
cargo run --locked -p registry-coordinator --bin coordinatorctl -- openapi \
  > products/coordinator/generated/openapi/coordinator.openapi.json
```

With dedicated disposable PostgreSQL 17+ databases configured, use
`scripts/test-postgres.sh` for the maintained durable-state, encrypted-custody,
restart, deployment/router and Messaging integration checks. That script first
builds the independent Messaging service and operator executable, then supplies
`COORDINATOR_MESSAGING_BIN` and `COORDINATOR_MESSAGINGCTL_BIN` to the tests.
The integration fixtures compose through Messaging's public HTTP contract and
refuse missing executables; Coordinator does not link its runtime as a test
dependency. The native-service
fixture script runs the controlled BReg, Casework, Scheduling and Messaging
journey. It requires Python 3, OpenSSL and PostgreSQL client tools, Docker,
distinct disposable PostgreSQL databases, and all ten native service/operator
binaries described by the script's `--help`. Those contributor checks do not replace the deployment runbook or imply
production credentials are needed to author a project.

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

The first native check proves one governed patch was accepted despite a lost response.
Reconstructed `HttpAdapters` reload the saved preparation and recover with the
same body, key and conditions, leaving one applied record revision and returning
the same application receipt. It checks fresh metadata, refusal through a real
read-only profile, and no BReg receipt lookup during reconciliation.

The second check executes `Worker` and `Store` through a real BReg action and a
real Messaging notice submission. After the accepted notice reply is dropped,
reconstructed objects recover through the exact original notice receipt lookup.
The action and notice are not resubmitted, and duplicate start admission returns
the original run. This proves message acceptance, not provider delivery.
Reconstruction replaces Rust objects; it does not restart the Coordinator OS
process. The separate `process_restart` target retains process restart coverage.
The separate `scripts/test-real-services.py` journey composes BReg, Casework,
Scheduling and Messaging with a persisted wait and an actual worker restart.
Its default 961-second wait crosses the immediate approval limit. It checks
fresh credentials bounded by the original deferred approval, original-receipt
recovery after lost booking and notice replies, and refusal of expired, unknown
or mismatched approvals without additional effects. Waits shorter than 901
seconds are smoke checks and do not establish the long-wait boundary.
The helper remains an explicit contributor check, not a new CI gate.
