# Deploy a controlled Coordinator pilot

You operate one Coordinator service beside PostgreSQL 17 or newer and the
institution's existing OIDC issuer. Receiving Registry Stack products still
verify their own caller and task authority. Coordinator runs a finite reviewed
workflow package and preserves every admitted run's original definition.

## Install and package

Build the two local binaries from the maintained checkout. No public release is
required for a controlled pilot. On Linux, install the completed binaries in a
service-owned executable directory:

```sh
cargo build --locked --release -p registry-coordinator --bins
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/coordinator target/release/coordinatorctl "$HOME/.local/bin/"
export PATH="$HOME/.local/bin:$PATH"
```

On macOS arm64, use the maintained packager to include and relocate the exact FIPS
library linked by this build. A fresh build directory avoids reusing a CMake
cache configured for a different minimum OS version. Keep each extracted binary
beside its bundled library and notices; copying the executable alone loses its
runtime dependency.

```sh
MACOSX_DEPLOYMENT_TARGET=11.0 CARGO_TARGET_DIR=target/coordinator-pilot-install \
  cargo build --locked --release -p registry-coordinator --bins \
  --message-format=json-render-diagnostics > coordinator-build.jsonl
COORDINATOR_FIPS_ROOT=$(python3 - <<'PYTHON'
import json
from pathlib import Path
messages = [json.loads(line) for line in Path("coordinator-build.jsonl").read_text().splitlines()]
roots = {str(Path(m["out_dir"]) / "build" / "artifacts") for m in messages
         if m.get("reason") == "build-script-executed" and "aws-lc-fips-sys@" in m.get("package_id", "")}
if len(roots) != 1:
    raise SystemExit("expected one exact FIPS build-script library root")
print(roots.pop())
PYTHON
)
for binary in coordinator coordinatorctl; do
  python3 release/scripts/macos_fips_packaging.py archive \
    --binary "target/coordinator-pilot-install/release/$binary" \
    --asset-name "$binary-pilot-macos-arm64" --library-root "$COORDINATOR_FIPS_ROOT" \
    --notice THIRD_PARTY_NOTICES --output "./$binary-pilot.tar.gz"
  python3 release/scripts/macos_fips_packaging.py extract \
    --archive "./$binary-pilot.tar.gz" --destination "./$binary-install" \
    --expected-executable "$binary-pilot-macos-arm64"
done
./coordinatorctl-install/coordinatorctl-pilot-macos-arm64 --help
./coordinator-install/coordinator-pilot-macos-arm64 --help
mkdir -p "$HOME/.local/bin"
ln -s "$PWD/coordinator-install/coordinator-pilot-macos-arm64" "$HOME/.local/bin/coordinator"
ln -s "$PWD/coordinatorctl-install/coordinatorctl-pilot-macos-arm64" "$HOME/.local/bin/coordinatorctl"
export PATH="$HOME/.local/bin:$PATH"
```

Use the absolute executable paths in your service definition. The operator shell
links point to the complete install directories; existing link destinations are
refused.
The packager refuses an existing output directory or archive and checks the
linked library's deployment target. Retain the complete install directories.

Create and check the governed workflow package:

```sh
coordinatorctl init --directory ./follow-up
coordinatorctl check --project ./follow-up --explain
coordinatorctl package --project ./follow-up --output ./follow-up-package
```

`package` writes one immutable `definition.json` snapshot and `SHA256SUMS`.
Install the directory read-only, record the returned package digest, and pin it
in `deployment.package.expectedDigest`. Runtime files, endpoints, credentials,
state keys and audit custody are deployment configuration, outside the package.
Existing output is never overwritten. Build a fresh directory for each update.
Use `coordinatorctl test --project DIR` for projects with `scenarios.yaml`.
Once a workflow version has admitted runs, change its version when changing its
definition. Apply checks retained history, including terminal runs and erased
payload tombstones, before activating a reused version.

## Configure the deployment

Runtime files use the `id.registrystack.org/formats/coordinator/runtime/v1alpha1`
`apiVersion` and `CoordinatorRuntimeConfig` kind. The shared runtime reader
checks the envelope, YAML structure and positioned diagnostics before deployment
values. Offline checking reads no credentials and contacts no endpoint.

Keep the project runtime's `secretProviders`, `database.runtimeUrlRef`, `namespace` and
logical `connections`. Add the `deployment` block shown in
[pilot-runtime.yaml](examples/pilot-runtime.yaml), adapting the paths, identity,
issuer and caller policy. The example contains references only. Provision each
secret separately through its enabled shared provider.

The shared `jwksSource` block selects its variant with `type`, for example
`type: discovery`. An older `kind` member is refused with its replacement
named. Write `allowedClients` as a nonempty list of exact client IDs;
Coordinator refuses omission, an empty list and `unrestricted`. Each listed
client also needs its explicit action and workflow policy.

Before applying an existing Coordinator database from schema revision 2 or 3,
stop its old workers. Explicit apply upgrades it to revision 4 and changes the
stored Dispatch state `dead_lettered` to `dead-lettered`. It preserves command
bytes, admission identity, approval and workflow deadlines, uncertainty, and
lease fields. Runtime startup refuses the older revision until apply succeeds;
the upgrade does not recover unknown effects or release a restore hold. This
Coordinator migration is not an in-place upgrade path for other products'
older configuration or databases.

For `invoke-breg-action`, configure a Base Registry Engine (BReg) connection with
an ordinary service `authorization` and an explicitly permitted `profile`. Do not configure
`authorization.taskAuthority` on that connection: this operation accepts no
Casework grant and has no task-authority fallback. Keep a task-bound record-read
connection separate when the workflow needs both authority types.

For `external-get`, configure `externalHttpConnections` separately from product
`connections`. Declare `baseUrl`, exact `paths`, optional `queryParameters`,
optional ordinary service `authorization`, and the required `responseSchema`
for `{status, body}`. Omitted authorization permits a public read and never
borrows the caller's token. The default attempt timeout is 2000 milliseconds
and the default response limit is 65,536 bytes; both may be reduced. Use HTTPS
for institutional endpoints; plain HTTP requires an explicit numeric loopback
address. See the [external directory example](examples/external-directory/runtime.yaml)
and [configuration reference](../../docs/site/src/content/docs/reference/coordinator-configuration.mdx).

For `evaluate-decision`, bind a logical `decision` connection under
`decisionConnections`. Select `system-one` or `openai-decisions`, an explicit
`baseUrl` and `model`, and either `authorization.bearer` with `tokenRef` and
`principal`, or explicit `authorization.local: {}` on numeric loopback. The
configured principal identifies the model account across credential rotation;
ensure a replacement key belongs to that same account. Request and response
limits default to 65,536 bytes and the attempt limit to 8000 milliseconds.
These limits can be reduced. Names across all three connection maps must be
unique, with at most 16 in total.

Review the data your mappings disclose before activating a remote model binding.
Model calls may incur cost. Inputs and results use Coordinator's existing protected
state and retention; provider retention remains your provider/account contract.
A model alias can change upstream even when the local binding is unchanged.
Use an immutable release/deployment identifier when your provider offers one.
No failover or model substitution occurs within an admitted command.

An accepted response must include the returned model and provider usage metadata.
OpenAI Decisions must supply its documented nonnegative token counts; malformed
metadata leaves the result uncertain rather than advancing the workflow.

If evaluation completion becomes unknown, inspection reports
`hold-after-dispatch` and refuses `retry-same` and reconciliation. Cancellation
sets `cancelRequested` while preserving `uncertain` and the attention state;
it cannot undo provider processing. A separately authorized new start can evaluate
again, with possible additional cost and a different answer. The
same conservative hold applies to HTTP 429, including temporary rate limits with
`Retry-After`: these bindings do not automatically resend an evaluation. The
[decision example](examples/decision-follow-up/README.md) includes refusal and
unknown-result cases; terminal `needs-review` returns control to the caller and
does not create a resumable approval task.

Create separate migration and runtime PostgreSQL roles. The migration role owns
the dedicated schema. The runtime role must not own that schema, inherit
migration authority, create objects, or write activation/schema ledgers. Apply
checks effective authority, including indirect role membership. Use the runtime
role in `database.runtimeUrlRef`; only `apply` resolves `database.migrationUrlRef`.

`databaseId` is the deployment's durable logical identity. Keep it constant
through restarts, credential rotation and compatible package updates. An existing
identity mismatch refuses startup or apply. Use a distinct identity and namespace
for an independent deployment.

Supply 32 raw random bytes for each payload state key and the separate admission
key. Preserve the admission key for the deployment's lifetime; it determines the
spent-key namespace and cannot rotate with payload encryption. Set
`activeStateKey` to the writing key version in `deployment.stateKeys`. Each entry
holds a `keyRef`, for example
`stateKeys: {"1": {keyRef: secret:file/state-key-1}}`. Key versions are canonical
decimal integers from 1 through 4294967295; zero is never an active or retained version.
Offline checks reject invalid versions before resolving key material. To rotate
payload keys, add the new version and reference, retain every registered older
key, then explicitly apply
the deployment before restarting. Apply verifies existing key custody and
registers new versions; merely editing runtime configuration cannot change a
registered key or activate an unregistered version. Retain the registered old
read keys under backup custody. Keep keys and database backups under separate
custody. The audit key supplies keyed private references. `deployment.auditFile` must be
an absolute path writable by the service user, with durable storage and custody
appropriate for the institution.

The service listener uses the shared private listener/TLS policy. Use
`operator-controlled-upstream` behind your controlled TLS terminator. The
explicit `development-loopback` option binds only loopback and permits local
plaintext PostgreSQL. Institutional database connections use TLS with
`sslmode=require`; configure `database.trustedRootCertificateRef` for private roots.
Configure `observationAuthorization` only on task-bound Scheduling connections.
Other adapters do not consume that identity; offline validation refuses it there
instead of presenting an unused credential as part of recovery authority.
Downstream bindings use HTTPS, or explicit loopback HTTP for supervised local
fixtures. Token signing-key rotation preserves the registered downstream client
identity, endpoint, audience, resource, scopes and approved task authority.

Caller policies list exact admitted OAuth clients, required scopes, allowed flow
identifiers and actions. Each verified client resolves one policy. Ownership and
admission idempotency come from the token's exact verified `iss` and `sub`, never
input fields. Operator policies explicitly grant recovery or diagnostics actions.
Do not give institutional producers operator authority. A task-exchanged inbound
token also requires the matching declared assertion issuer for that client.

## Apply and start

```sh
coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml plan
coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml apply
coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml deployment-status
coordinator --runtime-config /etc/registry-coordinator/runtime.yaml
```

`plan` reports the configured package and observed activation/schema without
claiming deployment validity. `deployment-status` checks the pinned package,
database identity, supported migration ledger, effective split runtime role,
narrow control grants and retained live binding compatibility. The connected
PostgreSQL `current_user`, configured `runtimeRole` and activated runtime role
must agree. It uses runtime credentials only, never migration
credentials, and does not migrate, activate or change recovery holds. JSON output
returns `status: checked`, `databaseId`, `packageDigest`, `schemaVersion`,
`runtimeRole` and the checked `active` activation. Refused checks exit nonzero
with `deployment.refused` for deployment-contract refusals or
`live-binding-conflict` for incompatible retained bindings, with operator recovery
advice. This report does not
replace the service's audit and recovery readiness checks.

Startup verifies package closure, checksum pin, executable ABI, active package,
database identity, schema, effective runtime role and configured state/audit
secrets before serving. Startup checks retained live definitions under the
admission lock before opening
the normal listener. Endpoint, registered identity, scopes and task authority
must retain each live run's original binding. New admissions repeat that check
inside their insertion transaction; worker polls keep their per-job fences
without rescanning history every poll. Restore the original bindings or use
`coordinator --runtime-config FILE --recovery-only` to investigate with dispatch
and admissions disabled. Recovery-only still verifies the active package,
database, schema, role and custody, and its readiness remains false.

Startup does not migrate or activate. `/health` means the
process answers. Every `/ready` probe checks mutable schema, activation, role,
state-key custody, audit and recovery holds. The retained live-binding scan is
coalesced and cached for 30 seconds, including failures; a cache miss still waits
for that scan, so the cache bounds frequency rather than latency. Startup,
explicit deployment status, admissions and worker transactions retain their
fresh authoritative checks. Keep health endpoints on the private service listener.

Apply serializes activation with database locks, migrates the dedicated schema,
grants the runtime role, and records the verified package in the shared ledger.
A refused incompatible live binding must be resolved by restoring the previous
binding or finishing/reconciling affected work. Compatible definitions govern new
admissions while old runs keep their encrypted snapshots and command identities.
Adding an unrelated logical connection does not change a workflow binding digest.
Reusing an admission key returns the original run rather than creating new work.

## Admit and inspect work

Acquire a current audience-bound access token from your institutional issuer.
Keep it in an owner-readable file; pass its path, never its value, to the CLI.
Use a stable key file for one logical admission and retain it through recovery.
Create a synthetic delayed-follow-up input using an application UUID present in
your approved registry; `sendAfter` is an RFC 3339 time within the workflow deadline.

```sh
umask 077
python3 -c 'import uuid; print(uuid.uuid4())' > ./start-key
cat > ./input.json <<'JSON'
{"applicationId":"00000000-0000-0000-0000-000000000001","sendAfter":"<RFC3339_TIME>"}
JSON
coordinatorctl --url https://coordinator.example.org --token-file /run/producer-token \
  start --flow delayed-follow-up --input ./input.json --key-file ./start-key
coordinatorctl --url https://coordinator.example.org --token-file /run/producer-token \
  status --run RUN_UUID
coordinatorctl --url https://coordinator.example.org --token-file /run/operator-token \
  inspect --run RUN_UUID
```

`start` sends `{ "flow": "delayed-follow-up", "input": ... }` to `POST /v1/runs`
with `Idempotency-Key`. Status and list show authorized progress and the reviewed
terminal projection. Inspection shows bounded durable step state. It never
returns original inputs, raw product responses or prepared command payloads.

Inspection includes `recovery.operation` for a compatible current call, with its
pinned ID, version, product, effect, key/preparation requirements, recovery and
`readReceipt` capability. When inspection can otherwise proceed, it omits the
field if no compatible current call is available, including pure steps, erased
payloads or incompatible snapshots. An unresolved original binding can still
refuse inspection. BReg action invocation declares `same-command` recovery
and `readReceipt: false`. `retryAllowed` and `reason` describe scheduling
eligibility; neither the descriptor nor that eligibility proves current product
authority or the existence of an original-key receipt.

One deployment admits one active flow definition; retained runs keep their
original definitions. The list endpoint returns the latest caller-owned runs
with a default `limit` of 20 and a maximum of 100, without pagination. Use the
authenticated HTTP API for application integration; `@registrystack/client`
does not yet export a Coordinator client.

Settled terminal history remains inspectable with its recorded binding identity
after an old connection is retired. This requires no runnable/uncertain job or
outstanding restore review; a failed label alone does not qualify. Unresolved
and recoverable work still requires its original configured connections.

The authenticated operator surface also exposes `doctor`, `cancel`, `reconcile`,
`retry-same`, `restore-hold`, `release-restore-hold`,
`release-admission-hold`, `complete-execution-recovery` and `retain`. Use the command's
`--help` for its exact arguments. Supply a bounded investigation reference such
as `incident-2026-10-09`; reasons must not contain personal data. The audit request
records a keyed `reasonRef`, scoped to the logical database and shared across
recovery actions. Raw investigation references stay outside the audit stream;
operators retain the external investigation record. Authenticated,
authorized requests with an empty, overlong or control-character reason, or an
out-of-bounds retention cutoff/limit, return HTTP 400. State and recovery
conflicts return HTTP 409. Recovery POSTs authenticate and authorize before
releasing malformed-body errors. They require `application/json` or an
application media type ending in `+json`; unsupported or absent media types return
415 only after authorization. Bodies remain bounded to 65,536 bytes and duplicate
or unknown fields are refused. Doctor exposes
state counts, aged work, uncertain effects, eligible terminal payload counts and
oldest terminal payload time, hold and audit readiness without
personal labels or payload values.

## Recover safely

Inspect before retrying. For Messaging and Scheduling, `reconcile` asks the
receiving product for authoritative evidence of the stored command using its
original key and owner. Missing or expired receipts and an unavailable receiver
do not prove absence. `retry-same`
uses the durable original body, key, binding and authority only when the receiver's
recovery contract and original deadline permit it. A fresh start key is a fresh
operation, so it is never a recovery procedure.

BReg action invocation has no read-only action receipt. `reconcile` therefore
leaves an uncertain action unresolved. Do not infer success or absence from an
ordinary record read. Same-command retry retains the saved client preparation,
conditional ETags and key, and checks current metadata and fresh authority before
dispatch. A changed contract, denied authority or stale condition safely stops
the call rather than refreshing its command. Preparation does not mutate BReg;
cancellation, restore holds and the original workflow deadline still fence
dispatch. Task-bound operations retain their original approval deadline too.

If a product call succeeds but the following wait mapping is invalid, the run
reports `failed` with `mapping-invalid` while retaining that call's successful
output and delivered job. `retry-same` cannot repeat the accepted call. Inspect
the existing effect before planning any new run with a corrected workflow
version. Settled failure payloads follow the same explicit retention policy;
recoverable failed jobs and uncertain effects remain protected.

Scheduling connections with `authorization.taskAuthority` require
`observationAuthorization` with ordinary receipt-read scopes and no
`taskAuthority`. Configure the same token endpoint, registered client and
resource as the mutation authorization. Scheduling requires the verified
issuer and subject to match the original receipt owner. This read credential
must work independently of the original grant's expiry or revocation. Recovery
never requests a Casework assertion or exchanges a task token; unavailable read
authority leaves the effect unresolved. Observation credentials never authorize
Coordinator dispatch.

Cancellation prevents future dispatch where possible. It does not roll back an
appointment, governed action or message the receiving product accepted.
Unresolved external effects remain uncertain until authoritative observation resolves them. Restore
the original downstream binding if configuration drift blocks recovery. Rotate
key material under the same registered identity rather than changing the identity.

`retain --before TIMESTAMP --limit N` erases eligible terminal payloads while
preserving bounded receipts/tombstones for spent start and command identities.
It does not erase live or uncertain work. Select the cutoff from your institution's
approved retention policy. Removing state keys before retained ciphertext is
erased makes that state unreadable and prevents safe execution or disclosure.

## Backup and restore

Back up PostgreSQL, all still-needed state-key versions, the stable admission
key, audit key, durable audit stream and the exact immutable packages. Preserve
custody records and test their restore procedure. Never restore only the database
and manufacture replacement keys. A backup can predate a downstream effect.

Before restoring, stop or externally fence the old service and all workers,
including replicas using the same database or credentials. Do not start an
ordinary worker on the restored database. Activate recovery hold through the
authenticated operator surface first, using an operator-controlled maintenance
instance started with `coordinator --recovery-only --runtime-config FILE`. This mode serves authenticated recovery operations and never runs worker dispatch. Inspect and reconcile every command that may
have been sent after the backup, using the receiving product's original-key
receipt APIs. Receipt expiry limits what can be established: hold unresolved work
and consult the authoritative product records, never infer non-existence.

Record the external fencing and reconciliation evidence before
`release-restore-hold`. Release is an accountable operator action; it cannot
itself prove another deployment has been fenced. Resume ordinary dispatch only
after that evidence has been reviewed. Preserve the original admission key and
command identities to avoid turning a restored history gap into a fresh effect.

Restore hold also persists a separate admission hold. Releasing worker recovery
hold does not reopen ingress. An older backup can omit entire admissions, so
reconciling the runs it contains does not prove that replaying an omitted start
key is safe. Keep admissions held until complete PITR/WAL recovery or separately
retained authoritative admission evidence establishes the full spent-key history.
An incomplete backup must remain closed to new admissions.

Only after execution hold is released, complete admission history is established,
and the previous deployment is externally fenced may an explicitly authorized
operator run `release-admission-hold --recovery-reference REFERENCE
--admission-history-complete --prior-deployment-fenced`. These flags are audited
operator attestations, not automated proof. Keep the supporting evidence under
institutional custody. False or omitted attestations refuse release.

Execution recovery also tracks every unfinished restored run, including rows
whose commands had not yet been prepared at the backup point. Those rows may
have progressed externally after the backup. Hold release refuses until each
review mark is resolved by a final authoritative receipt with no later external
call, or complete execution history and prior fencing are explicitly attested.
Do not cancel a restored run to erase its unresolved external-effect history.

A cancelled uncertain evaluation can be abandoned without blocking unrelated
work forever. Once its active lease has ended, complete execution recovery can
clear its restore review after validating the protected definition and prepared
request. Hold release checks those conditions again. `cancelRequested: true`
and `uncertain: true` remain visible; the request, unknown outcome and spent
start identity remain retained, and the run can never resume or replay. This
exception applies only to evaluations with `hold-after-dispatch` recovery.
Unknown product mutations still require their original recovery procedure.

When complete PITR/WAL or separately retained authoritative execution evidence
establishes that history, an operator may use `complete-execution-recovery
--recovery-reference REFERENCE --execution-history-complete
--prior-deployment-fenced` while execution hold remains. This audited attestation
clears execution review marks for resolved work. In that same locked transaction,
it can settle safe expired reads and local steps into held failed work after
validating their original protected definition and any prepared command. A call that never
prepared its command can also be held this way, only with complete recovered
history: command preparation always precedes sending. The same rules apply to
safe work already held after a lease lapsed, with no uncertain effect or active
lease. It preserves the original command and deadline, invalidates stale worker
completions, and starts no work. Prepared mutating commands left pending after
a definite retryable response are also held as failed work for an explicit
`retry-same` or cancellation, with their original command, key and deadline.
Schema revision 3 introduced these command-free holds without inventing an
attempt. The current schema revision 4 also adopts the shared Dispatch state
spelling. Stop old workers and explicitly run `coordinatorctl apply` to upgrade
revision 2 or 3 before serving; runtime startup does not migrate them. Apply
preserves stored identities, protected payloads and hold state. Earlier
Coordinator executables refuse the upgraded control revision.

Pending calls that have not prepared a command, and pending waits or local
steps also become held failed work. Attestation and
hold release never start these steps automatically. Prepared safe-read retries
keep their ordinary pending behavior. Explicitly retry a held wait to restore
its original scheduled instant atomically; a future wait does not advance early.
Active leases, prepared mutating leased or unknown calls, uncertain outcomes
and expired receipts remain protected. The cancelled-evaluation exception above
allows hold release without resolving or discarding the unknown outcome.
Recovery does not establish an external
outcome for any of these calls.
Prepared evaluations restored before recorded dispatch intent also retain the
conservative hold; the abandonment exception requires recorded uncertainty.

After `release-restore-hold`, inspect safe settled work and use `retry-same`
only when its original deadline permits it, or cancel and retain it when no
further execution is appropriate. Calls and waits retain their original
deadline; local `choose` and `finish` steps can complete under their existing
semantics. If an active lease later lapses, repeat complete execution recovery
only when the history and fencing attestations still hold. Releasing the
hold also requires repeated recovery if a previously active attempt returns a
definite retryable result after the first attestation. That prepared mutation
remains review-required until it is held for the explicit retry or cancellation.
Releasing the execution hold does not reopen admission or remove its separate
history requirement.

### Rehearse in disposable databases

Contributors can run the maintained older-backup rehearsal against two distinct,
disposable local databases. The rehearsal creates random Coordinator and Messaging
namespaces, takes an actual PostgreSQL backup before command preparation, accepts
one real Messaging submission, fences the previous worker, and restores the older
Coordinator namespace. The restored deployment must remain held and produce no
second effect when the backup lacks the later execution and admission history.

Use `pg_dump` and `psql` from the same PostgreSQL major version as the test server.
Do not point either test variable at institutional data or the runtime database.

```sh
export COORDINATOR_TEST_DATABASE_URL='postgresql://<test-role>@127.0.0.1:5432/coordinator_restore_test'
export COORDINATOR_MESSAGING_TEST_DATABASE_URL='postgresql://<test-role>@127.0.0.1:5432/messaging_restore_test'
export COORDINATOR_PG_DUMP=/absolute/path/to/pg_dump
export COORDINATOR_PSQL=/absolute/path/to/psql
products/coordinator/scripts/test-restore.sh
```

A passing rehearsal proves this controlled older-backup boundary. Your institution
still needs its own backup custody, complete history recovery, and external
fencing evidence before reopening a restored deployment.
