# Deploy Registry Coordinator

You operate one Coordinator service beside PostgreSQL 17 or newer and the
institution's existing OIDC issuer. Receiving Registry Stack products still
verify their own caller and task authority. Coordinator runs finite reviewed
workflow packages, one per workflow, and preserves every admitted run's original
definition.

## Deployment checklist

Do these tasks in order. Each one links to the section with the details.

1. [Install the binaries and build each workflow's package](#install-and-package).
   Record the package digest that `package` prints.

   ```sh
   coordinatorctl package --project ./follow-up --output ./follow-up-package
   ```

2. [Create the keys and secrets](#create-the-keys-and-secrets) as the service
   user: the payload state key, the admission key, the audit key and the two
   database URLs.

   ```sh
   (umask 077 && openssl rand -out /run/registry-coordinator/secrets/state-key-1 32)
   ```

3. [Create the database and roles](#create-the-database-and-roles) as a
   PostgreSQL administrator, with the SQL in that section.

4. [Write the runtime file](#configure-the-deployment), pin each package digest
   in `deployment.packages`, and check the file offline.

   ```sh
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml check
   ```

5. [Apply the deployment](#apply-and-start) with the migration credential, then
   check it with the runtime credential. `plan` and `apply` verify each pinned
   package.

   ```sh
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml plan
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml apply
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml deployment-status
   ```

6. [Start the service](#apply-and-start) under your supervisor. The service
   takes the absolute path of the runtime file.

   ```sh
   coordinator --runtime-config /etc/registry-coordinator/runtime.yaml
   ```

7. [Check health and run doctor](#check-health-and-run-doctor) with an operator
   token.

   ```sh
   curl -fsS http://127.0.0.1:8108/health
   curl -fsS http://127.0.0.1:8108/ready
   coordinatorctl doctor --url https://coordinator.example.org --token-file /run/operator-token
   ```

8. [Scrape the metrics listener](#watch-metrics) from your monitoring.

   ```sh
   curl -fsS http://127.0.0.1:9108/metrics
   ```

## Install and package

Starting with v0.44.0, release packaging includes `coordinator` and
`coordinatorctl` for Linux amd64, Linux arm64 and macOS arm64. Once that release
is published, install both using its checksum-verifying installer:

```sh
curl -fsSL https://github.com/registrystack/registry-stack/releases/download/v0.44.0/coordinator-v0.44.0-install.sh | bash
```

The installer keeps macOS FIPS libraries beside their executables. The binary
release does not imply that the Coordinator container image has been released;
its image-specific security evidence remains a separate gate.

Build the two local binaries from the maintained checkout. On Linux, install the
completed binaries in a service-owned executable directory:

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
MACOSX_DEPLOYMENT_TARGET=11.0 CARGO_TARGET_DIR=target/coordinator-install \
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
    --binary "target/coordinator-install/release/$binary" \
    --asset-name "$binary-macos-arm64" --library-root "$COORDINATOR_FIPS_ROOT" \
    --notice THIRD_PARTY_NOTICES --output "./$binary.tar.gz"
  python3 release/scripts/macos_fips_packaging.py extract \
    --archive "./$binary.tar.gz" --destination "./$binary-install" \
    --expected-executable "$binary-macos-arm64"
done
./coordinatorctl-install/coordinatorctl-macos-arm64 --help
./coordinator-install/coordinator-macos-arm64 --help
mkdir -p "$HOME/.local/bin"
ln -s "$PWD/coordinator-install/coordinator-macos-arm64" "$HOME/.local/bin/coordinator"
ln -s "$PWD/coordinatorctl-install/coordinatorctl-macos-arm64" "$HOME/.local/bin/coordinatorctl"
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
When the project has a `scenarios.yaml`, `package` runs it first and writes
nothing unless every case passes.
Install the directory read-only, record the returned package digest, and pin it
as that workflow's `deployment.packages` entry, with `root` and `expectedDigest`.
[Package digest and definition digest](#package-digest-and-definition-digest)
explains which of the two digests to pin.
One project is one workflow and one package; its workflow ID is the workflow name
callers start. A deployment lists one pinned package per workflow, up to sixteen.
Offline checks and startup refuse an empty list, a package root or digest
listed twice, and two packages with the same workflow ID, each naming the entry
to fix. [two-flow-runtime.yaml](examples/two-flow-runtime.yaml) serves the
delayed follow-up and governed action examples from one deployment. Runtime files, endpoints, credentials,
state keys and audit custody are deployment configuration, outside the package.
Existing output is never overwritten. Build a fresh directory for each update.
Use `coordinatorctl test --project DIR` for projects with `scenarios.yaml`.
The human `project.version` is a display label. A semantic change produces a new
`workflowRevision`; activating its package does not replace existing runs' snapshots.
Retain the keys needed to read those snapshots and the custody metadata needed for recovery.

### Package digest and definition digest

Pin the package digest for exact bytes; use `workflowRevision` for execution semantics.

- The computed Workflow revision hashes the input, graph, outcomes, used Operation and Function
  revisions, and host execution contracts. Presentation titles and descriptions do not change it.
  `check` prints this revision on its `Definition:` line. Start, status, list, and inspect report it
  as `workflowRevision`. Existing runs keep their admitted revision.
- The package digest is the SHA-256 of `SHA256SUMS`. That file covers the exact `definition.json`
  snapshot bytes, including presentation metadata. `package` prints the digest; `plan` reports
  listed `packageDigest` and `activePackageDigest`; `deployment-status` reports package pins under
  `workflows`.

Put the package digest in `expectedDigest`. `plan`, `apply` and startup check
the installed directory against it and refuse a package whose content no
longer matches with `coordinator.deployment.refused` and the advice to restore
the exact pinned package. `workflowsDigest` identifies the whole set of pinned
packages; the `active` activation record in `plan`, `apply` and
`deployment-status` carries that set digest in its `packageDigest` field.
New starts must name the active `workflowRevision`. A caller recovering an unknown
admission must send the exact original start key, input, and revision, even after a
new package is activated. The original run keeps its admitted snapshot and revision.
`plan` and `apply` also check current live-run connection bindings and refuse removal
of a workflow whose runs could still act or need review; work admitted after `plan`
can therefore make `apply` refuse.

## Create the keys and secrets

Create every secret as the user that runs `coordinator` and `coordinatorctl`.
A `secret:file/NAME` reference reads the file `NAME` directly under the file
provider's `root`. That file must be a regular file owned by that user, with
mode `0400` or `0600` and exactly one link. A `secret:env/NAME` reference reads
an environment variable when `secretProviders` declares `environment: {}`.

Coordinator uses three kinds of key. Each one is exactly 32 raw random bytes
in its own file:

- A payload state key encrypts the run state held in PostgreSQL.
  `deployment.stateKeys` lists its versions and `activeStateKey` names the
  version that writes.
- The admission key derives start identities, owner hashes and command keys,
  so it determines the spent-key namespace. It stays the same for the
  deployment's lifetime, and it must differ from every state key.
- The audit key derives the keyed private references in the audit journal.

Create the secret directory and the three key files:

```sh
install -d -m 0700 /run/registry-coordinator/secrets
(umask 077 && openssl rand -out /run/registry-coordinator/secrets/state-key-1 32)
(umask 077 && openssl rand -out /run/registry-coordinator/secrets/admission-key 32)
(umask 077 && openssl rand -out /run/registry-coordinator/secrets/audit-key 32)
```

Reference them from the runtime file:

```yaml
deployment:
  auditKeyRef: secret:file/audit-key
  activeStateKey: 1
  stateKeys:
    "1":
      keyRef: secret:file/state-key-1
  admissionKeyRef: secret:file/admission-key
```

Key versions are canonical decimal integers from 1 through 4294967295; zero is
never an active or retained version, and a deployment lists at most 16 versions.
Offline checks reject invalid versions before resolving key material. Keep keys
and database backups under separate custody. [Rotate and replace
keys](#rotate-and-replace-keys) gives the procedure for each key.

The database URLs are secrets too. `database.runtimeUrlRef` names the runtime
role's URL and `database.migrationUrlRef` the migration role's URL; only
`apply` resolves the migration URL. Institutional connections use
`sslmode=require`:

Enter each URL at a hidden prompt, so its password stays out of shell history. Use a
URL such as `postgresql://coordinator_runtime:...@db.example.org:5432/coordinator?sslmode=require`.
This writes new owner-only files and refuses to overwrite existing secrets:

```sh
python3 - <<'PYTHON'
import getpass
import os
from pathlib import Path

root = Path('/run/registry-coordinator/secrets')
for name in ('runtime-database-url', 'migration-database-url'):
    value = getpass.getpass(f'{name}: ')
    if not value:
        raise SystemExit('A database URL is required')
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as secret:
        secret.write(value)
PYTHON
```

```yaml
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
```

[single-flow-runtime.yaml](examples/single-flow-runtime.yaml) reads the same
two URLs from environment variables instead.

Write each connection credential the runtime file names the same way, such as
the signing key an `authorization.signingKeyRef` names. Secret values never
appear in a diagnostic or a log.

A Casework connection that receives completion events names a bearer token
that Casework presents to the Coordinator. Generate it as visible ASCII, for
example 32 random bytes in hexadecimal, and give Casework the same value under
its own secret reference:

```sh
(umask 077 && openssl rand -hex 32 > /run/registry-coordinator/secrets/review-completion-token)
```

## Create the database and roles

Use PostgreSQL 17 or newer; apply and startup refuse an older server. As a
PostgreSQL administrator, create the migration role, the runtime role and the
database, and let only those two roles connect:

```sql
CREATE ROLE coordinator_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOBYPASSRLS PASSWORD '<migration-password>';
CREATE ROLE coordinator_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOBYPASSRLS PASSWORD '<runtime-password>';
CREATE DATABASE coordinator;
REVOKE ALL ON DATABASE coordinator FROM PUBLIC;
GRANT CONNECT ON DATABASE coordinator TO coordinator_migration, coordinator_runtime;
GRANT CREATE ON DATABASE coordinator TO coordinator_migration;
```

These are the only grants you make. The migration role needs `CREATE` on the
database because `apply` creates the schema the runtime file's `namespace`
names, and the migration role owns that schema and its tables. A namespace
starts with `coordinator_` and is at most 60 characters. The runtime role
needs only `CONNECT`: `apply` grants it, in that schema, `USAGE` on the
schema, `SELECT`, `INSERT`, `UPDATE` and `DELETE` on `runs`, `jobs`,
`admission_lock` and `completion_waits`, `SELECT` on `control`, `coordinator_activations` and
`coordinator_migrations`, and `UPDATE` on the four recovery-hold columns of
`control`.

`apply`, `deployment-status` and startup check the runtime role's effective
authority, including indirect role membership. They refuse a runtime role that
is a superuser, bypasses row-level security, belongs to the migration role,
can create objects in the schema, holds `TRIGGER`, or owns objects there. Keep
the runtime role out of the migration role. Use the runtime role in
`database.runtimeUrlRef` and set `deployment.runtimeRole` to its name.

Each service process keeps a fixed pool of at most 32 sessions as the runtime
role, so allow 32 connections per process in the role's connection limit and the
server's `max_connections`.

## Configure the deployment

Runtime files use the `id.registrystack.org/formats/coordinator/runtime/v1alpha1`
`apiVersion` and `CoordinatorRuntimeConfig` kind. The shared runtime reader
checks the envelope, YAML structure and positioned diagnostics before deployment
values. Offline checking reads no credentials and contacts no endpoint.

Keep the project runtime's `secretProviders`, `database.runtimeUrlRef`, `namespace` and
logical `connections`. Add the `deployment` block shown in
[single-flow-runtime.yaml](examples/single-flow-runtime.yaml), adapting the paths, identity,
issuer and caller policy. The example contains references only. Provision each
secret separately through its enabled shared provider.

The shared `jwksSource` block selects its variant with `type`, for example
`type: discovery`. Key `authentication.policies` by exact verified client identity.
Each entry declares required scopes, actions, and permitted `workflows` for run actions.
The policy keys are the admitted client set. Coordinator reads scopes from `registry_scopes`;
set `scopeClaim: scope` when the issuer uses the standard `scope` claim.

For `breg.invoke-action/v1`, configure a Base Registry Engine (BReg) connection with
an ordinary service `authorization` and an explicitly permitted `profile`. Do not configure
`authorization.taskAuthority` on that connection: this operation accepts no
Casework grant and has no task-authority fallback. Keep a task-bound record-read
connection separate when the workflow needs both authority types.

The BReg Proposal operations use the same connection type. In the BReg project, grant the
connection's profile `get` on every Action a workflow follows, under `permissions.proposals`.
Where the workflow starts or submits requests itself, also grant `start` on the Action under
`permissions.actions`, and `cancel`, plus `submit` when the workflow submits, under
`permissions.proposals` with `ownership: caller`. Leave `writableInputs` off that Proposal grant,
or list every input the workflow sends: with the list, Start refuses a value for any other input.
Never grant `apply`: no Coordinator operation applies a Proposal. Two optional members serve
those waits:

```yaml
connections:
  licences:
    type: breg
    baseUrl: https://licences.example.org
    profile: coordinator-follow
    authorization: {...}
    resultCheckSeconds: 300
    requestLink: https://staff.example.org/proposals/{proposalId}
```

`resultCheckSeconds`, from 60 to 86,400 and 900 by default, spaces the Proposal reads of a
waiting run; each read is one request to BReg per waiting run. `requestLink` is an `https`
template with exactly one `{proposalId}`, or `http` on a loopback IP address such as
`127.0.0.1` for a local staff app; inspection shows it as "Open the request". Neither is
part of a live run's binding, so you can change both while runs wait. A missing `get` grant
shows on the waiting run as the hold `proposal-unreadable`; a missing `start` or `submit` grant
shows as BReg's refusal of that step.

Use one `connections` map for all logical connections. Each entry selects its complete
contract with `type`: `breg`, `casework-review-producer`, `messaging`, `scheduling`,
`external-http`, or `evaluation`. Declare at most sixteen names.

For `external.get/v1`, use `type: external-http` with `baseUrl`, exact `paths`, optional
`queryParameters`, optional ordinary service `authorization`, and the required `responseSchema`
for `{status, body}`. Omitted authorization means a public read. Attempt timeout defaults to
2000 milliseconds and response size to 65,536 bytes; both can be reduced. Use HTTPS for
institutional endpoints; HTTP requires numeric loopback.

For `external.command/v1`, add `commandPath` to an `external-http` connection: the one exact
relative path, resolved against `baseUrl`, that the command may POST to. The command uses the
connection's `authorization`, `responseSchema`, attempt timeout and response size bound, and its
request body is limited to 65,536 bytes. The attempt timeout also covers DNS resolution and token
acquisition, so a slow token endpoint leaves less time for the answer and makes a timeout after
the send, which holds the run as uncertain, more likely. Omit `commandPath` to keep a connection
read-only; `paths` still lists at least one read path. Use a separate connection when commands
need a different credential or scope than reads.

```yaml
connections:
  payments:
    type: external-http
    baseUrl: https://payments.example.org/v1/
    paths: [bills/status]
    commandPath: bills
    authorization:
      tokenEndpoint: https://issuer.example.org/oauth/token
      clientId: coordinator-payments
      signingKeyRef: secret:file/payments-jwk
      resource: https://payments.example.org
      scopes: [bills:create]
    responseSchema:
      type: object
      required: [status, body]
      properties:
        status: {type: integer}
```

The provider must deduplicate on the `Idempotency-Key` header. A repeated key must return the
original result and never apply the command twice, for at least as long as a run can be held and
retried, which is until its deadline. Coordinator sends the same key on every attempt of a step,
including after a restart and `retry-same`. A provider that cannot deduplicate is not safe for
same-command recovery: do not use `retry-same` with it, and resolve a held run from the
provider's own records. Coordinator trusts a 429 to mean the provider did not process the
command, so the provider must never answer 429 after applying it.

For `evaluation.evaluate/v1`, use `type: evaluation` with protocol `system-one` or
`openai-decisions`, `baseUrl`, `model`, and either `authorization.bearer` (`tokenRef` and stable
account `principal`) or explicit `authorization.local: {}` on numeric loopback. Request and
response limits default to 65,536 bytes and the attempt limit to 8000 milliseconds. Rotate
credentials under the same provider account and binding.

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

For `casework.submit-review-request/v1` and `casework.cancel-review-request/v1`, configure a Casework
connection as one of Casework's review producers. `profile` names the Casework
access profile the producer's client is admitted to, `producer` names the
producer's `id` in the Casework project's `trustedProducers`, and the ordinary
service `authorization` obtains a token whose issuer and subject are the ones
that producer declares. Do not configure `authorization.taskAuthority`: a
review producer acts under its own identity, and check refuses a task
authority on a Casework connection. Configure one connection for each producer.
A `wait-for` step reads the result through the same connection, with the same
producer authorization.

Add a `completion` block when Casework should wake a waiting run as soon as a
review completes:

```yaml
connections:
  review:
    type: casework-review-producer
    baseUrl: https://casework.example.org
    profile: coordinator-producer
    producer: coordinator
    authorization:
      tokenEndpoint: https://issuer.example.org/oauth/token
      clientId: coordinator-review-producer
      signingKeyRef: secret:file/review-jwk
      resource: urn:example:casework
      scopes: [casework:review]
    completion:
      recipientBinding: coordinator-v1
      bearerTokenRef: secret:file/review-completion-token
    resultCheckSeconds: 900
```

The Coordinator then accepts Casework's completion events at
`POST /v1/review-completions` on the service listener. It finds the connection
by the `Authorization: Bearer` token and the `registry-recipient-binding`
header together, comparing the token in constant time, and refuses any other
sender with HTTP 401 `authentication.refused` before reading the body. `recipientBinding` is 1 to 256
visible ASCII characters and differs between Casework connections. An
authenticated event must be `application/json`, at most 2048 bytes, name
non-nil identifiers, repeat its `eventId` as the `idempotency-key` header and
carry a `completedAt` no older than 365 days and no more than 5 minutes ahead
of the Coordinator's clock; anything else answers HTTP 400 `request.invalid`
or 415 `request.unsupported-media-type`. Every
authentic event answers HTTP 204, whether or not a run waits on its request,
and an event only brings forward the next result read of a run that does.
HTTP 503 `service.unavailable` asks Casework to deliver it again. Without a
`completion` block the route refuses every event, and waits rely on result
checks alone.

`resultCheckSeconds`, from 60 to 86,400 and 900 by default, spaces the reads
of a waiting run when no event arrives. Lower it when completion events cannot
reach the Coordinator; each read is one request to Casework per waiting run.
A live run's binding includes `producer` but neither `completion` nor
`resultCheckSeconds`, so you can change either, or rotate the completion
token, while runs wait.

Select the Review policy by ID from the owning Casework project's compiled `policyBindings`
report. Casework binds its current concrete policy at first acceptance. If the Workflow requires
an exact policy, also copy both its compiled version and digest; a synthetic fixture digest is
not a deployable pin. Preserve the original selection and idempotency key when recovering work.
Submitted context uses `mode: submitted`; current-source context uses the owning policy's
`mode: current-source` and configured context provider. Review policy and trusted producer
configuration remain owned by Casework.

Configure the same producer on the Casework side. In the Casework project, the
producer's `completion` block names a destination and the same recipient
binding:

```yaml
trustedProducers:
  coordinator:
    profile: coordinator-producer
    issuer: https://issuer.example.org
    subject: coordinator-review-producer
    sourceNamespaces: [applications]
    reviewPolicies: [application-review]
    retention: {receiptRetentionDays: 7}
    completion:
      destinationId: coordinator
      recipientBinding: coordinator-v1
```

In the Casework runtime file, bind that destination to the Coordinator's route
and to Casework's own reference to the same token. Present it as a bearer
token with `bearerTokenRef` or `auth: {secretRef}`; the Coordinator accepts no
custom header. `attemptTimeoutMilliseconds`, `maximumAttempts` and
`retryDelaySeconds` bound Casework's delivery, as the Casework runtime
configuration describes:

```yaml
reviewCompletionDestinations:
  coordinator:
    url: https://coordinator.example.org/v1/review-completions
    bearerTokenRef: secret:file/coordinator-completion-token
```

The [reviewed notice example](examples/reviewed-notice/README.md) lists the
full set of Casework prerequisites for one review producer.

`databaseId` is the deployment's durable logical identity. Keep it constant
through restarts, credential rotation and compatible package updates. An existing
identity mismatch refuses startup or apply. Use a distinct identity and namespace
for an independent deployment.

`deployment.auditFile` must be an absolute path writable by the service user,
with durable storage and custody appropriate for the institution.

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

`deployment.metricsListener` is optional. When present, its `bind` is required
and `/metrics` is served on that socket only: the service listener has no
metrics route and the OpenAPI document lists none. When absent, no metrics are
served. The address must be a concrete loopback or private address on a
nonzero port, and must not be the service listener's socket or one a wildcard
service listener already covers; the configuration check refuses any other
bind at `/deployment/metricsListener/bind`. The key and its address rule are
the ones Registry Messaging uses.

```yaml
deployment:
  metricsListener:
    bind: 127.0.0.1:9108
```

[Watch metrics](#watch-metrics) lists the series it serves.

Caller policies list exact admitted OAuth clients, required scopes, actions and,
for run actions, allowed workflow identifiers. Each verified client resolves one
policy. Ownership and admission idempotency come from the token's exact verified
`iss` and `sub`, never input fields. The run actions `start`, `status`,
`inspect`, `retry-same`, `cancel` and `reconcile` reach only the workflows the policy
lists in `workflows`, which is required when the policy lists any of them. The
deployment-wide actions `doctor`, `restore-hold`, `release-restore-hold`,
`release-admission-hold`, `complete-execution-recovery` and `retain` act on every
workflow at once, including workflows added later, and need `operator: true` on the
policy. They take no workflow list: a policy that lists only deployment-wide actions
omits `workflows`, and the configuration check refuses one that sets it.
Do not give institutional producers operator authority. A task-exchanged inbound
token also requires the matching declared assertion issuer for that client.

## Apply and start

```sh
coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml plan
coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml apply
coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml deployment-status
coordinator --runtime-config /etc/registry-coordinator/runtime.yaml
```

`plan` reports, for each workflow, whether apply would `install`, `replace`,
leave `unchanged` or `remove` its package, with the configured and active
package digests, the `workflowsDigest` of the listed set and the observed
activation/schema, without claiming deployment validity. `deployment-status` checks the pinned packages,
database identity, supported migration ledger, effective split runtime role,
narrow control grants and retained live binding compatibility. The connected
PostgreSQL `current_user`, configured `runtimeRole` and activated runtime role
must agree. It uses runtime credentials only, never migration
credentials, and does not migrate, activate or change recovery holds. JSON output
returns `status: checked`, `databaseId`, `workflowsDigest`, `workflows` (each workflow's
package digest), `schemaVersion`,
`runtimeRole` and the checked `active` activation. Refused checks exit nonzero
with `coordinator.deployment.refused` for deployment-contract refusals or
`coordinator.command.live-binding-conflict` for incompatible retained bindings, with operator recovery
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

The service writes JSON lines to standard error at the `info` level. A worker
poll that fails does not stop the service: it logs a warning with the failure
code, pauses, and repeats the full deployment check before it polls again. The
pause starts at 1 second and doubles up to 30 seconds while failures continue.
When that check cannot open a database connection, the worker polls nothing,
logs `store-unavailable` with the fix `restore database connectivity`, and
waits out the outage; meanwhile `/ready` answers 503 and admissions answer 503
`service.unavailable`. The periodic deployment check in recovery-only mode
waits out an unreachable database the same way. Any other refusal stops the
service with exit status 1 and its code and fix on standard error:
`deployment.refused` for an activation moved by an apply, `state-key-custody`
for key custody that no longer matches what apply registered. The service logs
`worker loop resumed` once a poll succeeds again.

SIGTERM or SIGINT stops the service gracefully. The listener accepts no new
connection and finishes the requests it is answering; the worker leases no
further attempt and finishes the one in flight. Both get 15 seconds, the
10-second attempt timeout plus the 5-second lease finalization allowance; the
service then logs `stopped` and exits 0. Give the supervisor a stop timeout of
at least 15 seconds before it sends SIGKILL. An attempt still unfinished when
the 15 seconds end, or when the process is killed, keeps its lease until the
lease expires. A `read-again` call then resumes on the ordinary retry schedule
within its original attempt and deadline bounds. Any other step, including a
mutation, evaluation or same-command call, holds for operator review. Both
transitions retain the lease-lapse audit record, and a late completion from the
old worker is fenced out.

Apply serializes activation with database locks, migrates the dedicated schema,
grants the runtime role, records the verified set of packages in the shared
ledger and each workflow's active package in the control record.
A refused incompatible live binding must be resolved by restoring the previous
binding or finishing/reconciling affected work. Compatible definitions govern new
admissions while old runs keep their encrypted snapshots and command identities.
Adding an unrelated logical connection does not change a workflow binding digest.
Reusing an idempotency key returns the original run rather than creating new work.

This source version creates protected state schema version 5. Earlier protected
state layouts are refused: apply reports `coordinator.command.schema-version`, and runtime state
access, including `deployment-status`, fails closed as `coordinator.command.store-unavailable`.
Apply does not adopt or rewrite them. Settle retained work with its matching
binary, then create a fresh namespace and database identity for this version.
Keep the original keys, packages, and audit history until retention permits
erasure. This source compatibility boundary does not promise an in-place state
migration.

Startup does not migrate or activate. The service reads its runtime file from
an absolute path; `coordinatorctl` also accepts a path relative to the current
directory.

### Check health and run doctor

Probe the private service listener, then ask the service for its own report
with an operator token:

```sh
curl -fsS http://127.0.0.1:8108/health
curl -fsS http://127.0.0.1:8108/ready
coordinatorctl doctor --url https://coordinator.example.org --token-file /run/operator-token
```

`/health` answers `{"live":true}` while the process answers. `/ready` answers
`{"ready":true}`, or HTTP 503 with `{"ready":false}` while the service cannot
accept work. Every `/ready` probe checks mutable schema, activation, role,
state-key custody, audit and recovery holds. The retained live-binding scan is
coalesced and cached for 30 seconds, including failures; a cache miss still waits
for that scan, so the cache bounds frequency rather than latency. Startup,
explicit deployment status, admissions and worker transactions retain their
fresh authoritative checks. Keep health endpoints on the private service listener.

In the doctor report, `activationReady` and `state.auditReady` are `true` on a
serving deployment. `state.restoreHold` and `state.admissionsHold` are `false`
until an operator or a restore places a hold. `state.states` counts runs by
state, `state.uncertain` counts steps whose effect waits for an operator, and
`state.restoreReviewRequired` counts runs that need restore review.
`state.oldestDueAt` is the earliest next attempt of a pending step.
`state.terminalPayloads` counts the terminal payloads retention can erase, and
`state.oldestTerminalPayloadAt` is when the oldest of those runs ended.
`state.proposalWaitsByTurn` counts BReg Proposal waits by their last observed turn, with
`unobserved` for waits not yet read, from stored observations; doctor makes no BReg call.

### Add, upgrade, roll back and remove a workflow

Each workflow's package is applied on its own. One deployment is one trust domain,
so workflows that must not share connections run in separate deployments. To add a
workflow, list its pinned package; to upgrade or roll one back, change only that entry's `root` and
`expectedDigest` to the new or previous package. Apply reports each workflow's
change and leaves every other workflow's active package and runs untouched. Runs in
flight on a replaced workflow keep the definition they were admitted with; new
starts of that workflow use the replacement. Any apply that changes the listed set
fences services started under the previous set until they restart, so restart
every service after each apply.

Dropping an entry never retires a workflow by itself. Plan and apply refuse an
active workflow missing from the list with `coordinator.deployment.workflow-unlisted`
until it is listed again or named explicitly:

```sh
coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml plan --remove-workflow governed-action-follow-up
coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml apply --remove-workflow governed-action-follow-up
```

Removal is refused with `coordinator.deployment.workflow-live-runs` while the workflow
has a run that retention could not yet erase: running, waiting, uncertain,
recoverable or awaiting restore review. Let those runs settle or cancel them
first; removal, unlike replacement, leaves no definition to finish them under.
Naming a workflow that is still listed or not active is refused. A removed workflow's
terminal runs stay readable and inspectable, and starts naming it are refused.

## Watch metrics

Scrape the metrics listener from your monitoring:

```sh
curl -fsS http://127.0.0.1:9108/metrics
```

The metrics are Prometheus text (`text/plain; version=0.0.4`, served with
`Cache-Control: no-store`), and every label is closed:

| Series | Type | Labels |
|---|---|---|
| `coordinator_runs_admitted_total` | counter | none |
| `coordinator_runs_finished_total` | counter | `state`: `finished`, `failed`, `cancelled`, `cancelled-after-effect`, `expired` |
| `coordinator_step_attempts_total` | counter | `outcome`: `accepted`, `transient`, `permanent`, `maybe-sent`, `unavailable` |
| `coordinator_authentication_refusals_total` | counter | `reason`: `refused`, `policy`, `unavailable` |
| `coordinator_dispatch_jobs` | gauge | `state`: `pending`, `leased`, `unknown` |

Counters are per process: each service process starts them at zero and counts
only its own work, so a restart resets them. They expose every label value from
the first scrape. A run counts as admitted once its admission commits; a
repeated idempotency key returns the original run and counts nothing. A run counts
as finished each time a committed change moves it into a terminal state, whether
the worker, an operator action or `complete-execution-recovery` made the change.
A run that recovery, for example `reconcile`, moves from one terminal state to
another therefore counts under both states, and the `state` series can add up
to more than the number of runs that finished. Every step attempt the worker makes counts, local steps
included: `maybe-sent` is an attempt whose effect is uncertain and that waits
for an operator, `transient` also counts a `wait-for` read that failed and left
its wait open, and `unavailable` an attempt that ended in an internal error,
such as an unreadable store, before the step answered. An authentication
refusal is a bearer credential refused before a caller is resolved: `refused`
for a missing, malformed or unverified token, or a completion event without a
configured completion token and recipient binding, `policy` for a verified token no
caller policy admits, and `unavailable` when the token verifier cannot answer.
A resolved caller refused an action is not counted here.

`coordinator_dispatch_jobs` is read from the database on each scrape: `pending`
steps wait for their next attempt, `leased` steps are being attempted, and
`unknown` steps wait for an operator to settle an uncertain effect. The count
is a read-only query bounded at 2 seconds. When the database cannot answer,
that scrape has no `coordinator_dispatch_jobs` samples rather than zeros, and
the service logs a warning with the failure code. Alert on the gauge going
absent as well as on its value.

No label carries a workflow, run, input, principal or other caller text, and workflow
identifiers are deliberately not a label. A workflow is configuration, so labelling
by it would grow the series with every workflow added and keep series for workflows
removed; an attempt whose snapshot cannot be decoded has no trustworthy workflow to
label; and per-workflow and per-run detail already lives in the audit journal and in
`coordinatorctl status` and `inspect`. Log lines carry fixed messages and
failure codes, never tokens, run inputs, step outputs, command bodies or caller
text. Bind the metrics listener where only your monitoring can reach it: the
counts describe the deployment's traffic even though they name no caller.

## Admit and inspect work

Acquire a current audience-bound access token from your institutional issuer.
Keep it in an owner-readable file; pass its path, never its value, to the CLI.
Use a stable key file for one logical admission and retain it through recovery.
Create a synthetic delayed-follow-up input using an application UUID present in
your approved registry; `sendAfter` is an RFC 3339 time within the workflow deadline.

```sh
umask 077
python3 -c 'import uuid; print(uuid.uuid4())' > ./idempotency-key
coordinatorctl workflow --workflow delayed-follow-up \
  --url https://coordinator.example.org --token-file /run/producer-token
cat > ./input.json <<'JSON'
{"applicationId":"00000000-0000-0000-0000-000000000001","sendAfter":"<RFC3339_TIME>"}
JSON
coordinatorctl start --workflow delayed-follow-up --workflow-revision <workflow-revision> --input ./input.json --key-file ./idempotency-key \
  --url https://coordinator.example.org --token-file /run/producer-token
coordinatorctl status --run RUN_UUID \
  --url https://coordinator.example.org --token-file /run/producer-token
coordinatorctl inspect --run RUN_UUID \
  --url https://coordinator.example.org --token-file /run/operator-token
```

`start` sends `workflow`, expected `workflowRevision`, and `input` to `POST /v1/runs`
with the idempotency key as `Idempotency-Key`. Status and list show authorized
progress and the reviewed terminal projection. Inspection shows bounded durable
step state. It never returns original inputs, raw product responses or prepared
command payloads.

Inspection also reports accepted or unknown `effects` with pinned operation revisions, and
`waits` with completion revisions, deadlines, next observations, persistent floors, and count/limit.
A Proposal wait also shows `lastObservation` (state, turn, submission version, any hand-off
refusal code, when it was read and since when that state held, as first seen by Coordinator)
and its "Open the request" link. A hand-off refusal on a request a person submitted shows there
while the run keeps waiting; that person resubmits in BReg.
A run held with `in-force-ambiguous` names the two record identifiers and the date in the held
step's `holdDetail` until the step is retried. Proposal and record identifiers are opaque and
grant nothing without the owning product's grant.
Protected command and correlation values remain absent.

To read a waiting request now instead of at its next scheduled read, run:

```sh
coordinatorctl check-now --run RUN_UUID --step decided \
  --url https://coordinator.example.org --token-file /run/operator-token
```

It brings the next read forward, never closer than the read floor to the last one, and needs
only the `inspect` grant. Each read counts against the wait's budget, which is sized at the read
floor, so an early read never stops the wait reaching its timeout route. A step that is not
waiting answers 409 `check.not-waiting`.

Inspection includes `recovery.operation` for a compatible current call, with its
pinned ID, version, product, effect, key/preparation requirements, recovery and
`readReceipt` capability. When inspection can otherwise proceed, it omits the
field if no compatible current call is available, including pure steps, erased
payloads or incompatible snapshots. An unresolved original binding can still
refuse inspection. BReg action invocation declares `same-command` recovery
and `readReceipt: false`. `retryAllowed` and `reason` describe scheduling
eligibility; neither the descriptor nor that eligibility proves current product
authority or the existence of an original-key receipt.

Use the discovered `workflowRevision` in the start command. A fresh admission must match
that active revision. If admission is unknown, resend the original identity, key, revision, and
input, including after a package change. A mismatch on new work returns
`workflow.revision-mismatch`; conflicting key reuse returns `idempotency.key-reused`.

A start is admitted under the named workflow's active definition; retained runs
keep their original definitions. A caller whose policy does not list the workflow
is refused with HTTP 403 `operation.not-authorized`; an allowed workflow this
deployment does not serve is refused with HTTP 404 `workflow.not-served`. `GET /v1/runs` returns at
most 100 of the caller's most recently admitted runs, newest first, from the
workflows its policy lists; an operator policy lists every owner's runs in those
workflows. `limit` takes 1 to 100 and defaults to 20. Use `state` to filter by effective state, or `attention=true` for effective states
`attention` and `failed` (`attention=false` excludes both). Use `proposal=<id>` to find the runs
waiting on one BReg request, and `turn=party`, `official` or `nobody` for runs whose request
last read that turn. Pass `nextCursor` as
`cursor` with the same filters to continue; each page rechecks current caller and workflow
permissions. The order is admission time and run ID, newest first. Keep the run ID a
start returns for direct lookup with `GET /v1/runs/{run}`. Use the
authenticated HTTP API for application integration, through the maintained
Coordinator client where one fits: the `registry-coordinator-client` Rust
crate, or its Node.js and Python bindings built from source. The unified
Registry Stack clients do not yet carry the Coordinator. The client resends an admission whose outcome is unknown only
under its original key; retain that key through recovery, as with the key file.

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
out-of-bounds retention cutoff/limit, return HTTP 400 `request.reason-invalid`
or `request.retention-invalid`. State and recovery conflicts return HTTP 409.
Every refusal is an RFC 9457 `application/problem+json` document whose `code`
names the refusal; the generated OpenAPI document owns the full code vocabulary.
Recovery POSTs authenticate and authorize before
releasing malformed-body errors. They require `application/json` or an
application media type ending in `+json`; unsupported or absent media types return
415 `request.unsupported-media-type` only after authorization. Bodies remain bounded to 65,536 bytes and duplicate
or unknown fields are refused. Doctor exposes
state counts, aged work, uncertain effects, eligible terminal payload counts and
oldest terminal payload time, hold and audit readiness without
personal labels or payload values.

## Recover safely

The Coordinator retries a call on its own only after a definite retryable
answer, one the receiving product reports it did not act on, and it resends the
saved command and key. A call step makes at most ten attempts, waiting about
1, 2, 4, 8, 16, 32, 64, 128 and then 256 seconds between them; each wait falls
between half and all of that delay. The nine waits therefore add up to between
255.5 and 511 seconds, about 4.3 to 8.5 minutes, plus up to 10 seconds for each
attempt. When the Messaging client or an external service reports a
`Retry-After` in whole seconds, the next attempt waits at least that long, up to
five minutes, so the waits never exceed 45 minutes in total. The BReg and
Scheduling clients report a rate limit without a wait, so those calls follow
the schedule alone. Every retry is bounded by the run deadline: a retry that
would start at or after it is never scheduled, and the run ends `expired` with
the call's failure code. After the tenth attempt the run reports `failed` with
that code and waits for the recovery below. Uncertain answers are never
retried automatically.

A worker lease that lapses has a narrower recovery rule based on the operation
in the run's protected definition snapshot:

| Lapsed step | Result after the lease expires |
|---|---|
| A call whose recovery is `read-again` | The saved read becomes `pending` on the ordinary backoff and runs again without `retry-same`. If its attempt limit is spent or the retry cannot start before the original run deadline, it holds `unknown` instead of becoming dead-lettered or expired. |
| A mutation, evaluation, same-command call, wait or local step | The job holds `unknown` and the run reports `attention`; inspect it before an operator recovery action. |

The transition is audited whether it reschedules or holds. Dispatch increments
the attempt and changes the lease token before a replacement read starts, so a
late result from the old worker cannot commit over it. This lease recovery is
not a new effect-retry rule: ambiguous mutations, evaluations and frozen
same-command effects remain held.

An `external.get/v1` reply with status 429, 502, 503 or 504 is a definite
retryable answer on every attempt but the tenth: 429 retries as
`external-rate-limited` and the others as `external-unavailable`. The tenth
attempt delivers that status to the workflow like any other, held to the
connection's `responseSchema`, so the workflow sees a busy status only after
the retries run out. A run deadline that ends the retries first ends the run
`expired` with the retry code instead. The ten attempts can span up to about
nine minutes, and longer when the service sends `Retry-After`.

Before the final attempt, these external replies must carry at most one
`Retry-After` field containing a whole-second value from zero through 86,400.
A date, duplicate field, malformed value, or longer wait
stops the call with `external-unusable-retry-after`. Zero still follows the normal
backoff schedule. A `wait-for` completion uses its own persisted observation
floor and deadline instead of the call retry schedule.

Inspect before retrying. For Messaging and Scheduling, `reconcile` asks the
receiving product for authoritative evidence of the stored command using its
original key and owner. Missing or expired receipts and an unavailable receiver
do not prove absence. `retry-same`
uses the durable original body, key, binding and authority only when the receiver's
recovery contract and original deadline permit it. A fresh idempotency key is a fresh
operation, so it is never a recovery procedure.

BReg action invocation has no read-only action receipt. `reconcile` therefore
leaves an uncertain action unresolved. Do not infer success or absence from an
ordinary record read. Same-command retry retains the saved client preparation,
conditional ETags and key, and checks current metadata and fresh authority before
dispatch. A changed contract, denied authority or stale condition safely stops
the call rather than refreshing its command. Preparation does not mutate BReg;
cancellation, restore holds and the original workflow deadline still fence
dispatch. Task-bound operations retain their original approval deadline too.

Casework review requests have no read-only receipt either. `reconcile` reports
`reconciliation-unavailable` for an uncertain `casework.submit-review-request/v1` or
`casework.cancel-review-request/v1`, and `retry-same` resends the saved request with its
original key. Casework answers a repeated key with its stored response while
it keeps one; after that the step reports an expired receipt and the effect
stays unresolved.

An `external.command/v1` call has no read-only receipt either. `reconcile` reports
`reconciliation-unavailable`, and `retry-same` resends the frozen body with its original
`Idempotency-Key`. Status 429 before the tenth attempt is a definite busy answer retried on the
schedule above; on the tenth attempt it ends the call with `external-rate-limited`. Status 503
before the tenth attempt is retried on the same schedule, but because it may follow an effect the
step stays uncertain until a later attempt settles it: a run deadline reached first holds the run
with the effect unknown, and on the tenth attempt a 503 holds it as uncertain. When the longest
wait the schedule allows after a 503, including its `Retry-After` and counted from the end of the
attempt's lease, would reach the run deadline, the retry is not scheduled: the run holds at once
with the effect unknown, and `retry-same` resends the same command while the deadline is still in
the future. A 429 the deadline ends still ends the run `expired`. A command ignores a `Retry-After`
it cannot use, such as a date, a duplicate field, a malformed value, or a wait over 86,400
seconds, and retries on the ordinary backoff instead. Any other server error, a redirect, a
timeout, a lost acknowledgement, or a response the interpretation Function cannot settle holds the
run as uncertain. Before retrying, confirm with the provider that it still deduplicates that key.
After an uncertain attempt, including a retried 503, a declared refusal or 429 keeps the run held;
check the provider's record and cancel the run if no further step should follow.

A `wait-for` observes a named completion, correlated to an earlier accepted call.
Casework exposes `result`; the BReg Proposal operations expose `proposal`; external GET can
expose an authored bounded-poll completion. These observations are read-only and spend no
mutation attempt. Pending Casework and BReg reads default to 900 seconds. Both allow
`resultCheckSeconds` from 60 to 86,400 seconds; an external completion declares `intervalSeconds`.

The durable read floor is 30 seconds by default for Casework, BReg and external poll reads.
Each Casework or BReg wait's read budget is sized at that floor, so wake-ups and Check now never
exhaust it before the timeout. Top-level `minimumObservationIntervalSeconds`
can raise it up to 86,400 seconds across the deployment. Restart, event wake-up, retry, and
timeout never bypass it. Retry hints postpone reads within the host ceiling of 86,400 seconds;
unusable hints hold the wait. Inspection exposes the floor, next read, count, and budget without
protected correlation values. A completion event cannot settle a result.

Transient outages leave observations pending within the original deadline. Invalid, refused,
blocked, or mismatched evidence holds the wait for investigation; it cannot route as a negative
business outcome. `retry-same` retains the same completion identity, floor, and timeout.
An ended wait cannot be restarted. Timeout can take `onTimeout`, or report `wait-timed-out`.
It does not cancel work in the owning product.

An optional `onCancel` takes an authored forward cleanup path. An active read records the intent
and routes when the lease settles or expires. Repeating cancellation preserves cleanup.
A Casework cancellation uses current producer authority, the original key, and the run deadline;
route on its `outcome`, because `already-terminal` means a decision won the race. Ordinary
cancellation leaves downstream work for explicit owner-authorized withdrawal.

If a product call succeeds but the following wait mapping is invalid, the run
reports `failed` with `mapping-invalid` while retaining that call's successful
output and delivered job. `retry-same` cannot repeat the accepted call. Inspect
the existing effect before planning any new run with a corrected workflow
version. Settled failure payloads follow the same explicit retention policy;
recoverable failed jobs and uncertain effects remain protected.

A computed call input outside its operation input contract fails the run with
`invalid-command` before the call is prepared, saved or sent. The run and step
status report `failurePath`, the RFC 6901 path into the input, and never the
value; an unexpected member is reported at the object that holds it. Correct the
mapping in a new workflow version, or correct the data it reads, then start a new
run.

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

## Rotate and replace keys

Each key has its own procedure. Run every command as the service user.

### Rotate the payload state key

Rotation adds a key version and makes it the one that writes. Apply registers
each version in the database, and the deployment keeps every registered version
for its lifetime: runs written under an older version still read with it.

1. Create the key file for the next version:

   ```sh
   (umask 077 && openssl rand -out /run/registry-coordinator/secrets/state-key-2 32)
   ```

2. Add the version to `deployment.stateKeys`, keep every version already
   listed, and set `activeStateKey` to the new version:

   ```yaml
   deployment:
     activeStateKey: 2
     stateKeys:
       "1":
         keyRef: secret:file/state-key-1
       "2":
         keyRef: secret:file/state-key-2
   ```

3. Put the edited runtime file and the new key file in place for every
   service, then apply the deployment and check it:

   ```sh
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml apply
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml deployment-status
   ```

4. Restart every service with the edited runtime file as soon as apply
   succeeds.

Roll the edited runtime file out together with apply. Until apply registers the
new version, startup and `deployment-status` refuse the edited file with
`state-key-custody` and the fix to run apply. Once apply has registered it,
every service still running with the previous file refuses with
`state-key-custody` until it restarts with the edited file. An ordinary service
answers starts with 409 `deployment.refused` and `/ready` with 503, and its
worker's next poll
dispatches nothing and stops the service with exit status 1. A recovery-only
service stops the same way at its periodic deployment check, every 30 seconds.

Apply, `deployment-status` and startup refuse with `state-key-custody` a runtime
file that omits a registered version or names different key bytes for it, and
name `deployment.stateKeys` as the fix. Keep every registered key file under
backup custody, because a restored database needs the versions its rows were
written with.

### Rotate the audit key

The audit key derives the keyed references in the audit journal, such as
`runRef`, `actorRef`, `stepRef` and `reasonRef`. The database holds no record
of it, so a rotation needs no apply.

1. Create the new key file:

   ```sh
   (umask 077 && openssl rand -out /run/registry-coordinator/secrets/audit-key-2 32)
   ```

2. Point `deployment.auditKeyRef` at it:

   ```yaml
   deployment:
     auditKeyRef: secret:file/audit-key-2
   ```

3. Check the runtime file, then restart every service with it, so all of them
   write under the same key:

   ```sh
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime.yaml check
   ```

The same run, actor, step or reason gets a different reference under each key,
so records written before the rotation do not join records written after it.
Keep the old key with the journal it wrote: an investigator needs it to match a
known run or actor to those records.

### Replace a compromised admission key

The admission key stays the same for the deployment's lifetime: apply refuses a
runtime file with a different admission key with `state-key-custody`. When the
key is exposed, close the deployment and admit new work in a fresh one.

1. Stop admissions. Remove `start` from each caller policy's `actions`; remove
   a policy left with no action, and its client policy. Restart
   the service. Starts are then refused with HTTP 403
   `operation.not-authorized`, while status, inspection and operator actions
   keep working. Do not use
   `restore-hold` for this step: it also stops dispatch, so runs in flight
   cannot finish.

2. Let runs finish, or cancel the ones you will not wait for. Doctor counts the
   runs still `running` in `state.states` and the steps waiting for an operator
   in `state.uncertain`. `list` shows the newest runs of the operator's workflows,
   up to 100. Settle each uncertain step as [Recover safely](#recover-safely)
   describes before you stop the service.

   ```sh
   coordinatorctl doctor --url https://coordinator.example.org --token-file /run/operator-token
   coordinatorctl list --limit 100 --url https://coordinator.example.org --token-file /run/operator-token
   coordinatorctl cancel --run RUN_UUID --reason incident-2026-10-11 \
     --url https://coordinator.example.org --token-file /run/operator-token
   ```

3. Stop the service. Keep its runtime file, namespace, keys and audit journal
   for as long as you need its history: the old runs stay in the old namespace.

4. Create a new admission key file:

   ```sh
   (umask 077 && openssl rand -out /run/registry-coordinator/secrets/admission-key-2 32)
   ```

5. Write a runtime file for the new deployment with a new `namespace`, a new
   `deployment.databaseId` and the new key, and restore `start` to the caller
   policies:

   ```yaml
   namespace: coordinator_follow_up_2
   deployment:
     databaseId: coordinator-institution-follow-up-2
     admissionKeyRef: secret:file/admission-key-2
   ```

6. Plan, apply, check and start the new deployment:

   ```sh
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime-2.yaml plan
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime-2.yaml apply
   coordinatorctl --runtime-config /etc/registry-coordinator/runtime-2.yaml deployment-status
   coordinator --runtime-config /etc/registry-coordinator/runtime-2.yaml
   ```

The new deployment has no record of the idempotency keys the old one spent, so
an idempotency key reused against it admits a new run. Tell producers to send a fresh
start only for work the old deployment did not admit.

## Backup and restore

Back up PostgreSQL, all still-needed state-key versions, the stable admission
key, audit key, durable audit stream and the exact immutable package of every
listed workflow. Preserve
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
reconciling the runs it contains does not prove that replaying an omitted
idempotency key is safe. Keep admissions held until complete PITR/WAL recovery or separately
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
A command-free hold keeps zero attempts; it never invents one.

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
