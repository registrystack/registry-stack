# Durable external job project

Use this project to admit one application-owned job durably, then observe that exact job until
its status is terminal or the bounded wait expires. Coordinator reaches the application through
its existing `external.command/v1` and `external.get/v1` contracts. The workflow uses no
Casework or Base Registry Engine connection.

From the repository root:

```sh
coordinatorctl check --project products/coordinator/examples/external-job --explain
coordinatorctl test --project products/coordinator/examples/external-job
```

The `read-job` Operation alias uses `external.get/v1`, specializes its response schema, and exposes
a named `terminal` completion. Its `bounded-poll` declaration names pure Function `job-observation`
and a 30-second interval. The workflow reads once, then waits on
`completion: {step: read, name: terminal}` for up to 600 seconds within a 900-second run deadline.

Before that read, `admit-job` sends an authenticated, bounded POST to the runtime's exact `jobs`
command path.
Coordinator freezes the `{reference}` body and its `Idempotency-Key` before sending. The
`job-admission` Function accepts only a 200 or 201 response containing a stable `jobId` receipt.
It declares a 422 `invalid-job` answer refused because the application rejected it before
admission. A malformed answer, server failure, response-encoding failure, or key conflict remains
uncertain. A key conflict cannot claim no effect because a different job already exists under
that key. `retry-same` resends the frozen body and key.

The read request Function takes the accepted receipt and selects only the configured
`jobs/status` path and `id` query parameter. The observation interpreter receives the saved
original `command` and latest validated `response`. It checks the job ID, returns `pending` for
queued/running, `complete` with
a typed job result for succeeded, or a declared `external-job-failed` refusal for failed.
Correlation or response-shape errors hold work and cannot become a successful business outcome.

The host owns GET transport, credentials, persistent minimum spacing, retry hints, and the finite
observation budget. A restart, wake-up, or timeout cannot bypass the durable floor. The deployment's
`minimumObservationIntervalSeconds` can raise the 30-second operation minimum. Inspection reports
next observation, count, and limit without the protected command or correlation values.

Timeout finishes `job-wait-expired`. It stops Coordinator observation and makes no claim that the
external job failed or was cancelled. Cancellation stops future observation where possible and
cannot stop an external job. There is no callback contract.

## Example application transaction

[`service.py`](service.py) is deliberately application code, not a client-library helper. Its
PostgreSQL `jobs` row contains the command key, canonical request digest, application work,
stable receipt, and current state. `JobStore.admit` inserts the job and receipt in one database
transaction. Concurrent duplicates contend on the unique key and return the committed receipt.
The same key with another request is a conflict and never selects the earlier receipt as if it
belonged to the changed command.

The commit completes before response encoding. If the process stops, the connection drops, or
encoding fails after commit, Coordinator sees an uncertain command. Repeating the same command
returns the original receipt without inserting another job. `JobStore.transition` represents the
application's worker moving a queued job to running and then to succeeded or failed. A terminal
job cannot be changed to another terminal state.

Both application routes require Registry Stack machine admission before parsing a command or
reading the job store. `JobApplication` passes only the WSGI `Authorization` value to
`stack.admit(...)`; browser cookies, Origin and other browser headers confer no authority. A
missing, malformed, expired or policy-mismatched bearer returns the value-free
`authentication.refused` response. A verifier outage returns `authentication.unavailable`.
Neither response reaches application work or observation.

Run the local fixture against a dedicated PostgreSQL database:

```sh
uv sync --project products/coordinator/examples/external-job
sdk='registry-stack-client==<matching-release-version>'
# Prepared source candidates may use an absolute assembled wheel path instead.
EXTERNAL_JOB_DATABASE_URL=postgresql://... \
REGISTRY_STACK_CONNECTION=/run/secrets/external-job/connection.json \
  uv run --project products/coordinator/examples/external-job --with "$sdk" \
  python products/coordinator/examples/external-job/service.py
```

Use the assembled `registry-stack-client` wheel from the same source or release as the services;
the source facade directory is not a wheel-equivalent runtime. `REGISTRY_STACK_CONNECTION` names
an owner-only `audience: service` connection whose admission section fixes the issuer, resource,
client ID, profile, required scopes and protected actor claims. The issuer registration must mint
the checked-in Coordinator client an access token with that exact service audience and claims.
The [Python client guide](../../../../crates/CLIENTS.md) owns connection assembly and deployment
requirements.

`service.py` binds only to `127.0.0.1:9010` by default. The checked-in runtime points there and
uses its own client assertion to request the exact `urn:example:external-job` resource with the
`external-job:admit` and `external-job:observe` scopes. It contains only synthetic loopback
configuration and a `secret:file/external-job-client-jwk` reference, never key material. Provision
that client signing key as an owner-only regular file under the declared file-provider root. A
matched live issuer, client and service connection remain required before claiming effective
issuer admission.

For deployment, configure `jobs` as `type: external-http`, with the actual base URL, exact command
path, allowed GET path and query name, authorization, and response schema. The loopback runtime is
a local fixture, not an institutional deployment. Use HTTPS and a separately configured service
admission connection. Copy runtime configuration outside the package and follow the
[deployment runbook](../../DEPLOYMENT.md).

Offline scenarios prove the accepted, declared-refusal, uncertain, recovery, terminal and timeout
routes through the pinned Functions. The Python unit test covers machine admission on both HTTP
routes, no cookie authority, refusal and verifier outage before the store, durable duplicate
semantics, exact observation, and a post-commit encoding failure. Its PostgreSQL test covers
concurrent duplicate admission, crash after commit, stable correlation and terminal state. Run it
only with an explicitly disposable database:

```sh
EXTERNAL_JOB_TEST_DATABASE_URL=postgresql://... \
  uv run --project products/coordinator/examples/external-job \
  python -m unittest discover \
  -s products/coordinator/examples/external-job/tests -p 'test_*.py'
```

`crates/registry-coordinator/tests/external_wait_postgres.rs` drives the maintained project through
the real external command and GET adapters, durable Coordinator store and worker. It covers
accepted and declared-refused admission, unusable post-effect responses, same-command recovery,
restart, correlation, pending/success/declared job failure, observation exhaustion, timeout,
cancellation and deadline. A skipped database test is not evidence for either durable store.
