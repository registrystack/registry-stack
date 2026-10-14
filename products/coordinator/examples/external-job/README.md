# External job completion project

Use this synthetic project to observe one previously selected external job until its status is
terminal or the bounded wait expires. The workflow uses no Casework or Base Registry Engine connection.

From the repository root:

```sh
coordinatorctl check --project products/coordinator/examples/external-job --explain
coordinatorctl test --project products/coordinator/examples/external-job
```

The `read-job` Operation alias uses `external.get/v1`, specializes its response schema, and exposes
a named `terminal` completion. Its `bounded-poll` declaration names pure Function `job-observation`
and a 30-second interval. The workflow reads once, then waits on
`completion: {step: read, name: terminal}` for up to 600 seconds within a 900-second run deadline.

The request Function takes one named-input object and selects only the configured `jobs/status`
path and `id` query parameter. The interpreter receives the saved original `command` and latest
validated `response`. It checks the job ID, returns `pending` for queued/running, `complete` with
a typed job result for succeeded, or a declared `external-job-failed` refusal for failed.
Correlation or response-shape errors hold work and cannot become a successful business outcome.

The host owns GET transport, credentials, persistent minimum spacing, retry hints, and the finite
observation budget. A restart, wake-up, or timeout cannot bypass the durable floor. The deployment's
`minimumObservationIntervalSeconds` can raise the 30-second operation minimum. Inspection reports
next observation, count, and limit without the protected command or correlation values.

Timeout finishes `job-wait-expired`. It stops Coordinator observation and makes no claim that the
external job failed or was cancelled. Cancellation stops future observation where possible and
cannot stop an external job. The project has no external mutation or callback contract.

For deployment, configure `jobs` as `type: external-http`, with the actual base URL, exact path,
allowed query name, and response schema. The loopback runtime is a local fixture, not an
institutional deployment. Use HTTPS and separately configured service authorization where needed;
omitting authorization means a public read. Copy runtime configuration outside the package and
follow the [deployment runbook](../../DEPLOYMENT.md).

Offline scenarios prove interpretation and routing with synthetic replies. They do not prove a
live job service or downstream authority. HTTP adapter and PostgreSQL wait tests cover their own
transport, floor, retry, timeout, and reconstruction boundaries.
