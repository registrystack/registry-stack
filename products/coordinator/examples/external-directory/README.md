# External directory project

Use this synthetic example when a run needs one read from an HTTP service that
is not a Registry Stack product, such as an office directory. The run sends one
GET for the input's `district` and finishes with the first office identifier,
with `no-directory-entry`, or with `directory-unavailable`. The workflow, pure
functions, deterministic scenarios and runtime template form one complete
project.

From the repository root, run the offline authoring commands:

```sh
coordinatorctl check --project products/coordinator/examples/external-directory --explain
coordinatorctl test --project products/coordinator/examples/external-directory
```

The `lookup` step calls `external-get` on the logical `directory` connection.
`lookup_request` supplies only the path `offices` and the query value
`district`. The runtime's `externalHttpConnections.directory` fixes the base
URL, the permitted path and query names, and the `responseSchema` that the
reply `{status, body}` must match. A path or query name outside those lists is
refused with `external-invalid-command`.

The `result` step calls `office_route` on the validated reply:

- Status 404, or status 200 with no items, finishes with `no-directory-entry`.
- Status 200 with items finishes with `office-found` and the first item's `id`
  as `officeId`.
- A 429, 502, 503 or 504 on the last attempt finishes with
  `directory-unavailable`.

The schema permits 404, 429, 502, 503 and 504 with an empty body, so the
workflow decides what they mean. A busy or failing gateway is retried first:
the adapter reports a 429 as the retryable `external-rate-limited` and a 502,
503 or 504, like a timeout or connection failure, as the retryable
`external-unavailable`, and the Coordinator retries it on its own, as
[Recover safely](../../DEPLOYMENT.md#recover-safely) describes. Only the tenth
attempt hands the status to the workflow. Ten attempts with nine waits of at
most the 300-second backoff cap, which a `Retry-After` never exceeds, take
less than an hour, so the run's 3600-second deadline lets a directory that
stays busy reach `directory-unavailable` instead of ending the run `expired`.
A reply the schema does not permit, such as status 500, stops the run with
`external-invalid-response` on its first attempt.

The scenarios cover an office found, a 404, an empty result, each of the four
busy or failing statuses on the last attempt, and a transport failure.
Scenarios do not run the automatic retries: a 429, 502, 503 or 504 reply in a
scenario stands for the final attempt, and the transport failure scenario
stops at the first `external-unavailable` answer.

The connection has no `authorization` block. It is a public read, and the
Coordinator never sends the caller's token to the directory. To call a
protected directory, add an ordinary service `authorization` with
`tokenEndpoint`, `clientId`, `signingKeyRef`, `resource` and `scopes`;
`taskAuthority` is not accepted here. Each attempt uses the defaults of 2000
milliseconds and 65,536 response bytes, which `attemptTimeoutMilliseconds` and
`maximumResponseBytes` may lower.

For a deployment, the institution must supply these prerequisites:

- The directory serves `GET offices?district=...` below its base URL with read
  semantics. It answers 200 with a JSON body of the form
  `{"items": [{"id": "..."}]}`, or 404 with an empty body. When it or a
  gateway in front of it is busy or failing, it answers 429, 502, 503 or 504
  with an empty body; the adapter reads that body only on the final attempt.
- The endpoint uses HTTPS. Plain HTTP is accepted only on an explicit numeric
  loopback address, as in this template.
- Callers hold a Coordinator access token for the `external-directory` flow,
  and an explicit operator policy grants inspection and recovery separately.

The runtime template has no product connections, uses a loopback endpoint, and
contains secret references only. Copy it outside the package and adapt its
endpoint, response schema, PostgreSQL identity and roles, and package pin.
Follow [the deployment runbook](../../DEPLOYMENT.md) for installation and apply.
