# Registry Coordinator client

A bounded server-side client for Registry Coordinator's HTTP contract. The
public Rust facade exposes it as `registry_stack_client::coordinator`; the
public Node.js and Python packages expose it as their `coordinator`
namespace. Browser apps call their own authorized server routes.

The operations are `start`, `list`, `status`, `inspect`, `reconcile`,
`retry_same`, and `cancel`. The operator routes (doctor, holds, execution
recovery and retention) are not part of this client; `coordinatorctl` owns them.
Admission requires a caller-chosen idempotency key and `{flow, input}`. HTTP
200 confirms admission and returns the run's current status. The runtime
answers the same run again for the same caller, flow, key and input, and
refuses the same key with a different input. A key is scoped to the caller and
the flow, so the same key under two flows starts two runs, and an allowed flow
the deployment does not serve is refused with 404 `flow.not-served`, a known
outcome the client never resends. When an admission's outcome is
unknown, after a timeout or broken exchange or on a 5xx answer, the client
resends the identical request under the same key, at most
`with_max_mutation_retries` times (2 by default, at most 2, 0 disables it).
It never resends after a 4xx status line. An error that still leaves the
outcome unknown may have admitted a run: the caller retains the exact key,
flow, input and service identity in durable state before dispatch and
recovers under that same identity. Changing the key or the verified
issuer/subject can create another run. `list`, `status`, `inspect`,
`reconcile`, `retry_same` and `cancel` send exactly once. `retry_same` and
`cancel` take no idempotency key, so the client never resends them: after an
error that leaves the outcome unknown, read the run before asking again.
`list` takes a limit from 1 to 100 and returns the first page of runs the
caller may read, newest admission first. `list_page` also accepts the opaque
cursor returned as `next_cursor`, an exact state, and an attention filter.
Pass a cursor unchanged with the same caller and filters. Attention means the
effective states `attention` and `failed`; the state filter exposes all eight
closed runtime states individually.

Status is protected by current Coordinator policy and ownership. A run started
by a backend is owned by that backend, even when its input mentions a citizen's
record. Applications must independently authorize source-record access and use
their explicit record-to-run correlation before displaying selected progress.

`reconcile`, `retry_same` and `cancel` take a reason of 1 to 256 bytes without
control characters, refused before sending. `reconcile` observes the original
supported product receipt from the runtime's saved command. It does not
resubmit a notice. A missing or expired receipt remains uncertain. A Messaging
acceptance is never proof of provider delivery. `retry_same` schedules the
saved command again, unchanged, only when the run's inspection allows it.
`cancel` stops further progression and never undoes a product effect.

Configuration validates a fixed HTTPS endpoint, or an explicit loopback HTTP
endpoint for local development. Deployment prefixes are preserved. Shared
transport disables redirects and ambient proxies; body and header limits apply
to successes and failures. Every refusal is an RFC 9457
`application/problem+json` document with exactly `type`, `title`, `status`,
`detail`, `code` and `traceId`. The client accepts it only when its status
equals the answer's, its `traceId` equals the answer's `traceparent` trace,
and its `type` is its `family.reason` code under
`https://id.registrystack.org/problems/registry-coordinator/`; anything else is
a protocol failure. It discards the title and detail, and reports closed error
categories with the answered status and the product's code. The code
vocabulary is listed in the runtime's generated OpenAPI document.

Run `cargo test --locked -p registry-coordinator-client` and
`cargo clippy --locked -p registry-coordinator-client --all-targets -- -D warnings`.
HTTP tests bind disposable loopback sockets. They verify transport behavior,
not product authorization.
