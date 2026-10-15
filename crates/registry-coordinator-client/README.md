# Registry Coordinator client

A bounded server-side client for Registry Coordinator's HTTP contract. The
public Rust facade exposes it as `registry_stack_client::coordinator`; the
public Node.js and Python packages expose it as their `coordinator`
namespace. Browser apps call their own authorized server routes.

The operations are `workflow`, `start`, `list`, `status`, `inspect`, `reconcile`,
`retry_same`, and `cancel`. The operator routes (doctor, holds, execution
recovery and retention) are not part of this client; `coordinatorctl` owns them.
`workflow` discovers the permitted active input and outcome contracts under current start
authority, including the computed `workflowRevision`, without starting a run. Admission requires
a caller-chosen idempotency key and `{workflow, workflowRevision, input}`. HTTP
200 confirms admission and returns the run's current status. The runtime
answers the same run again for the same caller, workflow, key, expected revision, and input, and
refuses conflicting revision or input under that key. A fresh start must match the active revision;
a mismatch is `409 workflow.revision-mismatch`. Recovery of an unknown admission retains the
original revision even when activation changes. A key is scoped to the caller and
the workflow, so the same key under two workflows starts two runs, and an allowed workflow
the deployment does not serve is refused with 404 `workflow.not-served`, a known
outcome the client never resends. When an admission's outcome is
unknown, after a timeout or broken exchange or on a 5xx answer, the client
resends the identical request under the same key, at most
`with_max_mutation_retries` times (2 by default, at most 2, 0 disables it).
It never resends after a 4xx status line. An error that still leaves the
outcome unknown may have admitted a run: the caller retains the exact key,
workflow, revision, input, and service identity in durable state before dispatch and
recovers under that same identity. Changing the key or the verified
issuer/subject can create another run. `workflow`, `list`, `status`, `inspect`,
`reconcile`, `retry_same` and `cancel` send exactly once. `retry_same` and
`cancel` take no idempotency key, so the client never resends them: after an
error that leaves the outcome unknown, read the run before asking again.
`list` takes a limit from 1 to 100 and returns the first page of runs the
caller may read, newest admission first. `list_page` also accepts the opaque
cursor returned as `next_cursor`, an exact state, and an attention filter.
Pass a cursor unchanged with the same caller and filters. Attention means the
effective states `attention` and `failed`; the state filter exposes all eight
closed runtime states individually.

The computed Workflow revision identifies execution semantics, including the typed input,
graph, declared outcomes, used Operation and Function revisions, and host execution contracts.
Workflow discovery also returns `reviewPolicy`: the exact shared Review
`PolicyBinding` for a provider workflow, or `null` when it is not a provider.
The client validates the policy through `registry-review-protocol`, checks its
ID against `workflow` and its digest against `workflowRevision`, and preserves
the returned bounded version. This metadata grants no review or source authority.
The runtime-free wire crate is the client's sole shared-protocol exception;
the client does not depend on a provider runtime, core or Review HTTP client.
Presentation titles and descriptions do not change it. Exact package bytes have a separate
package checksum. Status retains the admitted `workflow` and `workflowRevision` after upgrades.
Every returned run identity must be nonnil, and its deadline must follow its admission.
Historical deadlines remain readable; this check does not compare them to the local clock.
A finished run requires an outcome. Other states carry no terminal evidence, except
`attention` with `restoreReviewRequired` after a leased Finish commits during restore review.
That retained outcome does not complete the operator's recovery review. Output may be null
for an authored null result or after retention; non-null output always requires an outcome.
Run and step `failurePath` values preserve valid RFC 6901 pointers, including the empty
root path. Validation checks their syntax without resolving them against omitted command data.
Inspection requires `retryAllowed` to be true
exactly when its blocking `reason` is null. Each wait has a minimum interval from 30 to
86,400 seconds, a positive observation limit, and a count no greater than that limit.
Inconsistent documents are protocol failures;
a malformed successful admission or control answer leaves the outcome unknown and is never
automatically resent. Inspection adds accepted or unknown `effects` and named completion `waits`, including pinned
revisions, deadlines, next observations, persistent floors, and count/limit. Original inputs,
raw product responses, prepared requests, and protected correlation values remain absent.
The reviewed Workflow declares any terminal output projection.

`coordinatorctl types --project DIRECTORY --language typescript --output FILE` and the equivalent
`--language python` export typed Workflow wrappers over the maintained public generic clients.
Their `start`, `get`, and `cancel` methods pin the compiled revision and check returned workflow
identity and declared outcome names. They add no transport or authorization semantics; runtime
schema checks remain with Coordinator. Regenerate the wrapper when the execution contract changes.

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
