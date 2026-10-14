# Registry Coordinator Node binding

This internal napi-rs binding is assembled into the `coordinator` namespace of
`@registrystack/client`.

Each operation accepts the bearer token for that call. `workflow(token, workflow)` discovers
the active permitted contract and computed `workflowRevision` under current start authority.
`start(token, idempotencyKey, request)` takes `{workflow, workflowRevision, input}` and the caller's
chosen key. A fresh start must match the active revision, or it returns
`409 workflow.revision-mismatch`. Retain the original identity, key, revision, and input when
recovering an unknown admission, including after activation changes. The binding never acquires a
token or invents a key. `start` resends an admission whose outcome is unknown,
identically and under the caller's same key, at most `maxMutationRetries` times
(default 2, at most 2, 0 disables); a 4xx refusal is never resent. A key is
scoped to the caller and the workflow, so the same key under two workflows starts two
runs, and an allowed workflow the deployment does not serve is refused with 404
`workflow.not-served`, a known outcome never resent. `workflow`, `list`,
`status`, `inspect`, `reconcile`, `retrySame`, and `cancel` send exactly one
request. `reconcile` reads the receipt for the original operation and updates
recovery state; it never resubmits that operation. `retrySame` and `cancel`
take no idempotency key, so after an unknown outcome read the run before
asking again. Operator routes are not part of this binding; `coordinatorctl`
owns them.

The computed Workflow revision identifies execution semantics, including the typed input,
graph, declared outcomes, used Operation and Function revisions, and host execution contracts.
Presentation titles and descriptions do not change it. Exact package bytes have a separate
package checksum. Status retains the admitted `workflow` and `workflowRevision` after upgrades.
Inspection adds accepted or unknown `effects` and named completion `waits`, including pinned
revisions, deadlines, next observations, persistent floors, and count/limit. Original inputs,
raw product responses, prepared requests, and protected correlation values remain absent.
The reviewed Workflow declares any terminal output projection.

`coordinatorctl types --project DIRECTORY --language typescript --output FILE` and the equivalent
`--language python` export typed Workflow wrappers over the maintained public generic clients.
Their `start`, `get`, and `cancel` methods pin the compiled revision and check returned workflow
identity and declared outcome names. They add no transport or authorization semantics; runtime
schema checks remain with Coordinator. Regenerate the wrapper when the execution contract changes.

`list(token, limit, cursor?, state?, attention?)` preserves a returned opaque
cursor and its filters exactly. `attention: true` selects runs whose effective
state is `attention` or `failed`; `state` accepts any one of the eight closed
run states. Invalid cursors and filters fail before I/O.

Configuration, request documents, UUIDs, and JavaScript integer bounds are
checked before I/O. Errors expose a fixed safe message and the closed failure
category. A refusal is a `problem` error only when the service answered an
exact RFC 9457 `application/problem+json` document whose status, type and
trace agree with the answer; its `family.reason` code stays a string because
the Coordinator contract authors the vocabulary. Problem titles and details,
credentials, request bodies, and transport chains are not copied into errors.
