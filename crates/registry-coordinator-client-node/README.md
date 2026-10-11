# Registry Coordinator Node binding

This internal napi-rs binding is assembled into the `coordinator` namespace of
`@registrystack/client`.

Each operation accepts the bearer token for that call. `start` also takes the
caller's idempotency key and exact input document. The binding never acquires a
token or invents a key. `start` resends an admission whose outcome is unknown,
identically and under the caller's same key, at most `maxMutationRetries` times
(default 2, at most 2, 0 disables); a 4xx refusal is never resent. A key is
scoped to the caller and the flow, so the same key under two flows starts two
runs, and an allowed flow the deployment does not serve is refused with 404
`flow-absent`, a known outcome never resent. `list`,
`status`, `inspect`, `reconcile`, `retrySame`, and `cancel` send exactly one
request. `reconcile` reads the receipt for the original operation and updates
recovery state; it never resubmits that operation. `retrySame` and `cancel`
take no idempotency key, so after an unknown outcome read the run before
asking again. Operator routes are not part of this binding; `coordinatorctl`
owns them.

Configuration, request documents, UUIDs, and JavaScript integer bounds are
checked before I/O. Errors expose a fixed safe message and the closed failure
category. Coordinator problem codes remain strings because they are authored
by the Coordinator contract. Response messages, credentials, request bodies,
and transport chains are not copied into errors.
