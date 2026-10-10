# Registry Coordinator Node binding

This internal napi-rs binding is assembled into the `coordinator` namespace of
`@registrystack/client` for explicit Coordinator-enabled candidates.

Each operation accepts the bearer token for that call. `start` also takes the
caller's idempotency key and exact input document. The binding never acquires a
token, invents a key, or retries a request. `reconcile` reads the receipt for
the original operation and updates recovery state; it never resubmits that
operation.

Configuration, request documents, UUIDs, and JavaScript integer bounds are
checked before I/O. Errors expose a fixed safe message and the closed failure
category. Coordinator problem codes remain strings because they are authored
by the Coordinator contract. Response messages, credentials, request bodies,
and transport chains are not copied into errors.
