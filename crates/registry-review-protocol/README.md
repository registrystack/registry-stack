# Registry review protocol

This crate owns the runtime-free wire types exchanged between an admitted
producer and an independently authorized review provider. Registry Casework
provides human review; Registry Coordinator may provide a workflow-bound
decision or hand off to Casework under its own producer identity.
Business sources such as BReg use the types to bind submissions and verify
results without depending on the Casework runtime, task model, policy engine,
or database.

Producer operations use `Registry-Review-Profile` and bounded
`Registry-Review-Validation-Path`/`Registry-Review-Validation-Reason` diagnostics.
Problem type URIs may belong to the provider. Clients treat them as opaque
identifiers, never dereference them, and conservatively classify unknown failures.
Provider-specific human task and policy-evaluation APIs remain provider-owned.

The submission digest covers the authenticated producer, source namespace,
and complete create request, including its original `PolicySelection`.
The default selector is `{"id":"review-policy"}` and delegates version choice
to the trusted provider at first acceptance. Strict mode adds both `version`
and `digest`; partial pins are invalid. The provider atomically persists the
concrete `PolicyBinding`, policy snapshot and idempotent acceptance. Retries
recover that acceptance before consulting current policy. Results repeat the
accepted exact binding, while the original selector and submission digest stay
unchanged. JSON values are bounded by canonical byte size,
nesting depth, and node count so the same contract applies to parsed and
programmatically constructed values.

The crate contains no HTTP client, credentials, persistence, source adapter,
policy evaluator, reviewer task, or source execution code. In particular, a
completion envelope is only a synchronization hint. It cannot carry approval
evidence or authorize a source operation.
