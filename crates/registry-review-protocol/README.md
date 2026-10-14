# Registry review protocol

This crate owns the runtime-free wire types exchanged between an admitted
producer and an independently authorized review provider. Registry Casework
provides human review; Registry Coordinator may provide a workflow-bound
decision or hand off to Casework under its own producer identity.
Business sources such as BReg use the types to bind submissions and verify
results without depending on the Casework runtime, task model, policy engine,
or database.

Producer operations use `Registry-Review-Profile`, the shared
`https://id.registrystack.org/problems/registry-review/` problem namespace and
`Registry-Review-Validation-Path`/`Registry-Review-Validation-Reason` diagnostics.
Provider-specific human task and policy-evaluation APIs remain provider-owned.

The submission digest covers the authenticated producer, source namespace,
and complete create request, including its required policy ID, version, and
digest. JSON values are bounded by canonical byte size,
nesting depth, and node count so the same contract applies to parsed and
programmatically constructed values.

The crate contains no HTTP client, credentials, persistence, source adapter,
policy evaluator, reviewer task, or source execution code. In particular, a
completion envelope is only a synchronization hint. It cannot carry approval
evidence or authorize a source operation.
