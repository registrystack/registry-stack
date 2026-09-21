# Registry review protocol

This crate owns the runtime-free wire types exchanged between an admitted
producer and Registry Casework. Casework serves and evaluates the protocol.
Business sources such as BReg use the types to bind submissions and verify
results without depending on the Casework runtime, task model, policy engine,
or database.

The submission digest covers the authenticated producer, source namespace,
and complete create request. JSON values are bounded by canonical byte size,
nesting depth, and node count so the same contract applies to parsed and
programmatically constructed values.

The crate contains no HTTP client, credentials, persistence, source adapter,
policy evaluator, reviewer task, or source execution code. In particular, a
completion envelope is only a synchronization hint. It cannot carry approval
evidence or authorize a source operation.
