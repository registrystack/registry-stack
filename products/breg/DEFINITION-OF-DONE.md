# Definition of Done

`contracts/definition-of-done.yaml` owns the exact BReg delivery requirements and
proof references. `contracts/security-invariant-matrix.yaml` and
`contracts/security-test-traceability.yaml` own security invariants and resolving
negative tests. A planned row, mock database, skipped test, or generated document
alone does not establish completion.

The maintained public model consists of Record types, generated CRUD, immediate
atomic Actions, and durable Proposals. Canonical inputs live in `acceptance/`,
`fixtures/`, and `examples/`; tests load those inputs directly. The
[acceptance guide](ACCEPTANCE-JOURNEYS.md) maps their purpose without duplicating
fixture trees or claiming an old starter catalogue remains supported.

Runtime completion requires real PostgreSQL proof of authorization, concealment,
concurrency, history, atomic receipt/outbox behavior, and the changed operation's
retention boundary. Proposal proof includes exact frozen effects, independent
review, restricted default automatic application, explicit manual mode, current
guards, safely blocked work, and exact-command recovery. Optional dependencies
must fail closed only for operations that need them.

Adopter completion requires the smallest authoring, local development, package,
activation, and permitted/refused request journey for the changed surface.
Compiler success proves configuration, not successful execution. Use the documented
checks in [agent guidance](AGENTS.md), preserve the exact candidate identity, and
report unexecuted runtime or integration checks as limits. Release completion
follows the maintained Registry Stack release procedure.
