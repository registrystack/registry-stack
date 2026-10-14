# Registry Coordinator changelog

## Unreleased

First release of Registry Coordinator.

- Coordinator executes finite, acyclic Workflows across durable waits, outages, and restarts.
  Projects separate generated contracts, reusable types, named pure Functions, local exact
  Operation aliases, and one Workflow graph. Functions take one typed object of named inputs.
- Runtime bindings use one tagged `connections` map. Caller policies are keyed by exact verified
  client identity and scope run actions through `workflows`.
- Starts require an expected computed `workflowRevision`. Workflow discovery and generated
  TypeScript/Python wrappers provide revision-pinned typed `start`, `get`, and `cancel` through
  maintained public generic clients. Unknown admission preserves its original revision and key.
- Named completions share `completion: {step, name}` across Casework results, exact BReg Proposal
  application, and bounded external job observation. Persistent read floors, retry ceilings, and
  observation budgets survive restarts and wake-ups. Blocked or uncertain evidence remains held.
- BReg Action aliases import owner-generated exact contracts. Proposal draft creation, submission,
  review, application, and a later notice remain separate authorized stages. Only exact application
  evidence can release an application wait. Declared no-effect refusals can route explicitly.
- Inspection reports accepted or unknown effects and bounded wait state without protected inputs,
  raw product responses, prepared requests, or correlation values. Encrypted PostgreSQL custody,
  durable audit, retention tombstones, and explicit fenced restore recovery protect work.
- Protected state schema version 3 directly replaces earlier pilot layouts. Incompatible state is
  refused; there is no in-place conversion or legacy authoring syntax.
- Maintained examples cover independent Proposal follow-up, standalone Casework review, and
  external job completion. Offline scenarios do not establish a complete native reviewed BReg
  Proposal journey; owning Casework/BReg checkpoint integration remains required.
