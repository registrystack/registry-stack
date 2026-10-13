# Registry Coordinator changelog

## Unreleased

First release of Registry Coordinator.

- The `coordinator` runtime executes finite, acyclic YAML workflows with
  declarative mappings and bounded pure Rhai functions, across durable waits,
  service outages and worker restarts. PostgreSQL stores encrypted progress
  and prepared commands, the operation inventory is fixed, and receiving
  products retain authorization and ownership of every external effect. One
  deployment serves up to sixteen flows, one pinned package per flow.
- `coordinatorctl` authors and checks projects (`init`, `check`, `explain`,
  `test`, `package`), operates a deployment from its runtime file (`plan`,
  `apply`, `deployment-status`), and checks a running service (`doctor`).
- Every refusal of the HTTP API is an RFC 9457 `application/problem+json`
  document whose `type` sits under
  `https://id.registrystack.org/problems/registry-coordinator/`. The
  generated OpenAPI document lists the codes each operation can answer.
- The Coordinator client covers `start`, `list`, `status`, `inspect`,
  `reconcile`, `retry_same` and `cancel` as
  `registry_stack_client::coordinator` in Rust and the `coordinator`
  namespace of the unified Node.js and Python clients.
- `submit-review-request` and `cancel-review-request` hand work to Casework
  human review as a review producer, and a `wait-for` step on a
  `review-result` event waits for the reviewer's result.
- Coordinator joins the unified clients from v0.42.0. Runtime binary and image
  publication remain held until package permissions and Coordinator-specific
  advisory evidence are ready; source builds are available meanwhile.
- The reviewed-notice example and runnable tutorial coordinate a BReg record,
  Casework review and one Messaging notice, with fresh revision and permission
  checks before delivery and a recipient read from BReg.
- Review waits can author `onCancel` cleanup. Cancellation records durable intent
  and lets that path withdraw the original review across worker restarts; repeated
  cancellation preserves the cleanup. Protected state schema version 2 refuses
  earlier pilot namespaces rather than silently adopting an incompatible layout.
- Run discovery supports bounded cursor pagination, effective-state filters and
  an attention filter through HTTP, CLI and the Rust, Node.js and Python clients.
