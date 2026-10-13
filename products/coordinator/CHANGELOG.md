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
- `invoke-breg-action` calls may route a package-declared, no-effect BReg
  action refusal through `onDeclaredRefusal`. The branch receives only its
  validated `refusalCode`; operational failures and prior uncertain attempts
  retain their existing failure and recovery behavior.
- Add Linux amd64 `coordinator` and `coordinatorctl` binaries and a Docker
  image that carries both, from v0.41.0.
