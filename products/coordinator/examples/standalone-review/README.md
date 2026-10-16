# Standalone review project

Use this source-neutral project to submit bounded context to Registry Casework under a selected
review policy, wait for its result, and withdraw explicitly on timeout or operator cancellation.
The project needs no Base Registry Engine connection and creates no registry effect.

From the repository root:

```sh
coordinatorctl check --project products/coordinator/examples/standalone-review --explain
coordinatorctl test --project products/coordinator/examples/standalone-review
```

The workflow input uses the `casework.submit-review-request/v1` contract: a `policy` selection,
subject, requester reference, and reviewer context. Select a policy by ID by default; include both
version and digest when an exact policy is required. Casework freezes a concrete PolicyBinding
at first acceptance. Completion must match that accepted binding, subject, and submission digest.
Retries preserve the original request and key, including its original policy selection. Casework
owns reviewer authority, policy validation, and terminal outcomes.

`submit` exposes `result`. `await-result` uses
`completion: {step: submit, name: result}` for up to fourteen days within a thirty-day deadline.
A settled result finishes `review-result`. Timeout and operator cancellation take separate authored
withdrawal paths through `casework.cancel-review-request/v1`; their typed outputs preserve whether
withdrawal succeeded or a reviewer had already decided. `already-terminal` is not a withdrawal.
Repeated cancellation preserves durable cleanup.

Use `type: casework-review-producer` for the runtime connection. Its profile and producer must
match the Casework declaration, and its ordinary service identity must be independently admitted.
It accepts no task authority. Pending reads default to 900 seconds. Optional authenticated
completion wake-ups bring an eligible read forward without bypassing the durable floor or
providing trusted decision data. Unavailable, refused, invalid, or mismatched evidence cannot
become a negative business outcome. Inspect held work and recover under the original deadline.

Choose the policy from the owning Casework project's `caseworkctl check` report under
`policyBindings`. Use its ID for default selection, or its complete ID, version and digest for
strict selection. The offline scenarios exercise exact synthetic bindings; those digests are not
deployment values. Configure the matching trusted producer, service credentials, completion
destination, and Coordinator caller policies. The template contains synthetic HTTPS
endpoints and secret references. Adapt it outside the package and follow the
[deployment runbook](../../DEPLOYMENT.md).

Offline scenarios check results, timeout, cancellation, and races with synthetic replies.
Maintained Casework-client HTTP checks and Coordinator PostgreSQL checks cover the independent
boundary, correlation, durable waits, and cleanup. None of these imply a Base Registry Engine application or
Messaging delivery.
