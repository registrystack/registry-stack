# Kobo household Coordinator workflow

This reviewed package is the maintained workflow for `../job.coordinator.yaml`.
One workflow owns two signed event triggers and one common input:

- `submission-received` maps a literal `first-seen` discriminator and the
  complete event `data`, maps the projection in pure Rhai, submits one pinned
  BReg Proposal Action, and follows `applied`, `rejected`, `cancelled`, or
  `returned`.
- `submission-revised` maps a literal `revised` discriminator and the same
  data shape. It performs an existing-only BReg lookup. Both a resolved target
  and the deliberately indistinguishable `lookup.unresolved` path open a real
  Casework request and wait for its result. Neither path revises, applies, or
  creates a registry record automatically. A revised event does not require
  `priorRunId`.

A Run finishes with one named outcome per branch: `proposal-applied`,
`proposal-rejected`, `proposal-cancelled`, `proposal-timeout`,
`revised-reviewed` (the lookup resolved), `unresolved-reviewed` (the lookup did
not resolve), `returned-reviewed`, and `review-timeout`. A review or Proposal
that nobody answers within fourteen days finishes as `review-timeout` or
`proposal-timeout`; the workflow language has no step that raises attention, so
these are ordinary finished Runs. The Adapter has already acknowledged the
source item by then, so an operator who wants to catch timeouts lists them by
outcome: `coordinatorctl list --outcome review-timeout` and
`coordinatorctl list --outcome proposal-timeout` (the same filter is
`GET /v1/runs?outcome=review-timeout`).

`scenarios.yaml` runs the revised branches and the timeout offline:
`coordinatorctl test --project .`.

The checked-in Action contract is a synthetic authoring fixture. A deployment
must replace it with the operator-generated contract from the exact active
BReg package, and must replace the synthetic review-policy digest in
`functions.rhai` with the binding reported by `caseworkctl check`. Coordinator
package checking then pins both values.

Coordinator currently exposes state/attention, Proposal following, finish
outcome, and Run turn operations needed by this journey.
`GET /v1/runs?attention=true` remains sufficient for stopped or failed
work; it does not replace Casework for revised items requiring a person.
