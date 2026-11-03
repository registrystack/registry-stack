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

The checked-in Action contract is a synthetic authoring fixture. A deployment
must replace it with the operator-generated contract from the exact active
BReg package, and must replace the synthetic review-policy digest in
`functions.rhai` with the binding reported by `caseworkctl check`. Coordinator
package checking then pins both values.

Coordinator currently exposes state/attention, Proposal following, and Run
turn operations needed by this journey. It has no Run-list filter by finish
outcome. `GET /v1/runs?attention=true` remains sufficient for stopped or failed
work; it does not replace Casework for revised items requiring a person.
