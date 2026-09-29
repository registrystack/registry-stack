# Registry Platform Activation

`registry-platform-activation` is the single PostgreSQL implementation of the
package activation ledger and its runtime-role boundary for the stateful
Registry Stack products.

The crate owns the product-neutral parts of activation: ledger reads and
appends, deployment database identity checks, active-package startup checks,
schema-version observations, effective single- or split-role analysis,
runtime grants, refusal of indirect write authority, and activation read-back
after a lost commit acknowledgement. A product supplies a small, trusted
`Layout` naming the relations and object prefix its migrations own.

Products retain their package model, migration SQL and destructive-migration
guards, lock order, audit vocabulary, and semantic activation work. Those
steps run in the product's one activation transaction around these primitives.
The shared crate does not interpret a Casework policy, a Scheduling policy, a
Messaging package, or any product authorization rule.

Every split-role apply must call `default_trigger_grant`, perform its product
migrations and hooks, call `grant_runtime_role`, then observe the effective
role before appending the ledger row. Runtime startup must compare both the
configured database identity and verified package digest through
`check_active_package` before serving requests.

