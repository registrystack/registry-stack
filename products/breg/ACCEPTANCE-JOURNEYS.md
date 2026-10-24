# Acceptance journeys

The maintained BReg projects live in `acceptance/`, `fixtures/`, and
`examples/`. They are ordinary governed configuration, not production
Rust domain types. Tests load the canonical project files directly; no second
native-model mirror is maintained under the test tree.

## Start with the native model

| Project | Purpose |
| --- | --- |
| `examples/minimal` | Generated contact CRUD, claim-bound row authority, local clients, journeys, and a resumable scenario |
| `examples/reviewed-change` | One fixed-plan reviewed name correction and default automatic application |
| `examples/facility` | Reusable value types and a named function, immediate multi-record registration, reviewed automatic correction, explicit manual no-review work, and typed application clients |
| `fixtures/action-plan-branches` | Offline Rhai success, declared refusal, and value-free handler-result failure expectations for `bregctl project action-test` |

[Standalone examples](examples/README.md) owns their focused PostgreSQL
commands and verification boundaries. The built-in executor applies an exact
frozen submission under its compiled system grant. External review remains an
optional authenticated dependency; its absence disables dependent operations.

## Product coverage

The broader projects in `acceptance/` cover business and establishment records,
facilities, inspections, asset placements, spatial service sites, historical
queries, Registry Record envelopes, Rhai registration, conditional Evidence,
and issuer portability. The narrower `fixtures/` projects isolate compiler,
permission, Action, and query behavior. Consult the owning test and
`contracts/security-test-traceability.yaml` for the exact enforcement claim.

The [`action-plan-branches` fixture](fixtures/action-plan-branches/README.md)
also distinguishes the compiler's narrow direct-literal check from executable
coverage for helper-returned, computed, and dynamically assembled outcomes.

`products/breg/scripts/test-postgres.sh` selects the real-PostgreSQL lane.
`products/breg/scripts/check-contracts.sh` checks product contracts and generated
artifacts. Those commands may compile Rust or require services; see
[agent guidance](AGENTS.md#checks-per-change-kind) before running them.
A compiler check does not prove HTTP authorization or a database transaction.

## External delivery

The [durable webhook receiver](examples/webhook-receiver/README.md) is a separate
acceptance example. It verifies the event contract and signature, persists exact
acceptance before acknowledgement, and deduplicates retry/replay across restart.
Its focused Python behavioral tests start a temporary loopback listener. The
receiver provisions no registry, issuer, or webhook destination.
