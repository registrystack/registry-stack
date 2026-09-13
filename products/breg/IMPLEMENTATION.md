# Implementation schedule

The product is delivered through small vertical slices. The canonical schedule
is `contracts/implementation-schedule.yaml`.

1. **W0:** publish validated contracts, a non-person authored fixture, the two
   crate boundaries, and one CI ownership path.
2. **W1:** compile a strict, deterministic effective model and all Slice 0
   inventories from one source of truth.
3. **W2:** prove the PostgreSQL role, RLS, advisory-lock, and connection-pool
   design against a real PostgreSQL instance.
4. **W3:** add the real REST router, request authorization, revisions,
   idempotency, audit ordering, and transactional outbox as one path.
5. **W4:** add verified packages, migrations, activation, and recovery.
6. **W5:** complete the pilot tooling, bounded data operations, webhooks,
   generated baselines, selector/read-path samples, and five coequal adopter
   journeys.

No wave creates a generic storage framework, package framework, plugin runtime,
workflow engine, or second database client abstraction merely in anticipation
of future needs.

## Capability state within W5

W5 is the current wave in `contracts/implementation-schedule.yaml`. Each
capability below is authored configuration over the same binaries, and each is
bound to executable proof in `contracts/definition-of-done.yaml`. Enforced
means the surface and its refusals are proven on that revision. Trial means the
surface is implemented and tested but its authoring contract is not frozen for
Version 1.

| Capability | State | Proof |
| --- | --- | --- |
| Governed Rhai action handlers under `registry.action-handler/v1`, with declared write slots, declared refusals, and input-only evaluation | Enforced | `immediate_action_handler.rs` and `postgres_action_handlers.rs`, over `acceptance/person-registration-rhai` |
| Acceptance-time target requirements that check a stored field of an existing reference target | Enforced | `postgres_immediate_action_requirements.rs` and `postgres_registry_extensibility.rs`, over `fixtures/facility-registry-actions` |
| Native persisted field patterns compiled to one validated PostgreSQL CHECK per field | Enforced | `native_patterns.rs`, `postgres_migration.rs`, and `schema_fingerprint_rehearsal.rs` |
| Current membership read boundaries on read permissions, enforced by generated `SECURITY INVOKER` functions and forced row-level security | Enforced | `membership_access.rs` and `postgres_membership_access.rs`, over `fixtures/organization-membership-access` |
| Change-request `submitterTargets`, rechecking current same-profile target authority under a transaction-scoped lock at create, draft patch, submit, revise, and replay | Enforced | `compiler_submitter_targets.rs` and `support/submitter_targets.rs`, over `starters/professional-licences/core` |
| Conditional Evidence in Rhai under `registry.action-handler/v2`, calling `evidence::resolve` inside a governed action | Trial | `action_evidence_compiler.rs` and `postgres_action_evidence.rs`, over `acceptance/farmer-landholding-evidence` |
| Protected evidence-use retention and the operator command `bregctl evidence-retention erase-expired` | Trial | `postgres_action_evidence_retention.rs` and `crates/registry-bregctl/tests/evidence_retention.rs` |
| `bregctl init --from publicschema`, deriving a project from the pinned offline snapshot by `--starter`, `--selection`, or terminal selection | Enforced | `crates/registry-bregctl/src/init_from_model/` unit tests and `crates/registry-bregctl/tests/cli.rs` |
| Four published starters under `starters/*/core`, with `bregctl init --template <ID>` creating a project from one and `bregctl examples list` and `bregctl examples run` describing and running its scenarios | Enforced | `starter_projects.rs`, `support/starter_policy.rs`, `crates/registry-bregctl/src/starters.rs`, and `crates/registry-bregctl/src/dev/examples.rs` |
| `bregctl dev [project]`, reading the project's `dev-clients.yaml` without a flag | Enforced | `crates/registry-bregctl/src/dev/tests.rs` and `crates/registry-bregctl/tests/dev_lifecycle.rs` |

The two trial rows are the ABI and helper that `immediate-actions.md` and
`EVIDENCE.md` describe as a trial. `registry.action-handler/v1` input-only
actions keep their own path, and the retained evidence-use scope the operator
command erases exists only for the trial ABI. The contract grammar has no trial
state, so `contracts/definition-of-done.yaml` records each of them as `partial`
and names the trial in its `gap`.
