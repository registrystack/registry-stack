# Implementation ownership

Base Registry Engine compiles an authored registry project into a verified
PostgreSQL package and serves its governed operations. Production code carries
no fixture-specific domain types. Record types, Actions, and Proposals are the
public model; canonical projects live under `examples/refactor/`, `acceptance/`,
and `fixtures/`.

| Surface | Owning source and guide |
| --- | --- |
| Authoring, normalized model, diagnostics | `crates/registry-breg/src/contract.rs`, `compiler.rs`, and `schema.rs` |
| Generated CRUD, record reads and mutations | `api/`, `postgres/`, `mutation/`, and [history](HISTORY.md) |
| Immediate atomic plans | `immediate_actions.rs`, `action_handler.rs`, and [Actions](immediate-actions.md) |
| Durable plans and application | `proposal_prepare.rs`, `proposal_store.rs`, `proposal_workflow.rs`, `api/proposals.rs`, and [Proposals](proposals.md) |
| Review integration and deployment trust | `review_store.rs`, `review_integration.rs`, and `runtime_config.rs` |
| Restricted automatic application | Compiled system apply grants and the native Proposal worker, without an executor OAuth client or self-HTTP route |
| Record and Proposal events | `event_destination.rs`, `proposal_hooks.rs`, and [events and webhooks](EVENTS-AND-WEBHOOKS.md) |
| Application contracts and clients | [metadata](metadata.md), `registry-breg-client`, and generated project types |
| Local authoring and operator lifecycle | `registry-bregctl` and [development lifecycle](DEV.md) |

The machine-readable contracts under `contracts/` own delivery requirements and
security traceability. Read the exact row and resolving tests before making an
enforcement claim. A schedule or an offline compiler result does not establish
runtime behavior. [Acceptance journeys](ACCEPTANCE-JOURNEYS.md) maps canonical
projects to their purpose; [agent guidance](AGENTS.md) owns focused check commands.
