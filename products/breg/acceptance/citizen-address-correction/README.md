# Citizen address correction acceptance project

This synthetic Base Registry Engine project proves a citizen correcting their
own registered address through a standing agent, with the citizen confirming
the change and staff deciding it. All names, identifiers, and addresses are
invented.

The registry holds four entities:

- `person`, the registered person;
- `person-address`, the person's current address, whose `patch` requires a
  change request;
- `self-service-link`, a steward-provisioned fact binding a verified principal
  to one person, with an `active` flag;
- `address-correction-request`, a declarative change request with no Rhai. Its
  single effect patches the referenced address with the three proposed values.
  Review is delegated to the `casework` review authority and application is
  manual.

## Access profiles

Every profile binds `sub` as its principal claim, a fixed actor kind, and its
exact requester clients.

| Profile | Actor kind and client | Grants |
| --- | --- | --- |
| `citizen-agent` | `agent`, `citizen-gateway`, no task grant | `get` and `list` on `person-address` through a membership boundary on the active `self-service-link` for the caller, reading only the three address fields, so a list answers with the caller's own linked address and nothing else; `create`, `get`, and `patch` on `address-correction-request`, bound to rows whose `owner` equals `sub`, with `requestVisibility: owner` |
| `citizen-review` | `human`, `citizen-review-page` | `get`, `patch`, `submit_request`, and `cancel_request` on `address-correction-request`, with the same owner row boundary and request visibility; `owner` is not writable. `get` on `person-address` through the same `self-service-link` membership boundary, limited to the same three address fields |
| `reviewer` | `human`, `registry-staff-console` | `get` and `list` on `address-correction-request` |
| `applier` | `human`, `registry-staff-console` | `get` and `apply_request` on `address-correction-request`, with `person-address` as its apply target |
| `steward` | `human`, `registry-staff-console` | creates and reads persons and addresses, and creates, reads, and patches self-service links |

The citizen's agent never submits, revises, cancels, or applies a request, and
holds no direct write on any record. The runtime pins one actor identity to the
gateway client under `authentication.authorityClaims.trustedActors`. A gateway
token must carry the citizen in `sub` and that actor in `act.sub`; without it
the profile does not admit the token.

The two citizen profiles share request ownership. Request visibility and the
owner lifecycle checks key on the verified principal, so a draft the agent
creates is the same draft the citizen's review page reads and submits. The
review page submits with the `ifMatch` of the request it last read, so an agent
edit made after that read makes the submission fail its precondition.

## What the project does not bind

A membership boundary is read-only and cannot be combined with a change-request
lifecycle, and `submitterTargets` requires a same-profile read without
membership checks. The request's `address` reference is therefore not bound to
the caller's own link: a citizen could draft a correction naming another
person's address identifier, although the agent cannot read that address.
Four layers close that gap around the registry:

1. The gateway derives the target from the citizen's own linked address and
   takes no target identifier from tool arguments.
2. The review page reads the draft's target under the citizen's own token and
   refuses to offer submission when that read fails. The `citizen-review`
   profile reads only the citizen's linked address, so a draft naming anyone
   else's address cannot be submitted from the page.
3. Casework staff review confirms that the address belongs to the requester
   before approving.
4. Binding the target to the requester's link inside the registry is a tracked
   follow-up.

## Run it

Check the project from the repository root:

```bash
cargo run --locked -p registry-bregctl -- \
  check products/breg/acceptance/citizen-address-correction
```

The PostgreSQL proof is
[`postgres_citizen_address_correction.rs`](../../../../crates/registry-breg/tests/postgres_citizen_address_correction.rs),
in the postgres lane of `scripts/test-postgres.sh`. It needs a disposable
PostgreSQL 17 database named by `BREG_TEST_DATABASE_URL`:

```bash
BREG_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-breg --features postgres-test,tooling \
  --test postgres_citizen_address_correction
```

It runs `tests/journeys.yaml` through the authenticated runner and the
schema-test receipt, then drives the HTTP router directly for the refusals and
the approval. The review authority is a loopback stub serving one approved
result, and the test records the accepted submission the way reconciliation
records it, so no Casework runtime is started.

## Scripted local run

[`run-local.sh`](run-local.sh) takes one request from MCP tool calls through
review-page submission, the review authority's approval, and the registry's
apply, against the `breg-mcp` and `breg-review` binaries. Run it from the
repository root:

```bash
products/breg/acceptance/citizen-address-correction/run-local.sh
```

It needs Docker and starts a disposable `postgres:17` container on a loopback
port, removed when the run ends. With `BREG_TEST_DATABASE_URL` set to a
PostgreSQL 17 server it uses that server instead, in a fresh database it drops
at the end.

The script builds both binaries and the driver,
[`citizen_local_run.rs`](../../../../crates/registry-breg-mcp/examples/citizen_local_run.rs).
The driver starts the parties the binaries talk to and then the binaries:

| Party | What runs |
|---|---|
| Base Registry Engine | This project, compiled, signed as a package, installed into the fresh database, and served by the engine's verified startup |
| Authorization server | The test authorization server from `registry-platform-testing`, on loopback. It issues the chat host's token, performs the gateway's token exchange, and signs the citizen in to the review page |
| Gateway | The `breg-mcp` binary, from a runtime configuration the driver writes |
| Review page | The `breg-review` binary, from a runtime configuration the driver writes |
| Review authority | **A loopback stub standing in for Casework.** The driver records the approval the way reconciliation records it and the stub serves that one result for the check the engine makes before it applies. No Casework runtime is started |

The driver then acts as the chat host over MCP (`describe_service`,
`get_my_details`, `start_application`, `update_application`,
`prepare_review`), as the citizen's browser on the review page (sign-in, the
review view, submission), as the review authority through the stub, and as
the registry applier. It asks `get_application_status` after each stage and
finishes when the gateway reports `applied` and the stored address carries
the correction. It prints one line per step and no credential.

Between approval and apply the gateway still reports `submitted`: the
`citizen-agent` profile's grant does not name `review_state`, so the agent
reads no review outcome.

The configuration, owner-only secrets, and logs of both binaries go under a
temporary directory, removed after a successful run and kept for diagnosis
after a failed one. Every key in it is generated for the run or is a
committed test fixture.

The same journey runs in process as
`the_citizen_journey_runs_from_chat_to_an_applied_change` in
[`postgres_gateway.rs`](../../../../crates/registry-breg-mcp/tests/postgres_gateway.rs).
