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
| `citizen-agent` | `agent`, `citizen-gateway`, no task grant | `get` on `person-address` through a membership boundary on the active `self-service-link` for the caller, reading only the three address fields; `create`, `get`, and `patch` on `address-correction-request`, bound to rows whose `owner` equals `sub`, with `requestVisibility: owner` |
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
