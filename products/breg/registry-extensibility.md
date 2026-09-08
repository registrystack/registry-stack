# Governed facility registration and transfer

BREG owns registry records and their authorized, attributable changes. An
external application owns tasks, scheduling and coordination. This example
shows the boundary using the authored
[facility project](fixtures/facility-registry-actions/registry.yaml), its
[module](fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml)
and [journey](fixtures/facility-registry-actions/tests/journeys.yaml).

The model and operations are configured; the server has no facility-specific
code. The fixture uses ordinary records, references, immediate actions, access
profiles and declared events. The action acceptance guard checks a linked
record under the transaction's existing lock. It does not add a scripting
runtime or run an external check before a write.

## Records and authority

| Record | Meaning | Authority |
| --- | --- | --- |
| Operator | Registered operator code and active/inactive status | The operator administrator can create and maintain it. |
| Facility | Registered code, label and current owner principal | Registration creates it; transfer changes only its owner. The owner can read current records. |
| Initial operator assignment | The operator selected when the facility was registered | Registration creates it atomically with the facility. It is a historical registration fact. |

An operator record's identifier is distinct from the owner principal. The
owner and registrar profiles compare the stored owner with the same verified
scalar `registry_principal` used for actor identity; no duplicate identity
claim is needed. The initial assignment is neither a membership grant nor a promise that the operator
will remain active indefinitely. Inactivating an operator later does not undo
an earlier registration.

`register-facility` creates the facility and assignment in one transaction.
Its assignment refers to the earlier effect using `fromEffect: facility`.
The `facility-registrar` profile permits only this action, including its linked
operator target, and limits the facility owner to the verified principal. It
does not grant direct facility or assignment CRUD.

The action declares its acceptance rule once:

```yaml
requires:
  - {input: operator, field: status, equals: active}
```

`operator` is the required reference input whose public name is `operatorId`.
The action already uses it in the assignment effect. The runtime checks the
current linked record while holding its target lock. The caller cannot satisfy
the requirement by submitting a status value. A failed requirement returns
`412 precondition.failed` and commits neither registration record. See the
[immediate-action contract](immediate-actions.md) for the full supported guard
and target-authority rules.

`transfer-facility` patches only `owner`. Its separate broker profile has an
`allowed_owners` claim with an `in` row boundary. Both the stored owner and the
destination owner must be in that verified claim. The broker receives action
invocation authority, not general facility PATCH. A read-only owner cannot
transfer by editing their record directly.

After transfer, the same valid former-owner token loses current GET and LIST
access. The new owner gains it. This fixture uses direct claim comparison with
the current stored owner; it does not infer access through the initial
assignment or through an organization's membership records. History is
separately granted and governed by its retained authority anchors and current
claims; this fixture grants no history access and makes no history-revocation
claim.

## Author and inspect

Run from the repository root, using the existing tools:

```bash
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

cargo run --locked -p registry-bregctl -- \
  check products/breg/fixtures/facility-registry-actions
cargo run --locked -p registry-bregctl -- \
  --format json explain actions products/breg/fixtures/facility-registry-actions
cargo run --locked -p registry-bregctl -- \
  --format json explain events products/breg/fixtures/facility-registry-actions
```

After editing the module, refresh its source lock with
`bregctl project lock products/breg/fixtures/facility-registry-actions`, then
repeat checking. Generate the compiled action definitions into a fresh output
directory:

```bash
repository_root=$(pwd -P)
artifact_dir=$(mktemp -d "$repository_root/.breg-facility-actions.XXXXXX")
cargo run --locked -p registry-bregctl -- \
  generate actions products/breg/fixtures/facility-registry-actions \
  --output "$artifact_dir/actions"
```

The existing [action authoring and schema-test workflow](immediate-actions.md)
explains package preparation, activation and bearer-token bindings. The
fixture's journey declares its principals, scopes, purposes and direct claims.
Use the same package/sign/apply boundary as other BREG projects; checking source
alone does not activate a registry.

## Invoke and recover

An administrator first creates an operator through
`POST /v1/records/operators?accessProfile=operator-administrator`. Registration
then accepts this action body through `POST /v1/actions/register-facility`:

```json
{
  "input": {
    "facilityCode": "FAC-001",
    "label": "Synthetic facility",
    "owner": "owner-a",
    "operatorId": "00000000-0000-4000-8000-000000000001"
  }
}
```

Use an existing authorized operator identifier in place of the synthetic UUID.
Send the registrar token and a stable `Idempotency-Key` for the submission.
Registration returns identifiers for `facility` and `initial-assignment`.
A lost response is recovered by repeating the identical action with the same
key. A corrected submission gets a new key.

Transfer first obtains an opaque edit condition from
`POST /v1/actions/transfer-facility/target-conditions?accessProfile=facility-transfer`
with `{"input":{"facilityId":"<returned facility identifier>"}}`.
Submit the returned `preconditions` unchanged with the facility identifier and
destination `owner` to the transfer action. A stale condition requires a fresh
user decision; do not silently refresh the edit baseline before submission.
The [journey file](fixtures/facility-registry-actions/tests/journeys.yaml)
covers registration, replay, inactive-operator refusal, a refused destination,
successful transfer and former-owner refusal. Its `directClaims` uses the scalar
`registry_principal` and a string array for the broker's `allowed_owners`
boundary. Fixture metadata repeats the principal value to bind the expected
row boundary; the bearer token carries that claim only once.

## Committed events and external work

The module declares three versioned events: facility registration, initial
assignment and owner change. Their projections contain only the declared
fields; ownership change emits the facility code without exposing owner
principals. Capture commits with records, revisions and the action application.
A rejected or rolled-back action emits no corresponding event.

`facility-events` is a logical webhook destination. Deployment configuration
binds its HTTPS endpoint, classification ceiling and signing secret. It grants
no authority to call BREG. A consumer requesting a subsequent registry change
needs its own narrowly granted token and operation identity.

Use the existing [events and webhooks contract](EVENTS-AND-WEBHOOKS.md) and
[durable receiver example](demo/support/WEBHOOK-RECEIVER.md). Delivery is
asynchronous and can be repeated. Operator replay changes the delivery
idempotency key while preserving the event identity, so consumer business
deduplication must account for the stable CloudEvents source and event ID.
A webhook acknowledgement does not prove an entire external workflow completed.

## Verification and limits

With `BREG_TEST_DATABASE_URL` pointing to an explicitly disposable PostgreSQL
service that permits the existing test harness to create databases and roles:

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked -p registry-breg --features postgres-test,tooling \
  --test postgres_registry_extensibility
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked -p registry-breg --features postgres-test,tooling \
  --test postgres_immediate_action_examples \
  facility_action_example_runs_authorized_transfer_and_emits_schema_test_receipt
```

The focused test compiles the exact locked project and uses the authenticated
HTTP router, PostgreSQL roles and mutation kernel. It covers registration with
an active operator, inactive-operator refusal, late rollback of both records
and their events, receipt replay, constrained transfer, current GET/LIST
revocation using the same JWT, and committed event capture. It does not send a
webhook or claim to prove external execution. The existing webhook suites own
transport verification.

The second test executes the authored journey through the existing schema-test
runner, verified startup and an exact signed package. It validates the resulting
receipt against that package. This covers the scalar and string-set fixture
claims and the complete registration/transfer sequence; it does not start the
external webhook worker.

This fixture does not implement a general cross-record invariant, arbitrary
SQL/Rhai reads during mutations, or a process engine. The operator guard is an
acceptance-time check on a linked input, not a permanent condition on all future
records. The owner profile uses the direct stored-owner model; live relational
[membership authorization](membership-access.md) is a separate policy capability
and requires its own declared model and tests. Existing change-request approval
remains the path when accepting a change requires review.
