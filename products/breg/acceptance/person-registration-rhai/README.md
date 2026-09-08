# Rhai person registration

This synthetic project implements two immediate actions through the existing
BREG compiler, package lifecycle and HTTP API. `register-person` preserves a
13-digit identifier string and computes `displayName` from supplied name parts.
`register-person-with-registration` also demonstrates coordinated creates,
symbolic references and an optional patch of an existing register.

Only `identifier` and `display-name` are person fields. The `givenName` and
`familyName` inputs are transient. The scripts trim their outer whitespace,
join nonempty parts with one space, and preserve internal spaces and case.
Either part can be omitted, null or blank. With no nonblank part, the handler
returns the declared `blank-name` refusal.
This is an example name policy and identifier format, not a national identifier
specification or checksum.

## Authored contract

[registry.yaml](registry.yaml) is the complete project. The simple action uses:

```yaml
handler:
  kind: rhai
  script: scripts/register-person.rhai
  abi: registry.action-handler/v1
  refusals:
    - {code: blank-name, label: At least one name part is required.}
  writes:
    - id: person
      target: {entity: person}
      operation: create
      fields: [identifier, display-name]
```

This ABI accepts declared scalar inputs, including reference IDs. It does not
accept `crs84-point`, `structured`, or arbitrary JSON object or array values.
String and text inputs must declare `maxLength` of at most 4,096 Unicode scalar
values so every value fits Rhai's 16,384-byte UTF-8 string budget. This project
uses 13 characters for the identifier and 80 for each name part. Other scalar
types retain their own bounds, and decimal values use canonical JSON strings.
Every input string also has a 16,384-byte admission limit, including timestamps.
An HTTP request exceeding a declared bound or this byte limit returns
`400 request.invalid` before the handler runs. A project with an overlarge
`maxLength` must reduce it; use fixed effects for actions needing point or
structured inputs.

The [handler](scripts/register-person.rhai) exports `fn handle(ctx)` and reads
logical input IDs such as `ctx.inputs["given-name"]`. An omitted optional input
has no map key; an explicit JSON `null` has a key with Rhai's unit value `()`.
The scripts treat both as an empty name part, using this guard before trimming:

```rust
let family = if "family-name" in ctx.inputs && ctx.inputs["family-name"] != () {
    ctx.inputs["family-name"]
} else { "" };
family.trim();
```

Test membership with `in` when absence matters. Calling string methods on an
unguarded missing or null value fails handler execution. Required inputs such
as `identifier` still reject omission and null before the handler runs.
This optional-null behavior belongs to the handler ABI; fixed-effect actions
reject explicit null inputs.

The handler returns either
`{effects: [...]}` or `{refusal: {code: "blank-name", field: "given-name"}}`
using Rhai map syntax `#{...}`. An effect selects a declared slot by `id` and
supplies typed `set` values and, for optional patch fields, `clear` field IDs.
The host owns the target, operation, IDs, authority, validation and transaction.
There is no database, filesystem, network, clock or stored-record API in Rhai.

Each action declares exactly one of fixed `effects` or `handler`. The handler's
`writes` are a ceiling, not CRUD permission. `person-registrar` can invoke the
actions and receive their result references, but has no ordinary entity write
grant. `person-reader` independently grants reads; `person-administrator`
supplies ordinary creates and patches for the comparison and register setup.

The stored identifier uses `pattern: '^[0-9]{13}$'` with `maxLength: 13`.
[PostgreSQL native patterns](../../native-patterns.md) enforce the expression on
every write path. Requiredness is
separate. Patterns are not silently converted into JavaScript regular
expressions or JSON Schema patterns. Offline checks validate structure and
bounds; PostgreSQL-backed schema tests validate expression syntax and storage
integrity. Ordinary CRUD never runs these action handlers: a direct create
requires a supplied `displayName`, which it preserves as supplied.

## Local computation checks

Run these commands from the monorepo root. To build the local binary:

```bash
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
cargo build --locked -p registry-bregctl
bregctl="${CARGO_TARGET_DIR:-target}/debug/bregctl"
```

For an installed release instead, set `bregctl=$(command -v bregctl)`. Then run:

```bash
person_project=products/breg/acceptance/person-registration-rhai
"$bregctl" check "$person_project"
"$bregctl" --format json explain actions "$person_project"

for person_case in full-name given-only family-only null-given null-family \
  internal-spaces blank-name omitted-name null-name; do
  "$bregctl" project planner-test "$person_project" \
    --action register-person \
    --input "$person_project/examples/$person_case.input.json" \
    --expect "$person_project/examples/$person_case.expect.json"
done
for person_case in coordinated registration-only patch-only person-only; do
  "$bregctl" project planner-test "$person_project" \
    --action register-person-with-registration \
    --input "$person_project/examples/$person_case.input.json" \
    --expect "$person_project/examples/$person_case.expect.json"
done
```

Local `--input` JSON is a synthetic handler context keyed by authored IDs:
`given-name`, `family-name`, `register`. HTTP uses the public `apiName` keys:
`givenName`, `familyName`, `registerId`. Local files have no outer `input`
envelope. The separate [HTTP body](examples/register-person.http.json) uses the
HTTP envelope and names. Do not pass it as `--input`.

Project, `--input` and `--expect` paths must resolve through physical directories
without symlinks. On macOS use `/private/tmp/...` instead of `/tmp/...` for a
disposable copy, or keep it under the repository and locate it with `pwd -P`.

`--expect` compares exact canonical effects or refusal, including computed
values, against the explicit synthetic expectation file. Default reports expose
identity, field names, shapes and counts, without dumping input values, record
IDs or source. A mismatch reports a path without disclosing the values.
These checks prove calculation and decoding, not PostgreSQL patterns, target
existence, grants, locks, conditions, atomicity or delivery.
`check` reports that the identifier's native pattern is unverified offline;
the PostgreSQL journey below validates its syntax and enforcement.

If the local check fails, repair the input or source identified by its diagnostic:

- `action.input.invalid` means admission failed before Rhai ran. Use the local
  authored input IDs, remove the HTTP envelope, and meet the input's type and
  bounds.
- `action.handler.parse` or `action.handler.entrypoint` identifies script syntax
  or the missing `fn handle(ctx)` entry point. Correct the script at the reported
  action path.
- `action.handler.result` or `action.handler.ceiling` identifies an invalid
  result. Correct the named slot or field, or deliberately update its governed
  declaration, then rerun the expectation case.
- An expectation mismatch reports the differing path. Compare it with the
  synthetic fixture locally; change the expectation only when the new business
  behavior is intended.

## PostgreSQL and package journey

Use the existing disposable TLS PostgreSQL setup documented in
[the action guide](../../immediate-actions.md#runnable-schema-test-journey).
With `BREG_TEST_DATABASE_URL` and `BREG_TEST_TLS_CA_PEM_PATH` supplied by that
setup, run:

```bash
products/breg/scripts/test-immediate-action-examples.sh
```

The default run includes both fixed-action fixtures and this project's
[authored journeys](tests/journeys.yaml). Use
`--rhai-project /private/tmp/edited-person-project` to select an edited copy.
`--env /absolute/physical/path/test.env`
loads an existing trusted environment file. `--installed` uses the `breg` and
`bregctl` on `PATH`. The runner uses isolated databases and roles, private
credentials, and the existing `bregctl test` candidate and receipt workflow.
It also checks that an invalid native expression receives a field-addressed
schema-test refusal on an empty database. It then packages the exact tested
candidate, signs externally, applies and verifies it in a second fresh database,
and starts the real `breg` binary. The live check verifies metadata, the computed
value through GET, action-only authority, receipt replay and the declared
refusal. It removes only its own temporary resources.

The journeys verify padded, omitted and null name parts through authorized GETs,
blank-name refusal (with `expect.refusalCode: blank-name`), duplicate identifiers,
invalid stored formats (with `expect.entityId: person` and
`expect.fieldId: identifier`), lost-response
replay, changed-input conflict, the direct CRUD distinction, coordinated writes,
and omitted patch conditions and requirements. Person and registration creates
retain the configured events. The runner binds `person-events` to a synthetic
non-delivery destination; it does not prove transport delivery to a consumer.
For a deployed application, bind that logical destination through the existing
[events and webhooks](../../EVENTS-AND-WEBHOOKS.md) configuration.

For a long-running manual instance, use the normal
[quickstart lifecycle](../../quickstart/README.md) with this project: test the
candidate, package the exact tested bytes, sign with the configured authority,
apply and verify with migration authority, then serve with runtime authority.
The script, ABI, inputs, refusal catalogue and write ceiling are hash-covered.
Changing a script requires testing and packaging the changed project; it does
not require changes to server Rust. An edited module project must refresh its
module lock through `bregctl project lock` as usual; this inline project has no
module lock to edit.

## HTTP invocation and authorized read

Assume that this package is served at `BREG_BASE_URL`, and that `PERSON_ACTION_CURL_CONFIG`
and `PERSON_READER_CURL_CONFIG` are private curl configuration files containing
bearer authorization for the profiles below. Keep token contents out of command
history. The invocation needs no condition token because it only creates:

```bash
curl --config "$PERSON_ACTION_CURL_CONFIG" --silent --show-error \
  --request POST "$BREG_BASE_URL/v1/actions/register-person" \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: person-registration-001' \
  --data-binary @products/breg/acceptance/person-registration-rhai/examples/register-person.http.json \
  --output person-registration-receipt.json
```

The existing application receipt's `results.person` contains `entity: person`,
`recordId` and `revision`. It is a record reference. Extract the actual returned
ID and use the `people` route under independently sufficient read authority:

```bash
person_id=$(python3 -c 'import json; print(json.load(open("person-registration-receipt.json"))["results"]["person"]["recordId"])')
curl --config "$PERSON_READER_CURL_CONFIG" --silent --show-error \
  "$BREG_BASE_URL/v1/records/people/$person_id?accessProfile=person-reader" \
  --output registered-person.json
```

The authorized record response shows `identifier: "0123456789012"` and
`displayName: "Mina Example"`. The name parts are not person fields.

| Profile | Scope | Purpose | Use |
| --- | --- | --- | --- |
| `person-registrar` | `registry:person:register` | `person-registration` | Invoke both actions and obtain register conditions |
| `person-reader` | `registry:person:read` | `person-registration-audit` | Read people, registrations and registers |
| `person-administrator` | `registry:person:manage` | `person-maintenance` | Set up registers and demonstrate ordinary CRUD |

All profiles require a verified `registry_principal` claim. A business refusal
returns `422 action.refused`, `refusalCode: blank-name`, the configured static
label in `detail`, and `fieldPath: /input/givenName`. It commits no person,
registration, successful receipt or event. Correct the indicated name input and
resubmit. The same key can be used after this refusal because it has no stored
successful receipt; the live journey verifies that recovery.

A thrown script error or invalid output returns `500 action.handler_failed`.
The operator should use the bounded diagnostic to identify the action, slot or
field, repair and test the project, then package and activate the corrected
candidate. Do not change caller input merely to work around a package fault.
An exhausted deadline remains `503 service.unavailable`.

Repeat the identical committed request with the same idempotency key after a
lost response. Compatible replay returns the existing receipt under current
authority without reevaluating the handler or creating a second event. Reusing
a consumed key with changed input is `409 idempotency.conflict`; a separate key
with the same identifier is `409 mutation.conflict` because of uniqueness.

## Coordinated effects and omission

The [second handler](scripts/register-person-with-registration.rhai) always
emits `person`. When `recordRegistration` is true it emits `registration`,
linking the newly created person with `{fromEffect: "person"}` and the selected
existing register with `{fromField: "register"}`. When `updateRegister` is true
it emits the `register` patch setting `last-person` from the created person.
All selected effects commit together. Setting either flag false omits that
slot's write and receipt result. No script-supplied raw record ID becomes a
reference effect.

Create an active register with `person-administrator`, capture its actual ID,
and obtain its condition with the invoking profile:

```http
POST /v1/actions/register-person-with-registration/target-conditions

{"input":{"registerId":"<actual register ID>"}}
```

Save the returned `preconditions.registerId.ifMatch` with the form. Invoke with
that same saved condition:

```json
{
  "input": {
    "identifier": "0123456789013",
    "givenName": "  Mina  ",
    "familyName": " Example ",
    "registerId": "<actual register ID>",
    "registrationCode": "SYNTH-REG-001",
    "recordRegistration": true,
    "updateRegister": true
  },
  "preconditions": {"registerId": {"ifMatch": "<saved condition token>"}}
}
```

The compiled action still admits and authorizes `registerId`, locks that target,
checks `active: true`, and requires the current patch condition when
`updateRegister: false`, even when both flags are false. Omission changes only
writes and results. It does not provide conditional authority or conditional
input admission. A missing condition is `400 request.invalid`; stale conditions
or failed `requires` return `412 precondition.failed`. Retain the user's form,
recheck the target, and confirm current input before resubmitting with a refreshed
condition. Do not silently refresh immediately before submission.

Immediate handlers calculate one atomic invocation. Existing change-request
planners still compute retained proposals through `ctx.request`; review and
later apply use frozen effects. Existing webhooks deliver committed events
after commit and can retry independently. A failed delivery cannot undo a
committed registration.
