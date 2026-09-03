# Immediate Action Configuration Examples

Immediate actions are named, configuration-defined writes that run as one
authenticated mutation. They are useful when an application needs one button to
create or patch several records, while the server still owns the effect graph,
authorization, concurrency checks, idempotency, audit, events, and receipt.

The two fixtures in this directory are intentionally small:

- `fixtures/asset-registration-actions` creates an asset and its initial
  inspection in one action. The grant returns only the `asset` effect in the
  action receipt, so callers do not receive the `initial-inspection` reference.
- `fixtures/household-contact-actions` creates a person and membership, then
  patches the selected household's contact reference. It also links a service
  center by reference. The household reference requires a condition read because
  it is patched. The service-center reference is checked for existence and row
  authority because it is only linked.

These examples do not weaken reviewed change control. If an entity declares
`changeControl.requiredFor` for the operation an immediate action would perform,
the action is refused at compile time. Use a reviewed change-request fixture for
that workflow instead of granting an immediate action. The household example is a
separate direct-action fixture, not a shortcut around
`publicschema-household-change-requests`.

## Authoring Shape

Actions live in project or module configuration under `actions`. Inputs use the
same field-type grammar as entity fields, but they are not persisted and cannot
declare `validTimeRole`. Effects are inline and fixed. This complete create-only
action from `fixtures/asset-registration-actions` creates an asset, creates the
initial inspection, and links the inspection with the reserved asset identity:

```yaml
actions:
  - id: register-asset-with-inspection
    inputs:
      - {id: asset-code, apiName: assetCode, type: string, required: true, maxLength: 64, classification: internal}
      - {id: label, type: string, required: true, maxLength: 200, classification: internal}
      - {id: asset-type, apiName: assetType, type: vocabulary-code, vocabulary: asset-type, required: true, classification: internal}
      - {id: jurisdiction, type: string, required: true, maxLength: 80, classification: internal}
      - {id: observed-at, apiName: observedAt, type: timestamp, required: true, classification: internal}
      - {id: inspection-result, apiName: initialResult, type: vocabulary-code, vocabulary: inspection-result, required: true, classification: internal}
    effects:
      - id: asset
        target: {entity: asset}
        operation: create
        set:
          asset-code: {fromField: asset-code}
          label: {fromField: label}
          asset-type: {fromField: asset-type}
          jurisdiction: {fromField: jurisdiction}
      - id: initial-inspection
        target: {entity: asset-inspection}
        operation: create
        set:
          asset: {fromEffect: asset}
          observed-at: {fromField: observed-at}
          result: {fromField: inspection-result}
          jurisdiction: {fromField: jurisdiction}
```

HTTP callers use public API names such as `assetCode`, `assetType`,
`observedAt`, and `initialResult`. Effect mappings use logical input IDs such as
`asset-code`, `asset-type`, `observed-at`, and `inspection-result`.

To rename a public action input, edit its `apiName` under
`actions[].inputs` in the module, then update that action's caller input keys in
`tests/journeys.yaml`. Keep the logical input `id` and effect mappings unchanged.
For example, renaming the action input `assetCode` to `assetTag` does not rename
the persisted entity field at `entities[].fields`, which may still expose
`assetCode`. After a module edit, run `bregctl project lock <project>`
before repeating check, explain, generate, and the schema-test journey below.

An action grant is exclusive. It names `action`, uses only `operations:
[invoke]`, and supplies target authority for every entity that the compiled
effect graph creates, patches, or references:

```yaml
grants:
  - action: register-household-contact
    operations: [invoke]
    targets:
      - entity: household
        rowBoundaries:
          - {field: district, claim: district, operator: equals}
      - entity: person
        rowBoundaries:
          - {field: district, claim: district, operator: equals}
      - entity: group-membership
        rowBoundaries:
          - {field: district, claim: district, operator: equals}
      - entity: service-center
        rowBoundaries:
          - {field: district, claim: district, operator: equals}
    results: [person, membership, household]
```

Do not add `readableFields`, `writableFields`, query fields, request-stage
fields, SQL fragments, or Rust customization to an action grant. The action
contract and typed entities define the writable ceiling, and `results` controls
which minimal record and revision references appear in the application receipt.

For ordinary entity grants, keep boundary-bearing fields out of patch grants
unless moving a row between caller-visible boundaries is intentional and reviewed.
The household fixture splits setup authority from maintenance authority:
`household-operator` can create required `district` values for seed households
and service centers, while `household-maintainer` can patch only
`household-name`. The action patch of `contact-person` is governed by the
`contact-registrar` action grant and its target row boundaries.

## Local Checks

Run checks from the repository root. These commands validate the authoring
projects without opening a database:

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  check products/breg/fixtures/asset-registration-actions

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  check products/breg/fixtures/household-contact-actions
```

Inspect the compiled surface:

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  --format json explain actions \
  products/breg/fixtures/household-contact-actions

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  --format json explain routes \
  products/breg/fixtures/household-contact-actions

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  --format json explain model \
  products/breg/fixtures/household-contact-actions
```

Generate review artifacts into a new directory. The command refuses to merge
with an existing output directory. Use a repository-owned temporary directory so
macOS `/tmp` symlinks do not change the path seen by follow-up tooling:

```bash
repository_root=$(pwd -P)
artifact_dir=$(mktemp -d "$repository_root/.breg-actions.XXXXXX")

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  generate actions products/breg/fixtures/household-contact-actions \
  --output "$artifact_dir/actions"

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  generate openapi products/breg/fixtures/household-contact-actions \
  --output "$artifact_dir/openapi"

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  generate schemas products/breg/fixtures/household-contact-actions \
  --output "$artifact_dir/schemas"

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  generate sql products/breg/fixtures/household-contact-actions \
  --output "$artifact_dir/sql"
```

Project directories must also use canonical, non-symlink paths. On macOS, prefer
`/private/tmp/...` over `/tmp/...` for disposable project copies, or keep the
copy under the repository and use `pwd -P` before invoking the CLI.

## Runnable Schema-Test Journey

Run both immediate-action schema-test suites with the local runner. It expects
the same isolated TLS PostgreSQL environment used by the existing
[change-request examples](CHANGE_REQUEST_EXAMPLES.md). The runner creates unique
synthetic databases and roles, writes owner-only runtime configuration, JWTs,
token references, schema-test credentials, reports, and receipts under a
repository temporary directory, calls the real `bregctl test`, and
then removes the resources it created.

With `BREG_TEST_DATABASE_URL` and
`BREG_TEST_TLS_CA_PEM_PATH` exported by that PostgreSQL setup, run:

```bash
products/breg/scripts/test-immediate-action-examples.sh
```

If your setup keeps these exports in an existing owner-only shell file, pass
`--env /absolute/physical/path/to/test.env`. Only source a file you trust; the
runner executes its shell contents. Do not serialize secret values into shell
code or include credentials in command history.

For edited fixture copies, pass `--asset-project /private/tmp/path/to/copy` or
`--household-project /private/tmp/path/to/copy`. The runner reads
`package.environment`, `package.instanceId`, and `package.sourceRevision` from
each selected `registry.yaml`, so the runtime binding matches the candidate
under test.

The schema-test credentials must bind every journey step to a bearer token whose
verified claims satisfy the selected profile:

| Profile | Required principal claim | Required scope | Required purpose | Direct claim |
| --- | --- | --- | --- | --- |
| `asset-action-registrar` | `registry_principal` | `registry:asset:register` | `asset-registration` | `jurisdiction` equals the action target row boundary |
| `asset-auditor` | `registry_principal` | `registry:asset:audit` | `asset-audit` | `jurisdiction` equals the read row boundary |
| `household-operator` | `registry_principal` | `registry:household:operate` | `household-administration` | `district` equals create and read row boundaries |
| `household-maintainer` | `registry_principal` | `registry:household:maintain` | `household-maintenance` | `district` equals the patched household row boundary |
| `contact-registrar` | `registry_principal` | `registry:contact:register` | `contact-registration` | `district` equals every action target row boundary |

To serve a packaged fixture for manual HTTP calls, use the normal Registry
BReg lifecycle from the [quickstart](quickstart/README.md),
[local demo](demo/README.md), and
[change-request examples](CHANGE_REQUEST_EXAMPLES.md): run `bregctl
test`, package the exact tested candidate, apply it with the migration
authority, verify it, then start `breg` with the runtime config used
for that package. The scripts [quickstart/run.sh](quickstart/run.sh),
[demo/run.sh](demo/run.sh), and
[test-change-request-examples.sh](scripts/test-change-request-examples.sh) show
the runtime file shape, Mint setup, loopback server start, schema-test credential
binding, and owner-only token files. Keep bearer tokens in files or environment
variables, not in shell history or logs.

## HTTP Invocation

The HTTP examples below assume a served `household-contact-actions` or
`asset-registration-actions` package and profile-specific token files created by
your local lifecycle. Curl config files are created under
`$HOME/.breg-local` with `umask 077`, so bearer tokens are not placed
on curl's process command line.

Create-only actions need no condition read. A caller with a bearer token for the
`asset-action-registrar` profile can invoke the asset example directly:

```bash
umask 077
mkdir -p "$HOME/.breg-local"
read -r asset_registrar_token < "$ASSET_REGISTRAR_TOKEN_FILE"
asset_curl_config=$(mktemp "$HOME/.breg-local/asset-action.XXXXXX")
printf '%s\n' \
  'silent' \
  'show-error' \
  'request = "POST"' \
  "url = \"$BREG_BASE_URL/v1/actions/register-asset-with-inspection\"" \
  "header = \"Authorization: Bearer $asset_registrar_token\"" \
  'header = "Content-Type: application/json"' \
  'header = "Idempotency-Key: asset-registration-actions-001"' \
  'data = "@asset-registration-input.json"' \
  > "$asset_curl_config"
curl --config "$asset_curl_config"
rm -f "$asset_curl_config"
```

`asset-registration-input.json`:

```json
{
  "input": {
    "assetCode": "ASSET-ACTION-001",
    "label": "Synthetic generator",
    "assetType": "equipment",
    "jurisdiction": "north-district",
    "observedAt": "2026-09-01T08:30:00Z",
    "initialResult": "passed"
  }
}
```

For a patch-capable action, first seed or create the target records with ordinary
authorized record creates. Capture the IDs from the actual create responses and
reuse those IDs in the condition and invoke requests.

```bash
umask 077
mkdir -p "$HOME/.breg-local"
read -r household_operator_token < "$HOUSEHOLD_OPERATOR_TOKEN_FILE"

cat > household-create.json <<'JSON'
{
  "data": {
    "householdCode": "HH-ACTION-HTTP-001",
    "householdName": "Rivera household",
    "district": "north-district"
  }
}
JSON

household_create_config=$(mktemp "$HOME/.breg-local/household-create.XXXXXX")
printf '%s\n' \
  'silent' \
  'show-error' \
  'request = "POST"' \
  "url = \"$BREG_BASE_URL/v1/records/households\"" \
  "header = \"Authorization: Bearer $household_operator_token\"" \
  'header = "Content-Type: application/json"' \
  'data = "@household-create.json"' \
  'output = "household-create-response.json"' \
  > "$household_create_config"
curl --config "$household_create_config"
rm -f "$household_create_config"

cat > service-center-create.json <<'JSON'
{
  "data": {
    "centerCode": "CENTER-ACTION-HTTP-001",
    "label": "Northern field office",
    "district": "north-district"
  }
}
JSON

service_center_create_config=$(mktemp "$HOME/.breg-local/service-center-create.XXXXXX")
printf '%s\n' \
  'silent' \
  'show-error' \
  'request = "POST"' \
  "url = \"$BREG_BASE_URL/v1/records/service-centers\"" \
  "header = \"Authorization: Bearer $household_operator_token\"" \
  'header = "Content-Type: application/json"' \
  'data = "@service-center-create.json"' \
  'output = "service-center-create-response.json"' \
  > "$service_center_create_config"
curl --config "$service_center_create_config"
rm -f "$service_center_create_config"

household_id=$(python3 -c 'import json; print(json.load(open("household-create-response.json"))["id"])')
service_center_id=$(python3 -c 'import json; print(json.load(open("service-center-create-response.json"))["id"])')
```

When the user selects the household record, obtain the exact action condition
through the action condition endpoint. This does not require or grant generic
`GET` access.

```bash
read -r contact_registrar_token < "$CONTACT_REGISTRAR_TOKEN_FILE"
python3 - "$household_id" <<'PY'
import json
import sys
with open("household-condition-input.json", "w", encoding="utf-8") as handle:
    json.dump({"input": {"householdId": sys.argv[1]}}, handle, indent=2)
    handle.write("\n")
PY

condition_curl_config=$(mktemp "$HOME/.breg-local/action-condition.XXXXXX")
printf '%s\n' \
  'silent' \
  'show-error' \
  'request = "POST"' \
  "url = \"$BREG_BASE_URL/v1/actions/register-household-contact/target-conditions\"" \
  "header = \"Authorization: Bearer $contact_registrar_token\"" \
  'header = "Content-Type: application/json"' \
  'data = "@household-condition-input.json"' \
  'output = "household-conditions.json"' \
  > "$condition_curl_config"
curl --config "$condition_curl_config"
rm -f "$condition_curl_config"
```

The condition response contains only a `preconditions` object:

```json
{
  "preconditions": {
    "householdId": {
      "ifMatch": "\"opaque-condition-token\""
    }
  }
}
```

Keep that condition with the user's form state. If a stale condition is refused,
retain the user's input, fetch a new condition for the same selected record, and
resubmit only after the user confirms the still-current inputs. Do not silently
refresh the condition immediately before submission, because that can hide a
real concurrent edit from the user.

Build the invocation body from the captured record IDs and the saved condition:

```bash
python3 - "$household_id" "$service_center_id" <<'PY'
import json
import sys
with open("household-conditions.json", encoding="utf-8") as handle:
    conditions = json.load(handle)["preconditions"]
body = {
    "input": {
        "householdId": sys.argv[1],
        "serviceCenterId": sys.argv[2],
        "personCode": "PERSON-ACTION-HTTP-001",
        "contactName": "Alicia Rivera",
        "district": "north-district",
    },
    "preconditions": conditions,
}
with open("household-contact-invocation.json", "w", encoding="utf-8") as handle:
    json.dump(body, handle, indent=2)
    handle.write("\n")
PY

invoke_curl_config=$(mktemp "$HOME/.breg-local/contact-action.XXXXXX")
printf '%s\n' \
  'silent' \
  'show-error' \
  'request = "POST"' \
  "url = \"$BREG_BASE_URL/v1/actions/register-household-contact\"" \
  "header = \"Authorization: Bearer $contact_registrar_token\"" \
  'header = "Content-Type: application/json"' \
  'header = "Idempotency-Key: household-contact-actions-001"' \
  'data = "@household-contact-invocation.json"' \
  > "$invoke_curl_config"
curl --config "$invoke_curl_config"
rm -f "$invoke_curl_config"
```

Use the same `Idempotency-Key`, body, selected access profile, and condition
after a lost response. Within the original package and authority binding, the
server returns the stored receipt instead of running the mutation a second time.
After a successful commit, reusing that key with different input, conditions,
profile, or result permissions returns an idempotency conflict. A package change
or erased response can also prevent replay, but never makes the consumed key
eligible to execute again. A different key is a separate invocation; configure
entity uniqueness constraints for domain-level duplicate prevention.

The condition read does not grant ordinary `GET`, list, lookup, field
projection, or revision-history access. Missing and out-of-bound exact targets
use the same concealment behavior as the rest of the protected API.

| Response | What the caller should do |
| --- | --- |
| `200` | Keep the application receipt. Results contain only the effect references granted to the selected profile. |
| `400 request.invalid` | Correct the body. For admitted action bodies, `fieldPath` identifies a declared input or condition member, such as `/input/contactName` or `/preconditions/householdId/ifMatch`. Unknown names point to their enclosing object and are not echoed. |
| `404 resource.not_found` | The action or condition target is unavailable under the caller's authority. Do not infer whether a hidden target exists. |
| `412 precondition.failed` | Keep the form inputs. Recheck the selected targets, their current conditions and permitted boundaries before resubmitting. |
| `409` | Inspect the problem code: `idempotency.conflict` is a consumed-key binding mismatch; `mutation.conflict` is a state or configured constraint conflict. |
| `503 service.unavailable` or a lost response | Retry the identical request with the same key to recover a possible committed receipt. Do not generate a fresh key automatically. |

The compiler bounds an action to 16 target roles, 128 field mutations and a
2 MiB maximum snapshot. Multiple non-overlapping effects that resolve to the
same record share one committed revision and configured event. Each granted
effect still has its own result reference in the receipt.
