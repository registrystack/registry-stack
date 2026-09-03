# Change-request configuration examples

For a first walkthrough, use the docs-site tutorial at
`docs/site/src/content/docs/tutorials/review-registry-changes.mdx` in this source
checkout. It runs an approval workflow, adapts a stage, and checks a refused
direct-write grant. This guide covers the broader example and operator details.

Base Registry Engine change requests are ordinary product configuration. The compiler
turns each request type into finite action routes, bounded action input schemas,
controlled-write metadata, and immutable effect plans. Runtime apply is limited
to the compiled create, patch, set, and clear effects in that plan.

Both examples set `changeRequest.retention.mode: operator_erase`. That mode does
not create a TTL or scheduler. It means retained request detail can be erased
only through the explicit operator retention command path.

## Rhai planner adopter comparison

`acceptance/person-name-change-rhai` is the compact synthetic counterpart for
an adopter whose proposal value needs bounded computation. Its YAML declares
the entire authority boundary: the Rhai ABI, four request fields, one existing
`person` target, one `display-name` patch field, `review.mode: none`, planner
application outcomes (`apply` or `queue`), and the closed `assisted-review`
queue-reason catalogue. Its `scripts/person-name-change.rhai` only trims and
joins the supplied name parts, then selects one of those declared outcomes.

The selected `name-change-submitter` has both `apply_request` and the same
selected-profile `applyTargets` grant, because the planner's disposition is not
known until submission. A `routine` request freezes and applies atomically on
submit. An `assisted` request instead produces a frozen queued proposal. A
separate authorized assisted applier later invokes the ordinary `apply_request`
action using the proposal metadata returned by GET; it does not rerun Rhai.
This keeps static policy, authorization, and write ceilings in YAML while using
Rhai only for deterministic proposal construction.

The existing asset-placement correction remains declarative because it copies a
selected reference field without computation. Adding Rhai there would expand
the executable surface without adding adopter value.

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  check products/breg/acceptance/person-name-change-rhai

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  project planner-test products/breg/acceptance/person-name-change-rhai \
  --entity person-name-change-request \
  --request products/breg/acceptance/person-name-change-rhai/examples/routine-request.json
```

The planner test is offline and value-free outside its input file. It reports
the compiled ABI and script digest, disposition and declared queue reason,
ordinal effect aliases, target kinds, operations, field names, dependencies,
and counts. It never reads a target row and therefore does not replace the
PostgreSQL lifecycle journey.

## Run the asset example with Registry Workspace

The Base Registry Engine demo can leave the asset correction fixture running and
emit an owner-only handoff for Registry Workspace:

```bash
products/breg/demo/run.sh --fixture asset-change-request \
  --handoff /absolute/new/path/change-request-handoff.json
```

The demo seeds one draft correction from North Yard to South Yard. The handoff
contains separate submitter, reviewer, supervisor, applier, and site-planner
token-file paths, plus an inert request-record path. The site planner can browse
the supporting asset, site, and placement collections but is not part of the
lifecycle sequence. The handoff contains no token bytes and grants no action by
itself. A client must fetch caller-filtered metadata and the request record after
every persona change, then use only the action currently advertised in
`data.request.actions[]`.

Registry Workspace can attach to the generated handoff, or launch this mode
itself with its documented `asset-change-request` demo command. The interactive
sequence is submit, approve `review`, approve `final-approval`, then apply.

The committed examples are fixture copies, so the existing direct-write
acceptance fixtures keep their original behavior:

- `acceptance/asset-site-placement-change-requests` controls
  `asset-placement.patch` through `placement-correction-request`. The request
  proposes a corrected site for an existing placement and requires `review` and
  `final-approval` before `apply_request`.
- `acceptance/publicschema-household-change-requests` controls `person.create`,
  `group-membership.create`, and `household.patch` through
  `register-household-contact-request`. Applying the request creates the contact
  person, creates the membership row, and patches the household contact
  reference.

## First-hour structural checks

Run these from the repository root:

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  check products/breg/acceptance/asset-site-placement-change-requests

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  check products/breg/acceptance/publicschema-household-change-requests

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  explain change-requests products/breg/acceptance/asset-site-placement-change-requests \
  --format json > /tmp/asset-change-requests.json

CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  explain change-requests products/breg/acceptance/publicschema-household-change-requests \
  --format json > /tmp/household-change-requests.json
```

The explain output describes the compiled contract before running a database
journey. It shows request types, action preconditions, controlled-write targets,
bounds, review stages, grants, and compiled effects. Read `registry.yaml` for the
retention setting and a request's GET response for its current state and proposal
metadata.

## Run both examples against PostgreSQL

Use an owner-only env file so the tested admin URL stays out of the
documented command and ordinary shell history. The script expects an admin
PostgreSQL URL for a protected disposable test cluster and the CA PEM used by
that cluster. A valid file has this shape:

```bash
mkdir -p "$HOME/.breg-local"
chmod 700 "$HOME/.breg-local"
cat > "$HOME/.breg-local/change-request-test.env" <<'EOF_ENV'
export BREG_TEST_DATABASE_URL='postgresql://ADMIN:PASS@127.0.0.1:PORT/postgres'
export BREG_TEST_TLS_CA_PEM_PATH='/absolute/path/to/postgres-ca.pem'
EOF_ENV
chmod 600 "$HOME/.breg-local/change-request-test.env"
```

If you already ran the repository PostgreSQL TLS proof, copy its
`BREG_TEST_TLS_DATABASE_URL` value into `BREG_TEST_DATABASE_URL`
and copy its generated CA PEM path into `BREG_TEST_TLS_CA_PEM_PATH`.
The CR example script sets `SSL_CERT_FILE` from that PEM path, creates per-run
roles and databases, writes runtime URL and JWT secrets into an owner-only temp
directory, runs the public `bregctl test` command for all three examples,
and cleans only the temp resources it created.

```bash
products/breg/scripts/test-change-request-examples.sh \
  --env "$HOME/.breg-local/change-request-test.env"
```

Expected terminal shape:

```text
running change-request fixture: asset-site-placement-change-requests
change-request fixture passed: asset-site-placement-change-requests
running change-request fixture: publicschema-household-change-requests
change-request fixture passed: publicschema-household-change-requests
running change-request fixture: person-name-change-rhai
change-request fixture passed: person-name-change-rhai
```

The script requires Python 3 with PyYAML. It does not print bearer tokens or
database URLs. Runtime database URLs and bearer tokens generated by the script
are stored in owner-only secret files; the admin test URL is read from the env
file and used by local helper processes.

## Make a disposable authoring edit

Do not edit the committed acceptance fixture while learning the flow. Copy it,
make the change in the copy, and run the same script against that copied project.
For example, rename the second asset review stage and its matching journey action
input:

```bash
work_dir=$(mktemp -d "$PWD/.breg-cr-authoring.XXXXXX")
cp -R products/breg/acceptance/asset-site-placement-change-requests \
  "$work_dir/asset-site-placement-change-requests"

python3 - "$work_dir" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1]) / 'asset-site-placement-change-requests'
registry = root / 'registry.yaml'
registry_text = registry.read_text(encoding='utf-8')
registry.write_text(registry_text.replace('final-approval', 'operations-approval'), encoding='utf-8')

journey = root / 'tests/journeys.yaml'
journey_text = journey.read_text(encoding='utf-8')
journey.write_text(journey_text.replace('stage: final-approval', 'stage: operations-approval'), encoding='utf-8')
PY

products/breg/scripts/test-change-request-examples.sh \
  --env "$HOME/.breg-local/change-request-test.env" \
  --asset-project "$work_dir/asset-site-placement-change-requests"
```

The same pattern works for the household fixture with `--household-project` and
the Rhai fixture with `--rhai-project`. A
real adopter starting from one review stage must make the same three changes in
their own project: add the second stage under `changeRequest.review.stages`, add
a grant whose `reviewStages` names that stage, and add a GET plus action step in
the journey that uses the GET-discovered `request.actions[].ifMatch`,
`proposalVersion`, and `effectDigest`.

## Schema-test journey shape

`bregctl test` drives the configured journey suite through the real
Base Registry Engine router and a disposable PostgreSQL schema-test database. It uses
the same protected runtime model as the local quickstart: a fixture-specific
`runtime-test.yaml`, a `schema-test-credentials.yaml`, and one compact JWT per
role stored in owner-only files under the runtime secret root.

The credential binding file maps each journey step to a token reference:

```yaml
apiVersion: registry.registrystack.org/breg-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - journeyId: placement-correction-request-flow
    stepId: create-asset
    credential:
      type: bearer
      tokenRef: secret:file/asset-operator-token
  - journeyId: placement-correction-request-flow
    stepId: create-correction-request
    credential:
      type: bearer
      tokenRef: secret:file/correction-submitter-token
  - journeyId: placement-correction-request-flow
    stepId: approve-review-stage
    credential:
      type: bearer
      tokenRef: secret:file/correction-reviewer-token
  - journeyId: placement-correction-request-flow
    stepId: approve-final-stage
    credential:
      type: bearer
      tokenRef: secret:file/correction-supervisor-token
  - journeyId: placement-correction-request-flow
    stepId: apply-correction-request
    credential:
      type: bearer
      tokenRef: secret:file/correction-applier-token
```

The household example uses the same pattern with these identities and scopes:

| Profile | Purpose | Scope |
| --- | --- | --- |
| `household-operator` | `household-administration` | `registry:household:operate` |
| `household-contact-submitter` | `household-contact-registration` | `registry:household-contact:submit` |
| `household-contact-reviewer` | `household-contact-review` | `registry:household-contact:review` |
| `household-contact-supervisor` | `household-contact-review` | `registry:household-contact:supervise` |
| `household-contact-applier` | `household-contact-apply` | `registry:household-contact:apply` |

The committed fixture journeys fetch the request record before each action. The
runner uses the matching `request.actions[].ifMatch` value from that GET response
as the action `If-Match` header. It does not use a normal record GET `ETag` for
request actions. Approve, reject, request-revision, and apply also use the
GET-discovered `proposalVersion` and `effectDigest`.

## HTTP action sequence

On a deployment activated with either example, the HTTP flow is ordinary REST
plus finite action routes. The example runner exercises this sequence through
`bregctl test`; it does not leave a service running for curl commands.
The same sequence applies to both examples:

1. Create supporting records with the operator token.
2. Create the request record with the submitter token.
3. Edit the draft request with ordinary `PATCH` and the request record `ETag`.
4. GET the request using the next actor's profile and read `request.actions[]`.
5. POST the submit action with body `{}` and `If-Match` from the submit action link.
6. GET again as the reviewer, then approve the `review` stage with `proposalVersion` and `effectDigest` from the action link.
7. GET again as the supervisor, then approve the second stage.
8. GET again as the applier, then apply with the action link's `proposalVersion`, `effectDigest`, and `ifMatch`.

For a stale action precondition, keep the old apply action values and arrange a
permitted target revision change through another authorized path, such as another
approved request that touches the same target. Then POST the old apply action
using the old action `If-Match`, proposal version, and effect digest. The server
returns `412 precondition.failed`. Fetch the request again, use the
`revise_request` action link, and post this HTTP JSON body:

```json
{"rebase":true}
```

The fixture journey syntax is not nested under `data`. Use `rebase` directly
under the `request` action step:

```yaml
- id: rebase-primary-request
  entity: placement-correction-request
  accessProfile: correction-submitter
  request:
    operation: revise_request
    recordRef: primary-before-rebase
    etagRef: primary-before-rebase
    rebase: true
  expect:
    outcome: success
    status: 200
```

A fixture step for the stale precondition uses the same refusal contract:

```yaml
- id: apply-primary-with-stale-target
  entity: placement-correction-request
  accessProfile: correction-applier
  request:
    operation: apply_request
    recordRef: primary-before-stale-apply
    etagRef: primary-before-stale-apply
    proposalVersionRef: primary-before-stale-apply
    effectDigestRef: primary-before-stale-apply
  expect:
    outcome: refusal
    status: 412
    problemCode: precondition.failed
```

After revise, repeat submit, both approval stages, and apply using the new GET
metadata. A stale proposal version, stale effect digest, or stale action
`If-Match` is intentionally not reusable after the rebase.

## Retention operator checks

Use the retention operator CLI only for requests with retained detail, including
canceled drafts and retained proposal versions. List first, run dry-run, then
erase only requests whose compiled mode is `operator_erase`:

These commands operate on an activated Registry. Set `RUNTIME_CONFIG` to its
operator runtime configuration, which supplies the migration connection. The
starter cleans its disposable schema-test resources after each run.

```bash
bregctl request-retention list \
  --runtime-config "$RUNTIME_CONFIG" \
  --request-entity placement-correction-request \
  --limit 50

bregctl request-retention dry-run \
  --runtime-config "$RUNTIME_CONFIG" \
  --request-entity placement-correction-request \
  --request-id "$REQUEST_ID" \
  --proposal-version "$PROPOSAL_VERSION"

bregctl request-retention erase \
  --runtime-config "$RUNTIME_CONFIG" \
  --request-entity placement-correction-request \
  --request-id "$REQUEST_ID" \
  --proposal-version "$PROPOSAL_VERSION"
```

The operator path is explicit and exact. These examples do not imply automatic
expiry or background request deletion.

## Generated baselines

The generated OpenAPI, schema, metadata, manifest, and SQL baselines are
committed under `products/breg/generated`, including
`person-name-change-rhai`, and checked by:

```bash
products/breg/scripts/check-generated.sh
```

When generating an individual artifact for review, choose a new child directory
whose real parent already exists. The command intentionally refuses an existing
destination, a missing parent, parent-directory components, or symlinked path
components. A repository-owned temporary parent is portable on macOS:

```bash
repository_root=$(pwd -P)
artifact_parent=$(mktemp -d "$repository_root/.breg-generated.XXXXXX")

cargo run --locked -p registry-bregctl -- \
  generate openapi products/breg/acceptance/person-name-change-rhai \
  --output "$artifact_parent/openapi"
```
