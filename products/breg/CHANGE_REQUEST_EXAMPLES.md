# Change-request configuration examples

Base Registry Engine owns request authoring, frozen proposal effects, source
authorization, application guards, application, receipts, audit, and retention.
An external review authority such as Registry Casework owns review policy and
review decisions. BReg does not host review stages or evaluate a second copy of
that policy.

The compiler turns each request type into bounded submit, revise, cancel, and
apply actions. Submission freezes the proposal version, effects, application
preconditions, effect digest, review authority, review policy, and approved
application mode.

## Declare the review and application boundary

Use `review.authority` and `review.policyId` to bind the proposal to a configured
review authority. `onApproved` controls only how an accepted result is applied.

```yaml
changeRequest:
  effects:
    - target: {fromField: placement}
      operation: patch
      set:
        site: {fromField: proposed-site}
  review:
    authority: casework
    policyId: asset-placement-correction
  onApproved:
    mode: manual
  retention:
    mode: operator_erase
```

`manual` has no executor. A currently authorized caller must invoke the ordinary
`apply_request` action after BReg has durably reconciled the exact accepted
Casework result. `automatic` requires an explicit logical executor:

```yaml
  onApproved:
    mode: automatic
    executor: corrections-applier
```

The runtime maps that logical executor to a separately configured credential.
Automatic application uses the same authenticated BReg HTTP action and the same
current source permissions, proposal binding, preconditions, and transaction as
manual application. A completion notification is not application authority.

For a request that intentionally needs no external review, say so explicitly:

```yaml
  review: {mode: none}
  onApproved: {mode: manual}
```

An empty `application: {}` is optional. Add the section when the request has
application preconditions.

## Governed application preconditions

Application may require frozen request facts, current stored target facts, and
signed Evidence immediately before application. Preconditions are closed,
scalar, AND-only configuration.

```yaml
changeRequest:
  review:
    authority: casework
    policyId: seed-release
  onApproved: {mode: manual}
  application:
    preconditions:
      request:
        - {field: valid-from, currentDate: on_or_before}
        - {field: valid-through, currentDate: on_or_after}
      targets:
        - id: lot
          entity: lots
          fromField: lot-reference
          requires:
            - {field: owner-reference, equalsFromRequestField: owner-reference}
            - {field: active, equals: true}
      evidence:
        - id: release-check
          provider: laboratory
          requirement: urn:example:seed-release:v1
          subjects:
            subject:
              profile: lot-release-v1
              selectors:
                lot-reference: {source: request_field, field: lot-reference}
                owner-reference: {source: target_field, target: lot, field: owner-reference}
          requires:
            - {output: report-reference, equalsFromRequestField: report-reference}
            - {output: germination-basis-points, atLeast: 9000}
          maximumObservationAgeSeconds: 300
```

Submission freezes request values, target identities, target revisions, and
minimized guard fields. Apply rechecks current source authority, the exact
proposal and accepted result binding, current targets, UTC validity, Evidence
identity and freshness, and every predicate. Effects, the application receipt,
audit, outbox, and protected Evidence linkage commit atomically. Retrying the
same application idempotency key recovers the stored receipt without contacting
Casework or acquiring Evidence again.

## Reading external review status

Review status is separately disclosure-controlled. Add `review_state` to each
authenticated request permission that should receive `data.request.review`.
Explicit fields replace the default metadata projection, so retain `reason` if
that profile should also see retained explanations.

```yaml
permissions:
  - entity: placement-correction-request
    operations: [get, list]
    readableFields: [placement, proposed-site, reason]
    readableRequestFields: [reason, review_state]
    rowBoundaries: []
```

The closed review projection identifies the frozen authority and policy,
durable submission binding, exact Casework result status, delivery state, and
source application state. Optional members are omitted until known. These
fields report source-owned reconciliation state; they do not grant review or
application authority.

## Runtime review authority

`runtime.reviewAuthorities` binds the authored logical authority to one pinned
Casework endpoint, producer identity, Casework profile, recovery window, and
maintained credential. `producerId` is an explicit protocol identity and is
never inferred from the profile or OAuth client.

```yaml
reviewAuthorities:
  casework:
    endpoint: https://casework.example.test
    producerId: registry-breg
    profile: integration-requester
    recoveryDays: 7
    privateKeyJwt:
      tokenEndpoint: https://issuer.example.test/oauth/token
      assertionAudience: https://issuer.example.test
      resource: https://casework.example.test
      scopes: [casework:producer]
      clientIdRef: secret:file/casework-producer-client-id
      clientAssertionKeyRef: secret:file/casework-producer-private-jwk
```

Opaque deployments may instead use the explicitly supported static token
reference. Tokens and private keys remain secret references and are not embedded
in generated configuration or handoffs. The worker renews OAuth access tokens;
a startup bearer is not a long-running credential strategy.

## Rhai planners compute effects only

`acceptance/person-name-change-rhai` demonstrates a bounded planner. YAML owns
the ABI, request inputs, write ceiling, review choice, application mode, and
permissions. Rhai computes only frozen effects. It cannot decide who reviews or
who applies.

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

The offline planner report contains compiled planner identity and the declared
effect shape. It does not read target rows, credentials, or review results.

## First-hour structural checks

Run these from the repository root:

```bash
cargo run --locked -p registry-bregctl -- \
  check products/breg/acceptance/asset-site-placement-change-requests

cargo run --locked -p registry-bregctl -- \
  check products/breg/acceptance/publicschema-household-change-requests

cargo run --locked -p registry-bregctl -- \
  explain change-requests products/breg/acceptance/asset-site-placement-change-requests \
  --format json
```

The explain output describes frozen effects, review binding, application mode,
preconditions, controlled targets, and permissions. It contains no local review
stage or decision route.

The committed offline journeys create and submit requests, prove an authorized
reader can inspect the submitted source record, prove effects are not applied by
submission, and exercise source cancellation. End-to-end review and application
requires a configured Casework service and is covered by the composed runtime
test, not by an invented local review decision.

## HTTP sequence

1. Create supporting records using ordinary source permissions.
2. Create and edit the draft request.
3. GET the request and use the advertised `submit_request` action with its
   `ifMatch` value.
4. BReg durably submits the exact frozen proposal to the configured Casework
   authority and stores the accepted request ID, subject, policy binding, and
   submission digest.
5. Casework independently evaluates its policy. BReg reconciles the exact result
   through authenticated completion delivery or the requester result feed.
6. For manual mode, an ordinary currently authorized source caller GETs the
   request and invokes the advertised `apply_request` action with its proposal
   version, effect digest, and `ifMatch` binding.
7. For automatic mode, the configured executor does the same through the bounded
   self-HTTP path.

Substituting the Casework request ID, source subject, policy binding, submission
digest, proposal version, effect digest, or source target precondition is
refused. Cancellation and application race under database guards so only one
terminal source transition wins.

## Retention operator checks

Both examples use `retention.mode: operator_erase`. This creates no TTL or
scheduler. An operator must list, dry-run, and erase an exact eligible request:

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

## Generated baselines

Generated OpenAPI, schema, metadata, manifest, and SQL baselines are committed
under `products/breg/generated` and checked by:

```bash
products/breg/scripts/check-generated.sh
```

Do not hand-edit generated artifacts. Change authoring or generator code, run
the documented generator, and review the complete diff.
