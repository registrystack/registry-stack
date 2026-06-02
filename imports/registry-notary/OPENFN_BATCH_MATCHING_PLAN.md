# OpenFn Batch Matching Plan

## Final Contract Names

- Source binding connector: `connector: openfn_sidecar`.
- Source connection batch mode: `bulk_mode: openfn_sidecar_batch`.
- Sidecar single-read route:
  `GET /v1/datasets/{dataset}/entities/{entity}/records`.
- Sidecar batch route:
  `POST /v1/datasets/{dataset}/entities/{entity}/records:batchMatch`.
- Batch query contract: shared ordered `query_signature` with `op: eq` only,
  plus per-item `values` arrays matching the signature length.

## Definition Of Done

This work is done only when every item below is satisfied with code, tests, and
documentation in the same reviewed change set.

### Product Contract

- Registry Notary has a first-class OpenFn sidecar connector config value,
  `connector: openfn_sidecar`, that parses, validates, and is documented.
- Existing `connector: registry_data_api` behavior remains compatible and all
  existing RDA connector tests still pass.
- OpenFn sidecar batch matching uses a POST endpoint with an explicit batch
  contract, not generic RDA `.in` filter semantics.
- The batch endpoint path is stable and documented as:
  `POST /v1/datasets/{dataset}/entities/{entity}/records:batchMatch`.
- The batch request requires `Data-Purpose`, `Authorization`, `fields`,
  `query_signature`, and `items`.
- The v1 `query_signature` supports `op: eq` only.
- Every item in one batch request uses the same `query_signature`.
- The batch request does not include full `target`, `requester`,
  `relationship`, `assurance`, claim config, disclosure config, or unrelated
  request attributes.
- Notary applies matching policy and minimization before dispatching any
  sidecar batch request.
- Sidecar workers receive only source query terms, projected fields, purpose,
  correlation metadata, source id, dataset, entity, and sidecar-owned
  configuration.
- Batch matching is semantically equivalent to running the same source binding
  as single reads for each item.

### Request And Response Shape

- A valid batch request has this shape:

  ```json
  {
    "fields": ["national_id", "birth_date"],
    "query_signature": [
      { "field": "given_name", "op": "eq" },
      { "field": "family_name", "op": "eq" },
      { "field": "birthdate", "op": "eq" }
    ],
    "items": [
      { "id": "0", "values": ["Amina", "Diallo", "1990-01-01"] }
    ]
  }
  ```

- A successful batch response has this shape:

  ```json
  {
    "items": [
      {
        "id": "0",
        "data": [
          {
            "national_id": "12345",
            "birth_date": "1990-01-01"
          }
        ]
      }
    ]
  }
  ```

- Response item ids must correspond exactly to request item ids.
- A missing response item maps to `SourceUnavailable` for that item.
- A duplicate response item id causes the whole sidecar response to be rejected
  as invalid output.
- `data: []` maps to source not found for that item.
- `data: [record]` maps to a successful source match for that item.
- `data: [record1, record2]` maps to source ambiguous for that item.
- More than two records for one item are normalized to two records or rejected
  before reaching Notary. The chosen behavior is documented and tested.
- Returned records are projected to the requested `fields`; extra worker output
  fields are not returned to Notary.
- Per-item structured source errors are supported only for documented codes.
- Unknown per-item error codes map to source unavailable.

### Notary Runtime Behavior

- Batch prefetch groups OpenFn sidecar reads by:
  `connection_id`, `dataset`, `entity`, ordered `query_signature`,
  projected fields, and purpose.
- OpenFn sidecar batch grouping supports both single `lookup` and multi-field
  `query_fields` bindings.
- Existing RDA and DCI bulk grouping remains unchanged.
- Bindings with matching policy failures are not included in sidecar batch
  requests.
- Overprovisioned target or requester context is rejected before any sidecar
  request is sent.
- Missing required matching inputs are rejected before any sidecar request is
  sent.
- Matching policy purpose restrictions are enforced before any sidecar request
  is sent.
- `collapse_matching_errors` behavior remains owned by Notary and is tested for
  batch items.
- Per-item success and failure ordering matches the input batch item order.
- Errors from batch prefetch are not cached in the per-batch memo.
- If batch prefetch fails for an item, the item either falls through to the
  existing single-read path or returns the exact documented per-item error.
  The chosen behavior is implemented consistently and tested.
- Notary does not retry OpenFn worker execution failures unless a future
  explicit retry policy is added.

### Sidecar Behavior

- The sidecar exposes `POST /v1/datasets/{dataset}/entities/{entity}/records:batchMatch`.
- The sidecar rejects unauthenticated requests with `401` and a
  `WWW-Authenticate: Bearer` header.
- The sidecar rejects well-formed but unauthorized tokens with `403`.
- The sidecar rejects missing or empty `Data-Purpose` with `400`.
- The sidecar rejects unknown source routes with `404`.
- The sidecar rejects unsupported query operations with `400`.
- The sidecar rejects mixed item value lengths that do not match
  `query_signature.len()` with `400`.
- The sidecar enforces `max_batch_items`.
- The sidecar enforces max request bytes.
- The sidecar enforces max single field name bytes.
- The sidecar enforces max single item value bytes.
- The sidecar enforces max output bytes.
- The sidecar enforces worker timeout and kills timed-out workers.
- The sidecar returns `503` with `Retry-After` when the worker pool is saturated.
- The sidecar returns `504` when batch worker execution times out.
- The sidecar returns `502` for invalid worker output, truncated output, worker
  crash, or worker non-zero failure.
- The sidecar never logs raw credentials, raw request values, full request
  state, raw worker stderr, bearer tokens, token hashes, or credential lengths.
- Sidecar metrics include connector-specific batch counters without target
  identifiers, query values, request item ids, credentials, or correlation ids
  as labels.
- `/healthz`, `/ready`, and `/metrics` remain responsive while batch requests
  are running or the worker pool is saturated.

### Worker Protocol

- Worker requests include `mode: "batch_match"` for batch execution.
- Worker requests include `query_signature`, `items`, `fields`, `purpose`,
  `source_id`, `dataset`, `entity`, and `configuration`.
- Worker requests do not include full Notary request context.
- Worker responses include only an `items` array or a documented top-level
  error.
- Worker stdout remains one JSON value per line.
- Worker stderr is drained and bounded.
- Worker failures, invalid output, oversized output, and timeouts are not
  retried for the same batch request.
- The production OpenFn worker can execute one configured workflow for a batch
  request and return one item result per request item.
- OpenFn compiler, runtime, expressions, and adaptor versions remain pinned and
  verified before readiness succeeds.

### Configuration And Documentation

- Operator docs describe when to use direct DCI, direct RDA, first-class OpenFn
  sidecar single reads, and OpenFn sidecar batch matching.
- Docs state that OpenFn sidecar batch matching is a source-read optimization,
  not a new matching, authorization, disclosure, or identity proof model.
- Docs state that Notary owns policy, minimization, error collapsing, audit,
  disclosure, and credential issuance.
- Docs state that the sidecar owns adaptor execution, target credentials,
  source comparison, normalization, and worker isolation.
- Docs include a complete single-read OpenFn sidecar config example.
- Docs include a complete batch matching config example with `query_fields`.
- Docs include the exact batch request and response JSON contract.
- Docs include the no-retry behavior for OpenFn worker execution failures.
- Docs include the security guidance that the sidecar must run on localhost or
  a private pod network and must not be publicly exposed.

### Test Coverage

- Unit or integration tests cover first-class OpenFn connector config parsing.
- Tests cover invalid OpenFn connector config combinations.
- Tests cover backwards compatibility for existing `registry_data_api` sidecar
  use.
- Tests cover single OpenFn sidecar read through the first-class connector.
- Tests cover batch match by identifier.
- Tests cover batch match by multiple target attributes using `query_fields`.
- Tests cover batch match using requester or relationship-derived query values
  when those request paths are supported by the binding model.
- Tests cover overprovisioned request context rejection before sidecar dispatch.
- Tests cover insufficient matching inputs before sidecar dispatch.
- Tests cover matching purpose rejection before sidecar dispatch.
- Tests cover item ordering preservation.
- Tests cover mixed exact, not found, and ambiguous results in one batch.
- Tests cover missing response item id.
- Tests cover duplicate response item id.
- Tests cover item value length mismatch.
- Tests cover unsupported operation.
- Tests cover missing purpose.
- Tests cover missing token, malformed token, and rejected token.
- Tests cover worker saturation.
- Tests cover worker timeout and kill.
- Tests cover invalid worker output.
- Tests cover oversized worker output.
- Tests cover target auth and target rate-limit mapping.
- Tests cover no retry on OpenFn worker execution failure.
- Tests cover logs, metrics, HTTP responses, and worker diagnostics for
  credential and request-value non-disclosure.
- Focused tests pass:
  `cargo test -p registry-notary-openfn-sidecar`.
- Relevant server/runtime tests pass:
  `cargo test -p registry-notary-server`.
- Config tests pass:
  `cargo test -p registry-notary-core`.
- Formatting passes:
  `cargo fmt --all -- --check`.
- Lint passes:
  `cargo clippy -p registry-notary-openfn-sidecar --all-targets -- -D warnings`
  and the corresponding touched Notary crates' clippy checks.

### Review And Release Gates

- A reviewer confirms the final implementation still preserves the identity and
  record matching boundary documented in `docs/identity-and-record-matching.md`.
- A reviewer confirms no target-service credentials move into Notary config.
- A reviewer confirms no OpenFn or Node execution is embedded into
  `registry-notary-server`.
- A reviewer confirms no feature is marked implemented while any required test
  above is missing, skipped without reason, or failing.
- A reviewer confirms docs and code agree on endpoint names, config names, error
  mappings, limits, and retry behavior.

## Implementation Plan

### Wave 0: Spec Freeze And Review

- Parent owner: freeze this plan, choose final config names, endpoint name, and
  per-item error codes.
- Worker A: review existing matching policy and `query_fields` runtime paths.
- Worker B: review existing OpenFn sidecar HTTP and worker protocol paths.
- Worker C: review existing bulk prefetch grouping and memo behavior.

Definition of done:

- Final names are recorded in this file.
- Open decisions are resolved or explicitly moved to a later ticket.
- Reviewer signs off that the DoD is concrete, testable, and complete.

Review checkpoint:

- No implementation starts until review confirms the spec preserves Notary
  policy and minimization boundaries.

### Wave 1: Contract Tests First

- Worker A owns sidecar HTTP contract tests for `records:batchMatch`.
- Worker B owns worker protocol fixture tests for `mode: "batch_match"`.
- Worker C owns Notary runtime tests for OpenFn batch grouping with
  `query_fields`.
- Worker D owns config parsing and validation tests for the first-class
  connector.

Definition of done:

- Tests fail against the current implementation for each new required behavior.
- Tests cover every request, response, and error shape listed in the DoD.
- No production code is changed except minimal test-only fixtures.

Review checkpoint:

- Reviewer confirms the failing tests encode the intended behavior and do not
  assert implementation details that should remain flexible.

### Wave 2: First-Class Connector

- Worker D owns `SourceConnectorKind` or equivalent typed config additions.
- Worker C owns Notary single-read dispatch through the OpenFn sidecar
  connector.
- Worker E owns metrics and tracing labels for the new connector.

Definition of done:

- `connector: openfn_sidecar` parses, validates, and can run a single read.
- Existing `registry_data_api` tests still pass unchanged.
- OpenFn connector unsafe config combinations fail with clear errors.

Review checkpoint:

- Reviewer confirms OpenFn remains a sidecar boundary and target credentials do
  not enter Notary config.

### Wave 3: Sidecar Batch Endpoint

- Worker A owns the sidecar POST route, request validation, response
  normalization, and error mapping.
- Worker B owns sidecar worker pool integration for batch requests.
- Worker E owns non-disclosure checks for logs, metrics, responses, and worker
  diagnostics.

Definition of done:

- `records:batchMatch` exists and passes sidecar HTTP contract tests.
- Limits, auth, purpose, timeout, saturation, invalid output, and oversized
  output paths behave exactly as listed in the DoD.
- `/healthz`, `/ready`, and `/metrics` remain responsive under batch load.

Review checkpoint:

- Reviewer confirms the sidecar does not log or return raw credentials, raw
  query values, full request state, or worker stderr content.

### Wave 4: Worker Batch Protocol

- Worker B owns `mode: "batch_match"` support in the production OpenFn worker.
- Worker A owns fixture workers for deterministic success and failure paths.
- Worker E owns version pin and readiness regression tests.

Definition of done:

- The worker accepts one batch request and returns one result per item.
- The worker compiles and runs the configured OpenFn workflow for batch mode.
- Worker failures are not retried for the same batch request.
- Worker stdout, stderr, timeout, and output-size behavior pass all tests.

Review checkpoint:

- Reviewer confirms the worker receives minimized source query terms only and
  does not receive full Notary request context.

### Wave 5: Notary Batch Runtime Integration

- Worker C owns batch grouping by connection, dataset, entity,
  `query_signature`, projected fields, and purpose.
- Worker D owns config validation for OpenFn batch mode and compatibility with
  `query_fields`.
- Worker E owns audit, metrics, and error-collapsing assertions.

Definition of done:

- Batch evaluation dispatches one OpenFn sidecar batch request per compatible
  group.
- Identifier and multi-attribute matching both work.
- Requester and relationship-derived query values work where supported.
- Matching policy rejection, insufficient inputs, and overprovisioning happen
  before sidecar dispatch.
- Per-item outcomes match single-read semantics.

Review checkpoint:

- Reviewer confirms batch matching is an optimization over existing semantics,
  not a separate authorization, disclosure, or identity decision path.

### Wave 6: Documentation, Verification, And Final Review

- Worker F owns operator docs, config examples, and API contract docs.
- Worker A owns sidecar smoke or demo updates.
- Parent owner runs final verification and reviews the full diff.

Definition of done:

- Docs include the endpoint, config, examples, limits, errors, no-retry
  behavior, and security guidance.
- Required focused and broad verification commands listed in the DoD pass, or
  any skipped command has a specific recorded reason.
- Final diff contains no unrelated reformatting or cleanup.

Review checkpoint:

- Final reviewer signs off that every DoD item is satisfied by linked code,
  tests, docs, or an explicit follow-up ticket for non-required future work.
