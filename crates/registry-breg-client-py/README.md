# registry-breg-client-py

Internal PyO3 binding for `registry-breg-client`. The release process bundles
this module into the public `registry-stack-client` wheel. It is not published
as a standalone PyPI project.

The public import is `registry_client.breg`. Fetch `registry_contract(profile)`
before a write and select the operation from that caller-filtered contract. The
returned create, patch, Action, Tombstone, and Batch bindings are opaque authority
values tied to the client source and registry revision. Standalone Proposals
promote their own transition and attachment links under current caller authority.

Each item in `contract.operations` includes a snake-case `request` projection.
Its optional `allow_create` and `allow_patch` values are `True`, `False`, or
`None`; an explicit `False` is preserved. `contract.proposal_actions` describes
the selected profile's Proposal operations and readable inputs for each Action.
These descriptions support interface choices; select a binding before execution.

## Reads

`get_record` and `list_records` return strict Registry Record projections.
`list_records` accepts an optional exact decimal `bbox=(west, south, east,
north)`. GeoJSON has separate `get_geojson_record`, `list_geojson_records`, and
`continue_geojson_list` methods so its response contract cannot be confused
with a Registry Record.

Temporal and relationship collections also use operation-specific methods and
continuations:

```python
current = client.list_current_records("companies", access_profile=profile)
if current["continuation"] is not None:
    current = client.continue_current_list(current["continuation"])

historical = client.list_records_as_of(
    "companies", "2026-09-10T00:00:00Z", access_profile=profile
)
snapshot = client.list_snapshot_records("companies", access_profile=profile)
related = client.list_relationship_records(
    "companies", record_id, "directors", access_profile=profile
)
```

Use `get_record_revision` for one strict-decoded historical envelope and
`record_revisions` when the revisions resource itself must remain exact inert
bytes. Standalone Proposals use `get_proposal` or one explicit `list_proposals`
page. Application result references grant no target read authority. Read the
target through an ordinary authorized `get_record`; the retained result revision
records application provenance, not a current ETag or write precondition.

## Webhook verification

`verify_webhook_delivery(method=..., path=..., headers=..., body=..., key=...)`
authenticates one exact Base Registry Engine Version 1 delivery with the shared
Rust verifier. Arguments are keyword-only. `path` is the request target the
receiver was called on, `headers` is a `dict` of string names to string values
(names match without regard to ASCII case, and a name repeated under another
case is refused), and `body` and `key` are `bytes`. The result is a `dict` with
`id`, `source`, `type`, `time`, `dataschema`, `generation`, `attempt`,
`delivery_time`, `idempotency_key`, and the exact `body`. Generation and attempt
remain decimal strings, as signed.

The helper does not apply clock-skew or deduplication policy. Bound the returned
`delivery_time` against the receiver clock. `idempotency_key` collapses automatic
retries within one delivery generation; an effect that must remain once-only
across operator replay uses a durable apply-once operation keyed by authenticated
`source` plus `id`, or by an application business key, before acting on `body`.

Refusal raises `BaseRegistryClientError` with kind `webhook-verification` and a
`code` from `missing-header`, `invalid-delivery-time`, `duplicate-header`, `body-too-large`, `invalid-key`, `malformed-signature`, `signature-mismatch`, or `unsupported-version`; an
argument of the wrong type raises kind `invalid-request`. The message names
the input to check and never includes a header value, body, or key.

## Direct and atomic mutations

Immediate actions explicitly acquire target conditions when the served action
requires them. Conditions are opaque and can only be used with the selected
action and the same target inputs.

If the Action descriptor has an `availability_path`, query each selected
reference with `action_availability(action, "targetId", inputs)`. The input may
omit unrelated required form fields, while every supplied value is validated
before token acquisition or I/O. This single unkeyed POST is only a current
hint. Invocation remains authoritative and a readable field-guard failure is
reported as 412 `action.guard_failed`.

```python
contract = client.registry_contract(profile)
action = contract.select_action("rename-company", profile)
conditions = client.action_target_conditions(action, {"targetId": record_id})
receipt = client.invoke_action(
    action,
    {"targetId": record_id, "legalName": "Renamed Ltd"},
    "rename-company-1",
    conditions,
)
```

Tombstone and Batch are selected by Record type. Batch items are ordered mappings
with `operation: "create"` plus `data`, or `operation: "patch"` plus
`record_identifier`, `etag`, and JSON Patch `operations`. The optional shared
change context uses snake-case Python keys and is encoded to the wire contract.

```python
tombstone = contract.select_tombstone("company", profile)
client.tombstone_record(tombstone, record_id, etag, "remove-company-1")

batch = contract.select_batch("company", profile)
client.batch_records(
    batch,
    [{"operation": "create", "data": {"legalName": "Batch Ltd"}}],
    "company-batch-1",
    change_context={
        "kind": "correction",
        "reason_code": "verified-source",
        "source_references": ["register-42"],
    },
)
```

All action inputs, conditions, batch fields, item counts, correction context,
and byte limits are validated by the Rust client before network I/O.

A keyed mutation (create, patch, attachment upload or delete, Proposal
transition, immediate action, batch, tombstone, statistics publish or withdraw)
whose outcome is unknown is resent identically under the same key up to
`max_mutation_retries` times, a `BaseRegistryClient` keyword: 0 to 2, default
2, and 0 sends it once. The outcome is unknown after a timeout or broken
exchange once the request was sent, an unusable answer, or a 5xx other than
`action.handler_failed` and `statistical_dataset.domain_violation`, which the
engine returns only with the attempt rolled back. When the returned
`BaseRegistryClientError` still reports `outcome_unknown`, the mutation may
have taken effect: recover by sending it again under the same key, because a
new key could apply it twice. `outcome_unknown` is false for a configuration
or request defect, a credential the token provider could not supply, a
connection never established, and every 4xx refusal, none of which is resent.
It is false for `410 idempotency.expired` too, but there an earlier attempt
under the key committed and only its held response is gone: read the resource
before choosing a new key.

## Recovering interrupted mutations

`prepare_create` returns opaque evidence that can be persisted with `to_bytes()`
and restored with `BRegPreparedCreate.from_bytes()`.
Recovery is pure and does not send a request. Fetch a fresh contract, select
fresh authority, recover, then execute explicitly:

```python
prepared = client.prepare_create(binding, data, "create-company-1")
saved = prepared.to_bytes()

fresh = client.registry_contract(profile)
binding = fresh.select_create("records.company.create", profile)
restored = BRegPreparedCreate.from_bytes(saved)
recovered = client.recover_create(binding, restored)
result = client.execute_recovered_create(binding, recovered)
```

Prepared evidence contains the exact validated request, idempotency key, and
format, but never serializes metadata authority. Prepared and recovered values
have redacted representations.

Immediate actions follow the same pattern. Call `prepare_action` with the same
binding, inputs, idempotency key, and target conditions you pass to
`invoke_action`, and persist its `to_bytes()` value before invoking. After a
lost response, restore it with `BRegPreparedAction.from_bytes`, select the
action again from fresh metadata, and call `recover_action` with the original
inputs and idempotency key:

```python
prepared = client.prepare_action(binding, inputs, "rename-company-1", conditions)
saved = prepared.to_bytes()

fresh = client.registry_contract(profile)
binding = fresh.select_action("rename-company", profile)
restored = BRegPreparedAction.from_bytes(saved)
recovered = client.recover_action(binding, restored, inputs, "rename-company-1")
result = client.execute_recovered_action(binding, recovered)
```

Recovery refuses a different key, different inputs, or another selected
action, reuses the saved target conditions exactly, and never fetches new
ones. `execute_recovered_action` is the explicit send under the original key.
The saved bytes contain input values and must be treated as private
application state.

## Standalone Proposals

Select a Proposal-mode Action, start a draft, then use its promoted transitions:

```python
from registry_client.breg import BRegPreparedProposal

contract = client.registry_contract(profile)
action = contract.select_action("correct-address", profile)
draft = client.start_proposal(action, inputs, "correction-start-1")
submit = client.prepare_proposal(draft, "submit", {}, "correction-submit-1")
saved = submit.to_bytes()  # Persist in owner-protected storage before dispatch.
submitted = client.execute_proposal(submit)
```

Transitions are `edit`, `submit`, `revise`, `rebase`, `retry`, `cancel`, and
`apply`, subject to current availability and caller authority. Apply's body
binds `submissionVersion` and `effectDigest`; optional `reason` text is limited
to 4096 Unicode characters with NUL refused. Proposal conditions are distinct
from Record ETags. `proposal.document` exposes the validated wire document.
Read review status or context explicitly through `read_proposal_review_status`
or `read_proposal_review_context` when their links are promoted. A Proposal
document carries a derived `turn` (`party`, `official` or `nobody`) and, once a
review has decided, a `decision` with its status, `decidedAt` and optional
`publicReason`. `read_proposal_submission(proposal, version)` reads one
retained submission version, its review, application receipt and decision,
with the Proposal Get authority; an expired version is the
`proposal.submission_expired` problem.
When that profile also holds `get-application-actor`, Proposal Get and the
submission read include `appliedBy` and `appliedAt` together in the application
member. Proposal List omits both.

After an uncertain response or restart, fetch the current authorized Proposal
before recovering the original attempt:

```python
fresh = client.registry_contract(profile)
current = client.get_proposal(fresh.select_proposal_get(profile), proposal_id)
attempt = BRegPreparedProposal.from_bytes(saved)
recovered = client.recover_proposal(current, attempt)
result = client.execute_proposal(recovered)
```

Recovery retains the original condition, body and key and requires a matching
current transition or receipt-only recovery link. The Get flow above needs a
current `get` grant; an authorized List item can also supply the fresh Proposal
observation. Losing all such read access, including access to a current target
row, prevents recovery by that caller. Preserve the original attempt for an
authorized operator; do not infer failure or send it under a new key. A status
read alone does not recover an uncertain command.

To retain a Start attempt, call `prepare_action` before `start_proposal`, then
use `recover_action` and `execute_recovered_proposal_start` with fresh Action
authority and the original inputs and key. Protect saved bytes as private
application state.

## Proposal attachments

Governed binary slots are engine-owned and advertised on an authorized Proposal.
They are never set through Record creation or JSON Patch. Use the Proposal's
promoted slot links through the dedicated methods:

```python
contract = client.registry_contract(profile)
proposal = client.get_proposal(contract.select_proposal_get(profile), proposal_id)
proposal = client.upload_proposal_attachment(
    proposal, "supporting-document", "application/pdf", data, "upload-supporting-file-1"
)
stored = client.download_proposal_attachment(proposal, "supporting-document")
proposal = client.delete_proposal_attachment(
    proposal, "supporting-document", "remove-supporting-file-1"
)
```

`proposal.document` retains the disclosed slot policy and value. Uploads refuse
an empty body, a body larger than `maximumBytes`, and a content type outside
`contentTypes` before I/O. Uploads and removals use the promoted slot condition
and caller-chosen idempotency key and return a new Proposal. Downloads check the
frozen value's size, content type and SHA-256 before returning bytes. Keep the
returned Proposal for subsequent operations; do not substitute a Record ETag
or construct an attachment route.

A review-only caller can select `select_proposal_review_context(profile, action)`,
read with `read_proposal_review_by_id(binding, proposal_id)`, then call
`download_proposal_review_document(binding, context, field)` for a disclosed
document field. This does not require or grant ordinary Proposal Get authority.
The server rechecks the full context's current disclosure before releasing bytes.

## Explicit OAuth token exchange

For automatic context-bound authorization, construct `BaseRegistryClient` with
`authorization={"exchange": {"client": ..., "context": ..., "first_party": ...}}`
or a `remote` source. `client` and the remote `bootstrap` use snake-case
private-key-JWT fields with required `resource` and `scopes`. The context
names one verified person or approved grant, its source generation, and a
deadline. A first-party source signs once and requires a new verified host
context for renewal. A remote source sends an empty assertion POST with its
narrow bootstrap on refresh, then exchanges the returned assertion. PEM trust
roots in this new option are strings. Existing `private_key_jwt` authorization
and explicit exchange APIs remain available.

`registry_client.breg.PrivateKeyJwt(config)` wraps the shared Rust OAuth
provider. Its configuration uses the existing snake-case `private_key_jwt`
fields. Call `provider.exchange(subject_token)` with a short-lived signed task
assertion and explicit configured `resource` and `scopes`. Each exchange uses
fresh client authentication and bypasses the service cache;
`provider.bearer_token()` uses the separate client-credentials cache. Both
methods release the GIL during network work and return a credential string for
explicit use by the application. Keep that string out of logs and persistent
state. The resource server still validates the signed authority and bounds.
