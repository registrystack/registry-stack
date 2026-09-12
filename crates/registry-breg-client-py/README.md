# registry-breg-client-py

Internal PyO3 binding for `registry-breg-client`. The release process bundles
this module into the public `registry-stack-client` wheel. It is not published
as a standalone PyPI project.

The public import is `registry_client.breg`. Fetch `registry_contract(profile)`
before a write and select the operation from that caller-filtered contract. The
returned create, patch, action, Tombstone, Batch, lifecycle, and attachment
objects are opaque authority values tied to the client source and registry
revision.

Each item in `contract.operations` includes a snake-case `request` projection.
Its optional `allow_create` and `allow_patch` values are `True`, `False`, or
`None`; an explicit `False` is preserved. The descriptor's
`readable_request_fields` reports which retained request values the selected
profile may read.

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
bytes. `get_record(..., request_history_after_proposal_version=version)` asks
for proposal history after a known version.

## Direct and atomic mutations

Immediate actions explicitly acquire target conditions when the served action
requires them. Conditions are opaque and can only be used with the selected
action and the same target inputs.

```python
contract = client.registry_contract(profile)
action = contract.select_immediate_action("rename-company", profile)
conditions = client.action_target_conditions(action, {"targetId": record_id})
receipt = client.invoke_action(
    action,
    {"targetId": record_id, "legalName": "Renamed Ltd"},
    "rename-company-1",
    conditions,
)
```

Tombstone and Batch are selected by entity. Batch items are ordered mappings
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
and byte limits are validated by the Rust client before network I/O. Mutations
are sent once and are never retried automatically.

## Recovering interrupted mutations

`prepare_create` and `prepare_lifecycle_action` return opaque evidence that can
be persisted with `to_bytes()` and restored with the matching `from_bytes()`.
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

Use `action.with_reason(text)` on a promoted `reject_request` or
`request_revision` action to add optional reviewer text. It returns a copy and
validates before network effects. The original action omits the reason. Text
is preserved exactly, allows an empty string, and is limited to 4096 Unicode
characters with NUL refused. Reuse the same action and idempotency key for an
explicit retry.

## Request attachments

Governed binary slots are engine-owned. They are never set through create,
JSON Patch, or request effects. Select them from a caller-filtered contract,
then use the three exchanges the engine advertises.

```python
contract = client.registry_contract(profile)
slot, = contract.select_attachments("company", profile)
upload = slot.prepare_upload("application/pdf", data)
client.upload_attachment(slot, record_id, etag, upload, "upload-supporting-file-1")
stored = client.download_attachment(slot, record_id, proposal_version)
client.delete_attachment(slot, record_id, next_etag, "remove-supporting-file-1")
```

`slot` carries the served policy: `slot_identifier`, `required_for_submit`,
`maximum_bytes`, `content_types`, `classification`,
`accepts_content_type(value)`, and the `can_download`, `can_upload`, and
`can_remove` routes the caller's profile was granted. `prepare_upload` refuses
an empty body, a body larger than `maximum_bytes`, and any content type outside
`content_types` before a request is built, so a refused upload never leaves the
process. Uploads and removals need the record's current ETag and a caller-chosen
idempotency key, exactly like `patch_record`.

`slot.value_in(record)` reads the engine-owned projection of the slot out of one
record mapping: a `kind` of `not_selected`, `empty`, or `filled`, with a `value`
holding `proposal_version`, `byte_size`, `sha256`, `content_type`,
`uploaded_at`, `uploaded_by`, `erased`, and `verification_status` when the slot
is filled.

A download requires the proposal version and returns the stored bytes with their
stored content type. A retained older value may carry a content type the current
policy no longer accepts. The response is bounded by both the slot capacity and
the client's `max_response_bytes`, so raise `max_response_bytes` when a slot may
hold more than the default bound.

## Explicit OAuth token exchange

`registry_client.breg.PrivateKeyJwt(config)` wraps the shared Rust OAuth
provider. Its configuration uses the existing snake-case `private_key_jwt`
fields. Call `provider.exchange(subject_token)` with a short-lived signed task
assertion and explicit configured `resource` and `scopes`. Each exchange uses
fresh client authentication and bypasses the service cache;
`provider.bearer_token()` uses the separate client-credentials cache. Both
methods release the GIL during network work and return a credential string for
explicit use by the application. Keep that string out of logs and persistent
state. The resource server still validates the signed authority and bounds.
